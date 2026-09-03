//! Host-owned acceptance and derivation for intrusive stack samples.

use std::{
    collections::BTreeMap,
    fs::{self, Metadata, OpenOptions},
    io::{Read as _, Write as _},
    path::Path,
};

use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use t32perf_analysis::build_folded_stack_profile;
use t32perf_flamegraph::{
    MAX_OUTPUT_LIMIT_BYTES, StackFlameGraphOptions, render_stack_sampled_svg,
};
use t32perf_model::{
    Artifact, ArtifactPath, FirmwareBindingStatus, FoldedStackProfile, SessionStatus, Sha256Digest,
    StackCaptureAttempt, StackCaptureReceipt, StackCaptureReceiptSchemaVersion,
    StackCaptureRequest, StackDriverEvent, StackDriverEventDetails, StackSamples, strict_json,
    validate_successful_stack_event_sequence,
};
use t32perf_session::{
    ArtifactRoot, ArtifactSpec, Session, SessionId, SessionLock, verify_opened_plain_file_identity,
};

use crate::{
    app::{
        AppError, CommandOutcome, ingest_recovery_required, is_recoverable_ingest_intent,
        persist_ingest_captured_state, terminal_ingest_failure,
    },
    cli::{StackAnalyzeArgs, StackIngestArgs, StackPrepareArgs, StackRenderArgs, StackSummaryArgs},
};

const MAX_JSON_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CONTROL_BYTES: u64 = 64 * 1024;
// Must match the sidecar's closed stack-driver-event bound. This is smaller
// than the generic control-document cap so one maximal 512-sample transaction
// can reserve its full journal budget without making the shared history unbound.
const MAX_STACK_EVENT_BYTES: u64 = 4 * 1024;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EVENTS: usize = 16_384;
const DRIVER_EVENTS_PATH: &str = ".t32perf-control/stack-driver-events";
const CAPTURE_ATTEMPTS_PATH: &str = ".t32perf-control/stack-capture-attempts";

pub(crate) const ARTIFACT_ID_PREFIX: &str = "sampling-stack-";
pub(crate) const RAW_KIND: &str = "stack_samples";
pub(crate) const CAPTURE_RECEIPT_KIND: &str = "stack_capture_receipt";
pub(crate) const PROFILE_KIND: &str = "folded_stack_profile";
pub(crate) const FLAMEGRAPH_KIND: &str = "flamegraph";
pub(crate) const CAPTURE_ARTIFACT_PATH_PREFIX: &str = "capture/sampling/stack-";
pub(crate) const ANALYSIS_ARTIFACT_PATH_PREFIX: &str = "analysis/sampling-folded-stack-profile";
pub(crate) const REPORT_ARTIFACT_PATH_PREFIX: &str = "report/sampling-flamegraph-";
pub(crate) const SIDECAR_PRODUCER: &str = "lauterbach-stack-sampling-mcp/v1";
pub(crate) const CAPTURE_RECEIPT_PRODUCER: &str = "t32perf-stack-capture-receipt/v1";
pub(crate) const ANALYSIS_PRODUCER: &str = "t32perf-stack-analysis/v1";
pub(crate) const FLAMEGRAPH_PRODUCER: &str = "t32perf-stack-flamegraph/v1";

const RECEIPT_ID: &str = "sampling-stack-capture-receipt";
const RECEIPT_PATH: &str = "capture/sampling/stack-capture-receipt.json";
const RAW_ID: &str = "sampling-stack-samples";
const RAW_PATH: &str = "capture/sampling/stack-samples.json";
const PROFILE_ID: &str = "sampling-folded-stack-profile";
const PROFILE_PATH: &str = "analysis/sampling-folded-stack-profile.json";

struct JournalRecord {
    event: StackDriverEvent,
    bytes: Vec<u8>,
}

pub fn prepare(
    root: &ArtifactRoot,
    arguments: StackPrepareArgs,
) -> Result<CommandOutcome, AppError> {
    let request: StackCaptureRequest =
        strict_json::from_str(&arguments.capture_request).map_err(AppError::operational)?;
    request.validate().map_err(AppError::operational)?;
    let session = root
        .create_session_with_id(
            SessionId::new(&arguments.session).map_err(AppError::operational)?,
            &serde_json::to_value(&request).map_err(AppError::operational)?,
        )
        .map_err(AppError::from_session_store)?;
    let state = session.read_state().map_err(AppError::from_session_store)?;
    let mut stack_sampling_capture_arguments = json!({
        "session_id": session.id().as_str(), "operation_id": state.operation_id,
        "acknowledge_intrusive": true, "sample_period_ms": request.sample_period_ms,
        "duration_ms": request.duration_ms, "max_samples": request.max_samples,
        "max_frames": request.max_frames, "core_id": request.core_id,
        "address_space": request.address_space,
    });
    if let Some(digest) = request.deployed_firmware_elf_sha256 {
        stack_sampling_capture_arguments["deployed_firmware_elf_sha256"] = json!(digest);
    }
    Ok(outcome(
        "stack.prepare",
        json!({
            "session_id": session.id().as_str(), "state": state.status, "operation_id": state.operation_id,
            "request_sha256": session.request_sha256().map_err(AppError::from_session_store)?,
            "stack_sampling_capture_arguments": stack_sampling_capture_arguments,
        }),
    ))
}

pub fn ingest(root: &ArtifactRoot, arguments: StackIngestArgs) -> Result<CommandOutcome, AppError> {
    let session = root
        .session(&SessionId::new(&arguments.session).map_err(AppError::operational)?)
        .map_err(AppError::from_session_store)?;
    let lock = session.try_lock().map_err(AppError::from_session_store)?;
    let initial = session.read_state().map_err(AppError::from_session_store)?;
    if !matches!(
        initial.status,
        SessionStatus::Created | SessionStatus::Capturing | SessionStatus::Captured
    ) {
        return Err(AppError::operational(
            "stack ingest requires a created, capturing, or captured Session",
        ));
    }
    let request: StackCaptureRequest =
        serde_json::from_value(session.request().map_err(AppError::from_session_store)?)
            .map_err(AppError::operational)?;
    request.validate().map_err(AppError::operational)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::from_session_store)?;
    if artifacts
        .iter()
        .any(|a| a.id != RECEIPT_ID && a.id != RAW_ID)
    {
        return Err(AppError::operational(
            "stack ingest requires a dedicated Session without unrelated artifacts",
        ));
    }
    let (staged, session_staged) = staging_path(&arguments)?;
    let bytes = session
        .read_staged_bounded(&staged, MAX_JSON_BYTES)
        .map_err(AppError::from_session_store)?;
    let raw: StackSamples = strict_json::from_slice(&bytes).map_err(AppError::operational)?;
    raw.validate().map_err(AppError::operational)?;
    validate_raw_request(&raw, &request, &arguments.session)?;
    let digest = sha256(&bytes)?;
    let receipt = receipt_for(
        root,
        StackReceiptInput {
            raw: &raw,
            request: &request,
            staged: &session_staged,
            digest: &digest,
            size: bytes.len() as u64,
            operation_id: &initial.operation_id,
            request_sha256: session
                .request_sha256()
                .map_err(AppError::from_session_store)?,
        },
    )?;
    let receipt_artifact = commit_exact(
        &session,
        &lock,
        &artifacts,
        spec(
            RECEIPT_ID,
            CAPTURE_RECEIPT_KIND,
            RECEIPT_PATH,
            "application/json",
            CAPTURE_RECEIPT_PRODUCER,
            vec![],
        ),
        &json_bytes(&receipt)?,
    )?;
    if session
        .read_state()
        .map_err(AppError::from_session_store)?
        .status
        == SessionStatus::Created
    {
        session
            .transition(&lock, SessionStatus::Capturing, None)
            .map_err(AppError::from_session_store)?;
    }
    let host_staged = ArtifactPath::new("stack-host/stack-samples.json").expect("fixed path");
    session
        .ensure_staged_exact(&lock, &host_staged, &bytes, MAX_JSON_BYTES)
        .map_err(AppError::from_session_store)?;
    let raw_artifact = match session.ingest_staged_bounded(
        &lock,
        &host_staged,
        spec(
            RAW_ID,
            RAW_KIND,
            RAW_PATH,
            "application/json",
            SIDECAR_PRODUCER,
            vec![RECEIPT_ID.to_owned()],
        ),
        MAX_JSON_BYTES,
    ) {
        Ok(artifact) => artifact,
        Err(error) => {
            let inspections = session.inspect_ingest_intents();
            if !matches!(
                &error,
                t32perf_session::SessionStoreError::IngestIntentConflict { .. }
            ) && let Ok(inspections) = &inspections
                && !inspections.is_empty()
                && inspections.iter().all(is_recoverable_ingest_intent)
            {
                return Err(ingest_recovery_required(
                    &session,
                    initial.status,
                    &error,
                    inspections,
                ));
            }
            let durable_conflict = inspections.as_ref().map_or(true, |value| !value.is_empty());
            return Err(terminal_ingest_failure(
                &session,
                &lock,
                initial.status,
                durable_conflict,
                AppError::from_session_store(error),
            ));
        }
    };
    if raw_artifact.sha256 != digest || raw_artifact.size_bytes != bytes.len() as u64 {
        return Err(AppError::operational(
            "committed stack samples differ from journal-bound bytes",
        ));
    }
    let state = persist_ingest_captured_state(&session, &lock, initial)?;
    Ok(outcome(
        "stack.ingest",
        json!({"session_id": arguments.session, "status": state.status, "stack_samples_artifact": artifact_json(&raw_artifact), "capture_receipt_artifact": artifact_json(&receipt_artifact)}),
    ))
}

pub fn analyze(
    root: &ArtifactRoot,
    arguments: StackAnalyzeArgs,
) -> Result<CommandOutcome, AppError> {
    let session = captured(root, &arguments.session)?;
    let lock = session.try_lock().map_err(AppError::from_session_store)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::from_session_store)?;
    let (raw_artifact, raw) =
        verified_raw(&session, &artifacts, &arguments.stack_samples_artifact)?;
    let profile = build_folded_stack_profile(&raw, raw_artifact.sha256.clone())
        .map_err(AppError::operational)?;
    let artifact = commit_exact(
        &session,
        &lock,
        &artifacts,
        spec(
            PROFILE_ID,
            PROFILE_KIND,
            PROFILE_PATH,
            "application/json",
            ANALYSIS_PRODUCER,
            vec![RAW_ID.to_owned()],
        ),
        &json_bytes(&profile)?,
    )?;
    Ok(outcome(
        "stack.analyze",
        json!({"session_id": arguments.session, "artifact": artifact_json(&artifact), "intrusive": true, "statistical": true, "sample_measure": "halt_cycles_not_cpu_time"}),
    ))
}

pub fn summary(
    root: &ArtifactRoot,
    arguments: StackSummaryArgs,
) -> Result<CommandOutcome, AppError> {
    let session = captured(root, &arguments.session)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::from_session_store)?;
    let (_, raw) = verified_raw(&session, &artifacts, RAW_ID)?;
    let profile = canonical_profile(&session, &artifacts, &raw)?;
    let mut paths = profile.paths.clone();
    paths.sort_unstable_by(|a, b| {
        b.samples
            .cmp(&a.samples)
            .then_with(|| a.frames.cmp(&b.frames))
    });
    paths.truncate(arguments.top.into());
    Ok(outcome(
        "stack.summary",
        json!({"session_id": arguments.session, "intrusive": true, "statistical": true, "sample_measure": "halt_cycles_not_cpu_time", "collected_samples": profile.collected_samples, "terminal_unverified_samples": profile.terminal_unverified_samples, "truncated_samples": profile.truncated_samples, "rows": paths}),
    ))
}

pub fn render(root: &ArtifactRoot, arguments: StackRenderArgs) -> Result<CommandOutcome, AppError> {
    let session = captured(root, &arguments.session)?;
    let lock = session.try_lock().map_err(AppError::from_session_store)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::from_session_store)?;
    let (_, raw) = verified_raw(&session, &artifacts, RAW_ID)?;
    let profile = canonical_profile(&session, &artifacts, &raw)?;
    let document = render_stack_sampled_svg(
        &profile,
        StackFlameGraphOptions {
            max_depth: arguments.max_depth.into(),
            output_limit_bytes: MAX_OUTPUT_LIMIT_BYTES,
        },
    )
    .map_err(AppError::operational)?;
    let id = format!("sampling-flamegraph-svg-depth{:03}", arguments.max_depth);
    let path = format!(
        "report/sampling-flamegraph-depth{:03}.svg",
        arguments.max_depth
    );
    let artifact = commit_exact(
        &session,
        &lock,
        &artifacts,
        spec(
            &id,
            FLAMEGRAPH_KIND,
            &path,
            "image/svg+xml",
            FLAMEGRAPH_PRODUCER,
            vec![PROFILE_ID.to_owned()],
        ),
        document.svg.as_bytes(),
    )?;
    Ok(outcome(
        "stack.render",
        json!({"session_id": arguments.session, "artifact": artifact_json(&artifact), "rendered_frames": document.rendered_frames, "boundary_markers": document.boundary_markers, "other_markers": document.other_markers, "aggregated_nodes": document.aggregated_nodes, "omitted_depth": document.omitted_depth, "intrusive": true, "statistical": true, "sample_measure": "halt_cycles_not_cpu_time", "call_stack_evidence": true}),
    ))
}

fn staging_path(arguments: &StackIngestArgs) -> Result<(ArtifactPath, ArtifactPath), AppError> {
    let session_path = ArtifactPath::new(&arguments.staged).map_err(AppError::operational)?;
    let prefix = format!("capture/staging/stack-samples-{}-", arguments.session);
    let Some(suffix) = session_path
        .as_str()
        .strip_prefix(&prefix)
        .and_then(|s| s.strip_suffix(".json"))
    else {
        return Err(AppError::operational(
            "stack ingest requires the exact sidecar stack-samples staging path",
        ));
    };
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(AppError::operational(
            "stack sidecar staging filename has an invalid capture identifier",
        ));
    }
    Ok((
        ArtifactPath::new(
            session_path
                .as_str()
                .strip_prefix("capture/staging/")
                .expect("validated prefix"),
        )
        .map_err(AppError::operational)?,
        session_path,
    ))
}

fn validate_raw_request(
    raw: &StackSamples,
    request: &StackCaptureRequest,
    session: &str,
) -> Result<(), AppError> {
    if raw.session_id != session
        || raw.core_id != request.core_id
        || raw.address_space != request.address_space
        || raw.requested_duration_ms != request.duration_ms
        || raw.requested_sample_period_ms != request.sample_period_ms
        || raw.max_samples != request.max_samples
        || raw.max_frames != request.max_frames
    {
        return Err(AppError::operational(
            "stack samples do not exactly match the immutable capture request",
        ));
    }
    if raw.firmware.status != FirmwareBindingStatus::Unverified
        || raw.firmware.elf_sha256.is_some()
        || raw.firmware.proof.is_some()
    {
        return Err(AppError::operational(
            "stack sidecar may ingest only an unverified firmware binding",
        ));
    }
    Ok(())
}

struct StackReceiptInput<'a> {
    raw: &'a StackSamples,
    request: &'a StackCaptureRequest,
    staged: &'a ArtifactPath,
    digest: &'a Sha256Digest,
    size: u64,
    operation_id: &'a str,
    request_sha256: Sha256Digest,
}

fn receipt_for(
    root: &ArtifactRoot,
    input: StackReceiptInput<'_>,
) -> Result<StackCaptureReceipt, AppError> {
    let StackReceiptInput {
        raw,
        request,
        staged,
        digest,
        size,
        operation_id,
        request_sha256,
    } = input;
    validate_capture_attempt(root, raw, operation_id, &request_sha256)?;
    let records = read_events(root)?;
    let mut groups = BTreeMap::<String, Vec<JournalRecord>>::new();
    for record in records {
        groups
            .entry(record.event.transaction_id.clone())
            .or_default()
            .push(record);
    }
    let mut candidates = Vec::new();
    for (_, mut records) in groups {
        records.sort_unstable_by_key(|r| r.event.sequence);
        if records.iter().any(|r| matches!(&r.event.details, StackDriverEventDetails::ExportObserved { relative_path, sha256, size_bytes } if relative_path == staged && sha256 == digest && *size_bytes == size)) { candidates.push(records); }
    }
    let [records] = candidates.as_slice() else {
        return Err(AppError::operational(if candidates.is_empty() {
            "no stack journal transaction proves the staged stack-samples export"
        } else {
            "multiple stack journal transactions claim the staged stack-samples export"
        }));
    };
    let events = records.iter().map(|r| r.event.clone()).collect::<Vec<_>>();
    let binding =
        validate_successful_stack_event_sequence(&events).map_err(AppError::operational)?;
    if binding.relative_path != *staged
        || &binding.sha256 != digest
        || binding.size_bytes != size
        || binding.successful_sample_count != raw.collected_samples
        || binding.attempted_sample_count != raw.attempted_samples
        || binding.duration_ms != request.duration_ms
        || binding.sample_period_ms != request.sample_period_ms
        || binding.max_samples != request.max_samples
        || binding.max_frames != request.max_frames
        || events[0].endpoint_fingerprint != raw.endpoint_fingerprint
        || events[0].endpoint_fingerprint_scheme != raw.endpoint_fingerprint_scheme
    {
        return Err(AppError::operational(
            "stack journal does not exactly bind the accepted stack samples",
        ));
    }
    let chain = journal_chain(records)?;
    let receipt = StackCaptureReceipt {
        schema: StackCaptureReceiptSchemaVersion,
        session_id: raw.session_id.clone(),
        session_operation_id: operation_id.to_owned(),
        session_request_sha256: request_sha256,
        transaction_id: events[0].transaction_id.clone(),
        endpoint_fingerprint: raw.endpoint_fingerprint.clone(),
        endpoint_fingerprint_scheme: raw.endpoint_fingerprint_scheme,
        stack_samples_sha256: digest.clone(),
        stack_samples_size_bytes: size,
        journal_event_count: binding.event_count,
        journal_chain_sha256: chain,
        successful_sample_count: binding.successful_sample_count,
    };
    receipt.validate().map_err(AppError::operational)?;
    Ok(receipt)
}

fn validate_capture_attempt(
    root: &ArtifactRoot,
    raw: &StackSamples,
    operation_id: &str,
    request_sha256: &Sha256Digest,
) -> Result<(), AppError> {
    let directory = root.path().join(CAPTURE_ATTEMPTS_PATH);
    ensure_plain_directory(&directory, "stack capture-attempt directory")?;
    let path = directory.join(format!("{}.json", raw.session_id));
    let attempt: StackCaptureAttempt =
        strict_json::from_slice(&read_control_file(&path, MAX_STACK_EVENT_BYTES)?)
            .map_err(AppError::operational)?;
    attempt.validate().map_err(AppError::operational)?;
    if attempt.session_id != raw.session_id
        || attempt.operation_id != operation_id
        || &attempt.request_sha256 != request_sha256
        || attempt.endpoint_fingerprint != raw.endpoint_fingerprint
    {
        return Err(AppError::operational(
            "stack capture-attempt marker does not bind the accepted Session",
        ));
    }
    Ok(())
}

fn read_events(root: &ArtifactRoot) -> Result<Vec<JournalRecord>, AppError> {
    let directory = root.path().join(DRIVER_EVENTS_PATH);
    ensure_plain_directory(&directory, "stack driver-event directory")?;
    let mut paths = fs::read_dir(directory)
        .map_err(AppError::operational)?
        .map(|e| e.map(|x| x.path()).map_err(AppError::operational))
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort_unstable();
    if paths.len() > MAX_EVENTS {
        return Err(AppError::operational(
            "stack journal exceeds its bounded event limit",
        ));
    }
    let mut total_bytes = 0_u64;
    paths
        .into_iter()
        .map(|path| {
            if path.extension().and_then(|v| v.to_str()) != Some("json") {
                return Err(AppError::operational(
                    "stack journal contains a non-JSON entry",
                ));
            }
            let bytes = read_control_file(&path, MAX_STACK_EVENT_BYTES)?;
            total_bytes = total_bytes
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| AppError::operational("stack journal byte accounting overflow"))?;
            if total_bytes > MAX_JOURNAL_BYTES {
                return Err(AppError::operational(
                    "stack journal exceeds its total bounded byte limit",
                ));
            }
            let event: StackDriverEvent =
                strict_json::from_slice(&bytes).map_err(AppError::operational)?;
            event.validate().map_err(AppError::operational)?;
            let expected = format!("{}-{:08}.json", event.transaction_id, event.sequence);
            if path.file_name().and_then(|v| v.to_str()) != Some(&expected) {
                return Err(AppError::operational(
                    "stack journal filename does not match transaction and sequence",
                ));
            }
            Ok(JournalRecord { event, bytes })
        })
        .collect()
}

fn verified_raw<'a>(
    session: &Session,
    artifacts: &'a [Artifact],
    id: &str,
) -> Result<(&'a Artifact, StackSamples), AppError> {
    if id != RAW_ID {
        return Err(AppError::operational(
            "stack analysis requires the reserved stack-samples artifact",
        ));
    }
    let raw_artifact = required(artifacts, RAW_ID, RAW_KIND, RAW_PATH, SIDECAR_PRODUCER)?;
    if raw_artifact.input_artifact_ids != [RECEIPT_ID.to_owned()] {
        return Err(AppError::operational(
            "stack samples must directly reference their capture receipt",
        ));
    }
    let receipt_artifact = required(
        artifacts,
        RECEIPT_ID,
        CAPTURE_RECEIPT_KIND,
        RECEIPT_PATH,
        CAPTURE_RECEIPT_PRODUCER,
    )?;
    if !receipt_artifact.input_artifact_ids.is_empty() {
        return Err(AppError::operational(
            "stack capture receipt must not claim artifact inputs",
        ));
    }
    let receipt: StackCaptureReceipt = read_json(session, receipt_artifact, MAX_CONTROL_BYTES)?;
    receipt.validate().map_err(AppError::operational)?;
    let raw: StackSamples = read_json(session, raw_artifact, MAX_JSON_BYTES)?;
    raw.validate().map_err(AppError::operational)?;
    let request: StackCaptureRequest =
        serde_json::from_value(session.request().map_err(AppError::from_session_store)?)
            .map_err(AppError::operational)?;
    request.validate().map_err(AppError::operational)?;
    validate_raw_request(&raw, &request, session.id().as_str())?;
    let state = session.read_state().map_err(AppError::from_session_store)?;
    if receipt.session_id != session.id().as_str()
        || receipt.session_operation_id != state.operation_id
        || receipt.session_request_sha256
            != session
                .request_sha256()
                .map_err(AppError::from_session_store)?
        || receipt.stack_samples_sha256 != raw_artifact.sha256
        || receipt.stack_samples_size_bytes != raw_artifact.size_bytes
        || receipt.endpoint_fingerprint != raw.endpoint_fingerprint
        || receipt.endpoint_fingerprint_scheme != raw.endpoint_fingerprint_scheme
        || receipt.successful_sample_count != raw.collected_samples
    {
        return Err(AppError::operational(
            "stack capture receipt does not bind the selected Session and raw artifact",
        ));
    }
    Ok((raw_artifact, raw))
}

fn canonical_profile(
    session: &Session,
    artifacts: &[Artifact],
    raw: &StackSamples,
) -> Result<FoldedStackProfile, AppError> {
    let artifact = required(
        artifacts,
        PROFILE_ID,
        PROFILE_KIND,
        PROFILE_PATH,
        ANALYSIS_PRODUCER,
    )?;
    if artifact.input_artifact_ids != [RAW_ID.to_owned()] {
        return Err(AppError::operational(
            "folded stack profile must directly reference stack samples",
        ));
    }
    let stored = read_bytes(session, artifact, MAX_JSON_BYTES)?;
    let profile: FoldedStackProfile =
        strict_json::from_slice(&stored).map_err(AppError::operational)?;
    profile.validate().map_err(AppError::operational)?;
    let expected = build_folded_stack_profile(
        raw,
        artifacts
            .iter()
            .find(|a| a.id == RAW_ID)
            .expect("verified raw present")
            .sha256
            .clone(),
    )
    .map_err(AppError::operational)?;
    if json_bytes(&expected)? != stored {
        return Err(AppError::operational(
            "registered folded stack profile is not the canonical Host derivation",
        ));
    }
    Ok(profile)
}

fn captured(root: &ArtifactRoot, id: &str) -> Result<Session, AppError> {
    let session = root
        .session(&SessionId::new(id).map_err(AppError::operational)?)
        .map_err(AppError::from_session_store)?;
    if session
        .read_state()
        .map_err(AppError::from_session_store)?
        .status
        != SessionStatus::Captured
    {
        return Err(AppError::operational(
            "stack operations require a captured Session",
        ));
    }
    Ok(session)
}
fn required<'a>(
    artifacts: &'a [Artifact],
    id: &str,
    kind: &str,
    path: &str,
    producer: &str,
) -> Result<&'a Artifact, AppError> {
    let a = artifacts
        .iter()
        .find(|a| a.id == id)
        .ok_or_else(|| AppError::operational(format!("artifact `{id}` is not registered")))?;
    if a.kind != kind
        || a.relative_path.as_str() != path
        || a.media_type
            != if path.ends_with(".svg") {
                "image/svg+xml"
            } else {
                "application/json"
            }
        || a.producer != producer
    {
        return Err(AppError::operational(format!(
            "stack artifact `{id}` has an invalid reserved envelope"
        )));
    }
    Ok(a)
}
fn spec(
    id: &str,
    kind: &str,
    path: &str,
    media: &str,
    producer: &str,
    inputs: Vec<String>,
) -> ArtifactSpec {
    ArtifactSpec {
        id: id.to_owned(),
        kind: kind.to_owned(),
        relative_path: ArtifactPath::new(path).expect("fixed path"),
        media_type: media.to_owned(),
        producer: producer.to_owned(),
        input_artifact_ids: inputs,
    }
}
fn read_json<T: DeserializeOwned>(s: &Session, a: &Artifact, max: u64) -> Result<T, AppError> {
    strict_json::from_slice(&read_bytes(s, a, max)?).map_err(AppError::operational)
}
fn read_bytes(s: &Session, a: &Artifact, max: u64) -> Result<Vec<u8>, AppError> {
    if a.size_bytes > max {
        return Err(AppError::operational(
            "stack artifact exceeds bounded limit",
        ));
    }
    let mut f = s.open_artifact(a).map_err(AppError::from_session_store)?;
    let mut b = Vec::with_capacity(a.size_bytes as usize);
    (&mut f)
        .take(max + 1)
        .read_to_end(&mut b)
        .map_err(AppError::operational)?;
    if b.len() as u64 != a.size_bytes || b.len() as u64 > max {
        return Err(AppError::operational("stack artifact changed while read"));
    }
    Ok(b)
}
fn commit_exact(
    s: &Session,
    l: &SessionLock,
    as_: &[Artifact],
    sp: ArtifactSpec,
    b: &[u8],
) -> Result<Artifact, AppError> {
    if let Some(e) = as_.iter().find(|a| a.id == sp.id) {
        if e.kind == sp.kind
            && e.relative_path == sp.relative_path
            && e.media_type == sp.media_type
            && e.producer == sp.producer
            && e.input_artifact_ids == sp.input_artifact_ids
            && read_bytes(s, e, b.len() as u64)? == b
        {
            return Ok(e.clone());
        }
        return Err(AppError::operational(format!(
            "immutable stack artifact `{}` conflicts",
            e.id
        )));
    }
    let mut w = s
        .create_artifact(l, sp)
        .map_err(AppError::from_session_store)?;
    w.write_all(b).map_err(AppError::operational)?;
    s.commit_artifact(l, w)
        .map_err(AppError::from_session_store)
}
fn json_bytes<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, AppError> {
    let mut b = serde_json::to_vec_pretty(v).map_err(AppError::operational)?;
    b.push(b'\n');
    Ok(b)
}
fn sha256(b: &[u8]) -> Result<Sha256Digest, AppError> {
    let mut v = String::with_capacity(64);
    for x in Sha256::digest(b) {
        use std::fmt::Write as _;
        write!(&mut v, "{x:02x}").expect("String");
    }
    Sha256Digest::new(v).map_err(AppError::operational)
}
/// Domain-separated SHA-256 of ordered, length-delimited exact journal bytes.
///
/// Length prefixes make this unambiguous even if an event payload is changed to
/// contain another event's suffix.  The receipt binds the accepted raw endpoint
/// to the validated single transaction before this chain is computed.
fn journal_chain(records: &[JournalRecord]) -> Result<Sha256Digest, AppError> {
    let mut h = Sha256::new();
    h.update(b"t32perf.stack-driver-journal-chain/v1\0");
    for r in records {
        h.update(r.bytes.len().to_be_bytes());
        h.update(&r.bytes);
    }
    let mut v = String::with_capacity(64);
    for x in h.finalize() {
        use std::fmt::Write as _;
        write!(&mut v, "{x:02x}").expect("String");
    }
    Sha256Digest::new(v).map_err(AppError::operational)
}
fn read_control_file(path: &Path, max: u64) -> Result<Vec<u8>, AppError> {
    let mut f = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(AppError::operational)?;
    verify_opened_plain_file_identity(path, &f).map_err(AppError::from_session_store)?;
    let n = f.metadata().map_err(AppError::operational)?.len();
    if n == 0 || n > max {
        return Err(AppError::operational(
            "stack control document has invalid size",
        ));
    }
    let mut b = Vec::with_capacity(n as usize);
    (&mut f)
        .take(max + 1)
        .read_to_end(&mut b)
        .map_err(AppError::operational)?;
    if b.len() as u64 != n {
        return Err(AppError::operational(
            "stack control document changed while read",
        ));
    }
    Ok(b)
}
fn ensure_plain_directory(path: &Path, what: &str) -> Result<(), AppError> {
    let m = fs::symlink_metadata(path).map_err(AppError::operational)?;
    if !m.is_dir() || link_like(&m) {
        return Err(AppError::operational(format!(
            "{what} is not a plain directory"
        )));
    }
    Ok(())
}
fn link_like(m: &Metadata) -> bool {
    if m.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        m.file_attributes() & 0x0400 != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}
fn artifact_json(a: &Artifact) -> Value {
    json!({"id":a.id,"kind":a.kind,"path":a.relative_path,"sha256":a.sha256,"media_type":a.media_type,"producer":a.producer,"input_artifact_ids":a.input_artifact_ids})
}
fn outcome(command: &'static str, result: Value) -> CommandOutcome {
    CommandOutcome {
        command,
        result,
        exit_code: 0,
    }
}
