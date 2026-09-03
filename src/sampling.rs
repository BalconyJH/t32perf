//! Diagnostic-only projections of immutable TRACE32 PERF PC-hit histograms.
//!
//! This module intentionally does not control a target, emit Observation
//! events, or create an analysis-stage receipt.  Its artifacts remain a
//! separately labelled statistical diagnostic surface.

use std::{
    collections::BTreeMap,
    fs::{self, Metadata, OpenOptions},
    io::{Read as _, Write as _},
    path::Path,
};

use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use t32perf_analysis::{FunctionAddressRange, build_address_heatmap, build_function_heatmap};
use t32perf_flamegraph::{
    FlatFlameGraphOptions, MAX_OUTPUT_LIMIT_BYTES as MAX_FLAME_OUTPUT_LIMIT_BYTES,
    render_flat_sampled_svg,
};
use t32perf_heatmap::{
    MAX_OUTPUT_LIMIT_BYTES as MAX_HEATMAP_OUTPUT_LIMIT_BYTES, SvgRenderOptions, render_svg,
};
use t32perf_model::{
    Artifact, ArtifactPath, FirmwareBindingEvidence, FirmwareBindingEvidenceResult,
    FirmwareBindingProof, FirmwareBindingProofKind, FirmwareBindingStatus, Heatmap,
    HeatmapProjectionKind, PcHitHistogram, PcSamplingMethod, SamplingCaptureReceipt,
    SamplingCaptureReceiptSchemaVersion, SamplingCaptureRequest, SamplingConfigureMethod,
    SamplingDriverEvent, SamplingDriverEventDetails, SamplingDriverEventName,
    SamplingEndpointBinding, SamplingJournalEventClaim, SamplingMethodPolicy, SessionStatus,
    Sha256Digest, strict_json,
};
use t32perf_session::{
    ArtifactRoot, ArtifactSpec, Session, SessionStoreError, verify_opened_plain_file_identity,
};
use t32perf_trace32::sampling_function_ranges_from_elf;

use crate::{
    app::{
        AppError, CommandOutcome, ensure_controller_capture_complete_for_ingest,
        ingest_recovery_required, is_recoverable_ingest_intent, persist_ingest_captured_state,
        terminal_ingest_failure,
    },
    cli::{
        SamplingAnalyzeArgs, SamplingBindFirmwareArgs, SamplingFlameArgs, SamplingIngestArgs,
        SamplingPrepareArgs, SamplingProjection, SamplingRenderArgs, SamplingSummaryArgs,
    },
};

const MAX_HISTOGRAM_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ELF_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FIRMWARE_EVIDENCE_BYTES: u64 = 1024 * 1024;
const MAX_CONTROL_DOCUMENT_BYTES: u64 = 64 * 1024;
const MAX_SAMPLING_DRIVER_EVENTS: usize = 16_384;

pub(crate) const ARTIFACT_ID_PREFIX: &str = "sampling-";
pub(crate) const HISTOGRAM_KIND: &str = "pc_hit_histogram";
pub(crate) const CAPTURE_RECEIPT_KIND: &str = "sampling_capture_receipt";
pub(crate) const FIRMWARE_EVIDENCE_KIND: &str = "firmware_binding_evidence";
pub(crate) const HEATMAP_KIND: &str = "heatmap";
pub(crate) const FLAT_PROFILE_KIND: &str = "flat_sampled_profile";
pub(crate) const CAPTURE_ARTIFACT_PATH_PREFIX: &str = "capture/sampling/";
pub(crate) const ANALYSIS_ARTIFACT_PATH_PREFIX: &str = "analysis/sampling-";
pub(crate) const REPORT_ARTIFACT_PATH_PREFIX: &str = "report/sampling-";
pub(crate) const SIDECAR_PRODUCER: &str = "lauterbach-sampling-mcp/v1";
pub(crate) const CAPTURE_RECEIPT_PRODUCER: &str = "t32perf-sampling-capture-receipt/v1";
pub(crate) const FIRMWARE_ELF_PRODUCER: &str = "t32perf-sampling-firmware-elf/v1";
pub(crate) const FIRMWARE_EVIDENCE_PRODUCER: &str = "t32perf-sampling-firmware-evidence/v1";
pub(crate) const ANALYSIS_PRODUCER: &str = "t32perf-sampling-analysis/v1";
pub(crate) const FLAT_PROFILE_PRODUCER: &str = "t32perf-flat-profile-renderer/v1";

const HISTOGRAM_ID: &str = "sampling-pc-hit-histogram";
const HISTOGRAM_PATH: &str = "capture/sampling/pc-hit-histogram.json";
const CAPTURE_RECEIPT_ID: &str = "sampling-capture-receipt";
const CAPTURE_RECEIPT_PATH: &str = "capture/sampling/capture-receipt.json";
const FIRMWARE_EVIDENCE_ID: &str = "sampling-firmware-binding-evidence";
const FIRMWARE_EVIDENCE_PATH: &str = "capture/sampling/firmware-binding-evidence.json";
const FIRMWARE_ELF_ID: &str = "firmware-elf";
const FIRMWARE_ELF_PATH: &str = "capture/firmware.elf";
const HOST_STAGING_HISTOGRAM: &str = "sampling-host/pc-hit-histogram.json";
const ENDPOINT_BINDING_PATH: &str = ".t32perf-control/sampling-endpoint-binding.json";
const DRIVER_EVENTS_PATH: &str = ".t32perf-control/sampling-driver-events";

struct JournalRecord {
    event: SamplingDriverEvent,
    bytes: Vec<u8>,
}

/// Prevents any cooperating TRACE32 driver from crossing a durable sampling quarantine.
pub(crate) fn ensure_endpoint_not_quarantined(root: &ArtifactRoot) -> Result<(), AppError> {
    let directory = root.path().join(DRIVER_EVENTS_PATH);
    match fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(AppError::operational(error)),
        Ok(_) => {}
    }
    let records = read_driver_events(root)?;
    if let Some(first) = records.first() {
        let binding: SamplingEndpointBinding = read_control_json(
            &root.path().join(ENDPOINT_BINDING_PATH),
            MAX_CONTROL_DOCUMENT_BYTES,
        )?;
        binding.validate().map_err(AppError::operational)?;
        if records.iter().any(|record| {
            record.event.endpoint_fingerprint != binding.endpoint_fingerprint
                || record.event.endpoint_fingerprint_scheme != binding.endpoint_fingerprint_scheme
        }) {
            return Err(sampling_quarantine_error(
                &first.event.transaction_id,
                "journal endpoint does not match the root binding",
            ));
        }
    }
    let mut grouped = BTreeMap::<String, Vec<SamplingDriverEvent>>::new();
    for record in records {
        grouped
            .entry(record.event.transaction_id.clone())
            .or_default()
            .push(record.event);
    }
    let mut quarantined = Vec::new();
    for (transaction_id, mut events) in grouped {
        events.sort_unstable_by_key(|event| event.sequence);
        if events
            .iter()
            .enumerate()
            .any(|(index, event)| event.sequence != (index + 1) as u64)
        {
            return Err(sampling_quarantine_error(
                &transaction_id,
                "journal sequence is ambiguous",
            ));
        }
        validate_quarantine_projection(&events)
            .map_err(|reason| sampling_quarantine_error(&transaction_id, reason))?;
        let cleanup_outcome = events.iter().rev().find_map(|event| match event.details {
            SamplingDriverEventDetails::CleanupObserved {} => Some("cleanup_observed"),
            SamplingDriverEventDetails::RecoveryObserved { .. } => Some("recovery_observed"),
            SamplingDriverEventDetails::CleanupFailed { .. } => Some("cleanup_failed"),
            _ => None,
        });
        if !matches!(
            cleanup_outcome,
            Some("cleanup_observed" | "recovery_observed")
        ) {
            quarantined.push((transaction_id, cleanup_outcome.unwrap_or("incomplete")));
        }
    }
    if let Some((transaction_id, reason)) = quarantined.first() {
        return Err(sampling_quarantine_error(transaction_id, reason));
    }
    Ok(())
}

fn validate_quarantine_projection(events: &[SamplingDriverEvent]) -> Result<(), &'static str> {
    #[derive(Clone, Copy)]
    enum Phase {
        Initial,
        Configuring(SamplingConfigureMethod),
        Configured,
        StartPending,
        Started,
        StopPending,
        Stopped,
        CleanupPending { recovery: bool },
        CleanupFailed,
        CleanupObserved,
        RecoveryObserved,
        ExportPending,
        Exported,
    }

    let mut phase = Phase::Initial;
    for event in events {
        phase = match (phase, &event.details) {
            (Phase::Initial, SamplingDriverEventDetails::ConfigureIntent { method }) => {
                Phase::Configuring(*method)
            }
            (
                Phase::Configuring(expected),
                SamplingDriverEventDetails::ConfigureObserved { method },
            ) if *method == expected => Phase::Configured,
            (Phase::Configured, SamplingDriverEventDetails::StartIntent { .. }) => {
                Phase::StartPending
            }
            (Phase::StartPending, SamplingDriverEventDetails::StartObserved {}) => Phase::Started,
            (Phase::Started, SamplingDriverEventDetails::StopIntent {}) => Phase::StopPending,
            (Phase::StopPending, SamplingDriverEventDetails::StopObserved {}) => Phase::Stopped,
            (
                Phase::Configuring(_)
                | Phase::Configured
                | Phase::StartPending
                | Phase::Started
                | Phase::StopPending
                | Phase::Stopped,
                SamplingDriverEventDetails::CleanupIntent { recovery },
            ) => Phase::CleanupPending {
                recovery: recovery.is_some(),
            },
            (
                Phase::CleanupPending { .. } | Phase::CleanupFailed,
                SamplingDriverEventDetails::CleanupIntent { recovery: Some(_) },
            ) => Phase::CleanupPending { recovery: true },
            (
                Phase::CleanupPending { recovery: false },
                SamplingDriverEventDetails::CleanupObserved {},
            ) => Phase::CleanupObserved,
            (Phase::CleanupPending { .. }, SamplingDriverEventDetails::CleanupFailed { .. }) => {
                Phase::CleanupFailed
            }
            (
                Phase::CleanupPending { recovery: true },
                SamplingDriverEventDetails::RecoveryObserved { .. },
            ) => Phase::RecoveryObserved,
            (Phase::CleanupObserved, SamplingDriverEventDetails::ExportIntent {}) => {
                Phase::ExportPending
            }
            (Phase::ExportPending, SamplingDriverEventDetails::ExportObserved { .. }) => {
                Phase::Exported
            }
            _ => return Err("journal event order is invalid"),
        };
    }
    Ok(())
}

fn sampling_quarantine_error(transaction_id: &str, reason: &str) -> AppError {
    AppError {
        code: "SAMPLING_ENDPOINT_QUARANTINED",
        message: "TRACE32 endpoint is blocked by an incomplete sampling transaction".to_owned(),
        details: json!({
            "transaction_id": transaction_id,
            "reason": reason,
            "recovery": "restart the sampling sidecar with --recover-quarantined under deployment control",
        }),
        exit_code: crate::app::EXIT_OPERATIONAL,
    }
}

/// Creates one immutable Host authorization for a sampling-sidecar call.
pub fn prepare(
    root: &ArtifactRoot,
    arguments: SamplingPrepareArgs,
) -> Result<CommandOutcome, AppError> {
    let request: SamplingCaptureRequest =
        strict_json::from_str(&arguments.capture_request).map_err(AppError::operational)?;
    request.validate().map_err(AppError::operational)?;
    let request_value = serde_json::to_value(&request).map_err(AppError::operational)?;
    let session = root
        .create_session_with_id(
            t32perf_session::SessionId::new(&arguments.session).map_err(AppError::operational)?,
            &request_value,
        )
        .map_err(AppError::from_session_store)?;
    let state = session.read_state().map_err(AppError::from_session_store)?;
    let request_sha256 = session
        .request_sha256()
        .map_err(AppError::from_session_store)?;
    let mut sampling_capture_arguments = json!({
        "session_id": session.id().as_str(),
        "operation_id": state.operation_id,
        "ranges": request.ranges,
        "bucket_size": request.bucket_size,
        "duration_ms": request.duration_ms,
        "method_policy": request.method_policy,
        "core_id": request.core_id,
        "address_space": request.address_space,
    });
    if let Some(digest) = request.deployed_firmware_elf_sha256 {
        sampling_capture_arguments["deployed_firmware_elf_sha256"] = json!(digest);
    }
    Ok(outcome(
        "sampling.prepare",
        json!({
            "session_id": session.id().as_str(),
            "state": state.status,
            "operation_id": state.operation_id,
            "request_sha256": request_sha256,
            "sampling_capture_arguments": sampling_capture_arguments,
        }),
    ))
}

/// Accepts one exact sidecar export through the Host's reserved capture boundary.
pub fn ingest(
    root: &ArtifactRoot,
    arguments: SamplingIngestArgs,
) -> Result<CommandOutcome, AppError> {
    let session = root
        .session(
            &t32perf_session::SessionId::new(&arguments.session).map_err(AppError::operational)?,
        )
        .map_err(AppError::from_session_store)?;
    let lock = session.try_lock().map_err(AppError::from_session_store)?;
    let initial = session.read_state().map_err(AppError::from_session_store)?;
    if !matches!(
        initial.status,
        SessionStatus::Created | SessionStatus::Capturing | SessionStatus::Captured
    ) {
        return Err(AppError::operational(format!(
            "sampling ingest requires a created, capturing, or captured Session; current status is {:?}",
            initial.status
        )));
    }
    let capture_request: SamplingCaptureRequest =
        serde_json::from_value(session.request().map_err(AppError::from_session_store)?)
            .map_err(AppError::operational)?;
    capture_request.validate().map_err(AppError::operational)?;
    let session_request_sha256 = session
        .request_sha256()
        .map_err(AppError::from_session_store)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::from_session_store)?;
    if artifacts
        .iter()
        .any(|artifact| !matches!(artifact.id.as_str(), CAPTURE_RECEIPT_ID | HISTOGRAM_ID))
    {
        return Err(AppError::operational(
            "sampling ingest requires a dedicated Session without unrelated artifacts",
        ));
    }
    ensure_controller_capture_complete_for_ingest(root, &session, &artifacts)?;

    let (staged, session_relative_staged) = sidecar_staging_path(&arguments)?;
    let source_bytes = session
        .read_staged_bounded(&staged, MAX_HISTOGRAM_BYTES)
        .map_err(AppError::from_session_store)?;
    let histogram: PcHitHistogram =
        strict_json::from_slice(&source_bytes).map_err(AppError::operational)?;
    histogram.validate().map_err(AppError::operational)?;
    ensure_session(&histogram.session_id, &arguments.session)?;
    validate_histogram_request(&histogram, &capture_request)?;
    if histogram.firmware.status != FirmwareBindingStatus::Unverified
        || histogram.firmware.elf_sha256.is_some()
        || histogram.firmware.proof.is_some()
    {
        return Err(AppError::operational(
            "the v1 sampling sidecar may ingest only an unverified firmware binding",
        ));
    }
    let source_digest = sha256(&source_bytes)?;
    let receipt = capture_receipt(
        root,
        &histogram,
        &session_relative_staged,
        source_digest.clone(),
        u64::try_from(source_bytes.len()).unwrap_or(u64::MAX),
        &initial.operation_id,
        session_request_sha256,
    )?;
    let receipt_bytes = json_bytes(&receipt)?;
    let receipt_spec = ArtifactSpec {
        id: CAPTURE_RECEIPT_ID.to_owned(),
        kind: CAPTURE_RECEIPT_KIND.to_owned(),
        relative_path: ArtifactPath::new(CAPTURE_RECEIPT_PATH).expect("fixed valid path"),
        media_type: "application/json".to_owned(),
        producer: CAPTURE_RECEIPT_PRODUCER.to_owned(),
        input_artifact_ids: Vec::new(),
    };
    let receipt_artifact = commit_exact(&session, &lock, &artifacts, receipt_spec, &receipt_bytes)?;

    let current = session.read_state().map_err(AppError::from_session_store)?;
    if current.status == SessionStatus::Created {
        session
            .transition(&lock, SessionStatus::Capturing, None)
            .map_err(AppError::from_session_store)?;
    }
    let host_staged = ArtifactPath::new(HOST_STAGING_HISTOGRAM).expect("fixed valid path");
    session
        .ensure_staged_exact(&lock, &host_staged, &source_bytes, MAX_HISTOGRAM_BYTES)
        .map_err(AppError::from_session_store)?;
    let histogram_spec = ArtifactSpec {
        id: HISTOGRAM_ID.to_owned(),
        kind: HISTOGRAM_KIND.to_owned(),
        relative_path: ArtifactPath::new(HISTOGRAM_PATH).expect("fixed valid path"),
        media_type: "application/json".to_owned(),
        producer: SIDECAR_PRODUCER.to_owned(),
        input_artifact_ids: vec![receipt_artifact.id.clone()],
    };
    let histogram_artifact = match session.ingest_staged_bounded(
        &lock,
        &host_staged,
        histogram_spec,
        MAX_HISTOGRAM_BYTES,
    ) {
        Ok(artifact) => artifact,
        Err(error) => {
            let inspections = session.inspect_ingest_intents();
            if !matches!(&error, SessionStoreError::IngestIntentConflict { .. })
                && let Ok(inspections) = &inspections
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
            let durable_conflict = inspections
                .as_ref()
                .map_or(true, |inspections| !inspections.is_empty());
            return Err(terminal_ingest_failure(
                &session,
                &lock,
                initial.status,
                durable_conflict,
                AppError::from_session_store(error),
            ));
        }
    };
    if histogram_artifact.sha256 != source_digest
        || histogram_artifact.size_bytes != u64::try_from(source_bytes.len()).unwrap_or(u64::MAX)
    {
        return Err(terminal_ingest_failure(
            &session,
            &lock,
            initial.status,
            true,
            AppError::operational(
                "committed sampling histogram differs from the journal-bound sidecar bytes",
            ),
        ));
    }
    let state = persist_ingest_captured_state(&session, &lock, initial)?;
    Ok(outcome(
        "sampling.ingest",
        json!({
            "session_id": arguments.session,
            "status": state.status,
            "histogram_artifact": artifact_json(&histogram_artifact),
            "capture_receipt_artifact": artifact_json(&receipt_artifact),
        }),
    ))
}

fn sidecar_staging_path(
    arguments: &SamplingIngestArgs,
) -> Result<(ArtifactPath, ArtifactPath), AppError> {
    let session_relative = ArtifactPath::new(&arguments.staged).map_err(AppError::operational)?;
    let expected_prefix = format!("capture/staging/pc-hit-histogram-{}-", arguments.session);
    let Some(filename_suffix) = session_relative.as_str().strip_prefix(&expected_prefix) else {
        return Err(AppError::operational(
            "sampling ingest requires the exact sidecar histogram staging path",
        ));
    };
    let Some(identifier) = filename_suffix.strip_suffix(".json") else {
        return Err(AppError::operational(
            "sampling sidecar staging path must end in .json",
        ));
    };
    if identifier.len() != 32
        || !identifier
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AppError::operational(
            "sampling sidecar staging filename has an invalid capture identifier",
        ));
    }
    let relative = session_relative
        .as_str()
        .strip_prefix("capture/staging/")
        .expect("validated sidecar prefix");
    Ok((
        ArtifactPath::new(relative).map_err(AppError::operational)?,
        session_relative,
    ))
}

fn validate_histogram_request(
    histogram: &PcHitHistogram,
    request: &SamplingCaptureRequest,
) -> Result<(), AppError> {
    let requested_duration_ns = u64::from(request.duration_ms)
        .checked_mul(1_000_000)
        .ok_or_else(|| AppError::operational("sampling request duration overflow"))?;
    if histogram.requested_duration_ns != requested_duration_ns
        || histogram.core_id != request.core_id
        || histogram.address_space != "P"
    {
        return Err(AppError::operational(
            "sampling histogram does not match the authorized duration, core, and address space",
        ));
    }
    if matches!(histogram.method, PcSamplingMethod::StopAndGo { .. })
        && request.method_policy != SamplingMethodPolicy::AllowStopAndGo
    {
        return Err(AppError::operational(
            "sampling histogram used StopAndGo without request authorization",
        ));
    }
    let expected_buckets = request.buckets().map_err(AppError::operational)?;
    if histogram.buckets.len() != expected_buckets.len()
        || histogram
            .buckets
            .iter()
            .zip(expected_buckets)
            .any(|(actual, expected)| {
                actual.start_address != expected.start_address
                    || actual.end_address != expected.end_address
            })
    {
        return Err(AppError::operational(
            "sampling histogram buckets do not match the authorized ranges and bucket size",
        ));
    }
    Ok(())
}

fn capture_receipt(
    root: &ArtifactRoot,
    histogram: &PcHitHistogram,
    staged_relative_path: &ArtifactPath,
    histogram_sha256: Sha256Digest,
    histogram_size_bytes: u64,
    session_operation_id: &str,
    session_request_sha256: Sha256Digest,
) -> Result<SamplingCaptureReceipt, AppError> {
    let binding: SamplingEndpointBinding = read_control_json(
        &root.path().join(ENDPOINT_BINDING_PATH),
        MAX_CONTROL_DOCUMENT_BYTES,
    )?;
    binding.validate().map_err(AppError::operational)?;
    if binding.endpoint_fingerprint != histogram.endpoint_fingerprint {
        return Err(AppError::operational(
            "sampling endpoint binding does not match the histogram endpoint",
        ));
    }
    if binding.endpoint_fingerprint_scheme != histogram.endpoint_fingerprint_scheme {
        return Err(AppError::operational(
            "sampling endpoint fingerprint scheme does not match the histogram endpoint",
        ));
    }

    let records = read_driver_events(root)?;
    let mut by_transaction = BTreeMap::<String, Vec<JournalRecord>>::new();
    for record in records {
        by_transaction
            .entry(record.event.transaction_id.clone())
            .or_default()
            .push(record);
    }
    let mut candidates = Vec::new();
    for (transaction_id, mut records) in by_transaction {
        if records.iter().any(|record| {
            matches!(
                &record.event.details,
                SamplingDriverEventDetails::ExportObserved {
                    relative_path,
                    sha256,
                    size_bytes,
                } if relative_path == staged_relative_path
                    && sha256 == &histogram_sha256
                    && *size_bytes == histogram_size_bytes
            )
        }) {
            records.sort_unstable_by_key(|record| record.event.sequence);
            candidates.push((transaction_id, records));
        }
    }
    let [(transaction_id, records)] = candidates.as_slice() else {
        return Err(AppError::operational(if candidates.is_empty() {
            "no sampling journal transaction proves the staged histogram export"
        } else {
            "multiple sampling journal transactions claim the staged histogram export"
        }));
    };
    validate_successful_journal(
        records,
        histogram,
        staged_relative_path,
        &histogram_sha256,
        histogram_size_bytes,
    )?;
    let journal_event_claims = records
        .iter()
        .map(|record| {
            Ok(SamplingJournalEventClaim {
                sequence: record.event.sequence,
                event: event_name(&record.event.details),
                sha256: sha256(&record.bytes)?,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    let receipt = SamplingCaptureReceipt {
        schema: SamplingCaptureReceiptSchemaVersion,
        session_id: histogram.session_id.clone(),
        session_operation_id: session_operation_id.to_owned(),
        transaction_id: transaction_id.clone(),
        endpoint_fingerprint: histogram.endpoint_fingerprint.clone(),
        endpoint_fingerprint_scheme: histogram.endpoint_fingerprint_scheme,
        session_request_sha256,
        histogram_sha256,
        histogram_size_bytes,
        journal_event_claims,
    };
    receipt.validate().map_err(AppError::operational)?;
    Ok(receipt)
}

fn read_driver_events(root: &ArtifactRoot) -> Result<Vec<JournalRecord>, AppError> {
    let directory = root.path().join(DRIVER_EVENTS_PATH);
    ensure_plain_directory(&directory, "sampling driver-event directory")?;
    let mut paths = fs::read_dir(&directory)
        .map_err(AppError::operational)?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(AppError::operational)
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort_unstable();
    if paths.len() > MAX_SAMPLING_DRIVER_EVENTS {
        return Err(AppError::operational(format!(
            "sampling journal contains {} events; maximum is {MAX_SAMPLING_DRIVER_EVENTS}",
            paths.len()
        )));
    }
    let mut records = Vec::with_capacity(paths.len());
    for path in paths {
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            return Err(AppError::operational(
                "sampling journal contains a non-JSON directory entry",
            ));
        }
        let bytes = read_control_file(&path, MAX_CONTROL_DOCUMENT_BYTES)?;
        let event: SamplingDriverEvent =
            strict_json::from_slice(&bytes).map_err(AppError::operational)?;
        event.validate().map_err(AppError::operational)?;
        let expected_filename = format!("{}-{:08}.json", event.transaction_id, event.sequence);
        if path.file_name().and_then(|value| value.to_str()) != Some(&expected_filename) {
            return Err(AppError::operational(
                "sampling journal filename does not match its transaction and sequence",
            ));
        }
        records.push(JournalRecord { event, bytes });
    }
    Ok(records)
}

fn validate_successful_journal(
    records: &[JournalRecord],
    histogram: &PcHitHistogram,
    staged_relative_path: &ArtifactPath,
    histogram_sha256: &Sha256Digest,
    histogram_size_bytes: u64,
) -> Result<(), AppError> {
    if records.len() != 10 {
        return Err(AppError::operational(
            "sampling export transaction is not the exact ten-event success sequence",
        ));
    }
    let endpoint = &histogram.endpoint_fingerprint;
    let transaction_id = &records[0].event.transaction_id;
    for (index, record) in records.iter().enumerate() {
        if record.event.sequence != (index + 1) as u64
            || &record.event.endpoint_fingerprint != endpoint
            || record.event.endpoint_fingerprint_scheme != histogram.endpoint_fingerprint_scheme
            || &record.event.transaction_id != transaction_id
        {
            return Err(AppError::operational(
                "sampling journal transaction identity or sequence is inconsistent",
            ));
        }
    }
    let method = match histogram.method {
        PcSamplingMethod::Realtime => SamplingConfigureMethod::Realtime,
        PcSamplingMethod::StopAndGo { .. } => SamplingConfigureMethod::StopAndGo,
    };
    let duration_ms = histogram
        .requested_duration_ns
        .checked_div(1_000_000)
        .filter(|duration| {
            duration.saturating_mul(1_000_000) == histogram.requested_duration_ns
                && (1..=60_000).contains(duration)
        })
        .ok_or_else(|| {
            AppError::operational(
                "histogram requested duration does not match the sidecar millisecond contract",
            )
        })?;
    let expected = [
        matches!(
            records[0].event.details,
            SamplingDriverEventDetails::ConfigureIntent { method: actual } if actual == method
        ),
        matches!(
            records[1].event.details,
            SamplingDriverEventDetails::ConfigureObserved { method: actual } if actual == method
        ),
        matches!(
            records[2].event.details,
            SamplingDriverEventDetails::StartIntent { duration_ms: actual }
                if u64::from(actual) == duration_ms
        ),
        matches!(
            records[3].event.details,
            SamplingDriverEventDetails::StartObserved {}
        ),
        matches!(
            records[4].event.details,
            SamplingDriverEventDetails::StopIntent {}
        ),
        matches!(
            records[5].event.details,
            SamplingDriverEventDetails::StopObserved {}
        ),
        matches!(
            records[6].event.details,
            SamplingDriverEventDetails::CleanupIntent { recovery: None }
        ),
        matches!(
            records[7].event.details,
            SamplingDriverEventDetails::CleanupObserved {}
        ),
        matches!(
            records[8].event.details,
            SamplingDriverEventDetails::ExportIntent {}
        ),
        matches!(
            &records[9].event.details,
            SamplingDriverEventDetails::ExportObserved {
                relative_path,
                sha256,
                size_bytes,
            } if relative_path == staged_relative_path
                && sha256 == histogram_sha256
                && *size_bytes == histogram_size_bytes
        ),
    ];
    if expected.iter().any(|matches| !matches) {
        return Err(AppError::operational(
            "sampling journal does not bind the exact successful method, duration, cleanup, and export",
        ));
    }
    Ok(())
}

fn event_name(details: &SamplingDriverEventDetails) -> SamplingDriverEventName {
    match details {
        SamplingDriverEventDetails::ConfigureIntent { .. } => {
            SamplingDriverEventName::ConfigureIntent
        }
        SamplingDriverEventDetails::ConfigureObserved { .. } => {
            SamplingDriverEventName::ConfigureObserved
        }
        SamplingDriverEventDetails::StartIntent { .. } => SamplingDriverEventName::StartIntent,
        SamplingDriverEventDetails::StartObserved {} => SamplingDriverEventName::StartObserved,
        SamplingDriverEventDetails::StopIntent {} => SamplingDriverEventName::StopIntent,
        SamplingDriverEventDetails::StopObserved {} => SamplingDriverEventName::StopObserved,
        SamplingDriverEventDetails::CleanupIntent { .. } => SamplingDriverEventName::CleanupIntent,
        SamplingDriverEventDetails::CleanupObserved {} => SamplingDriverEventName::CleanupObserved,
        SamplingDriverEventDetails::CleanupFailed { .. } => SamplingDriverEventName::CleanupFailed,
        SamplingDriverEventDetails::RecoveryObserved { .. } => {
            SamplingDriverEventName::RecoveryObserved
        }
        SamplingDriverEventDetails::ExportIntent {} => SamplingDriverEventName::ExportIntent,
        SamplingDriverEventDetails::ExportObserved { .. } => {
            SamplingDriverEventName::ExportObserved
        }
    }
}

fn read_control_json<T: DeserializeOwned>(path: &Path, maximum: u64) -> Result<T, AppError> {
    strict_json::from_slice(&read_control_file(path, maximum)?).map_err(AppError::operational)
}

fn read_control_file(path: &Path, maximum: u64) -> Result<Vec<u8>, AppError> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(AppError::operational)?;
    verify_opened_plain_file_identity(path, &file).map_err(AppError::from_session_store)?;
    let size = file.metadata().map_err(AppError::operational)?.len();
    if size == 0 || size > maximum {
        return Err(AppError::operational(format!(
            "sampling control document `{}` has invalid size {size}",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
    (&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(AppError::operational)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != size {
        return Err(AppError::operational(
            "sampling control document changed while it was read",
        ));
    }
    Ok(bytes)
}

fn ensure_plain_directory(path: &Path, description: &str) -> Result<(), AppError> {
    let metadata = fs::symlink_metadata(path).map_err(AppError::operational)?;
    if !metadata.is_dir() || is_link_like(&metadata) {
        return Err(AppError::operational(format!(
            "{description} `{}` is not a plain directory",
            path.display()
        )));
    }
    Ok(())
}

fn is_link_like(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

fn sha256(bytes: &[u8]) -> Result<Sha256Digest, AppError> {
    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    Sha256Digest::new(encoded).map_err(AppError::operational)
}

/// Records a deployment-bound ELF whose digest was committed in the immutable
/// sampling request. The sidecar histogram stays unmodified and unverified;
/// symbol projection constructs its deployment-asserted binding in memory from this
/// evidence.
pub fn bind_firmware(
    root: &ArtifactRoot,
    arguments: SamplingBindFirmwareArgs,
) -> Result<CommandOutcome, AppError> {
    let session = open_captured(root, &arguments.session)?;
    let lock = session.try_lock().map_err(AppError::from_session_store)?;
    ensure_captured(&session)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::from_session_store)?;
    let histogram_artifact =
        required_sampling_histogram(&session, &artifacts, HISTOGRAM_ID, &arguments.session)?;
    let histogram: PcHitHistogram = read_json(&session, histogram_artifact, MAX_HISTOGRAM_BYTES)?;
    if histogram.firmware.status != FirmwareBindingStatus::Unverified
        || histogram.firmware.elf_sha256.is_some()
        || histogram.firmware.proof.is_some()
    {
        return Err(AppError::operational(
            "sampling firmware binding requires the exact unverified sidecar histogram",
        ));
    }
    ensure_cortex_m_cpu(&histogram.cpu)?;
    let request: SamplingCaptureRequest =
        serde_json::from_value(session.request().map_err(AppError::from_session_store)?)
            .map_err(AppError::operational)?;
    request.validate().map_err(AppError::operational)?;
    let expected_digest = request.deployed_firmware_elf_sha256.as_ref().ok_or_else(|| {
        AppError::operational(
            "sampling firmware binding requires deployed_firmware_elf_sha256 in the immutable capture request",
        )
    })?;
    if artifacts
        .iter()
        .any(|artifact| artifact.id == FIRMWARE_EVIDENCE_ID)
        && !artifacts
            .iter()
            .any(|artifact| artifact.id == FIRMWARE_ELF_ID)
    {
        return Err(AppError::operational(
            "sampling firmware evidence exists without its immutable ELF input",
        ));
    }
    let elf_artifact = if artifacts
        .iter()
        .any(|artifact| artifact.id == FIRMWARE_ELF_ID)
    {
        let existing = required_sampling_elf(&artifacts, FIRMWARE_ELF_ID)?;
        if &existing.sha256 != expected_digest {
            return Err(AppError::operational(
                "registered firmware ELF digest does not match the immutable capture request",
            ));
        }
        let elf = read_bytes(&session, existing, MAX_ELF_BYTES)?;
        sampling_function_ranges_from_elf(
            &elf,
            "firmware",
            t32perf_analysis::MAX_FUNCTION_ADDRESS_RANGES,
        )
        .map_err(AppError::operational)?;
        existing.clone()
    } else {
        let staged = ArtifactPath::new(&arguments.staged).map_err(AppError::operational)?;
        let elf = session
            .read_staged_bounded(&staged, MAX_ELF_BYTES)
            .map_err(AppError::from_session_store)?;
        let observed_digest = sha256(&elf)?;
        if &observed_digest != expected_digest {
            return Err(AppError::operational(
                "staged firmware ELF digest does not match the immutable capture request",
            ));
        }
        sampling_function_ranges_from_elf(
            &elf,
            "firmware",
            t32perf_analysis::MAX_FUNCTION_ADDRESS_RANGES,
        )
        .map_err(AppError::operational)?;

        let elf_spec = ArtifactSpec {
            id: FIRMWARE_ELF_ID.to_owned(),
            kind: "firmware_elf".to_owned(),
            relative_path: ArtifactPath::new(FIRMWARE_ELF_PATH).expect("fixed valid path"),
            media_type: "application/x-elf".to_owned(),
            producer: FIRMWARE_ELF_PRODUCER.to_owned(),
            input_artifact_ids: Vec::new(),
        };
        let committed = commit_exact(&session, &lock, &artifacts, elf_spec, &elf)?;
        if committed.sha256 != observed_digest {
            return Err(AppError::operational(
                "committed firmware ELF digest differs from the staged bytes",
            ));
        }
        committed
    };
    if let Some(existing) = artifacts
        .iter()
        .find(|artifact| artifact.id == FIRMWARE_EVIDENCE_ID)
    {
        let (evidence_artifact, _) = bound_function_histogram(
            &session,
            &artifacts,
            &existing.id,
            &elf_artifact,
            &histogram,
        )?;
        return Ok(firmware_binding_outcome(
            &arguments.session,
            &elf_artifact,
            &evidence_artifact,
        ));
    }
    let evidence = FirmwareBindingEvidence {
        schema: t32perf_model::FirmwareBindingEvidenceSchemaVersion,
        session_id: arguments.session.clone(),
        endpoint_fingerprint: histogram.endpoint_fingerprint.clone(),
        endpoint_fingerprint_scheme: histogram.endpoint_fingerprint_scheme,
        elf_sha256: elf_artifact.sha256.clone(),
        proof_kind: FirmwareBindingProofKind::PrecommittedElfAssertion,
        result: FirmwareBindingEvidenceResult::Asserted,
    };
    evidence.validate().map_err(AppError::operational)?;
    let evidence_spec = ArtifactSpec {
        id: FIRMWARE_EVIDENCE_ID.to_owned(),
        kind: FIRMWARE_EVIDENCE_KIND.to_owned(),
        relative_path: ArtifactPath::new(FIRMWARE_EVIDENCE_PATH).expect("fixed valid path"),
        media_type: "application/json".to_owned(),
        producer: FIRMWARE_EVIDENCE_PRODUCER.to_owned(),
        input_artifact_ids: vec![histogram_artifact.id.clone(), elf_artifact.id.clone()],
    };
    let evidence_artifact = commit_exact(
        &session,
        &lock,
        &artifacts,
        evidence_spec,
        &json_bytes(&evidence)?,
    )?;
    Ok(firmware_binding_outcome(
        &arguments.session,
        &elf_artifact,
        &evidence_artifact,
    ))
}

fn firmware_binding_outcome(
    session_id: &str,
    elf_artifact: &Artifact,
    evidence_artifact: &Artifact,
) -> CommandOutcome {
    outcome(
        "sampling.bind-firmware",
        json!({
            "session_id": session_id,
            "firmware_elf_artifact": artifact_json(elf_artifact),
            "firmware_evidence_artifact": artifact_json(evidence_artifact),
            "proof_kind": "precommitted_elf_assertion",
            "target_image_compared": false,
            "diagnostic_only": true,
            "statistical": true,
        }),
    )
}

pub fn analyze(
    root: &ArtifactRoot,
    arguments: SamplingAnalyzeArgs,
) -> Result<CommandOutcome, AppError> {
    let session = open_captured(root, &arguments.session)?;
    let lock = session.try_lock().map_err(AppError::from_session_store)?;
    ensure_captured(&session)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::from_session_store)?;
    let histogram_artifact = required_sampling_histogram(
        &session,
        &artifacts,
        &arguments.histogram_artifact,
        &arguments.session,
    )?;
    let histogram: PcHitHistogram = read_json(&session, histogram_artifact, MAX_HISTOGRAM_BYTES)?;
    histogram.validate().map_err(AppError::operational)?;
    ensure_session(&histogram.session_id, arguments.session.as_str())?;

    let (heatmap, inputs) = match arguments.projection {
        SamplingProjection::Address => {
            if arguments.elf_artifact.is_some() {
                return Err(AppError::operational(
                    "--elf-artifact is only valid for function projection",
                ));
            }
            if arguments.firmware_evidence_artifact.is_some() {
                return Err(AppError::operational(
                    "--firmware-evidence-artifact is only valid for function projection",
                ));
            }
            (
                build_address_heatmap(&histogram, histogram_artifact.sha256.clone())
                    .map_err(AppError::operational)?,
                vec![histogram_artifact.id.clone()],
            )
        }
        SamplingProjection::Function => {
            let elf_id = arguments.elf_artifact.as_deref().ok_or_else(|| {
                AppError::operational("function projection requires --elf-artifact")
            })?;
            let elf_artifact = required_sampling_elf(&artifacts, elf_id)?;
            let evidence_id = arguments
                .firmware_evidence_artifact
                .as_deref()
                .ok_or_else(|| {
                    AppError::operational(
                        "function projection requires --firmware-evidence-artifact",
                    )
                })?;
            let (evidence_artifact, bound_histogram) = bound_function_histogram(
                &session,
                &artifacts,
                evidence_id,
                elf_artifact,
                &histogram,
            )?;
            let elf = read_bytes(&session, elf_artifact, MAX_ELF_BYTES)?;
            let ranges = sampling_function_ranges_from_elf(
                &elf,
                "firmware",
                t32perf_analysis::MAX_FUNCTION_ADDRESS_RANGES,
            )
            .map_err(AppError::operational)?
            .into_iter()
            .map(|range| FunctionAddressRange {
                function_id: range.function_id,
                display_name: range.display_name,
                start_address: range.start,
                end_address: range.end,
            })
            .collect::<Vec<_>>();
            (
                build_function_heatmap(
                    &bound_histogram,
                    histogram_artifact.sha256.clone(),
                    &ranges,
                )
                .map_err(AppError::operational)?,
                vec![
                    histogram_artifact.id.clone(),
                    elf_artifact.id.clone(),
                    evidence_artifact.id.clone(),
                ],
            )
        }
    };
    let spec = heatmap_spec(arguments.projection, inputs);
    let bytes = json_bytes(&heatmap)?;
    let artifact = commit_exact(&session, &lock, &artifacts, spec, &bytes)?;
    Ok(outcome(
        "sampling.analyze",
        json!({
            "session_id": arguments.session,
            "projection": arguments.projection.as_str(),
            "artifact": artifact_json(&artifact),
            "diagnostic_only": true,
            "statistical": true,
            "trusted_analysis_stage_generated": false,
        }),
    ))
}

pub fn summary(
    root: &ArtifactRoot,
    arguments: SamplingSummaryArgs,
) -> Result<CommandOutcome, AppError> {
    let session = open_captured(root, &arguments.session)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::from_session_store)?;
    let projection = load_projection(&session, &artifacts, arguments.projection)?;
    let firmware_binding = projection.histogram.firmware.clone();
    let target_image_compared = matches!(
        &firmware_binding.proof,
        Some(FirmwareBindingProof::TargetImageComparison { .. })
    );
    let heatmap = projection.heatmap;
    let mut cells = heatmap.cells.clone();
    cells.sort_unstable_by(|left, right| {
        right
            .hits
            .cmp(&left.hits)
            .then_with(|| left.display_name.cmp(&right.display_name))
    });
    cells.truncate(usize::from(arguments.top));
    Ok(outcome(
        "sampling.summary",
        json!({
            "session_id": arguments.session,
            "projection": arguments.projection.as_str(),
            "statistical": true,
            "diagnostic_only": true,
            "firmware_binding": firmware_binding,
            "target_image_compared": target_image_compared,
            "quantitative_policy": heatmap.quantitative_policy,
            "denominator_hits": heatmap.denominator_hits,
            "attributed_hits": heatmap.attributed_hits,
            "unattributed_hits": heatmap.unattributed_hits,
            "rows": cells.into_iter().map(|cell| json!({
                "key": cell.key,
                "display_name": cell.display_name,
                "hits": cell.hits,
                "share": (cell.hits as f64) / (heatmap.denominator_hits as f64),
            })).collect::<Vec<_>>(),
        }),
    ))
}

pub fn render(
    root: &ArtifactRoot,
    arguments: SamplingRenderArgs,
) -> Result<CommandOutcome, AppError> {
    let session = open_captured(root, &arguments.session)?;
    let lock = session.try_lock().map_err(AppError::from_session_store)?;
    ensure_captured(&session)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::from_session_store)?;
    let projection = load_projection(&session, &artifacts, arguments.projection)?;
    let document = render_svg(
        &projection.histogram,
        projection.histogram_artifact.sha256.clone(),
        &projection.heatmap,
        SvgRenderOptions {
            max_rows: usize::from(arguments.max_rows),
            output_limit_bytes: MAX_HEATMAP_OUTPUT_LIMIT_BYTES,
        },
    )
    .map_err(AppError::operational)?;
    let spec = ArtifactSpec {
        id: format!(
            "sampling-heatmap-{}-svg-top{:03}",
            arguments.projection.as_str(),
            arguments.max_rows
        ),
        kind: HEATMAP_KIND.to_owned(),
        relative_path: ArtifactPath::new(format!(
            "report/sampling-heatmap-{}-top{:03}.svg",
            arguments.projection.as_str(),
            arguments.max_rows
        ))
        .map_err(AppError::operational)?,
        media_type: "image/svg+xml".to_owned(),
        producer: ANALYSIS_PRODUCER.to_owned(),
        input_artifact_ids: std::iter::once(projection.heatmap_artifact.id.clone())
            .chain(projection.heatmap_artifact.input_artifact_ids.clone())
            .collect(),
    };
    let artifact = commit_exact(&session, &lock, &artifacts, spec, document.svg.as_bytes())?;
    Ok(outcome(
        "sampling.render",
        json!({
            "session_id": arguments.session,
            "projection": arguments.projection.as_str(),
            "artifact": artifact_json(&artifact),
            "rendered_rows": document.rendered_rows,
            "omitted_rows": document.omitted_rows,
            "diagnostic_only": true,
            "statistical": true,
        }),
    ))
}

/// Renders a flame-shaped flat PC profile without claiming caller/callee evidence.
pub fn render_flat_flame(
    root: &ArtifactRoot,
    arguments: SamplingFlameArgs,
) -> Result<CommandOutcome, AppError> {
    let session = open_captured(root, &arguments.session)?;
    let lock = session.try_lock().map_err(AppError::from_session_store)?;
    ensure_captured(&session)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::from_session_store)?;
    let projection = load_projection(&session, &artifacts, arguments.projection)?;
    let document = render_flat_sampled_svg(
        &projection.histogram,
        projection.histogram_artifact.sha256.clone(),
        &projection.heatmap,
        FlatFlameGraphOptions {
            max_frames: usize::from(arguments.max_frames),
            output_limit_bytes: MAX_FLAME_OUTPUT_LIMIT_BYTES,
        },
    )
    .map_err(AppError::operational)?;
    let spec = ArtifactSpec {
        id: format!(
            "sampling-flat-profile-{}-svg-top{:03}",
            arguments.projection.as_str(),
            arguments.max_frames
        ),
        kind: FLAT_PROFILE_KIND.to_owned(),
        relative_path: ArtifactPath::new(format!(
            "report/sampling-flat-profile-{}-top{:03}.svg",
            arguments.projection.as_str(),
            arguments.max_frames
        ))
        .map_err(AppError::operational)?,
        media_type: "image/svg+xml".to_owned(),
        producer: FLAT_PROFILE_PRODUCER.to_owned(),
        input_artifact_ids: std::iter::once(projection.heatmap_artifact.id.clone())
            .chain(projection.heatmap_artifact.input_artifact_ids.clone())
            .collect(),
    };
    let artifact = commit_exact(&session, &lock, &artifacts, spec, document.svg.as_bytes())?;
    Ok(outcome(
        "sampling.flame",
        json!({
            "session_id": arguments.session,
            "projection": arguments.projection.as_str(),
            "artifact": artifact_json(&artifact),
            "rendered_frames": document.rendered_frames,
            "omitted_frames": document.omitted_frames,
            "profile_kind": "flat_sampled_profile",
            "hierarchy": "synthetic",
            "call_stack_evidence": false,
            "diagnostic_only": true,
            "statistical": true,
        }),
    ))
}

fn open_captured(root: &ArtifactRoot, id: &str) -> Result<Session, AppError> {
    let session = root
        .session(&t32perf_session::SessionId::new(id).map_err(AppError::operational)?)
        .map_err(AppError::from_session_store)?;
    ensure_captured(&session)?;
    Ok(session)
}

fn ensure_captured(session: &Session) -> Result<(), AppError> {
    if session
        .read_state()
        .map_err(AppError::from_session_store)?
        .status
        != SessionStatus::Captured
    {
        return Err(AppError::operational(
            "sampling diagnostics require a captured Session and never transition its lifecycle",
        ));
    }
    Ok(())
}

fn required_kind<'a>(
    artifacts: &'a [Artifact],
    id: &str,
    kind: &str,
) -> Result<&'a Artifact, AppError> {
    let artifact = artifacts
        .iter()
        .find(|artifact| artifact.id == id)
        .ok_or_else(|| AppError::operational(format!("artifact `{id}` is not registered")))?;
    if artifact.kind != kind {
        return Err(AppError::operational(format!(
            "artifact `{id}` must have kind `{kind}`"
        )));
    }
    Ok(artifact)
}

fn required_sampling_histogram<'a>(
    session: &Session,
    artifacts: &'a [Artifact],
    id: &str,
    expected_session: &str,
) -> Result<&'a Artifact, AppError> {
    if id != HISTOGRAM_ID {
        return Err(AppError::operational(format!(
            "sampling analysis requires the reserved histogram artifact `{HISTOGRAM_ID}`"
        )));
    }
    let artifact = required_kind(artifacts, id, HISTOGRAM_KIND)?;
    require_envelope(
        artifact,
        HISTOGRAM_PATH,
        "application/json",
        SIDECAR_PRODUCER,
    )?;
    if artifact.input_artifact_ids != [CAPTURE_RECEIPT_ID.to_owned()] {
        return Err(AppError::operational(
            "sampling histogram does not directly reference its capture receipt",
        ));
    }
    let receipt_artifact = artifacts
        .iter()
        .find(|candidate| candidate.id == CAPTURE_RECEIPT_ID)
        .ok_or_else(|| AppError::operational("sampling capture receipt is not registered"))?;
    if receipt_artifact.kind != CAPTURE_RECEIPT_KIND {
        return Err(AppError::operational(
            "sampling capture receipt has the wrong artifact kind",
        ));
    }
    require_envelope(
        receipt_artifact,
        CAPTURE_RECEIPT_PATH,
        "application/json",
        CAPTURE_RECEIPT_PRODUCER,
    )?;
    if !receipt_artifact.input_artifact_ids.is_empty() {
        return Err(AppError::operational(
            "sampling capture receipt must not claim Session artifact inputs",
        ));
    }
    let receipt: SamplingCaptureReceipt =
        read_json(session, receipt_artifact, MAX_CONTROL_DOCUMENT_BYTES)?;
    receipt.validate().map_err(AppError::operational)?;
    let state = session.read_state().map_err(AppError::from_session_store)?;
    let request_sha256 = session
        .request_sha256()
        .map_err(AppError::from_session_store)?;
    if receipt.session_id != expected_session
        || receipt.session_operation_id != state.operation_id
        || receipt.session_request_sha256 != request_sha256
        || receipt.histogram_sha256 != artifact.sha256
        || receipt.histogram_size_bytes != artifact.size_bytes
    {
        return Err(AppError::operational(
            "sampling capture receipt does not bind the selected Session and histogram artifact",
        ));
    }
    let histogram: PcHitHistogram = read_json(session, artifact, MAX_HISTOGRAM_BYTES)?;
    histogram.validate().map_err(AppError::operational)?;
    let capture_request: SamplingCaptureRequest =
        serde_json::from_value(session.request().map_err(AppError::from_session_store)?)
            .map_err(AppError::operational)?;
    capture_request.validate().map_err(AppError::operational)?;
    validate_histogram_request(&histogram, &capture_request)?;
    if histogram.session_id != expected_session
        || histogram.endpoint_fingerprint != receipt.endpoint_fingerprint
        || histogram.endpoint_fingerprint_scheme != receipt.endpoint_fingerprint_scheme
    {
        return Err(AppError::operational(
            "sampling histogram content does not match its capture receipt",
        ));
    }
    Ok(artifact)
}

fn required_sampling_elf<'a>(
    artifacts: &'a [Artifact],
    id: &str,
) -> Result<&'a Artifact, AppError> {
    if id != FIRMWARE_ELF_ID {
        return Err(AppError::operational(format!(
            "function projection requires the reserved ELF artifact `{FIRMWARE_ELF_ID}`"
        )));
    }
    let artifact = required_kind(artifacts, id, "firmware_elf")?;
    require_envelope(
        artifact,
        FIRMWARE_ELF_PATH,
        "application/x-elf",
        FIRMWARE_ELF_PRODUCER,
    )?;
    if !artifact.input_artifact_ids.is_empty() {
        return Err(AppError::operational(
            "sampling firmware ELF must not claim artifact inputs",
        ));
    }
    Ok(artifact)
}

fn bound_function_histogram(
    session: &Session,
    artifacts: &[Artifact],
    id: &str,
    elf_artifact: &Artifact,
    original_histogram: &PcHitHistogram,
) -> Result<(Artifact, PcHitHistogram), AppError> {
    ensure_cortex_m_cpu(&original_histogram.cpu)?;
    if id != FIRMWARE_EVIDENCE_ID {
        return Err(AppError::operational(format!(
            "function projection requires the reserved evidence artifact `{FIRMWARE_EVIDENCE_ID}`"
        )));
    }
    let artifact = required_kind(artifacts, id, FIRMWARE_EVIDENCE_KIND)?;
    require_envelope(
        artifact,
        FIRMWARE_EVIDENCE_PATH,
        "application/json",
        FIRMWARE_EVIDENCE_PRODUCER,
    )?;
    if artifact.input_artifact_ids != [HISTOGRAM_ID.to_owned(), elf_artifact.id.clone()] {
        return Err(AppError::operational(
            "firmware-binding evidence must directly reference the captured histogram and selected ELF artifact",
        ));
    }
    let evidence: FirmwareBindingEvidence =
        read_json(session, artifact, MAX_FIRMWARE_EVIDENCE_BYTES)?;
    evidence.validate().map_err(AppError::operational)?;
    if original_histogram.firmware.status != FirmwareBindingStatus::Unverified
        || original_histogram.firmware.elf_sha256.is_some()
        || original_histogram.firmware.proof.is_some()
        || evidence.session_id != original_histogram.session_id
        || evidence.endpoint_fingerprint != original_histogram.endpoint_fingerprint
        || evidence.endpoint_fingerprint_scheme != original_histogram.endpoint_fingerprint_scheme
        || evidence.elf_sha256 != elf_artifact.sha256
        || evidence.proof_kind != FirmwareBindingProofKind::PrecommittedElfAssertion
        || evidence.result != FirmwareBindingEvidenceResult::Asserted
    {
        return Err(AppError::operational(
            "firmware-binding evidence does not bind this Session, endpoint, and ELF assertion",
        ));
    }
    let request: SamplingCaptureRequest =
        serde_json::from_value(session.request().map_err(AppError::from_session_store)?)
            .map_err(AppError::operational)?;
    request.validate().map_err(AppError::operational)?;
    if request.deployed_firmware_elf_sha256.as_ref() != Some(&elf_artifact.sha256) {
        return Err(AppError::operational(
            "immutable sampling request does not bind the selected firmware ELF digest",
        ));
    }
    let mut bound = original_histogram.clone();
    bound.firmware = t32perf_model::FirmwareBinding {
        status: FirmwareBindingStatus::DeploymentAsserted,
        elf_sha256: Some(elf_artifact.sha256.clone()),
        proof: Some(FirmwareBindingProof::PrecommittedElfAssertion {
            evidence_artifact_sha256: artifact.sha256.clone(),
        }),
    };
    bound.validate().map_err(AppError::operational)?;
    Ok((artifact.clone(), bound))
}

fn ensure_cortex_m_cpu(cpu: &str) -> Result<(), AppError> {
    let normalized = cpu
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|character| character.to_ascii_lowercase())
        .collect::<String>();
    if normalized.starts_with("cortexm") {
        Ok(())
    } else {
        Err(AppError::operational(
            "sampling function attribution v1 requires a TRACE32 Cortex-M CPU identity",
        ))
    }
}

fn require_envelope(
    artifact: &Artifact,
    path: &str,
    media_type: &str,
    producer: &str,
) -> Result<(), AppError> {
    if artifact.relative_path.as_str() != path
        || artifact.media_type != media_type
        || artifact.producer != producer
    {
        return Err(AppError::operational(format!(
            "sampling artifact `{}` has an invalid reserved envelope",
            artifact.id
        )));
    }
    Ok(())
}

fn read_bytes(session: &Session, artifact: &Artifact, maximum: u64) -> Result<Vec<u8>, AppError> {
    if artifact.size_bytes > maximum {
        return Err(AppError::operational(format!(
            "artifact `{}` exceeds {maximum}-byte diagnostic limit",
            artifact.id
        )));
    }
    let mut file = session
        .open_artifact(artifact)
        .map_err(AppError::from_session_store)?;
    let mut bytes = Vec::with_capacity(usize::try_from(artifact.size_bytes).unwrap_or(0));
    (&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(AppError::operational)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(AppError::operational(
            "artifact grew beyond its diagnostic limit",
        ));
    }
    Ok(bytes)
}

fn read_json<T: DeserializeOwned>(
    session: &Session,
    artifact: &Artifact,
    maximum: u64,
) -> Result<T, AppError> {
    strict_json::from_slice(&read_bytes(session, artifact, maximum)?).map_err(AppError::operational)
}

fn ensure_session(actual: &str, expected: &str) -> Result<(), AppError> {
    if actual == expected {
        Ok(())
    } else {
        Err(AppError::operational(
            "sampling document session_id does not match the selected Session",
        ))
    }
}

fn heatmap_id(projection: SamplingProjection) -> &'static str {
    match projection {
        SamplingProjection::Address => "sampling-heatmap-address",
        SamplingProjection::Function => "sampling-heatmap-function",
    }
}

fn heatmap_spec(projection: SamplingProjection, inputs: Vec<String>) -> ArtifactSpec {
    ArtifactSpec {
        id: heatmap_id(projection).to_owned(),
        kind: HEATMAP_KIND.to_owned(),
        relative_path: ArtifactPath::new(format!("analysis/{}.json", heatmap_id(projection)))
            .expect("fixed valid path"),
        media_type: "application/json".to_owned(),
        producer: ANALYSIS_PRODUCER.to_owned(),
        input_artifact_ids: inputs,
    }
}

struct LoadedProjection {
    heatmap_artifact: Artifact,
    heatmap: Heatmap,
    histogram_artifact: Artifact,
    histogram: PcHitHistogram,
}

fn load_projection(
    session: &Session,
    artifacts: &[Artifact],
    projection: SamplingProjection,
) -> Result<LoadedProjection, AppError> {
    let heatmap_artifact = required_kind(artifacts, heatmap_id(projection), HEATMAP_KIND)?;
    require_envelope(
        heatmap_artifact,
        &format!("analysis/{}.json", heatmap_id(projection)),
        "application/json",
        ANALYSIS_PRODUCER,
    )?;
    let heatmap_bytes = read_bytes(session, heatmap_artifact, MAX_HISTOGRAM_BYTES)?;
    let heatmap: Heatmap =
        strict_json::from_slice(&heatmap_bytes).map_err(AppError::operational)?;
    ensure_session(&heatmap.session_id, session.id().as_str())?;
    ensure_projection(&heatmap, projection)?;

    let expected_input_count = match projection {
        SamplingProjection::Address => 1,
        SamplingProjection::Function => 3,
    };
    if heatmap_artifact.input_artifact_ids.len() != expected_input_count {
        return Err(AppError::operational(
            "sampling heatmap does not have the exact direct input set for its projection",
        ));
    }
    let histogram_id = &heatmap_artifact.input_artifact_ids[0];
    let histogram_artifact =
        required_sampling_histogram(session, artifacts, histogram_id, session.id().as_str())?;
    let histogram: PcHitHistogram = read_json(session, histogram_artifact, MAX_HISTOGRAM_BYTES)?;
    let (expected, bound_histogram) = match projection {
        SamplingProjection::Address => (
            build_address_heatmap(&histogram, histogram_artifact.sha256.clone())
                .map_err(AppError::operational)?,
            histogram.clone(),
        ),
        SamplingProjection::Function => {
            let elf_artifact =
                required_sampling_elf(artifacts, &heatmap_artifact.input_artifact_ids[1])?;
            let (_, bound_histogram) = bound_function_histogram(
                session,
                artifacts,
                &heatmap_artifact.input_artifact_ids[2],
                elf_artifact,
                &histogram,
            )?;
            let elf = read_bytes(session, elf_artifact, MAX_ELF_BYTES)?;
            let ranges = sampling_function_ranges_from_elf(
                &elf,
                "firmware",
                t32perf_analysis::MAX_FUNCTION_ADDRESS_RANGES,
            )
            .map_err(AppError::operational)?
            .into_iter()
            .map(|range| FunctionAddressRange {
                function_id: range.function_id,
                display_name: range.display_name,
                start_address: range.start,
                end_address: range.end,
            })
            .collect::<Vec<_>>();
            (
                build_function_heatmap(
                    &bound_histogram,
                    histogram_artifact.sha256.clone(),
                    &ranges,
                )
                .map_err(AppError::operational)?,
                bound_histogram,
            )
        }
    };
    if json_bytes(&expected)? != heatmap_bytes {
        return Err(AppError::operational(
            "registered sampling heatmap is not the canonical Host derivation of its direct inputs",
        ));
    }
    Ok(LoadedProjection {
        heatmap_artifact: heatmap_artifact.clone(),
        heatmap,
        histogram_artifact: histogram_artifact.clone(),
        histogram: bound_histogram,
    })
}

fn ensure_projection(heatmap: &Heatmap, projection: SamplingProjection) -> Result<(), AppError> {
    let expected = match projection {
        SamplingProjection::Address => HeatmapProjectionKind::AddressRange,
        SamplingProjection::Function => HeatmapProjectionKind::Function,
    };
    if heatmap.projection_kind == expected {
        Ok(())
    } else {
        Err(AppError::operational(
            "fixed heatmap projection does not match the requested projection",
        ))
    }
}

fn json_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, AppError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(AppError::operational)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn commit_exact(
    session: &Session,
    lock: &t32perf_session::SessionLock,
    artifacts: &[Artifact],
    spec: ArtifactSpec,
    bytes: &[u8],
) -> Result<Artifact, AppError> {
    if let Some(existing) = artifacts.iter().find(|artifact| artifact.id == spec.id) {
        let metadata_matches = existing.kind == spec.kind
            && existing.relative_path == spec.relative_path
            && existing.media_type == spec.media_type
            && existing.producer == spec.producer
            && existing.input_artifact_ids == spec.input_artifact_ids;
        if metadata_matches
            && read_bytes(
                session,
                existing,
                u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            )? == bytes
        {
            return Ok(existing.clone());
        }
        return Err(AppError::operational(format!(
            "immutable sampling artifact `{}` conflicts with this request",
            existing.id
        )));
    }
    let mut writer = session
        .create_artifact(lock, spec)
        .map_err(AppError::from_session_store)?;
    writer.write_all(bytes).map_err(AppError::operational)?;
    session
        .commit_artifact(lock, writer)
        .map_err(AppError::from_session_store)
}

fn artifact_json(artifact: &Artifact) -> Value {
    json!({"id": artifact.id, "kind": artifact.kind, "path": artifact.relative_path, "sha256": artifact.sha256, "media_type": artifact.media_type, "producer": artifact.producer, "input_artifact_ids": artifact.input_artifact_ids})
}

fn outcome(command: &'static str, result: Value) -> CommandOutcome {
    CommandOutcome {
        command,
        result,
        exit_code: 0,
    }
}
