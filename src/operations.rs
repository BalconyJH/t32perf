use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, BufReader, Read as _, Write},
    path::{Component, Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use atomic_write_file::AtomicWriteFile;
use fs2::FileExt;
use jiff::Timestamp;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use t32perf_analysis::ComparisonPolicy;
use t32perf_model::{
    Artifact, ComparisonReport, Manifest, PERFORMANCE_RUN_REQUEST_SCHEMA, PerformanceRunRequest,
    SessionStatus, Sha256Digest, schema_documents, strict_json,
};
use t32perf_session::{ArtifactRoot, INGEST_INTENT_SCHEMA, Session, SessionId};
use uuid::Uuid;

use crate::app::{AppError, CommandOutcome, EXIT_OPERATIONAL, EXIT_SUCCESS};

fn acquire_session_maintenance_guards(
    root: &ArtifactRoot,
    mut session_ids: Vec<SessionId>,
) -> Result<Vec<crate::perf_run::SessionIdExecutionLease>, AppError> {
    session_ids.sort();
    session_ids.dedup();
    session_ids
        .iter()
        .map(|session_id| crate::perf_run::try_acquire_session_id_execution_lease(root, session_id))
        .collect()
}

fn validate_strict_performance_run_request_claim(session: &Session) -> Result<(), AppError> {
    let request = session.request().map_err(AppError::operational)?;
    if request.get("schema").and_then(Value::as_str) != Some(PERFORMANCE_RUN_REQUEST_SCHEMA) {
        return Ok(());
    }
    let request: PerformanceRunRequest = serde_json::from_value(request).map_err(|error| {
        AppError::operational(format!(
            "perf_run Session `{}` has an invalid immutable request: {error}",
            session.id()
        ))
    })?;
    request.validate().map_err(AppError::operational)
}

const CONTROL_DIRECTORY: &str = ".t32perf-control";
const RETENTION_PLAN_SCHEMA: &str = "t32perf.retention-plan/v1";
const RETENTION_JOURNAL_SCHEMA: &str = "t32perf.retention-journal-event/v1";
const DIAGNOSTIC_BUNDLE_SCHEMA: &str = "t32perf.diagnostic-bundle/v1";
const COMPARISON_ARTIFACT_SCHEMA: &str = "t32perf.comparison-artifact/v1";
const ABANDON_PLAN_SCHEMA: &str = "t32perf.abandon-plan/v1";
const ABANDON_JOURNAL_SCHEMA: &str = "t32perf.abandon-journal-event/v1";
const RETENTION_ACTION: &str = "quarantine";
const ABANDON_ACTION: &str = "abandon_session";
const MAX_CONTROL_DOCUMENT_BYTES: u64 = 1024 * 1024;
const MAX_COMPARISON_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CONTROL_ENTRIES_PER_DIRECTORY: usize = 4096;
const MAX_RETENTION_SESSIONS: usize = 1024;
const MAX_INSPECTION_ENTRIES: usize = 100_000;
const MAX_REPORTED_ENTRIES: usize = 512;
const MAX_DIAGNOSTIC_REPORTED_ENTRIES: usize = 64;
const MAX_DIAGNOSTIC_STRING_BYTES: usize = 512;
const COMPARISON_MAINTENANCE_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const COMPARISON_MAINTENANCE_LOCK_RETRY: Duration = Duration::from_millis(10);
const FILESYSTEM_INVENTORY_DOMAIN: &[u8] = b"t32perf-session-filesystem-inventory-v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetentionPlan {
    schema: String,
    action: String,
    plan_id: String,
    artifact_root_fingerprint: Sha256Digest,
    created_at: String,
    sessions: Vec<RetentionPlanEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetentionPlanEntry {
    session_id: String,
    state_revision: u64,
    state_sha256: Sha256Digest,
    request_sha256: Sha256Digest,
    manifest_sha256: Sha256Digest,
    artifact_count: u64,
    filesystem_file_count: u64,
    filesystem_total_bytes: u64,
    filesystem_inventory_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetentionJournalEvent {
    schema: String,
    plan_id: String,
    plan_sha256: Sha256Digest,
    artifact_root_fingerprint: Sha256Digest,
    sequence: usize,
    action: String,
    session_id: String,
    recorded_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AbandonPlan {
    schema: String,
    action: String,
    plan_id: String,
    artifact_root_fingerprint: Sha256Digest,
    created_at: String,
    session: AbandonPlanEntry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AbandonPlanEntry {
    session_id: String,
    status: SessionStatus,
    state_revision: u64,
    state_sha256: Sha256Digest,
    request_sha256: Sha256Digest,
    filesystem_file_count: u64,
    filesystem_total_bytes: u64,
    filesystem_inventory_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AbandonJournalEvent {
    schema: String,
    plan_id: String,
    plan_sha256: Sha256Digest,
    artifact_root_fingerprint: Sha256Digest,
    sequence: usize,
    action: String,
    session_id: String,
    recorded_at: String,
}

struct MaintenanceLock {
    file: File,
}

pub(crate) struct ComparisonControlPlane<'root> {
    root: &'root ArtifactRoot,
    _maintenance: MaintenanceLock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ComparisonInputClaims {
    session_id: String,
    canonical_manifest_sha256: Sha256Digest,
    analysis_stage_sha256: Sha256Digest,
    health_sha256: Sha256Digest,
    hotspots_sha256: Option<Sha256Digest>,
    analysis_summary_sha256: Sha256Digest,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ComparisonArtifactDocument<'a> {
    schema: &'static str,
    tool: ComparisonArtifactTool,
    policy_sha256: Sha256Digest,
    policy: &'a ComparisonPolicy,
    baseline: &'a ComparisonInputClaims,
    candidate: &'a ComparisonInputClaims,
    report: &'a ComparisonReport,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ComparisonArtifactTool {
    name: &'static str,
    version: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct ComparisonArtifactReference {
    schema: &'static str,
    control_path: String,
    sha256: Sha256Digest,
    size_bytes: u64,
    policy_sha256: Sha256Digest,
    publication: &'static str,
}

struct BoundedDigestWriter<W> {
    inner: W,
    hasher: Sha256,
    size_bytes: u64,
    limit_bytes: u64,
}

impl Drop for MaintenanceLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

impl<W> BoundedDigestWriter<W> {
    fn new(inner: W, limit_bytes: u64) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            size_bytes: 0,
            limit_bytes,
        }
    }

    fn finish(self) -> Result<(W, u64, Sha256Digest), AppError> {
        let digest = Sha256Digest::new(encode_hex(&self.hasher.finalize()))
            .map_err(AppError::operational)?;
        Ok((self.inner, self.size_bytes, digest))
    }
}

impl<W: Write> Write for BoundedDigestWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let requested = u64::try_from(bytes.len())
            .map_err(|_| io::Error::other("comparison write length exceeds u64"))?;
        let attempted = self
            .size_bytes
            .checked_add(requested)
            .ok_or_else(|| io::Error::other("comparison artifact size exceeds u64"))?;
        if attempted > self.limit_bytes {
            return Err(io::Error::other(format!(
                "comparison artifact exceeds {} bytes",
                self.limit_bytes
            )));
        }
        let written = self.inner.write(bytes)?;
        self.hasher.update(&bytes[..written]);
        self.size_bytes = self
            .size_bytes
            .checked_add(u64::try_from(written).unwrap_or(u64::MAX))
            .ok_or_else(|| io::Error::other("comparison artifact size exceeds u64"))?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub(crate) fn comparison_input_claims(
    manifest: &Manifest,
    analysis_stage: &Artifact,
    health: &Artifact,
    hotspots: Option<&Artifact>,
    analysis_summary: &Artifact,
) -> Result<ComparisonInputClaims, AppError> {
    Ok(ComparisonInputClaims {
        session_id: manifest.session_id.clone(),
        canonical_manifest_sha256: digest_serialized(manifest, MAX_COMPARISON_ARTIFACT_BYTES)?,
        analysis_stage_sha256: analysis_stage.sha256.clone(),
        health_sha256: health.sha256.clone(),
        hotspots_sha256: hotspots.map(|artifact| artifact.sha256.clone()),
        analysis_summary_sha256: analysis_summary.sha256.clone(),
    })
}

pub(crate) fn comparison_control_plane(
    root: &ArtifactRoot,
) -> Result<ComparisonControlPlane<'_>, AppError> {
    Ok(ComparisonControlPlane {
        root,
        _maintenance: acquire_maintenance_lock_with_timeout(root)?,
    })
}

impl ComparisonControlPlane<'_> {
    pub(crate) fn persist_report(
        &self,
        policy: &ComparisonPolicy,
        baseline: &ComparisonInputClaims,
        candidate: &ComparisonInputClaims,
        report: &ComparisonReport,
    ) -> Result<ComparisonArtifactReference, AppError> {
        let policy_sha256 = digest_serialized(policy, MAX_CONTROL_DOCUMENT_BYTES)?;
        let document = ComparisonArtifactDocument {
            schema: COMPARISON_ARTIFACT_SCHEMA,
            tool: ComparisonArtifactTool {
                name: "t32perf",
                version: env!("CARGO_PKG_VERSION"),
            },
            policy_sha256: policy_sha256.clone(),
            policy,
            baseline,
            candidate,
            report,
        };
        let (_, size_bytes, sha256) =
            serialize_bounded_json_line(io::sink(), &document, MAX_COMPARISON_ARTIFACT_BYTES)?;
        let directory = control_subdirectory(self.root, &["comparisons"])?;
        let filename = format!("{sha256}.json");
        let path = directory.join(&filename);

        if filesystem_entry_exists(&path)? {
            verify_existing_comparison(&path, size_bytes, &sha256)?;
            return Ok(ComparisonArtifactReference {
                schema: COMPARISON_ARTIFACT_SCHEMA,
                control_path: format!("{CONTROL_DIRECTORY}/comparisons/{filename}"),
                sha256,
                size_bytes,
                policy_sha256,
                publication: "existing",
            });
        }

        ensure_new_entry_capacity(&directory)?;
        let file = AtomicWriteFile::open(&path).map_err(AppError::operational)?;
        let (file, written_size, written_sha256) =
            serialize_bounded_json_line(file, &document, MAX_COMPARISON_ARTIFACT_BYTES)?;
        if written_size != size_bytes || written_sha256 != sha256 {
            file.discard().map_err(AppError::operational)?;
            return Err(AppError::operational(
                "comparison artifact changed between digest and publication passes",
            ));
        }
        if filesystem_entry_exists(&path)? {
            file.discard().map_err(AppError::operational)?;
            verify_existing_comparison(&path, size_bytes, &sha256)?;
            return Ok(ComparisonArtifactReference {
                schema: COMPARISON_ARTIFACT_SCHEMA,
                control_path: format!("{CONTROL_DIRECTORY}/comparisons/{filename}"),
                sha256,
                size_bytes,
                policy_sha256,
                publication: "existing",
            });
        }
        file.commit().map_err(AppError::operational)?;
        sync_control_directory(&directory)?;

        Ok(ComparisonArtifactReference {
            schema: COMPARISON_ARTIFACT_SCHEMA,
            control_path: format!("{CONTROL_DIRECTORY}/comparisons/{filename}"),
            sha256,
            size_bytes,
            policy_sha256,
            publication: "created",
        })
    }
}

fn serialize_bounded_json_line<W: Write>(
    writer: W,
    value: &impl Serialize,
    limit_bytes: u64,
) -> Result<(W, u64, Sha256Digest), AppError> {
    let mut writer = BoundedDigestWriter::new(writer, limit_bytes);
    serde_json::to_writer(&mut writer, value).map_err(AppError::operational)?;
    writer.write_all(b"\n").map_err(AppError::operational)?;
    writer.flush().map_err(AppError::operational)?;
    writer.finish()
}

fn digest_serialized(value: &impl Serialize, limit_bytes: u64) -> Result<Sha256Digest, AppError> {
    let (_, _, digest) = serialize_bounded_json_line(io::sink(), value, limit_bytes)?;
    Ok(digest)
}

fn verify_existing_comparison(
    path: &Path,
    expected_size: u64,
    expected_sha256: &Sha256Digest,
) -> Result<(), AppError> {
    ensure_plain_file(path)?;
    let actual_size = fs::metadata(path).map_err(AppError::operational)?.len();
    if actual_size > MAX_COMPARISON_ARTIFACT_BYTES {
        return Err(AppError::operational(format!(
            "comparison artifact `{}` exceeds {MAX_COMPARISON_ARTIFACT_BYTES} bytes",
            path.display()
        )));
    }
    let (observed_size, observed_sha256) = digest_plain_file(path)?;
    if observed_size != expected_size || &observed_sha256 != expected_sha256 {
        return Err(AppError::operational(format!(
            "content-addressed comparison artifact `{}` does not match its expected digest and size",
            path.display()
        )));
    }
    Ok(())
}

pub fn inspect(
    root: &ArtifactRoot,
    session_id: &str,
    deep: bool,
) -> Result<CommandOutcome, AppError> {
    let session = open_session(root, session_id)?;
    let _lock = session.try_lock().map_err(AppError::operational)?;
    let inspection = inspect_session(root, &session, deep)?;
    let healthy = inspection["healthy"].as_bool().unwrap_or(false);
    Ok(CommandOutcome {
        command: "maintenance.inspect",
        result: inspection,
        exit_code: if healthy {
            EXIT_SUCCESS
        } else {
            EXIT_OPERATIONAL
        },
    })
}

pub fn diagnostics(root: &ArtifactRoot, session_id: &str) -> Result<CommandOutcome, AppError> {
    let _maintenance = acquire_maintenance_lock(root)?;
    let session = open_session(root, session_id)?;
    let _session_lock = session.try_lock().map_err(AppError::operational)?;
    let mut inspection = inspect_session(root, &session, true)?;
    redact_paths(&mut inspection, root.path());
    constrain_diagnostic_inspection(&mut inspection);

    let bundle_id = format!("diagnostic-{}", Uuid::now_v7().simple());
    let document = json!({
        "schema": DIAGNOSTIC_BUNDLE_SCHEMA,
        "bundle_id": bundle_id,
        "generated_at": Timestamp::now().to_string(),
        "tool": {
            "name": "t32perf",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "redaction": {
            "raw_artifacts_included": false,
            "request_body_included": false,
            "capture_policy_included": false,
            "artifact_root_paths_redacted": true,
        },
        "inspection": inspection,
    });
    let bytes = serialize_control_document(&document)?;
    let directory = control_subdirectory(root, &["diagnostics"])?;
    ensure_new_entry_capacity(&directory)?;
    let path = directory.join(format!("{bundle_id}.json"));
    write_new_file(&path, &bytes)?;
    let digest = digest_bytes(&bytes)?;

    Ok(CommandOutcome {
        command: "maintenance.diagnostics",
        result: json!({
            "session_id": session_id,
            "bundle_id": bundle_id,
            "control_path": format!("{CONTROL_DIRECTORY}/diagnostics/{bundle_id}.json"),
            "sha256": digest,
            "redacted": true,
        }),
        exit_code: EXIT_SUCCESS,
    })
}

pub fn schema_inventory(
    root: &ArtifactRoot,
    session_id: Option<&str>,
) -> Result<CommandOutcome, AppError> {
    let mut documents = schema_documents();
    for generated in [
        t32perf_trace32::c_wire_schema_documents(),
        t32perf_trace32::controller_schema_documents(),
        t32perf_trace32::driver_schema_documents(),
        t32perf_trace32::qualification_schema_documents(),
        t32perf_trace32::resource_schema_documents(),
        t32perf_trace32::target_adapter_schema_documents(),
        t32perf_trace32::trace_export_schema_documents(),
    ] {
        for (file, document) in generated {
            if documents.insert(file, document).is_some() {
                return Err(AppError::operational(format!(
                    "duplicate generated schema filename `{file}`"
                )));
            }
        }
    }
    let supported = documents
        .into_iter()
        .map(|(file, document)| {
            json!({
                "file": file,
                "title": document.get("title").and_then(Value::as_str),
            })
        })
        .collect::<Vec<_>>();
    let observed = session_id
        .map(|session_id| -> Result<Value, AppError> {
            let session = open_session(root, session_id)?;
            let _lock = session.try_lock().map_err(AppError::operational)?;
            let state = session.read_state().map_err(AppError::operational)?;
            let manifest = session.manifest().map_err(AppError::operational)?;
            let artifacts = session
                .registered_artifacts(false)
                .map_err(AppError::operational)?;
            let artifact_kinds = artifacts
                .iter()
                .map(|artifact| artifact.kind.clone())
                .collect::<BTreeSet<_>>();
            Ok(json!({
                "session_id": session_id,
                "state_schema": serde_json::to_value(&state).map_err(AppError::operational)?["schema"],
                "manifest_schema": manifest
                    .as_ref()
                    .map(|manifest| serde_json::to_value(manifest).map(|value| value["schema"].clone()))
                    .transpose()
                    .map_err(AppError::operational)?,
                "artifact_kinds": artifact_kinds,
            }))
        })
        .transpose()?;

    Ok(CommandOutcome {
        command: "maintenance.schema",
        result: json!({
            "supported": supported,
            "control_schemas": [
                INGEST_INTENT_SCHEMA,
                RETENTION_PLAN_SCHEMA,
                RETENTION_JOURNAL_SCHEMA,
                DIAGNOSTIC_BUNDLE_SCHEMA,
                COMPARISON_ARTIFACT_SCHEMA,
                ABANDON_PLAN_SCHEMA,
                ABANDON_JOURNAL_SCHEMA,
            ],
            "observed": observed,
            "migration": {
                "in_place_supported": false,
                "available_routes": [],
                "reason": "only v1 contracts exist; future major migrations must create a new Session and migration receipt",
            },
        }),
        exit_code: EXIT_SUCCESS,
    })
}

pub fn retention_plan(
    root: &ArtifactRoot,
    requested_sessions: &[String],
) -> Result<CommandOutcome, AppError> {
    if requested_sessions.is_empty() {
        return Err(AppError::operational(
            "retention planning requires at least one explicit Session",
        ));
    }
    if requested_sessions.len() > MAX_RETENTION_SESSIONS {
        return Err(AppError::operational(format!(
            "retention plan has {} Sessions; maximum is {MAX_RETENTION_SESSIONS}",
            requested_sessions.len()
        )));
    }
    let _maintenance = acquire_maintenance_lock(root)?;
    let mut session_ids = requested_sessions
        .iter()
        .map(|value| SessionId::new(value.clone()).map_err(AppError::operational))
        .collect::<Result<Vec<_>, _>>()?;
    session_ids.sort();
    if session_ids
        .windows(2)
        .any(|pair| pair[0].as_str() == pair[1].as_str())
    {
        return Err(AppError::operational(
            "retention Session identifiers must be unique",
        ));
    }

    let _session_execution_guards = acquire_session_maintenance_guards(root, session_ids.clone())?;
    let sessions = session_ids
        .iter()
        .map(|session_id| root.session(session_id).map_err(AppError::operational))
        .collect::<Result<Vec<_>, _>>()?;
    for session in &sessions {
        validate_strict_performance_run_request_claim(session)?;
    }

    let mut entries = Vec::with_capacity(sessions.len());
    for session in sessions {
        let _lock = session.try_lock().map_err(AppError::operational)?;
        entries.push(snapshot_complete_session(root, &session)?);
    }

    let plan_id = format!("retention-{}", Uuid::now_v7().simple());
    let plan = RetentionPlan {
        schema: RETENTION_PLAN_SCHEMA.to_owned(),
        action: RETENTION_ACTION.to_owned(),
        plan_id: plan_id.clone(),
        artifact_root_fingerprint: artifact_root_fingerprint(root)?,
        created_at: Timestamp::now().to_string(),
        sessions: entries,
    };
    validate_retention_plan(&plan)?;
    let bytes = serialize_control_document(&plan)?;
    let directory = control_subdirectory(root, &["retention", "plans"])?;
    ensure_new_entry_capacity(&directory)?;
    let path = directory.join(format!("{plan_id}.json"));
    write_new_file(&path, &bytes)?;
    let digest = digest_bytes(&bytes)?;

    Ok(CommandOutcome {
        command: "maintenance.retention.plan",
        result: json!({
            "plan_id": plan_id,
            "action": RETENTION_ACTION,
            "session_count": plan.sessions.len(),
            "sessions": plan.sessions.iter().map(|entry| &entry.session_id).collect::<Vec<_>>(),
            "control_path": format!("{CONTROL_DIRECTORY}/retention/plans/{plan_id}.json"),
            "confirm_sha256": digest,
            "next_command": format!("maintenance retention apply {plan_id} --confirm {digest}"),
        }),
        exit_code: EXIT_SUCCESS,
    })
}

pub fn retention_apply(
    root: &ArtifactRoot,
    plan_id: &str,
    confirmation: &str,
) -> Result<CommandOutcome, AppError> {
    let _maintenance = acquire_maintenance_lock(root)?;
    let (plan, digest) = load_retention_plan(root, plan_id)?;
    verify_confirmation(&digest, confirmation)?;
    verify_plan_root(root, &plan)?;
    let session_ids = plan
        .sessions
        .iter()
        .map(|entry| SessionId::new(entry.session_id.clone()).map_err(AppError::operational))
        .collect::<Result<Vec<_>, _>>()?;
    let _session_execution_guards = acquire_session_maintenance_guards(root, session_ids)?;
    let quarantine_path = control_subdirectory(root, &["retention", "quarantine", plan_id])?;
    let quarantine_root =
        ArtifactRoot::open(&quarantine_path, root.limits()).map_err(AppError::operational)?;
    for entry in &plan.sessions {
        let session_id = SessionId::new(entry.session_id.clone()).map_err(AppError::operational)?;
        if plain_directory_exists(&root.path().join(session_id.as_str()))? {
            validate_strict_performance_run_request_claim(
                &root.session(&session_id).map_err(AppError::operational)?,
            )?;
        } else if plain_directory_exists(&quarantine_root.path().join(session_id.as_str()))? {
            validate_strict_performance_run_request_claim(
                &quarantine_root
                    .session(&session_id)
                    .map_err(AppError::operational)?,
            )?;
        }
    }
    let namespace = root.try_namespace_lock().map_err(AppError::operational)?;
    let quarantine_namespace = quarantine_root
        .try_namespace_lock()
        .map_err(AppError::operational)?;
    let journal = control_subdirectory(root, &["retention", "journals", plan_id])?;
    validate_retention_journal_directory(&journal, &plan, &digest)?;
    for (sequence, entry) in plan.sessions.iter().enumerate() {
        validate_existing_journal_event(
            &journal,
            plan_id,
            &digest,
            &plan.artifact_root_fingerprint,
            sequence,
            "quarantined",
            &entry.session_id,
        )?;
    }
    let mut moved = Vec::new();
    let mut already_quarantined = Vec::new();

    for (sequence, entry) in plan.sessions.iter().enumerate() {
        let session_id = SessionId::new(entry.session_id.clone()).map_err(AppError::operational)?;
        let source = root.path().join(session_id.as_str());
        let destination = quarantine_root.path().join(session_id.as_str());
        let source_exists = plain_directory_exists(&source)?;
        let destination_exists = plain_directory_exists(&destination)?;
        match (source_exists, destination_exists) {
            (true, true) => {
                return Err(AppError::operational(format!(
                    "retention plan `{plan_id}` has both active and quarantined copies of Session `{session_id}`"
                )));
            }
            (false, false) => {
                return Err(AppError::operational(format!(
                    "retention plan `{plan_id}` cannot find Session `{session_id}` in either active or quarantine storage"
                )));
            }
            (false, true) => {
                let session = quarantine_root
                    .session(&session_id)
                    .map_err(AppError::operational)?;
                let _lock = session
                    .try_lock_in_namespace(&quarantine_namespace)
                    .map_err(AppError::operational)?;
                validate_plan_entry(&quarantine_root, &session, entry)?;
                write_journal_event(
                    &journal,
                    plan_id,
                    &digest,
                    &plan.artifact_root_fingerprint,
                    sequence,
                    "quarantined",
                    session_id.as_str(),
                )?;
                already_quarantined.push(session_id.to_string());
            }
            (true, false) => {
                let session = root.session(&session_id).map_err(AppError::operational)?;
                let lock = session
                    .try_lock_in_namespace(&namespace)
                    .map_err(AppError::operational)?;
                validate_plan_entry(root, &session, entry)?;
                // Windows does not allow renaming a directory that contains the open
                // Session lock file. Complete Sessions are terminal and immutable, so
                // release the Session lock after exact validation while retaining both
                // namespace leases and the maintenance lock for rename and journaling.
                drop(lock);
                fs::rename(&source, &destination).map_err(|error| {
                    AppError::operational(format!(
                        "failed to quarantine Session `{session_id}` from `{}` to `{}`: {error}",
                        source.display(),
                        destination.display()
                    ))
                })?;
                sync_rename_parents(&source, &destination)?;
                let quarantined = quarantine_root
                    .session(&session_id)
                    .map_err(AppError::operational)?;
                let _lock = quarantined
                    .try_lock_in_namespace(&quarantine_namespace)
                    .map_err(AppError::operational)?;
                validate_plan_entry(&quarantine_root, &quarantined, entry)?;
                write_journal_event(
                    &journal,
                    plan_id,
                    &digest,
                    &plan.artifact_root_fingerprint,
                    sequence,
                    "quarantined",
                    session_id.as_str(),
                )?;
                moved.push(session_id.to_string());
            }
        }
    }

    Ok(CommandOutcome {
        command: "maintenance.retention.apply",
        result: json!({
            "plan_id": plan_id,
            "confirm_sha256": digest,
            "moved": moved,
            "already_quarantined": already_quarantined,
            "quarantine_root": format!("{CONTROL_DIRECTORY}/retention/quarantine/{plan_id}"),
            "recoverable": true,
        }),
        exit_code: EXIT_SUCCESS,
    })
}

pub fn retention_restore(
    root: &ArtifactRoot,
    plan_id: &str,
    requested_session_id: &str,
    confirmation: &str,
) -> Result<CommandOutcome, AppError> {
    let _maintenance = acquire_maintenance_lock(root)?;
    let (plan, digest) = load_retention_plan(root, plan_id)?;
    verify_confirmation(&digest, confirmation)?;
    verify_plan_root(root, &plan)?;
    let session_id =
        SessionId::new(requested_session_id.to_owned()).map_err(AppError::operational)?;
    let entry = plan
        .sessions
        .iter()
        .find(|entry| entry.session_id == session_id.as_str())
        .ok_or_else(|| {
            AppError::operational(format!(
                "Session `{session_id}` is not present in retention plan `{plan_id}`"
            ))
        })?;
    let _session_execution_guards =
        acquire_session_maintenance_guards(root, vec![session_id.clone()])?;
    let quarantine_path = control_subdirectory(root, &["retention", "quarantine", plan_id])?;
    let quarantine_root =
        ArtifactRoot::open(&quarantine_path, root.limits()).map_err(AppError::operational)?;
    let source = quarantine_root.path().join(session_id.as_str());
    let destination = root.path().join(session_id.as_str());
    let source_exists = plain_directory_exists(&source)?;
    let destination_exists = plain_directory_exists(&destination)?;
    if destination_exists {
        validate_strict_performance_run_request_claim(
            &root.session(&session_id).map_err(AppError::operational)?,
        )?;
    } else if source_exists {
        validate_strict_performance_run_request_claim(
            &quarantine_root
                .session(&session_id)
                .map_err(AppError::operational)?,
        )?;
    }
    let namespace = root.try_namespace_lock().map_err(AppError::operational)?;
    let quarantine_namespace = quarantine_root
        .try_namespace_lock()
        .map_err(AppError::operational)?;
    let journal = control_subdirectory(root, &["retention", "journals", plan_id])?;
    validate_retention_journal_directory(&journal, &plan, &digest)?;
    validate_existing_journal_event(
        &journal,
        plan_id,
        &digest,
        &plan.artifact_root_fingerprint,
        plan.sessions.len(),
        "restored",
        session_id.as_str(),
    )?;
    let already_restored = match (source_exists, destination_exists) {
        (true, true) => {
            return Err(AppError::operational(format!(
                "active and quarantined copies of Session `{session_id}` both exist; restore never overwrites"
            )));
        }
        (false, false) => {
            return Err(AppError::operational(format!(
                "Session `{session_id}` does not exist in active or quarantine storage for plan `{plan_id}`"
            )));
        }
        (false, true) => {
            let restored = root.session(&session_id).map_err(AppError::operational)?;
            let _lock = restored
                .try_lock_in_namespace(&namespace)
                .map_err(AppError::operational)?;
            validate_plan_entry(root, &restored, entry)?;
            true
        }
        (true, false) => {
            let session = quarantine_root
                .session(&session_id)
                .map_err(AppError::operational)?;
            let lock = session
                .try_lock_in_namespace(&quarantine_namespace)
                .map_err(AppError::operational)?;
            validate_plan_entry(&quarantine_root, &session, entry)?;
            // The terminal Session is immutable. Close its lock for the Windows
            // rename while retaining both namespace leases and the maintenance lock.
            drop(lock);
            fs::rename(&source, &destination).map_err(|error| {
                AppError::operational(format!(
                    "failed to restore Session `{session_id}` from `{}` to `{}`: {error}",
                    source.display(),
                    destination.display()
                ))
            })?;
            sync_rename_parents(&source, &destination)?;
            let restored = root.session(&session_id).map_err(AppError::operational)?;
            let _lock = restored
                .try_lock_in_namespace(&namespace)
                .map_err(AppError::operational)?;
            validate_plan_entry(root, &restored, entry)?;
            false
        }
    };
    write_journal_event(
        &journal,
        plan_id,
        &digest,
        &plan.artifact_root_fingerprint,
        plan.sessions.len(),
        "restored",
        session_id.as_str(),
    )?;

    Ok(CommandOutcome {
        command: "maintenance.retention.restore",
        result: json!({
            "plan_id": plan_id,
            "session_id": session_id.as_str(),
            "confirm_sha256": digest,
            "restored": !already_restored,
            "already_restored": already_restored,
        }),
        exit_code: EXIT_SUCCESS,
    })
}

pub fn abandon_plan(
    root: &ArtifactRoot,
    requested_session_id: &str,
) -> Result<CommandOutcome, AppError> {
    let _maintenance = acquire_maintenance_lock(root)?;
    let session_id =
        SessionId::new(requested_session_id.to_owned()).map_err(AppError::operational)?;
    let _session_execution_guards =
        acquire_session_maintenance_guards(root, vec![session_id.clone()])?;
    let session = root.session(&session_id).map_err(AppError::operational)?;
    validate_strict_performance_run_request_claim(&session)?;
    let namespace = root.try_namespace_lock().map_err(AppError::operational)?;
    let _lock = session
        .try_lock_in_namespace(&namespace)
        .map_err(AppError::operational)?;
    crate::controller::ensure_controller_session_releasable(root, &session)?;
    let entry = snapshot_abandonable_session(&session)?;
    let plan_id = format!("abandon-{}", Uuid::now_v7().simple());
    let plan = AbandonPlan {
        schema: ABANDON_PLAN_SCHEMA.to_owned(),
        action: ABANDON_ACTION.to_owned(),
        plan_id: plan_id.clone(),
        artifact_root_fingerprint: artifact_root_fingerprint(root)?,
        created_at: Timestamp::now().to_string(),
        session: entry,
    };
    validate_abandon_plan(&plan)?;
    let bytes = serialize_control_document(&plan)?;
    let directory = control_subdirectory(root, &["abandon", "plans"])?;
    ensure_new_entry_capacity(&directory)?;
    let path = directory.join(format!("{plan_id}.json"));
    write_new_file(&path, &bytes)?;
    let digest = digest_bytes(&bytes)?;
    Ok(CommandOutcome {
        command: "maintenance.abandon.plan",
        result: json!({
            "plan_id": plan_id,
            "action": ABANDON_ACTION,
            "session_id": plan.session.session_id,
            "status": plan.session.status,
            "filesystem_file_count": plan.session.filesystem_file_count,
            "filesystem_total_bytes": plan.session.filesystem_total_bytes,
            "control_path": format!("{CONTROL_DIRECTORY}/abandon/plans/{plan_id}.json"),
            "confirm_sha256": digest,
            "next_command": format!("maintenance abandon apply {plan_id} --confirm {digest}"),
            "recoverable": true,
        }),
        exit_code: EXIT_SUCCESS,
    })
}

pub fn abandon_apply(
    root: &ArtifactRoot,
    plan_id: &str,
    confirmation: &str,
) -> Result<CommandOutcome, AppError> {
    let _maintenance = acquire_maintenance_lock(root)?;
    let (plan, digest) = load_abandon_plan(root, plan_id)?;
    verify_confirmation(&digest, confirmation)?;
    verify_abandon_plan_root(root, &plan)?;
    let session_id =
        SessionId::new(plan.session.session_id.clone()).map_err(AppError::operational)?;
    let _session_execution_guards =
        acquire_session_maintenance_guards(root, vec![session_id.clone()])?;
    let quarantine_path = control_subdirectory(root, &["abandon", "quarantine", plan_id])?;
    let quarantine_root =
        ArtifactRoot::open(&quarantine_path, root.limits()).map_err(AppError::operational)?;
    let source = root.path().join(session_id.as_str());
    let destination = quarantine_root.path().join(session_id.as_str());
    let source_exists = plain_directory_exists(&source)?;
    let destination_exists = plain_directory_exists(&destination)?;
    if source_exists {
        validate_strict_performance_run_request_claim(
            &root.session(&session_id).map_err(AppError::operational)?,
        )?;
    } else if destination_exists {
        validate_strict_performance_run_request_claim(
            &quarantine_root
                .session(&session_id)
                .map_err(AppError::operational)?,
        )?;
    }
    let namespace = root.try_namespace_lock().map_err(AppError::operational)?;
    let quarantine_namespace = quarantine_root
        .try_namespace_lock()
        .map_err(AppError::operational)?;
    let journal = control_subdirectory(root, &["abandon", "journals", plan_id])?;
    validate_abandon_journal_directory(&journal, &plan, &digest)?;
    let already_abandoned = match (source_exists, destination_exists) {
        (true, true) => {
            return Err(AppError::operational(format!(
                "abandon plan `{plan_id}` has both active and quarantined copies of Session `{session_id}`"
            )));
        }
        (false, false) => {
            return Err(AppError::operational(format!(
                "abandon plan `{plan_id}` cannot find Session `{session_id}`"
            )));
        }
        (false, true) => {
            let session = quarantine_root
                .session(&session_id)
                .map_err(AppError::operational)?;
            let _lock = session
                .try_lock_in_namespace(&quarantine_namespace)
                .map_err(AppError::operational)?;
            validate_abandon_entry(&session, &plan.session)?;
            true
        }
        (true, false) => {
            let session = root.session(&session_id).map_err(AppError::operational)?;
            let lock = session
                .try_lock_in_namespace(&namespace)
                .map_err(AppError::operational)?;
            crate::controller::ensure_controller_session_releasable(root, &session)?;
            validate_abandon_entry(&session, &plan.session)?;
            drop(lock);
            fs::rename(&source, &destination).map_err(|error| {
                AppError::operational(format!(
                    "failed to abandon Session `{session_id}` from `{}` to `{}`: {error}",
                    source.display(),
                    destination.display()
                ))
            })?;
            sync_rename_parents(&source, &destination)?;
            let quarantined = quarantine_root
                .session(&session_id)
                .map_err(AppError::operational)?;
            let _lock = quarantined
                .try_lock_in_namespace(&quarantine_namespace)
                .map_err(AppError::operational)?;
            validate_abandon_entry(&quarantined, &plan.session)?;
            false
        }
    };
    write_abandon_journal_event(&journal, &plan, &digest, 0, "abandoned")?;
    Ok(CommandOutcome {
        command: "maintenance.abandon.apply",
        result: json!({
            "plan_id": plan_id,
            "session_id": session_id.as_str(),
            "confirm_sha256": digest,
            "abandoned": !already_abandoned,
            "already_abandoned": already_abandoned,
            "quarantine_root": format!("{CONTROL_DIRECTORY}/abandon/quarantine/{plan_id}"),
            "recoverable": true,
        }),
        exit_code: EXIT_SUCCESS,
    })
}

pub fn abandon_restore(
    root: &ArtifactRoot,
    plan_id: &str,
    confirmation: &str,
) -> Result<CommandOutcome, AppError> {
    let _maintenance = acquire_maintenance_lock(root)?;
    let (plan, digest) = load_abandon_plan(root, plan_id)?;
    verify_confirmation(&digest, confirmation)?;
    verify_abandon_plan_root(root, &plan)?;
    let session_id =
        SessionId::new(plan.session.session_id.clone()).map_err(AppError::operational)?;
    let _session_execution_guards =
        acquire_session_maintenance_guards(root, vec![session_id.clone()])?;
    let quarantine_path = control_subdirectory(root, &["abandon", "quarantine", plan_id])?;
    let quarantine_root =
        ArtifactRoot::open(&quarantine_path, root.limits()).map_err(AppError::operational)?;
    let source = quarantine_root.path().join(session_id.as_str());
    let destination = root.path().join(session_id.as_str());
    let source_exists = plain_directory_exists(&source)?;
    let destination_exists = plain_directory_exists(&destination)?;
    if destination_exists {
        validate_strict_performance_run_request_claim(
            &root.session(&session_id).map_err(AppError::operational)?,
        )?;
    } else if source_exists {
        validate_strict_performance_run_request_claim(
            &quarantine_root
                .session(&session_id)
                .map_err(AppError::operational)?,
        )?;
    }
    let namespace = root.try_namespace_lock().map_err(AppError::operational)?;
    let quarantine_namespace = quarantine_root
        .try_namespace_lock()
        .map_err(AppError::operational)?;
    let journal = control_subdirectory(root, &["abandon", "journals", plan_id])?;
    validate_abandon_journal_directory(&journal, &plan, &digest)?;
    let already_restored = match (source_exists, destination_exists) {
        (true, true) => {
            return Err(AppError::operational(format!(
                "active and abandoned copies of Session `{session_id}` both exist; restore never overwrites"
            )));
        }
        (false, false) => {
            return Err(AppError::operational(format!(
                "Session `{session_id}` does not exist in active or abandon quarantine storage"
            )));
        }
        (false, true) => {
            let session = root.session(&session_id).map_err(AppError::operational)?;
            let _lock = session
                .try_lock_in_namespace(&namespace)
                .map_err(AppError::operational)?;
            validate_abandon_entry(&session, &plan.session)?;
            true
        }
        (true, false) => {
            let session = quarantine_root
                .session(&session_id)
                .map_err(AppError::operational)?;
            let lock = session
                .try_lock_in_namespace(&quarantine_namespace)
                .map_err(AppError::operational)?;
            validate_abandon_entry(&session, &plan.session)?;
            drop(lock);
            fs::rename(&source, &destination).map_err(|error| {
                AppError::operational(format!(
                    "failed to restore abandoned Session `{session_id}` from `{}` to `{}`: {error}",
                    source.display(),
                    destination.display()
                ))
            })?;
            sync_rename_parents(&source, &destination)?;
            let restored = root.session(&session_id).map_err(AppError::operational)?;
            let _lock = restored
                .try_lock_in_namespace(&namespace)
                .map_err(AppError::operational)?;
            validate_abandon_entry(&restored, &plan.session)?;
            false
        }
    };
    write_abandon_journal_event(&journal, &plan, &digest, 1, "restored")?;
    Ok(CommandOutcome {
        command: "maintenance.abandon.restore",
        result: json!({
            "plan_id": plan_id,
            "session_id": session_id.as_str(),
            "confirm_sha256": digest,
            "restored": !already_restored,
            "already_restored": already_restored,
        }),
        exit_code: EXIT_SUCCESS,
    })
}

fn inspect_session(root: &ArtifactRoot, session: &Session, deep: bool) -> Result<Value, AppError> {
    let mut checks = Vec::new();
    let state = match session.read_state() {
        Ok(state) => {
            checks.push(check("state", true, "durable state is valid"));
            Some(state)
        }
        Err(error) => {
            checks.push(check("state", false, error.to_string()));
            None
        }
    };
    let request_sha256 = match session.request_sha256() {
        Ok(digest) => {
            checks.push(check("request", true, "request digest is readable"));
            Some(digest)
        }
        Err(error) => {
            checks.push(check("request", false, error.to_string()));
            None
        }
    };
    let artifacts = match session.registered_artifacts(deep) {
        Ok(artifacts) => {
            checks.push(check(
                if deep {
                    "artifacts_deep"
                } else {
                    "artifacts_shallow"
                },
                true,
                format!("{} registered artifacts validated", artifacts.len()),
            ));
            Some(artifacts)
        }
        Err(error) => {
            checks.push(check(
                if deep {
                    "artifacts_deep"
                } else {
                    "artifacts_shallow"
                },
                false,
                error.to_string(),
            ));
            None
        }
    };
    let manifest = match session.manifest() {
        Ok(Some(manifest)) => {
            match session.validate_manifest(&manifest, deep) {
                Ok(()) => checks.push(check("manifest", true, "manifest is consistent")),
                Err(error) => checks.push(check("manifest", false, error.to_string())),
            }
            Some(manifest)
        }
        Ok(None) => {
            let required = state
                .as_ref()
                .is_some_and(|state| state.status == SessionStatus::Complete);
            checks.push(check(
                "manifest",
                !required,
                if required {
                    "complete Session has no manifest"
                } else {
                    "manifest has not been committed"
                },
            ));
            None
        }
        Err(error) => {
            checks.push(check("manifest", false, error.to_string()));
            None
        }
    };
    let (ingest_intents, ingest_intents_total, ingest_intents_truncated) =
        match session.inspect_ingest_intents() {
            Ok(intents) => {
                let total = intents.len();
                checks.push(check(
                    "ingest_intents",
                    intents.is_empty(),
                    if intents.is_empty() {
                        "no unfinished ingest intents found".to_owned()
                    } else {
                        format!("{total} unfinished ingest intents require review")
                    },
                ));
                let reported = intents
                    .into_iter()
                    .take(MAX_REPORTED_ENTRIES)
                    .collect::<Vec<_>>();
                (
                    serde_json::to_value(reported).map_err(AppError::operational)?,
                    Some(total),
                    total > MAX_REPORTED_ENTRIES,
                )
            }
            Err(error) => {
                checks.push(check("ingest_intents", false, error.to_string()));
                (json!([]), None, true)
            }
        };
    let registered_paths = artifacts
        .as_ref()
        .map(|artifacts| {
            artifacts
                .iter()
                .map(|artifact| artifact.relative_path.as_str().to_owned())
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let committed_staging_sources = match if deep {
        session.verify_committed_staging_sources()
    } else {
        session.verify_committed_staging_sources_shallow()
    } {
        Ok(sources) => {
            checks.push(check(
                "committed_staging_sources",
                true,
                format!(
                    "{} retained staging sources are bound to committed artifacts",
                    sources.len()
                ),
            ));
            sources
        }
        Err(error) => {
            checks.push(check("committed_staging_sources", false, error.to_string()));
            Vec::new()
        }
    };
    let retained_staging_paths = committed_staging_sources
        .iter()
        .map(|source| format!("capture/staging/{}", source.staged_relative_path))
        .collect::<BTreeSet<_>>();
    let tree = inspect_session_tree(
        session.path(),
        &registered_paths,
        &retained_staging_paths,
        deep,
    )?;
    checks.push(check(
        "unregistered_files",
        tree.orphans.total == 0,
        if tree.orphans.total == 0 {
            "no unregistered durable files found".to_owned()
        } else {
            format!("{} unregistered files found", tree.orphans.total)
        },
    ));
    let staging_allowed = state.as_ref().is_some_and(|state| {
        matches!(
            state.status,
            SessionStatus::Created | SessionStatus::Capturing | SessionStatus::Captured
        )
    });
    checks.push(check(
        "staging",
        tree.staging.total == 0 || staging_allowed,
        format!("{} staging files found", tree.staging.total),
    ));
    checks.push(check(
        "filesystem_entries",
        tree.unsafe_entries.total == 0 && !tree.scan_truncated,
        if tree.scan_truncated {
            format!("inspection exceeded {MAX_INSPECTION_ENTRIES} entries")
        } else if tree.unsafe_entries.total == 0 {
            "no links or reparse points found".to_owned()
        } else {
            format!("{} unsafe entries found", tree.unsafe_entries.total)
        },
    ));
    let healthy = checks
        .iter()
        .all(|entry| entry["ok"].as_bool().unwrap_or(false));
    let artifacts = artifacts.unwrap_or_default();
    let artifact_claims_truncated = artifacts.len() > MAX_REPORTED_ENTRIES;
    let artifact_claims = artifacts
        .into_iter()
        .take(MAX_REPORTED_ENTRIES)
        .map(|artifact| {
            json!({
                "id": artifact.id,
                "kind": artifact.kind,
                "media_type": artifact.media_type,
                "size_bytes": artifact.size_bytes,
                "sha256": artifact.sha256,
                "producer": artifact.producer,
            })
        })
        .collect::<Vec<_>>();

    Ok(json!({
        "session_id": session.id().as_str(),
        "deep": deep,
        "healthy": healthy,
        "state": state.map(|state| json!({
            "status": state.status,
            "revision": state.revision,
            "updated_at": state.updated_at,
            "error_code": state.error.map(|error| error.code),
        })),
        "request_sha256": request_sha256,
        "manifest": manifest.map(|manifest| json!({
            "schema": manifest.schema,
            "artifact_count": manifest.artifacts.len(),
            "tool": manifest.tool,
        })),
        "artifacts": artifact_claims,
        "artifact_claims_truncated": artifact_claims_truncated,
        "ingest_intents": ingest_intents,
        "ingest_intents_total": ingest_intents_total,
        "ingest_intents_truncated": ingest_intents_truncated,
        "staging_files": tree.staging.entries(),
        "staging_files_total": tree.staging.total,
        "staging_files_truncated": tree.staging.truncated(tree.scan_truncated),
        "committed_staging_sources": committed_staging_sources,
        "retained_staging_files": tree.retained_staging.entries(),
        "retained_staging_files_total": tree.retained_staging.total,
        "retained_staging_files_truncated": tree.retained_staging.truncated(tree.scan_truncated),
        "unregistered_files": tree.orphans.entries(),
        "unregistered_files_total": tree.orphans.total,
        "unregistered_files_truncated": tree.orphans.truncated(tree.scan_truncated),
        "unsafe_entries": tree.unsafe_entries.entries(),
        "unsafe_entries_total": tree.unsafe_entries.total,
        "unsafe_entries_truncated": tree.unsafe_entries.truncated(tree.scan_truncated),
        "filesystem_entries_total": tree.entries_inspected,
        "filesystem_entries_truncated": tree.scan_truncated,
        "entries_truncated": tree.scan_truncated,
        "filesystem_inventory": tree.inventory.as_ref().map(|inventory| json!({
            "schema": "t32perf.session-filesystem-inventory/v1",
            "file_count": inventory.file_count,
            "total_bytes": inventory.total_bytes,
            "sha256": inventory.sha256,
        })),
        "checks": checks,
        "artifact_root_fingerprint": artifact_root_fingerprint(root)?,
    }))
}

fn snapshot_complete_session(
    root: &ArtifactRoot,
    session: &Session,
) -> Result<RetentionPlanEntry, AppError> {
    let state = session.read_state().map_err(AppError::operational)?;
    if state.status != SessionStatus::Complete {
        return Err(AppError::operational(format!(
            "retention only accepts complete Sessions; `{}` is {:?}",
            session.id(),
            state.status
        )));
    }
    let inspection = inspect_session(root, session, true)?;
    if inspection["healthy"] != Value::Bool(true) {
        let failed = inspection["checks"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|entry| entry["ok"] != Value::Bool(true))
            .map(|entry| {
                format!(
                    "{}: {}",
                    entry["name"].as_str().unwrap_or("unknown"),
                    entry["message"].as_str().unwrap_or("failed")
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(AppError::operational(format!(
            "retention Session `{}` failed deep inspection: {failed}",
            session.id()
        )));
    }
    let inventory = inspection["filesystem_inventory"]
        .as_object()
        .ok_or_else(|| AppError::operational("deep inspection omitted filesystem inventory"))?;
    let filesystem_inventory_sha256 = Sha256Digest::new(
        inventory
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::operational("filesystem inventory omitted SHA-256"))?
            .to_owned(),
    )
    .map_err(AppError::operational)?;
    let filesystem_file_count = inventory
        .get("file_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| AppError::operational("filesystem inventory omitted file count"))?;
    let filesystem_total_bytes = inventory
        .get("total_bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| AppError::operational("filesystem inventory omitted total bytes"))?;
    let manifest = session
        .manifest()
        .map_err(AppError::operational)?
        .ok_or_else(|| {
            AppError::operational(format!(
                "complete Session `{}` has no manifest",
                session.id()
            ))
        })?;
    Ok(RetentionPlanEntry {
        session_id: session.id().to_string(),
        state_revision: state.revision,
        state_sha256: digest_file(&session.path().join("state.json"))?,
        request_sha256: session.request_sha256().map_err(AppError::operational)?,
        manifest_sha256: digest_file(&session.path().join("manifest.json"))?,
        artifact_count: u64::try_from(manifest.artifacts.len())
            .map_err(|_| AppError::operational("manifest artifact count exceeds u64"))?,
        filesystem_file_count,
        filesystem_total_bytes,
        filesystem_inventory_sha256,
    })
}

fn validate_plan_entry(
    root: &ArtifactRoot,
    session: &Session,
    expected: &RetentionPlanEntry,
) -> Result<(), AppError> {
    let actual = snapshot_complete_session(root, session)?;
    if &actual != expected {
        return Err(AppError::operational(format!(
            "Session `{}` no longer matches retention plan: expected {}, observed {}",
            session.id(),
            serde_json::to_string(expected).map_err(AppError::operational)?,
            serde_json::to_string(&actual).map_err(AppError::operational)?
        )));
    }
    Ok(())
}

fn snapshot_abandonable_session(session: &Session) -> Result<AbandonPlanEntry, AppError> {
    let state = session.read_state().map_err(AppError::operational)?;
    if state.status == SessionStatus::Complete {
        return Err(AppError::operational(format!(
            "complete Session `{}` must use retention, not abandon quarantine",
            session.id()
        )));
    }
    let inventory = inventory_all_plain_session_files(session.path())?;
    Ok(AbandonPlanEntry {
        session_id: session.id().to_string(),
        status: state.status,
        state_revision: state.revision,
        state_sha256: digest_file(&session.path().join("state.json"))?,
        request_sha256: session.request_sha256().map_err(AppError::operational)?,
        filesystem_file_count: inventory.file_count,
        filesystem_total_bytes: inventory.total_bytes,
        filesystem_inventory_sha256: inventory.sha256,
    })
}

fn validate_abandon_entry(session: &Session, expected: &AbandonPlanEntry) -> Result<(), AppError> {
    let actual = snapshot_abandonable_session(session)?;
    if &actual != expected {
        return Err(AppError::operational(format!(
            "Session `{}` no longer matches abandon plan: expected {}, observed {}",
            session.id(),
            serde_json::to_string(expected).map_err(AppError::operational)?,
            serde_json::to_string(&actual).map_err(AppError::operational)?
        )));
    }
    Ok(())
}

fn inventory_all_plain_session_files(root: &Path) -> Result<FilesystemInventory, AppError> {
    let mut pending = vec![root.to_path_buf()];
    let mut records = Vec::new();
    let mut entries_inspected = 0_usize;
    while let Some(directory) = pending.pop() {
        let mut entries = fs::read_dir(&directory)
            .map_err(AppError::operational)?
            .collect::<io::Result<Vec<_>>>()
            .map_err(AppError::operational)?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            entries_inspected = entries_inspected.saturating_add(1);
            if entries_inspected > MAX_INSPECTION_ENTRIES {
                return Err(AppError::operational(format!(
                    "abandon inventory exceeds {MAX_INSPECTION_ENTRIES} filesystem entries"
                )));
            }
            let path = entry.path();
            let relative = portable_relative_path(root, &path)?;
            let metadata = fs::symlink_metadata(&path).map_err(AppError::operational)?;
            if unsafe_file_type(&metadata) || (!metadata.is_dir() && !metadata.is_file()) {
                return Err(AppError::operational(format!(
                    "abandon inventory contains unsafe filesystem entry `{relative}`"
                )));
            }
            if metadata.is_dir() {
                pending.push(path);
                continue;
            }
            let (size_bytes, sha256) = if relative == ".session.lock" {
                if metadata.len() != 0 {
                    return Err(AppError::operational(
                        "Session lock file must remain empty during abandon planning",
                    ));
                }
                (0, digest_bytes(&[])?)
            } else {
                digest_plain_file(&path)?
            };
            records.push(InventoryRecord {
                relative_path: relative,
                size_bytes,
                sha256,
            });
        }
    }
    filesystem_inventory(records)
}

fn validate_abandon_plan(plan: &AbandonPlan) -> Result<(), AppError> {
    if plan.schema != ABANDON_PLAN_SCHEMA || plan.action != ABANDON_ACTION {
        return Err(AppError::operational(
            "abandon plan schema or action is unsupported",
        ));
    }
    SessionId::new(plan.plan_id.clone()).map_err(AppError::operational)?;
    SessionId::new(plan.session.session_id.clone()).map_err(AppError::operational)?;
    if plan.session.status == SessionStatus::Complete {
        return Err(AppError::operational(
            "abandon plan cannot contain a complete Session",
        ));
    }
    plan.created_at
        .parse::<Timestamp>()
        .map_err(|error| AppError::operational(format!("invalid abandon timestamp: {error}")))?;
    Ok(())
}

fn load_abandon_plan(
    root: &ArtifactRoot,
    plan_id: &str,
) -> Result<(AbandonPlan, Sha256Digest), AppError> {
    let plan_id = SessionId::new(plan_id.to_owned()).map_err(AppError::operational)?;
    let directory = control_subdirectory(root, &["abandon", "plans"])?;
    let path = directory.join(format!("{plan_id}.json"));
    let bytes = read_bounded_plain_file(&path, MAX_CONTROL_DOCUMENT_BYTES)?;
    let digest = digest_bytes(&bytes)?;
    let plan: AbandonPlan = decode_control_document(&bytes)?;
    validate_abandon_plan(&plan)?;
    if plan.plan_id != plan_id.as_str() {
        return Err(AppError::operational(
            "abandon plan identity does not match its filename",
        ));
    }
    Ok((plan, digest))
}

fn verify_abandon_plan_root(root: &ArtifactRoot, plan: &AbandonPlan) -> Result<(), AppError> {
    if artifact_root_fingerprint(root)? != plan.artifact_root_fingerprint {
        return Err(AppError::operational(
            "abandon plan belongs to a different canonical artifact root",
        ));
    }
    Ok(())
}

fn validate_retention_plan(plan: &RetentionPlan) -> Result<(), AppError> {
    if plan.schema != RETENTION_PLAN_SCHEMA || plan.action != RETENTION_ACTION {
        return Err(AppError::operational(
            "retention plan schema or action is unsupported",
        ));
    }
    SessionId::new(plan.plan_id.clone()).map_err(AppError::operational)?;
    if plan.sessions.is_empty() {
        return Err(AppError::operational("retention plan is empty"));
    }
    if plan.sessions.len() > MAX_RETENTION_SESSIONS {
        return Err(AppError::operational(format!(
            "retention plan has {} Sessions; maximum is {MAX_RETENTION_SESSIONS}",
            plan.sessions.len()
        )));
    }
    plan.created_at
        .parse::<Timestamp>()
        .map_err(|error| AppError::operational(format!("invalid retention timestamp: {error}")))?;
    let mut previous = None;
    for entry in &plan.sessions {
        SessionId::new(entry.session_id.clone()).map_err(AppError::operational)?;
        if let Some(previous) = previous
            && previous >= entry.session_id.as_str()
        {
            return Err(AppError::operational(
                "retention plan Sessions must be unique and sorted",
            ));
        }
        previous = Some(entry.session_id.as_str());
    }
    Ok(())
}

fn load_retention_plan(
    root: &ArtifactRoot,
    plan_id: &str,
) -> Result<(RetentionPlan, Sha256Digest), AppError> {
    let plan_id = SessionId::new(plan_id.to_owned()).map_err(AppError::operational)?;
    let directory = control_subdirectory(root, &["retention", "plans"])?;
    let path = directory.join(format!("{plan_id}.json"));
    let bytes = read_bounded_plain_file(&path, MAX_CONTROL_DOCUMENT_BYTES)?;
    let digest = digest_bytes(&bytes)?;
    let plan: RetentionPlan = decode_control_document(&bytes)?;
    validate_retention_plan(&plan)?;
    if plan.plan_id != plan_id.as_str() {
        return Err(AppError::operational(
            "retention plan identity does not match its filename",
        ));
    }
    Ok((plan, digest))
}

fn verify_confirmation(expected: &Sha256Digest, confirmation: &str) -> Result<(), AppError> {
    let confirmation = Sha256Digest::new(confirmation.to_owned()).map_err(AppError::operational)?;
    if &confirmation != expected {
        return Err(AppError::operational(format!(
            "maintenance confirmation does not match the exact plan SHA-256; expected `{expected}`"
        )));
    }
    Ok(())
}

fn verify_plan_root(root: &ArtifactRoot, plan: &RetentionPlan) -> Result<(), AppError> {
    let actual = artifact_root_fingerprint(root)?;
    if actual != plan.artifact_root_fingerprint {
        return Err(AppError::operational(
            "retention plan belongs to a different canonical artifact root",
        ));
    }
    Ok(())
}

fn acquire_maintenance_lock(root: &ArtifactRoot) -> Result<MaintenanceLock, AppError> {
    let file = open_maintenance_lock_file(root)?;
    file.try_lock_exclusive().map_err(|error| {
        AppError::operational(format!(
            "artifact-root maintenance is already active or cannot be locked: {error}"
        ))
    })?;
    Ok(MaintenanceLock { file })
}

fn acquire_maintenance_lock_with_timeout(root: &ArtifactRoot) -> Result<MaintenanceLock, AppError> {
    let file = open_maintenance_lock_file(root)?;
    let started = Instant::now();
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(MaintenanceLock { file }),
            Err(_) if started.elapsed() < COMPARISON_MAINTENANCE_LOCK_TIMEOUT => {
                thread::sleep(COMPARISON_MAINTENANCE_LOCK_RETRY);
            }
            Err(error) => {
                return Err(AppError::operational(format!(
                    "artifact-root maintenance remained active or could not be locked within {} ms: {error}",
                    COMPARISON_MAINTENANCE_LOCK_TIMEOUT.as_millis()
                )));
            }
        }
    }
}

fn open_maintenance_lock_file(root: &ArtifactRoot) -> Result<File, AppError> {
    let directory = control_subdirectory(root, &[])?;
    let path = directory.join("maintenance.lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(AppError::operational)?;
    ensure_plain_file(&path)?;
    Ok(file)
}

fn control_subdirectory(root: &ArtifactRoot, parts: &[&str]) -> Result<PathBuf, AppError> {
    let mut current = root.path().to_path_buf();
    for part in std::iter::once(CONTROL_DIRECTORY).chain(parts.iter().copied()) {
        if part.is_empty() || part == "." || part == ".." || part.contains(['/', '\\']) {
            return Err(AppError::operational(
                "internal control-plane path component is invalid",
            ));
        }
        current.push(part);
        create_or_validate_plain_directory(&current)?;
    }
    Ok(current)
}

fn create_or_validate_plain_directory(path: &Path) -> Result<(), AppError> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(AppError::operational(error)),
    }
    let metadata = fs::symlink_metadata(path).map_err(AppError::operational)?;
    if !metadata.is_dir() || unsafe_file_type(&metadata) {
        return Err(AppError::operational(format!(
            "control-plane directory `{}` is not a plain directory",
            path.display()
        )));
    }
    Ok(())
}

fn plain_directory_exists(path: &Path) -> Result<bool, AppError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !unsafe_file_type(&metadata) => Ok(true),
        Ok(_) => Err(AppError::operational(format!(
            "expected `{}` to be a plain directory",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(AppError::operational(error)),
    }
}

fn ensure_plain_file(path: &Path) -> Result<(), AppError> {
    let metadata = fs::symlink_metadata(path).map_err(AppError::operational)?;
    if !metadata.is_file() || unsafe_file_type(&metadata) {
        return Err(AppError::operational(format!(
            "control-plane file `{}` is not a plain file",
            path.display()
        )));
    }
    Ok(())
}

fn unsafe_file_type(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    false
}

fn serialize_control_document(value: &impl Serialize) -> Result<Vec<u8>, AppError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(AppError::operational)?;
    bytes.push(b'\n');
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CONTROL_DOCUMENT_BYTES {
        return Err(AppError::operational(format!(
            "control-plane document exceeds {MAX_CONTROL_DOCUMENT_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), AppError> {
    if filesystem_entry_exists(path)? {
        return Err(AppError::operational(format!(
            "control-plane file already exists: `{}`",
            path.display()
        )));
    }
    let mut file = AtomicWriteFile::open(path).map_err(AppError::operational)?;
    file.write_all(bytes).map_err(AppError::operational)?;
    if filesystem_entry_exists(path)? {
        file.discard().map_err(AppError::operational)?;
        return Err(AppError::operational(format!(
            "control-plane file appeared during atomic publish: `{}`",
            path.display()
        )));
    }
    file.commit().map_err(AppError::operational)?;
    sync_control_directory(
        path.parent()
            .expect("control-plane file always has a parent directory"),
    )
}

fn filesystem_entry_exists(path: &Path) -> Result<bool, AppError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(AppError::operational(error)),
    }
}

#[cfg(unix)]
fn sync_control_directory(path: &Path) -> Result<(), AppError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(AppError::operational)
}

#[cfg(not(unix))]
fn sync_control_directory(_path: &Path) -> Result<(), AppError> {
    Ok(())
}

#[cfg(unix)]
fn sync_rename_parents(source: &Path, destination: &Path) -> Result<(), AppError> {
    let source_parent = source
        .parent()
        .ok_or_else(|| AppError::operational("rename source has no parent directory"))?;
    let destination_parent = destination
        .parent()
        .ok_or_else(|| AppError::operational("rename destination has no parent directory"))?;
    sync_control_directory(source_parent)?;
    if destination_parent != source_parent {
        sync_control_directory(destination_parent)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_rename_parents(_source: &Path, _destination: &Path) -> Result<(), AppError> {
    Ok(())
}

fn ensure_new_entry_capacity(directory: &Path) -> Result<(), AppError> {
    let mut count = 0_usize;
    for entry in fs::read_dir(directory)
        .map_err(AppError::operational)?
        .take(MAX_CONTROL_ENTRIES_PER_DIRECTORY.saturating_add(1))
    {
        entry.map_err(AppError::operational)?;
        count = count
            .checked_add(1)
            .ok_or_else(|| AppError::operational("control-plane directory entry count overflow"))?;
    }
    if count >= MAX_CONTROL_ENTRIES_PER_DIRECTORY {
        return Err(AppError::operational(format!(
            "control-plane directory `{}` has {count} entries; maximum is {MAX_CONTROL_ENTRIES_PER_DIRECTORY}",
            directory.display()
        )));
    }
    Ok(())
}

fn read_bounded_plain_file(path: &Path, limit: u64) -> Result<Vec<u8>, AppError> {
    ensure_plain_file(path)?;
    let file = File::open(path).map_err(AppError::operational)?;
    let metadata = file.metadata().map_err(AppError::operational)?;
    if metadata.len() > limit {
        return Err(AppError::operational(format!(
            "control-plane file `{}` exceeds {limit} bytes",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    BufReader::new(file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(AppError::operational)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(AppError::operational(format!(
            "control-plane file `{}` grew beyond {limit} bytes while reading",
            path.display()
        )));
    }
    Ok(bytes)
}

fn decode_control_document<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, AppError> {
    strict_json::from_slice(bytes).map_err(AppError::operational)
}

fn digest_bytes(bytes: &[u8]) -> Result<Sha256Digest, AppError> {
    Sha256Digest::new(encode_hex(&Sha256::digest(bytes))).map_err(AppError::operational)
}

fn digest_file(path: &Path) -> Result<Sha256Digest, AppError> {
    digest_plain_file(path).map(|(_, digest)| digest)
}

fn digest_plain_file(path: &Path) -> Result<(u64, Sha256Digest), AppError> {
    ensure_plain_file(path)?;
    let file = File::open(path).map_err(AppError::operational)?;
    let expected_size = file.metadata().map_err(AppError::operational)?.len();
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut observed_size = 0_u64;
    loop {
        let read = reader.read(&mut buffer).map_err(AppError::operational)?;
        if read == 0 {
            break;
        }
        observed_size = observed_size
            .checked_add(
                u64::try_from(read)
                    .map_err(|_| AppError::operational("file read length exceeds u64"))?,
            )
            .ok_or_else(|| AppError::operational("file size exceeds u64"))?;
        hasher.update(&buffer[..read]);
    }
    if observed_size != expected_size {
        return Err(AppError::operational(format!(
            "plain file `{}` changed size while hashing: expected {expected_size}, observed {observed_size}",
            path.display()
        )));
    }
    Ok((
        observed_size,
        Sha256Digest::new(encode_hex(&hasher.finalize())).map_err(AppError::operational)?,
    ))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn artifact_root_fingerprint(root: &ArtifactRoot) -> Result<Sha256Digest, AppError> {
    let normalized = root.path().to_string_lossy().replace('\\', "/");
    digest_bytes(normalized.as_bytes())
}

fn write_journal_event(
    directory: &Path,
    plan_id: &str,
    plan_sha256: &Sha256Digest,
    artifact_root_fingerprint: &Sha256Digest,
    sequence: usize,
    action: &str,
    session_id: &str,
) -> Result<(), AppError> {
    validate_existing_journal_event(
        directory,
        plan_id,
        plan_sha256,
        artifact_root_fingerprint,
        sequence,
        action,
        session_id,
    )?;
    let path = journal_event_path(directory, sequence, action, session_id);
    if filesystem_entry_exists(&path)? {
        return Ok(());
    }
    ensure_new_entry_capacity(directory)?;
    let event = RetentionJournalEvent {
        schema: RETENTION_JOURNAL_SCHEMA.to_owned(),
        plan_id: plan_id.to_owned(),
        plan_sha256: plan_sha256.clone(),
        artifact_root_fingerprint: artifact_root_fingerprint.clone(),
        sequence,
        action: action.to_owned(),
        session_id: session_id.to_owned(),
        recorded_at: Timestamp::now().to_string(),
    };
    write_new_file(&path, &serialize_control_document(&event)?)
}

fn validate_retention_journal_directory(
    directory: &Path,
    plan: &RetentionPlan,
    plan_sha256: &Sha256Digest,
) -> Result<(), AppError> {
    let maximum_events = plan
        .sessions
        .len()
        .checked_mul(2)
        .ok_or_else(|| AppError::operational("retention journal event limit overflow"))?;
    let mut entries_seen = 0_usize;
    for entry in fs::read_dir(directory)
        .map_err(AppError::operational)?
        .take(maximum_events.saturating_add(1))
    {
        let entry = entry.map_err(AppError::operational)?;
        entries_seen = entries_seen.saturating_add(1);
        if entries_seen > maximum_events {
            return Err(AppError::operational(format!(
                "retention journal directory `{}` has more than {maximum_events} events",
                directory.display()
            )));
        }
        let path = entry.path();
        let bytes = read_bounded_plain_file(&path, MAX_CONTROL_DOCUMENT_BYTES)?;
        let event: RetentionJournalEvent = decode_control_document(&bytes)?;
        validate_journal_event(&event)?;
        if event.plan_id != plan.plan_id
            || &event.plan_sha256 != plan_sha256
            || event.artifact_root_fingerprint != plan.artifact_root_fingerprint
        {
            return Err(AppError::operational(format!(
                "retention journal event `{}` is not bound to the requested plan and root",
                path.display()
            )));
        }
        let valid_plan_event = match event.action.as_str() {
            "quarantined" => plan
                .sessions
                .get(event.sequence)
                .is_some_and(|entry| entry.session_id == event.session_id),
            "restored" => {
                event.sequence == plan.sessions.len()
                    && plan
                        .sessions
                        .iter()
                        .any(|entry| entry.session_id == event.session_id)
            }
            _ => false,
        };
        let expected_path =
            journal_event_path(directory, event.sequence, &event.action, &event.session_id);
        if !valid_plan_event || path != expected_path {
            return Err(AppError::operational(format!(
                "retention journal event `{}` does not match a canonical plan event",
                path.display()
            )));
        }
    }
    Ok(())
}

fn validate_existing_journal_event(
    directory: &Path,
    plan_id: &str,
    plan_sha256: &Sha256Digest,
    artifact_root_fingerprint: &Sha256Digest,
    sequence: usize,
    action: &str,
    session_id: &str,
) -> Result<(), AppError> {
    let path = journal_event_path(directory, sequence, action, session_id);
    if !filesystem_entry_exists(&path)? {
        return Ok(());
    }
    let existing = read_bounded_plain_file(&path, MAX_CONTROL_DOCUMENT_BYTES)?;
    let event: RetentionJournalEvent = decode_control_document(&existing)?;
    validate_journal_event(&event)?;
    if event.plan_id == plan_id
        && &event.plan_sha256 == plan_sha256
        && &event.artifact_root_fingerprint == artifact_root_fingerprint
        && event.sequence == sequence
        && event.action == action
        && event.session_id == session_id
    {
        return Ok(());
    }
    Err(AppError::operational(format!(
        "retention journal event `{}` conflicts with the requested operation",
        path.display()
    )))
}

fn journal_event_path(
    directory: &Path,
    sequence: usize,
    action: &str,
    session_id: &str,
) -> PathBuf {
    directory.join(format!("{sequence:06}-{action}-{session_id}.json"))
}

fn validate_journal_event(event: &RetentionJournalEvent) -> Result<(), AppError> {
    if event.schema != RETENTION_JOURNAL_SCHEMA {
        return Err(AppError::operational(
            "retention journal schema is unsupported",
        ));
    }
    SessionId::new(event.plan_id.clone()).map_err(AppError::operational)?;
    SessionId::new(event.session_id.clone()).map_err(AppError::operational)?;
    if !matches!(event.action.as_str(), "quarantined" | "restored") {
        return Err(AppError::operational(
            "retention journal action is unsupported",
        ));
    }
    event
        .recorded_at
        .parse::<Timestamp>()
        .map_err(|error| AppError::operational(format!("invalid journal timestamp: {error}")))?;
    Ok(())
}

fn write_abandon_journal_event(
    directory: &Path,
    plan: &AbandonPlan,
    plan_sha256: &Sha256Digest,
    sequence: usize,
    action: &str,
) -> Result<(), AppError> {
    let path = journal_event_path(directory, sequence, action, &plan.session.session_id);
    if filesystem_entry_exists(&path)? {
        let bytes = read_bounded_plain_file(&path, MAX_CONTROL_DOCUMENT_BYTES)?;
        let event: AbandonJournalEvent = decode_control_document(&bytes)?;
        validate_abandon_journal_event(&event, plan, plan_sha256, &path)?;
        return Ok(());
    }
    ensure_new_entry_capacity(directory)?;
    let event = AbandonJournalEvent {
        schema: ABANDON_JOURNAL_SCHEMA.to_owned(),
        plan_id: plan.plan_id.clone(),
        plan_sha256: plan_sha256.clone(),
        artifact_root_fingerprint: plan.artifact_root_fingerprint.clone(),
        sequence,
        action: action.to_owned(),
        session_id: plan.session.session_id.clone(),
        recorded_at: Timestamp::now().to_string(),
    };
    validate_abandon_journal_event(&event, plan, plan_sha256, &path)?;
    write_new_file(&path, &serialize_control_document(&event)?)
}

fn validate_abandon_journal_directory(
    directory: &Path,
    plan: &AbandonPlan,
    plan_sha256: &Sha256Digest,
) -> Result<(), AppError> {
    let mut entries_seen = 0_usize;
    for entry in fs::read_dir(directory)
        .map_err(AppError::operational)?
        .take(3)
    {
        let entry = entry.map_err(AppError::operational)?;
        entries_seen = entries_seen.saturating_add(1);
        if entries_seen > 2 {
            return Err(AppError::operational(format!(
                "abandon journal directory `{}` has more than two events",
                directory.display()
            )));
        }
        let path = entry.path();
        let bytes = read_bounded_plain_file(&path, MAX_CONTROL_DOCUMENT_BYTES)?;
        let event: AbandonJournalEvent = decode_control_document(&bytes)?;
        validate_abandon_journal_event(&event, plan, plan_sha256, &path)?;
    }
    Ok(())
}

fn validate_abandon_journal_event(
    event: &AbandonJournalEvent,
    plan: &AbandonPlan,
    plan_sha256: &Sha256Digest,
    path: &Path,
) -> Result<(), AppError> {
    if event.schema != ABANDON_JOURNAL_SCHEMA
        || event.plan_id != plan.plan_id
        || &event.plan_sha256 != plan_sha256
        || event.artifact_root_fingerprint != plan.artifact_root_fingerprint
        || event.session_id != plan.session.session_id
        || !matches!(
            (event.sequence, event.action.as_str()),
            (0, "abandoned") | (1, "restored")
        )
    {
        return Err(AppError::operational(format!(
            "abandon journal event `{}` is not bound to the requested plan and root",
            path.display()
        )));
    }
    event.recorded_at.parse::<Timestamp>().map_err(|error| {
        AppError::operational(format!("invalid abandon journal timestamp: {error}"))
    })?;
    let expected = journal_event_path(
        path.parent()
            .ok_or_else(|| AppError::operational("abandon journal event has no parent"))?,
        event.sequence,
        &event.action,
        &event.session_id,
    );
    if path != expected {
        return Err(AppError::operational(format!(
            "abandon journal event `{}` has a noncanonical filename",
            path.display()
        )));
    }
    Ok(())
}

fn open_session(root: &ArtifactRoot, value: &str) -> Result<Session, AppError> {
    let id = SessionId::new(value.to_owned()).map_err(AppError::operational)?;
    root.session(&id).map_err(AppError::operational)
}

fn check(name: &str, ok: bool, message: impl Into<String>) -> Value {
    json!({"name": name, "ok": ok, "message": message.into()})
}

#[derive(Default)]
struct BoundedPaths {
    total: usize,
    samples: BTreeSet<String>,
}

impl BoundedPaths {
    fn record(&mut self, path: String) {
        self.total = self.total.saturating_add(1);
        self.samples.insert(path);
        if self.samples.len() > MAX_REPORTED_ENTRIES {
            self.samples.pop_last();
        }
    }

    fn entries(&self) -> Vec<&str> {
        self.samples.iter().map(String::as_str).collect()
    }

    fn truncated(&self, scan_truncated: bool) -> bool {
        scan_truncated || self.total > self.samples.len()
    }
}

struct FilesystemInventory {
    file_count: u64,
    total_bytes: u64,
    sha256: Sha256Digest,
}

struct InventoryRecord {
    relative_path: String,
    size_bytes: u64,
    sha256: Sha256Digest,
}

#[derive(Default)]
struct TreeInspection {
    staging: BoundedPaths,
    retained_staging: BoundedPaths,
    orphans: BoundedPaths,
    unsafe_entries: BoundedPaths,
    entries_inspected: usize,
    scan_truncated: bool,
    inventory: Option<FilesystemInventory>,
}

fn inspect_session_tree(
    session_root: &Path,
    registered_paths: &BTreeSet<String>,
    retained_staging_paths: &BTreeSet<String>,
    deep: bool,
) -> Result<TreeInspection, AppError> {
    inspect_session_tree_with_limit(
        session_root,
        registered_paths,
        retained_staging_paths,
        deep,
        MAX_INSPECTION_ENTRIES,
    )
}

fn inspect_session_tree_with_limit(
    session_root: &Path,
    registered_paths: &BTreeSet<String>,
    retained_staging_paths: &BTreeSet<String>,
    deep: bool,
    entry_limit: usize,
) -> Result<TreeInspection, AppError> {
    let mut result = TreeInspection::default();
    let mut pending = vec![session_root.to_path_buf()];
    let mut inventory_records = Vec::new();
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory).map_err(AppError::operational)?;
        for entry in entries {
            let entry = entry.map_err(AppError::operational)?;
            result.entries_inspected = result.entries_inspected.saturating_add(1);
            if result.entries_inspected > entry_limit {
                result.scan_truncated = true;
                return Ok(result);
            }
            let path = entry.path();
            let relative = portable_relative_path(session_root, &path)?;
            let metadata = fs::symlink_metadata(&path).map_err(AppError::operational)?;
            if unsafe_file_type(&metadata) {
                result.unsafe_entries.record(relative);
                continue;
            }
            if metadata.is_dir() {
                pending.push(path);
                continue;
            }
            if !metadata.is_file() {
                result.unsafe_entries.record(relative);
                continue;
            }
            let retained_staging = if relative.starts_with("capture/staging/") {
                if retained_staging_paths.contains(&relative) {
                    result.retained_staging.record(relative.clone());
                    true
                } else {
                    result.staging.record(relative);
                    continue;
                }
            } else {
                false
            };
            if !retained_staging
                && !is_session_metadata(&relative)
                && !registered_paths.contains(&relative)
            {
                result.orphans.record(relative);
                continue;
            }
            if deep {
                let (size_bytes, sha256) = if relative == ".session.lock" {
                    if metadata.len() != 0 {
                        return Err(AppError::operational(format!(
                            "Session lock file `{}` must remain empty",
                            path.display()
                        )));
                    }
                    (0, digest_bytes(&[])?)
                } else {
                    digest_plain_file(&path)?
                };
                inventory_records.push(InventoryRecord {
                    relative_path: relative.clone(),
                    size_bytes,
                    sha256,
                });
            }
        }
    }
    if deep {
        result.inventory = Some(filesystem_inventory(inventory_records)?);
    }
    Ok(result)
}

fn filesystem_inventory(
    mut records: Vec<InventoryRecord>,
) -> Result<FilesystemInventory, AppError> {
    records.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let file_count = u64::try_from(records.len())
        .map_err(|_| AppError::operational("filesystem inventory file count exceeds u64"))?;
    let total_bytes = records.iter().try_fold(0_u64, |total, record| {
        total.checked_add(record.size_bytes).ok_or_else(|| {
            AppError::operational("filesystem inventory total byte count exceeds u64")
        })
    })?;
    let mut hasher = Sha256::new();
    hasher.update(FILESYSTEM_INVENTORY_DOMAIN);
    hasher.update(file_count.to_be_bytes());
    hasher.update(total_bytes.to_be_bytes());
    let mut previous = None;
    for record in records {
        if previous.as_deref() == Some(record.relative_path.as_str()) {
            return Err(AppError::operational(format!(
                "filesystem inventory contains duplicate path `{}`",
                record.relative_path
            )));
        }
        let path_bytes = record.relative_path.as_bytes();
        let path_length = u64::try_from(path_bytes.len())
            .map_err(|_| AppError::operational("filesystem inventory path length exceeds u64"))?;
        hasher.update(path_length.to_be_bytes());
        hasher.update(path_bytes);
        hasher.update(record.size_bytes.to_be_bytes());
        hasher.update(record.sha256.as_str().as_bytes());
        previous = Some(record.relative_path);
    }
    Ok(FilesystemInventory {
        file_count,
        total_bytes,
        sha256: Sha256Digest::new(encode_hex(&hasher.finalize())).map_err(AppError::operational)?,
    })
}

fn is_session_metadata(relative: &str) -> bool {
    matches!(
        relative,
        ".session.lock" | "request.json" | "state.json" | "manifest.json"
    ) || (relative.starts_with("artifact-index/") && relative.ends_with(".json"))
        || (relative.starts_with("ingest-intents/") && relative.ends_with(".json"))
        || (relative.starts_with("committed-staging-sources/") && relative.ends_with(".json"))
}

fn portable_relative_path(root: &Path, path: &Path) -> Result<String, AppError> {
    let relative = path.strip_prefix(root).map_err(AppError::operational)?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(value) => parts.push(value.to_string_lossy().into_owned()),
            _ => {
                return Err(AppError::operational(format!(
                    "non-portable Session entry `{}`",
                    path.display()
                )));
            }
        }
    }
    Ok(parts.join("/"))
}

fn redact_paths(value: &mut Value, artifact_root: &Path) {
    let native = artifact_root.to_string_lossy().into_owned();
    let portable = native.replace('\\', "/");
    match value {
        Value::String(text) => {
            *text = text
                .replace(&native, "<artifact-root>")
                .replace(&portable, "<artifact-root>");
        }
        Value::Array(values) => {
            for value in values {
                redact_paths(value, artifact_root);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                redact_paths(value, artifact_root);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn constrain_diagnostic_inspection(inspection: &mut Value) {
    truncate_diagnostic_array(inspection, "artifacts", "artifact_claims_truncated");
    truncate_diagnostic_array(inspection, "ingest_intents", "ingest_intents_truncated");
    truncate_diagnostic_array(inspection, "staging_files", "staging_files_truncated");
    truncate_diagnostic_array(
        inspection,
        "unregistered_files",
        "unregistered_files_truncated",
    );
    truncate_diagnostic_array(inspection, "unsafe_entries", "unsafe_entries_truncated");
    constrain_diagnostic_strings(inspection);
}

fn truncate_diagnostic_array(value: &mut Value, array_key: &str, truncated_key: &str) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    let was_truncated = object
        .get(array_key)
        .and_then(Value::as_array)
        .is_some_and(|values| values.len() > MAX_DIAGNOSTIC_REPORTED_ENTRIES);
    if let Some(values) = object.get_mut(array_key).and_then(Value::as_array_mut)
        && was_truncated
    {
        values.truncate(MAX_DIAGNOSTIC_REPORTED_ENTRIES);
    }
    if was_truncated {
        object.insert(truncated_key.to_owned(), Value::Bool(true));
    }
}

fn constrain_diagnostic_strings(value: &mut Value) {
    match value {
        Value::String(text) => truncate_utf8(text, MAX_DIAGNOSTIC_STRING_BYTES),
        Value::Array(values) => {
            for value in values {
                constrain_diagnostic_strings(value);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                constrain_diagnostic_strings(value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn truncate_utf8(value: &mut String, limit: usize) {
    if value.len() <= limit {
        return;
    }
    let suffix = "...";
    let mut boundary = limit.saturating_sub(suffix.len());
    while !value.is_char_boundary(boundary) {
        boundary = boundary.saturating_sub(1);
    }
    value.truncate(boundary);
    value.push_str(suffix);
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use t32perf_model::{
        AdapterInfo, CaptureInfo, FirmwareInfo, Manifest, ManifestSchemaVersion,
        PerformanceRunRequest, ToolInfo,
    };
    use t32perf_session::{ArtifactRoot, ArtifactSpec, SessionId, SessionLimits};
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn control_documents_reject_duplicate_members_recursively() {
        let error = decode_control_document::<Value>(
            br#"{"schema":"t32perf.retention-plan/v1","session":{"evidence":{"digest":"first","digest":"last"}}}"#,
        )
        .expect_err("duplicate control-document member");

        assert!(
            error
                .message
                .contains("duplicate JSON object member name `digest`")
        );
    }

    #[test]
    fn comparison_serialization_is_streamed_deterministic_and_bounded() {
        let document = json!({"schema": "test/v1", "payload": "x".repeat(128)});
        let (_, first_size, first_digest) =
            serialize_bounded_json_line(io::sink(), &document, 1024).expect("serialize report");
        let (_, second_size, second_digest) =
            serialize_bounded_json_line(io::sink(), &document, 1024).expect("serialize report");
        assert_eq!(first_size, second_size);
        assert_eq!(first_digest, second_digest);

        let error = serialize_bounded_json_line(io::sink(), &document, 32)
            .expect_err("writer must reject output above its independent limit");
        assert!(
            error
                .message
                .contains("comparison artifact exceeds 32 bytes")
        );
    }

    fn complete_session(root: &ArtifactRoot, id: &str, request: Value) {
        let session = root
            .create_session_with_id(SessionId::new(id).unwrap(), &request)
            .unwrap();
        let lock = session.try_lock().unwrap();
        session
            .transition(&lock, SessionStatus::Capturing, None)
            .unwrap();
        let captured = session
            .transition(&lock, SessionStatus::Captured, None)
            .unwrap();
        let manifest = Manifest {
            schema: ManifestSchemaVersion,
            session_id: id.to_owned(),
            created_at: captured.created_at,
            tool: ToolInfo {
                name: "t32perf-test".to_owned(),
                version: "0.1.0".to_owned(),
                commit: None,
            },
            capture: CaptureInfo {
                provider: None,
                mode: "synthetic".to_owned(),
                adapter: AdapterInfo {
                    id: "synthetic-v1".to_owned(),
                    version: "1".to_owned(),
                },
                target: None,
                trace32: None,
                request_sha256: None,
                covered_cores: Vec::new(),
                capabilities: None,
                capture_config: None,
                instrumentation: None,
            },
            firmware: FirmwareInfo {
                elf_path: None,
                elf_sha256: None,
                build_id: None,
            },
            clocks: Vec::new(),
            stages: Vec::new(),
            artifacts: Vec::new(),
        };
        session.finalize(&lock, &manifest).unwrap();
    }

    fn performance_run_request() -> Value {
        serde_json::to_value(PerformanceRunRequest {
            schema: t32perf_model::PerformanceRunRequestSchemaVersion,
            duration_ns: 1_000_000,
            top: 1,
            report_format: t32perf_model::PerformanceReportFormat::PerfettoJson,
        })
        .unwrap()
    }

    fn expect_perf_run_busy(result: Result<CommandOutcome, AppError>) {
        let error = match result {
            Ok(_) => panic!("maintenance unexpectedly acquired an active perf_run Session"),
            Err(error) => error,
        };
        assert_eq!(error.code, "SESSION_EXECUTION_BUSY");
    }

    fn complete_session_with_retained_source(root: &ArtifactRoot, id: &str) -> Session {
        let session = root
            .create_session_with_id(SessionId::new(id).unwrap(), &json!({}))
            .unwrap();
        let lock = session.try_lock().unwrap();
        session
            .transition(&lock, SessionStatus::Capturing, None)
            .unwrap();
        let staged = t32perf_model::ArtifactPath::new("retained.bin").unwrap();
        fs::write(session.staging_path(&staged).unwrap(), b"trace-data").unwrap();
        let artifact = session
            .ingest_staged(
                &lock,
                &staged,
                ArtifactSpec {
                    id: "retained-source".to_owned(),
                    kind: "raw_trace".to_owned(),
                    relative_path: t32perf_model::ArtifactPath::new("capture/raw/retained.bin")
                        .unwrap(),
                    media_type: "application/octet-stream".to_owned(),
                    producer: "test".to_owned(),
                    input_artifact_ids: Vec::new(),
                },
            )
            .unwrap();
        let captured = session
            .transition(&lock, SessionStatus::Captured, None)
            .unwrap();
        let manifest = Manifest {
            schema: ManifestSchemaVersion,
            session_id: id.to_owned(),
            created_at: captured.created_at,
            tool: ToolInfo {
                name: "t32perf-test".to_owned(),
                version: "0.1.0".to_owned(),
                commit: None,
            },
            capture: CaptureInfo {
                provider: None,
                mode: "synthetic".to_owned(),
                adapter: AdapterInfo {
                    id: "synthetic-v1".to_owned(),
                    version: "1".to_owned(),
                },
                target: None,
                trace32: None,
                request_sha256: None,
                covered_cores: Vec::new(),
                capabilities: None,
                capture_config: None,
                instrumentation: None,
            },
            firmware: FirmwareInfo {
                elf_path: None,
                elf_sha256: None,
                build_id: None,
            },
            clocks: Vec::new(),
            stages: Vec::new(),
            artifacts: vec![artifact],
        };
        session.finalize(&lock, &manifest).unwrap();
        session
    }

    #[test]
    fn retention_requires_exact_plan_digest_and_is_recoverable() {
        let temp = TempDir::new().unwrap();
        let root =
            ArtifactRoot::open(temp.path().join("sessions"), SessionLimits::default()).unwrap();
        complete_session(&root, "session-a", json!({"secret": "do-not-copy"}));

        let planned = retention_plan(&root, &["session-a".to_owned()]).unwrap();
        let plan_id = planned.result["plan_id"].as_str().unwrap();
        let confirmation = planned.result["confirm_sha256"].as_str().unwrap();
        let wrong = "0".repeat(64);
        assert!(retention_apply(&root, plan_id, &wrong).is_err());
        assert!(root.path().join("session-a").is_dir());

        let applied = retention_apply(&root, plan_id, confirmation).unwrap();
        assert_eq!(applied.result["moved"], json!(["session-a"]));
        assert!(!root.path().join("session-a").exists());
        let applied_again = retention_apply(&root, plan_id, confirmation).unwrap();
        assert_eq!(
            applied_again.result["already_quarantined"],
            json!(["session-a"])
        );

        let restored_once = retention_restore(&root, plan_id, "session-a", confirmation).unwrap();
        assert_eq!(restored_once.result["restored"], true);
        let restored_again = retention_restore(&root, plan_id, "session-a", confirmation).unwrap();
        assert_eq!(restored_again.result["already_restored"], true);
        let restored = root.session(&SessionId::new("session-a").unwrap()).unwrap();
        let manifest = restored.manifest().unwrap().unwrap();
        restored.validate_manifest(&manifest, true).unwrap();
    }

    #[test]
    fn abandon_quarantines_an_entire_incomplete_session_with_exact_recovery() {
        let temp = TempDir::new().unwrap();
        let root =
            ArtifactRoot::open(temp.path().join("sessions"), SessionLimits::default()).unwrap();
        root.create_session_with_id(
            SessionId::new("crash-residue").unwrap(),
            &json!({"workload": "interrupted"}),
        )
        .unwrap();
        let staging = root
            .path()
            .join("crash-residue/capture/staging/partial.bin");
        let orphan = root.path().join("crash-residue/logs/process.tmp");
        fs::write(&staging, b"partial capture").unwrap();
        fs::write(&orphan, b"atomic residue").unwrap();

        let planned = abandon_plan(&root, "crash-residue").unwrap();
        let plan_id = planned.result["plan_id"].as_str().unwrap();
        let confirmation = planned.result["confirm_sha256"].as_str().unwrap();
        assert!(planned.result["filesystem_file_count"].as_u64().unwrap() >= 5);
        assert!(abandon_apply(&root, plan_id, &"0".repeat(64)).is_err());

        fs::write(&orphan, b"changed after plan").unwrap();
        assert!(abandon_apply(&root, plan_id, confirmation).is_err());
        fs::write(&orphan, b"atomic residue").unwrap();

        let applied = abandon_apply(&root, plan_id, confirmation).unwrap();
        assert_eq!(applied.result["abandoned"], true);
        assert!(!root.path().join("crash-residue").exists());
        let applied_again = abandon_apply(&root, plan_id, confirmation).unwrap();
        assert_eq!(applied_again.result["already_abandoned"], true);

        let restored = abandon_restore(&root, plan_id, confirmation).unwrap();
        assert_eq!(restored.result["restored"], true);
        assert_eq!(fs::read(&staging).unwrap(), b"partial capture");
        assert_eq!(fs::read(&orphan).unwrap(), b"atomic residue");
        let restored_again = abandon_restore(&root, plan_id, confirmation).unwrap();
        assert_eq!(restored_again.result["already_restored"], true);
    }

    #[test]
    fn active_perf_run_lease_blocks_complete_and_incomplete_maintenance_plans() {
        let temp = TempDir::new().unwrap();
        let root =
            ArtifactRoot::open(temp.path().join("sessions"), SessionLimits::default()).unwrap();
        let incomplete = root
            .create_session_with_id(
                SessionId::new("active-incomplete-perf-run").unwrap(),
                &performance_run_request(),
            )
            .unwrap();
        let incomplete_before = incomplete.read_state().unwrap();
        let lease = crate::perf_run::try_acquire_session_id_execution_lease(&root, incomplete.id())
            .unwrap();

        expect_perf_run_busy(abandon_plan(&root, incomplete.id().as_str()));
        assert_eq!(incomplete.read_state().unwrap(), incomplete_before);
        drop(lease);

        complete_session(&root, "active-complete-perf-run", performance_run_request());
        let complete_id = SessionId::new("active-complete-perf-run").unwrap();
        let complete = root.session(&complete_id).unwrap();
        let complete_before = complete.read_state().unwrap();
        let lease =
            crate::perf_run::try_acquire_session_id_execution_lease(&root, &complete_id).unwrap();

        expect_perf_run_busy(retention_plan(&root, &[complete_id.as_str().to_owned()]));
        assert_eq!(complete.read_state().unwrap(), complete_before);
        drop(lease);
    }

    #[test]
    fn active_perf_run_lease_blocks_retention_apply_and_restore() {
        let temp = TempDir::new().unwrap();
        let root =
            ArtifactRoot::open(temp.path().join("sessions"), SessionLimits::default()).unwrap();
        let id = SessionId::new("retained-perf-run").unwrap();
        complete_session(&root, id.as_str(), performance_run_request());
        let planned = retention_plan(&root, &[id.as_str().to_owned()]).unwrap();
        let plan_id = planned.result["plan_id"].as_str().unwrap();
        let confirmation = planned.result["confirm_sha256"].as_str().unwrap();
        let lease = crate::perf_run::try_acquire_session_id_execution_lease(&root, &id).unwrap();

        expect_perf_run_busy(retention_apply(&root, plan_id, confirmation));
        assert!(root.path().join(id.as_str()).is_dir());
        drop(lease);

        retention_apply(&root, plan_id, confirmation).unwrap();
        let quarantine = root
            .path()
            .join(CONTROL_DIRECTORY)
            .join("retention/quarantine")
            .join(plan_id)
            .join(id.as_str());
        assert!(quarantine.is_dir());
        let lease = crate::perf_run::try_acquire_session_id_execution_lease(&root, &id).unwrap();

        expect_perf_run_busy(retention_restore(&root, plan_id, id.as_str(), confirmation));
        assert!(quarantine.is_dir());
        assert!(!root.path().join(id.as_str()).exists());
        drop(lease);

        retention_restore(&root, plan_id, id.as_str(), confirmation).unwrap();
        assert!(root.path().join(id.as_str()).is_dir());
    }

    #[test]
    fn active_perf_run_lease_blocks_abandon_apply_and_restore() {
        let temp = TempDir::new().unwrap();
        let root =
            ArtifactRoot::open(temp.path().join("sessions"), SessionLimits::default()).unwrap();
        let id = SessionId::new("abandoned-perf-run").unwrap();
        root.create_session_with_id(id.clone(), &performance_run_request())
            .unwrap();
        let planned = abandon_plan(&root, id.as_str()).unwrap();
        let plan_id = planned.result["plan_id"].as_str().unwrap();
        let confirmation = planned.result["confirm_sha256"].as_str().unwrap();
        let lease = crate::perf_run::try_acquire_session_id_execution_lease(&root, &id).unwrap();

        expect_perf_run_busy(abandon_apply(&root, plan_id, confirmation));
        assert!(root.path().join(id.as_str()).is_dir());
        drop(lease);

        abandon_apply(&root, plan_id, confirmation).unwrap();
        let quarantine = root
            .path()
            .join(CONTROL_DIRECTORY)
            .join("abandon/quarantine")
            .join(plan_id)
            .join(id.as_str());
        assert!(quarantine.is_dir());
        let lease = crate::perf_run::try_acquire_session_id_execution_lease(&root, &id).unwrap();

        expect_perf_run_busy(abandon_restore(&root, plan_id, confirmation));
        assert!(quarantine.is_dir());
        assert!(!root.path().join(id.as_str()).exists());
        drop(lease);

        abandon_restore(&root, plan_id, confirmation).unwrap();
        assert!(root.path().join(id.as_str()).is_dir());
    }

    #[test]
    fn abandon_rejects_complete_sessions_and_unsafe_entries() {
        let temp = TempDir::new().unwrap();
        let root =
            ArtifactRoot::open(temp.path().join("sessions"), SessionLimits::default()).unwrap();
        complete_session(&root, "complete", json!({}));
        let error = match abandon_plan(&root, "complete") {
            Ok(_) => panic!("abandon unexpectedly accepted a complete Session"),
            Err(error) => error,
        };
        assert!(error.message.contains("must use retention"));

        let session = root
            .create_session_with_id(SessionId::new("unsafe").unwrap(), &json!({}))
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(
                session.path().join("state.json"),
                session.path().join("logs/linked-state"),
            )
            .unwrap();
            let error = match abandon_plan(&root, "unsafe") {
                Ok(_) => panic!("abandon unexpectedly accepted an unsafe entry"),
                Err(error) => error,
            };
            assert!(error.message.contains("unsafe filesystem entry"));
        }
        #[cfg(windows)]
        {
            fs::write(session.path().join("logs/plain-residue.tmp"), b"owned").unwrap();
            assert!(abandon_plan(&root, "unsafe").is_ok());
        }
    }

    #[test]
    fn diagnostics_excludes_request_and_artifact_payloads() {
        let temp = TempDir::new().unwrap();
        let root =
            ArtifactRoot::open(temp.path().join("sessions"), SessionLimits::default()).unwrap();
        complete_session(
            &root,
            "session-diagnostics",
            json!({"credential": "not-in-diagnostic-bundle"}),
        );

        let outcome = diagnostics(&root, "session-diagnostics").unwrap();
        let relative = outcome.result["control_path"].as_str().unwrap();
        let contents = fs::read_to_string(root.path().join(relative)).unwrap();
        assert!(!contents.contains("not-in-diagnostic-bundle"));
        assert!(contents.contains("raw_artifacts_included"));
        assert!(contents.contains("request_body_included"));
        assert!(contents.contains("artifact_root_paths_redacted"));
        assert!(!contents.contains("absolute_paths_redacted"));
    }

    #[test]
    fn inspection_reports_unregistered_files_without_removing_them() {
        let temp = TempDir::new().unwrap();
        let root =
            ArtifactRoot::open(temp.path().join("sessions"), SessionLimits::default()).unwrap();
        complete_session(&root, "session-orphan", json!({}));
        let orphan = root
            .path()
            .join("session-orphan")
            .join("logs")
            .join("orphan.log");
        fs::write(&orphan, b"diagnostic evidence").unwrap();

        let outcome = inspect(&root, "session-orphan", true).unwrap();
        assert_eq!(outcome.exit_code, EXIT_OPERATIONAL);
        assert_eq!(
            outcome.result["unregistered_files"],
            json!(["logs/orphan.log"])
        );
        assert_eq!(outcome.result["unregistered_files_total"], 1);
        assert_eq!(outcome.result["unregistered_files_truncated"], false);
        assert!(orphan.is_file());
    }

    #[test]
    fn retention_plan_rejects_incomplete_filesystem_evidence() {
        for (case, relative, contents, expected_check) in [
            (
                "orphan",
                "logs/orphan.log",
                b"orphan".as_slice(),
                "unregistered_files",
            ),
            (
                "staging",
                "capture/staging/stale.bin",
                b"staged".as_slice(),
                "staging",
            ),
            (
                "intent",
                "ingest-intents/stale.json",
                b"{".as_slice(),
                "ingest_intents",
            ),
        ] {
            let temp = TempDir::new().unwrap();
            let root =
                ArtifactRoot::open(temp.path().join(case), SessionLimits::default()).unwrap();
            complete_session(&root, "candidate", json!({}));
            fs::write(root.path().join("candidate").join(relative), contents).unwrap();

            let error = match retention_plan(&root, &["candidate".to_owned()]) {
                Ok(_) => panic!("retention unexpectedly accepted {case}"),
                Err(error) => error,
            };
            assert!(
                error.message.contains(expected_check),
                "unexpected error for {case}: {}",
                error.message
            );
        }
    }

    #[test]
    fn inspection_verifies_retained_sources_at_the_requested_depth() {
        let cases = [
            ("missing", None, false, false),
            (
                "wrong-size",
                Some(b"different-size".as_slice()),
                false,
                false,
            ),
            ("same-size", Some(b"alter-data".as_slice()), true, false),
        ];
        for (case, replacement, shallow_healthy, deep_healthy) in cases {
            let temp = TempDir::new().unwrap();
            let root =
                ArtifactRoot::open(temp.path().join(case), SessionLimits::default()).unwrap();
            let session = complete_session_with_retained_source(&root, "candidate");
            let staged = session.staging_root().join("retained.bin");
            match replacement {
                Some(bytes) => fs::write(&staged, bytes).unwrap(),
                None => fs::remove_file(&staged).unwrap(),
            }

            let shallow = inspect(&root, "candidate", false).unwrap();
            assert_eq!(
                shallow.result["healthy"],
                json!(shallow_healthy),
                "unexpected shallow result for {case}"
            );
            let deep = inspect(&root, "candidate", true).unwrap();
            assert_eq!(
                deep.result["healthy"],
                json!(deep_healthy),
                "unexpected deep result for {case}"
            );
            if case == "same-size" {
                assert_eq!(shallow.exit_code, EXIT_SUCCESS);
                assert_eq!(deep.exit_code, EXIT_OPERATIONAL);
            } else {
                assert_eq!(shallow.exit_code, EXIT_OPERATIONAL);
                assert_eq!(deep.exit_code, EXIT_OPERATIONAL);
            }
        }
    }

    #[test]
    fn retention_requires_deep_retained_source_verification() {
        let temp = TempDir::new().unwrap();
        let root =
            ArtifactRoot::open(temp.path().join("sessions"), SessionLimits::default()).unwrap();
        let session = complete_session_with_retained_source(&root, "candidate");
        fs::write(session.staging_root().join("retained.bin"), b"alter-data").unwrap();

        let error = match retention_plan(&root, &["candidate".to_owned()]) {
            Ok(_) => panic!("retention unexpectedly accepted a tampered retained source"),
            Err(error) => error,
        };
        assert!(error.message.contains("committed_staging_sources"));
    }

    #[cfg(unix)]
    #[test]
    fn retention_plan_rejects_unsafe_filesystem_entries() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let root =
            ArtifactRoot::open(temp.path().join("sessions"), SessionLimits::default()).unwrap();
        complete_session(&root, "candidate", json!({}));
        symlink(
            root.path().join("candidate").join("state.json"),
            root.path()
                .join("candidate")
                .join("logs")
                .join("linked-state"),
        )
        .unwrap();

        let error = match retention_plan(&root, &["candidate".to_owned()]) {
            Ok(_) => panic!("retention unexpectedly accepted unsafe entry"),
            Err(error) => error,
        };
        assert!(error.message.contains("filesystem_entries"));
    }

    #[test]
    fn retention_revalidates_state_digest_and_zero_length_orphans() {
        let temp = TempDir::new().unwrap();
        let root =
            ArtifactRoot::open(temp.path().join("sessions"), SessionLimits::default()).unwrap();
        complete_session(&root, "state-tamper", json!({}));
        let planned = retention_plan(&root, &["state-tamper".to_owned()]).unwrap();
        let plan_id = planned.result["plan_id"].as_str().unwrap();
        let confirmation = planned.result["confirm_sha256"].as_str().unwrap();
        let plan_path = root
            .path()
            .join(planned.result["control_path"].as_str().unwrap());
        let plan: RetentionPlan = serde_json::from_slice(&fs::read(&plan_path).unwrap()).unwrap();
        assert!(plan.sessions[0].filesystem_file_count >= 4);
        assert_eq!(
            plan.sessions[0].state_sha256,
            digest_file(&root.path().join("state-tamper/state.json")).unwrap()
        );

        let session = root
            .session(&SessionId::new("state-tamper").unwrap())
            .unwrap();
        let state = session.read_state().unwrap();
        let state_path = session.path().join("state.json");
        let original = fs::read_to_string(&state_path).unwrap();
        let replacement_first = if state.operation_id.starts_with('0') {
            "1"
        } else {
            "0"
        };
        let replacement = format!("{replacement_first}{}", &state.operation_id[1..]);
        let tampered = original.replacen(&state.operation_id, &replacement, 1);
        assert_eq!(tampered.len(), original.len());
        fs::write(&state_path, tampered).unwrap();
        assert!(retention_apply(&root, plan_id, confirmation).is_err());
        assert!(session.path().is_dir());

        let temp = TempDir::new().unwrap();
        let root =
            ArtifactRoot::open(temp.path().join("sessions"), SessionLimits::default()).unwrap();
        complete_session(&root, "orphan-after-plan", json!({}));
        let planned = retention_plan(&root, &["orphan-after-plan".to_owned()]).unwrap();
        fs::write(
            root.path().join("orphan-after-plan/logs/zero-length.log"),
            b"",
        )
        .unwrap();
        assert!(
            retention_apply(
                &root,
                planned.result["plan_id"].as_str().unwrap(),
                planned.result["confirm_sha256"].as_str().unwrap(),
            )
            .is_err()
        );
        assert!(root.path().join("orphan-after-plan").is_dir());
    }

    #[test]
    fn retention_rejects_tampered_plan_even_with_its_new_digest() {
        let temp = TempDir::new().unwrap();
        let root =
            ArtifactRoot::open(temp.path().join("sessions"), SessionLimits::default()).unwrap();
        complete_session(&root, "candidate", json!({}));
        let planned = retention_plan(&root, &["candidate".to_owned()]).unwrap();
        let plan_id = planned.result["plan_id"].as_str().unwrap();
        let plan_path = root
            .path()
            .join(planned.result["control_path"].as_str().unwrap());
        let mut plan: RetentionPlan =
            serde_json::from_slice(&fs::read(&plan_path).unwrap()).unwrap();
        plan.sessions[0].state_revision += 1;
        let bytes = serialize_control_document(&plan).unwrap();
        fs::write(&plan_path, &bytes).unwrap();
        let tampered_digest = digest_bytes(&bytes).unwrap();

        assert!(retention_apply(&root, plan_id, tampered_digest.as_str()).is_err());
        assert!(root.path().join("candidate").is_dir());
    }

    #[test]
    fn retention_recovers_rename_without_journal_and_rejects_corrupt_journal() {
        let temp = TempDir::new().unwrap();
        let root =
            ArtifactRoot::open(temp.path().join("sessions"), SessionLimits::default()).unwrap();
        complete_session(&root, "renamed", json!({}));
        let planned = retention_plan(&root, &["renamed".to_owned()]).unwrap();
        let plan_id = planned.result["plan_id"].as_str().unwrap();
        let confirmation = planned.result["confirm_sha256"].as_str().unwrap();
        let quarantine =
            control_subdirectory(&root, &["retention", "quarantine", plan_id]).unwrap();
        fs::rename(root.path().join("renamed"), quarantine.join("renamed")).unwrap();

        let recovered = retention_apply(&root, plan_id, confirmation).unwrap();
        assert_eq!(recovered.result["already_quarantined"], json!(["renamed"]));
        let journal = root
            .path()
            .join(CONTROL_DIRECTORY)
            .join("retention/journals")
            .join(plan_id)
            .join("000000-quarantined-renamed.json");
        let event: RetentionJournalEvent =
            serde_json::from_slice(&fs::read(&journal).unwrap()).unwrap();
        validate_journal_event(&event).unwrap();
        assert_eq!(
            retention_apply(&root, plan_id, confirmation)
                .unwrap()
                .result["already_quarantined"],
            json!(["renamed"])
        );

        let temp = TempDir::new().unwrap();
        let root =
            ArtifactRoot::open(temp.path().join("sessions"), SessionLimits::default()).unwrap();
        complete_session(&root, "corrupt-journal", json!({}));
        let planned = retention_plan(&root, &["corrupt-journal".to_owned()]).unwrap();
        let plan_id = planned.result["plan_id"].as_str().unwrap();
        let journal = control_subdirectory(&root, &["retention", "journals", plan_id]).unwrap();
        fs::write(journal.join("unexpected-truncated.json"), b"{").unwrap();
        assert!(
            retention_apply(
                &root,
                plan_id,
                planned.result["confirm_sha256"].as_str().unwrap()
            )
            .is_err()
        );
        assert!(root.path().join("corrupt-journal").is_dir());
    }

    #[test]
    fn inspection_and_diagnostics_bound_large_problem_sets() {
        let temp = TempDir::new().unwrap();
        let root =
            ArtifactRoot::open(temp.path().join("sessions"), SessionLimits::default()).unwrap();
        complete_session(&root, "many", json!({"marker": "request-secret-marker"}));
        let session_path = root.path().join("many");
        for index in 0..600 {
            fs::write(
                session_path
                    .join("logs")
                    .join(format!("orphan-{index:04}.log")),
                b"x",
            )
            .unwrap();
            fs::write(
                session_path
                    .join("capture/staging")
                    .join(format!("staged-{index:04}.bin")),
                b"x",
            )
            .unwrap();
            fs::write(
                session_path
                    .join("ingest-intents")
                    .join(format!("intent-{index:04}.json")),
                b"{",
            )
            .unwrap();
        }

        let inspection = inspect(&root, "many", true).unwrap();
        assert_eq!(inspection.result["unregistered_files_total"], 600);
        assert_eq!(inspection.result["staging_files_total"], 600);
        assert_eq!(inspection.result["ingest_intents_total"], 600);
        assert_eq!(
            inspection.result["unregistered_files"]
                .as_array()
                .unwrap()
                .len(),
            MAX_REPORTED_ENTRIES
        );
        assert_eq!(inspection.result["unregistered_files_truncated"], true);
        assert_eq!(inspection.result["staging_files_truncated"], true);
        assert_eq!(inspection.result["ingest_intents_truncated"], true);

        let diagnostic = diagnostics(&root, "many").unwrap();
        let path = root
            .path()
            .join(diagnostic.result["control_path"].as_str().unwrap());
        let bytes = fs::read(path).unwrap();
        assert!(u64::try_from(bytes.len()).unwrap() <= MAX_CONTROL_DOCUMENT_BYTES);
        let document: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(document["inspection"]["unregistered_files_total"], 600);
        assert!(
            document["inspection"]["unregistered_files"]
                .as_array()
                .unwrap()
                .len()
                <= MAX_DIAGNOSTIC_REPORTED_ENTRIES
        );
        assert!(
            !String::from_utf8(bytes)
                .unwrap()
                .contains("request-secret-marker")
        );
    }

    #[test]
    fn inspection_stops_after_the_configured_entry_limit() {
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join("a"), b"a").unwrap();
        fs::write(temp.path().join("b"), b"b").unwrap();
        let inspection = inspect_session_tree_with_limit(
            temp.path(),
            &BTreeSet::new(),
            &BTreeSet::new(),
            true,
            1,
        )
        .unwrap();
        assert_eq!(inspection.entries_inspected, 2);
        assert!(inspection.scan_truncated);
        assert!(inspection.inventory.is_none());
    }

    #[test]
    fn redaction_only_claims_and_replaces_artifact_root_paths() {
        let root = Path::new(r"C:\T32Perf\Artifacts");
        let mut value = json!({
            "native": r"C:\T32Perf\Artifacts\session\state.json",
            "portable": "C:/T32Perf/Artifacts/session/state.json",
            "unrelated": r"D:\Other\marker\state.json",
        });
        redact_paths(&mut value, root);
        assert_eq!(value["native"], "<artifact-root>\\session\\state.json");
        assert_eq!(value["portable"], "<artifact-root>/session/state.json");
        assert_eq!(value["unrelated"], r"D:\Other\marker\state.json");
    }

    #[test]
    fn namespace_leases_reject_active_and_quarantine_create_races() {
        let temp = TempDir::new().unwrap();
        let root =
            ArtifactRoot::open(temp.path().join("sessions"), SessionLimits::default()).unwrap();
        let namespace = root.try_namespace_lock().unwrap();
        assert!(
            root.create_session_with_id(SessionId::new("racing-create").unwrap(), &json!({}))
                .is_err()
        );
        drop(namespace);

        complete_session(&root, "candidate", json!({}));
        let planned = retention_plan(&root, &["candidate".to_owned()]).unwrap();
        let plan_id = planned.result["plan_id"].as_str().unwrap();
        let quarantine_path =
            control_subdirectory(&root, &["retention", "quarantine", plan_id]).unwrap();
        let quarantine_root =
            ArtifactRoot::open(&quarantine_path, SessionLimits::default()).unwrap();
        let quarantine_namespace = quarantine_root.try_namespace_lock().unwrap();
        assert!(
            retention_apply(
                &root,
                plan_id,
                planned.result["confirm_sha256"].as_str().unwrap()
            )
            .is_err()
        );
        assert!(root.path().join("candidate").is_dir());
        drop(quarantine_namespace);

        retention_apply(
            &root,
            plan_id,
            planned.result["confirm_sha256"].as_str().unwrap(),
        )
        .unwrap();
        let quarantine_namespace = quarantine_root.try_namespace_lock().unwrap();
        assert!(
            retention_restore(
                &root,
                plan_id,
                "candidate",
                planned.result["confirm_sha256"].as_str().unwrap()
            )
            .is_err()
        );
        assert!(!root.path().join("candidate").exists());
        drop(quarantine_namespace);
    }

    #[test]
    fn schema_inventory_declares_no_in_place_migration() {
        let temp = TempDir::new().unwrap();
        let root =
            ArtifactRoot::open(temp.path().join("sessions"), SessionLimits::default()).unwrap();
        let outcome = schema_inventory(&root, None).unwrap();
        assert_eq!(outcome.exit_code, EXIT_SUCCESS);
        assert_eq!(outcome.result["migration"]["in_place_supported"], false);
        let supported = outcome.result["supported"].as_array().unwrap();
        assert!(supported.len() >= 20);
        for filename in [
            "controller-request.schema.json",
            "t32mcp-driver-config.schema.json",
            "static-ram-report.schema.json",
            "stack-usage-report.schema.json",
        ] {
            assert!(
                supported.iter().any(|schema| schema["file"] == filename),
                "schema inventory omits {filename}"
            );
        }
        assert!(
            outcome.result["control_schemas"]
                .as_array()
                .unwrap()
                .iter()
                .any(|schema| schema == COMPARISON_ARTIFACT_SCHEMA)
        );
    }
}
