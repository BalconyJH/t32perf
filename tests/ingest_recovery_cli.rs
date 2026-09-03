use std::{fs, path::Path, process::Output};

use assert_cmd::cargo::cargo_bin_cmd;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use t32perf_model::{Artifact, ArtifactPath, SessionStatus, Sha256Digest};
use t32perf_session::{
    ArtifactRoot, ArtifactSpec, INGEST_INTENT_SCHEMA, IngestIntentClassification, Session,
    SessionId, SessionLimits,
};
use tempfile::TempDir;

const PAYLOAD: &[u8] = b"trace-data";

#[derive(Clone, Copy)]
enum CrashWindow {
    Pending,
    Resumable,
    CommittedStale,
}

#[test]
fn cli_recovers_pending_resumable_and_committed_stale_ingests() {
    let temp = TempDir::new().expect("temporary directory");
    let root_path = temp.path().join("artifacts");
    let root = ArtifactRoot::open(&root_path, SessionLimits::default()).expect("artifact root");

    for (session_id, initial_status, window, expected_classification) in [
        (
            "session-cli-pending",
            SessionStatus::Created,
            CrashWindow::Pending,
            IngestIntentClassification::Pending,
        ),
        (
            "session-cli-resumable",
            SessionStatus::Capturing,
            CrashWindow::Resumable,
            IngestIntentClassification::Resumable,
        ),
        (
            "session-cli-committed-stale",
            SessionStatus::Capturing,
            CrashWindow::CommittedStale,
            IngestIntentClassification::CommittedStale,
        ),
    ] {
        let artifact = prepare_crash_window(&root, session_id, initial_status, window);
        let session = root
            .session(&SessionId::new(session_id).expect("Session ID"))
            .expect("Session");
        assert_eq!(
            session.inspect_ingest_intents().expect("intent inspection")[0].classification,
            expected_classification
        );

        let recovered = run_ingest(&root_path, session_id, "raw_trace", None);
        assert_eq!(recovered.status.code(), Some(0), "{}", stderr(&recovered));
        let recovered_json = json_stdout(&recovered);
        assert_eq!(recovered_json["command"], "session.ingest");
        assert_eq!(recovered_json["result"]["status"], "captured");
        assert_eq!(recovered_json["result"]["artifact"]["id"], "raw");

        let state = session.read_state().expect("captured state");
        assert_eq!(state.status, SessionStatus::Captured);
        assert!(
            session
                .inspect_ingest_intents()
                .expect("intent cleanup")
                .is_empty()
        );
        let artifacts = session
            .registered_artifacts(true)
            .expect("deep artifact verification");
        assert_eq!(artifacts.as_slice(), std::slice::from_ref(&artifact));
        session
            .verify_artifact(&artifacts[0], true)
            .expect("deep artifact verification");
    }
}

#[test]
fn recoverable_quota_error_preserves_state_and_exact_retry_succeeds() {
    let temp = TempDir::new().expect("temporary directory");
    let root_path = temp.path().join("artifacts");
    let root = ArtifactRoot::open(&root_path, SessionLimits::default()).expect("artifact root");
    let artifact = prepare_crash_window(
        &root,
        "session-cli-recovery-required",
        SessionStatus::Created,
        CrashWindow::Pending,
    );
    let session = root
        .session(&SessionId::new("session-cli-recovery-required").expect("Session ID"))
        .expect("Session");
    let baseline = payload_size(session.path());
    let catalog_bytes = pretty_json_size(&artifact);
    let limited = SessionLimits {
        max_file_bytes: u64::try_from(PAYLOAD.len()).expect("payload size"),
        max_session_bytes: baseline + catalog_bytes - 1,
    };

    let failed = run_ingest(
        &root_path,
        "session-cli-recovery-required",
        "raw_trace",
        Some(limited),
    );
    assert_eq!(failed.status.code(), Some(1), "{}", stderr(&failed));
    let failed_json = json_stdout(&failed);
    assert_eq!(failed_json["error"]["code"], "INGEST_RECOVERY_REQUIRED");
    assert_eq!(failed_json["error"]["details"]["intent_count"], 1);
    assert_eq!(
        failed_json["error"]["details"]["intents"][0]["classification"],
        "pending"
    );
    assert_eq!(
        session.read_state().expect("preserved state").status,
        SessionStatus::Created
    );
    assert_eq!(
        session.inspect_ingest_intents().expect("pending intent")[0].classification,
        IngestIntentClassification::Pending
    );

    let recovered = run_ingest(
        &root_path,
        "session-cli-recovery-required",
        "raw_trace",
        None,
    );
    assert_eq!(recovered.status.code(), Some(0), "{}", stderr(&recovered));
    assert_eq!(
        session.read_state().expect("captured state").status,
        SessionStatus::Captured
    );
    assert!(
        session
            .inspect_ingest_intents()
            .expect("intent cleanup")
            .is_empty()
    );
    session
        .verify_artifact(&artifact, true)
        .expect("deep artifact verification");
}

#[test]
fn wrong_spec_conflict_is_terminal_and_preserves_recovery_evidence() {
    let temp = TempDir::new().expect("temporary directory");
    let root_path = temp.path().join("artifacts");
    let root = ArtifactRoot::open(&root_path, SessionLimits::default()).expect("artifact root");
    prepare_crash_window(
        &root,
        "session-cli-spec-conflict",
        SessionStatus::Created,
        CrashWindow::Pending,
    );
    let session = root
        .session(&SessionId::new("session-cli-spec-conflict").expect("Session ID"))
        .expect("Session");

    let failed = run_ingest(
        &root_path,
        "session-cli-spec-conflict",
        "different_kind",
        None,
    );
    assert_eq!(failed.status.code(), Some(1), "{}", stderr(&failed));
    let failed_json = json_stdout(&failed);
    assert_eq!(failed_json["error"]["code"], "OPERATIONAL_ERROR");
    assert_ne!(failed_json["error"]["code"], "INGEST_RECOVERY_REQUIRED");

    let state = session.read_state().expect("failed state");
    assert_eq!(state.status, SessionStatus::Failed);
    assert_eq!(
        state.error.as_ref().expect("terminal error").code,
        "INGEST_FAILED"
    );
    assert_eq!(
        session.inspect_ingest_intents().expect("preserved intent")[0].classification,
        IngestIntentClassification::Pending
    );
    assert!(
        session
            .staging_path(&ArtifactPath::new("raw.bin").expect("staging path"))
            .expect("staged file")
            .exists()
    );
    assert!(
        session
            .registered_artifacts(false)
            .expect("empty catalog")
            .is_empty()
    );
}

#[test]
fn captured_session_with_durable_ingest_conflict_becomes_failed() {
    let temp = TempDir::new().expect("temporary directory");
    let root_path = temp.path().join("artifacts");
    let root = ArtifactRoot::open(&root_path, SessionLimits::default()).expect("artifact root");
    prepare_crash_window(
        &root,
        "session-cli-captured-conflict",
        SessionStatus::Captured,
        CrashWindow::Pending,
    );
    let session = root
        .session(&SessionId::new("session-cli-captured-conflict").expect("Session ID"))
        .expect("Session");

    let failed = run_ingest(
        &root_path,
        "session-cli-captured-conflict",
        "different_kind",
        None,
    );
    assert_eq!(failed.status.code(), Some(1), "{}", stderr(&failed));
    let state = session.read_state().expect("failed state");
    assert_eq!(state.status, SessionStatus::Failed);
    assert_eq!(
        state.error.as_ref().expect("terminal error").code,
        "INGEST_FAILED"
    );
    assert_eq!(
        session.inspect_ingest_intents().expect("preserved intent")[0].classification,
        IngestIntentClassification::Pending
    );
}

fn prepare_crash_window(
    root: &ArtifactRoot,
    session_id: &str,
    initial_status: SessionStatus,
    window: CrashWindow,
) -> Artifact {
    let session = root
        .create_session_with_id(
            SessionId::new(session_id).expect("Session ID"),
            &json!({"provider": "external"}),
        )
        .expect("create Session");
    if matches!(
        initial_status,
        SessionStatus::Capturing | SessionStatus::Captured
    ) {
        let lock = session.try_lock().expect("Session lock");
        session
            .transition(&lock, SessionStatus::Capturing, None)
            .expect("capturing state");
        if initial_status == SessionStatus::Captured {
            session
                .transition(&lock, SessionStatus::Captured, None)
                .expect("captured state");
        }
    }

    let staged_relative = ArtifactPath::new("raw.bin").expect("staging path");
    let staged_path = session
        .staging_path(&staged_relative)
        .expect("staged file path");
    fs::write(&staged_path, PAYLOAD).expect("staged bytes");
    let spec = raw_spec();
    let artifact = expected_artifact(&spec, PAYLOAD);
    write_ingest_intent(&session, &staged_relative, &artifact);

    if matches!(window, CrashWindow::Resumable | CrashWindow::CommittedStale) {
        fs::rename(
            &staged_path,
            session.path().join(artifact.relative_path.as_str()),
        )
        .expect("move staged artifact");
    }
    if matches!(window, CrashWindow::CommittedStale) {
        let lock = session.try_lock().expect("Session lock");
        session
            .register_artifact(&lock, &artifact)
            .expect("catalog record");
    }
    artifact
}

fn raw_spec() -> ArtifactSpec {
    ArtifactSpec {
        id: "raw".to_owned(),
        kind: "raw_trace".to_owned(),
        relative_path: ArtifactPath::new("capture/raw/raw.bin").expect("artifact path"),
        media_type: "application/octet-stream".to_owned(),
        producer: "external-capture".to_owned(),
        input_artifact_ids: Vec::new(),
    }
}

fn expected_artifact(spec: &ArtifactSpec, payload: &[u8]) -> Artifact {
    Artifact {
        id: spec.id.clone(),
        kind: spec.kind.clone(),
        relative_path: spec.relative_path.clone(),
        media_type: spec.media_type.clone(),
        size_bytes: u64::try_from(payload.len()).expect("payload size"),
        sha256: digest_bytes(payload),
        producer: spec.producer.clone(),
        input_artifact_ids: spec.input_artifact_ids.clone(),
    }
}

fn write_ingest_intent(session: &Session, staged_relative: &ArtifactPath, artifact: &Artifact) {
    let intent = json!({
        "schema": INGEST_INTENT_SCHEMA,
        "session_id": session.id().as_str(),
        "operation_id": session.read_state().expect("Session state").operation_id,
        "staged_relative_path": staged_relative,
        "artifact": artifact,
    });
    write_pretty_json(
        &session
            .path()
            .join("ingest-intents")
            .join(format!("{}.json", artifact.id)),
        &intent,
    );
}

fn run_ingest(root: &Path, session_id: &str, kind: &str, limits: Option<SessionLimits>) -> Output {
    let mut command = cargo_bin_cmd!("t32perf");
    command.arg("--artifact-root").arg(root).arg("--json");
    if let Some(limits) = limits {
        command
            .arg("--max-file-bytes")
            .arg(limits.max_file_bytes.to_string())
            .arg("--max-session-bytes")
            .arg(limits.max_session_bytes.to_string());
    }
    command
        .args([
            "session",
            "ingest",
            session_id,
            "--staged",
            "raw.bin",
            "--id",
            "raw",
            "--kind",
            kind,
            "--destination",
            "capture/raw/raw.bin",
            "--media-type",
            "application/octet-stream",
            "--producer",
            "external-capture",
        ])
        .output()
        .expect("run t32perf")
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    let digest = Sha256::digest(bytes);
    Sha256Digest::new(
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
    .expect("SHA-256 digest")
}

fn write_pretty_json(path: &Path, value: &impl Serialize) {
    let mut bytes = serde_json::to_vec_pretty(value).expect("serialize JSON");
    bytes.push(b'\n');
    fs::write(path, bytes).expect("write JSON");
}

fn pretty_json_size(value: &impl Serialize) -> u64 {
    let mut bytes = serde_json::to_vec_pretty(value).expect("serialize JSON");
    bytes.push(b'\n');
    u64::try_from(bytes.len()).expect("JSON size")
}

fn payload_size(path: &Path) -> u64 {
    let mut total = 0_u64;
    let mut pending = vec![path.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).expect("read Session directory") {
            let entry = entry.expect("Session entry");
            let metadata = entry.metadata().expect("Session entry metadata");
            if metadata.is_dir() {
                pending.push(entry.path());
            } else {
                total = total.checked_add(metadata.len()).expect("Session size");
            }
        }
    }
    total
}

fn json_stdout(output: &Output) -> Value {
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert_eq!(stdout.lines().count(), 1, "stdout was not one JSON object");
    serde_json::from_str(stdout).expect("stdout is JSON")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
