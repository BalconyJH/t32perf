use std::{
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
};

use fs2::FileExt as _;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use t32perf_model::{
    AdapterInfo, Artifact, ArtifactPath, CaptureInfo, FirmwareInfo, MAX_ARTIFACT_INPUTS, Manifest,
    ManifestSchemaVersion, SessionError, SessionStatus, Sha256Digest, ToolInfo,
};
use t32perf_session::{
    ArtifactRoot, ArtifactSpec, INGEST_INTENT_SCHEMA, IngestIntentClassification, Session,
    SessionId, SessionLimits, SessionStoreError,
};
use tempfile::TempDir;

fn root(temp: &TempDir) -> ArtifactRoot {
    ArtifactRoot::open(temp.path().join("sessions"), SessionLimits::default()).unwrap()
}

fn spec(id: &str, path: &str) -> ArtifactSpec {
    ArtifactSpec {
        id: id.to_owned(),
        kind: "test".to_owned(),
        relative_path: ArtifactPath::new(path).unwrap(),
        media_type: "application/octet-stream".to_owned(),
        producer: "test".to_owned(),
        input_artifact_ids: Vec::new(),
    }
}

fn manifest(session_id: &str, artifacts: Vec<Artifact>) -> Manifest {
    Manifest {
        schema: ManifestSchemaVersion,
        session_id: session_id.to_owned(),
        created_at: "2026-08-23T00:00:00Z".to_owned(),
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
        artifacts,
    }
}

fn payload_size(path: &std::path::Path) -> u64 {
    let mut total = 0_u64;
    let mut pending = vec![path.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let metadata = entry.metadata().unwrap();
            if metadata.is_dir() {
                pending.push(entry.path());
            } else {
                total += metadata.len();
            }
        }
    }
    total
}

fn pretty_json_size(value: &impl Serialize) -> u64 {
    let mut bytes = serde_json::to_vec_pretty(value).unwrap();
    bytes.push(b'\n');
    u64::try_from(bytes.len()).unwrap()
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    let digest = Sha256::digest(bytes);
    Sha256Digest::new(
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
    .unwrap()
}

fn expected_artifact(spec: &ArtifactSpec, payload: &[u8]) -> Artifact {
    Artifact {
        id: spec.id.clone(),
        kind: spec.kind.clone(),
        relative_path: spec.relative_path.clone(),
        media_type: spec.media_type.clone(),
        size_bytes: u64::try_from(payload.len()).unwrap(),
        sha256: digest_bytes(payload),
        producer: spec.producer.clone(),
        input_artifact_ids: spec.input_artifact_ids.clone(),
    }
}

fn ingest_intent_value(
    session: &Session,
    staged_relative: &ArtifactPath,
    artifact: &Artifact,
) -> serde_json::Value {
    json!({
        "schema": INGEST_INTENT_SCHEMA,
        "session_id": session.id().as_str(),
        "operation_id": session.read_state().unwrap().operation_id,
        "staged_relative_path": staged_relative,
        "private_relative_path": format!("capture/.ingest-private/{}.payload", artifact.id),
        "artifact": artifact,
    })
}

fn intent_path(session: &Session, artifact_id: &str) -> std::path::PathBuf {
    session
        .path()
        .join("ingest-intents")
        .join(format!("{artifact_id}.json"))
}

fn write_pretty_json(path: &std::path::Path, value: &impl Serialize) {
    let mut bytes = serde_json::to_vec_pretty(value).unwrap();
    bytes.push(b'\n');
    fs::write(path, bytes).unwrap();
}

fn create_manual_intent(session: &Session, staged_relative: &ArtifactPath, artifact: &Artifact) {
    let private_path = session
        .path()
        .join("capture/.ingest-private")
        .join(format!("{}.payload", artifact.id));
    fs::create_dir_all(private_path.parent().unwrap()).unwrap();
    fs::copy(session.staging_path(staged_relative).unwrap(), private_path).unwrap();
    write_pretty_json(
        &intent_path(session, &artifact.id),
        &ingest_intent_value(session, staged_relative, artifact),
    );
}

#[test]
fn creates_standard_layout_and_never_overwrites_session() {
    let temp = TempDir::new().unwrap();
    let root = root(&temp);
    let id = SessionId::new("session-fixed").unwrap();
    let session = root
        .create_session_with_id(id.clone(), &json!({"provider": "synthetic"}))
        .unwrap();

    for relative in [
        "capture/raw",
        "capture/staging",
        "normalized",
        "analysis",
        "report",
        "logs",
        "ingest-intents",
    ] {
        assert!(session.path().join(relative).is_dir());
    }
    assert_eq!(session.read_state().unwrap().status, SessionStatus::Created);
    assert_eq!(session.request().unwrap(), json!({"provider": "synthetic"}));
    assert_eq!(session.request_sha256().unwrap().as_str().len(), 64);
    assert!(matches!(
        root.create_session_with_id(id, &json!({})),
        Err(SessionStoreError::SessionExists { .. })
    ));
    assert!(fs::read_dir(root.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".session-create-")
    }));
}

#[test]
fn namespace_lock_blocks_create_without_publishing_or_removing_a_session() {
    let temp = TempDir::new().unwrap();
    let root = root(&temp);
    let namespace = root.try_namespace_lock().unwrap();
    let id = SessionId::new("session-namespace").unwrap();
    assert!(matches!(
        root.create_session_with_id(id.clone(), &json!({})),
        Err(SessionStoreError::ArtifactRootNamespaceLocked { .. })
    ));
    assert!(!root.path().join(id.as_str()).exists());
    drop(namespace);

    let session = root.create_session_with_id(id, &json!({})).unwrap();
    assert_eq!(session.read_state().unwrap().status, SessionStatus::Created);
}

#[test]
fn cross_handle_os_contention_maps_to_typed_session_and_namespace_errors() {
    let temp = TempDir::new().unwrap();
    let root = root(&temp);
    let session = root
        .create_session_with_id(SessionId::new("cross-handle-lock").unwrap(), &json!({}))
        .unwrap();

    let session_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(session.path().join(".session.lock"))
        .unwrap();
    session_file.try_lock_exclusive().unwrap();
    assert!(matches!(
        session.try_lock(),
        Err(SessionStoreError::SessionLocked { .. })
    ));
    fs2::FileExt::unlock(&session_file).unwrap();

    let namespace_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.path().join(".artifact-root.lock"))
        .unwrap();
    namespace_file.try_lock_exclusive().unwrap();
    assert!(matches!(
        root.try_namespace_lock(),
        Err(SessionStoreError::ArtifactRootNamespaceLocked { .. })
    ));
    fs2::FileExt::unlock(&namespace_file).unwrap();
}

#[test]
fn rejects_nonportable_session_ids() {
    for invalid in [
        "",
        "../escape",
        "a/b",
        "a\\b",
        "-leading",
        "space id",
        "CON",
        "nul",
        "COM1",
        "lpt9",
    ] {
        assert!(SessionId::new(invalid).is_err(), "accepted {invalid:?}");
    }
    assert!(SessionId::new("A_valid-01").is_ok());
}

#[test]
fn namespace_shared_and_exclusive_leases_follow_root_then_session_order() {
    let temp = TempDir::new().unwrap();
    let root = root(&temp);
    let first = root
        .create_session_with_id(SessionId::new("session-first").unwrap(), &json!({}))
        .unwrap();
    let second = root
        .create_session_with_id(SessionId::new("session-second").unwrap(), &json!({}))
        .unwrap();
    let other_root =
        ArtifactRoot::open(temp.path().join("other-sessions"), SessionLimits::default()).unwrap();
    let other = other_root
        .create_session_with_id(SessionId::new("session-other").unwrap(), &json!({}))
        .unwrap();

    let first_lock = first.try_lock().unwrap();
    let second_lock = second.try_lock().unwrap();
    assert!(matches!(
        root.try_namespace_lock(),
        Err(SessionStoreError::ArtifactRootNamespaceLocked { .. })
    ));
    drop(second_lock);
    drop(first_lock);

    let namespace = root.try_namespace_lock().unwrap();
    assert!(matches!(
        first.try_lock(),
        Err(SessionStoreError::ArtifactRootNamespaceLocked { .. })
    ));
    assert!(matches!(
        other.try_lock_in_namespace(&namespace),
        Err(SessionStoreError::NamespaceLockMismatch { .. })
    ));
    let first_lock = first.try_lock_in_namespace(&namespace).unwrap();
    drop(namespace);
    assert!(matches!(
        root.try_namespace_lock(),
        Err(SessionStoreError::ArtifactRootNamespaceLocked { .. })
    ));
    drop(first_lock);
    drop(root.try_namespace_lock().unwrap());
}

#[test]
fn session_names_and_catalog_keys_enforce_portable_ascii_namespace() {
    for invalid in [
        "analysis/\u{62a5}\u{544a}.bin",
        "analysis/Ä.bin",
        "analysis/ä.bin",
        "analysis/COM¹.log",
    ] {
        assert!(
            ArtifactPath::new(invalid).is_err(),
            "accepted non-ASCII artifact path {invalid:?}"
        );
    }

    let temp = TempDir::new().unwrap();
    let root = root(&temp);
    let session = root
        .create_session_with_id(SessionId::new("Session-Portable").unwrap(), &json!({}))
        .unwrap();
    assert!(matches!(
        root.create_session_with_id(SessionId::new("session-portable").unwrap(), &json!({})),
        Err(SessionStoreError::SessionNameConflict { .. })
    ));

    let lock = session.try_lock().unwrap();
    let first_spec = spec("Raw", "analysis/Report.bin");
    let mut writer = session.create_artifact(&lock, first_spec).unwrap();
    writer.write_all(b"payload").unwrap();
    session.commit_artifact(&lock, writer).unwrap();
    assert!(matches!(
        session.create_artifact(&lock, spec("raw", "analysis/other.bin")),
        Err(SessionStoreError::ArtifactRecordConflict { .. })
    ));
    assert!(matches!(
        session.create_artifact(&lock, spec("other", "analysis/report.bin")),
        Err(SessionStoreError::InvalidArtifactSpec { .. })
    ));
}

#[test]
fn lock_and_state_machine_are_enforced() {
    let temp = TempDir::new().unwrap();
    let session = root(&temp).create_session(&json!({})).unwrap();
    let lock = session.try_lock().unwrap();
    assert!(matches!(
        session.try_lock(),
        Err(SessionStoreError::SessionLocked { .. })
    ));
    assert!(matches!(
        session.transition(&lock, SessionStatus::Processing, None),
        Err(SessionStoreError::InvalidTransition { .. })
    ));

    let capturing = session
        .transition(&lock, SessionStatus::Capturing, None)
        .unwrap();
    assert_eq!(capturing.revision, 1);
    let captured = session
        .transition(&lock, SessionStatus::Captured, None)
        .unwrap();
    assert_eq!(captured.revision, 2);
    assert!(
        session
            .transition(
                &lock,
                SessionStatus::Failed,
                Some(SessionError {
                    code: "INJECTED".to_owned(),
                    message: "injected failure".to_owned(),
                    details: Default::default(),
                }),
            )
            .is_ok()
    );
}

#[test]
fn writes_hashes_finalizes_and_detects_tampering() {
    let temp = TempDir::new().unwrap();
    let session = root(&temp).create_session(&json!({})).unwrap();
    let lock = session.try_lock().unwrap();
    session
        .transition(&lock, SessionStatus::Capturing, None)
        .unwrap();
    session
        .transition(&lock, SessionStatus::Captured, None)
        .unwrap();

    let mut writer = session
        .create_artifact(&lock, spec("events", "normalized/events.jsonl"))
        .unwrap();
    writer.write_all(b"{\"type\":\"header\"}\n").unwrap();
    let artifact = session.commit_artifact(&lock, writer).unwrap();
    assert_eq!(artifact.size_bytes, 18);
    let registered = session.registered_artifacts(true).unwrap();
    assert_eq!(registered.len(), 1);
    assert_eq!(registered[0], artifact);
    let mut opened = session.open_artifact(&artifact).unwrap();
    let mut contents = String::new();
    opened.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "{\"type\":\"header\"}\n");

    let manifest = manifest(session.id().as_str(), vec![artifact.clone()]);
    let state = session.finalize(&lock, &manifest).unwrap();
    assert_eq!(state.status, SessionStatus::Complete);
    assert_eq!(session.manifest().unwrap(), Some(manifest.clone()));
    session.validate_manifest(&manifest, true).unwrap();

    fs::write(
        session.path().join(artifact.relative_path.as_str()),
        b"tampered",
    )
    .unwrap();
    assert!(matches!(
        session.validate_manifest(&manifest, true),
        Err(SessionStoreError::ArtifactSizeMismatch { .. })
            | Err(SessionStoreError::ArtifactDigestMismatch { .. })
    ));
}

#[test]
fn ingests_only_from_session_staging() {
    let temp = TempDir::new().unwrap();
    let session = root(&temp).create_session(&json!({})).unwrap();
    let lock = session.try_lock().unwrap();
    let staged = ArtifactPath::new("raw.txt").unwrap();
    fs::write(session.staging_path(&staged).unwrap(), b"trace-data").unwrap();

    let artifact = session
        .ingest_staged(&lock, &staged, spec("raw", "capture/raw/raw.txt"))
        .unwrap();
    assert_eq!(artifact.size_bytes, 10);
    assert!(session.staging_path(&staged).unwrap().exists());
    assert_eq!(
        fs::read(session.path().join("capture/raw/raw.txt")).unwrap(),
        b"trace-data"
    );
    assert!(session.inspect_ingest_intents().unwrap().is_empty());
}

#[test]
fn staged_hardlink_and_retained_writer_cannot_modify_committed_artifact() {
    let temp = TempDir::new().unwrap();
    let session = root(&temp).create_session(&json!({})).unwrap();
    let lock = session.try_lock().unwrap();
    let staged = ArtifactPath::new("raw.txt").unwrap();
    let staged_path = session.staging_path(&staged).unwrap();
    let linked_path = session.staging_root().join("retained-link.txt");
    fs::write(&staged_path, b"original-bytes").unwrap();
    fs::hard_link(&staged_path, &linked_path).unwrap();
    let mut retained_writer = fs::OpenOptions::new()
        .write(true)
        .open(&staged_path)
        .unwrap();

    let artifact = session
        .ingest_staged(&lock, &staged, spec("raw", "capture/raw/raw.txt"))
        .unwrap();
    retained_writer.write_all(b"changed-bytes!").unwrap();
    retained_writer.flush().unwrap();

    assert_eq!(fs::read(&linked_path).unwrap(), b"changed-bytes!");
    assert_eq!(
        fs::read(session.path().join(artifact.relative_path.as_str())).unwrap(),
        b"original-bytes"
    );
    assert!(staged_path.exists());
}

#[test]
fn committed_staging_source_cannot_be_reused_by_a_different_artifact() {
    let temp = TempDir::new().unwrap();
    let session = root(&temp).create_session(&json!({})).unwrap();
    let lock = session.try_lock().unwrap();
    let staged = ArtifactPath::new("raw.txt").unwrap();
    fs::write(session.staging_path(&staged).unwrap(), b"trace-data").unwrap();
    session
        .ingest_staged(&lock, &staged, spec("raw-a", "capture/raw/raw-a.txt"))
        .unwrap();

    assert!(matches!(
        session.ingest_staged(&lock, &staged, spec("raw-b", "capture/raw/raw-b.txt")),
        Err(SessionStoreError::IngestIntentConflict { .. })
    ));
}

#[test]
fn idempotent_ingest_uses_committed_source_metadata_after_source_removal() {
    let temp = TempDir::new().unwrap();
    let session = root(&temp).create_session(&json!({})).unwrap();
    let lock = session.try_lock().unwrap();
    let staged = ArtifactPath::new("raw.txt").unwrap();
    let staged_path = session.staging_path(&staged).unwrap();
    let artifact_spec = spec("raw", "capture/raw/raw.txt");
    fs::write(&staged_path, b"trace-data").unwrap();

    let committed = session
        .ingest_staged(&lock, &staged, artifact_spec.clone())
        .unwrap();
    fs::remove_file(&staged_path).unwrap();

    assert_eq!(
        session
            .ingest_staged(&lock, &staged, artifact_spec)
            .unwrap(),
        committed
    );
    assert!(session.verify_committed_staging_sources_shallow().is_err());
}

#[test]
fn legacy_destination_recovery_replaces_the_external_inode_before_registration() {
    const PAYLOAD: &[u8] = b"trace-data";
    let temp = TempDir::new().unwrap();
    let session = root(&temp).create_session(&json!({})).unwrap();
    let staged = ArtifactPath::new("raw.txt").unwrap();
    let staged_path = session.staging_path(&staged).unwrap();
    let artifact_spec = spec("raw", "capture/raw/raw.txt");
    let artifact = expected_artifact(&artifact_spec, PAYLOAD);
    let destination = session.path().join(artifact.relative_path.as_str());
    let retained_link = session.staging_root().join("legacy-destination-link.txt");
    fs::write(&staged_path, PAYLOAD).unwrap();
    fs::rename(&staged_path, &destination).unwrap();
    fs::hard_link(&destination, &retained_link).unwrap();
    let mut legacy = ingest_intent_value(&session, &staged, &artifact);
    legacy["schema"] = json!("t32perf.ingest-intent/v1");
    legacy
        .as_object_mut()
        .unwrap()
        .remove("private_relative_path");
    write_pretty_json(&intent_path(&session, "raw"), &legacy);

    let lock = session.try_lock().unwrap();
    session
        .ingest_staged(&lock, &staged, artifact_spec)
        .unwrap();
    fs::write(&retained_link, b"changed---").unwrap();

    assert_eq!(fs::read(&retained_link).unwrap(), b"changed---");
    assert_eq!(fs::read(&destination).unwrap(), PAYLOAD);
}

#[test]
fn legacy_destination_recovery_accepts_the_exact_replacement_peak() {
    const PAYLOAD: &[u8] = b"trace-data";
    let temp = TempDir::new().unwrap();
    let default_root = root(&temp);
    let session = default_root
        .create_session_with_id(
            SessionId::new("session-ingest-v1-replacement-quota").unwrap(),
            &json!({}),
        )
        .unwrap();
    let session_id = session.id().clone();
    let staged = ArtifactPath::new("raw.txt").unwrap();
    let staged_path = session.staging_path(&staged).unwrap();
    let artifact_spec = spec("raw", "capture/raw/raw.txt");
    let artifact = expected_artifact(&artifact_spec, PAYLOAD);
    let destination = session.path().join(artifact.relative_path.as_str());
    fs::write(&staged_path, PAYLOAD).unwrap();
    fs::rename(&staged_path, &destination).unwrap();
    let mut legacy = ingest_intent_value(&session, &staged, &artifact);
    legacy["schema"] = json!("t32perf.ingest-intent/v1");
    legacy
        .as_object_mut()
        .unwrap()
        .remove("private_relative_path");
    write_pretty_json(&intent_path(&session, "raw"), &legacy);
    let baseline = payload_size(session.path());
    let catalog_bytes = pretty_json_size(&artifact);
    let source_record_bytes = pretty_json_size(&json!({
        "schema": "t32perf.committed-staging-source/v1",
        "session_id": session_id.as_str(),
        "source": {
            "artifact_id": artifact.id,
            "staged_relative_path": staged,
            "size_bytes": artifact.size_bytes,
            "sha256": artifact.sha256,
            "artifact_relative_path": artifact.relative_path,
        }
    }));
    drop(session);

    let limited_root = ArtifactRoot::open(
        default_root.path(),
        SessionLimits {
            max_file_bytes: u64::try_from(PAYLOAD.len()).unwrap(),
            max_session_bytes: baseline
                + u64::try_from(PAYLOAD.len())
                    .unwrap()
                    .max(catalog_bytes + source_record_bytes),
        },
    )
    .unwrap();
    let session = limited_root.session(&session_id).unwrap();
    let lock = session.try_lock().unwrap();
    session
        .ingest_staged(&lock, &staged, artifact_spec)
        .unwrap();
    assert_eq!(fs::read(&destination).unwrap(), PAYLOAD);
    assert!(!intent_path(&session, "raw").exists());
}

#[cfg(windows)]
#[test]
fn staged_ingest_completes_with_a_source_handle_that_denies_delete_sharing() {
    use std::os::windows::fs::OpenOptionsExt as _;

    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

    let temp = TempDir::new().unwrap();
    let session = root(&temp).create_session(&json!({})).unwrap();
    let lock = session.try_lock().unwrap();
    let staged = ArtifactPath::new("locked-source.txt").unwrap();
    let staged_path = session.staging_path(&staged).unwrap();
    fs::write(&staged_path, b"trace-data").unwrap();
    let retained = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(&staged_path)
        .unwrap();

    let artifact = session
        .ingest_staged(&lock, &staged, spec("locked-raw", "capture/raw/locked.txt"))
        .unwrap();
    drop(retained);

    assert!(staged_path.exists());
    assert_eq!(
        fs::read(session.path().join(artifact.relative_path.as_str())).unwrap(),
        b"trace-data"
    );
}

#[test]
fn staged_ingest_recovers_all_supported_crash_windows_and_final_retry() {
    const PAYLOAD: &[u8] = b"trace-data";
    let temp = TempDir::new().unwrap();
    let root = root(&temp);

    for (session_name, expected, move_to_destination, register_catalog) in [
        (
            "session-ingest-pending",
            IngestIntentClassification::Pending,
            false,
            false,
        ),
        (
            "session-ingest-resumable",
            IngestIntentClassification::Resumable,
            true,
            false,
        ),
        (
            "session-ingest-committed",
            IngestIntentClassification::CommittedStale,
            true,
            true,
        ),
    ] {
        let session = root
            .create_session_with_id(SessionId::new(session_name).unwrap(), &json!({}))
            .unwrap();
        let staged_relative = ArtifactPath::new("raw.txt").unwrap();
        let staged_path = session.staging_path(&staged_relative).unwrap();
        let spec = spec("raw", "capture/raw/raw.txt");
        let artifact = expected_artifact(&spec, PAYLOAD);
        fs::write(&staged_path, PAYLOAD).unwrap();
        create_manual_intent(&session, &staged_relative, &artifact);
        if move_to_destination {
            fs::rename(
                session.path().join("capture/.ingest-private/raw.payload"),
                session.path().join(artifact.relative_path.as_str()),
            )
            .unwrap();
        }

        let lock = session.try_lock().unwrap();
        if register_catalog {
            session.register_artifact(&lock, &artifact).unwrap();
        }
        let inspections = session.inspect_ingest_intents().unwrap();
        assert_eq!(inspections.len(), 1);
        assert_eq!(inspections[0].classification, expected);
        assert_eq!(inspections[0].artifact_id.as_deref(), Some("raw"));
        if expected == IngestIntentClassification::Pending {
            assert!(matches!(
                session.transition(&lock, SessionStatus::Capturing, None),
                Err(SessionStoreError::IngestIntentConflict { .. })
            ));
        }

        let recovered = session
            .ingest_staged(&lock, &staged_relative, spec.clone())
            .unwrap();
        assert_eq!(recovered, artifact);
        assert!(session.inspect_ingest_intents().unwrap().is_empty());
        let registered = session.registered_artifacts(true).unwrap();
        assert_eq!(registered.as_slice(), std::slice::from_ref(&artifact));

        let final_retry = session
            .ingest_staged(&lock, &staged_relative, spec)
            .unwrap();
        assert_eq!(final_retry, artifact);
    }
}

#[test]
fn staged_ingest_conflicts_are_read_only_and_fail_closed() {
    const PAYLOAD: &[u8] = b"trace-data";
    let temp = TempDir::new().unwrap();
    let root = root(&temp);

    let session = root
        .create_session_with_id(
            SessionId::new("session-ingest-spec-conflict").unwrap(),
            &json!({}),
        )
        .unwrap();
    let staged_relative = ArtifactPath::new("raw.txt").unwrap();
    let staged_path = session.staging_path(&staged_relative).unwrap();
    let original_spec = spec("raw", "capture/raw/raw.txt");
    let artifact = expected_artifact(&original_spec, PAYLOAD);
    fs::write(&staged_path, PAYLOAD).unwrap();
    create_manual_intent(&session, &staged_relative, &artifact);
    let mut changed_spec = original_spec.clone();
    changed_spec.kind = "different".to_owned();
    let lock = session.try_lock().unwrap();
    assert!(matches!(
        session.ingest_staged(&lock, &staged_relative, changed_spec),
        Err(SessionStoreError::IngestIntentConflict { .. })
    ));
    assert!(staged_path.exists());
    assert!(intent_path(&session, "raw").exists());

    fs::write(&staged_path, b"changed-data").unwrap();
    let inspections = session.inspect_ingest_intents().unwrap();
    assert_eq!(
        inspections[0].classification,
        IngestIntentClassification::Conflict
    );
    assert!(matches!(
        session.ingest_staged(&lock, &staged_relative, original_spec),
        Err(SessionStoreError::IngestIntentConflict { .. })
    ));
    assert!(staged_path.exists());
    assert!(intent_path(&session, "raw").exists());

    let unknown = session.path().join("ingest-intents").join("README.txt");
    fs::write(&unknown, b"unknown").unwrap();
    let inspections = session.inspect_ingest_intents().unwrap();
    assert!(inspections.iter().any(|inspection| {
        inspection.intent_relative_path == "ingest-intents/README.txt"
            && inspection.classification == IngestIntentClassification::Conflict
    }));
    assert!(unknown.exists());
    drop(lock);

    let destination_session = root
        .create_session_with_id(
            SessionId::new("session-ingest-destination-conflict").unwrap(),
            &json!({}),
        )
        .unwrap();
    let destination_spec = spec("raw", "capture/raw/raw.txt");
    let destination_artifact = expected_artifact(&destination_spec, PAYLOAD);
    let source = destination_session.staging_path(&staged_relative).unwrap();
    let destination = destination_session.path().join("capture/raw/raw.txt");
    fs::write(&source, PAYLOAD).unwrap();
    create_manual_intent(
        &destination_session,
        &staged_relative,
        &destination_artifact,
    );
    fs::rename(&source, &destination).unwrap();
    fs::write(&destination, b"tampered").unwrap();
    assert_eq!(
        destination_session.inspect_ingest_intents().unwrap()[0].classification,
        IngestIntentClassification::Conflict
    );
    let lock = destination_session.try_lock().unwrap();
    assert!(matches!(
        destination_session.ingest_staged(&lock, &staged_relative, destination_spec),
        Err(SessionStoreError::IngestIntentConflict { .. })
    ));
    assert!(destination.exists());
    assert!(intent_path(&destination_session, "raw").exists());
}

#[test]
fn staged_ingest_rejects_operation_catalog_path_and_unknown_field_conflicts() {
    const PAYLOAD: &[u8] = b"trace-data";
    let temp = TempDir::new().unwrap();
    let root = root(&temp);

    let operation_session = root
        .create_session_with_id(
            SessionId::new("session-ingest-operation-conflict").unwrap(),
            &json!({}),
        )
        .unwrap();
    let staged_relative = ArtifactPath::new("raw.txt").unwrap();
    let raw_spec = spec("raw", "capture/raw/raw.txt");
    let artifact = expected_artifact(&raw_spec, PAYLOAD);
    fs::write(
        operation_session.staging_path(&staged_relative).unwrap(),
        PAYLOAD,
    )
    .unwrap();
    let mut intent = ingest_intent_value(&operation_session, &staged_relative, &artifact);
    intent["operation_id"] = json!("different-operation");
    intent["unknown"] = json!(true);
    write_pretty_json(&intent_path(&operation_session, "raw"), &intent);
    let inspections = operation_session.inspect_ingest_intents().unwrap();
    assert_eq!(
        inspections[0].classification,
        IngestIntentClassification::Conflict
    );
    let lock = operation_session.try_lock().unwrap();
    assert!(matches!(
        operation_session.ingest_staged(&lock, &staged_relative, raw_spec.clone()),
        Err(SessionStoreError::Json { .. }) | Err(SessionStoreError::IngestIntentConflict { .. })
    ));
    drop(lock);

    let catalog_session = root
        .create_session_with_id(
            SessionId::new("session-ingest-catalog-conflict").unwrap(),
            &json!({}),
        )
        .unwrap();
    fs::write(
        catalog_session.staging_path(&staged_relative).unwrap(),
        PAYLOAD,
    )
    .unwrap();
    let mut conflicting = expected_artifact(&raw_spec, PAYLOAD);
    conflicting.kind = "different".to_owned();
    write_pretty_json(
        &catalog_session
            .path()
            .join("artifact-index")
            .join("raw.json"),
        &conflicting,
    );
    let lock = catalog_session.try_lock().unwrap();
    assert!(matches!(
        catalog_session.ingest_staged(&lock, &staged_relative, raw_spec.clone()),
        Err(SessionStoreError::IngestIntentConflict { .. })
    ));
    assert!(
        catalog_session
            .staging_path(&staged_relative)
            .unwrap()
            .exists()
    );
    drop(lock);

    let path_session = root
        .create_session_with_id(
            SessionId::new("session-ingest-path-conflict").unwrap(),
            &json!({}),
        )
        .unwrap();
    fs::write(
        path_session.staging_path(&staged_relative).unwrap(),
        PAYLOAD,
    )
    .unwrap();
    let other_spec = spec("other", "capture/raw/raw.txt");
    let other_artifact = expected_artifact(&other_spec, PAYLOAD);
    write_pretty_json(
        &path_session
            .path()
            .join("artifact-index")
            .join("other.json"),
        &other_artifact,
    );
    let lock = path_session.try_lock().unwrap();
    assert!(matches!(
        path_session.ingest_staged(&lock, &staged_relative, raw_spec),
        Err(SessionStoreError::IngestIntentConflict { .. })
    ));
    assert!(
        path_session
            .staging_path(&staged_relative)
            .unwrap()
            .exists()
    );
}

#[test]
fn staged_ingest_quota_reserves_intent_and_catalog_atomic_payloads() {
    const PAYLOAD: &[u8] = b"trace-data";
    let temp = TempDir::new().unwrap();
    let default_root = root(&temp);
    let session = default_root
        .create_session_with_id(SessionId::new("session-ingest-quota").unwrap(), &json!({}))
        .unwrap();
    let session_id = session.id().clone();
    let staged_relative = ArtifactPath::new("raw.txt").unwrap();
    let spec = spec("raw", "capture/raw/raw.txt");
    let artifact = expected_artifact(&spec, PAYLOAD);
    fs::write(session.staging_path(&staged_relative).unwrap(), PAYLOAD).unwrap();
    let intent = ingest_intent_value(&session, &staged_relative, &artifact);
    let intent_bytes = pretty_json_size(&intent);
    let catalog_bytes = pretty_json_size(&artifact);
    let source_record_bytes = pretty_json_size(&json!({
        "schema": "t32perf.committed-staging-source/v1",
        "session_id": session_id.as_str(),
        "source": {
            "artifact_id": artifact.id,
            "staged_relative_path": staged_relative,
            "size_bytes": artifact.size_bytes,
            "sha256": artifact.sha256,
            "artifact_relative_path": artifact.relative_path,
        }
    }));
    let baseline = payload_size(session.path());
    drop(session);

    let limited_root = ArtifactRoot::open(
        default_root.path(),
        SessionLimits {
            max_file_bytes: u64::try_from(PAYLOAD.len()).unwrap(),
            max_session_bytes: baseline + intent_bytes + catalog_bytes + source_record_bytes - 1,
        },
    )
    .unwrap();
    let session = limited_root.session(&session_id).unwrap();
    let lock = session.try_lock().unwrap();
    assert!(matches!(
        session.ingest_staged(&lock, &staged_relative, spec),
        Err(SessionStoreError::SessionLimitExceeded { .. })
    ));
    assert!(session.staging_path(&staged_relative).unwrap().exists());
    assert!(!intent_path(&session, "raw").exists());
    assert!(!session.path().join("capture/raw/raw.txt").exists());
    assert!(session.registered_artifacts(false).unwrap().is_empty());
}

#[test]
fn pending_ingest_retry_reserves_catalog_before_rename() {
    const PAYLOAD: &[u8] = b"trace-data";
    let temp = TempDir::new().unwrap();
    let default_root = root(&temp);
    let session = default_root
        .create_session_with_id(
            SessionId::new("session-ingest-retry-quota").unwrap(),
            &json!({}),
        )
        .unwrap();
    let session_id = session.id().clone();
    let staged_relative = ArtifactPath::new("raw.txt").unwrap();
    let raw_spec = spec("raw", "capture/raw/raw.txt");
    let artifact = expected_artifact(&raw_spec, PAYLOAD);
    fs::write(session.staging_path(&staged_relative).unwrap(), PAYLOAD).unwrap();
    create_manual_intent(&session, &staged_relative, &artifact);
    let baseline = payload_size(session.path());
    let catalog_bytes = pretty_json_size(&artifact);
    drop(session);

    let limited_root = ArtifactRoot::open(
        default_root.path(),
        SessionLimits {
            max_file_bytes: u64::try_from(PAYLOAD.len()).unwrap(),
            max_session_bytes: baseline + catalog_bytes - 1,
        },
    )
    .unwrap();
    let session = limited_root.session(&session_id).unwrap();
    let lock = session.try_lock().unwrap();
    assert!(matches!(
        session.ingest_staged(&lock, &staged_relative, raw_spec),
        Err(SessionStoreError::SessionLimitExceeded { .. })
    ));
    assert_eq!(
        session.inspect_ingest_intents().unwrap()[0].classification,
        IngestIntentClassification::Pending
    );
    assert!(session.staging_path(&staged_relative).unwrap().exists());
    assert!(!session.path().join("capture/raw/raw.txt").exists());
    assert!(session.registered_artifacts(false).unwrap().is_empty());
}

#[test]
fn pending_ingest_with_a_complete_private_copy_accepts_exact_catalog_capacity() {
    const PAYLOAD: &[u8] = b"trace-data";
    let temp = TempDir::new().unwrap();
    let default_root = root(&temp);
    let session = default_root
        .create_session_with_id(
            SessionId::new("session-ingest-ready-private-capacity").unwrap(),
            &json!({}),
        )
        .unwrap();
    let session_id = session.id().clone();
    let staged_relative = ArtifactPath::new("raw.txt").unwrap();
    let raw_spec = spec("raw", "capture/raw/raw.txt");
    let artifact = expected_artifact(&raw_spec, PAYLOAD);
    fs::write(session.staging_path(&staged_relative).unwrap(), PAYLOAD).unwrap();
    create_manual_intent(&session, &staged_relative, &artifact);
    let baseline = payload_size(session.path());
    let catalog_bytes = pretty_json_size(&artifact);
    let source_record_bytes = pretty_json_size(&json!({
        "schema": "t32perf.committed-staging-source/v1",
        "session_id": session_id.as_str(),
        "source": {
            "artifact_id": artifact.id,
            "staged_relative_path": staged_relative,
            "size_bytes": artifact.size_bytes,
            "sha256": artifact.sha256,
            "artifact_relative_path": artifact.relative_path,
        }
    }));
    drop(session);

    let limited_root = ArtifactRoot::open(
        default_root.path(),
        SessionLimits {
            max_file_bytes: u64::try_from(PAYLOAD.len()).unwrap(),
            max_session_bytes: baseline + catalog_bytes + source_record_bytes,
        },
    )
    .unwrap();
    let session = limited_root.session(&session_id).unwrap();
    let lock = session.try_lock().unwrap();
    session
        .ingest_staged(&lock, &staged_relative, raw_spec)
        .unwrap();
    assert!(session.inspect_ingest_intents().unwrap().is_empty());
    assert_eq!(
        fs::read(session.path().join("capture/raw/raw.txt")).unwrap(),
        PAYLOAD
    );
}

#[test]
fn prepared_ingest_recovery_reserves_private_copy_and_catalog_before_copying() {
    const PAYLOAD: &[u8] = b"trace-data";
    let temp = TempDir::new().unwrap();
    let default_root = root(&temp);
    let session = default_root
        .create_session_with_id(
            SessionId::new("session-ingest-prepare-quota").unwrap(),
            &json!({}),
        )
        .unwrap();
    let session_id = session.id().clone();
    let staged_relative = ArtifactPath::new("raw.txt").unwrap();
    let raw_spec = spec("raw", "capture/raw/raw.txt");
    let artifact = expected_artifact(&raw_spec, PAYLOAD);
    fs::write(session.staging_path(&staged_relative).unwrap(), PAYLOAD).unwrap();
    create_manual_intent(&session, &staged_relative, &artifact);
    fs::remove_file(session.path().join("capture/.ingest-private/raw.payload")).unwrap();
    let mut preparing = ingest_intent_value(&session, &staged_relative, &artifact);
    preparing["phase"] = json!("preparing");
    write_pretty_json(&intent_path(&session, "raw"), &preparing);
    let baseline = payload_size(session.path());
    let catalog_bytes = pretty_json_size(&artifact);
    drop(session);

    let limited_root = ArtifactRoot::open(
        default_root.path(),
        SessionLimits {
            max_file_bytes: u64::try_from(PAYLOAD.len()).unwrap(),
            max_session_bytes: baseline + u64::try_from(PAYLOAD.len()).unwrap() + catalog_bytes - 1,
        },
    )
    .unwrap();
    let session = limited_root.session(&session_id).unwrap();
    let lock = session.try_lock().unwrap();
    assert!(matches!(
        session.ingest_staged(&lock, &staged_relative, raw_spec),
        Err(SessionStoreError::SessionLimitExceeded { .. })
    ));
    assert!(
        !session
            .path()
            .join("capture/.ingest-private/raw.payload")
            .exists()
    );
    assert!(intent_path(&session, "raw").exists());
}

#[test]
fn prepared_ingest_rebuilds_an_intent_bound_partial_private_copy() {
    const PAYLOAD: &[u8] = b"trace-data";
    let temp = TempDir::new().unwrap();
    let session = root(&temp).create_session(&json!({})).unwrap();
    let staged_relative = ArtifactPath::new("raw.txt").unwrap();
    let raw_spec = spec("raw", "capture/raw/raw.txt");
    let artifact = expected_artifact(&raw_spec, PAYLOAD);
    fs::write(session.staging_path(&staged_relative).unwrap(), PAYLOAD).unwrap();
    create_manual_intent(&session, &staged_relative, &artifact);
    let private_path = session.path().join("capture/.ingest-private/raw.payload");
    fs::write(&private_path, b"partial").unwrap();
    let mut preparing = ingest_intent_value(&session, &staged_relative, &artifact);
    preparing["phase"] = json!("preparing");
    write_pretty_json(&intent_path(&session, "raw"), &preparing);

    let lock = session.try_lock().unwrap();
    let committed = session
        .ingest_staged(&lock, &staged_relative, raw_spec)
        .unwrap();
    assert_eq!(committed, artifact);
    assert_eq!(
        fs::read(session.path().join("capture/raw/raw.txt")).unwrap(),
        PAYLOAD
    );
    assert!(session.inspect_ingest_intents().unwrap().is_empty());
}

#[test]
fn legacy_pending_recovery_reserves_private_copy_and_catalog_before_copying() {
    const PAYLOAD: &[u8] = b"trace-data";
    let temp = TempDir::new().unwrap();
    let default_root = root(&temp);
    let session = default_root
        .create_session_with_id(
            SessionId::new("session-ingest-v1-quota").unwrap(),
            &json!({}),
        )
        .unwrap();
    let session_id = session.id().clone();
    let staged_relative = ArtifactPath::new("raw.txt").unwrap();
    let raw_spec = spec("raw", "capture/raw/raw.txt");
    let artifact = expected_artifact(&raw_spec, PAYLOAD);
    fs::write(session.staging_path(&staged_relative).unwrap(), PAYLOAD).unwrap();
    let mut legacy = ingest_intent_value(&session, &staged_relative, &artifact);
    legacy["schema"] = json!("t32perf.ingest-intent/v1");
    legacy
        .as_object_mut()
        .unwrap()
        .remove("private_relative_path");
    write_pretty_json(&intent_path(&session, "raw"), &legacy);
    let baseline = payload_size(session.path());
    let catalog_bytes = pretty_json_size(&artifact);
    drop(session);

    let limited_root = ArtifactRoot::open(
        default_root.path(),
        SessionLimits {
            max_file_bytes: u64::try_from(PAYLOAD.len()).unwrap(),
            max_session_bytes: baseline + u64::try_from(PAYLOAD.len()).unwrap() + catalog_bytes - 1,
        },
    )
    .unwrap();
    let session = limited_root.session(&session_id).unwrap();
    let lock = session.try_lock().unwrap();
    assert!(matches!(
        session.ingest_staged(&lock, &staged_relative, raw_spec),
        Err(SessionStoreError::SessionLimitExceeded { .. })
    ));
    assert!(intent_path(&session, "raw").exists());
}

#[test]
fn file_limit_stops_writer_before_commit() {
    let temp = TempDir::new().unwrap();
    let root = ArtifactRoot::open(
        temp.path().join("sessions"),
        SessionLimits {
            max_file_bytes: 4,
            max_session_bytes: 1024 * 1024,
        },
    )
    .unwrap();
    let session = root.create_session(&json!({})).unwrap();
    let lock = session.try_lock().unwrap();
    let mut writer = session
        .create_artifact(&lock, spec("limited", "analysis/limited.bin"))
        .unwrap();
    assert!(writer.write_all(b"12345").is_err());
    drop(writer);
    assert!(!session.path().join("analysis/limited.bin").exists());
}

#[test]
fn lists_only_valid_session_directories() {
    let temp = TempDir::new().unwrap();
    let root = root(&temp);
    root.create_session_with_id(SessionId::new("session-b").unwrap(), &json!({}))
        .unwrap();
    root.create_session_with_id(SessionId::new("session-a").unwrap(), &json!({}))
        .unwrap();
    fs::create_dir(root.path().join("invalid name")).unwrap();

    let listed: Vec<_> = root
        .list_sessions()
        .unwrap()
        .into_iter()
        .map(|id| id.to_string())
        .collect();
    assert_eq!(listed, ["session-a", "session-b"]);
}

#[test]
fn creation_preflights_tiny_quota_and_large_request_without_leaving_a_session() {
    let temp = TempDir::new().unwrap();
    let sessions = temp.path().join("sessions");
    let root = ArtifactRoot::open(
        &sessions,
        SessionLimits {
            max_file_bytes: 1,
            max_session_bytes: 512,
        },
    )
    .unwrap();
    let id = SessionId::new("session-request-overflow").unwrap();
    let result = root.create_session_with_id(id.clone(), &json!({"payload": "x".repeat(4 * 1024)}));
    assert!(matches!(
        result,
        Err(SessionStoreError::SessionLimitExceeded { .. })
    ));
    assert!(!sessions.join(id.as_str()).exists());

    let tiny = ArtifactRoot::open(
        temp.path().join("tiny-sessions"),
        SessionLimits {
            max_file_bytes: 1,
            max_session_bytes: 1,
        },
    )
    .unwrap();
    assert!(matches!(
        tiny.create_session_with_id(SessionId::new("session-tiny").unwrap(), &json!({})),
        Err(SessionStoreError::SessionLimitExceeded { .. })
    ));
    assert!(!tiny.path().join("session-tiny").exists());
}

#[test]
fn request_serialization_has_an_independent_memory_bound() {
    let temp = TempDir::new().unwrap();
    let root = root(&temp);
    let id = SessionId::new("session-metadata-overflow").unwrap();
    let request = json!({"payload": "x".repeat(16 * 1024 * 1024)});
    assert!(matches!(
        root.create_session_with_id(id.clone(), &request),
        Err(SessionStoreError::MetadataLimitExceeded {
            document: "session request",
            ..
        })
    ));
    assert!(!root.path().join(id.as_str()).exists());
}

#[test]
fn artifact_writer_reserves_catalog_bytes_before_accepting_content() {
    let temp = TempDir::new().unwrap();
    let default_root = root(&temp);
    let session = default_root.create_session(&json!({})).unwrap();
    let id = session.id().clone();
    let baseline = payload_size(session.path());
    drop(session);

    let limited_root = ArtifactRoot::open(
        default_root.path(),
        SessionLimits {
            max_file_bytes: 1,
            max_session_bytes: baseline + 1,
        },
    )
    .unwrap();
    let session = limited_root.session(&id).unwrap();
    let lock = session.try_lock().unwrap();
    assert!(matches!(
        session.create_artifact(&lock, spec("catalog-overflow", "analysis/empty.bin")),
        Err(SessionStoreError::SessionLimitExceeded { .. })
    ));
    assert!(!session.path().join("analysis/empty.bin").exists());
    assert_eq!(
        fs::read_dir(session.path().join("artifact-index"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn state_replacement_reserves_the_atomic_temporary_payload() {
    let temp = TempDir::new().unwrap();
    let default_root = root(&temp);
    let session = default_root.create_session(&json!({})).unwrap();
    let id = session.id().clone();
    let baseline = payload_size(session.path());
    drop(session);

    let limited_root = ArtifactRoot::open(
        default_root.path(),
        SessionLimits {
            max_file_bytes: 1,
            max_session_bytes: baseline + 1,
        },
    )
    .unwrap();
    let session = limited_root.session(&id).unwrap();
    let lock = session.try_lock().unwrap();
    assert!(matches!(
        session.transition(&lock, SessionStatus::Capturing, None),
        Err(SessionStoreError::SessionLimitExceeded { .. })
    ));
    assert_eq!(session.read_state().unwrap().status, SessionStatus::Created);
}

#[test]
fn one_active_writer_prevents_concurrent_quota_reservations() {
    let temp = TempDir::new().unwrap();
    let session = root(&temp).create_session(&json!({})).unwrap();
    let lock = session.try_lock().unwrap();
    let writer = session
        .create_artifact(&lock, spec("first", "analysis/first.bin"))
        .unwrap();
    assert!(matches!(
        session.create_artifact(&lock, spec("second", "analysis/second.bin")),
        Err(SessionStoreError::ArtifactWriterActive { .. })
    ));
    assert!(matches!(
        session.transition(&lock, SessionStatus::Capturing, None),
        Err(SessionStoreError::ArtifactWriterActive { .. })
    ));
    drop(writer);
    session
        .transition(&lock, SessionStatus::Capturing, None)
        .unwrap();
}

#[test]
fn invalid_or_oversized_artifact_metadata_never_creates_catalog_state() {
    let temp = TempDir::new().unwrap();
    let session = root(&temp).create_session(&json!({})).unwrap();
    let lock = session.try_lock().unwrap();

    let mut oversized = spec("oversized", "analysis/oversized.bin");
    oversized.kind = "x".repeat(257);
    assert!(matches!(
        session.create_artifact(&lock, oversized),
        Err(SessionStoreError::InvalidArtifactSpec { .. })
    ));

    let mut too_many_inputs = spec("too-many", "analysis/too-many.bin");
    too_many_inputs.input_artifact_ids = (0..=MAX_ARTIFACT_INPUTS)
        .map(|index| format!("input-{index}"))
        .collect();
    assert!(matches!(
        session.create_artifact(&lock, too_many_inputs),
        Err(SessionStoreError::InvalidArtifactSpec { .. })
    ));

    let mut duplicate_inputs = spec("duplicates", "analysis/duplicates.bin");
    duplicate_inputs.input_artifact_ids = vec!["raw".to_owned(), "raw".to_owned()];
    assert!(matches!(
        session.create_artifact(&lock, duplicate_inputs),
        Err(SessionStoreError::InvalidArtifactSpec { .. })
    ));
    assert_eq!(
        fs::read_dir(session.path().join("artifact-index"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn finalize_reserves_manifest_and_replacement_state_before_manifest_commit() {
    let temp = TempDir::new().unwrap();
    let default_root = root(&temp);
    let session = default_root.create_session(&json!({})).unwrap();
    let id = session.id().clone();
    {
        let lock = session.try_lock().unwrap();
        session
            .transition(&lock, SessionStatus::Capturing, None)
            .unwrap();
        session
            .transition(&lock, SessionStatus::Captured, None)
            .unwrap();
    }
    let manifest = manifest(id.as_str(), Vec::new());
    let baseline = payload_size(session.path());
    let manifest_bytes = pretty_json_size(&manifest);
    drop(session);

    let limited_root = ArtifactRoot::open(
        default_root.path(),
        SessionLimits {
            max_file_bytes: 1,
            max_session_bytes: baseline + manifest_bytes,
        },
    )
    .unwrap();
    let session = limited_root.session(&id).unwrap();
    let lock = session.try_lock().unwrap();
    assert!(matches!(
        session.finalize(&lock, &manifest),
        Err(SessionStoreError::SessionLimitExceeded { .. })
    ));
    assert!(!session.path().join("manifest.json").exists());
    assert_eq!(
        session.read_state().unwrap().status,
        SessionStatus::Captured
    );
}

#[test]
fn complete_session_retries_are_noops_and_new_mutations_are_rejected() {
    let temp = TempDir::new().unwrap();
    let session = root(&temp).create_session(&json!({})).unwrap();
    let lock = session.try_lock().unwrap();
    session
        .transition(&lock, SessionStatus::Capturing, None)
        .unwrap();
    session
        .transition(&lock, SessionStatus::Captured, None)
        .unwrap();

    let artifact_spec = spec("result", "analysis/result.bin");
    let mut writer = session
        .create_artifact(&lock, artifact_spec.clone())
        .unwrap();
    writer.write_all(b"result").unwrap();
    let artifact = session.commit_artifact(&lock, writer).unwrap();
    let manifest = manifest(session.id().as_str(), vec![artifact.clone()]);
    let completed = session.finalize(&lock, &manifest).unwrap();
    let retried = session.finalize(&lock, &manifest).unwrap();
    assert_eq!(retried, completed);
    assert_eq!(session.read_state().unwrap(), completed);
    assert!(matches!(
        session.transition(&lock, SessionStatus::Complete, None),
        Err(SessionStoreError::InvalidTransition { .. })
    ));

    session.register_artifact(&lock, &artifact).unwrap();
    let new_artifact = expected_artifact(&spec("new-register", "analysis/new-register.bin"), b"");
    assert!(matches!(
        session.register_artifact(&lock, &new_artifact),
        Err(SessionStoreError::TerminalSessionMutation {
            status: SessionStatus::Complete
        })
    ));
    let staged = ArtifactPath::new("retry.bin").unwrap();
    assert_eq!(
        session
            .ingest_staged(&lock, &staged, artifact_spec)
            .unwrap(),
        artifact
    );
    let pending = ArtifactPath::new("pending.bin").unwrap();
    fs::write(session.staging_path(&pending).unwrap(), b"pending").unwrap();
    assert!(matches!(
        session.ingest_staged(&lock, &pending, spec("pending", "capture/raw/pending.bin"),),
        Err(SessionStoreError::TerminalSessionMutation {
            status: SessionStatus::Complete
        })
    ));
    assert!(session.staging_path(&pending).unwrap().exists());
    assert!(!session.path().join("capture/raw/pending.bin").exists());
    assert!(matches!(
        session.create_artifact(&lock, spec("new", "analysis/new.bin")),
        Err(SessionStoreError::TerminalSessionMutation {
            status: SessionStatus::Complete
        })
    ));
    let nested = ArtifactPath::new("new/path.bin").unwrap();
    assert!(matches!(
        session.prepare_staging_path(&lock, &nested),
        Err(SessionStoreError::TerminalSessionMutation {
            status: SessionStatus::Complete
        })
    ));
    assert!(!session.staging_root().join("new").exists());

    let mut conflicting = manifest;
    conflicting.tool.version = "different".to_owned();
    assert!(matches!(
        session.finalize(&lock, &conflicting),
        Err(SessionStoreError::ManifestConflict)
    ));
    assert_eq!(session.read_state().unwrap(), completed);
}

#[test]
fn failed_session_same_error_is_noop_and_new_mutations_are_rejected() {
    let temp = TempDir::new().unwrap();
    let session = root(&temp).create_session(&json!({})).unwrap();
    let lock = session.try_lock().unwrap();
    let artifact_spec = spec("diagnostic", "analysis/diagnostic.bin");
    let mut writer = session
        .create_artifact(&lock, artifact_spec.clone())
        .unwrap();
    writer.write_all(b"diagnostic").unwrap();
    let artifact = session.commit_artifact(&lock, writer).unwrap();
    let failure = SessionError {
        code: "INJECTED".to_owned(),
        message: "injected failure".to_owned(),
        details: Default::default(),
    };
    let failed = session
        .transition(&lock, SessionStatus::Failed, Some(failure.clone()))
        .unwrap();
    let retried = session
        .transition(&lock, SessionStatus::Failed, Some(failure.clone()))
        .unwrap();
    assert_eq!(retried, failed);

    let different = SessionError {
        message: "different".to_owned(),
        ..failure
    };
    assert!(matches!(
        session.transition(&lock, SessionStatus::Failed, Some(different)),
        Err(SessionStoreError::InvalidTransition { .. })
    ));
    session.register_artifact(&lock, &artifact).unwrap();
    let new_artifact = expected_artifact(&spec("new-register", "analysis/new-register.bin"), b"");
    assert!(matches!(
        session.register_artifact(&lock, &new_artifact),
        Err(SessionStoreError::TerminalSessionMutation {
            status: SessionStatus::Failed
        })
    ));
    assert_eq!(
        session
            .ingest_staged(
                &lock,
                &ArtifactPath::new("retry.bin").unwrap(),
                artifact_spec,
            )
            .unwrap(),
        artifact
    );
    assert!(matches!(
        session.create_artifact(&lock, spec("new", "analysis/new.bin")),
        Err(SessionStoreError::TerminalSessionMutation {
            status: SessionStatus::Failed
        })
    ));
    assert!(matches!(
        session.finalize(&lock, &manifest(session.id().as_str(), vec![artifact])),
        Err(SessionStoreError::InvalidTransition { .. })
    ));
    assert_eq!(session.read_state().unwrap(), failed);
}

#[test]
fn staging_path_is_read_only_until_locked_prepare() {
    let temp = TempDir::new().unwrap();
    let session = root(&temp).create_session(&json!({})).unwrap();
    let nested = ArtifactPath::new("provider/run/raw.bin").unwrap();
    let parsed = session.staging_path(&nested).unwrap();
    assert_eq!(parsed, session.staging_root().join("provider/run/raw.bin"));
    assert!(!session.staging_root().join("provider").exists());

    let lock = session.try_lock().unwrap();
    assert_eq!(
        session.prepare_staging_path(&lock, &nested).unwrap(),
        parsed
    );
    assert!(session.staging_root().join("provider/run").is_dir());
}

#[test]
fn bounded_staging_read_rejects_oversized_control_files_without_mutation() {
    let temp = TempDir::new().unwrap();
    let root = root(&temp);
    let session = root
        .create_session_with_id(SessionId::new("bounded-staging").unwrap(), &json!({}))
        .unwrap();
    let relative = ArtifactPath::new("controller/response.txt").unwrap();
    let lock = session.try_lock().unwrap();
    let path = session.prepare_staging_path(&lock, &relative).unwrap();
    fs::write(&path, b"finished response").unwrap();

    assert_eq!(
        session.read_staged_bounded(&relative, 64).unwrap(),
        b"finished response"
    );
    assert!(matches!(
        session.read_staged_bounded(&relative, 4),
        Err(SessionStoreError::MetadataLimitExceeded {
            document: "staged control file",
            limit_bytes: 4,
            ..
        })
    ));
    assert_eq!(fs::read(path).unwrap(), b"finished response");
}

#[test]
fn ensure_staged_exact_is_idempotent_and_never_overwrites_conflicts() {
    let temp = TempDir::new().unwrap();
    let session = root(&temp).create_session(&json!({})).unwrap();
    let lock = session.try_lock().unwrap();
    let relative = ArtifactPath::new("controller/generated.json").unwrap();

    session
        .ensure_staged_exact(&lock, &relative, b"authoritative", 64)
        .unwrap();
    session
        .ensure_staged_exact(&lock, &relative, b"authoritative", 64)
        .unwrap();
    assert_eq!(
        session.read_staged_bounded(&relative, 64).unwrap(),
        b"authoritative"
    );
    assert!(matches!(
        session.ensure_staged_exact(&lock, &relative, b"conflicting", 64),
        Err(SessionStoreError::IngestIntentConflict { .. })
    ));
    assert_eq!(
        session.read_staged_bounded(&relative, 64).unwrap(),
        b"authoritative"
    );
}

#[test]
fn ensure_staged_exact_ignores_crashed_temporary_residue_before_atomic_publish() {
    let temp = TempDir::new().unwrap();
    let session = root(&temp).create_session(&json!({})).unwrap();
    let lock = session.try_lock().unwrap();
    let relative = ArtifactPath::new("controller/generated.json").unwrap();
    let destination = session.prepare_staging_path(&lock, &relative).unwrap();
    let residue = destination.with_file_name(".generated.json.crashed.partial");
    fs::write(&residue, b"truncated").unwrap();

    session
        .ensure_staged_exact(&lock, &relative, b"authoritative", 64)
        .unwrap();
    assert_eq!(
        session.read_staged_bounded(&relative, 64).unwrap(),
        b"authoritative"
    );
    assert_eq!(fs::read(residue).unwrap(), b"truncated");
}

#[cfg(unix)]
#[test]
fn ensure_staged_exact_rejects_symlink_leaves() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().unwrap();
    let session = root(&temp).create_session(&json!({})).unwrap();
    let lock = session.try_lock().unwrap();
    let relative = ArtifactPath::new("controller/generated.json").unwrap();
    let staged = session.prepare_staging_path(&lock, &relative).unwrap();
    let external = temp.path().join("external.json");
    fs::write(&external, b"external").unwrap();
    symlink(&external, &staged).unwrap();

    assert!(matches!(
        session.ensure_staged_exact(&lock, &relative, b"authoritative", 64),
        Err(SessionStoreError::LinkNotAllowed { .. })
    ));
    assert_eq!(fs::read(external).unwrap(), b"external");
}

#[test]
fn managed_json_reads_reject_oversized_files_before_parsing() {
    const OVERSIZED: u64 = 16 * 1024 * 1024 + 1;
    let temp = TempDir::new().unwrap();
    let root = root(&temp);

    let state_session = root
        .create_session_with_id(SessionId::new("session-state-dos").unwrap(), &json!({}))
        .unwrap();
    fs::File::options()
        .write(true)
        .open(state_session.path().join("state.json"))
        .unwrap()
        .set_len(OVERSIZED)
        .unwrap();
    assert!(matches!(
        state_session.read_state(),
        Err(SessionStoreError::MetadataLimitExceeded {
            document: "session state",
            ..
        })
    ));

    let request_session = root
        .create_session_with_id(SessionId::new("session-request-dos").unwrap(), &json!({}))
        .unwrap();
    fs::File::options()
        .write(true)
        .open(request_session.path().join("request.json"))
        .unwrap()
        .set_len(OVERSIZED)
        .unwrap();
    assert!(matches!(
        request_session.request(),
        Err(SessionStoreError::MetadataLimitExceeded {
            document: "session request",
            ..
        })
    ));

    let catalog_session = root
        .create_session_with_id(SessionId::new("session-catalog-dos").unwrap(), &json!({}))
        .unwrap();
    fs::File::create(
        catalog_session
            .path()
            .join("artifact-index")
            .join("oversized.json"),
    )
    .unwrap()
    .set_len(OVERSIZED)
    .unwrap();
    assert!(matches!(
        catalog_session.registered_artifacts(false),
        Err(SessionStoreError::MetadataLimitExceeded {
            document: "artifact catalog record",
            ..
        })
    ));

    let manifest_session = root
        .create_session_with_id(SessionId::new("session-manifest-dos").unwrap(), &json!({}))
        .unwrap();
    fs::File::create(manifest_session.path().join("manifest.json"))
        .unwrap()
        .set_len(OVERSIZED)
        .unwrap();
    assert!(matches!(
        manifest_session.manifest(),
        Err(SessionStoreError::MetadataLimitExceeded {
            document: "manifest",
            ..
        })
    ));
}

#[test]
fn managed_json_reads_reject_duplicate_members_recursively() {
    let temp = TempDir::new().unwrap();
    let root = root(&temp);

    let request_session = root
        .create_session_with_id(
            SessionId::new("session-request-duplicate").unwrap(),
            &json!({}),
        )
        .unwrap();
    fs::write(
        request_session.path().join("request.json"),
        br#"{"properties":{"mode":"first","mode":"last"}}"#,
    )
    .unwrap();
    let request_error = request_session
        .request()
        .expect_err("duplicate request property");
    assert!(matches!(request_error, SessionStoreError::Json { .. }));
    assert!(
        request_error
            .to_string()
            .contains("duplicate JSON object member name `mode`")
    );

    let state_session = root
        .create_session_with_id(
            SessionId::new("session-state-duplicate").unwrap(),
            &json!({}),
        )
        .unwrap();
    let state = fs::read_to_string(state_session.path().join("state.json")).unwrap();
    let duplicated = state.replacen(
        "\"revision\": 0,",
        "\"revision\": 0,\n  \"revision\": 1,",
        1,
    );
    assert_ne!(duplicated, state);
    fs::write(state_session.path().join("state.json"), duplicated).unwrap();
    let state_error = state_session
        .read_state()
        .expect_err("duplicate state revision");
    assert!(
        state_error
            .to_string()
            .contains("duplicate JSON object member name `revision`")
    );

    let manifest_session = root
        .create_session_with_id(
            SessionId::new("session-manifest-duplicate").unwrap(),
            &json!({}),
        )
        .unwrap();
    let mut document =
        serde_json::to_value(manifest(manifest_session.id().as_str(), Vec::new())).unwrap();
    document["capture"]["target"] = json!({
        "architecture": "armv8-m",
        "properties": {"rtos": "first"}
    });
    let serialized = serde_json::to_string(&document).unwrap();
    let duplicated = serialized.replacen(
        "\"rtos\":\"first\"",
        "\"rtos\":\"first\",\"rtos\":\"last\"",
        1,
    );
    assert_ne!(duplicated, serialized);
    fs::write(manifest_session.path().join("manifest.json"), duplicated).unwrap();
    let manifest_error = manifest_session
        .manifest()
        .expect_err("duplicate manifest property");
    assert!(
        manifest_error
            .to_string()
            .contains("duplicate JSON object member name `rtos`")
    );
}

#[cfg(unix)]
#[test]
fn rejects_symlink_inside_session() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().unwrap();
    let session = root(&temp).create_session(&json!({})).unwrap();
    let lock = session.try_lock().unwrap();
    symlink(temp.path(), session.path().join("analysis/link")).unwrap();
    let result = session.create_artifact(&lock, spec("escape", "analysis/link/out.bin"));
    assert!(matches!(
        result,
        Err(SessionStoreError::LinkNotAllowed { .. })
    ));
}

#[cfg(unix)]
#[test]
fn lock_and_session_listing_reject_symlink_leaves() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().unwrap();
    let root = root(&temp);
    let session = root
        .create_session_with_id(SessionId::new("session-lock-link").unwrap(), &json!({}))
        .unwrap();
    let external_lock = temp.path().join("external.lock");
    fs::write(&external_lock, b"").unwrap();
    fs::remove_file(session.path().join(".session.lock")).unwrap();
    symlink(&external_lock, session.path().join(".session.lock")).unwrap();
    assert!(matches!(
        session.try_lock(),
        Err(SessionStoreError::LinkNotAllowed { .. })
    ));

    symlink(temp.path(), root.path().join("session-linked")).unwrap();
    let listed = root.list_sessions().unwrap();
    assert!(!listed.iter().any(|id| id.as_str() == "session-linked"));
}
