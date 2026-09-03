use std::{path::Path, process::Output};

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::{Value, json};
use t32perf_model::ArtifactPath;
use t32perf_model::{
    AdapterInfo, CaptureInfo, FirmwareInfo, Manifest, ManifestSchemaVersion, SessionStatus,
    ToolInfo,
};
use t32perf_session::{ArtifactRoot, ArtifactSpec, SessionId, SessionLimits};
use tempfile::TempDir;

#[test]
fn maintenance_cli_inspects_bundles_and_round_trips_retention() {
    let temp = TempDir::new().expect("temporary directory");
    let root_path = temp.path().join("artifacts");
    let root = ArtifactRoot::open(&root_path, SessionLimits::default()).expect("artifact root");
    complete_session(&root, "retained-session");

    let inspected = run(
        &root_path,
        &["maintenance", "inspect", "retained-session", "--deep"],
    );
    println!("{}", stderr(&inspected));
    assert_eq!(inspected.status.code(), Some(0), "{}", stderr(&inspected));
    assert_eq!(json_stdout(&inspected)["result"]["healthy"], true);

    let diagnostics = run(
        &root_path,
        &["maintenance", "diagnostics", "retained-session"],
    );
    assert_eq!(
        diagnostics.status.code(),
        Some(0),
        "{}",
        stderr(&diagnostics)
    );
    let diagnostics_json = json_stdout(&diagnostics);
    let bundle = diagnostics_json["result"]["control_path"]
        .as_str()
        .expect("diagnostic path");
    assert!(root_path.join(bundle).is_file());
    let diagnostic_document: Value =
        serde_json::from_slice(&std::fs::read(root_path.join(bundle)).expect("read diagnostic"))
            .expect("diagnostic JSON");
    assert_eq!(
        diagnostic_document["redaction"]["artifact_root_paths_redacted"],
        true
    );
    assert!(
        diagnostic_document["redaction"]
            .get("absolute_paths_redacted")
            .is_none()
    );

    let schema = run(&root_path, &["maintenance", "schema", "retained-session"]);
    assert_eq!(schema.status.code(), Some(0), "{}", stderr(&schema));
    assert_eq!(
        json_stdout(&schema)["result"]["migration"]["in_place_supported"],
        false
    );

    let planned = run(
        &root_path,
        &[
            "maintenance",
            "retention",
            "plan",
            "--session",
            "retained-session",
        ],
    );
    assert_eq!(planned.status.code(), Some(0), "{}", stderr(&planned));
    let planned_json = json_stdout(&planned);
    let plan_id = planned_json["result"]["plan_id"].as_str().expect("plan ID");
    let confirmation = planned_json["result"]["confirm_sha256"]
        .as_str()
        .expect("confirmation digest");

    let rejected = run(
        &root_path,
        &[
            "maintenance",
            "retention",
            "apply",
            plan_id,
            "--confirm",
            &"0".repeat(64),
        ],
    );
    assert_eq!(rejected.status.code(), Some(1));
    assert!(root_path.join("retained-session").is_dir());

    let applied = run(
        &root_path,
        &[
            "maintenance",
            "retention",
            "apply",
            plan_id,
            "--confirm",
            confirmation,
        ],
    );
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    assert!(!root_path.join("retained-session").exists());
    let applied_again = run(
        &root_path,
        &[
            "maintenance",
            "retention",
            "apply",
            plan_id,
            "--confirm",
            confirmation,
        ],
    );
    assert_eq!(
        applied_again.status.code(),
        Some(0),
        "{}",
        stderr(&applied_again)
    );
    assert_eq!(
        json_stdout(&applied_again)["result"]["already_quarantined"],
        json!(["retained-session"])
    );

    let restored = run(
        &root_path,
        &[
            "maintenance",
            "retention",
            "restore",
            plan_id,
            "retained-session",
            "--confirm",
            confirmation,
        ],
    );
    assert_eq!(restored.status.code(), Some(0), "{}", stderr(&restored));
    assert!(root_path.join("retained-session").is_dir());
    let restored_again = run(
        &root_path,
        &[
            "maintenance",
            "retention",
            "restore",
            plan_id,
            "retained-session",
            "--confirm",
            confirmation,
        ],
    );
    assert_eq!(
        restored_again.status.code(),
        Some(0),
        "{}",
        stderr(&restored_again)
    );
    assert_eq!(
        json_stdout(&restored_again)["result"]["already_restored"],
        true
    );

    complete_session(&root, "orphan-session");
    std::fs::write(root_path.join("orphan-session/logs/orphan.log"), b"orphan")
        .expect("write orphan");
    let orphan_plan = run(
        &root_path,
        &[
            "maintenance",
            "retention",
            "plan",
            "--session",
            "orphan-session",
        ],
    );
    assert_eq!(orphan_plan.status.code(), Some(1));
    assert!(root_path.join("orphan-session").is_dir());
}

#[test]
fn maintenance_retains_a_complete_session_with_a_verified_staging_source() {
    let temp = TempDir::new().expect("temporary directory");
    let root_path = temp.path().join("artifacts");
    let root = ArtifactRoot::open(&root_path, SessionLimits::default()).expect("artifact root");
    complete_staged_session(&root, "retained-staged-source");

    let inspected = run(
        &root_path,
        &["maintenance", "inspect", "retained-staged-source", "--deep"],
    );
    assert_eq!(inspected.status.code(), Some(0), "{}", stderr(&inspected));
    let inspected_json = json_stdout(&inspected);
    assert_eq!(inspected_json["result"]["healthy"], true);
    assert_eq!(inspected_json["result"]["retained_staging_files_total"], 1);

    let planned = run(
        &root_path,
        &[
            "maintenance",
            "retention",
            "plan",
            "--session",
            "retained-staged-source",
        ],
    );
    assert_eq!(planned.status.code(), Some(0), "{}", stderr(&planned));
    let planned_json = json_stdout(&planned);
    let plan_id = planned_json["result"]["plan_id"].as_str().unwrap();
    let confirmation = planned_json["result"]["confirm_sha256"].as_str().unwrap();
    let applied = run(
        &root_path,
        &[
            "maintenance",
            "retention",
            "apply",
            plan_id,
            "--confirm",
            confirmation,
        ],
    );
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    let restored = run(
        &root_path,
        &[
            "maintenance",
            "retention",
            "restore",
            plan_id,
            "retained-staged-source",
            "--confirm",
            confirmation,
        ],
    );
    assert_eq!(restored.status.code(), Some(0), "{}", stderr(&restored));
}

#[test]
fn maintenance_cli_abandons_and_restores_crash_residue_as_one_session() {
    let temp = TempDir::new().expect("temporary directory");
    let root_path = temp.path().join("artifacts");
    let root = ArtifactRoot::open(&root_path, SessionLimits::default()).expect("artifact root");
    root.create_session_with_id(
        SessionId::new("crash-residue").expect("Session ID"),
        &json!({"workload": "interrupted"}),
    )
    .expect("create incomplete Session");
    let staging = root_path.join("crash-residue/capture/staging/partial.bin");
    let orphan = root_path.join("crash-residue/logs/process.tmp");
    std::fs::write(&staging, b"partial").expect("write staging residue");
    std::fs::write(&orphan, b"temporary").expect("write orphan residue");

    let planned = run(
        &root_path,
        &["maintenance", "abandon", "plan", "crash-residue"],
    );
    assert_eq!(planned.status.code(), Some(0), "{}", stderr(&planned));
    let planned = json_stdout(&planned);
    let plan_id = planned["result"]["plan_id"].as_str().expect("plan ID");
    let confirmation = planned["result"]["confirm_sha256"]
        .as_str()
        .expect("confirmation digest");

    let applied = run(
        &root_path,
        &[
            "maintenance",
            "abandon",
            "apply",
            plan_id,
            "--confirm",
            confirmation,
        ],
    );
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    assert!(!root_path.join("crash-residue").exists());

    let restored = run(
        &root_path,
        &[
            "maintenance",
            "abandon",
            "restore",
            plan_id,
            "--confirm",
            confirmation,
        ],
    );
    assert_eq!(restored.status.code(), Some(0), "{}", stderr(&restored));
    assert_eq!(
        std::fs::read(staging).expect("restored staging"),
        b"partial"
    );
    assert_eq!(
        std::fs::read(orphan).expect("restored orphan"),
        b"temporary"
    );
}

#[test]
fn maintenance_cli_fails_closed_on_corrupt_journal() {
    let temp = TempDir::new().expect("temporary directory");
    let root_path = temp.path().join("artifacts");
    let root = ArtifactRoot::open(&root_path, SessionLimits::default()).expect("artifact root");
    complete_session(&root, "corrupt-journal");
    let planned = run(
        &root_path,
        &[
            "maintenance",
            "retention",
            "plan",
            "--session",
            "corrupt-journal",
        ],
    );
    assert_eq!(planned.status.code(), Some(0), "{}", stderr(&planned));
    let document = json_stdout(&planned);
    let plan_id = document["result"]["plan_id"].as_str().expect("plan ID");
    let confirmation = document["result"]["confirm_sha256"]
        .as_str()
        .expect("confirmation");
    let journal = root_path
        .join(".t32perf-control/retention/journals")
        .join(plan_id);
    std::fs::create_dir_all(&journal).expect("journal directory");
    std::fs::write(
        journal.join("000000-quarantined-corrupt-journal.json"),
        b"{",
    )
    .expect("corrupt journal");

    let applied = run(
        &root_path,
        &[
            "maintenance",
            "retention",
            "apply",
            plan_id,
            "--confirm",
            confirmation,
        ],
    );
    assert_eq!(applied.status.code(), Some(1));
    assert!(root_path.join("corrupt-journal").is_dir());
}

fn complete_session(root: &ArtifactRoot, id: &str) {
    let session = root
        .create_session_with_id(
            SessionId::new(id).expect("Session ID"),
            &json!({"secret": "not-copied-to-diagnostics"}),
        )
        .expect("create Session");
    let lock = session.try_lock().expect("lock Session");
    session
        .transition(&lock, SessionStatus::Capturing, None)
        .expect("capture start");
    let captured = session
        .transition(&lock, SessionStatus::Captured, None)
        .expect("capture complete");
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
    session
        .finalize(&lock, &manifest)
        .expect("finalize Session");
}

fn complete_staged_session(root: &ArtifactRoot, id: &str) {
    let session = root
        .create_session_with_id(SessionId::new(id).unwrap(), &json!({}))
        .unwrap();
    let lock = session.try_lock().unwrap();
    session
        .transition(&lock, SessionStatus::Capturing, None)
        .unwrap();
    let staged = ArtifactPath::new("capture.bin").unwrap();
    std::fs::write(session.staging_path(&staged).unwrap(), b"capture-data").unwrap();
    let artifact = session
        .ingest_staged(
            &lock,
            &staged,
            ArtifactSpec {
                id: "capture".to_owned(),
                kind: "raw_trace".to_owned(),
                relative_path: ArtifactPath::new("capture/raw/capture.bin").unwrap(),
                media_type: "application/octet-stream".to_owned(),
                producer: "test".to_owned(),
                input_artifact_ids: Vec::new(),
            },
        )
        .unwrap();
    let captured = session
        .transition(&lock, SessionStatus::Captured, None)
        .unwrap();
    session
        .finalize(
            &lock,
            &Manifest {
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
            },
        )
        .unwrap();
}

fn run(root: &Path, arguments: &[&str]) -> Output {
    let mut command = cargo_bin_cmd!("t32perf");
    command
        .arg("--artifact-root")
        .arg(root)
        .arg("--json")
        .args(arguments)
        .output()
        .expect("run t32perf")
}

fn json_stdout(output: &Output) -> Value {
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert_eq!(stdout.lines().count(), 1, "stdout was not one JSON object");
    serde_json::from_str(stdout).expect("stdout is JSON")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
