use std::{fs, io::Write as _, path::Path, process::Output};

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::{Value, json};
use t32perf_model::ArtifactPath;
use t32perf_session::{ArtifactRoot, ArtifactSpec, SessionId, SessionLimits};
use tempfile::TempDir;

fn run(root: &Path, arguments: &[&str]) -> Output {
    cargo_bin_cmd!("t32perf")
        .args(["--artifact-root", &root.to_string_lossy(), "--json"])
        .args(arguments)
        .output()
        .expect("run t32perf")
}

fn stdout_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid JSON stdout: {error}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The endpoint-only `GetCapabilities` request still proves the controller's
/// immutable firmware-to-S3 binding.  This self-contained fixture satisfies
/// that parser without selecting a profile, a target, or a TRACE32 endpoint.
fn register_synthetic_tricore_firmware(root: &Path, session: &str) {
    let artifact_root = ArtifactRoot::open(root, SessionLimits::default()).unwrap();
    let store = artifact_root
        .session(&SessionId::new(session.to_owned()).unwrap())
        .unwrap();
    let lock = store.try_lock().unwrap();
    let mut writer = store
        .create_artifact(
            &lock,
            ArtifactSpec {
                id: "firmware-elf".to_owned(),
                kind: "firmware_elf".to_owned(),
                relative_path: ArtifactPath::new("capture/firmware.elf").unwrap(),
                media_type: "application/x-elf".to_owned(),
                producer: "t32perf-deployment-firmware/v1".to_owned(),
                input_artifact_ids: Vec::new(),
            },
        )
        .unwrap();
    writer.write_all(&synthetic_tricore_elf()).unwrap();
    store.commit_artifact(&lock, writer).unwrap();
}

fn synthetic_tricore_elf() -> Vec<u8> {
    let mut elf = vec![0_u8; 97];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 1;
    elf[5] = 1;
    elf[6] = 1;
    elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
    elf[18..20].copy_from_slice(&44_u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
    elf[24..28].copy_from_slice(&0x8000_0000_u32.to_le_bytes());
    elf[28..32].copy_from_slice(&52_u32.to_le_bytes());
    elf[40..42].copy_from_slice(&52_u16.to_le_bytes());
    elf[42..44].copy_from_slice(&32_u16.to_le_bytes());
    elf[44..46].copy_from_slice(&1_u16.to_le_bytes());
    elf[52..56].copy_from_slice(&1_u32.to_le_bytes());
    elf[56..60].copy_from_slice(&96_u32.to_le_bytes());
    elf[60..64].copy_from_slice(&0x8000_0000_u32.to_le_bytes());
    elf[64..68].copy_from_slice(&0xa000_0000_u32.to_le_bytes());
    elf[68..72].copy_from_slice(&1_u32.to_le_bytes());
    elf[72..76].copy_from_slice(&1_u32.to_le_bytes());
    elf[76..80].copy_from_slice(&5_u32.to_le_bytes());
    elf[80..84].copy_from_slice(&4_u32.to_le_bytes());
    elf[96] = 0x5a;
    elf
}

#[test]
fn endpoint_recovery_is_idempotent_and_keeps_failed_session_terminal() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("artifact root with spaces");
    let session = "controller-endpoint-recovery";
    let created = run(&root, &["session", "create", "--id", session]);
    assert_eq!(created.status.code(), Some(0), "{}", stderr(&created));
    register_synthetic_tricore_firmware(&root, session);

    let prepared = run(
        &root,
        &[
            "controller",
            "prepare",
            session,
            "--operation",
            "perf_get_capabilities",
        ],
    );
    assert_eq!(prepared.status.code(), Some(0), "{}", stderr(&prepared));
    let prepared = stdout_json(&prepared);
    let transaction = prepared["result"]["transaction_id"].as_str().unwrap();

    let aborted = run(
        &root,
        &[
            "controller",
            "abort",
            session,
            transaction,
            "--reason",
            "operator_request",
        ],
    );
    assert_eq!(aborted.status.code(), Some(0), "{}", stderr(&aborted));
    let confirmed = run(
        &root,
        &[
            "controller",
            "confirm-abort",
            session,
            transaction,
            "--acknowledge-unbound-success",
        ],
    );
    assert_eq!(confirmed.status.code(), Some(0), "{}", stderr(&confirmed));
    assert_eq!(
        stdout_json(&confirmed)["result"]["target_quarantined"],
        true
    );

    let recovery = run(
        &root,
        &[
            "controller",
            "recover",
            "prepare",
            session,
            transaction,
            "--scope",
            "endpoint",
        ],
    );
    assert_eq!(recovery.status.code(), Some(0), "{}", stderr(&recovery));
    let recovery = stdout_json(&recovery);
    let expectation = &recovery["result"]["evidence_expectation"];
    let evidence = json!({
        "schema": "t32perf.controller-endpoint-recovery-evidence/v1",
        "adapter_catalog_sha256": expectation["adapter_catalog_sha256"],
        "binding_sha256": expectation["binding_sha256"],
        "failed_operation": expectation["failed_operation"],
        "upstream_abort_confirmed": true,
        "upstream_abort_receipt_sha256": expectation["upstream_abort_receipt_sha256"],
        "adapter_mutation": false,
        "files_deleted": false,
        "new_session_required": true
    });
    fs::write(
        recovery["result"]["evidence_handoff_path"]
            .as_str()
            .unwrap(),
        serde_json::to_vec(&evidence).unwrap(),
    )
    .unwrap();
    let reservation = recovery["result"]["reservation_id"].as_str().unwrap();
    let accepted = run(&root, &["controller", "recover", "accept", reservation]);
    assert_eq!(accepted.status.code(), Some(0), "{}", stderr(&accepted));
    let accepted = stdout_json(&accepted);
    assert_eq!(accepted["result"]["failed_session_remains_terminal"], true);
    assert_eq!(
        accepted["result"]["active_quarantine_moved_to_history"],
        true
    );
    let repeated = run(&root, &["controller", "recover", "accept", reservation]);
    assert_eq!(repeated.status.code(), Some(0), "{}", stderr(&repeated));
    assert_eq!(stdout_json(&repeated)["result"]["already_recovered"], true);

    let status = run(&root, &["session", "status", session]);
    assert_eq!(status.status.code(), Some(0), "{}", stderr(&status));
    assert_eq!(stdout_json(&status)["result"]["state"]["state"], "failed");
}
