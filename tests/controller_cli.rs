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

fn json_stdout(output: &Output) -> Value {
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

fn create(root: &Path, session: &str) {
    let output = run(root, &["session", "create", "--id", session]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let artifact_root = ArtifactRoot::open(root, SessionLimits::default()).unwrap();
    let session_store = artifact_root
        .session(&SessionId::new(session.to_owned()).unwrap())
        .unwrap();
    let lock = session_store.try_lock().unwrap();
    let mut writer = session_store
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
    writer.write_all(&minimal_tricore_elf()).unwrap();
    session_store.commit_artifact(&lock, writer).unwrap();
}

fn minimal_tricore_elf() -> Vec<u8> {
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
    elf
}

fn prepare(root: &Path, session: &str, operation: &str) -> Value {
    let output = run(
        root,
        &["controller", "prepare", session, "--operation", operation],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    json_stdout(&output)
}

fn write_response(prepared: &Value, operation: &str, status: &str, code: &str) {
    let binding = prepared["result"]["binding_sha256"].as_str().unwrap();
    let path = prepared["result"]["response_handoff"]["path"]
        .as_str()
        .unwrap();
    fs::write(
        path,
        format!(
            "<FINISHED>\n<CONTENT>\nT32PERF_RESULT_BEGIN\n{{\"protocol\":\"t32perf/1\",\"operation\":\"{operation}\",\"status\":\"{status}\",\"code\":\"{code}\",\"binding_sha256\":\"{binding}\"}}\nT32PERF_RESULT_END\n"
        ),
    )
    .unwrap();
}

fn accept_capabilities(root: &Path, session: &str) {
    let prepared = prepare(root, session, "perf_get_capabilities");
    let binding = prepared["result"]["binding_sha256"].as_str().unwrap();
    let evidence = json!({
        "schema": "t32perf.controller-capabilities-evidence/v2",
        "operation": "perf_get_capabilities", "binding_sha256": binding,
        "trace32_release": "2026.02", "trace32_build": 190766,
        "architecture_package": "tricore", "target_identifier": "infineon-tc234l-core0",
        "probe_identifier": "powerdebug-pro:E17090031792:C23090376246",
        "license_features": ["TriCore"], "trace_routing": ["runtime-pc-access-via-debug-port"],
        "capture_modes": ["snooper-pc-realtime-stack"], "trace_sinks": ["host_snooper_buffer"],
        "covered_cores": [0], "timestamp_supported": true,
        "health_signals": ["sampling_buffer_full", "sampling_unexpected_stop", "elf_mismatch"],
        "initial_target_state": "halted"
    });
    let evidence_path = prepared["result"]["output_reservation"]["script_output_path"]
        .as_str()
        .unwrap();
    fs::write(evidence_path, serde_json::to_vec(&evidence).unwrap()).unwrap();
    write_response(
        &prepared,
        "perf_get_capabilities",
        "OK",
        "capabilities_exported",
    );
    let transaction = prepared["result"]["transaction_id"].as_str().unwrap();
    let accepted = run(root, &["controller", "accept", session, transaction]);
    assert_eq!(accepted.status.code(), Some(0), "{}", stderr(&accepted));
}

#[test]
fn capabilities_prefix_is_accepted_but_unprovisioned_firmware_blocks_configure_and_holds_lease() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("artifacts");
    create(&root, "controller-firmware-owner");
    create(&root, "controller-firmware-contender");
    accept_capabilities(&root, "controller-firmware-owner");

    let configure = run(
        &root,
        &[
            "controller",
            "prepare",
            "controller-firmware-owner",
            "--operation",
            "perf_configure",
        ],
    );
    assert_eq!(configure.status.code(), Some(1));
    let configure = json_stdout(&configure);
    assert_eq!(configure["error"]["code"], "OPERATIONAL_ERROR");
    assert!(
        configure["error"]["message"]
            .as_str()
            .unwrap()
            .contains("is not registered by a compiled target-adapter profile")
    );

    let owner = json_stdout(&run(
        &root,
        &["controller", "status", "controller-firmware-owner"],
    ));
    assert_eq!(owner["result"]["state"], "created");
    assert_eq!(owner["result"]["capture_phase"], "configure_required");
    assert!(owner["result"]["pending_operation"].is_null());
    let contender = run(
        &root,
        &[
            "controller",
            "prepare",
            "controller-firmware-contender",
            "--operation",
            "perf_get_capabilities",
        ],
    );
    assert_eq!(contender.status.code(), Some(1));
    assert_eq!(
        json_stdout(&contender)["error"]["code"],
        "CONTROLLER_ROOT_BUSY"
    );
}

#[test]
fn unsupported_response_is_persisted_and_idempotent() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("artifacts");
    create(&root, "controller-unsupported");
    let prepared = prepare(&root, "controller-unsupported", "perf_get_capabilities");
    assert_eq!(
        prepared["result"]["mcp"]["execute"]["tool"],
        "execute_practice_skill"
    );
    let transaction = prepared["result"]["transaction_id"].as_str().unwrap();
    write_response(
        &prepared,
        "perf_get_capabilities",
        "UNSUPPORTED_NEEDS_TRACE32",
        "hardware_adapter_required",
    );
    let accepted = run(
        &root,
        &[
            "controller",
            "accept",
            "controller-unsupported",
            transaction,
        ],
    );
    assert_eq!(accepted.status.code(), Some(20), "{}", stderr(&accepted));
    let accepted = json_stdout(&accepted);
    assert_eq!(accepted["error"]["code"], "UNSUPPORTED");
    let repeated = run(
        &root,
        &[
            "controller",
            "accept",
            "controller-unsupported",
            transaction,
        ],
    );
    assert_eq!(repeated.status.code(), Some(20));
    assert_eq!(
        json_stdout(&repeated)["error"]["details"]["response_artifact"]["sha256"],
        accepted["error"]["details"]["response_artifact"]["sha256"]
    );
}

#[test]
fn mismatched_response_binding_preserves_raw_response_and_holds_root_slot() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("artifacts");
    create(&root, "controller-mismatch");
    create(&root, "controller-waiting");
    let prepared = prepare(&root, "controller-mismatch", "perf_get_capabilities");
    let transaction = prepared["result"]["transaction_id"].as_str().unwrap();
    let path = prepared["result"]["response_handoff"]["path"]
        .as_str()
        .unwrap();
    fs::write(path, "<FINISHED>\n<CONTENT>\nT32PERF_RESULT_BEGIN\n{\"protocol\":\"t32perf/1\",\"operation\":\"perf_get_capabilities\",\"status\":\"OK\",\"code\":\"capabilities_exported\",\"binding_sha256\":\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"}\nT32PERF_RESULT_END\n").unwrap();
    let accepted = run(
        &root,
        &["controller", "accept", "controller-mismatch", transaction],
    );
    assert_eq!(accepted.status.code(), Some(1));
    let accepted = json_stdout(&accepted);
    assert_eq!(
        accepted["error"]["code"],
        "CONTROLLER_RESPONSE_BINDING_MISMATCH"
    );
    assert_eq!(
        accepted["error"]["details"]["raw_response_artifact"]["kind"],
        "controller_mcp_response"
    );
    let blocked = run(
        &root,
        &[
            "controller",
            "prepare",
            "controller-waiting",
            "--operation",
            "perf_get_capabilities",
        ],
    );
    assert_eq!(
        json_stdout(&blocked)["error"]["code"],
        "CONTROLLER_ROOT_BUSY"
    );
}

#[test]
fn pending_transaction_blocks_mutation_until_abort_is_confirmed() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("artifacts");
    create(&root, "controller-pending");
    let prepared = prepare(&root, "controller-pending", "perf_get_capabilities");
    let transaction = prepared["result"]["transaction_id"].as_str().unwrap();
    fs::write(
        root.join("controller-pending/capture/staging/raw.bin"),
        b"raw",
    )
    .unwrap();
    let ingest = run(
        &root,
        &[
            "session",
            "ingest",
            "controller-pending",
            "--staged",
            "raw.bin",
            "--id",
            "raw",
            "--kind",
            "raw_trace",
            "--destination",
            "capture/raw/raw.bin",
            "--media-type",
            "application/octet-stream",
        ],
    );
    assert_eq!(
        json_stdout(&ingest)["error"]["code"],
        "CONTROLLER_TRANSACTION_PENDING"
    );
    let abort = run(
        &root,
        &[
            "controller",
            "abort",
            "controller-pending",
            transaction,
            "--reason",
            "operator_request",
        ],
    );
    assert_eq!(abort.status.code(), Some(0));
    let confirmed = run(
        &root,
        &[
            "controller",
            "confirm-abort",
            "controller-pending",
            transaction,
            "--acknowledge-unbound-success",
        ],
    );
    assert_eq!(confirmed.status.code(), Some(0), "{}", stderr(&confirmed));
}

#[test]
fn public_performance_surface_rejects_deployment_fault_scenarios() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("artifacts");
    let session = "controller-public-fault";
    create(&root, session);
    let store = ArtifactRoot::open(&root, SessionLimits::default())
        .unwrap()
        .session(&SessionId::new(session.to_owned()).unwrap())
        .unwrap();
    let lock = store.try_lock().unwrap();
    let mut writer = store
        .create_artifact(
            &lock,
            ArtifactSpec {
                id: "target-adapter-scenario".to_owned(),
                kind: "target_adapter_scenario".to_owned(),
                relative_path: ArtifactPath::new("capture/deployment/target-adapter-scenario.json")
                    .unwrap(),
                media_type: "application/json".to_owned(),
                producer: "t32perf-deployment-scenario/v1".to_owned(),
                input_artifact_ids: vec!["firmware-elf".to_owned()],
            },
        )
        .unwrap();
    writer.write_all(br#"{"schema":"t32perf.target-adapter-scenario/v1","scenario":"cmm_abort","evidence_only":true}"#).unwrap();
    store.commit_artifact(&lock, writer).unwrap();
    let output = run(&root, &["perf_capabilities", session]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        json_stdout(&output)["error"]["code"],
        "PERF_SURFACE_FAULT_SCENARIO_FORBIDDEN"
    );
}

#[test]
fn generic_ingest_cannot_forge_controller_artifacts() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("artifacts");
    create(&root, "controller-reserved");
    fs::write(
        root.join("controller-reserved/capture/staging/fake.json"),
        b"{}\n",
    )
    .unwrap();
    let ingested = run(
        &root,
        &[
            "session",
            "ingest",
            "controller-reserved",
            "--staged",
            "fake.json",
            "--id",
            "controller-request-fake",
            "--kind",
            "raw_trace",
            "--destination",
            "capture/raw/fake.json",
            "--media-type",
            "application/json",
        ],
    );
    assert_eq!(ingested.status.code(), Some(1));
    assert!(
        json_stdout(&ingested)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("reserved")
    );
}
