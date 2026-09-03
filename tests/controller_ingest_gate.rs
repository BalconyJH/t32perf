use std::{fs, io::Write as _, path::Path, process::Output};

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;
use t32perf_model::ArtifactPath;
use t32perf_session::{ArtifactRoot, ArtifactSpec, SessionId, SessionLimits};
use t32perf_trace32::{ControllerTargetState, tc234l_snooper_capture_config};
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
}

fn register_portable_controller_firmware(root: &Path, session: &str) {
    let artifact_root = ArtifactRoot::open(root, SessionLimits::default()).unwrap();
    let store = artifact_root
        .session(&SessionId::new(session).unwrap())
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
    writer.write_all(&minimal_tricore_elf()).unwrap();
    store.commit_artifact(&lock, writer).unwrap();
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
    elf[96] = 0x5a;
    elf
}

fn ingest_raw(root: &Path, session: &str) -> Output {
    fs::write(root.join(session).join("capture/staging/raw.bin"), b"raw").unwrap();
    run(
        root,
        &[
            "session",
            "ingest",
            session,
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
    )
}

fn write_response(prepared: &Value, operation: &str, code: &str) {
    let binding = prepared["result"]["binding_sha256"]
        .as_str()
        .expect("binding");
    let path = prepared["result"]["response_handoff"]["path"]
        .as_str()
        .expect("response handoff path");
    fs::write(
        path,
        format!(
            "<FINISHED>\n<CONTENT>\nT32PERF_RESULT_BEGIN\n{{\"protocol\":\"t32perf/1\",\"operation\":\"{operation}\",\"status\":\"OK\",\"code\":\"{code}\",\"binding_sha256\":\"{binding}\"}}\nT32PERF_RESULT_END\n"
        ),
    )
    .expect("write controller response");
}

fn write_capabilities_evidence(prepared: &Value) {
    write_evidence(
        prepared,
        serde_json::json!({
            "schema": "t32perf.controller-capabilities-evidence/v2",
            "operation": "perf_get_capabilities",
            "binding_sha256": prepared["result"]["binding_sha256"],
            "trace32_release": "2026.02",
            "trace32_build": 190766,
            "architecture_package": "tricore",
            "target_identifier": "infineon-tc234l-core0",
            "probe_identifier": "powerdebug-pro:E17090031792:C23090376246",
            "license_features": ["TriCore"],
            "trace_routing": ["runtime-pc-access-via-debug-port"],
            "capture_modes": ["snooper-pc-realtime-stack"],
            "trace_sinks": ["host_snooper_buffer"],
            "covered_cores": [0],
            "timestamp_supported": true,
            "health_signals": [
                "sampling_buffer_full",
                "sampling_unexpected_stop",
                "elf_mismatch"
            ],
            "initial_target_state": "halted"
        }),
    );
}

fn write_evidence(prepared: &Value, evidence: Value) {
    let path = prepared["result"]["output_reservation"]["script_output_path"]
        .as_str()
        .expect("evidence path");
    fs::write(path, serde_json::to_vec_pretty(&evidence).unwrap()).expect("write evidence");
}

#[test]
fn trace32_ascii_normalize_requires_a_completed_runtime_binding_before_mapping() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("artifacts");
    let session_id = "trace32-normalize-candidate";
    create(&root, session_id);
    let ingested = ingest_raw(&root, session_id);
    assert_eq!(ingested.status.code(), Some(0), "{}", stderr(&ingested));

    let artifact_root = ArtifactRoot::open(&root, SessionLimits::default()).unwrap();
    let session = artifact_root
        .session(&SessionId::new(session_id).unwrap())
        .unwrap();
    let raw = session
        .registered_artifacts(true)
        .unwrap()
        .into_iter()
        .find(|artifact| artifact.id == "raw")
        .expect("generic raw input");
    let lock = session.try_lock().unwrap();
    session
        .write_json_artifact(
            &lock,
            ArtifactSpec {
                id: "capture-config".to_owned(),
                kind: "capture_config".to_owned(),
                relative_path: ArtifactPath::new("capture/capture-config.json").unwrap(),
                media_type: "application/json".to_owned(),
                producer: "test.capture-config/v1".to_owned(),
                input_artifact_ids: Vec::new(),
            },
            &tc234l_snooper_capture_config(session_id, ControllerTargetState::Halted, 65_536),
        )
        .unwrap();
    session
        .write_json_artifact(
            &lock,
            ArtifactSpec {
                id: "normalize-config".to_owned(),
                kind: "normalization_config".to_owned(),
                relative_path: ArtifactPath::new("capture/normalize-config.json").unwrap(),
                media_type: "application/json".to_owned(),
                producer: "test.normalize-config/v1".to_owned(),
                input_artifact_ids: Vec::new(),
            },
            &serde_json::json!({
                "schema": "t32perf.normalize-config/v1",
                "mode": "single_source",
                "source": {
                    "adapter": "trace32_snooper_ascii_v1",
                    "source_id": "tc234l-snooper",
                    "expected_profile_id": "t32perf.trace32-ascii-profile/tc234l-build190766-v1",
                    "firmware_elf_artifact_id": "firmware-elf",
                    "limits": {"max_line_bytes": 4096, "max_records": 100}
                },
                "output_limits": {"max_line_bytes": 4096, "max_records": 100}
            }),
        )
        .unwrap();
    drop(lock);

    let normalized = run(
        &root,
        &[
            "normalize",
            session_id,
            "--input-artifact",
            &raw.id,
            "--config-artifact",
            "normalize-config",
        ],
    );
    assert_eq!(
        normalized.status.code(),
        Some(20),
        "{}",
        stderr(&normalized)
    );
    let error = json_stdout(&normalized);
    assert_eq!(error["error"]["code"], "UNSUPPORTED");
    assert_eq!(
        error["error"]["details"]["feature"],
        "normalize.trace32.runtime_binding"
    );
    assert!(
        !root
            .join(session_id)
            .join("normalized/trace32-symbol-mapping.json")
            .exists()
    );
}

#[test]
fn controller_artifacts_require_a_completed_capture_chain_before_ingest() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("artifacts");
    let session = "controller-ingest-gate";
    create(&root, session);
    register_portable_controller_firmware(&root, session);

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
    let prepared = json_stdout(&prepared);
    let transaction = prepared["result"]["transaction_id"]
        .as_str()
        .unwrap()
        .to_owned();
    write_capabilities_evidence(&prepared);
    write_response(&prepared, "perf_get_capabilities", "capabilities_exported");
    let accepted = run(&root, &["controller", "accept", session, &transaction]);
    assert_eq!(accepted.status.code(), Some(0), "{}", stderr(&accepted));

    let blocked = ingest_raw(&root, session);
    assert_eq!(blocked.status.code(), Some(1), "{}", stderr(&blocked));
    let blocked = json_stdout(&blocked);
    assert_eq!(blocked["error"]["code"], "CONTROLLER_CAPTURE_LEASE_ACTIVE");
    assert_eq!(
        blocked["error"]["details"]["capture_phase"],
        "configure_required"
    );
    assert_eq!(
        json_stdout(&run(&root, &["session", "status", session]))["result"]["state"]["state"],
        "created"
    );
}

#[test]
fn external_capture_ingest_remains_available_without_controller_artifacts() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("artifacts");
    let session = "external-ingest";
    create(&root, session);

    let ingested = ingest_raw(&root, session);
    assert_eq!(ingested.status.code(), Some(0), "{}", stderr(&ingested));
    assert_eq!(json_stdout(&ingested)["result"]["status"], "captured");
}

#[test]
fn generic_ingest_cannot_spoof_controller_driver_journal_claims() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("artifacts");
    let session = "controller-driver-journal-spoof";
    create(&root, session);

    let cases = [
        (
            "controller-driver-event-spoof",
            "generic_json",
            "capture/raw/spoof-id.json",
            "external-producer",
        ),
        (
            "generic-kind",
            "controller_driver_event",
            "capture/raw/spoof-kind.json",
            "external-producer",
        ),
        (
            "generic-path",
            "generic_json",
            "logs/controller/driver-events/spoof.json",
            "external-producer",
        ),
        (
            "generic-producer",
            "generic_json",
            "capture/raw/spoof-producer.json",
            "t32perf-controller-driver-journal/v1",
        ),
    ];
    for (index, (id, kind, destination, producer)) in cases.into_iter().enumerate() {
        let staged = format!("journal-spoof-{index}.json");
        fs::write(
            root.join(session).join("capture/staging").join(&staged),
            b"{}",
        )
        .unwrap();
        let output = run(
            &root,
            &[
                "session",
                "ingest",
                session,
                "--staged",
                &staged,
                "--id",
                id,
                "--kind",
                kind,
                "--destination",
                destination,
                "--media-type",
                "application/json",
                "--producer",
                producer,
            ],
        );
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        let error = json_stdout(&output);
        assert_eq!(error["error"]["code"], "OPERATIONAL_ERROR");
        assert!(
            error["error"]["message"]
                .as_str()
                .unwrap()
                .contains("controller artifact")
        );
    }
}

#[test]
fn provisioned_controller_session_rejects_generic_ingest_without_state_change() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("artifacts");
    let session = "controller-ingest-provisioned";
    create(&root, session);
    register_portable_controller_firmware(&root, session);

    let blocked = ingest_raw(&root, session);
    assert_eq!(blocked.status.code(), Some(1), "{}", stderr(&blocked));
    assert_eq!(
        json_stdout(&blocked)["error"]["code"],
        "CONTROLLER_CAPTURE_INCOMPLETE"
    );
    assert_eq!(
        json_stdout(&run(&root, &["session", "status", session]))["result"]["state"]["state"],
        "created"
    );
}
