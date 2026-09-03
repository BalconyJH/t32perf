use std::{io::Write as _, path::Path, process::Output};

use assert_cmd::Command;
use serde_json::Value;
use t32perf_model::ArtifactPath;
use t32perf_session::{ArtifactRoot, ArtifactSpec, SessionId, SessionLimits};
use tempfile::TempDir;

fn run(root: &Path, arguments: &[&str]) -> Output {
    let mut command = Command::cargo_bin("t32perf").unwrap();
    command
        .arg("--artifact-root")
        .arg(root)
        .arg("--json")
        .args(arguments)
        .output()
        .unwrap()
}

fn json_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout is not JSON: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn assert_success(output: &Output) -> Value {
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document = json_stdout(output);
    assert_eq!(document["ok"], true);
    document
}

fn create_complete(root: &Path, session_id: &str) {
    assert_success(&run(
        root,
        &[
            "capture",
            "--provider",
            "synthetic",
            "--id",
            session_id,
            "--events",
            "32",
        ],
    ));
    assert_success(&run(root, &["analyze", session_id]));
}

fn assert_surface<'a>(document: &'a Value, operation: &str) -> &'a serde_json::Map<String, Value> {
    assert_eq!(document["command"], operation);
    assert_eq!(document["result"]["schema"], "t32perf.perf-surface/v1");
    assert_eq!(document["result"]["operation"], operation);
    document["result"]["payload"]
        .as_object()
        .expect("surface payload")
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
    writer.write_all(&elf).unwrap();
    store.commit_artifact(&lock, writer).unwrap();
}

#[test]
fn exact_read_convert_and_compare_surfaces_reuse_bounded_host_operations() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("artifacts");
    create_complete(&root, "perf-baseline");
    create_complete(&root, "perf-candidate");

    let status = assert_success(&run(&root, &["perf_get_status", "perf-baseline"]));
    let status = assert_surface(&status, "perf_get_status");
    assert_eq!(status["session_id"], "perf-baseline");
    assert_eq!(status["state"]["state"], "processing");
    assert_eq!(status["health_verdict"], "VALID");

    let summary = assert_success(&run(
        &root,
        &["perf_get_summary", "perf-baseline", "--top", "3"],
    ));
    let summary = assert_surface(&summary, "perf_get_summary");
    assert_eq!(summary["session_id"], "perf-baseline");
    assert!(
        summary["quantitative"]["hotspots"]["functions"]
            .as_array()
            .unwrap()
            .len()
            <= 3
    );

    let artifacts = assert_success(&run(
        &root,
        &["perf_list_artifacts", "perf-baseline", "--limit", "2"],
    ));
    let artifacts = assert_surface(&artifacts, "perf_list_artifacts");
    assert_eq!(artifacts["limit"], 2);
    assert_eq!(artifacts["returned_count"], 2);
    assert_eq!(artifacts["truncated"], true);
    assert!(artifacts["next_after"].is_string());

    let converted = assert_success(&run(
        &root,
        &["perf_convert", "perf-baseline", "--format", "perfetto-json"],
    ));
    let converted = assert_surface(&converted, "perf_convert");
    assert_eq!(converted["session_id"], "perf-baseline");
    assert_eq!(converted["artifact"]["kind"], "perfetto");

    assert_success(&run(
        &root,
        &[
            "perf_convert",
            "perf-candidate",
            "--format",
            "perfetto-json",
        ],
    ));

    let comparison = assert_success(&run(
        &root,
        &[
            "perf_compare",
            "perf-baseline",
            "perf-candidate",
            "--policy",
            "default",
            "--top",
            "3",
        ],
    ));
    let comparison = assert_surface(&comparison, "perf_compare");
    assert_eq!(comparison["report"]["baseline_session_id"], "perf-baseline");
    assert_eq!(
        comparison["report"]["candidate_session_id"],
        "perf-candidate"
    );
    assert!(comparison["report_artifact"]["sha256"].is_string());
}

#[test]
fn capability_and_capture_surfaces_expose_one_durable_mcp_action_at_a_time() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("artifacts");
    assert_success(&run(
        &root,
        &[
            "session",
            "create",
            "--id",
            "perf-control",
            "--request",
            "{}",
        ],
    ));
    register_portable_controller_firmware(&root, "perf-control");

    let prepared = assert_success(&run(&root, &["perf_capabilities", "perf-control"]));
    let schema = t32perf_model::schema_documents()["perf-surface.schema.json"].clone();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(validator.is_valid(&prepared["result"]));
    let prepared = assert_surface(&prepared, "perf_capabilities");
    assert_eq!(prepared["capture_phase"], "capabilities_required");
    assert_eq!(prepared["next_action"]["kind"], "execute");
    assert_eq!(
        prepared["next_action"]["mcp"]["tool"],
        "execute_practice_skill"
    );
    assert_eq!(
        prepared["next_action"]["mcp"]["arguments"]["script_name"],
        "perf_get_capabilities.cmm"
    );
    assert!(prepared["transaction_id"].is_string());

    let pending = assert_success(&run(&root, &["perf_capabilities", "perf-control"]));
    let pending = assert_surface(&pending, "perf_capabilities");
    assert_eq!(pending["next_action"]["kind"], "collect");
    assert_eq!(
        pending["next_action"]["mcp"]["tool"],
        "collect_practice_skill_response"
    );
    assert_eq!(pending["pending_operation"], "perf_get_capabilities");

    let capture_pending = assert_success(&run(&root, &["perf_capture", "perf-control"]));
    let capture_pending = assert_surface(&capture_pending, "perf_capture");
    assert_eq!(capture_pending["next_action"]["kind"], "collect");

    let invalid_ack = run(
        &root,
        &["perf_capture", "perf-control", "--workload-complete"],
    );
    assert_eq!(invalid_ack.status.code(), Some(1));
    assert!(
        json_stdout(&invalid_ack)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("pending")
    );
}
