use std::{fs, path::Path, process::Output};

use assert_cmd::Command;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
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

fn document(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stderr)))
}

fn request() -> Value {
    json!({
        "schema": "t32perf.stack-capture-request/v1",
        "acknowledge_intrusive": true,
        "sample_period_ms": 10,
        "duration_ms": 100,
        "max_samples": 2,
        "max_frames": 4,
        "core_id": 0,
        "address_space": "P",
    })
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn prepare(root: &Path, session: &str) {
    let output = run(
        root,
        &[
            "stack",
            "prepare",
            session,
            "--capture-request",
            &request().to_string(),
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = document(&output);
    assert_eq!(
        result["result"]["stack_sampling_capture_arguments"]["acknowledge_intrusive"],
        true
    );
    assert!(
        result["result"]["stack_sampling_capture_arguments"]
            .get("deployed_firmware_elf_sha256")
            .is_none()
    );
}

fn seed_stack_export(root: &Path, session: &str) -> (String, Vec<Vec<u8>>) {
    let endpoint = "a".repeat(64);
    let raw = json!({
        "schema": "t32perf.stack-samples/v1", "session_id": session,
        "endpoint_fingerprint": endpoint, "endpoint_fingerprint_scheme": "t32perf.endpoint-fingerprint/v2",
        "trace32": "R.2026.02", "cpu": "CortexM0+", "core_id": 0, "address_space": "P",
        "method": "break_frame_walk", "intrusive": true, "frame_order": "leaf_to_root",
        "requested_duration_ms": 100, "observed_duration_ms": 100, "requested_sample_period_ms": 10,
        "max_samples": 2, "max_frames": 4, "attempted_samples": 2, "collected_samples": 2,
        "total_halt_cycle_duration_ns": 30, "target_state_before": {"powered":true,"running":true,"halted":false},
        "target_state_after": {"powered":true,"running":true,"halted":false}, "firmware":{"status":"unverified"},
        "cleanup_complete":true, "debugger_symbolization_source":"trace32_symbol_table", "debugger_symbolization_trust":"debugger_reported",
        "samples":[
          {"sample_index":1,"halt_cycle_duration_ns":10,"termination":"terminal_unverified","frames":[
             {"depth":0,"pc":4096,"function_name":"leaf<&>"},{"depth":1,"pc":8192,"function_name":"root"}]},
          {"sample_index":2,"halt_cycle_duration_ns":20,"termination":"terminal_unverified","frames":[
             {"depth":0,"pc":4096,"function_name":"leaf<&>"},{"depth":1,"pc":12288,"function_name":"other"}]}
        ]
    });
    let mut raw_bytes = serde_json::to_vec_pretty(&raw).unwrap();
    raw_bytes.push(b'\n');
    let name = format!("stack-samples-{session}-11111111111111111111111111111111.json");
    let staged = format!("capture/staging/{name}");
    fs::write(root.join(session).join(&staged), &raw_bytes).unwrap();
    let state: Value =
        serde_json::from_slice(&fs::read(root.join(session).join("state.json")).unwrap()).unwrap();
    let request_bytes = fs::read(root.join(session).join("request.json")).unwrap();
    let attempts = root.join(".t32perf-control/stack-capture-attempts");
    fs::create_dir_all(&attempts).unwrap();
    fs::write(
        attempts.join(format!("{session}.json")),
        serde_json::to_vec(&json!({
            "schema":"t32perf.stack-capture-attempt/v1",
            "session_id":session,
            "operation_id":state["operation_id"],
            "request_sha256":digest(&request_bytes),
            "endpoint_fingerprint":"a".repeat(64),
            "created_at":"2026-09-01T00:00:00Z"
        }))
        .unwrap(),
    )
    .unwrap();
    let tx = "123e4567-e89b-42d3-a456-426614174000";
    let events = [
        (
            "capture_intent",
            json!({"initial_running":true,"duration_ms":100,"sample_period_ms":10,"max_samples":2,"max_frames":4}),
        ),
        ("break_intent", json!({"sample_index":1})),
        ("break_observed", json!({"sample_index":1})),
        ("go_intent", json!({"sample_index":1})),
        ("go_observed", json!({"sample_index":1})),
        ("break_intent", json!({"sample_index":2})),
        ("break_observed", json!({"sample_index":2})),
        ("go_intent", json!({"sample_index":2})),
        ("go_observed", json!({"sample_index":2})),
        (
            "capture_observed",
            json!({"attempted_samples":2,"collected_samples":2}),
        ),
        ("cleanup_intent", json!({})),
        ("cleanup_observed", json!({})),
        ("export_intent", json!({})),
        (
            "export_observed",
            json!({"relative_path":staged,"sha256":digest(&raw_bytes),"size_bytes":raw_bytes.len()}),
        ),
    ];
    let directory = root.join(".t32perf-control/stack-driver-events");
    fs::create_dir_all(&directory).unwrap();
    let mut bytes = Vec::new();
    for (index, (event, details)) in events.into_iter().enumerate() {
        let sequence = index + 1;
        let mut event_bytes = serde_json::to_vec(&json!({
            "schema":"t32perf.stack-driver-event/v1", "transaction_id":tx,
            "endpoint_fingerprint":"a".repeat(64), "endpoint_fingerprint_scheme":"t32perf.endpoint-fingerprint/v2",
            "owner":"lauterbach-stack-sampling-mcp/v1", "event":event, "sequence":sequence,
            "observed_at":format!("2026-09-01T00:00:{sequence:02}Z"), "details":details,
        })).unwrap();
        event_bytes.push(b'\n');
        fs::write(
            directory.join(format!("{tx}-{sequence:08}.json")),
            &event_bytes,
        )
        .unwrap();
        bytes.push(event_bytes);
    }
    (staged, bytes)
}

fn append_completed_history(root: &Path, transaction_id: &str, samples: usize) {
    let directory = root.join(".t32perf-control/stack-driver-events");
    fs::create_dir_all(&directory).unwrap();
    let mut sequence = 1;
    let mut write = |event: &str, details: Value| {
        let bytes = serde_json::to_vec(&json!({
            "schema":"t32perf.stack-driver-event/v1", "transaction_id":transaction_id,
            "endpoint_fingerprint":"a".repeat(64), "endpoint_fingerprint_scheme":"t32perf.endpoint-fingerprint/v2",
            "owner":"lauterbach-stack-sampling-mcp/v1", "event":event, "sequence":sequence,
            "observed_at":format!("2026-09-01T00:{:02}:{:02}Z", sequence / 60, sequence % 60), "details":details,
        }))
        .unwrap();
        fs::write(
            directory.join(format!("{transaction_id}-{sequence:08}.json")),
            bytes,
        )
        .unwrap();
        sequence += 1;
    };
    write(
        "capture_intent",
        json!({"initial_running":true,"duration_ms":60000,"sample_period_ms":10,"max_samples":samples,"max_frames":1}),
    );
    for sample_index in 1..=samples {
        for event in ["break_intent", "break_observed", "go_intent", "go_observed"] {
            write(event, json!({"sample_index":sample_index}));
        }
    }
    write(
        "capture_observed",
        json!({"attempted_samples":samples,"collected_samples":samples}),
    );
    write("cleanup_intent", json!({}));
    write("cleanup_observed", json!({}));
    write("export_intent", json!({}));
    write(
        "export_observed",
        json!({
            "relative_path":format!("capture/staging/stack-samples-history-{transaction_id}.json"),
            "sha256":"b".repeat(64),
            "size_bytes":1,
        }),
    );
}

#[test]
fn ingest_binds_exact_journal_then_derives_and_renders_real_stack_flamegraph() {
    let temporary = TempDir::new().unwrap();
    let session = "stack-e2e";
    prepare(temporary.path(), session);
    let (staged, journal) = seed_stack_export(temporary.path(), session);
    let ingest = run(
        temporary.path(),
        &["stack", "ingest", session, "--staged", &staged],
    );
    assert!(
        ingest.status.success(),
        "{}",
        String::from_utf8_lossy(&ingest.stdout)
    );
    let receipt: Value = serde_json::from_slice(
        &fs::read(
            temporary
                .path()
                .join(session)
                .join("capture/sampling/stack-capture-receipt.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let mut hasher = Sha256::new();
    hasher.update(b"t32perf.stack-driver-journal-chain/v1\0");
    for event in journal {
        hasher.update((event.len() as u64).to_be_bytes());
        hasher.update(event);
    }
    let expected_chain = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(receipt["journal_chain_sha256"], expected_chain);
    let analyze = run(
        temporary.path(),
        &[
            "stack",
            "analyze",
            session,
            "--stack-samples-artifact",
            "sampling-stack-samples",
        ],
    );
    assert!(analyze.status.success());
    let summary = run(
        temporary.path(),
        &["stack", "summary", session, "--top", "1"],
    );
    let value = document(&summary);
    assert_eq!(
        value["result"]["sample_measure"],
        "halt_cycles_not_cpu_time"
    );
    assert_eq!(value["result"]["rows"].as_array().unwrap().len(), 1);
    let first = run(
        temporary.path(),
        &["stack", "render", session, "--max-depth", "2"],
    );
    assert!(first.status.success());
    let svg = fs::read(
        temporary
            .path()
            .join(session)
            .join("report/sampling-flamegraph-depth002.svg"),
    )
    .unwrap();
    assert!(String::from_utf8_lossy(&svg).contains("leaf&lt;&amp;&gt;"));
    assert!(String::from_utf8_lossy(&svg).contains("not CPU time"));
    let second = run(
        temporary.path(),
        &["stack", "render", session, "--max-depth", "2"],
    );
    assert!(second.status.success());
    assert_eq!(
        svg,
        fs::read(
            temporary
                .path()
                .join(session)
                .join("report/sampling-flamegraph-depth002.svg")
        )
        .unwrap()
    );
    let inspection = run(
        temporary.path(),
        &["maintenance", "inspect", session, "--deep"],
    );
    assert!(
        inspection.status.success(),
        "{}",
        String::from_utf8_lossy(&inspection.stderr)
    );
    assert_eq!(
        document(&inspection)["result"]["unregistered_files_total"],
        0
    );
}

#[test]
fn ingest_rejects_unmatched_or_tampered_stack_evidence() {
    let temporary = TempDir::new().unwrap();
    let session = "stack-tamper";
    prepare(temporary.path(), session);
    let (staged, _) = seed_stack_export(temporary.path(), session);
    let journal = temporary
        .path()
        .join(".t32perf-control/stack-driver-events");
    fs::write(
        journal.join("123e4567-e89b-42d3-a456-426614174000-00000015.json"),
        serde_json::to_vec(&json!({
            "schema":"t32perf.stack-driver-event/v1", "transaction_id":"123e4567-e89b-42d3-a456-426614174000",
            "endpoint_fingerprint":"a".repeat(64), "endpoint_fingerprint_scheme":"t32perf.endpoint-fingerprint/v2",
            "owner":"lauterbach-stack-sampling-mcp/v1", "event":"break_intent", "sequence":15,
            "observed_at":"2026-09-01T00:00:15Z", "details":{"sample_index":1},
        }))
        .unwrap(),
    )
    .unwrap();
    let rejected = run(
        temporary.path(),
        &["stack", "ingest", session, "--staged", &staged],
    );
    assert!(!rejected.status.success());
    let error = document(&rejected);
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("trailing"),
        "{error}"
    );
}

#[test]
fn ingest_rejects_journal_parameters_that_differ_from_the_session_request() {
    let temporary = TempDir::new().unwrap();
    let session = "stack-request-mismatch";
    prepare(temporary.path(), session);
    let (staged, _) = seed_stack_export(temporary.path(), session);
    let event = temporary
        .path()
        .join(".t32perf-control/stack-driver-events")
        .join("123e4567-e89b-42d3-a456-426614174000-00000001.json");
    let mut journal_event: Value = serde_json::from_slice(&fs::read(&event).unwrap()).unwrap();
    journal_event["details"]["duration_ms"] = json!(101);
    fs::write(&event, serde_json::to_vec(&journal_event).unwrap()).unwrap();

    let rejected = run(
        temporary.path(),
        &["stack", "ingest", session, "--staged", &staged],
    );
    assert!(!rejected.status.success());
    assert!(
        document(&rejected)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("does not exactly bind")
    );
}

#[test]
fn ingest_rejects_journal_attempts_that_differ_from_raw_accounting() {
    let temporary = TempDir::new().unwrap();
    let session = "stack-attempt-mismatch";
    prepare(temporary.path(), session);
    let (staged, _) = seed_stack_export(temporary.path(), session);
    let staged_path = temporary.path().join(session).join(&staged);
    let mut raw: Value = serde_json::from_slice(&fs::read(&staged_path).unwrap()).unwrap();
    raw["attempted_samples"] = json!(1);
    raw["collected_samples"] = json!(1);
    raw["total_halt_cycle_duration_ns"] = json!(10);
    raw["samples"].as_array_mut().unwrap().truncate(1);
    let mut raw_bytes = serde_json::to_vec_pretty(&raw).unwrap();
    raw_bytes.push(b'\n');
    fs::write(&staged_path, &raw_bytes).unwrap();

    let directory = temporary
        .path()
        .join(".t32perf-control/stack-driver-events");
    let capture_path = directory.join("123e4567-e89b-42d3-a456-426614174000-00000010.json");
    let mut capture: Value = serde_json::from_slice(&fs::read(&capture_path).unwrap()).unwrap();
    capture["details"]["collected_samples"] = json!(1);
    fs::write(&capture_path, serde_json::to_vec(&capture).unwrap()).unwrap();
    let export_path = directory.join("123e4567-e89b-42d3-a456-426614174000-00000014.json");
    let mut export: Value = serde_json::from_slice(&fs::read(&export_path).unwrap()).unwrap();
    export["details"]["sha256"] = json!(digest(&raw_bytes));
    export["details"]["size_bytes"] = json!(raw_bytes.len());
    fs::write(&export_path, serde_json::to_vec(&export).unwrap()).unwrap();

    let rejected = run(
        temporary.path(),
        &["stack", "ingest", session, "--staged", &staged],
    );
    assert!(!rejected.status.success());
    assert!(
        document(&rejected)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("does not exactly bind")
    );
}

#[test]
fn ingest_rejects_a_capture_attempt_marker_with_the_wrong_request() {
    let temporary = TempDir::new().unwrap();
    let session = "stack-attempt-binding";
    prepare(temporary.path(), session);
    let (staged, _) = seed_stack_export(temporary.path(), session);
    let marker = temporary
        .path()
        .join(".t32perf-control/stack-capture-attempts")
        .join(format!("{session}.json"));
    let mut attempt: Value = serde_json::from_slice(&fs::read(&marker).unwrap()).unwrap();
    attempt["request_sha256"] = json!("b".repeat(64));
    fs::write(&marker, serde_json::to_vec(&attempt).unwrap()).unwrap();

    let rejected = run(
        temporary.path(),
        &["stack", "ingest", session, "--staged", &staged],
    );
    assert!(!rejected.status.success());
    assert!(
        document(&rejected)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("capture-attempt marker")
    );
}

#[test]
fn ingest_accepts_a_new_transaction_after_multiple_maximum_size_histories() {
    let temporary = TempDir::new().unwrap();
    append_completed_history(
        temporary.path(),
        "123e4567-e89b-42d3-a456-426614174001",
        512,
    );
    append_completed_history(
        temporary.path(),
        "123e4567-e89b-42d3-a456-426614174002",
        512,
    );
    let session = "stack-shared-history";
    prepare(temporary.path(), session);
    let (staged, _) = seed_stack_export(temporary.path(), session);
    let output = run(
        temporary.path(),
        &["stack", "ingest", session, "--staged", &staged],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn ordinary_ingest_cannot_claim_stack_reserved_envelope() {
    let temporary = TempDir::new().unwrap();
    let create = run(temporary.path(), &["session", "create", "--id", "ordinary"]);
    assert!(create.status.success());
    let session = temporary.path().join("ordinary");
    fs::create_dir_all(session.join("capture/staging")).unwrap();
    fs::write(session.join("capture/staging/input.json"), b"{}\n").unwrap();
    let output = run(
        temporary.path(),
        &[
            "session",
            "ingest",
            "ordinary",
            "--staged",
            "capture/staging/input.json",
            "--id",
            "sampling-stack-samples",
            "--kind",
            "stack_samples",
            "--destination",
            "capture/sampling/stack-samples.json",
            "--media-type",
            "application/json",
            "--producer",
            "lauterbach-stack-sampling-mcp/v1",
        ],
    );
    assert!(!output.status.success());
    assert!(
        document(&output)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("reserved")
    );
}
