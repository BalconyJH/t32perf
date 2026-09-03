use std::{collections::BTreeMap, io::Write as _, path::Path, process::Output};

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use t32perf_model::{
    AdapterInfo, ArtifactPath, CaptureCapabilities, CaptureConfigArtifactClaim,
    CaptureConfigDocument, CaptureConfigSchemaVersion, CaptureDurationConfig, CaptureReceipt,
    CaptureReceiptSchemaVersion, CaptureRtosAwarenessConfig, CaptureSinkConfig,
    CaptureTimestampConfig, CaptureTriggerConfig, ClockInfo, FirmwareInfo, InitialTargetState,
    MetricSupportEntry, MetricSupportLevel, Observation, ObservationDictionary, ObservationEvent,
    ObservationStreamHeader, Quality, SessionStatus, TargetInfo,
};
use t32perf_session::{ArtifactRoot, ArtifactSpec, SessionId, SessionLimits};
use t32perf_trace32::{LineLimits, NdjsonObservationWriter};
use tempfile::TempDir;

#[test]
fn malformed_header_completes_an_invalid_diagnostic_pipeline() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    create_corrupt_synthetic_session(&root, "malformed-header", b"{\"schema\":}\n");

    let analyzed = run(&root, &["analyze", "malformed-header"]);
    assert_eq!(analyzed.status.code(), Some(11), "{}", stderr(&analyzed));
    let analyzed = json_stdout(&analyzed);
    assert_eq!(analyzed["result"]["health_verdict"], "INVALID");
    assert_eq!(analyzed["result"]["diagnostics"]["observation_count"], 0);
    assert!(analyzed["result"].get("summary").is_none());
    assert!(
        analyzed["result"]["artifacts"]
            .as_array()
            .expect("analysis artifacts")
            .iter()
            .all(|artifact| !matches!(
                artifact["id"].as_str(),
                Some("hotspots" | "static-ram" | "stack-usage")
            ))
    );

    let health = read_json(&root.join("malformed-header/analysis/health.json"));
    let parser_fact = health["observations"]
        .as_array()
        .expect("health observations")
        .iter()
        .find(|observation| observation["code"] == "malformed_input")
        .expect("malformed parser fact");
    assert_eq!(parser_fact["artifact_id"], "observations");
    assert_eq!(parser_fact["record"], 0);
    assert_eq!(parser_fact["evidence"]["line"], 1);
    assert!(parser_fact["evidence"]["byte_offset"].is_u64());
    assert!(
        health["issues"]
            .as_array()
            .expect("health issues")
            .iter()
            .any(|issue| issue["code"] == "malformed_input" && issue["severity"] == "fatal")
    );
    assert_eq!(
        health["metric_support"]["function_timeline"]["support"],
        "unavailable"
    );
    let summary = read_json(&root.join("malformed-header/analysis/summary.json"));
    assert_eq!(summary["health_verdict"], "INVALID");
    assert!(summary.get("quantitative").is_none());
    assert!(
        !root
            .join("malformed-header/analysis/hotspots.json")
            .exists()
    );

    let converted = run(
        &root,
        &["convert", "malformed-header", "--format", "perfetto-json"],
    );
    assert_eq!(converted.status.code(), Some(11), "{}", stderr(&converted));
    let trace = read_json(&root.join("malformed-header/report/trace.json"));
    assert_eq!(trace["otherData"]["t32perf"]["diagnostic_only"], true);
    assert!(
        trace["traceEvents"]
            .as_array()
            .expect("trace events")
            .iter()
            .any(|event| event["name"] == "INVALID trace: diagnostic use only")
    );

    let validated = run(&root, &["validate", "malformed-header", "--deep"]);
    assert_eq!(validated.status.code(), Some(11), "{}", stderr(&validated));
    assert_eq!(json_stdout(&validated)["result"]["valid"], false);
    let status = run(&root, &["session", "status", "malformed-header"]);
    assert_eq!(json_stdout(&status)["result"]["state"]["state"], "complete");
}

#[test]
fn a_truncated_tail_retains_the_valid_prefix_and_converts_diagnostically() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    let mut bytes = canonical_instants("truncated-tail", &[(0, 10), (1, 20)]);
    assert_eq!(bytes.pop(), Some(b'\n'));
    create_corrupt_synthetic_session(&root, "truncated-tail", &bytes);

    let analyzed = run(&root, &["analyze", "truncated-tail"]);
    assert_eq!(analyzed.status.code(), Some(11), "{}", stderr(&analyzed));
    let analyzed = json_stdout(&analyzed);
    assert_eq!(analyzed["result"]["diagnostics"]["observation_count"], 1);
    let health = read_json(&root.join("truncated-tail/analysis/health.json"));
    let parser_fact = health["observations"]
        .as_array()
        .expect("health observations")
        .iter()
        .find(|observation| observation["code"] == "truncated_input")
        .expect("truncation parser fact");
    assert_eq!(parser_fact["record"], 2);
    assert_eq!(parser_fact["evidence"]["line"], 3);
    assert!(parser_fact["evidence"]["byte_offset"].is_u64());

    let converted = run(
        &root,
        &["convert", "truncated-tail", "--format", "perfetto-json"],
    );
    assert_eq!(converted.status.code(), Some(11), "{}", stderr(&converted));
    let trace = read_json(&root.join("truncated-tail/report/trace.json"));
    assert!(
        trace["traceEvents"]
            .as_array()
            .expect("trace events")
            .iter()
            .any(|event| event["name"] == "event-0")
    );
    let validated = run(&root, &["validate", "truncated-tail", "--deep"]);
    assert_eq!(validated.status.code(), Some(11), "{}", stderr(&validated));
}

#[test]
fn out_of_order_input_is_an_invalid_health_fact() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    let bytes = raw_canonical_records(
        "out-of-order",
        &[
            instant("source", 0, 10, "first"),
            instant("source", 0, 20, "duplicate-sequence"),
        ],
    );
    create_corrupt_synthetic_session(&root, "out-of-order", &bytes);

    let analyzed = run(&root, &["analyze", "out-of-order"]);
    assert_eq!(analyzed.status.code(), Some(11), "{}", stderr(&analyzed));
    let analyzed = json_stdout(&analyzed);
    assert_eq!(analyzed["result"]["diagnostics"]["observation_count"], 1);
    let health = read_json(&root.join("out-of-order/analysis/health.json"));
    let parser_fact = health["observations"]
        .as_array()
        .expect("health observations")
        .iter()
        .find(|observation| observation["code"] == "out_of_order_sequence")
        .expect("order parser fact");
    assert_eq!(parser_fact["record"], 2);
    assert_eq!(parser_fact["evidence"]["line"], 3);
    assert_eq!(
        parser_fact["evidence"]["parser_error_kind"],
        "source_sequence"
    );
    assert!(
        health["issues"]
            .as_array()
            .expect("health issues")
            .iter()
            .any(|issue| {
                issue["code"] == "out_of_order_sequence" && issue["severity"] == "fatal"
            })
    );
    assert!(analyzed["result"].get("summary").is_none());
}

#[test]
fn unsupported_schema_remains_a_terminal_unsupported_error() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    let bytes = b"{\"schema\":\"t32perf.observation/v2\",\"session_id\":\"unsupported-schema\",\"encoding\":\"ndjson\",\"time_unit\":\"ns\",\"time_origin\":\"session_relative\"}\n";
    create_corrupt_synthetic_session(&root, "unsupported-schema", bytes);

    let analyzed = run(&root, &["analyze", "unsupported-schema"]);
    assert_eq!(analyzed.status.code(), Some(20), "{}", stderr(&analyzed));
    let error = json_stdout(&analyzed);
    assert_eq!(error["error"]["code"], "UNSUPPORTED");
    assert_eq!(error["error"]["details"]["feature"], "observations.schema");
    let status = run(&root, &["session", "status", "unsupported-schema"]);
    let status = json_stdout(&status);
    assert_eq!(status["result"]["state"]["state"], "failed");
    assert_eq!(status["result"]["state"]["error"]["code"], "ANALYZE_FAILED");
    assert!(!root.join("unsupported-schema/analysis/stage.json").exists());
}

#[test]
fn canonical_session_dictionary_observation_and_unknown_field_errors_are_diagnostic() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    let cases = [
        (
            "wrong-stream-session",
            json_records(&[serde_json::to_value(ObservationStreamHeader::ndjson(
                "another-session",
            ))
            .expect("header value")]),
            "session_mismatch",
        ),
        (
            "unknown-header-field",
            json_records(&[serde_json::json!({
                "schema": "t32perf.observation/v1",
                "session_id": "unknown-header-field",
                "encoding": "ndjson",
                "time_unit": "ns",
                "time_origin": "session_relative",
                "unexpected": true,
            })]),
            "unknown_field",
        ),
        (
            "invalid-dictionary",
            json_records(&[
                serde_json::to_value(ObservationStreamHeader::ndjson("invalid-dictionary"))
                    .expect("header value"),
                serde_json::json!({"type": "DefineFunction", "id": "", "name": "bad"}),
            ]),
            "invalid_dictionary",
        ),
        (
            "invalid-observation",
            json_records(&[
                serde_json::to_value(ObservationStreamHeader::ndjson("invalid-observation"))
                    .expect("header value"),
                serde_json::json!({
                    "source_id": "",
                    "source_seq": 0,
                    "quality": "exact",
                    "type": "Instant",
                    "ts_ns": 0,
                    "name": "bad",
                    "args": {},
                }),
            ]),
            "invalid_observation",
        ),
        (
            "late-dictionary",
            json_records(&[
                serde_json::to_value(ObservationStreamHeader::ndjson("late-dictionary"))
                    .expect("header value"),
                serde_json::to_value(instant("source", 0, 0, "prefix")).expect("observation value"),
                serde_json::json!({
                    "type": "DefineFunction",
                    "id": "late",
                    "name": "late",
                }),
            ]),
            "dictionary_after_observation",
        ),
    ];

    for (session_id, bytes, expected_kind) in cases {
        create_corrupt_synthetic_session(&root, session_id, &bytes);
        let analyzed = run(&root, &["analyze", session_id]);
        assert_eq!(
            analyzed.status.code(),
            Some(11),
            "case={session_id}: {}",
            stderr(&analyzed)
        );
        let health = read_json(&root.join(session_id).join("analysis/health.json"));
        assert!(
            health["observations"]
                .as_array()
                .expect("health observations")
                .iter()
                .any(|observation| {
                    observation["code"] == "malformed_input"
                        && observation["artifact_id"] == "observations"
                        && observation["evidence"]["parser_error_kind"] == expected_kind
                        && observation["evidence"]["line"].is_u64()
                        && observation["evidence"]["byte_offset"].is_u64()
                }),
            "case={session_id}"
        );
    }
}

fn create_corrupt_synthetic_session(root: &Path, id: &str, bytes: &[u8]) {
    let artifact_root =
        ArtifactRoot::open(root, SessionLimits::default()).expect("open artifact root");
    let session = artifact_root
        .create_session_with_id(
            SessionId::new(id).expect("session ID"),
            &serde_json::json!({"provider": "synthetic", "events": 1}),
        )
        .expect("create session");
    let lock = session.try_lock().expect("lock session");
    session
        .transition(&lock, SessionStatus::Capturing, None)
        .expect("start capture");
    let capture_config_document = synthetic_capture_config(id);
    let capture_config = session
        .write_json_artifact(
            &lock,
            ArtifactSpec {
                id: "capture-config".to_owned(),
                kind: "capture_config".to_owned(),
                relative_path: ArtifactPath::new("capture/capture-config.json")
                    .expect("capture config path"),
                media_type: "application/json".to_owned(),
                producer: "t32perf.fixture.synthetic/v1".to_owned(),
                input_artifact_ids: Vec::new(),
            },
            &capture_config_document,
        )
        .expect("write capture config");
    let mut writer = session
        .create_artifact(
            &lock,
            ArtifactSpec {
                id: "observations".to_owned(),
                kind: "observations".to_owned(),
                relative_path: ArtifactPath::new("normalized/observations.ndjson")
                    .expect("artifact path"),
                media_type: "application/x-ndjson".to_owned(),
                producer: "t32perf.fixture.synthetic/v1".to_owned(),
                input_artifact_ids: vec![capture_config.id.clone()],
            },
        )
        .expect("create observation artifact");
    writer.write_all(bytes).expect("write corrupt observations");
    let observations = session
        .commit_artifact(&lock, writer)
        .expect("commit corrupt observations with its matching digest");
    let receipt = synthetic_receipt(
        id,
        session.request_sha256().expect("request digest"),
        CaptureConfigArtifactClaim {
            artifact_id: capture_config.id.clone(),
            sha256: capture_config.sha256.clone(),
            configuration_sha256: capture_config_identity_digest(&capture_config_document),
        },
    );
    session
        .write_json_artifact(
            &lock,
            ArtifactSpec {
                id: "capture-receipt".to_owned(),
                kind: "capture_receipt".to_owned(),
                relative_path: ArtifactPath::new("capture/capture-receipt.json")
                    .expect("receipt path"),
                media_type: "application/json".to_owned(),
                producer: "t32perf.fixture.synthetic/v1".to_owned(),
                input_artifact_ids: vec![observations.id, capture_config.id],
            },
            &receipt,
        )
        .expect("write capture receipt");
    session
        .transition(&lock, SessionStatus::Captured, None)
        .expect("finish capture");
}

fn synthetic_receipt(
    session_id: &str,
    request_sha256: t32perf_model::Sha256Digest,
    capture_config: CaptureConfigArtifactClaim,
) -> CaptureReceipt {
    let exact = MetricSupportEntry::new(MetricSupportLevel::Exact);
    CaptureReceipt {
        schema: CaptureReceiptSchemaVersion,
        session_id: session_id.to_owned(),
        provider: "synthetic".to_owned(),
        mode: "synthetic".to_owned(),
        adapter: AdapterInfo {
            id: "synthetic-v1".to_owned(),
            version: "1".to_owned(),
        },
        target: Some(TargetInfo {
            architecture: Some("synthetic".to_owned()),
            device: Some("t32perf-fixture".to_owned()),
            board: None,
            core_count: Some(1),
            properties: BTreeMap::new(),
        }),
        trace32: None,
        firmware: FirmwareInfo {
            elf_path: None,
            elf_sha256: None,
            build_id: Some("synthetic-fixture-v1".to_owned()),
        },
        clocks: vec![ClockInfo {
            id: "session".to_owned(),
            frequency_hz: Some(1_000_000_000),
            source: Some("synthetic nanosecond clock".to_owned()),
            properties: BTreeMap::new(),
        }],
        covered_cores: vec![0],
        capabilities: CaptureCapabilities {
            function_events: exact.clone(),
            context_switches: exact.clone(),
            interrupt_events: exact.clone(),
            samples: MetricSupportEntry {
                support: MetricSupportLevel::Unavailable,
                reasons: vec!["synthetic provider does not emit PC samples".to_owned()],
            },
            custom_events: exact.clone(),
            counters: exact,
        },
        health_observations: Vec::new(),
        request_sha256,
        capture_config: Some(capture_config),
        controller_health: None,
        properties: BTreeMap::from([(
            "observation_artifact_id".to_owned(),
            serde_json::json!("observations"),
        )]),
    }
}

fn synthetic_capture_config(session_id: &str) -> CaptureConfigDocument {
    CaptureConfigDocument {
        schema: CaptureConfigSchemaVersion,
        session_id: session_id.to_owned(),
        provider: "synthetic".to_owned(),
        adapter: AdapterInfo {
            id: "synthetic-v1".to_owned(),
            version: "1".to_owned(),
        },
        mode: "synthetic".to_owned(),
        covered_cores: vec![0],
        sink: CaptureSinkConfig {
            kind: "synthetic_memory".to_owned(),
            id: "fixture-buffer".to_owned(),
            capacity_bytes: None,
            stream_destination_identity: None,
        },
        timestamp: CaptureTimestampConfig {
            enabled: true,
            clock_id: Some("session".to_owned()),
        },
        filters: Vec::new(),
        trigger: CaptureTriggerConfig {
            kind: "immediate".to_owned(),
            pre_trigger_ns: None,
            post_trigger_ns: None,
            condition_identity: None,
        },
        duration: CaptureDurationConfig {
            duration_ns: None,
            observation_limit: Some(1),
        },
        workload_identity: "t32perf.synthetic-fixture/v1".to_owned(),
        initial_target_state: InitialTargetState::Running,
        rtos_awareness: CaptureRtosAwarenessConfig {
            kind: "none".to_owned(),
            metadata_artifact_ids: Vec::new(),
        },
        instrumentation: None,
        adapter_parameters: BTreeMap::new(),
    }
}

fn capture_config_identity_digest(config: &CaptureConfigDocument) -> t32perf_model::Sha256Digest {
    let digest = Sha256::digest(
        config
            .configuration_identity_bytes()
            .expect("serialize capture config identity"),
    );
    t32perf_model::Sha256Digest::new(lower_hex(digest.as_ref()))
        .expect("capture config identity digest")
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn canonical_instants(session_id: &str, observations: &[(u64, i64)]) -> Vec<u8> {
    let dictionary = ObservationDictionary::new(session_id);
    let mut writer = NdjsonObservationWriter::new(
        Vec::new(),
        &ObservationStreamHeader::ndjson(session_id),
        &dictionary,
        LineLimits::default(),
    )
    .expect("open canonical writer");
    for (sequence, timestamp) in observations {
        writer
            .write_observation(&instant(
                "source",
                *sequence,
                *timestamp,
                &format!("event-{sequence}"),
            ))
            .expect("write canonical observation");
    }
    writer.finish().expect("finish canonical observations")
}

fn raw_canonical_records(session_id: &str, observations: &[Observation]) -> Vec<u8> {
    let mut bytes = Vec::new();
    append_record(&mut bytes, &ObservationStreamHeader::ndjson(session_id));
    for observation in observations {
        append_record(&mut bytes, observation);
    }
    bytes
}

fn json_records(records: &[Value]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for record in records {
        append_record(&mut bytes, record);
    }
    bytes
}

fn append_record(bytes: &mut Vec<u8>, value: &impl serde::Serialize) {
    value
        .serialize(&mut serde_json::Serializer::new(&mut *bytes))
        .expect("serialize canonical record");
    bytes.push(b'\n');
}

fn instant(source_id: &str, source_seq: u64, ts_ns: i64, name: &str) -> Observation {
    Observation::new(
        source_id,
        source_seq,
        Quality::Exact,
        ObservationEvent::Instant {
            ts_ns,
            core_id: Some(0),
            context_id: None,
            name: name.to_owned(),
            args: BTreeMap::new(),
        },
    )
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

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).expect("read JSON artifact"))
        .expect("valid JSON artifact")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
