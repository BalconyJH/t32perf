use std::{fs, path::Path, process::Output};

use assert_cmd::Command;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use t32perf_model::{
    DebuggerHotspotLocation, DebuggerSymbolization, DebuggerSymbolizationSource,
    DebuggerSymbolizationTrust, FirmwareBinding, FirmwareBindingStatus, PcHitBucket,
    PcHitHistogram, PcHitHistogramSchemaVersion, PcSamplingMethod, Sha256Digest,
    TargetExecutionState,
};
use t32perf_session::{ArtifactRoot, SessionId, SessionLimits};
use tempfile::TempDir;

const ARM_THUMB_EXECUTABLE: &[u8] =
    include_bytes!("../crates/t32perf-trace32/tests/fixtures/elf/arm-thumb-et-exec.elf");

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

fn seed_sidecar_export(root: &Path, session_id: &str, hits: u64, failures: u64) -> String {
    seed_sidecar_export_for_cpu(root, session_id, hits, failures, "CortexM0+")
}

fn seed_sidecar_export_for_cpu(
    root: &Path,
    session_id: &str,
    hits: u64,
    failures: u64,
    cpu: &str,
) -> String {
    seed_sidecar_export_with_symbolization(root, session_id, hits, failures, cpu, None)
}

fn seed_sidecar_export_with_symbolization(
    root: &Path,
    session_id: &str,
    hits: u64,
    failures: u64,
    cpu: &str,
    debugger_symbolization: Option<DebuggerSymbolization>,
) -> String {
    let artifact_root = ArtifactRoot::open(root, SessionLimits::default()).unwrap();
    let session_id_value = SessionId::new(session_id).unwrap();
    let request = match artifact_root.session(&session_id_value) {
        Ok(session) => session.request().unwrap(),
        Err(_) => {
            let request = sampling_request(0x1000, 0x1010, 0x10);
            artifact_root
                .create_session_with_id(session_id_value, &request)
                .unwrap();
            request
        }
    };
    let start_address = request["ranges"][0]["start_address"].as_u64().unwrap();
    let end_address = request["ranges"][0]["end_address"].as_u64().unwrap();
    let bucket_size = request["bucket_size"].as_u64().unwrap();
    let mut buckets = Vec::new();
    let mut cursor = start_address;
    while cursor < end_address {
        let end = cursor.saturating_add(bucket_size).min(end_address);
        buckets.push(PcHitBucket {
            start_address: cursor,
            end_address: end,
            hits: if cursor == start_address { hits } else { 0 },
        });
        cursor = end;
    }
    let histogram = PcHitHistogram {
        schema: PcHitHistogramSchemaVersion,
        session_id: session_id.to_owned(),
        endpoint_fingerprint: digest('a'),
        endpoint_fingerprint_scheme:
            t32perf_model::EndpointFingerprintScheme::T32PerfEndpointFingerprintV2,
        trace32: "R.2026.02".to_owned(),
        cpu: cpu.to_owned(),
        address_space: "P".to_owned(),
        core_id: 0,
        method: PcSamplingMethod::Realtime,
        intrusive: false,
        requested_duration_ns: 100_000_000,
        observed_duration_ns: 100_000_000,
        last_sample_rate_hz: 1000,
        snoop_failures: failures,
        target_state_before: TargetExecutionState {
            powered: true,
            running: true,
            halted: false,
        },
        target_state_after: TargetExecutionState {
            powered: true,
            running: true,
            halted: false,
        },
        firmware: FirmwareBinding {
            status: FirmwareBindingStatus::Unverified,
            elf_sha256: None,
            proof: None,
        },
        cleanup_complete: true,
        in_scope_hits: hits,
        buckets,
        debugger_symbolization,
    };
    let mut histogram_bytes = serde_json::to_vec(&histogram).unwrap();
    histogram_bytes.push(b'\n');
    let filename = format!("pc-hit-histogram-{session_id}-11111111111111111111111111111111.json");
    let session_relative = format!("capture/staging/{filename}");
    fs::write(
        root.join(session_id).join(&session_relative),
        &histogram_bytes,
    )
    .unwrap();

    let control = root.join(".t32perf-control");
    let events = control.join("sampling-driver-events");
    fs::create_dir_all(&events).unwrap();
    fs::write(
        control.join("sampling-endpoint-binding.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema": "t32perf.sampling-endpoint-binding/v1",
            "endpoint_fingerprint": digest('a'),
            "endpoint_fingerprint_scheme": "t32perf.endpoint-fingerprint/v2",
        }))
        .unwrap(),
    )
    .unwrap();
    let transaction_id = "123e4567-e89b-42d3-a456-426614174000";
    let histogram_sha256 = hex_digest(&histogram_bytes);
    let journal = [
        (
            "configure_intent",
            serde_json::json!({"method": "realtime"}),
        ),
        (
            "configure_observed",
            serde_json::json!({"method": "realtime"}),
        ),
        ("start_intent", serde_json::json!({"duration_ms": 100})),
        ("start_observed", serde_json::json!({})),
        ("stop_intent", serde_json::json!({})),
        ("stop_observed", serde_json::json!({})),
        ("cleanup_intent", serde_json::json!({})),
        ("cleanup_observed", serde_json::json!({})),
        ("export_intent", serde_json::json!({})),
        (
            "export_observed",
            serde_json::json!({
                "relative_path": session_relative,
                "sha256": histogram_sha256,
                "size_bytes": histogram_bytes.len(),
            }),
        ),
    ];
    for (index, (event, details)) in journal.into_iter().enumerate() {
        let sequence = index + 1;
        let mut bytes = serde_json::to_vec(&serde_json::json!({
            "schema": "t32perf.sampling-driver-event/v1",
            "transaction_id": transaction_id,
            "endpoint_fingerprint": digest('a'),
            "endpoint_fingerprint_scheme": "t32perf.endpoint-fingerprint/v2",
            "owner": "lauterbach-sampling-mcp/v1",
            "event": event,
            "sequence": sequence,
            "observed_at": format!("2026-08-29T00:00:{sequence:02}+00:00"),
            "details": details,
        }))
        .unwrap();
        bytes.push(b'\n');
        fs::write(
            events.join(format!("{transaction_id}-{sequence:08}.json")),
            bytes,
        )
        .unwrap();
    }
    session_relative
}

fn seed_symbolized_sidecar_export(root: &Path, session_id: &str) -> String {
    seed_sidecar_export_with_symbolization(
        root,
        session_id,
        100,
        0,
        "CortexM0+",
        Some(DebuggerSymbolization {
            source: DebuggerSymbolizationSource::Trace32SymbolTable,
            trust: DebuggerSymbolizationTrust::DebuggerReported,
            refinement_granularity_bytes: 4,
            locations: vec![DebuggerHotspotLocation {
                bucket_start_address: 0x1000,
                bucket_end_address: 0x1010,
                hits: 100,
                dominant_start_address: 0x1004,
                dominant_end_address: 0x1008,
                dominant_hits: 75,
                function_name: Some("hot<&>".to_owned()),
                source_file: Some("hot&loop.c".to_owned()),
                source_line: Some(42),
            }],
        }),
    )
}

fn digest(character: char) -> Sha256Digest {
    Sha256Digest::new(character.to_string().repeat(64)).unwrap()
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn ingest(root: &Path, session_id: &str, staged: &str) -> Output {
    run(
        root,
        &["sampling", "ingest", session_id, "--staged", staged],
    )
}

fn sampling_request(start: u64, end: u64, bucket_size: u64) -> Value {
    serde_json::json!({
        "schema": "t32perf.sampling-capture-request/v1",
        "ranges": [{"start_address": start, "end_address": end}],
        "bucket_size": bucket_size,
        "duration_ms": 100,
        "method_policy": "realtime_only",
        "core_id": 0,
        "address_space": "P",
    })
}

fn sampling_request_with_elf(start: u64, end: u64, bucket_size: u64) -> Value {
    let mut request = sampling_request(start, end, bucket_size);
    request["deployed_firmware_elf_sha256"] = Value::String(hex_digest(ARM_THUMB_EXECUTABLE));
    request
}

#[test]
fn prepare_issues_an_exact_one_session_capture_capability() {
    let temporary = TempDir::new().unwrap();
    let request = sampling_request(0x1000, 0x1100, 0x20).to_string();
    let output = run(
        temporary.path(),
        &[
            "sampling",
            "prepare",
            "sampling-prepared",
            "--capture-request",
            &request,
        ],
    );
    assert_eq!(output.status.code(), Some(0));
    let result = document(&output);
    let operation_id = result["result"]["operation_id"].as_str().unwrap();
    assert_eq!(operation_id.len(), 32);
    assert!(
        operation_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert_eq!(
        result["result"]["sampling_capture_arguments"]["operation_id"],
        operation_id
    );
    assert_eq!(
        result["result"]["sampling_capture_arguments"]["ranges"][0]["end_address"],
        0x1100
    );
    assert_eq!(result["result"]["state"], "created");

    let replay = run(
        temporary.path(),
        &[
            "sampling",
            "prepare",
            "sampling-prepared",
            "--capture-request",
            &request,
        ],
    );
    assert_ne!(replay.status.code(), Some(0));
}

#[test]
fn address_diagnostic_is_immutable_and_renderable() {
    let temporary = TempDir::new().unwrap();
    let staged = seed_sidecar_export(temporary.path(), "sampling-address", 100, 0);
    let accepted = ingest(temporary.path(), "sampling-address", &staged);
    assert_eq!(
        accepted.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    assert_eq!(
        document(&accepted)["result"]["histogram_artifact"]["id"],
        "sampling-pc-hit-histogram"
    );
    let accepted_again = ingest(temporary.path(), "sampling-address", &staged);
    assert_eq!(accepted_again.status.code(), Some(0));
    let args = [
        "sampling",
        "analyze",
        "sampling-address",
        "--histogram-artifact",
        "sampling-pc-hit-histogram",
        "--projection",
        "address",
    ];
    let first = run(temporary.path(), &args);
    assert_eq!(
        first.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let result = document(&first);
    assert_eq!(
        result["result"]["artifact"]["id"],
        "sampling-heatmap-address"
    );
    assert_eq!(result["result"]["diagnostic_only"], true);
    let second = run(temporary.path(), &args);
    assert_eq!(second.status.code(), Some(0));
    let summary = run(
        temporary.path(),
        &[
            "sampling",
            "summary",
            "sampling-address",
            "--projection",
            "address",
            "--top",
            "1",
        ],
    );
    assert_eq!(summary.status.code(), Some(0));
    assert_eq!(document(&summary)["result"]["rows"][0]["hits"], 100);
    let render = run(
        temporary.path(),
        &[
            "sampling",
            "render",
            "sampling-address",
            "--projection",
            "address",
            "--max-rows",
            "1",
        ],
    );
    assert_eq!(
        render.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&render.stderr)
    );
    assert_eq!(
        document(&render)["result"]["artifact"]["path"],
        "report/sampling-heatmap-address-top001.svg"
    );
    let render_again = run(
        temporary.path(),
        &[
            "sampling",
            "render",
            "sampling-address",
            "--projection",
            "address",
            "--max-rows",
            "1",
        ],
    );
    assert_eq!(render_again.status.code(), Some(0));
    assert_eq!(
        document(&render_again)["result"]["artifact"]["sha256"],
        document(&render)["result"]["artifact"]["sha256"]
    );
    let second_render = run(
        temporary.path(),
        &[
            "sampling",
            "render",
            "sampling-address",
            "--projection",
            "address",
            "--max-rows",
            "2",
        ],
    );
    assert_eq!(second_render.status.code(), Some(0));
    assert_eq!(
        document(&second_render)["result"]["artifact"]["path"],
        "report/sampling-heatmap-address-top002.svg"
    );

    let flame = run(
        temporary.path(),
        &[
            "sampling",
            "flame",
            "sampling-address",
            "--projection",
            "address",
            "--max-frames",
            "1",
        ],
    );
    assert_eq!(
        flame.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&flame.stderr)
    );
    let flame_document = document(&flame);
    assert_eq!(
        flame_document["result"]["artifact"]["path"],
        "report/sampling-flat-profile-address-top001.svg"
    );
    assert_eq!(
        flame_document["result"]["profile_kind"],
        "flat_sampled_profile"
    );
    assert_eq!(flame_document["result"]["hierarchy"], "synthetic");
    assert_eq!(flame_document["result"]["call_stack_evidence"], false);
    let flame_again = run(
        temporary.path(),
        &[
            "sampling",
            "flame",
            "sampling-address",
            "--projection",
            "address",
            "--max-frames",
            "1",
        ],
    );
    assert_eq!(flame_again.status.code(), Some(0));
    assert_eq!(
        document(&flame_again)["result"]["artifact"]["sha256"],
        flame_document["result"]["artifact"]["sha256"]
    );
}

#[test]
fn debugger_reported_hot_code_is_automatically_labeled_in_address_svg() {
    let temporary = TempDir::new().unwrap();
    let session = "sampling-symbolized-address";
    let staged = seed_symbolized_sidecar_export(temporary.path(), session);
    let accepted = ingest(temporary.path(), session, &staged);
    assert_eq!(
        accepted.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );

    let analyzed = run(
        temporary.path(),
        &[
            "sampling",
            "analyze",
            session,
            "--histogram-artifact",
            "sampling-pc-hit-histogram",
            "--projection",
            "address",
        ],
    );
    assert_eq!(
        analyzed.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&analyzed.stderr)
    );
    let heatmap: Value = serde_json::from_slice(
        &fs::read(
            temporary
                .path()
                .join(session)
                .join("analysis/sampling-heatmap-address.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        heatmap["cells"][0]["debugger_location"]["function_name"],
        "hot<&>"
    );
    assert_eq!(
        heatmap["cells"][0]["debugger_location"]["dominant_hits"],
        75
    );

    let rendered = run(
        temporary.path(),
        &[
            "sampling",
            "render",
            session,
            "--projection",
            "address",
            "--max-rows",
            "1",
        ],
    );
    assert_eq!(
        rendered.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&rendered.stderr)
    );
    let svg = fs::read_to_string(
        temporary
            .path()
            .join(session)
            .join("report/sampling-heatmap-address-top001.svg"),
    )
    .unwrap();
    assert!(svg.contains(">0x00001000..0x00001010</text>"));
    assert!(svg.contains(">dominant 75/100 · hot&lt;&amp;&gt; · hot&amp;loop.c:42</text>"));
    assert!(
        svg.contains(
            "TRACE32 symbol-table labels: debugger-reported; labels do not verify firmware"
        )
    );
    assert!(svg.contains("Firmware status: unverified"));

    let flame = run(
        temporary.path(),
        &[
            "sampling",
            "flame",
            session,
            "--projection",
            "address",
            "--max-frames",
            "2",
        ],
    );
    assert_eq!(
        flame.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&flame.stderr)
    );
    let flame_svg = fs::read_to_string(
        temporary
            .path()
            .join(session)
            .join("report/sampling-flat-profile-address-top002.svg"),
    )
    .unwrap();
    assert!(flame_svg.contains("Flat sampled profile"));
    assert!(flame_svg.contains("synthetic hierarchy"));
    assert!(flame_svg.contains("no call-stack evidence"));
    assert!(flame_svg.contains("hot&lt;&amp;&gt;"));
    assert!(!flame_svg.contains("hot<&>"));
    assert!(flame_svg.contains("data-hits=\"75\""));
}

#[test]
fn function_projection_binds_an_immutable_request_digest_through_the_public_cli() {
    let temporary = TempDir::new().unwrap();
    let request = sampling_request_with_elf(0x100, 0x10c, 2).to_string();
    let prepared = run(
        temporary.path(),
        &[
            "sampling",
            "prepare",
            "sampling-function",
            "--capture-request",
            &request,
        ],
    );
    assert_eq!(prepared.status.code(), Some(0));
    // This represents the independently-produced sidecar histogram and journal.
    let staged = seed_sidecar_export(temporary.path(), "sampling-function", 100, 0);
    let ingested = ingest(temporary.path(), "sampling-function", &staged);
    assert_eq!(ingested.status.code(), Some(0));
    let staging = temporary
        .path()
        .join("sampling-function/capture/staging/firmware.elf");
    fs::create_dir_all(staging.parent().unwrap()).unwrap();
    fs::write(&staging, ARM_THUMB_EXECUTABLE).unwrap();
    let bound = run(
        temporary.path(),
        &[
            "sampling",
            "bind-firmware",
            "sampling-function",
            "--staged",
            "firmware.elf",
        ],
    );
    assert_eq!(
        bound.status.code(),
        Some(0),
        "stdout: {} stderr: {}",
        String::from_utf8_lossy(&bound.stdout),
        String::from_utf8_lossy(&bound.stderr)
    );
    assert_eq!(
        document(&bound)["result"]["proof_kind"],
        "precommitted_elf_assertion"
    );
    assert_eq!(document(&bound)["result"]["target_image_compared"], false);
    fs::remove_file(&staging).unwrap();
    let bound_again = run(
        temporary.path(),
        &[
            "sampling",
            "bind-firmware",
            "sampling-function",
            "--staged",
            "firmware.elf",
        ],
    );
    assert_eq!(bound_again.status.code(), Some(0));
    let original_histogram: Value = serde_json::from_slice(
        &fs::read(
            temporary
                .path()
                .join("sampling-function/capture/sampling/pc-hit-histogram.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(original_histogram["firmware"]["status"], "unverified");
    assert!(original_histogram["firmware"].get("elf_sha256").is_none());
    let analyze = run(
        temporary.path(),
        &[
            "sampling",
            "analyze",
            "sampling-function",
            "--histogram-artifact",
            "sampling-pc-hit-histogram",
            "--projection",
            "function",
            "--elf-artifact",
            "firmware-elf",
            "--firmware-evidence-artifact",
            "sampling-firmware-binding-evidence",
        ],
    );
    assert_eq!(
        analyze.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&analyze.stderr)
    );
    let summary = run(
        temporary.path(),
        &[
            "sampling",
            "summary",
            "sampling-function",
            "--projection",
            "function",
            "--top",
            "3",
        ],
    );
    assert_eq!(summary.status.code(), Some(0));
    let summary = document(&summary);
    assert_eq!(summary["result"]["rows"][0]["display_name"], "_start");
    assert_eq!(summary["result"]["rows"][0]["hits"], 100);
    assert_eq!(
        summary["result"]["firmware_binding"]["status"],
        "deployment_asserted"
    );
    assert_eq!(
        summary["result"]["firmware_binding"]["proof"]["kind"],
        "precommitted_elf_assertion"
    );
    assert_eq!(summary["result"]["target_image_compared"], false);

    let render = run(
        temporary.path(),
        &[
            "sampling",
            "render",
            "sampling-function",
            "--projection",
            "function",
        ],
    );
    assert_eq!(
        render.status.code(),
        Some(0),
        "stdout: {} stderr: {}",
        String::from_utf8_lossy(&render.stdout),
        String::from_utf8_lossy(&render.stderr)
    );

    let evidence = temporary
        .path()
        .join("sampling-function/capture/sampling/firmware-binding-evidence.json");
    let mut tampered = fs::read(&evidence).unwrap();
    tampered.push(b' ');
    fs::write(&evidence, tampered).unwrap();
    let replay = run(
        temporary.path(),
        &[
            "sampling",
            "summary",
            "sampling-function",
            "--projection",
            "function",
        ],
    );
    assert_ne!(replay.status.code(), Some(0));
}

#[test]
fn firmware_binding_rejects_an_elf_that_does_not_match_the_immutable_request() {
    let temporary = TempDir::new().unwrap();
    let mut request = sampling_request_with_elf(0x100, 0x10c, 2);
    request["deployed_firmware_elf_sha256"] = Value::String("b".repeat(64));
    let request = request.to_string();
    assert_eq!(
        run(
            temporary.path(),
            &[
                "sampling",
                "prepare",
                "sampling-mismatch",
                "--capture-request",
                &request,
            ],
        )
        .status
        .code(),
        Some(0)
    );
    let staged = seed_sidecar_export(temporary.path(), "sampling-mismatch", 100, 0);
    assert_eq!(
        ingest(temporary.path(), "sampling-mismatch", &staged)
            .status
            .code(),
        Some(0)
    );
    let staged_elf = temporary
        .path()
        .join("sampling-mismatch/capture/staging/firmware.elf");
    fs::write(staged_elf, ARM_THUMB_EXECUTABLE).unwrap();
    let rejected = run(
        temporary.path(),
        &[
            "sampling",
            "bind-firmware",
            "sampling-mismatch",
            "--staged",
            "firmware.elf",
        ],
    );
    assert_ne!(rejected.status.code(), Some(0));
    assert!(
        document(&rejected)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("digest does not match")
    );
}

#[test]
fn firmware_binding_requires_a_deployed_elf_digest_in_the_capture_request() {
    let temporary = TempDir::new().unwrap();
    let staged = seed_sidecar_export(temporary.path(), "sampling-no-elf-digest", 100, 0);
    assert_eq!(
        ingest(temporary.path(), "sampling-no-elf-digest", &staged)
            .status
            .code(),
        Some(0)
    );
    let staged_elf = temporary
        .path()
        .join("sampling-no-elf-digest/capture/staging/firmware.elf");
    fs::write(staged_elf, ARM_THUMB_EXECUTABLE).unwrap();
    let rejected = run(
        temporary.path(),
        &[
            "sampling",
            "bind-firmware",
            "sampling-no-elf-digest",
            "--staged",
            "firmware.elf",
        ],
    );
    assert_ne!(rejected.status.code(), Some(0));
    assert!(
        document(&rejected)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("requires deployed_firmware_elf_sha256")
    );
}

#[test]
fn firmware_binding_requires_a_cortex_m_capture_identity() {
    let temporary = TempDir::new().unwrap();
    let request = sampling_request_with_elf(0x100, 0x10c, 2).to_string();
    assert_eq!(
        run(
            temporary.path(),
            &[
                "sampling",
                "prepare",
                "sampling-wrong-cpu",
                "--capture-request",
                &request,
            ],
        )
        .status
        .code(),
        Some(0)
    );
    let staged = seed_sidecar_export_for_cpu(temporary.path(), "sampling-wrong-cpu", 100, 0, "x86");
    assert_eq!(
        ingest(temporary.path(), "sampling-wrong-cpu", &staged)
            .status
            .code(),
        Some(0)
    );
    fs::write(
        temporary
            .path()
            .join("sampling-wrong-cpu/capture/staging/firmware.elf"),
        ARM_THUMB_EXECUTABLE,
    )
    .unwrap();
    let rejected = run(
        temporary.path(),
        &[
            "sampling",
            "bind-firmware",
            "sampling-wrong-cpu",
            "--staged",
            "firmware.elf",
        ],
    );
    assert_ne!(rejected.status.code(), Some(0));
    assert!(
        document(&rejected)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Cortex-M CPU identity")
    );
}

#[test]
fn quantitative_gate_and_cli_bounds_reject_invalid_inputs() {
    let temporary = TempDir::new().unwrap();
    let staged = seed_sidecar_export(temporary.path(), "sampling-gate", 0, 0);
    let accepted = ingest(temporary.path(), "sampling-gate", &staged);
    assert_eq!(accepted.status.code(), Some(0));
    let output = run(
        temporary.path(),
        &[
            "sampling",
            "analyze",
            "sampling-gate",
            "--histogram-artifact",
            "sampling-pc-hit-histogram",
            "--projection",
            "address",
        ],
    );
    assert_ne!(output.status.code(), Some(0));
    assert!(
        document(&output)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("in_scope_hits")
    );
    let invalid = run(
        temporary.path(),
        &[
            "sampling",
            "summary",
            "sampling-gate",
            "--projection",
            "address",
            "--top",
            "101",
        ],
    );
    assert_ne!(invalid.status.code(), Some(0));
    assert_eq!(document(&invalid)["error"]["code"], "INVALID_ARGUMENT");
}

#[test]
fn typed_ingest_rejects_unbound_endpoint_without_advancing_session() {
    let temporary = TempDir::new().unwrap();
    let staged = seed_sidecar_export(temporary.path(), "sampling-binding", 100, 0);
    fs::write(
        temporary
            .path()
            .join(".t32perf-control/sampling-endpoint-binding.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema": "t32perf.sampling-endpoint-binding/v1",
            "endpoint_fingerprint": digest('b'),
            "endpoint_fingerprint_scheme": "t32perf.endpoint-fingerprint/v2",
        }))
        .unwrap(),
    )
    .unwrap();
    let output = ingest(temporary.path(), "sampling-binding", &staged);
    assert_ne!(output.status.code(), Some(0));
    assert_eq!(
        document(&output)["error"]["code"],
        "SAMPLING_ENDPOINT_QUARANTINED"
    );
    assert_eq!(
        document(&output)["error"]["details"]["reason"],
        "journal endpoint does not match the root binding"
    );
    let status = run(temporary.path(), &["session", "status", "sampling-binding"]);
    assert_eq!(status.status.code(), Some(0));
    assert_eq!(document(&status)["result"]["state"]["state"], "created");
}

#[test]
fn typed_ingest_rechecks_the_host_authorized_capture_request() {
    let temporary = TempDir::new().unwrap();
    let staged = seed_sidecar_export(temporary.path(), "sampling-request", 100, 0);
    let mut request_bytes =
        serde_json::to_vec_pretty(&sampling_request(0x1000, 0x1020, 0x10)).unwrap();
    request_bytes.push(b'\n');
    fs::write(
        temporary.path().join("sampling-request/request.json"),
        request_bytes,
    )
    .unwrap();
    let output = ingest(temporary.path(), "sampling-request", &staged);
    assert_ne!(output.status.code(), Some(0));
    assert!(
        document(&output)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("authorized ranges")
    );
}

#[test]
fn generic_ingest_cannot_claim_sampling_artifact_names_or_producers() {
    let temporary = TempDir::new().unwrap();
    let cases = [
        (
            "sampling-forged",
            "raw",
            "capture/raw/forged.bin",
            "external",
        ),
        (
            "forged",
            "pc_hit_histogram",
            "capture/raw/forged.bin",
            "external",
        ),
        ("forged", "heatmap", "capture/raw/forged.bin", "external"),
        (
            "forged",
            "sampling_capture_receipt",
            "capture/raw/forged.bin",
            "external",
        ),
        (
            "forged",
            "firmware_binding_evidence",
            "capture/raw/forged.bin",
            "external",
        ),
        ("forged", "raw", "analysis/sampling-forged.json", "external"),
        ("forged", "raw", "capture/sampling/forged.json", "external"),
        ("forged", "raw", "report/sampling-forged.svg", "external"),
        (
            "forged",
            "raw",
            "capture/raw/forged.bin",
            "t32perf-sampling-analysis/v1",
        ),
        (
            "forged",
            "raw",
            "capture/raw/forged.bin",
            "lauterbach-sampling-mcp/v1",
        ),
        (
            "forged",
            "raw",
            "capture/raw/forged.bin",
            "t32perf-sampling-capture-receipt/v1",
        ),
        (
            "forged",
            "raw",
            "capture/raw/forged.bin",
            "t32perf-sampling-firmware-elf/v1",
        ),
        (
            "forged",
            "raw",
            "capture/raw/forged.bin",
            "t32perf-sampling-firmware-evidence/v1",
        ),
    ];
    for (id, kind, destination, producer) in cases {
        let output = run(
            temporary.path(),
            &[
                "session",
                "ingest",
                "not-created",
                "--staged",
                "forged.bin",
                "--id",
                id,
                "--kind",
                kind,
                "--destination",
                destination,
                "--media-type",
                "application/octet-stream",
                "--producer",
                producer,
            ],
        );
        assert_ne!(output.status.code(), Some(0));
        assert!(
            document(&output)["error"]["message"]
                .as_str()
                .unwrap()
                .contains("typed sampling boundary")
        );
    }
}
