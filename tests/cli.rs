use std::{
    collections::BTreeMap,
    io::Write as _,
    path::Path,
    process::Output,
    sync::{Arc, Barrier},
    thread,
};

use assert_cmd::cargo::cargo_bin_cmd;
use ed25519_dalek::{Signer as _, SigningKey};
use object::{Architecture, BinaryFormat, Endianness, SectionKind, write::Object};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use t32perf_model::{
    AdapterInfo, ArtifactPath, CaptureAttestation, CaptureAttestationPayload,
    CaptureAttestationSchemaVersion, CaptureCapabilities, CaptureConfigArtifactClaim,
    CaptureConfigConstraints, CaptureConfigDocument, CaptureConfigSchemaVersion,
    CaptureDurationConfig, CaptureInstrumentationConfig, CaptureInstrumentationOverhead,
    CaptureReceipt, CaptureReceiptSchemaVersion, CaptureRtosAwarenessConfig, CaptureSinkConfig,
    CaptureTimestampConfig, CaptureTriggerConfig, CaptureTrustKey, CaptureTrustPolicy,
    CaptureTrustPolicySchemaVersion, ClockInfo, ContextKind, CounterSemantic, CounterSubject,
    DictionaryEntry, FirmwareInfo, HealthObservation, InitialTargetState, MetricSupportEntry,
    MetricSupportLevel, Observation, ObservationDictionary, ObservationEvent,
    ObservationStreamHeader, Quality, SessionStatus, Sha256Digest, TargetInfo, Trace32Info,
};
use t32perf_session::{ArtifactRoot, ArtifactSpec, SessionId, SessionLimits};
use t32perf_trace32::{LineLimits, NdjsonObservationWriter};
use tempfile::TempDir;

#[test]
fn json_session_create_list_and_status_are_single_objects() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");

    let created = run(&root, &["session", "create", "--id", "session-a"]);
    assert_eq!(created.status.code(), Some(0), "{}", stderr(&created));
    let created_json = json_stdout(&created);
    assert_eq!(created_json["command"], "session.create");
    assert_eq!(created_json["result"]["session_id"], "session-a");
    assert_eq!(created_json["result"]["status"], "created");

    let listed = run(&root, &["session", "list"]);
    assert_eq!(listed.status.code(), Some(0), "{}", stderr(&listed));
    let listed_json = json_stdout(&listed);
    assert_eq!(
        listed_json["result"]["sessions"][0]["session_id"],
        "session-a"
    );

    let status = run(&root, &["session", "status", "session-a"]);
    assert_eq!(status.status.code(), Some(0), "{}", stderr(&status));
    let status_json = json_stdout(&status);
    assert_eq!(status_json["result"]["state"]["state"], "created");
    assert_eq!(status_json["result"]["artifact_count"], 0);
}

#[test]
fn session_create_rejects_duplicate_request_members_recursively() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    let output = run(
        &root,
        &[
            "session",
            "create",
            "--id",
            "duplicate-request",
            "--request",
            r#"{"properties":{"mode":"first","mode":"last"}}"#,
        ],
    );

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let error = json_stdout(&output);
    assert_eq!(error["error"]["code"], "OPERATIONAL_ERROR");
    assert!(
        error["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("duplicate JSON object member name `mode`"))
    );
    assert!(!root.join("duplicate-request").exists());
}

#[test]
fn list_surfaces_are_bounded_and_cursor_paginated() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    let store = ArtifactRoot::open(&root, SessionLimits::default()).expect("artifact root");
    for index in 0..125 {
        store
            .create_session_with_id(
                SessionId::new(format!("page-session-{index:03}")).expect("session id"),
                &serde_json::json!({}),
            )
            .expect("create paginated session");
    }

    let first = run(&root, &["session", "list", "--limit", "25"]);
    assert_eq!(first.status.code(), Some(0), "{}", stderr(&first));
    assert!(first.stdout.len() < 64 * 1024);
    let first = json_stdout(&first);
    assert_eq!(first["result"]["total_count"], 125);
    assert_eq!(first["result"]["returned_count"], 25);
    assert_eq!(first["result"]["truncated"], true);
    assert_eq!(first["result"]["next_after"], "page-session-024");

    let second = run(
        &root,
        &[
            "session",
            "list",
            "--limit",
            "25",
            "--after",
            "page-session-024",
        ],
    );
    assert_eq!(second.status.code(), Some(0), "{}", stderr(&second));
    let second = json_stdout(&second);
    assert_eq!(
        second["result"]["sessions"][0]["session_id"],
        "page-session-025"
    );

    let artifact_session = store
        .session(&SessionId::new("page-session-000").expect("session id"))
        .expect("artifact session");
    let lock = artifact_session.try_lock().expect("session lock");
    for index in 0..125 {
        let mut writer = artifact_session
            .create_artifact(
                &lock,
                ArtifactSpec {
                    id: format!("page-artifact-{index:03}"),
                    kind: "test".to_owned(),
                    relative_path: ArtifactPath::new(format!("logs/page-{index:03}.bin"))
                        .expect("artifact path"),
                    media_type: "application/octet-stream".to_owned(),
                    producer: "pagination-test".to_owned(),
                    input_artifact_ids: Vec::new(),
                },
            )
            .expect("create artifact");
        writer.write_all(b"x").expect("write artifact");
        artifact_session
            .commit_artifact(&lock, writer)
            .expect("commit artifact");
    }
    let mut writer = artifact_session
        .create_artifact(
            &lock,
            ArtifactSpec {
                id: "page-with-many-inputs".to_owned(),
                kind: "test".to_owned(),
                relative_path: ArtifactPath::new("logs/page-with-many-inputs.bin")
                    .expect("artifact path"),
                media_type: "application/octet-stream".to_owned(),
                producer: "pagination-test".to_owned(),
                input_artifact_ids: (0..20)
                    .map(|index| format!("page-artifact-{index:03}"))
                    .collect(),
            },
        )
        .expect("create artifact with many inputs");
    writer.write_all(b"x").expect("write artifact");
    artifact_session
        .commit_artifact(&lock, writer)
        .expect("commit artifact with many inputs");
    drop(lock);

    let artifacts = run(
        &root,
        &["artifacts", "list", "page-session-000", "--limit", "25"],
    );
    assert_eq!(artifacts.status.code(), Some(0), "{}", stderr(&artifacts));
    assert!(artifacts.stdout.len() < 64 * 1024);
    let artifacts = json_stdout(&artifacts);
    assert_eq!(artifacts["result"]["total_count"], 126);
    assert_eq!(artifacts["result"]["returned_count"], 25);
    assert_eq!(artifacts["result"]["truncated"], true);
    assert_eq!(artifacts["result"]["next_after"], "page-artifact-024");

    let provenance_page = run(
        &root,
        &[
            "artifacts",
            "list",
            "page-session-000",
            "--after",
            "page-artifact-124",
        ],
    );
    assert_eq!(
        provenance_page.status.code(),
        Some(0),
        "{}",
        stderr(&provenance_page)
    );
    let provenance_page = json_stdout(&provenance_page);
    let provenance = &provenance_page["result"]["artifacts"][0];
    assert_eq!(provenance["id"], "page-with-many-inputs");
    assert_eq!(provenance["input_artifact_ids_total_count"], 20);
    assert_eq!(provenance["input_artifact_ids_returned_count"], 16);
    assert_eq!(provenance["input_artifact_ids_truncated"], true);

    let invalid_cursor = run(
        &root,
        &[
            "artifacts",
            "list",
            "page-session-000",
            "--after",
            "not/a/portable/id",
        ],
    );
    assert_eq!(invalid_cursor.status.code(), Some(1));
    assert_eq!(
        json_stdout(&invalid_cursor)["error"]["code"],
        "OPERATIONAL_ERROR"
    );
}

#[test]
fn synthetic_capture_analyze_convert_and_validate_form_a_real_pipeline() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");

    let captured = run(
        &root,
        &[
            "capture",
            "--provider",
            "synthetic",
            "--id",
            "session-pipeline",
            "--events",
            "16",
        ],
    );
    assert_eq!(captured.status.code(), Some(0), "{}", stderr(&captured));
    let captured_json = json_stdout(&captured);
    assert_eq!(captured_json["result"]["status"], "captured");
    assert_eq!(captured_json["result"]["event_count"], 16);
    assert_eq!(
        captured_json["result"]["artifacts"]
            .as_array()
            .expect("capture artifacts")
            .len(),
        3
    );
    assert!(
        captured.stdout.len() < 16 * 1024,
        "capture leaked event data"
    );
    let observations = std::fs::read_to_string(
        root.join("session-pipeline")
            .join("normalized")
            .join("observations.ndjson"),
    )
    .expect("canonical observations");
    let mut records = observations.lines();
    let header: Value = serde_json::from_str(records.next().expect("header")).expect("header JSON");
    let dictionary_entry: Value = serde_json::from_str(records.next().expect("dictionary entry"))
        .expect("dictionary entry JSON");
    assert_eq!(header["encoding"], "ndjson");
    assert_eq!(dictionary_entry["type"], "DefineContext");

    let artifacts = run(&root, &["artifacts", "list", "session-pipeline"]);
    assert_eq!(artifacts.status.code(), Some(0), "{}", stderr(&artifacts));
    let capture_artifacts = json_stdout(&artifacts)["result"]["artifacts"]
        .as_array()
        .expect("artifact array")
        .clone();
    assert_eq!(capture_artifacts.len(), 3);
    assert!(
        !capture_artifacts
            .iter()
            .any(|artifact| artifact["id"] == "dictionary")
    );

    let analyzed = run(&root, &["analyze", "session-pipeline"]);
    assert_eq!(analyzed.status.code(), Some(0), "{}", stderr(&analyzed));
    let analyzed_json = json_stdout(&analyzed);
    assert_eq!(analyzed_json["result"]["health_verdict"], "VALID");
    assert_eq!(analyzed_json["result"]["observation_count"], 16);
    assert_eq!(analyzed_json["result"]["function_span_count"], 1);
    let derived = std::fs::read_to_string(
        root.join("session-pipeline")
            .join("analysis")
            .join("derived.ndjson"),
    )
    .expect("derived stream");
    assert_eq!(derived.lines().count(), 2, "header plus one span");

    let converted = run(
        &root,
        &["convert", "session-pipeline", "--format", "perfetto-json"],
    );
    assert_eq!(converted.status.code(), Some(0), "{}", stderr(&converted));
    let converted_json = json_stdout(&converted);
    assert_eq!(converted_json["result"]["status"], "complete");
    assert_eq!(converted_json["result"]["artifact"]["id"], "perfetto");
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(root.join("session-pipeline/manifest.json")).expect("manifest"),
    )
    .expect("manifest JSON");
    assert_eq!(manifest["capture"]["provider"], "synthetic");
    assert_eq!(manifest["capture"]["covered_cores"], serde_json::json!([0]));
    assert_eq!(
        manifest["capture"]["capture_config"]["artifact_id"],
        "capture-config"
    );
    assert_eq!(
        manifest["capture"]["capture_config"]["sha256"]
            .as_str()
            .expect("capture config artifact digest")
            .len(),
        64
    );
    assert_eq!(
        manifest["capture"]["capture_config"]["configuration_sha256"]
            .as_str()
            .expect("capture config identity digest")
            .len(),
        64
    );
    assert_eq!(
        manifest["capture"]["capabilities"]["function_events"]["support"],
        "exact"
    );

    let validated = run(&root, &["validate", "session-pipeline", "--deep"]);
    assert_eq!(validated.status.code(), Some(0), "{}", stderr(&validated));
    let validated_json = json_stdout(&validated);
    assert_eq!(validated_json["result"]["health_verdict"], "VALID");
    assert_eq!(validated_json["result"]["trust_status"], "VALID");
    assert_eq!(validated_json["result"]["artifact_count"], 10);

    let verified = run(
        &root,
        &[
            "artifacts",
            "verify",
            "session-pipeline",
            "--id",
            "perfetto",
        ],
    );
    assert_eq!(verified.status.code(), Some(0), "{}", stderr(&verified));
    assert!(
        root.join("session-pipeline")
            .join("report")
            .join("trace.json")
            .is_file()
    );
    let inspected = run(
        &root,
        &["maintenance", "inspect", "session-pipeline", "--deep"],
    );
    assert_eq!(inspected.status.code(), Some(0), "{}", stderr(&inspected));
    let inspected = json_stdout(&inspected);
    assert_eq!(inspected["result"]["healthy"], true);
    assert_eq!(
        inspected["result"]["committed_staging_sources"][0]["artifact_id"],
        "analysis-request"
    );
}

#[test]
fn canonical_staged_ingest_is_not_trusted_without_a_capture_receipt() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    let created = run(
        &root,
        &[
            "session",
            "create",
            "--id",
            "golden-basic",
            "--request",
            r#"{"provider":"ingested"}"#,
        ],
    );
    assert_eq!(created.status.code(), Some(0), "{}", stderr(&created));
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("golden")
        .join("observations.jsonl");
    let staged = root
        .join("golden-basic")
        .join("capture")
        .join("staging")
        .join("observations.jsonl");
    std::fs::copy(source, staged).expect("stage canonical fixture");

    let ingested = run(
        &root,
        &[
            "session",
            "ingest",
            "golden-basic",
            "--staged",
            "observations.jsonl",
            "--id",
            "observations",
            "--kind",
            "observations",
            "--destination",
            "normalized/observations.ndjson",
            "--media-type",
            "application/x-ndjson",
        ],
    );
    assert_eq!(ingested.status.code(), Some(0), "{}", stderr(&ingested));
    assert_eq!(json_stdout(&ingested)["result"]["status"], "captured");

    let analyzed = run(&root, &["analyze", "golden-basic"]);
    assert_eq!(analyzed.status.code(), Some(20), "{}", stderr(&analyzed));
    assert_eq!(json_stdout(&analyzed)["error"]["code"], "UNSUPPORTED");

    let validated = run(&root, &["validate", "golden-basic", "--deep"]);
    assert_eq!(validated.status.code(), Some(20), "{}", stderr(&validated));
    let validated = json_stdout(&validated);
    assert_eq!(validated["result"]["trust_status"], "NOT_EVALUATED");
    assert_eq!(validated["result"]["valid"], false);

    let artifacts = run(&root, &["artifacts", "list", "golden-basic"]);
    let artifacts = json_stdout(&artifacts)["result"]["artifacts"]
        .as_array()
        .expect("artifact array")
        .clone();
    assert_eq!(artifacts.len(), 1);
    assert!(
        !artifacts
            .iter()
            .any(|artifact| artifact["id"] == "dictionary")
    );
}

#[test]
fn signed_external_capture_can_be_attested_and_analyzed() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    prepare_external_observations(&root, "golden-basic");
    let policy_path =
        stage_signed_capture_attestation(&root, "golden-basic", AttestationMutation::None);

    let attested = run(
        &root,
        &[
            "session",
            "attest",
            "golden-basic",
            "--staged",
            "capture-attestation.json",
            "--policy",
            &policy_path.to_string_lossy(),
        ],
    );
    assert_eq!(attested.status.code(), Some(0), "{}", stderr(&attested));
    let attested_json = json_stdout(&attested);
    assert_eq!(attested_json["command"], "session.attest");
    assert_eq!(attested_json["result"]["status"], "captured");
    assert_eq!(attested_json["result"]["producer"], "lab.trace32/v1");
    assert_eq!(attested_json["result"]["policy_id"], "lab-policy");
    assert_eq!(attested_json["result"]["key_id"], "lab-key");

    let listed = run(&root, &["artifacts", "list", "golden-basic"]);
    assert_eq!(listed.status.code(), Some(0), "{}", stderr(&listed));
    let artifacts = json_stdout(&listed)["result"]["artifacts"]
        .as_array()
        .expect("artifact array")
        .clone();
    let receipt = artifacts
        .iter()
        .find(|artifact| artifact["id"] == "capture-receipt")
        .expect("capture receipt");
    assert_eq!(receipt["producer"], "lab.trace32/v1");
    assert_eq!(
        receipt["input_artifact_ids"],
        serde_json::json!([
            "observations",
            "capture-config",
            "capture-attestation",
            "capture-trust-policy"
        ])
    );

    std::fs::write(&policy_path, b"{}\n").expect("replace external policy source");

    let analyzed = run(&root, &["analyze", "golden-basic"]);
    assert_eq!(analyzed.status.code(), Some(0), "{}", stderr(&analyzed));
    assert_eq!(json_stdout(&analyzed)["result"]["health_verdict"], "VALID");

    let converted = run(
        &root,
        &["convert", "golden-basic", "--format", "perfetto-json"],
    );
    assert_eq!(converted.status.code(), Some(0), "{}", stderr(&converted));
    let validated = run(&root, &["validate", "golden-basic", "--deep"]);
    assert_eq!(validated.status.code(), Some(0), "{}", stderr(&validated));
}

#[test]
fn external_capture_attestation_failures_are_terminal() {
    for (index, mutation) in [
        AttestationMutation::TamperedPayload,
        AttestationMutation::TamperedSignature,
        AttestationMutation::WrongObservationDigest,
        AttestationMutation::WrongRequestDigest,
        AttestationMutation::WrongNonce,
        AttestationMutation::CapabilityAboveCeiling,
        AttestationMutation::WrongCaptureConfigDigest,
        AttestationMutation::CaptureConfigOutsidePolicy,
        AttestationMutation::MissingCaptureConfigClaim,
    ]
    .into_iter()
    .enumerate()
    {
        let temp = TempDir::new().expect("temporary directory");
        let root = temp.path().join("artifacts");
        let session_id = format!("attestation-failure-{index}");
        prepare_external_observations(&root, &session_id);
        let policy_path = stage_signed_capture_attestation(&root, &session_id, mutation);

        let attested = run(
            &root,
            &[
                "session",
                "attest",
                &session_id,
                "--staged",
                "capture-attestation.json",
                "--policy",
                &policy_path.to_string_lossy(),
            ],
        );
        assert_eq!(attested.status.code(), Some(1), "{}", stderr(&attested));
        assert_eq!(json_stdout(&attested)["error"]["code"], "OPERATIONAL_ERROR");

        let status = run(&root, &["session", "status", &session_id]);
        assert_eq!(status.status.code(), Some(0), "{}", stderr(&status));
        let status = json_stdout(&status);
        assert_eq!(status["result"]["state"]["state"], "failed");
        assert_eq!(
            status["result"]["state"]["error"]["code"],
            "CAPTURE_ATTESTATION_FAILED"
        );
        assert_eq!(status["result"]["trust_status"], "INCOMPLETE");
    }
}

#[test]
fn generic_ingest_cannot_claim_reserved_capture_provenance() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    let created = run(&root, &["session", "create", "--id", "reserved-receipt"]);
    assert_eq!(created.status.code(), Some(0), "{}", stderr(&created));
    std::fs::write(
        root.join("reserved-receipt")
            .join("capture")
            .join("staging")
            .join("receipt.json"),
        b"{}\n",
    )
    .expect("stage fake receipt");

    for (id, kind, destination) in [
        (
            "capture-receipt",
            "capture_receipt",
            "capture/capture-receipt.json",
        ),
        ("Capture-Receipt", "other", "capture/other.json"),
        ("other-receipt", "other", "Capture/Capture-Receipt.json"),
    ] {
        let ingested = run(
            &root,
            &[
                "session",
                "ingest",
                "reserved-receipt",
                "--staged",
                "receipt.json",
                "--id",
                id,
                "--kind",
                kind,
                "--destination",
                destination,
                "--media-type",
                "application/json",
                "--producer",
                "lab.trace32/v1",
            ],
        );
        assert_eq!(ingested.status.code(), Some(1), "{}", stderr(&ingested));
        assert!(
            json_stdout(&ingested)["error"]["message"]
                .as_str()
                .expect("error message")
                .contains("reserved")
        );
    }
    assert_eq!(
        json_stdout(&run(&root, &["session", "status", "reserved-receipt"]))["result"]["state"]["state"],
        "created"
    );
}

#[test]
fn generic_ingest_cannot_claim_trace32_mapping_or_qualification_provenance() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    let session_id = "reserved-trace32-mapping";
    let created = run(&root, &["session", "create", "--id", session_id]);
    assert_eq!(created.status.code(), Some(0), "{}", stderr(&created));
    std::fs::write(
        root.join(session_id)
            .join("capture/staging/fake-mapping.json"),
        b"{}\n",
    )
    .expect("stage fake mapping");

    for (id, kind, destination, producer) in [
        (
            "trace32-symbol-mapping",
            "trace32_symbol_mapping",
            "normalized/trace32-symbol-mapping.json",
            "lab.trace32/v1",
        ),
        (
            "target-adapter-qualification",
            "target_adapter_qualification",
            "capture/target-adapter-qualification.json",
            "t32perf-deployment-qualification/v1",
        ),
        (
            "c-wire-counter-map-deadbeef",
            "c_wire_counter_mapping",
            "normalized/c-wire-counter-maps/deadbeef.json",
            "t32perf-c-wire-mapping/v1",
        ),
        (
            "Trace32-Symbol-Mapping",
            "other",
            "normalized/other-mapping.json",
            "lab.trace32/v1",
        ),
        (
            "other-task-mapping",
            "other",
            "Normalized/Trace32-Task-Events-Mapping.json",
            "lab.trace32/v1",
        ),
    ] {
        let ingested = run(
            &root,
            &[
                "session",
                "ingest",
                session_id,
                "--staged",
                "fake-mapping.json",
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
        assert_eq!(ingested.status.code(), Some(1), "{}", stderr(&ingested));
        assert!(
            json_stdout(&ingested)["error"]["message"]
                .as_str()
                .expect("error message")
                .contains("reserved")
        );
    }
}

#[test]
fn compare_verdicts_use_contract_exit_codes() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    complete_synthetic(&root, "baseline", 10);
    complete_synthetic(&root, "candidate", 20);
    let policy = temp.path().join("comparison-policy.json");
    std::fs::write(
        &policy,
        serde_json::to_vec(&serde_json::json!({
            "relative_threshold": 0.05,
            "absolute_time_threshold_ns": 0,
            "absolute_count_threshold": 0,
            "require_exact_metrics": true,
            "require_matching_request": false,
            "require_same_adapter_version": true,
            "compare_statistical_metrics": false,
            "require_complete_provenance": true
        }))
        .expect("serialize policy"),
    )
    .expect("write policy");
    let policy = policy.to_string_lossy();

    let compared = run(
        &root,
        &["compare", "baseline", "candidate", "--policy", &policy],
    );
    assert_eq!(compared.status.code(), Some(13), "{}", stderr(&compared));
    let compared = json_stdout(&compared);
    assert_eq!(compared["result"]["verdict"], "inconclusive");
    assert_eq!(compared["result"]["inconclusive_allowed"], false);
    assert!(
        compared["result"]["report"]["reasons"]
            .as_array()
            .expect("comparison reasons")
            .iter()
            .any(|reason| reason == "capture_config_digest_mismatch")
    );

    let regressed_allowed = run(
        &root,
        &[
            "compare",
            "baseline",
            "candidate",
            "--policy",
            &policy,
            "--allow-inconclusive",
        ],
    );
    assert_eq!(
        regressed_allowed.status.code(),
        Some(0),
        "{}",
        stderr(&regressed_allowed)
    );
    let regressed_allowed = json_stdout(&regressed_allowed);
    assert_eq!(regressed_allowed["result"]["verdict"], "inconclusive");
    assert_eq!(regressed_allowed["result"]["inconclusive_allowed"], true);

    let improved = run(
        &root,
        &["compare", "candidate", "baseline", "--policy", &policy],
    );
    assert_eq!(improved.status.code(), Some(13), "{}", stderr(&improved));
    let improved = json_stdout(&improved);
    assert_eq!(improved["result"]["verdict"], "inconclusive");
    assert_eq!(improved["result"]["inconclusive_allowed"], false);

    let unchanged = run(
        &root,
        &["compare", "baseline", "baseline", "--policy", &policy],
    );
    assert_eq!(unchanged.status.code(), Some(0), "{}", stderr(&unchanged));
    let unchanged = json_stdout(&unchanged);
    assert_eq!(unchanged["result"]["verdict"], "unchanged");
    assert_eq!(unchanged["result"]["inconclusive_allowed"], false);
}

#[test]
fn comparison_report_is_content_addressed_bounded_and_idempotent() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    complete_synthetic(&root, "comparison-artifact", 64);
    let state_before =
        std::fs::read(root.join("comparison-artifact/state.json")).expect("read complete state");
    let manifest_before = std::fs::read(root.join("comparison-artifact/manifest.json"))
        .expect("read complete manifest");

    let first = run(
        &root,
        &[
            "compare",
            "comparison-artifact",
            "comparison-artifact",
            "--policy",
            "strict",
            "--top",
            "1",
        ],
    );
    assert_eq!(first.status.code(), Some(0), "{}", stderr(&first));
    assert!(first.stdout.len() < 64 * 1024);
    let first = json_stdout(&first);
    assert_eq!(first["result"]["report_artifact"]["publication"], "created");
    assert_eq!(
        first["result"]["report_artifact"]["schema"],
        "t32perf.comparison-artifact/v1"
    );
    assert_eq!(first["result"]["report"]["requested_top"], 1);
    assert_eq!(first["result"]["report"]["metrics_returned_count"], 1);
    assert_eq!(first["result"]["report"]["metrics_truncated"], true);

    let control_path = first["result"]["report_artifact"]["control_path"]
        .as_str()
        .expect("control path");
    let control_path = root.join(control_path);
    let bytes = std::fs::read(&control_path).expect("comparison control artifact");
    let digest = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        digest,
        first["result"]["report_artifact"]["sha256"]
            .as_str()
            .expect("reported digest")
    );
    assert_eq!(
        bytes.len() as u64,
        first["result"]["report_artifact"]["size_bytes"]
            .as_u64()
            .expect("reported size")
    );
    let document: Value = serde_json::from_slice(&bytes).expect("comparison document");
    assert_eq!(document["schema"], "t32perf.comparison-artifact/v1");
    assert_eq!(document["report"]["schema"], "t32perf.comparison/v1");
    assert_eq!(
        document["report"]["metrics"]
            .as_array()
            .expect("complete metric rows")
            .len(),
        first["result"]["report"]["metrics_total_count"]
            .as_u64()
            .expect("metric count") as usize
    );

    let second = run(
        &root,
        &[
            "compare",
            "comparison-artifact",
            "comparison-artifact",
            "--policy",
            "strict",
            "--top",
            "1",
        ],
    );
    assert_eq!(second.status.code(), Some(0), "{}", stderr(&second));
    let second = json_stdout(&second);
    assert_eq!(
        second["result"]["report_artifact"]["publication"],
        "existing"
    );
    assert_eq!(
        second["result"]["report_artifact"]["sha256"],
        first["result"]["report_artifact"]["sha256"]
    );
    assert_eq!(
        std::fs::read(root.join("comparison-artifact/state.json")).expect("state after compare"),
        state_before
    );
    assert_eq!(
        std::fs::read(root.join("comparison-artifact/manifest.json"))
            .expect("manifest after compare"),
        manifest_before
    );

    std::fs::write(&control_path, b"corrupted\n").expect("corrupt control artifact");
    let corrupted = run(
        &root,
        &[
            "compare",
            "comparison-artifact",
            "comparison-artifact",
            "--policy",
            "strict",
        ],
    );
    assert_eq!(corrupted.status.code(), Some(1));
    assert!(
        json_stdout(&corrupted)["error"]["message"]
            .as_str()
            .expect("comparison error")
            .contains("does not match its expected digest and size")
    );
}

#[test]
fn concurrent_identical_comparisons_publish_one_idempotent_artifact() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    complete_synthetic(&root, "comparison-concurrent", 64);
    let root = Arc::new(root);
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let root = Arc::clone(&root);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            run(
                &root,
                &[
                    "compare",
                    "comparison-concurrent",
                    "comparison-concurrent",
                    "--policy",
                    "strict",
                ],
            )
        }));
    }
    barrier.wait();
    let outputs = workers
        .into_iter()
        .map(|worker| worker.join().expect("comparison worker"))
        .collect::<Vec<_>>();
    for output in &outputs {
        assert_eq!(output.status.code(), Some(0), "{}", stderr(output));
    }
    let documents = outputs.iter().map(json_stdout).collect::<Vec<_>>();
    assert_eq!(
        documents[0]["result"]["report_artifact"]["sha256"],
        documents[1]["result"]["report_artifact"]["sha256"]
    );
    let mut publications = documents
        .iter()
        .map(|document| {
            document["result"]["report_artifact"]["publication"]
                .as_str()
                .expect("publication")
        })
        .collect::<Vec<_>>();
    publications.sort_unstable();
    assert_eq!(publications, ["created", "existing"]);
    assert_eq!(
        std::fs::read_dir(root.join(".t32perf-control/comparisons"))
            .expect("comparison directory")
            .count(),
        1
    );
}

#[test]
fn resource_regression_uses_semantic_subject_identity_and_exit_code() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    create_synthetic_resource_session(
        &root,
        "resource-baseline",
        "opaque-baseline-id",
        &[100.0, 100.0],
    );
    create_synthetic_resource_session(
        &root,
        "resource-candidate",
        "renamed-candidate-id",
        &[100.0, 200.0],
    );
    for id in ["resource-baseline", "resource-candidate"] {
        let analyzed = run(&root, &["analyze", id]);
        assert_eq!(analyzed.status.code(), Some(0), "{}", stderr(&analyzed));
        let converted = run(&root, &["convert", id, "--format", "perfetto-json"]);
        assert_eq!(converted.status.code(), Some(0), "{}", stderr(&converted));
    }

    let compared = run(
        &root,
        &[
            "compare",
            "resource-baseline",
            "resource-candidate",
            "--policy",
            "strict",
        ],
    );
    assert_eq!(compared.status.code(), Some(12), "{}", stderr(&compared));
    let report = json_stdout(&compared);
    assert_eq!(report["result"]["verdict"], "regressed");
    assert_eq!(report["result"]["inconclusive_allowed"], false);
    let row = report["result"]["report"]["resource_metrics"]
        .as_array()
        .expect("resource comparison rows")
        .iter()
        .find(|row| row["semantic"] == "heap.current_allocated_bytes")
        .expect("heap comparison row");
    assert_eq!(row["baseline_source"]["kind"], "counter");
    assert_eq!(row["baseline_source"]["counter_id"], "opaque-baseline-id");
    assert_eq!(row["candidate_source"]["kind"], "counter");
    assert_eq!(
        row["candidate_source"]["counter_id"],
        "renamed-candidate-id"
    );
    assert_eq!(row["outcome"], "regressed");
}

#[test]
fn resource_subject_set_change_is_inconclusive_by_default() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    create_synthetic_resource_session_with_allocator(
        &root,
        "resource-subject-baseline",
        "heap-used-baseline",
        "system",
        &[100.0, 100.0],
    );
    create_synthetic_resource_session_with_allocator(
        &root,
        "resource-subject-candidate",
        "heap-used-candidate",
        "secondary",
        &[100.0, 100.0],
    );
    for id in ["resource-subject-baseline", "resource-subject-candidate"] {
        let analyzed = run(&root, &["analyze", id]);
        assert_eq!(analyzed.status.code(), Some(0), "{}", stderr(&analyzed));
        let converted = run(&root, &["convert", id, "--format", "perfetto-json"]);
        assert_eq!(converted.status.code(), Some(0), "{}", stderr(&converted));
    }

    let compared = run(
        &root,
        &[
            "compare",
            "resource-subject-baseline",
            "resource-subject-candidate",
            "--policy",
            "strict",
        ],
    );
    assert_eq!(compared.status.code(), Some(13), "{}", stderr(&compared));
    let compared = json_stdout(&compared);
    assert_eq!(compared["result"]["verdict"], "inconclusive");
    assert_eq!(compared["result"]["inconclusive_allowed"], false);
    assert!(
        compared["result"]["report"]["reasons"]
            .as_array()
            .expect("comparison reasons")
            .iter()
            .any(|reason| reason
                .as_str()
                .is_some_and(|reason| reason.starts_with("resource_subject_set_differs:")))
    );
}

#[test]
fn strict_comparison_is_inconclusive_when_required_provenance_is_missing() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    complete_synthetic(&root, "provenance-baseline", 10);
    complete_synthetic(&root, "provenance-candidate", 10);

    let candidate_manifest = root.join("provenance-candidate").join("manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&std::fs::read(&candidate_manifest).expect("candidate manifest"))
            .expect("candidate manifest JSON");
    manifest["capture"]
        .as_object_mut()
        .expect("capture object")
        .remove("request_sha256");
    std::fs::write(
        &candidate_manifest,
        serde_json::to_vec(&manifest).expect("serialize candidate manifest"),
    )
    .expect("write candidate manifest");

    let policy = temp.path().join("provenance-policy.json");
    std::fs::write(
        &policy,
        serde_json::to_vec(&serde_json::json!({
            "relative_threshold": 0.05,
            "absolute_time_threshold_ns": 0,
            "absolute_count_threshold": 0,
            "require_exact_metrics": true,
            "require_matching_request": false,
            "require_same_adapter_version": true,
            "compare_statistical_metrics": false,
            "require_complete_provenance": true
        }))
        .expect("serialize policy"),
    )
    .expect("write policy");
    let policy = policy.to_string_lossy();
    let compared = run(
        &root,
        &[
            "compare",
            "provenance-baseline",
            "provenance-candidate",
            "--policy",
            &policy,
        ],
    );
    assert_eq!(
        compared.status.code(),
        Some(13),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&compared.stdout),
        stderr(&compared)
    );
    let compared = json_stdout(&compared);
    assert_eq!(compared["result"]["verdict"], "inconclusive");
    assert_eq!(compared["result"]["inconclusive_allowed"], false);
    assert!(
        compared["result"]["report"]["reasons"]
            .as_array()
            .expect("comparison reasons")
            .iter()
            .any(|reason| reason == "capture_request_mismatch")
    );

    let allowed = run(
        &root,
        &[
            "compare",
            "provenance-baseline",
            "provenance-candidate",
            "--policy",
            &policy,
            "--allow-inconclusive",
        ],
    );
    assert_eq!(allowed.status.code(), Some(0), "{}", stderr(&allowed));
    let allowed = json_stdout(&allowed);
    assert_eq!(allowed["result"]["verdict"], "inconclusive");
    assert_eq!(allowed["result"]["inconclusive_allowed"], true);
}

#[test]
fn unsupported_and_operational_failures_use_contract_exit_codes() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");

    let unsupported = run(&root, &["capture", "--provider", "trace32"]);
    assert_eq!(unsupported.status.code(), Some(20));
    assert_eq!(json_stdout(&unsupported)["error"]["code"], "UNSUPPORTED");

    let doctor = run(&root, &["doctor"]);
    assert_eq!(doctor.status.code(), Some(20));
    assert_eq!(json_stdout(&doctor)["result"]["status"], "unsupported");

    let help = run(&root, &["--help"]);
    assert_eq!(help.status.code(), Some(0));
    assert_eq!(json_stdout(&help)["command"], "help");

    let compare_help = run(&root, &["compare", "--help"]);
    assert_eq!(compare_help.status.code(), Some(0));
    assert!(
        json_stdout(&compare_help)["result"]["text"]
            .as_str()
            .expect("compare help text")
            .contains("--allow-inconclusive")
    );

    let mut command = cargo_bin_cmd!("t32perf");
    let operational = command
        .arg("--artifact-root")
        .arg(&root)
        .args([
            "--max-file-bytes",
            "10",
            "--max-session-bytes",
            "5",
            "--json",
            "session",
            "list",
        ])
        .output()
        .expect("run t32perf");
    assert_eq!(operational.status.code(), Some(1));
    assert_eq!(
        json_stdout(&operational)["error"]["code"],
        "OPERATIONAL_ERROR"
    );
}

#[test]
fn comparison_policy_files_reject_nonobjects_and_oversize_inputs() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    let nonobject = temp.path().join("nonobject.json");
    std::fs::write(&nonobject, b"[]").expect("write policy");
    let nonobject = nonobject.to_string_lossy();
    let output = run(
        &root,
        &["compare", "baseline", "candidate", "--policy", &nonobject],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(
        json_stdout(&output)["error"]["message"]
            .as_str()
            .expect("error message")
            .contains("exactly one object")
    );

    let oversized = temp.path().join("oversized.json");
    std::fs::write(&oversized, vec![b' '; 64 * 1024 + 1]).expect("write policy");
    let oversized = oversized.to_string_lossy();
    let output = run(
        &root,
        &["compare", "baseline", "candidate", "--policy", &oversized],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(
        json_stdout(&output)["error"]["message"]
            .as_str()
            .expect("error message")
            .contains("exceeds")
    );
}

#[test]
fn fixture_surface_and_unevaluated_validation_are_explicit() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");

    let fixture = run(
        &root,
        &[
            "fixture",
            "generate",
            "--id",
            "fixture-session",
            "--events",
            "3",
        ],
    );
    assert_eq!(fixture.status.code(), Some(0), "{}", stderr(&fixture));
    assert_eq!(json_stdout(&fixture)["command"], "fixture.generate");

    let validated = run(&root, &["validate", "fixture-session", "--deep"]);
    assert_eq!(validated.status.code(), Some(20), "{}", stderr(&validated));
    let validated_json = json_stdout(&validated);
    assert_eq!(validated_json["result"]["trust_status"], "NOT_EVALUATED");
    assert_eq!(validated_json["result"]["valid"], false);
}

#[test]
fn linker_map_and_stack_usage_are_analyzed_with_explicit_flavors() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    let captured = run(
        &root,
        &[
            "capture",
            "--provider",
            "synthetic",
            "--id",
            "resource-session",
            "--events",
            "8",
        ],
    );
    assert_eq!(captured.status.code(), Some(0), "{}", stderr(&captured));
    stage_and_ingest(
        &root,
        "resource-session",
        "firmware.map",
        "linker-map",
        "linker_map",
        "capture/firmware.map",
        b".data 0x20000000 0x10\n.bss 0x20000010 0x20\n.noinit 0x20000030 0x8\n.dma_buffers 0x20000038 0x4\n.rtos_objects 0x2000003c 0x8\n.project_cache 0x20000044 0xc\n",
    );
    stage_and_ingest(
        &root,
        "resource-session",
        "static-ram-config.json",
        "static-ram-config",
        "static_ram_config",
        "capture/static-ram-config.json",
        br#"{"schema":"t32perf.static-ram-config/v1","flavor":"gnu-ld-map-v1","additional_sections":[{"name":".dma_buffers","kind":"dma"},{"name":".rtos_objects","kind":"rtos"},{"name":".project_cache","kind":"custom"}]}"#,
    );
    stage_and_ingest(
        &root,
        "resource-session",
        "firmware.su",
        "stack-input",
        "stack_usage",
        "capture/firmware.su",
        b"src/main.c:1:1:frame_a\t128\tstatic\nsrc/main.c:2:1:frame_b\t64\tdynamic\n",
    );

    let analyzed = run(
        &root,
        &[
            "analyze",
            "resource-session",
            "--linker-map-flavor",
            "gnu-ld-map-v1",
        ],
    );
    assert_eq!(analyzed.status.code(), Some(0), "{}", stderr(&analyzed));
    let analyzed = json_stdout(&analyzed);
    assert_eq!(
        analyzed["result"]["summary"]["static_ram"]["total_bytes"],
        80
    );
    assert_eq!(
        analyzed["result"]["summary"]["static_ram"]["flavor"],
        "gnu-ld-map-v1"
    );
    assert_eq!(
        analyzed["result"]["summary"]["static_ram"]["config"]["artifact_id"],
        "static-ram-config"
    );
    assert_eq!(
        analyzed["result"]["summary"]["static_ram"]["totals"]["dma_bytes"],
        4
    );
    assert_eq!(
        analyzed["result"]["summary"]["static_ram"]["totals"]["rtos_bytes"],
        8
    );
    assert_eq!(
        analyzed["result"]["summary"]["static_ram"]["totals"]["custom_bytes"],
        12
    );
    assert_eq!(
        analyzed["result"]["summary"]["stack_usage"]["maximum_static_bytes"],
        128
    );
    assert_eq!(
        analyzed["result"]["summary"]["stack_usage"]["flavor"],
        "gcc-stack-usage-v1"
    );
    let stage: Value = serde_json::from_slice(
        &std::fs::read(
            root.join("resource-session")
                .join("analysis")
                .join("stage.json"),
        )
        .expect("stage receipt"),
    )
    .expect("stage receipt JSON");
    let outputs = stage["output_artifacts"].as_array().expect("output claims");
    assert!(
        stage["input_artifacts"]
            .as_array()
            .expect("input claims")
            .iter()
            .any(|artifact| artifact["id"] == "static-ram-config")
    );
    assert!(
        outputs
            .iter()
            .any(|artifact| artifact["id"] == "static-ram")
    );
    assert!(
        outputs
            .iter()
            .any(|artifact| artifact["id"] == "stack-usage")
    );

    let converted = run(
        &root,
        &["convert", "resource-session", "--format", "perfetto-json"],
    );
    assert_eq!(converted.status.code(), Some(0), "{}", stderr(&converted));
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(root.join("resource-session").join("manifest.json")).expect("manifest"),
    )
    .expect("manifest JSON");
    assert!(
        manifest["artifacts"]
            .as_array()
            .expect("manifest artifacts")
            .iter()
            .any(|artifact| {
                artifact["id"] == "static-ram"
                    && artifact["producer"] == "t32perf-static-ram"
                    && artifact["kind"] == "static_ram:gnu-ld-map-v1"
                    && artifact["input_artifact_ids"]
                        == serde_json::json!([
                            "linker-map",
                            "analysis-request",
                            "static-ram-config"
                        ])
            })
    );
}

#[test]
fn generic_firmware_elf_static_ram_requires_and_records_explicit_flavor() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    let captured = run(
        &root,
        &[
            "capture",
            "--provider",
            "synthetic",
            "--id",
            "elf-resource-session",
            "--events",
            "8",
        ],
    );
    assert_eq!(captured.status.code(), Some(0), "{}", stderr(&captured));
    stage_and_ingest(
        &root,
        "elf-resource-session",
        "firmware.elf",
        "static-ram-firmware-elf",
        "firmware_elf",
        "capture/resources/firmware.elf",
        &elf_resource_fixture(),
    );
    stage_and_ingest(
        &root,
        "elf-resource-session",
        "static-ram-config.json",
        "static-ram-config",
        "static_ram_config",
        "capture/static-ram-config.json",
        br#"{"schema":"t32perf.static-ram-config/v1","flavor":"elf-sections-v1","additional_sections":[{"name":".dma_buffers","kind":"dma"}]}"#,
    );

    let analyzed = run(
        &root,
        &[
            "analyze",
            "elf-resource-session",
            "--static-ram-flavor",
            "elf-sections-v1",
        ],
    );
    assert_eq!(analyzed.status.code(), Some(0), "{}", stderr(&analyzed));
    let analyzed = json_stdout(&analyzed);
    assert_eq!(
        analyzed["result"]["summary"]["static_ram"]["flavor"],
        "elf-sections-v1"
    );
    assert_eq!(
        analyzed["result"]["summary"]["static_ram"]["total_bytes"],
        52
    );
    let report: Value = serde_json::from_slice(
        &std::fs::read(
            root.join("elf-resource-session")
                .join("analysis")
                .join("static-ram.json"),
        )
        .expect("static RAM report"),
    )
    .expect("static RAM report JSON");
    assert_eq!(report["schema"], "t32perf.static-ram/elf-sections-v1");
    assert_eq!(report["elf"]["architecture"], "arm");
    assert_eq!(report["elf"]["object_kind"], "relocatable");
    assert!(
        report["sections"]
            .as_array()
            .unwrap()
            .iter()
            .all(|section| {
                section.get("source_line").is_none()
                    && section["source_section_index"]
                        .as_u64()
                        .is_some_and(|index| index > 0)
            })
    );

    let converted = run(
        &root,
        &[
            "convert",
            "elf-resource-session",
            "--format",
            "perfetto-json",
        ],
    );
    assert_eq!(converted.status.code(), Some(0), "{}", stderr(&converted));
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(root.join("elf-resource-session").join("manifest.json")).expect("manifest"),
    )
    .expect("manifest JSON");
    assert!(
        manifest["artifacts"]
            .as_array()
            .expect("manifest artifacts")
            .iter()
            .any(|artifact| {
                artifact["id"] == "static-ram"
                    && artifact["kind"] == "static_ram:elf-sections-v1"
                    && artifact["input_artifact_ids"]
                        == serde_json::json!([
                            "static-ram-firmware-elf",
                            "analysis-request",
                            "static-ram-config"
                        ])
            })
    );
}

#[test]
fn session_rejects_a_second_firmware_elf_resource_before_catalog_conflict() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    let captured = run(
        &root,
        &[
            "capture",
            "--provider",
            "synthetic",
            "--id",
            "firmware-resource-unique",
            "--events",
            "8",
        ],
    );
    assert_eq!(captured.status.code(), Some(0), "{}", stderr(&captured));
    stage_and_ingest_typed(
        &root,
        "firmware-resource-unique",
        (
            "first.elf",
            "analysis-firmware-one",
            "firmware_elf",
            "capture/resources/first.elf",
            "application/x-elf",
        ),
        &elf_resource_fixture(),
    );
    // An exact retry is delegated to the durable ingest protocol, which verifies the
    // complete catalog envelope and digest before returning the existing artifact.
    stage_and_ingest_typed(
        &root,
        "firmware-resource-unique",
        (
            "first.elf",
            "analysis-firmware-one",
            "firmware_elf",
            "capture/resources/first.elf",
            "application/x-elf",
        ),
        &elf_resource_fixture(),
    );
    std::fs::write(
        root.join("firmware-resource-unique/capture/staging/retry.elf"),
        elf_resource_fixture(),
    )
    .unwrap();
    let conflicting_envelope = run(
        &root,
        &[
            "session",
            "ingest",
            "firmware-resource-unique",
            "--staged",
            "retry.elf",
            "--id",
            "ANALYSIS-FIRMWARE-ONE",
            "--kind",
            "firmware_elf",
            "--destination",
            "capture/resources/first.elf",
            "--media-type",
            "application/octet-stream",
        ],
    );
    assert_eq!(
        conflicting_envelope.status.code(),
        Some(1),
        "{}",
        stderr(&conflicting_envelope)
    );
    assert!(
        json_stdout(&conflicting_envelope)["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("different specification"))
    );
    std::fs::write(
        root.join("firmware-resource-unique/capture/staging/second.elf"),
        elf_resource_fixture(),
    )
    .unwrap();
    let rejected = run(
        &root,
        &[
            "session",
            "ingest",
            "firmware-resource-unique",
            "--staged",
            "second.elf",
            "--id",
            "analysis-firmware-two",
            "--kind",
            "firmware_elf",
            "--destination",
            "capture/resources/second.elf",
            "--media-type",
            "application/x-elf",
        ],
    );
    assert_eq!(rejected.status.code(), Some(1), "{}", stderr(&rejected));
    assert!(
        json_stdout(&rejected)["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("only one firmware_elf"))
    );
    assert_eq!(
        json_stdout(&run(
            &root,
            &["session", "status", "firmware-resource-unique"]
        ))["result"]["state"]["state"],
        "captured"
    );
}

#[test]
fn unsupported_resource_flavor_and_analysis_failure_are_durable() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    let captured = run(
        &root,
        &[
            "capture",
            "--provider",
            "synthetic",
            "--id",
            "unknown-flavor",
        ],
    );
    assert_eq!(captured.status.code(), Some(0), "{}", stderr(&captured));
    let unsupported = run(
        &root,
        &[
            "analyze",
            "unknown-flavor",
            "--linker-map-flavor",
            "vendor-latest",
        ],
    );
    assert_eq!(
        unsupported.status.code(),
        Some(20),
        "{}",
        stderr(&unsupported)
    );
    let status = run(&root, &["session", "status", "unknown-flavor"]);
    assert_eq!(json_stdout(&status)["result"]["state"]["state"], "captured");
    let conflicting = run(
        &root,
        &[
            "analyze",
            "unknown-flavor",
            "--static-ram-flavor",
            "elf-sections-v1",
            "--linker-map-flavor",
            "gnu-ld-map-v1",
        ],
    );
    assert_eq!(
        conflicting.status.code(),
        Some(20),
        "{}",
        stderr(&conflicting)
    );

    let captured = run(
        &root,
        &[
            "capture",
            "--provider",
            "synthetic",
            "--id",
            "failed-analysis",
        ],
    );
    assert_eq!(captured.status.code(), Some(0), "{}", stderr(&captured));
    stage_and_ingest(
        &root,
        "failed-analysis",
        "broken.map",
        "linker-map",
        "linker_map",
        "capture/broken.map",
        b".data 0x20000000 not-a-size\n",
    );
    let analyzed = run(&root, &["analyze", "failed-analysis"]);
    assert_eq!(analyzed.status.code(), Some(1));
    let status = run(&root, &["session", "status", "failed-analysis"]);
    let status = json_stdout(&status);
    assert_eq!(status["result"]["state"]["state"], "failed");
    assert_eq!(status["result"]["state"]["error"]["code"], "ANALYZE_FAILED");
    let validated = run(&root, &["validate", "failed-analysis", "--deep"]);
    assert_eq!(validated.status.code(), Some(1), "{}", stderr(&validated));
    assert_eq!(
        json_stdout(&validated)["result"]["trust_status"],
        "INCOMPLETE"
    );
}

#[test]
fn summary_is_health_gated_and_bounded_for_skill_consumers() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    let captured = run(
        &root,
        &[
            "capture",
            "--provider",
            "synthetic",
            "--id",
            "summary-valid",
            "--events",
            "64",
        ],
    );
    assert_eq!(captured.status.code(), Some(0), "{}", stderr(&captured));
    let analyzed = run(&root, &["analyze", "summary-valid"]);
    assert_eq!(analyzed.status.code(), Some(0), "{}", stderr(&analyzed));

    let summarized = run(&root, &["summary", "summary-valid", "--top", "1"]);
    assert_eq!(summarized.status.code(), Some(0), "{}", stderr(&summarized));
    assert!(summarized.stdout.len() < 64 * 1024);
    let document = json_stdout(&summarized);
    assert_eq!(document["command"], "summary");
    assert_eq!(document["result"]["health"]["verdict"], "VALID");
    assert_eq!(document["result"]["quantitative_available"], true);
    assert_eq!(document["result"]["report"]["schema"], "t32perf.report/v1");
    assert_eq!(document["result"]["report"]["health_verdict"], "VALID");
    assert_eq!(
        document["result"]["quantitative"]["hotspots"]["functions"]
            .as_array()
            .expect("function hotspots")
            .len(),
        1
    );
    assert!(
        document["result"]["quantitative"]["execution"]["tasks"]
            .as_array()
            .expect("task summaries")
            .len()
            <= 1
    );
    assert!(
        document["result"]["quantitative"]["resources"]["heaps"]
            .as_array()
            .expect("heap summaries")
            .len()
            <= 1
    );
    assert!(
        document["result"]["artifact_references"]
            .as_array()
            .expect("artifact references")
            .iter()
            .any(|artifact| artifact["id"] == "analysis-stage")
    );

    let invalid_top = run(&root, &["summary", "summary-valid", "--top", "0"]);
    assert_eq!(invalid_top.status.code(), Some(1));
    assert!(
        json_stdout(&invalid_top)["error"]["message"]
            .as_str()
            .expect("error message")
            .contains("1..=100")
    );
    let status = run(&root, &["session", "status", "summary-valid"]);
    assert_eq!(
        json_stdout(&status)["result"]["state"]["state"],
        "processing"
    );
}

#[test]
fn invalid_summary_returns_diagnostics_without_quantitative_hotspots() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    create_invalid_synthetic_session(&root, "summary-invalid");
    stage_and_ingest(
        &root,
        "summary-invalid",
        "invalid-firmware.map",
        "linker-map",
        "linker_map",
        "capture/invalid-firmware.map",
        b".data 0x20000000 0x10\n",
    );

    let analyzed = run(&root, &["analyze", "summary-invalid"]);
    assert_eq!(analyzed.status.code(), Some(11), "{}", stderr(&analyzed));
    let analyzed_document = json_stdout(&analyzed);
    assert_eq!(analyzed_document["result"]["health_verdict"], "INVALID");
    assert!(analyzed_document["result"].get("summary").is_none());
    assert!(
        analyzed_document["result"]
            .get("observation_count")
            .is_none()
    );
    assert!(
        analyzed_document["result"]["artifacts"]
            .as_array()
            .expect("artifact references")
            .iter()
            .all(|artifact| artifact["id"] != "hotspots")
    );
    let persisted_summary: Value = serde_json::from_slice(
        &std::fs::read(
            root.join("summary-invalid")
                .join("analysis")
                .join("summary.json"),
        )
        .expect("persisted diagnostic summary"),
    )
    .expect("summary JSON");
    assert_eq!(persisted_summary["schema"], "t32perf.analysis-summary/v1");
    assert_eq!(persisted_summary["session_id"], "summary-invalid");
    assert_eq!(persisted_summary["health_verdict"], "INVALID");
    assert!(persisted_summary.get("quantitative").is_none());
    assert!(!root.join("summary-invalid/analysis/hotspots.json").exists());
    assert!(
        !root
            .join("summary-invalid/analysis/static-ram.json")
            .exists()
    );
    let stage: Value = serde_json::from_slice(
        &std::fs::read(root.join("summary-invalid/analysis/stage.json")).expect("analysis stage"),
    )
    .expect("analysis stage JSON");
    assert!(
        stage["output_artifacts"]
            .as_array()
            .expect("stage outputs")
            .iter()
            .all(|artifact| !matches!(
                artifact["id"].as_str(),
                Some("hotspots" | "static-ram" | "stack-usage")
            ))
    );
    let summarized = run(&root, &["summary", "summary-invalid", "--top", "10"]);
    assert_eq!(
        summarized.status.code(),
        Some(11),
        "{}",
        stderr(&summarized)
    );
    let document = json_stdout(&summarized);
    assert_eq!(document["result"]["health"]["verdict"], "INVALID");
    assert_eq!(document["result"]["quantitative_available"], false);
    assert!(document["result"].get("quantitative").is_none());
    assert!(
        document["result"]["health"]["issues"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .any(|issue| issue["code"] == "mismatched_function_exit")
    );
    assert!(summarized.stdout.len() < 64 * 1024);
}

#[test]
fn degraded_analysis_is_diagnostic_only_under_the_conservative_summary_policy() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    create_degraded_synthetic_session(&root, "summary-degraded");

    let analyzed = run(&root, &["analyze", "summary-degraded"]);
    assert_eq!(analyzed.status.code(), Some(10), "{}", stderr(&analyzed));
    let analyzed = json_stdout(&analyzed);
    assert_eq!(analyzed["result"]["health_verdict"], "DEGRADED");
    assert!(analyzed["result"].get("summary").is_none());
    assert!(
        analyzed["result"]["artifacts"]
            .as_array()
            .expect("artifact references")
            .iter()
            .all(|artifact| artifact["id"] != "hotspots")
    );

    let persisted_summary: Value = serde_json::from_slice(
        &std::fs::read(
            root.join("summary-degraded")
                .join("analysis")
                .join("summary.json"),
        )
        .expect("persisted degraded summary"),
    )
    .expect("summary JSON");
    assert_eq!(persisted_summary["health_verdict"], "DEGRADED");
    assert!(persisted_summary.get("quantitative").is_none());

    let summarized = run(&root, &["summary", "summary-degraded", "--top", "10"]);
    assert_eq!(
        summarized.status.code(),
        Some(10),
        "{}",
        stderr(&summarized)
    );
    let summarized = json_stdout(&summarized);
    assert_eq!(summarized["result"]["quantitative_available"], false);
    assert!(summarized["result"].get("quantitative").is_none());
    assert!(summarized["result"].get("report").is_none());
}

#[test]
fn analysis_receipt_detects_catalog_claim_tampering() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    let captured = run(
        &root,
        &["capture", "--provider", "synthetic", "--id", "claim-tamper"],
    );
    assert_eq!(captured.status.code(), Some(0), "{}", stderr(&captured));
    let analyzed = run(&root, &["analyze", "claim-tamper"]);
    assert_eq!(analyzed.status.code(), Some(0), "{}", stderr(&analyzed));

    let catalog_path = root.join("claim-tamper/artifact-index/health.json");
    let mut catalog: Value =
        serde_json::from_slice(&std::fs::read(&catalog_path).expect("health catalog record"))
            .expect("catalog JSON");
    catalog["producer"] = serde_json::json!("tampered-producer");
    std::fs::write(
        &catalog_path,
        serde_json::to_vec_pretty(&catalog).expect("serialize tampered catalog"),
    )
    .expect("tamper catalog claim");

    let validated = run(&root, &["validate", "claim-tamper", "--deep"]);
    assert_eq!(validated.status.code(), Some(1));
    assert!(
        json_stdout(&validated)["error"]["message"]
            .as_str()
            .expect("error message")
            .contains("does not exactly match the catalog")
    );
}

#[test]
fn comparison_with_nonvalid_session_is_inconclusive_without_a_hotspot_artifact() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    complete_synthetic(&root, "compare-valid", 8);
    create_invalid_synthetic_session(&root, "compare-invalid");
    let analyzed = run(&root, &["analyze", "compare-invalid"]);
    assert_eq!(analyzed.status.code(), Some(11), "{}", stderr(&analyzed));
    let converted = run(
        &root,
        &["convert", "compare-invalid", "--format", "perfetto-json"],
    );
    assert_eq!(converted.status.code(), Some(11), "{}", stderr(&converted));

    let compared = run(
        &root,
        &[
            "compare",
            "compare-valid",
            "compare-invalid",
            "--policy",
            "default",
        ],
    );
    assert_eq!(
        compared.status.code(),
        Some(13),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&compared.stdout),
        stderr(&compared)
    );
    let compared = json_stdout(&compared);
    assert_eq!(compared["result"]["verdict"], "inconclusive");
    assert_eq!(compared["result"]["inconclusive_allowed"], false);
    assert!(
        compared["result"]["report"]["reasons"]
            .as_array()
            .expect("comparison reasons")
            .iter()
            .any(|reason| reason == "quantitative_hotspots_unavailable_for_nonvalid_input")
    );
}

#[test]
fn canonical_and_c_wire_normalization_are_strict_and_streaming() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");

    let created = run(&root, &["session", "create", "--id", "normalize-canonical"]);
    assert_eq!(created.status.code(), Some(0), "{}", stderr(&created));
    stage_normalize_capture_config(&root, "normalize-canonical");
    let canonical = concat!(
        "{\"schema\":\"t32perf.observation/v1\",\"session_id\":\"normalize-canonical\",\"encoding\":\"ndjson\",\"time_unit\":\"ns\",\"time_origin\":\"session_relative\",\"properties\":{\"capture_mode\":\"fixture\"}}\n",
        "{\"type\":\"DefineContext\",\"id\":\"task-main\",\"kind\":\"task\",\"name\":\"Main\",\"core_id\":0}\n",
        "{\"source_id\":\"raw\",\"source_seq\":0,\"quality\":\"exact\",\"type\":\"Instant\",\"ts_ns\":0,\"core_id\":0,\"context_id\":\"task-main\",\"name\":\"boot\"}\n",
    );
    let canonical_config = serde_json::to_vec(&serde_json::json!({
        "schema": "t32perf.normalize-config/v1",
        "mode": "single_source",
        "source": {
            "adapter": "canonical_ndjson_v1",
            "source_id": "canonical-input",
            "limits": {"max_line_bytes": 4096, "max_records": 16}
        },
        "output_limits": {"max_line_bytes": 4096, "max_records": 16}
    }))
    .expect("serialize config");
    stage_and_ingest_typed(
        &root,
        "normalize-canonical",
        (
            "raw.jsonl",
            "raw-input",
            "raw_observations",
            "capture/raw.jsonl",
            "application/x-ndjson",
        ),
        canonical.as_bytes(),
    );
    stage_and_ingest_typed(
        &root,
        "normalize-canonical",
        (
            "normalize.json",
            "normalize-config",
            "normalization_config",
            "capture/normalize.json",
            "application/json",
        ),
        &canonical_config,
    );
    let normalized = run(
        &root,
        &[
            "normalize",
            "normalize-canonical",
            "--input-artifact",
            "raw-input",
            "--config-artifact",
            "normalize-config",
        ],
    );
    assert_eq!(
        normalized.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&normalized.stdout),
        stderr(&normalized)
    );
    let normalized = json_stdout(&normalized);
    assert_eq!(normalized["result"]["observation_count"], 1);
    assert_eq!(
        normalized["result"]["artifact"]["input_artifact_ids"],
        serde_json::json!(["raw-input", "normalize-config", "capture-config"])
    );
    let output = std::fs::read_to_string(
        root.join("normalize-canonical")
            .join("normalized")
            .join("observations.ndjson"),
    )
    .expect("normalized canonical output");
    assert_eq!(output.lines().count(), 3);
    let output_header: Value =
        serde_json::from_str(output.lines().next().expect("output header")).expect("header JSON");
    assert_eq!(output_header["properties"]["capture_mode"], "fixture");
    assert_eq!(
        output_header["properties"]["normalization_schema"],
        "t32perf.normalize-config/v1"
    );

    let created = run(&root, &["session", "create", "--id", "normalize-wire"]);
    assert_eq!(created.status.code(), Some(0), "{}", stderr(&created));
    stage_normalize_capture_config(&root, "normalize-wire");
    let wire = wire_record(1, 0, 0, 100, 7, 9, b"boot");
    let wire_config = serde_json::to_vec(&serde_json::json!({
        "schema": "t32perf.normalize-config/v1",
        "mode": "single_source",
        "source": {
            "adapter": "c_wire_v1",
            "wire_version": 1,
            "source_id": "sdk",
            "core_id": 0,
            "clock": {
                "domain_id": "sdk-clock",
                "frequency_hz": {"numerator": 1_000_000, "denominator": 1},
                "wrap": {"modulus": 4_294_967_296_u64, "max_forward_ticks": 1_000_000}
            },
            "origin": {"mode": "first_record", "session_ns": 0},
            "limits": {"max_payload_bytes": 256, "max_records": 16}
        },
        "output_limits": {"max_line_bytes": 4096, "max_records": 32}
    }))
    .expect("serialize config");
    stage_and_ingest_typed(
        &root,
        "normalize-wire",
        (
            "raw.bin",
            "wire-input",
            "raw_sdk_wire",
            "capture/raw.bin",
            "application/octet-stream",
        ),
        &wire,
    );
    stage_and_ingest_typed(
        &root,
        "normalize-wire",
        (
            "normalize.json",
            "normalize-config",
            "normalization_config",
            "capture/normalize.json",
            "application/json",
        ),
        &wire_config,
    );
    let normalized = run(
        &root,
        &[
            "normalize",
            "normalize-wire",
            "--input-artifact",
            "wire-input",
            "--config-artifact",
            "normalize-config",
        ],
    );
    assert_eq!(normalized.status.code(), Some(0), "{}", stderr(&normalized));
    assert_eq!(json_stdout(&normalized)["result"]["observation_count"], 1);
}

#[test]
fn mapped_c_wire_normalize_derives_dictionary_and_reuses_mapping_across_sources() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    let mapping = serde_json::to_vec(&serde_json::json!({
        "schema": "t32perf.c-wire-counter-mapping/v1",
        "contexts": [{
            "wire_context_id": 7,
            "context_id": "task:control",
            "name": "control-task",
            "kind": "task",
            "core_id": 0,
            "priority": 7
        }],
        "counters": [{
            "event_id": 42,
            "counter_id": "heap:primary:current",
            "name": "Heap current allocation",
            "unit": "bytes",
            "description": "Current allocated bytes for the primary allocator.",
            "semantic": CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES,
            "subject": CounterSubject::Allocator { allocator_id: "primary".to_owned() }
        }]
    }))
    .expect("serialize counter mapping");
    let mapping_sha256 = encode_hex(Sha256::digest(&mapping).as_ref());
    let derived_mapping_id = format!("c-wire-counter-map-{mapping_sha256}");

    let prepare_capture = |session_id: &str| {
        let created = run(&root, &["session", "create", "--id", session_id]);
        assert_eq!(created.status.code(), Some(0), "{}", stderr(&created));
        stage_and_ingest_typed(
            &root,
            session_id,
            (
                "counter-mapping.json",
                "counter-mapping-source",
                "c_wire_counter_mapping_source",
                "capture/counter-mapping.json",
                "application/json",
            ),
            &mapping,
        );
        stage_and_ingest_typed(
            &root,
            session_id,
            (
                "instrumentation-overhead.json",
                "instrumentation-overhead",
                "instrumentation_overhead",
                "capture/instrumentation-overhead.json",
                "application/json",
            ),
            b"{}\n",
        );
        let mut capture_config = external_capture_config(session_id);
        capture_config.instrumentation = Some(CaptureInstrumentationConfig {
            method: "t32perf-c-wire/v1".to_owned(),
            transport: "shared-memory-ring-buffer/v1".to_owned(),
            overhead: CaptureInstrumentationOverhead {
                measurement_method: "controlled-paired-run/v1".to_owned(),
                baseline_duration_ns: 100,
                instrumented_duration_ns: 110,
                emitted_event_count: 1,
                evidence_artifact_id: "instrumentation-overhead".to_owned(),
            },
        });
        capture_config.adapter_parameters.insert(
            "c_wire.counter_mapping_artifact_id".to_owned(),
            serde_json::json!("counter-mapping-source"),
        );
        capture_config.adapter_parameters.insert(
            "c_wire.counter_mapping_sha256".to_owned(),
            serde_json::json!(mapping_sha256),
        );
        let capture_config =
            serde_json::to_vec(&capture_config).expect("serialize mapped capture config");
        stage_and_ingest_typed_with_inputs(
            &root,
            session_id,
            (
                "capture-config.json",
                "capture-config",
                "capture_config",
                "capture/capture-config.json",
                "application/json",
            ),
            &capture_config,
            &["instrumentation-overhead"],
        );
    };

    prepare_capture("normalize-wire-mapped");
    let wire = wire_record(4, 0, 1, 0, 7, 42, &123_i64.to_le_bytes());
    stage_and_ingest_typed(
        &root,
        "normalize-wire-mapped",
        (
            "raw.bin",
            "wire-input",
            "raw_sdk_wire",
            "capture/raw.bin",
            "application/octet-stream",
        ),
        &wire,
    );
    let config = serde_json::to_vec(&serde_json::json!({
        "schema": "t32perf.normalize-config/v1",
        "mode": "single_source",
        "source": {
            "adapter": "c_wire_v1",
            "wire_version": 1,
            "source_id": "sdk",
            "core_id": 0,
            "clock": {
                "domain_id": "sdk-clock",
                "frequency_hz": {"numerator": 1_000_000_000, "denominator": 1}
            },
            "origin": {"mode": "explicit", "ticks": 0, "session_ns": 0},
            "counter_mapping_artifact_id": "counter-mapping-source",
            "limits": {"max_payload_bytes": 256, "max_records": 16}
        },
        "output_limits": {"max_line_bytes": 4096, "max_records": 32}
    }))
    .unwrap();
    stage_and_ingest_typed(
        &root,
        "normalize-wire-mapped",
        (
            "normalize.json",
            "normalize-config",
            "normalization_config",
            "capture/normalize.json",
            "application/json",
        ),
        &config,
    );
    let normalized = run(
        &root,
        &[
            "normalize",
            "normalize-wire-mapped",
            "--input-artifact",
            "wire-input",
            "--config-artifact",
            "normalize-config",
        ],
    );
    assert_eq!(
        normalized.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&normalized.stdout),
        stderr(&normalized)
    );
    let normalized = json_stdout(&normalized);
    assert_eq!(normalized["result"]["observation_count"], 1);
    assert_eq!(
        normalized["result"]["artifact"]["input_artifact_ids"],
        serde_json::json!([
            "wire-input",
            "normalize-config",
            "capture-config",
            "counter-mapping-source",
            derived_mapping_id
        ])
    );
    let output =
        std::fs::read_to_string(root.join("normalize-wire-mapped/normalized/observations.ndjson"))
            .unwrap();
    let records = output
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        records[0]["properties"]["c_wire_counter_semantics"],
        "deployment_mapping"
    );
    assert_eq!(records[1]["type"], "DefineContext");
    assert_eq!(records[1]["id"], "task:control");
    assert_eq!(records[2]["type"], "DefineCounter");
    assert_eq!(records[2]["id"], "heap:primary:current");
    assert_eq!(
        records[2]["semantic"],
        CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES
    );
    assert_eq!(records[3]["context_id"], "task:control");
    assert_eq!(records[3]["counter_id"], "heap:primary:current");
    let artifact_root = ArtifactRoot::open(&root, SessionLimits::default()).unwrap();
    let session = artifact_root
        .session(&SessionId::new("normalize-wire-mapped").unwrap())
        .unwrap();
    let derived = session
        .registered_artifacts(true)
        .unwrap()
        .into_iter()
        .find(|artifact| artifact.id == derived_mapping_id)
        .expect("derived counter mapping");
    assert_eq!(derived.kind, "c_wire_counter_mapping");
    assert_eq!(derived.producer, "t32perf-c-wire-mapping/v1");
    assert_eq!(
        derived.input_artifact_ids,
        ["counter-mapping-source", "capture-config"]
    );

    prepare_capture("normalize-wire-mapped-multi");
    for (name, ticks, value) in [("left", 0_u64, 10_i64), ("right", 1, 20)] {
        stage_and_ingest_typed(
            &root,
            "normalize-wire-mapped-multi",
            (
                &format!("{name}.bin"),
                &format!("{name}-input"),
                "raw_sdk_wire",
                &format!("capture/{name}.bin"),
                "application/octet-stream",
            ),
            &wire_record(4, 0, 1, ticks, 7, 42, &value.to_le_bytes()),
        );
    }
    let config = serde_json::to_vec(&serde_json::json!({
        "schema": "t32perf.normalize-config/v1",
        "mode": "multi_source",
        "sources": [
            {
                "input_artifact_id": "left-input",
                "clock_domain": "sdk-clock",
                "order": "reject_ambiguous_ties",
                "source": {
                    "adapter": "c_wire_v1",
                    "wire_version": 1,
                    "source_id": "left-sdk",
                    "core_id": 0,
                    "clock": {"domain_id": "sdk-clock", "frequency_hz": {"numerator": 1000000000, "denominator": 1}},
                    "origin": {"mode": "explicit", "ticks": 0, "session_ns": 0},
                    "counter_mapping_artifact_id": "counter-mapping-source",
                    "limits": {"max_payload_bytes": 256, "max_records": 16}
                }
            },
            {
                "input_artifact_id": "right-input",
                "clock_domain": "sdk-clock",
                "order": "reject_ambiguous_ties",
                "source": {
                    "adapter": "c_wire_v1",
                    "wire_version": 1,
                    "source_id": "right-sdk",
                    "core_id": 0,
                    "clock": {"domain_id": "sdk-clock", "frequency_hz": {"numerator": 1000000000, "denominator": 1}},
                    "origin": {"mode": "explicit", "ticks": 0, "session_ns": 0},
                    "counter_mapping_artifact_id": "counter-mapping-source",
                    "limits": {"max_payload_bytes": 256, "max_records": 16}
                }
            }
        ],
        "output_limits": {"max_line_bytes": 4096, "max_records": 32}
    }))
    .unwrap();
    stage_and_ingest_typed(
        &root,
        "normalize-wire-mapped-multi",
        (
            "normalize.json",
            "normalize-config",
            "normalization_config",
            "capture/normalize.json",
            "application/json",
        ),
        &config,
    );
    let normalized = run(
        &root,
        &[
            "normalize",
            "normalize-wire-mapped-multi",
            "--config-artifact",
            "normalize-config",
        ],
    );
    assert_eq!(normalized.status.code(), Some(0), "{}", stderr(&normalized));
    assert_eq!(json_stdout(&normalized)["result"]["observation_count"], 2);
    let session = artifact_root
        .session(&SessionId::new("normalize-wire-mapped-multi").unwrap())
        .unwrap();
    assert_eq!(
        session
            .registered_artifacts(true)
            .unwrap()
            .iter()
            .filter(|artifact| artifact.id == derived_mapping_id)
            .count(),
        1
    );
}

#[test]
fn multi_source_normalization_merges_large_canonical_streams_and_fails_closed() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    const PER_SOURCE: u64 = 10_000;

    let left = canonical_normalize_input(
        "normalize-multi",
        "left-source",
        "left-function",
        "left",
        0,
        2,
        PER_SOURCE,
    );
    let right = canonical_normalize_input(
        "normalize-multi",
        "right-source",
        "right-function",
        "right",
        1,
        2,
        PER_SOURCE,
    );
    prepare_multi_normalize_session(
        &root,
        "normalize-multi",
        &left,
        &right,
        "session",
        2 * PER_SOURCE + 3,
    );
    let normalized = run(
        &root,
        &[
            "normalize",
            "normalize-multi",
            "--config-artifact",
            "normalize-config",
        ],
    );
    assert_eq!(normalized.status.code(), Some(0), "{}", stderr(&normalized));
    let normalized = json_stdout(&normalized);
    assert_eq!(normalized["result"]["mode"], "multi_source");
    assert_eq!(normalized["result"]["adapter"], "multi_source_v1");
    assert_eq!(normalized["result"]["observation_count"], 2 * PER_SOURCE);
    assert_eq!(
        normalized["result"]["artifact"]["input_artifact_ids"],
        serde_json::json!([
            "left-input",
            "right-input",
            "normalize-config",
            "capture-config"
        ])
    );
    let output =
        std::fs::read_to_string(root.join("normalize-multi/normalized/observations.ndjson"))
            .expect("multi-source canonical output");
    let records = output.lines().collect::<Vec<_>>();
    assert_eq!(records.len() as u64, 1 + 2 + 2 * PER_SOURCE);
    let header: Value = serde_json::from_str(records[0]).expect("multi-source header");
    assert_eq!(
        header["properties"]["normalization_sources"]
            .as_array()
            .expect("source contracts")
            .len(),
        2
    );
    let first: Value = serde_json::from_str(records[3]).expect("first observation");
    let second: Value = serde_json::from_str(records[4]).expect("second observation");
    assert_eq!(first["ts_ns"], 0);
    assert_eq!(second["ts_ns"], 1);

    let conflict_left = canonical_normalize_input(
        "normalize-conflict",
        "left-source",
        "shared-function",
        "left-name",
        0,
        2,
        1,
    );
    let conflict_right = canonical_normalize_input(
        "normalize-conflict",
        "right-source",
        "shared-function",
        "right-name",
        1,
        2,
        1,
    );
    prepare_multi_normalize_session(
        &root,
        "normalize-conflict",
        &conflict_left,
        &conflict_right,
        "session",
        8,
    );
    let conflict = run(
        &root,
        &[
            "normalize",
            "normalize-conflict",
            "--config-artifact",
            "normalize-config",
        ],
    );
    assert_eq!(conflict.status.code(), Some(1));
    assert!(
        json_stdout(&conflict)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("dictionary definition conflicts")
    );
    assert_normalize_failed_without_output(&root, "normalize-conflict");

    let clock_left = canonical_normalize_input(
        "normalize-clock",
        "left-source",
        "left-function",
        "left",
        0,
        2,
        1,
    );
    let clock_right = canonical_normalize_input(
        "normalize-clock",
        "right-source",
        "right-function",
        "right",
        1,
        2,
        1,
    );
    prepare_multi_normalize_session(
        &root,
        "normalize-clock",
        &clock_left,
        &clock_right,
        "other-clock",
        8,
    );
    let clock = run(
        &root,
        &[
            "normalize",
            "normalize-clock",
            "--config-artifact",
            "normalize-config",
        ],
    );
    assert_eq!(clock.status.code(), Some(1));
    assert!(
        json_stdout(&clock)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("does not match declared")
    );
    assert_normalize_failed_without_output(&root, "normalize-clock");

    let tie_left = canonical_normalize_input(
        "normalize-tie",
        "left-source",
        "left-function",
        "left",
        0,
        1,
        1,
    );
    let tie_right = canonical_normalize_input(
        "normalize-tie",
        "right-source",
        "right-function",
        "right",
        0,
        1,
        1,
    );
    prepare_multi_normalize_session(&root, "normalize-tie", &tie_left, &tie_right, "session", 8);
    let tie = run(
        &root,
        &[
            "normalize",
            "normalize-tie",
            "--config-artifact",
            "normalize-config",
        ],
    );
    assert_eq!(tie.status.code(), Some(1));
    assert!(
        json_stdout(&tie)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("ambiguous cross-source order")
    );
    assert_normalize_failed_without_output(&root, "normalize-tie");
}

#[test]
fn explicit_csv_normalization_handles_large_input_with_bounded_output() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    let created = run(&root, &["session", "create", "--id", "normalize-csv"]);
    assert_eq!(created.status.code(), Some(0), "{}", stderr(&created));
    stage_normalize_capture_config(&root, "normalize-csv");

    const RECORDS: u64 = 20_000;
    let mut csv = String::from("tick,seq,event,core,context,name,ignored\n");
    for sequence in 0..RECORDS {
        csv.push_str(&format!(
            "{sequence},{sequence},instant,0,task-main,event-{sequence},unused\n"
        ));
    }
    let config = serde_json::to_vec(&serde_json::json!({
        "schema": "t32perf.normalize-config/v1",
        "mode": "single_source",
        "source": {
            "adapter": "explicit_csv_v1",
            "source_id": "mapped-csv",
            "columns": [
                {"field": "timestamp_ticks", "column": "tick"},
                {"field": "source_sequence", "column": "seq"},
                {"field": "event_type", "column": "event"},
                {"field": "core_id", "column": "core"},
                {"field": "context_id", "column": "context"},
                {"field": "name", "column": "name"}
            ],
            "ignored_columns": ["ignored"],
            "clock": {
                "domain_id": "csv-clock",
                "frequency_hz": {"numerator": 1_000_000_000_u64, "denominator": 1}
            },
            "origin": {"mode": "explicit", "ticks": 0, "session_ns": 0},
            "quality": "exact",
            "limits": {"max_line_bytes": 4096, "max_records": RECORDS + 1}
        },
        "output_limits": {"max_line_bytes": 4096, "max_records": RECORDS + 1}
    }))
    .expect("serialize config");
    stage_and_ingest_typed(
        &root,
        "normalize-csv",
        (
            "raw.csv",
            "csv-input",
            "raw_csv",
            "capture/raw.csv",
            "text/csv",
        ),
        csv.as_bytes(),
    );
    stage_and_ingest_typed(
        &root,
        "normalize-csv",
        (
            "normalize.json",
            "normalize-config",
            "normalization_config",
            "capture/normalize.json",
            "application/json",
        ),
        &config,
    );
    let normalized = run(
        &root,
        &[
            "normalize",
            "normalize-csv",
            "--input-artifact",
            "csv-input",
            "--config-artifact",
            "normalize-config",
        ],
    );
    assert_eq!(normalized.status.code(), Some(0), "{}", stderr(&normalized));
    assert_eq!(
        json_stdout(&normalized)["result"]["observation_count"],
        RECORDS
    );
    let output = std::fs::read_to_string(
        root.join("normalize-csv")
            .join("normalized")
            .join("observations.ndjson"),
    )
    .expect("normalized CSV output");
    assert_eq!(output.lines().count() as u64, RECORDS + 1);
}

#[test]
fn unsupported_normalization_adapter_fails_closed_and_is_durable() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    let created = run(
        &root,
        &["session", "create", "--id", "normalize-unsupported"],
    );
    assert_eq!(created.status.code(), Some(0), "{}", stderr(&created));
    stage_normalize_capture_config(&root, "normalize-unsupported");
    let config = serde_json::to_vec(&serde_json::json!({
        "schema": "t32perf.normalize-config/v1",
        "mode": "single_source",
        "source": {"adapter": "trace32-export-ascii"},
        "output_limits": {"max_line_bytes": 4096, "max_records": 16}
    }))
    .expect("serialize config");
    stage_and_ingest_typed(
        &root,
        "normalize-unsupported",
        (
            "raw.txt",
            "raw-input",
            "raw_trace",
            "capture/raw.txt",
            "text/plain",
        ),
        b"undocumented trace format\n",
    );
    stage_and_ingest_typed(
        &root,
        "normalize-unsupported",
        (
            "normalize.json",
            "normalize-config",
            "normalization_config",
            "capture/normalize.json",
            "application/json",
        ),
        &config,
    );
    let normalized = run(
        &root,
        &[
            "normalize",
            "normalize-unsupported",
            "--input-artifact",
            "raw-input",
            "--config-artifact",
            "normalize-config",
        ],
    );
    assert_eq!(normalized.status.code(), Some(20));
    assert_eq!(json_stdout(&normalized)["error"]["code"], "UNSUPPORTED");
    let status = run(&root, &["session", "status", "normalize-unsupported"]);
    let status = json_stdout(&status);
    assert_eq!(status["result"]["state"]["state"], "failed");
    assert_eq!(
        status["result"]["state"]["error"]["code"],
        "NORMALIZE_FAILED"
    );
    assert!(
        !root
            .join("normalize-unsupported")
            .join("normalized")
            .join("observations.ndjson")
            .exists()
    );
}

#[derive(Clone, Copy)]
enum AttestationMutation {
    None,
    TamperedPayload,
    TamperedSignature,
    WrongObservationDigest,
    WrongRequestDigest,
    WrongNonce,
    CapabilityAboveCeiling,
    WrongCaptureConfigDigest,
    CaptureConfigOutsidePolicy,
    MissingCaptureConfigClaim,
}

fn prepare_external_observations(root: &Path, session_id: &str) {
    let created = run(
        root,
        &[
            "session",
            "create",
            "--id",
            session_id,
            "--request",
            r#"{"provider":"trace32","mode":"etm"}"#,
        ],
    );
    assert_eq!(created.status.code(), Some(0), "{}", stderr(&created));
    let capture_config = external_capture_config(session_id);
    stage_and_ingest_typed(
        root,
        session_id,
        (
            "capture-config.json",
            "capture-config",
            "capture_config",
            "capture/capture-config.json",
            "application/json",
        ),
        &serde_json::to_vec_pretty(&capture_config).expect("serialize capture config"),
    );
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("golden")
        .join("observations.jsonl");
    let bytes = std::fs::read(source).expect("read canonical fixture");
    stage_and_ingest_typed(
        root,
        session_id,
        (
            "observations.jsonl",
            "observations",
            "observations",
            "normalized/observations.ndjson",
            "application/x-ndjson",
        ),
        &bytes,
    );
}

fn external_capture_config(session_id: &str) -> CaptureConfigDocument {
    CaptureConfigDocument {
        schema: CaptureConfigSchemaVersion,
        session_id: session_id.to_owned(),
        provider: "trace32".to_owned(),
        adapter: AdapterInfo {
            id: "lab-adapter".to_owned(),
            version: "1".to_owned(),
        },
        mode: "etm".to_owned(),
        covered_cores: vec![0],
        sink: CaptureSinkConfig {
            kind: "probe_buffer".to_owned(),
            id: "powertrace-0".to_owned(),
            capacity_bytes: Some(1_048_576),
            stream_destination_identity: None,
        },
        timestamp: CaptureTimestampConfig {
            enabled: true,
            clock_id: Some("trace".to_owned()),
        },
        filters: Vec::new(),
        trigger: CaptureTriggerConfig {
            kind: "manual".to_owned(),
            pre_trigger_ns: Some(250_000),
            post_trigger_ns: Some(750_000),
            condition_identity: None,
        },
        duration: CaptureDurationConfig {
            duration_ns: Some(1_000_000),
            observation_limit: None,
        },
        workload_identity: "golden-workload/v1".to_owned(),
        initial_target_state: InitialTargetState::Halted,
        rtos_awareness: CaptureRtosAwarenessConfig {
            kind: "none".to_owned(),
            metadata_artifact_ids: Vec::new(),
        },
        instrumentation: None,
        adapter_parameters: BTreeMap::from([
            (
                "trace_source_identity".to_owned(),
                serde_json::json!("etm-core-0"),
            ),
            (
                "firmware.elf_sha256".to_owned(),
                serde_json::json!("c".repeat(64)),
            ),
        ]),
    }
}

fn stage_signed_capture_attestation(
    root: &Path,
    session_id: &str,
    mutation: AttestationMutation,
) -> std::path::PathBuf {
    let artifact_root =
        ArtifactRoot::open(root, SessionLimits::default()).expect("open artifact root");
    let session = artifact_root
        .session(&SessionId::new(session_id).expect("Session ID"))
        .expect("open Session");
    let state = session.read_state().expect("read Session state");
    assert_eq!(state.status, SessionStatus::Captured);
    let artifacts = session.registered_artifacts(true).expect("read artifacts");
    let observations = artifacts
        .iter()
        .find(|artifact| artifact.id == "observations")
        .expect("observations artifact");
    let capture_config = artifacts
        .iter()
        .find(|artifact| artifact.id == "capture-config")
        .expect("capture config artifact");
    let capture_config_document = external_capture_config(session_id);
    let configuration_digest = Sha256::digest(
        capture_config_document
            .configuration_identity_bytes()
            .expect("serialize capture config identity"),
    );
    let configuration_sha256 =
        Sha256Digest::new(encode_hex(configuration_digest.as_ref())).expect("configuration digest");
    let config_claim = CaptureConfigArtifactClaim {
        artifact_id: capture_config.id.clone(),
        sha256: if matches!(mutation, AttestationMutation::WrongCaptureConfigDigest) {
            Sha256Digest::new("9".repeat(64)).expect("wrong capture config digest")
        } else {
            capture_config.sha256.clone()
        },
        configuration_sha256: if matches!(mutation, AttestationMutation::WrongCaptureConfigDigest) {
            Sha256Digest::new("8".repeat(64)).expect("wrong configuration digest")
        } else {
            configuration_sha256.clone()
        },
    };
    let request_sha256 = session.request_sha256().expect("request digest");

    let exact = MetricSupportEntry::new(MetricSupportLevel::Exact);
    let unavailable = MetricSupportEntry {
        support: MetricSupportLevel::Unavailable,
        reasons: vec!["not captured by this mode".to_owned()],
    };
    let claimed_capabilities = CaptureCapabilities {
        function_events: exact.clone(),
        context_switches: exact.clone(),
        interrupt_events: unavailable.clone(),
        samples: unavailable.clone(),
        custom_events: unavailable.clone(),
        counters: exact.clone(),
    };
    let mut ceiling = CaptureCapabilities {
        function_events: exact.clone(),
        context_switches: exact.clone(),
        interrupt_events: exact.clone(),
        samples: exact.clone(),
        custom_events: exact.clone(),
        counters: exact,
    };
    if matches!(mutation, AttestationMutation::CapabilityAboveCeiling) {
        ceiling.function_events = unavailable.clone();
    }
    let target = TargetInfo {
        architecture: Some("armv8-m".to_owned()),
        device: Some("golden-mcu".to_owned()),
        board: Some("golden-board".to_owned()),
        core_count: Some(1),
        properties: BTreeMap::new(),
    };
    let trace32 = Trace32Info {
        build: Some("R.2026.02".to_owned()),
        probe: Some("PowerTrace".to_owned()),
        architecture_package: Some("ARM".to_owned()),
        properties: BTreeMap::new(),
    };
    let clocks = vec![ClockInfo {
        id: "trace".to_owned(),
        frequency_hz: Some(100_000_000),
        source: Some("target".to_owned()),
        properties: BTreeMap::new(),
    }];
    let receipt = CaptureReceipt {
        schema: CaptureReceiptSchemaVersion,
        session_id: session_id.to_owned(),
        provider: "trace32".to_owned(),
        mode: "etm".to_owned(),
        adapter: AdapterInfo {
            id: "lab-adapter".to_owned(),
            version: "1".to_owned(),
        },
        target: Some(target.clone()),
        trace32: Some(trace32.clone()),
        firmware: FirmwareInfo {
            elf_path: None,
            elf_sha256: Some(Sha256Digest::new("c".repeat(64)).expect("ELF digest")),
            build_id: Some("golden-build".to_owned()),
        },
        clocks: clocks.clone(),
        covered_cores: vec![0],
        capabilities: claimed_capabilities,
        health_observations: Vec::new(),
        request_sha256: if matches!(mutation, AttestationMutation::WrongRequestDigest) {
            Sha256Digest::new("e".repeat(64)).expect("wrong request digest")
        } else {
            request_sha256
        },
        capture_config: (!matches!(mutation, AttestationMutation::MissingCaptureConfigClaim))
            .then(|| config_claim.clone()),
        controller_health: None,
        properties: BTreeMap::new(),
    };
    let mut payload = CaptureAttestationPayload {
        schema: CaptureAttestationSchemaVersion,
        key_id: "lab-key".to_owned(),
        nonce: if matches!(mutation, AttestationMutation::WrongNonce) {
            "wrong-operation".to_owned()
        } else {
            state.operation_id
        },
        receipt,
        observation_artifact_id: "observations".to_owned(),
        observation_sha256: if matches!(mutation, AttestationMutation::WrongObservationDigest) {
            Sha256Digest::new("d".repeat(64)).expect("wrong observation digest")
        } else {
            observations.sha256.clone()
        },
        capture_config: (!matches!(mutation, AttestationMutation::MissingCaptureConfigClaim))
            .then_some(config_claim),
        controller_health: None,
    };
    let signing_key = SigningKey::from_bytes(&[17_u8; 32]);
    let signature = signing_key.sign(&payload.signing_bytes().expect("signing payload"));
    let mut attestation = CaptureAttestation {
        payload: payload.clone(),
        signature_ed25519: encode_hex(&signature.to_bytes()),
    };
    if matches!(mutation, AttestationMutation::TamperedPayload) {
        payload.receipt.mode = "sampling".to_owned();
        attestation.payload = payload;
    }
    if matches!(mutation, AttestationMutation::TamperedSignature) {
        let replacement = if attestation.signature_ed25519.starts_with('0') {
            "1"
        } else {
            "0"
        };
        attestation
            .signature_ed25519
            .replace_range(0..1, replacement);
    }
    let policy = CaptureTrustPolicy {
        schema: CaptureTrustPolicySchemaVersion,
        policy_id: "lab-policy".to_owned(),
        keys: vec![CaptureTrustKey {
            key_id: "lab-key".to_owned(),
            public_key_ed25519: encode_hex(&signing_key.verifying_key().to_bytes()),
            producer: "lab.trace32/v1".to_owned(),
            provider: "trace32".to_owned(),
            adapter: AdapterInfo {
                id: "lab-adapter".to_owned(),
                version: "1".to_owned(),
            },
            allowed_modes: vec!["etm".to_owned()],
            target,
            trace32: Some(trace32),
            clocks,
            allowed_cores: vec![0],
            allowed_firmware_elf_sha256: vec![
                Sha256Digest::new("c".repeat(64)).expect("ELF allowlist digest"),
            ],
            capability_ceiling: ceiling,
            config_constraints: Some(CaptureConfigConstraints {
                allowed_sink_kinds: vec![if matches!(
                    mutation,
                    AttestationMutation::CaptureConfigOutsidePolicy
                ) {
                    "stream".to_owned()
                } else {
                    "probe_buffer".to_owned()
                }],
                allowed_sink_ids: vec!["powertrace-0".to_owned()],
                allowed_initial_target_states: vec![InitialTargetState::Halted],
                allowed_rtos_awareness_kinds: vec!["none".to_owned()],
                max_sink_capacity_bytes: Some(1_048_576),
                require_timestamp_enabled: Some(true),
                allowed_config_sha256: vec![configuration_sha256],
            }),
        }],
    };
    let staging = root.join(session_id).join("capture").join("staging");
    std::fs::write(
        staging.join("capture-attestation.json"),
        serde_json::to_vec_pretty(&attestation).expect("serialize attestation"),
    )
    .expect("stage capture attestation");
    let policy_path = root
        .parent()
        .expect("artifact-root parent")
        .join(format!("{session_id}-policy.json"));
    std::fs::write(
        &policy_path,
        serde_json::to_vec_pretty(&policy).expect("serialize policy"),
    )
    .expect("write capture trust policy");
    policy_path
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn complete_synthetic(root: &Path, id: &str, events: u64) {
    let capture = run(
        root,
        &[
            "capture",
            "--provider",
            "synthetic",
            "--id",
            id,
            "--events",
            &events.to_string(),
        ],
    );
    assert_eq!(capture.status.code(), Some(0), "{}", stderr(&capture));
    let analyze = run(root, &["analyze", id]);
    assert_eq!(analyze.status.code(), Some(0), "{}", stderr(&analyze));
    let convert = run(root, &["convert", id, "--format", "perfetto-json"]);
    assert_eq!(convert.status.code(), Some(0), "{}", stderr(&convert));
}

fn create_invalid_synthetic_session(root: &Path, id: &str) {
    create_synthetic_health_session(root, id, true, Vec::new());
}

fn create_degraded_synthetic_session(root: &Path, id: &str) {
    create_synthetic_health_session(
        root,
        id,
        false,
        vec![HealthObservation {
            code: "trace_gap".to_owned(),
            source: "synthetic-test".to_owned(),
            artifact_id: Some("observations".to_owned()),
            record: Some(1),
            start_ns: Some(10),
            end_ns: Some(11),
            evidence: BTreeMap::new(),
        }],
    );
}

fn create_synthetic_health_session(
    root: &Path,
    id: &str,
    mismatched_exit: bool,
    health_observations: Vec<HealthObservation>,
) {
    create_custom_synthetic_session(root, id, mismatched_exit, health_observations, None);
}

fn create_synthetic_resource_session(root: &Path, id: &str, counter_id: &str, values: &[f64]) {
    create_synthetic_resource_session_with_allocator(root, id, counter_id, "system", values);
}

fn create_synthetic_resource_session_with_allocator(
    root: &Path,
    id: &str,
    counter_id: &str,
    allocator_id: &str,
    values: &[f64],
) {
    create_custom_synthetic_session(
        root,
        id,
        false,
        Vec::new(),
        Some((counter_id, allocator_id, values)),
    );
}

fn create_custom_synthetic_session(
    root: &Path,
    id: &str,
    mismatched_exit: bool,
    health_observations: Vec<HealthObservation>,
    resource: Option<(&str, &str, &[f64])>,
) {
    let artifact_root =
        ArtifactRoot::open(root, SessionLimits::default()).expect("open artifact root");
    let request = serde_json::json!({"provider": "synthetic", "events": 4});
    let session = artifact_root
        .create_session_with_id(SessionId::new(id).expect("session ID"), &request)
        .expect("create session");
    let lock = session.try_lock().expect("lock session");
    session
        .transition(&lock, SessionStatus::Capturing, None)
        .expect("start capture");
    let capture_config_document = synthetic_config_document(id, 4);
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

    let mut dictionary = ObservationDictionary::new(id);
    dictionary.entries = vec![
        DictionaryEntry::DefineContext {
            id: "task-main".to_owned(),
            kind: ContextKind::Task,
            name: "Main".to_owned(),
            core_id: Some(0),
            priority: Some(1),
        },
        DictionaryEntry::DefineFunction {
            id: "root".to_owned(),
            name: "root".to_owned(),
            module: None,
            address: Some(0x1000),
            file: None,
            line: None,
        },
        DictionaryEntry::DefineFunction {
            id: "child".to_owned(),
            name: "child".to_owned(),
            module: None,
            address: Some(0x1100),
            file: None,
            line: None,
        },
    ];
    if let Some((counter_id, allocator_id, _)) = resource {
        dictionary.entries.push(DictionaryEntry::DefineCounter {
            id: counter_id.to_owned(),
            name: "Opaque allocator gauge".to_owned(),
            unit: Some("bytes".to_owned()),
            description: None,
            semantic: Some(
                CounterSemantic::new(CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES)
                    .expect("built-in semantic"),
            ),
            subject: Some(CounterSubject::Allocator {
                allocator_id: allocator_id.to_owned(),
            }),
        });
    }
    let artifact_writer = session
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
        .expect("create observations");
    let mut writer = NdjsonObservationWriter::new(
        artifact_writer,
        &ObservationStreamHeader::ndjson(id),
        &dictionary,
        LineLimits::default(),
    )
    .expect("open observation writer");
    let mut events = vec![
        ObservationEvent::ContextSwitch {
            ts_ns: 0,
            core_id: 0,
            prev_context_id: None,
            next_context_id: "task-main".to_owned(),
            reason: None,
        },
        ObservationEvent::FunctionEnter {
            ts_ns: 10,
            core_id: 0,
            context_id: "task-main".to_owned(),
            function_id: "root".to_owned(),
            frame_id: None,
        },
    ];
    if mismatched_exit {
        events.push(ObservationEvent::FunctionEnter {
            ts_ns: 20,
            core_id: 0,
            context_id: "task-main".to_owned(),
            function_id: "child".to_owned(),
            frame_id: None,
        });
    }
    if let Some((counter_id, _, values)) = resource {
        events.extend(
            values
                .iter()
                .enumerate()
                .map(|(index, value)| ObservationEvent::Counter {
                    ts_ns: 20 + i64::try_from(index).expect("resource timestamp"),
                    core_id: Some(0),
                    context_id: Some("task-main".to_owned()),
                    counter_id: counter_id.to_owned(),
                    value: *value,
                    args: BTreeMap::new(),
                }),
        );
    }
    events.push(ObservationEvent::FunctionExit {
        ts_ns: 30,
        core_id: 0,
        context_id: "task-main".to_owned(),
        function_id: "root".to_owned(),
        frame_id: None,
    });
    for (sequence, event) in events.into_iter().enumerate() {
        writer
            .write_observation(&Observation::new(
                "synthetic",
                sequence as u64,
                Quality::Exact,
                event,
            ))
            .expect("write observation");
    }
    let observations = session
        .commit_artifact(&lock, writer.finish().expect("finish observations"))
        .expect("commit observations");

    let exact = MetricSupportEntry::new(MetricSupportLevel::Exact);
    let receipt = CaptureReceipt {
        schema: CaptureReceiptSchemaVersion,
        session_id: id.to_owned(),
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
        health_observations,
        request_sha256: session.request_sha256().expect("request digest"),
        capture_config: Some(CaptureConfigArtifactClaim {
            artifact_id: capture_config.id.clone(),
            sha256: capture_config.sha256.clone(),
            configuration_sha256: capture_config_identity_digest(&capture_config_document),
        }),
        controller_health: None,
        properties: BTreeMap::from([(
            "observation_artifact_id".to_owned(),
            serde_json::json!("observations"),
        )]),
    };
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

fn synthetic_config_document(session_id: &str, observation_limit: u64) -> CaptureConfigDocument {
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
            observation_limit: Some(observation_limit),
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

fn capture_config_identity_digest(config: &CaptureConfigDocument) -> Sha256Digest {
    let digest = Sha256::digest(
        config
            .configuration_identity_bytes()
            .expect("serialize capture config identity"),
    );
    Sha256Digest::new(encode_hex(digest.as_ref())).expect("capture config identity digest")
}

fn stage_and_ingest(
    root: &Path,
    session_id: &str,
    staged_name: &str,
    artifact_id: &str,
    kind: &str,
    destination: &str,
    contents: &[u8],
) {
    stage_and_ingest_typed(
        root,
        session_id,
        (staged_name, artifact_id, kind, destination, "text/plain"),
        contents,
    );
}

fn elf_resource_fixture() -> Vec<u8> {
    let mut object = Object::new(BinaryFormat::Elf, Architecture::Arm, Endianness::Little);
    for (name, kind, size) in [
        (".text", SectionKind::Text, 64_u64),
        (".data", SectionKind::Data, 16),
        (".bss", SectionKind::UninitializedData, 24),
        (".dma_buffers", SectionKind::Data, 12),
    ] {
        let section = object.add_section(Vec::new(), name.as_bytes().to_vec(), kind);
        if kind.is_bss() {
            object.append_section_bss(section, size, 4);
        } else {
            object.append_section_data(section, &vec![0_u8; usize::try_from(size).unwrap()], 4);
        }
    }
    object.write().expect("generate ELF fixture")
}

fn stage_and_ingest_typed(
    root: &Path,
    session_id: &str,
    artifact: (&str, &str, &str, &str, &str),
    contents: &[u8],
) {
    let (staged_name, artifact_id, kind, destination, media_type) = artifact;
    let staging = root.join(session_id).join("capture").join("staging");
    std::fs::write(staging.join(staged_name), contents).expect("write staged input");
    let output = run(
        root,
        &[
            "session",
            "ingest",
            session_id,
            "--staged",
            staged_name,
            "--id",
            artifact_id,
            "--kind",
            kind,
            "--destination",
            destination,
            "--media-type",
            media_type,
        ],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

fn stage_and_ingest_typed_with_inputs(
    root: &Path,
    session_id: &str,
    artifact: (&str, &str, &str, &str, &str),
    contents: &[u8],
    input_artifact_ids: &[&str],
) {
    let (staged_name, artifact_id, kind, destination, media_type) = artifact;
    let staging = root.join(session_id).join("capture").join("staging");
    std::fs::write(staging.join(staged_name), contents).expect("write staged input");
    let mut command = cargo_bin_cmd!("t32perf");
    command.args([
        "--artifact-root",
        &root.to_string_lossy(),
        "--json",
        "session",
        "ingest",
        session_id,
        "--staged",
        staged_name,
        "--id",
        artifact_id,
        "--kind",
        kind,
        "--destination",
        destination,
        "--media-type",
        media_type,
    ]);
    for input in input_artifact_ids {
        command.args(["--input-artifact", input]);
    }
    let output = command.output().expect("run t32perf ingest");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

fn canonical_normalize_input(
    session_id: &str,
    source_id: &str,
    function_id: &str,
    function_name: &str,
    start_ns: i64,
    step_ns: i64,
    observations: u64,
) -> Vec<u8> {
    let header = ObservationStreamHeader::ndjson(session_id);
    let mut dictionary = ObservationDictionary::new(session_id);
    dictionary.entries.push(DictionaryEntry::DefineFunction {
        id: function_id.to_owned(),
        name: function_name.to_owned(),
        module: None,
        address: None,
        file: None,
        line: None,
    });
    let mut writer = NdjsonObservationWriter::new(
        Vec::new(),
        &header,
        &dictionary,
        LineLimits {
            max_records: observations + 2,
            ..LineLimits::default()
        },
    )
    .expect("canonical normalize writer");
    for sequence in 0..observations {
        let timestamp = start_ns + i64::try_from(sequence).unwrap() * step_ns;
        let observation = Observation::new(
            source_id,
            sequence,
            Quality::Exact,
            ObservationEvent::Instant {
                ts_ns: timestamp,
                core_id: Some(0),
                context_id: None,
                name: "tick".to_owned(),
                args: BTreeMap::new(),
            },
        );
        writer
            .write_observation(&observation)
            .expect("write canonical normalize observation");
    }
    writer.finish().expect("finish canonical normalize input")
}

fn prepare_multi_normalize_session(
    root: &Path,
    session_id: &str,
    left: &[u8],
    right: &[u8],
    right_clock_domain: &str,
    output_records: u64,
) {
    let created = run(root, &["session", "create", "--id", session_id]);
    assert_eq!(created.status.code(), Some(0), "{}", stderr(&created));
    stage_normalize_capture_config(root, session_id);
    stage_and_ingest_typed(
        root,
        session_id,
        (
            "left.jsonl",
            "left-input",
            "raw_observations",
            "capture/left.jsonl",
            "application/x-ndjson",
        ),
        left,
    );
    stage_and_ingest_typed(
        root,
        session_id,
        (
            "right.jsonl",
            "right-input",
            "raw_observations",
            "capture/right.jsonl",
            "application/x-ndjson",
        ),
        right,
    );
    let config = serde_json::to_vec(&serde_json::json!({
        "schema": "t32perf.normalize-config/v1",
        "mode": "multi_source",
        "sources": [
            {
                "input_artifact_id": "left-input",
                "clock_domain": "session",
                "order": "reject_ambiguous_ties",
                "source": {
                    "adapter": "canonical_ndjson_v1",
                    "source_id": "left-channel",
                    "limits": {
                        "max_line_bytes": 4096,
                        "max_records": output_records,
                        "max_dictionary_entries": 65_536,
                        "max_dictionary_bytes": 67_108_864
                    }
                }
            },
            {
                "input_artifact_id": "right-input",
                "clock_domain": right_clock_domain,
                "order": "reject_ambiguous_ties",
                "source": {
                    "adapter": "canonical_ndjson_v1",
                    "source_id": "right-channel",
                    "limits": {
                        "max_line_bytes": 4096,
                        "max_records": output_records,
                        "max_dictionary_entries": 65_536,
                        "max_dictionary_bytes": 67_108_864
                    }
                }
            }
        ],
        "output_limits": {
            "max_line_bytes": 4096,
            "max_records": output_records,
            "max_dictionary_entries": 65_536,
            "max_dictionary_bytes": 67_108_864
        }
    }))
    .expect("serialize multi-source config");
    stage_and_ingest_typed(
        root,
        session_id,
        (
            "normalize.json",
            "normalize-config",
            "normalization_config",
            "capture/normalize.json",
            "application/json",
        ),
        &config,
    );
}

fn assert_normalize_failed_without_output(root: &Path, session_id: &str) {
    let status = run(root, &["session", "status", session_id]);
    assert_eq!(status.status.code(), Some(0), "{}", stderr(&status));
    assert_eq!(json_stdout(&status)["result"]["state"]["state"], "failed");
    assert!(
        !root
            .join(session_id)
            .join("normalized/observations.ndjson")
            .exists()
    );
}

fn stage_normalize_capture_config(root: &Path, session_id: &str) {
    let config = serde_json::to_vec(&external_capture_config(session_id))
        .expect("serialize normalize capture config");
    stage_and_ingest_typed(
        root,
        session_id,
        (
            "capture-config.json",
            "capture-config",
            "capture_config",
            "capture/capture-config.json",
            "application/json",
        ),
        &config,
    );
}

fn wire_record(
    kind: u8,
    flags: u16,
    sequence: u32,
    ticks: u64,
    context: u32,
    event: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 + payload.len());
    bytes.extend_from_slice(b"T3PF");
    bytes.push(1);
    bytes.push(kind);
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.extend_from_slice(&ticks.to_le_bytes());
    bytes.extend_from_slice(&context.to_le_bytes());
    bytes.extend_from_slice(&event.to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
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
