use sha2::{Digest as _, Sha256};
use t32perf_model::Sha256Digest;
use t32perf_trace32::{
    HilFaultScenario, HilVerificationKind, HilVerificationVerdict, TargetAdapterAdmissionSnapshot,
    TargetAdapterAdmissionSnapshotSchemaVersion, TargetAdapterQualificationPolicy,
    TargetAdapterQualificationPolicySchemaVersion, TargetAdapterQualificationReceipt,
    TargetAdapterQualificationReceiptSchemaVersion, TargetAdapterScenario,
    parse_hil_verification_receipt, parse_target_adapter_admission_snapshot,
    parse_target_adapter_qualification_policy, parse_target_adapter_qualification_receipt,
    parse_target_adapter_qualification_trust_store, qualification_schema_documents,
    tc234l_build190766_candidate_profile, validate_target_adapter_qualification,
};

fn sha(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
    .unwrap()
}

fn digest(character: char) -> Sha256Digest {
    Sha256Digest::new(character.to_string().repeat(64)).unwrap()
}

fn hil_receipt() -> Vec<u8> {
    let roles = [
        "manifest",
        "health",
        "observations",
        "analysis_summary",
        "hotspots",
        "static_ram_report",
        "static_ram_config",
        "static_ram_source",
        "resource_source",
        "normalize_config",
    ];
    let categories = [
        "artifact_binding",
        "allocator",
        "stack",
        "static_ram",
        "trace_buffer",
        "clock_alignment",
        "call_depth",
        "analysis_summary",
    ];
    serde_json::to_vec(&serde_json::json!({
        "schema": "t32perf.hil-verification-receipt/v1",
        "source": "host-reconstructed-session-artifacts",
        "kind": "resources",
        "scenario": null,
        "board_id": "tc234l-board",
        "session_id": "hil-session-1",
        "driver_reference_sha256": digest('d'),
        "recovery_evidence": null,
        "tolerance": {"timestamp_absolute_ns": 0.0, "timestamp_relative": 0.0, "continuous_relative": 0.0, "continuous_absolute": 0.0, "integer_absolute": 0.0},
        "artifact_bindings": roles.into_iter().map(|role| serde_json::json!({"role": role, "artifact_id": if role == "manifest" { None } else { Some(format!("{role}-artifact")) }, "sha256": digest('a')})).collect::<Vec<_>>(),
        "checks": {"total": 8, "passed": 8, "failed": 0},
        "check_categories": categories.into_iter().map(|category| serde_json::json!({"category": category, "counts": {"total": 1, "passed": 1, "failed": 0}})).collect::<Vec<_>>(),
        "max_error": {"check": null, "absolute": 0.0, "relative": 0.0},
        "failure_count": 0,
        "failures": [],
        "failures_truncated": false,
        "verdict": "PASS"
    }))
    .unwrap()
}

fn qualification_receipt(hil: &[u8]) -> Vec<u8> {
    let candidate = tc234l_build190766_candidate_profile();
    serde_json::to_vec(&TargetAdapterQualificationReceipt {
        schema: TargetAdapterQualificationReceiptSchemaVersion::V1,
        adapter_id: candidate.adapter_id.clone(),
        adapter_version: candidate.adapter_version.clone(),
        candidate_profile_sha256: candidate.qualification_identity_digest().unwrap(),
        implementation_sha256: candidate.implementation_sha256.clone(),
        trace32_release: candidate.build_gate.trace32_release.clone(),
        trace32_build: candidate.build_gate.minimum_build,
        architecture_package: candidate.build_gate.architecture_package.clone(),
        target_identifier: candidate.target_identifier.clone(),
        probe_identifier: candidate.probe_identifier.clone(),
        firmware_elf_sha256: candidate.firmware_elf_sha256.clone(),
        t32mcp_version: "0.2.2".to_owned(),
        hil_verification_receipt_sha256: sha(hil),
    })
    .unwrap()
}

fn policy(qualification: &[u8], hil: &[u8]) -> TargetAdapterQualificationPolicy {
    let candidate = tc234l_build190766_candidate_profile();
    let mut qualified = candidate.clone();
    qualified.qualification_sha256 = Some(sha(qualification));
    TargetAdapterQualificationPolicy {
        schema: TargetAdapterQualificationPolicySchemaVersion::V1,
        policy_id: "tc234l-build190766-qualification".to_owned(),
        adapter_id: candidate.adapter_id.clone(),
        adapter_version: candidate.adapter_version.clone(),
        candidate_profile_sha256: candidate.qualification_identity_digest().unwrap(),
        qualified_profile_sha256: qualified.digest().unwrap(),
        implementation_sha256: candidate.implementation_sha256.clone(),
        firmware_elf_sha256: candidate.firmware_elf_sha256.clone(),
        trace32_release: candidate.build_gate.trace32_release.clone(),
        trace32_build: candidate.build_gate.minimum_build,
        architecture_package: candidate.build_gate.architecture_package.clone(),
        target_identifier: candidate.target_identifier.clone(),
        probe_identifier: candidate.probe_identifier.clone(),
        qualification_receipt_sha256: sha(qualification),
        hil_verification_receipt_sha256: sha(hil),
        board_id: "tc234l-board".to_owned(),
        t32mcp_version: "0.2.2".to_owned(),
        expected_hil_kind: HilVerificationKind::Resources,
        expected_hil_scenario: None,
        allowed_scenarios: vec![TargetAdapterScenario::Normal],
    }
}

fn snapshot(qualification: &[u8], hil: &[u8]) -> TargetAdapterAdmissionSnapshot {
    let candidate = tc234l_build190766_candidate_profile();
    let mut qualified = candidate.clone();
    qualified.qualification_sha256 = Some(sha(qualification));
    TargetAdapterAdmissionSnapshot {
        schema: TargetAdapterAdmissionSnapshotSchemaVersion::V1,
        policy_id: "tc234l-build190766-qualification".to_owned(),
        policy_sha256: digest('e'),
        hil_verification_receipt_sha256: sha(hil),
        qualification_receipt_sha256: sha(qualification),
        candidate_profile_sha256: candidate.qualification_identity_digest().unwrap(),
        qualified_profile_sha256: qualified.digest().unwrap(),
        implementation_sha256: candidate.implementation_sha256.clone(),
        firmware_elf_sha256: candidate.firmware_elf_sha256.clone(),
        t32mcp_version: "0.2.2".to_owned(),
        allowed_scenarios: vec![TargetAdapterScenario::Normal],
    }
}

#[test]
fn strict_hil_and_policy_authorize_the_exact_candidate() {
    let hil_bytes = hil_receipt();
    let qualification_bytes = qualification_receipt(&hil_bytes);
    let policy = policy(&qualification_bytes, &hil_bytes);
    let parsed_hil = parse_hil_verification_receipt(&hil_bytes).unwrap();
    let parsed_qualification =
        parse_target_adapter_qualification_receipt(&qualification_bytes).unwrap();

    assert_eq!(parsed_hil.verdict, HilVerificationVerdict::Pass);
    validate_target_adapter_qualification(
        &policy,
        &tc234l_build190766_candidate_profile(),
        &qualification_bytes,
        &parsed_qualification,
        &hil_bytes,
        &parsed_hil,
    )
    .unwrap();
}

#[test]
fn strict_parsers_reject_duplicate_unknown_failed_and_inconsistent_documents() {
    let hil_bytes = hil_receipt();
    let duplicate = br#"{"schema":"t32perf.hil-verification-receipt/v1","schema":"other"}"#;
    assert!(parse_hil_verification_receipt(duplicate).is_err());

    let mut failed: serde_json::Value = serde_json::from_slice(&hil_bytes).unwrap();
    failed["verdict"] = serde_json::json!("FAIL");
    assert!(parse_hil_verification_receipt(&serde_json::to_vec(&failed).unwrap()).is_err());
    failed = serde_json::from_slice(&hil_bytes).unwrap();
    failed["unexpected"] = serde_json::json!(true);
    assert!(parse_hil_verification_receipt(&serde_json::to_vec(&failed).unwrap()).is_err());
    failed = serde_json::from_slice(&hil_bytes).unwrap();
    failed["check_categories"][0]["counts"]["total"] = serde_json::json!(2);
    assert!(parse_hil_verification_receipt(&serde_json::to_vec(&failed).unwrap()).is_err());

    let policy_bytes = serde_json::to_vec(&policy(b"qualification", &hil_bytes)).unwrap();
    assert!(parse_target_adapter_qualification_policy(&policy_bytes).is_ok());
    assert!(
        parse_target_adapter_qualification_policy(
            br#"{"schema":"t32perf.target-adapter-qualification-policy/v1","schema":"x"}"#
        )
        .is_err()
    );
}

#[test]
fn qualification_rejects_policy_and_receipt_cross_binding_mismatches() {
    let hil_bytes = hil_receipt();
    let qualification_bytes = qualification_receipt(&hil_bytes);
    let parsed_hil = parse_hil_verification_receipt(&hil_bytes).unwrap();
    let parsed_qualification =
        parse_target_adapter_qualification_receipt(&qualification_bytes).unwrap();
    let mut mismatched = policy(&qualification_bytes, &hil_bytes);
    mismatched.board_id = "other-board".to_owned();
    assert!(
        validate_target_adapter_qualification(
            &mismatched,
            &tc234l_build190766_candidate_profile(),
            &qualification_bytes,
            &parsed_qualification,
            &hil_bytes,
            &parsed_hil
        )
        .is_err()
    );
    mismatched = policy(&qualification_bytes, &hil_bytes);
    mismatched.t32mcp_version = "9.9.9".to_owned();
    assert!(
        validate_target_adapter_qualification(
            &mismatched,
            &tc234l_build190766_candidate_profile(),
            &qualification_bytes,
            &parsed_qualification,
            &hil_bytes,
            &parsed_hil
        )
        .is_err()
    );
    mismatched = policy(&qualification_bytes, &hil_bytes);
    mismatched.allowed_scenarios = vec![TargetAdapterScenario::TraceOverflow];
    assert!(
        validate_target_adapter_qualification(
            &mismatched,
            &tc234l_build190766_candidate_profile(),
            &qualification_bytes,
            &parsed_qualification,
            &hil_bytes,
            &parsed_hil
        )
        .is_err()
    );
    mismatched = policy(&qualification_bytes, &hil_bytes);
    mismatched.qualified_profile_sha256 = digest('f');
    assert!(
        validate_target_adapter_qualification(
            &mismatched,
            &tc234l_build190766_candidate_profile(),
            &qualification_bytes,
            &parsed_qualification,
            &hil_bytes,
            &parsed_hil
        )
        .is_err()
    );
}

#[test]
fn policy_schema_is_exposed() {
    let documents = qualification_schema_documents();
    assert_eq!(
        documents["target-adapter-qualification-policy.schema.json"]["$id"],
        "t32perf.target-adapter-qualification-policy/v1"
    );
    assert_eq!(
        documents["target-adapter-admission-snapshot.schema.json"]["$id"],
        "t32perf.target-adapter-admission-snapshot/v1"
    );
    assert_eq!(
        documents["target-adapter-qualification-trust-store.schema.json"]["$id"],
        "t32perf.target-adapter-qualification-trust-store/v1"
    );
}

#[test]
fn trust_store_is_strict_and_canonical() {
    let canonical = br#"{"schema":"t32perf.target-adapter-qualification-trust-store/v1","entries":[{"policy_id":"a","policy_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"policy_id":"b","policy_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}"#;
    let store = parse_target_adapter_qualification_trust_store(canonical).unwrap();
    assert_eq!(store.policy_sha256("b"), Some(&digest('b')));
    for invalid in [
        br#"{"schema":"t32perf.target-adapter-qualification-trust-store/v1","entries":[]}"#.as_slice(),
        br#"{"schema":"t32perf.target-adapter-qualification-trust-store/v1","entries":[{"policy_id":"b","policy_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},{"policy_id":"a","policy_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}"#.as_slice(),
        br#"{"schema":"t32perf.target-adapter-qualification-trust-store/v1","entries":[{"policy_id":"a","policy_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"policy_id":"a","policy_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}"#.as_slice(),
        br#"{"schema":"t32perf.target-adapter-qualification-trust-store/v1","entries":[{"policy_id":"../a","policy_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}"#.as_slice(),
        br#"{"schema":"t32perf.target-adapter-qualification-trust-store/v1","entries":[{"policy_id":"a","policy_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"extra":true}"#.as_slice(),
    ] {
        assert!(parse_target_adapter_qualification_trust_store(invalid).is_err());
    }
}

#[test]
fn trust_store_accepts_the_document_bound_larger_than_a_policy() {
    let entries = (0..256)
        .map(|index| {
            serde_json::json!({
                "policy_id": format!("policy-{index:03}-{}", "x".repeat(32)),
                "policy_sha256": digest('a'),
            })
        })
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schema": "t32perf.target-adapter-qualification-trust-store/v1",
        "entries": entries,
    }))
    .unwrap();
    assert!(bytes.len() > 16 * 1024);
    assert!(parse_target_adapter_qualification_trust_store(&bytes).is_ok());
}

#[test]
fn hil_count_overflow_is_rejected_without_panicking() {
    let mut receipt: serde_json::Value = serde_json::from_slice(&hil_receipt()).unwrap();
    receipt["checks"] = serde_json::json!({
        "total": u64::MAX,
        "passed": u64::MAX,
        "failed": 0,
    });
    for category in receipt["check_categories"].as_array_mut().unwrap() {
        category["counts"] = serde_json::json!({
            "total": u64::MAX,
            "passed": u64::MAX,
            "failed": 0,
        });
    }
    assert!(parse_hil_verification_receipt(&serde_json::to_vec(&receipt).unwrap()).is_err());
}

#[test]
fn sampling_buffer_full_is_a_distinct_non_recovery_hil_scenario() {
    let candidate = tc234l_build190766_candidate_profile();
    let mut hil: serde_json::Value = serde_json::from_slice(&hil_receipt()).unwrap();
    hil["kind"] = serde_json::json!("fault_injection");
    hil["scenario"] = serde_json::json!("sampling_buffer_full");
    hil["recovery_evidence"] = serde_json::Value::Null;
    hil["fault_adapter_binding"] = serde_json::json!({
        "scenario": "sampling_buffer_full",
        "fault_scenarios_sha256": digest('c'),
        "adapter_id": candidate.adapter_id,
        "profile_sha256": candidate.qualification_identity_digest().unwrap(),
        "profile_file_sha256": digest('e'),
        "bundle_sha256": candidate.implementation_sha256,
    });
    hil["artifact_bindings"] = serde_json::json!([
        {"role": "manifest", "artifact_id": null, "sha256": digest('a')},
        {"role": "health", "artifact_id": "health-artifact", "sha256": digest('a')},
    ]);
    hil["check_categories"] = serde_json::json!([
        {"category": "artifact_binding", "counts": {"total": 1, "passed": 1, "failed": 0}},
        {"category": "health", "counts": {"total": 1, "passed": 1, "failed": 0}},
        {"category": "fault_publication", "counts": {"total": 1, "passed": 1, "failed": 0}},
        {"category": "recovery", "counts": {"total": 0, "passed": 0, "failed": 0}},
    ]);
    hil["checks"] = serde_json::json!({"total": 3, "passed": 3, "failed": 0});
    let hil_bytes = serde_json::to_vec(&hil).unwrap();
    let qualification = qualification_receipt(&hil_bytes);
    let mut admission = policy(&qualification, &hil_bytes);
    admission.expected_hil_kind = HilVerificationKind::FaultInjection;
    admission.expected_hil_scenario = Some(t32perf_trace32::HilFaultScenario::SamplingBufferFull);
    admission.allowed_scenarios = vec![TargetAdapterScenario::SamplingBufferFull];
    let parsed_hil = parse_hil_verification_receipt(&hil_bytes).unwrap();
    let parsed_qualification = parse_target_adapter_qualification_receipt(&qualification).unwrap();
    validate_target_adapter_qualification(
        &admission,
        &tc234l_build190766_candidate_profile(),
        &qualification,
        &parsed_qualification,
        &hil_bytes,
        &parsed_hil,
    )
    .unwrap();
}

#[test]
fn python_generated_sampling_receipt_binds_the_exact_rust_candidate() {
    // Generated with hil/verification_receipt.py::build_verification_receipt;
    // the fixture deliberately uses the HIL-side canonical profile digest.
    let hil = include_bytes!("fixtures/hil/python-sampling-buffer-full-receipt.json");
    let parsed_hil = parse_hil_verification_receipt(hil).unwrap();
    let binding = parsed_hil.fault_adapter_binding.as_ref().unwrap();
    assert_eq!(binding.scenario, HilFaultScenario::SamplingBufferFull);
    assert_eq!(
        binding.profile_sha256,
        tc234l_build190766_candidate_profile()
            .qualification_identity_digest()
            .unwrap()
    );

    let qualification = qualification_receipt(hil);
    let parsed_qualification = parse_target_adapter_qualification_receipt(&qualification).unwrap();
    let mut admission = policy(&qualification, hil);
    admission.expected_hil_kind = HilVerificationKind::FaultInjection;
    admission.expected_hil_scenario = Some(HilFaultScenario::SamplingBufferFull);
    admission.allowed_scenarios = vec![TargetAdapterScenario::SamplingBufferFull];
    validate_target_adapter_qualification(
        &admission,
        &tc234l_build190766_candidate_profile(),
        &qualification,
        &parsed_qualification,
        hil,
        &parsed_hil,
    )
    .unwrap();
}

#[test]
fn fault_adapter_binding_is_closed_required_for_sampling_and_cross_bound() {
    let base = include_bytes!("fixtures/hil/python-sampling-buffer-full-receipt.json");
    let mut receipt: serde_json::Value = serde_json::from_slice(base).unwrap();

    receipt["fault_adapter_binding"]["unexpected"] = serde_json::json!(true);
    assert!(parse_hil_verification_receipt(&serde_json::to_vec(&receipt).unwrap()).is_err());

    receipt = serde_json::from_slice(base).unwrap();
    receipt["fault_adapter_binding"] = serde_json::Value::Null;
    assert!(parse_hil_verification_receipt(&serde_json::to_vec(&receipt).unwrap()).is_err());

    receipt = serde_json::from_slice(base).unwrap();
    receipt
        .as_object_mut()
        .unwrap()
        .remove("fault_adapter_binding");
    assert!(parse_hil_verification_receipt(&serde_json::to_vec(&receipt).unwrap()).is_err());

    receipt = serde_json::from_slice(base).unwrap();
    receipt["fault_adapter_binding"]["scenario"] = serde_json::json!("flow_error");
    assert!(parse_hil_verification_receipt(&serde_json::to_vec(&receipt).unwrap()).is_err());

    receipt = serde_json::from_slice(base).unwrap();
    receipt["kind"] = serde_json::json!("resources");
    receipt["scenario"] = serde_json::Value::Null;
    assert!(parse_hil_verification_receipt(&serde_json::to_vec(&receipt).unwrap()).is_err());

    receipt = serde_json::from_slice(base).unwrap();
    receipt["fault_adapter_binding"]["profile_sha256"] = serde_json::json!(digest('f'));
    let hil = serde_json::to_vec(&receipt).unwrap();
    let parsed_hil = parse_hil_verification_receipt(&hil).unwrap();
    let qualification = qualification_receipt(&hil);
    let parsed_qualification = parse_target_adapter_qualification_receipt(&qualification).unwrap();
    let mut admission = policy(&qualification, &hil);
    admission.expected_hil_kind = HilVerificationKind::FaultInjection;
    admission.expected_hil_scenario = Some(HilFaultScenario::SamplingBufferFull);
    admission.allowed_scenarios = vec![TargetAdapterScenario::SamplingBufferFull];
    assert!(
        validate_target_adapter_qualification(
            &admission,
            &tc234l_build190766_candidate_profile(),
            &qualification,
            &parsed_qualification,
            &hil,
            &parsed_hil,
        )
        .is_err()
    );
}

#[test]
fn trace_overflow_is_canonical_but_legacy_overflow_still_parses() {
    assert_eq!(
        serde_json::to_value(HilFaultScenario::TraceOverflow).unwrap(),
        serde_json::json!("trace_overflow")
    );
    let mut receipt: serde_json::Value = serde_json::from_slice(&hil_receipt()).unwrap();
    receipt["kind"] = serde_json::json!("fault_injection");
    receipt["scenario"] = serde_json::json!("overflow");
    receipt["recovery_evidence"] = serde_json::Value::Null;
    receipt["artifact_bindings"] = serde_json::json!([
        {"role": "manifest", "artifact_id": null, "sha256": digest('a')},
        {"role": "health", "artifact_id": "health-artifact", "sha256": digest('a')},
    ]);
    receipt["check_categories"] = serde_json::json!([
        {"category": "artifact_binding", "counts": {"total": 1, "passed": 1, "failed": 0}},
        {"category": "health", "counts": {"total": 1, "passed": 1, "failed": 0}},
        {"category": "fault_publication", "counts": {"total": 1, "passed": 1, "failed": 0}},
        {"category": "recovery", "counts": {"total": 0, "passed": 0, "failed": 0}},
    ]);
    receipt["checks"] = serde_json::json!({"total": 3, "passed": 3, "failed": 0});
    assert_eq!(
        parse_hil_verification_receipt(&serde_json::to_vec(&receipt).unwrap())
            .unwrap()
            .scenario,
        Some(HilFaultScenario::TraceOverflow)
    );
}

#[test]
fn admission_snapshot_is_closed_and_requires_canonical_scenarios() {
    let hil = hil_receipt();
    let qualification = qualification_receipt(&hil);
    let snapshot = snapshot(&qualification, &hil);
    assert!(
        parse_target_adapter_admission_snapshot(&serde_json::to_vec(&snapshot).unwrap()).is_ok()
    );
    let mut invalid = serde_json::to_value(snapshot).unwrap();
    invalid["allowed_scenarios"] = serde_json::json!(["normal", "normal"]);
    assert!(
        parse_target_adapter_admission_snapshot(&serde_json::to_vec(&invalid).unwrap()).is_err()
    );
    invalid = serde_json::json!({"schema":"t32perf.target-adapter-admission-snapshot/v1"});
    assert!(
        parse_target_adapter_admission_snapshot(&serde_json::to_vec(&invalid).unwrap()).is_err()
    );
}
