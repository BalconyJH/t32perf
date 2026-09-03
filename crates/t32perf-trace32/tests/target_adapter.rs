use std::{fs, path::PathBuf};

use sha2::{Digest as _, Sha256};
use t32perf_model::{CaptureCapabilities, MetricSupportEntry, MetricSupportLevel, Sha256Digest};
use t32perf_trace32::{
    CONTROLLER_CAPABILITIES_EVIDENCE_SCHEMA, CONTROLLER_CAPABILITIES_EVIDENCE_V2_SCHEMA,
    ControllerCapabilitiesEvidence, ControllerCapabilitiesEvidenceSchemaVersion,
    ControllerCapabilitiesEvidenceV2, ControllerCapabilitiesEvidenceV2SchemaVersion,
    ControllerCapabilitiesOperation, ControllerCleanupEvidence,
    ControllerCleanupEvidenceSchemaVersion, ControllerCleanupEvidenceV2,
    ControllerCleanupEvidenceV2SchemaVersion, ControllerCleanupOperation,
    ControllerConfigureEvidence, ControllerConfigureEvidenceSchemaVersion,
    ControllerConfigureOperation, ControllerEvidence, ControllerHealthEvidenceV2,
    ControllerHealthEvidenceV2SchemaVersion, ControllerHealthOperation, ControllerHealthSignal,
    ControllerProgramFlowHealthEvidence, ControllerProgramFlowHealthEvidenceSchemaVersion,
    ControllerSamplingBufferMode, ControllerSamplingCleanupEvidence,
    ControllerSamplingHealthEvidence, ControllerSamplingMethod, ControllerSamplingObject,
    ControllerSamplingPreStopState, ControllerSamplingState, ControllerStartEvidence,
    ControllerStartEvidenceSchemaVersion, ControllerStartEvidenceV2,
    ControllerStartEvidenceV2SchemaVersion, ControllerStartOperation, ControllerStopEvidence,
    ControllerStopEvidenceSchemaVersion, ControllerStopEvidenceV2,
    ControllerStopEvidenceV2SchemaVersion, ControllerStopOperation, ControllerTargetState,
    ControllerWorkloadOwner, MAX_CUSTOM_EVENT_CLOCK_FREQUENCY_HZ,
    MAX_CUSTOM_EVENT_COLLECTOR_OUTPUT_BYTES, PROGRAM_FLOW_HEALTH_SIGNALS, PerfOperation,
    PerfScriptResponse, PerfStatus, T32PERF_PROTOCOL, TARGET_ADAPTER_PROFILE_SCHEMA,
    TARGET_ADAPTER_QUALIFICATION_RECEIPT_SCHEMA, TARGET_ADAPTER_RECOVERY_EVIDENCE_SCHEMA,
    TARGET_ADAPTER_SCENARIO_SELECTION_SCHEMA, TargetAdapterBuildGate, TargetAdapterCaptureContract,
    TargetAdapterCaptureKind, TargetAdapterControllerProtocol,
    TargetAdapterCustomEventClockContract, TargetAdapterCustomEventCollectorContract,
    TargetAdapterCustomEventMergeOrder, TargetAdapterCustomEventWireProtocol,
    TargetAdapterFailureKind, TargetAdapterFaultPoint, TargetAdapterPhase, TargetAdapterProfile,
    TargetAdapterProfileSchemaVersion, TargetAdapterQualificationReceipt,
    TargetAdapterQualificationReceiptSchemaVersion, TargetAdapterRecoveryEvidence,
    TargetAdapterRecoveryEvidenceSchemaVersion, TargetAdapterRegistry, TargetAdapterRun,
    TargetAdapterScenario, TargetAdapterScenarioContract, TargetAdapterSelection,
    TargetAdapterSelectionDiscriminator, parse_target_adapter_profile,
    parse_target_adapter_scenario_selection, target_adapter_schema_documents,
    tc234l_build190766_candidate_profile, tc234l_snooper_capture_config,
};

fn digest(character: char) -> Sha256Digest {
    Sha256Digest::new(character.to_string().repeat(64)).unwrap()
}

fn profile() -> TargetAdapterProfile {
    let capture = TargetAdapterCaptureContract {
        configuration_sha256_by_initial_state: std::collections::BTreeMap::from([
            (ControllerTargetState::Running, digest('3')),
            (ControllerTargetState::Halted, digest('4')),
        ]),
        capture_mode: "etm-program-flow".to_owned(),
        trace_sink: "probe-buffer".to_owned(),
        capture_kind: TargetAdapterCaptureKind::ProgramFlowTaskEvents {
            export_profile_id: "fixture.task-events/v1".to_owned(),
            rtos_awareness: "fixture-rtos-awareness/v1".to_owned(),
            timestamp_clock_id: "fixture-trace-clock/v1".to_owned(),
            orti_artifact_id: "fixture-orti".to_owned(),
            task_marker_artifact_id: "fixture-task-markers".to_owned(),
        },
        timestamp_enabled: true,
        workload_identity: "fixed-workload/v1".to_owned(),
        covered_cores: vec![0],
        supported_initial_states: vec![
            ControllerTargetState::Running,
            ControllerTargetState::Halted,
        ],
    };
    let unavailable = MetricSupportEntry::unavailable("not-supported-by-test-profile");
    let mut profile = TargetAdapterProfile {
        schema: TargetAdapterProfileSchemaVersion::V1,
        adapter_id: "qualified-test-adapter".to_owned(),
        adapter_version: "1.0.0".to_owned(),
        implementation_sha256: digest('1'),
        qualification_sha256: None,
        build_gate: TargetAdapterBuildGate {
            trace32_release: "2025/09".to_owned(),
            minimum_build: 183_242,
            maximum_build: 183_242,
            architecture_package: "arm".to_owned(),
        },
        target_identifier: "test-target".to_owned(),
        probe_identifier: "test-probe".to_owned(),
        license_features: vec!["etm".to_owned()],
        trace_routing: vec!["etm-to-probe-buffer".to_owned()],
        firmware_elf_sha256: digest('7'),
        health_signals: vec![
            ControllerHealthSignal::TraceOverflow,
            ControllerHealthSignal::FlowError,
            ControllerHealthSignal::TraceGap,
            ControllerHealthSignal::Truncation,
            ControllerHealthSignal::TimestampDiscontinuity,
            ControllerHealthSignal::ElfMismatch,
            ControllerHealthSignal::ProgramFlowClosure,
        ],
        capabilities: CaptureCapabilities {
            function_events: MetricSupportEntry::new(MetricSupportLevel::Exact),
            context_switches: MetricSupportEntry::new(MetricSupportLevel::Exact),
            interrupt_events: MetricSupportEntry::new(MetricSupportLevel::Exact),
            samples: unavailable.clone(),
            custom_events: unavailable.clone(),
            counters: unavailable,
        },
        controller_protocol: TargetAdapterControllerProtocol::V1,
        custom_event_collector: None,
        scenarios: vec![
            TargetAdapterScenarioContract {
                scenario: TargetAdapterScenario::Normal,
                fault_point: None,
                capture: capture.clone(),
            },
            TargetAdapterScenarioContract {
                scenario: TargetAdapterScenario::TraceOverflow,
                fault_point: None,
                capture: capture.clone(),
            },
            TargetAdapterScenarioContract {
                scenario: TargetAdapterScenario::FlowError,
                fault_point: None,
                capture: capture.clone(),
            },
            TargetAdapterScenarioContract {
                scenario: TargetAdapterScenario::Trace32Disconnect,
                fault_point: Some(TargetAdapterFaultPoint::Stop),
                capture: capture.clone(),
            },
            TargetAdapterScenarioContract {
                scenario: TargetAdapterScenario::DriverDisconnect,
                fault_point: Some(TargetAdapterFaultPoint::Export),
                capture: capture.clone(),
            },
            TargetAdapterScenarioContract {
                scenario: TargetAdapterScenario::CmmAbort,
                fault_point: Some(TargetAdapterFaultPoint::Start),
                capture,
            },
        ],
    };
    let receipt = qualification_receipt(&profile);
    profile.qualification_sha256 = Some(
        Sha256Digest::new(
            Sha256::digest(receipt)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
        .unwrap(),
    );
    profile
}

fn qualification_receipt(profile: &TargetAdapterProfile) -> Vec<u8> {
    serde_json::to_vec(&TargetAdapterQualificationReceipt {
        schema: TargetAdapterQualificationReceiptSchemaVersion::V1,
        adapter_id: profile.adapter_id.clone(),
        adapter_version: profile.adapter_version.clone(),
        candidate_profile_sha256: profile.qualification_identity_digest().unwrap(),
        implementation_sha256: profile.implementation_sha256.clone(),
        trace32_release: profile.build_gate.trace32_release.clone(),
        trace32_build: profile.build_gate.minimum_build,
        architecture_package: profile.build_gate.architecture_package.clone(),
        target_identifier: profile.target_identifier.clone(),
        probe_identifier: profile.probe_identifier.clone(),
        firmware_elf_sha256: profile.firmware_elf_sha256.clone(),
        t32mcp_version: "0.2.2".to_owned(),
        hil_verification_receipt_sha256: digest('8'),
    })
    .unwrap()
}

fn profile_with_adapter_id(adapter_id: &str) -> TargetAdapterProfile {
    let mut profile = profile();
    profile.adapter_id = adapter_id.to_owned();
    profile.qualification_sha256 = None;
    let receipt = qualification_receipt(&profile);
    profile.qualification_sha256 = Some(
        Sha256Digest::new(
            Sha256::digest(receipt)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
        .unwrap(),
    );
    profile
}

fn custom_event_collector() -> TargetAdapterCustomEventCollectorContract {
    TargetAdapterCustomEventCollectorContract {
        wire_protocol: TargetAdapterCustomEventWireProtocol::CWireV1,
        source_id: "fixture-custom-events".to_owned(),
        core_id: 0,
        clock: TargetAdapterCustomEventClockContract {
            clock_id: "fixture-trace-clock/v1".to_owned(),
            frequency_hz: 100_000_000,
            timestamp_modulus: 1_u64 << 32,
            max_forward_ticks: 1_u64 << 31,
            origin_ticks: 0,
            origin_ns: 0,
        },
        transport: "shared-memory-ring-buffer/v1".to_owned(),
        mapping_artifact_id: "fixture-c-wire-mapping".to_owned(),
        instrumentation_overhead_artifact_id: "fixture-instrumentation-overhead".to_owned(),
        max_output_bytes: 16 * 1024 * 1024,
        merge_order: TargetAdapterCustomEventMergeOrder::RejectAmbiguousTies,
    }
}

fn v2_custom_event_profile() -> TargetAdapterProfile {
    let mut profile = profile();
    profile.qualification_sha256 = None;
    profile.controller_protocol = TargetAdapterControllerProtocol::V2CustomEventsExport;
    profile.custom_event_collector = Some(custom_event_collector());
    profile.capabilities.custom_events = MetricSupportEntry::new(MetricSupportLevel::Exact);
    profile.capabilities.counters = MetricSupportEntry::new(MetricSupportLevel::Exact);
    profile
}

fn binding() -> Sha256Digest {
    digest('a')
}

fn capabilities() -> ControllerEvidence {
    ControllerEvidence::Capabilities(ControllerCapabilitiesEvidence {
        schema: ControllerCapabilitiesEvidenceSchemaVersion::V1,
        operation: ControllerCapabilitiesOperation::V1,
        binding_sha256: binding(),
        trace32_release: "2025/09".to_owned(),
        trace32_build: 183_242,
        architecture_package: "arm".to_owned(),
        target_identifier: "test-target".to_owned(),
        probe_identifier: "test-probe".to_owned(),
        license_features: vec!["etm".to_owned()],
        trace_routing: vec!["etm-to-probe-buffer".to_owned()],
        capture_modes: vec!["etm-program-flow".to_owned()],
        trace_sinks: vec!["probe-buffer".to_owned()],
        covered_cores: vec![0],
        timestamp_supported: true,
        rtos_awareness: Some("fixture-rtos-awareness/v1".to_owned()),
        health_signals: profile().health_signals,
    })
}

fn capabilities_v2(
    profile: &TargetAdapterProfile,
    capture: &TargetAdapterCaptureContract,
    initial_target_state: ControllerTargetState,
) -> ControllerEvidence {
    ControllerEvidence::CapabilitiesV2(ControllerCapabilitiesEvidenceV2 {
        schema: ControllerCapabilitiesEvidenceV2SchemaVersion::V1,
        operation: ControllerCapabilitiesOperation::V1,
        binding_sha256: binding(),
        trace32_release: profile.build_gate.trace32_release.clone(),
        trace32_build: profile.build_gate.minimum_build,
        architecture_package: profile.build_gate.architecture_package.clone(),
        target_identifier: profile.target_identifier.clone(),
        probe_identifier: profile.probe_identifier.clone(),
        license_features: profile.license_features.clone(),
        trace_routing: profile.trace_routing.clone(),
        capture_modes: vec![capture.capture_mode.clone()],
        trace_sinks: vec![capture.trace_sink.clone()],
        covered_cores: capture.covered_cores.clone(),
        timestamp_supported: capture.timestamp_enabled,
        rtos_awareness: match &capture.capture_kind {
            TargetAdapterCaptureKind::Sampling { .. } => None,
            TargetAdapterCaptureKind::ProgramFlowTaskEvents { rtos_awareness, .. } => {
                Some(rtos_awareness.clone())
            }
        },
        health_signals: profile.health_signals.clone(),
        initial_target_state,
    })
}

fn configure(initial: ControllerTargetState) -> ControllerEvidence {
    ControllerEvidence::Configure(ControllerConfigureEvidence {
        schema: ControllerConfigureEvidenceSchemaVersion::V1,
        operation: ControllerConfigureOperation::V1,
        binding_sha256: binding(),
        configuration_sha256: if initial == ControllerTargetState::Running {
            digest('3')
        } else {
            digest('4')
        },
        capture_mode: "etm-program-flow".to_owned(),
        trace_sink: "probe-buffer".to_owned(),
        timestamp_enabled: true,
        filters_verified: true,
        trigger_verified: true,
        initial_target_state: initial,
        workload_identity: "fixed-workload/v1".to_owned(),
        covered_cores: vec![0],
    })
}

fn start(initial: ControllerTargetState) -> ControllerEvidence {
    ControllerEvidence::Start(ControllerStartEvidence {
        schema: ControllerStartEvidenceSchemaVersion::V1,
        operation: ControllerStartOperation::V1,
        binding_sha256: binding(),
        initial_target_state: initial,
        capture_started: true,
        workload_owned: true,
        workload_identity: "fixed-workload/v1".to_owned(),
    })
}

fn start_v2(initial: ControllerTargetState) -> ControllerEvidence {
    ControllerEvidence::StartV2(ControllerStartEvidenceV2 {
        schema: ControllerStartEvidenceV2SchemaVersion::V1,
        operation: ControllerStartOperation::V1,
        binding_sha256: binding(),
        initial_target_state: initial,
        capture_armed: true,
        workload_owner: ControllerWorkloadOwner::TargetSpecificController,
        workload_identity: "fixed-workload/v1".to_owned(),
    })
}

fn stop(initial: ControllerTargetState) -> ControllerEvidence {
    ControllerEvidence::Stop(ControllerStopEvidence {
        schema: ControllerStopEvidenceSchemaVersion::V1,
        operation: ControllerStopOperation::V1,
        binding_sha256: binding(),
        capture_stopped: true,
        workload_completed: true,
        workload_identity: "fixed-workload/v1".to_owned(),
        target_state_after_stop: initial,
    })
}

fn health(overflow: bool, flow_error: bool) -> ControllerEvidence {
    health_facts(
        overflow,
        flow_error,
        false,
        false,
        false,
        true,
        !overflow && !flow_error,
    )
}

fn health_facts(
    trace_overflow: bool,
    flow_error: bool,
    trace_gap: bool,
    truncated: bool,
    timestamp_discontinuity: bool,
    elf_matches_firmware: bool,
    program_flow_closed: bool,
) -> ControllerEvidence {
    ControllerEvidence::HealthV3(ControllerProgramFlowHealthEvidence {
        schema: ControllerProgramFlowHealthEvidenceSchemaVersion::V1,
        operation: ControllerHealthOperation::V1,
        binding_sha256: binding(),
        capture_stopped: true,
        supported_signals: PROGRAM_FLOW_HEALTH_SIGNALS.to_vec(),
        stop_evidence_sha256: digest('d'),
        trace_overflow,
        flow_error,
        trace_gap,
        truncated,
        timestamp_discontinuity,
        elf_matches_firmware,
        program_flow_closed,
    })
}

fn legacy_program_flow_health() -> ControllerEvidence {
    ControllerEvidence::Health(t32perf_trace32::ControllerHealthEvidence {
        schema: t32perf_trace32::ControllerHealthEvidenceSchemaVersion::V1,
        operation: ControllerHealthOperation::V1,
        binding_sha256: binding(),
        capture_stopped: true,
        trace_overflow: false,
        flow_error: false,
        trace_gap: false,
        truncated: false,
        timestamp_discontinuity: false,
        elf_matches_firmware: true,
        program_flow_closed: true,
    })
}

fn export_response() -> PerfScriptResponse {
    PerfScriptResponse {
        protocol: T32PERF_PROTOCOL,
        operation: PerfOperation::Export,
        status: PerfStatus::Ok,
        code: "task_events_exported".to_owned(),
        binding_sha256: binding().to_string(),
        files_deleted: None,
    }
}

fn sampling_export_response() -> PerfScriptResponse {
    PerfScriptResponse {
        protocol: T32PERF_PROTOCOL,
        operation: PerfOperation::Export,
        status: PerfStatus::Ok,
        code: "raw_ascii_exported".to_owned(),
        binding_sha256: binding().to_string(),
        files_deleted: None,
    }
}

fn cleanup() -> ControllerEvidence {
    ControllerEvidence::Cleanup(ControllerCleanupEvidence {
        schema: ControllerCleanupEvidenceSchemaVersion::V1,
        operation: ControllerCleanupOperation::V1,
        binding_sha256: binding(),
        adapter_state_restored: true,
        target_state_restored: true,
        files_deleted: false,
    })
}

fn sampling_cleanup(initial: ControllerTargetState) -> ControllerEvidence {
    ControllerEvidence::CleanupV2(ControllerCleanupEvidenceV2 {
        schema: ControllerCleanupEvidenceV2SchemaVersion::V1,
        operation: ControllerCleanupOperation::V1,
        binding_sha256: binding(),
        initial_target_state: initial,
        adapter_state_restored: true,
        target_state_restored: true,
        sampling: ControllerSamplingCleanupEvidence {
            method: ControllerSamplingMethod::RealTime,
            object: ControllerSamplingObject::ProgramCounter,
            buffer_mode: ControllerSamplingBufferMode::Stack,
            state: ControllerSamplingState::Off,
            requested_rate_ns: 1_000_000,
            capacity_records: 65_536,
            auto_arm: false,
            auto_init: false,
            zero_reset: true,
        },
        files_deleted: false,
    })
}

fn sampling_health(
    profile: &TargetAdapterProfile,
    pre_stop_state: ControllerSamplingPreStopState,
    capacity_records: u64,
    recorded_records: u64,
    elf_matches_firmware: Option<bool>,
) -> ControllerEvidence {
    ControllerEvidence::HealthV2(ControllerHealthEvidenceV2 {
        schema: ControllerHealthEvidenceV2SchemaVersion::V1,
        operation: ControllerHealthOperation::V1,
        binding_sha256: binding(),
        capture_stopped: true,
        supported_signals: profile.health_signals.clone(),
        stop_evidence_sha256: digest('c'),
        sampling: ControllerSamplingHealthEvidence {
            method: ControllerSamplingMethod::RealTime,
            object: ControllerSamplingObject::ProgramCounter,
            buffer_mode: ControllerSamplingBufferMode::Stack,
            state: ControllerSamplingState::Off,
            pre_stop_state,
            requested_rate_ns: 1_000_000,
            capacity_records,
            recorded_records,
            buffer_full: pre_stop_state == ControllerSamplingPreStopState::Break
                && recorded_records == capacity_records,
            unexpected_stop: pre_stop_state == ControllerSamplingPreStopState::Break
                && recorded_records < capacity_records,
        },
        elf_matches_firmware,
    })
}

fn sampling_capacity(capture: &TargetAdapterCaptureContract) -> u64 {
    capture
        .capture_kind
        .sampling_capacity_records()
        .expect("sampling fixture has capacity")
}

fn accept_sampling_until_stopped(
    run: &mut TargetAdapterRun<'_>,
    profile: &TargetAdapterProfile,
    capture: &TargetAdapterCaptureContract,
    initial_target_state: ControllerTargetState,
    pre_stop_state: ControllerSamplingPreStopState,
    recorded_records: u64,
) {
    run.accept_evidence(&capabilities_v2(profile, capture, initial_target_state))
        .unwrap();
    run.accept_evidence(&ControllerEvidence::Configure(
        ControllerConfigureEvidence {
            schema: ControllerConfigureEvidenceSchemaVersion::V1,
            operation: ControllerConfigureOperation::V1,
            binding_sha256: binding(),
            configuration_sha256: capture.configuration_sha256_by_initial_state
                [&initial_target_state]
                .clone(),
            capture_mode: capture.capture_mode.clone(),
            trace_sink: capture.trace_sink.clone(),
            timestamp_enabled: capture.timestamp_enabled,
            filters_verified: true,
            trigger_verified: true,
            initial_target_state,
            workload_identity: capture.workload_identity.clone(),
            covered_cores: capture.covered_cores.clone(),
        },
    ))
    .unwrap();
    run.accept_evidence(&ControllerEvidence::StartV2(ControllerStartEvidenceV2 {
        schema: ControllerStartEvidenceV2SchemaVersion::V1,
        operation: ControllerStartOperation::V1,
        binding_sha256: binding(),
        initial_target_state,
        capture_armed: true,
        workload_owner: ControllerWorkloadOwner::TargetSpecificController,
        workload_identity: capture.workload_identity.clone(),
    }))
    .unwrap();
    run.accept_evidence(&ControllerEvidence::StopV2(ControllerStopEvidenceV2 {
        schema: ControllerStopEvidenceV2SchemaVersion::V1,
        operation: ControllerStopOperation::V1,
        binding_sha256: binding(),
        capture_stopped: true,
        workload_identity: capture.workload_identity.clone(),
        target_state_after_stop: initial_target_state,
        pre_stop_state,
        capacity_records: capture
            .capture_kind
            .sampling_capacity_records()
            .expect("sampling fixture has capacity"),
        recorded_records,
        time_origin_zeroed_to_first_record: true,
    }))
    .unwrap();
}

#[test]
fn profile_is_strict_build_target_and_qualification_gated() {
    let profile = profile();
    profile.validate().unwrap();
    let serialized = serde_json::to_vec(&profile).unwrap();
    assert_eq!(parse_target_adapter_profile(&serialized).unwrap(), profile);
    let serialized_value: serde_json::Value = serde_json::from_slice(&serialized).unwrap();
    assert_eq!(
        serialized_value["scenarios"][0]["capture"]["capture_kind"]["kind"],
        "program_flow_task_events"
    );
    assert!(
        serialized_value["scenarios"][0]["capture"]
            .get("capacity_records")
            .is_none()
    );

    let mut registry = TargetAdapterRegistry::new();
    registry
        .register(profile.clone(), &qualification_receipt(&profile))
        .unwrap();
    let mut forged_registry = TargetAdapterRegistry::new();
    assert!(forged_registry.register(profile.clone(), b"{}").is_err());
    let mut changed_bytes = qualification_receipt(&profile);
    changed_bytes.push(b'\n');
    assert!(
        forged_registry
            .register(profile.clone(), &changed_bytes)
            .is_err()
    );
    let selected = registry
        .select(&TargetAdapterSelection {
            trace32_release: "2025/09".to_owned(),
            trace32_build: 183_242,
            architecture_package: "arm".to_owned(),
            target_identifier: "test-target".to_owned(),
            probe_identifier: "test-probe".to_owned(),
            discriminator: None,
        })
        .unwrap();
    assert_eq!(selected.profile.adapter_id, "qualified-test-adapter");
    assert_eq!(
        selected.qualification_receipt.adapter_id,
        "qualified-test-adapter"
    );

    let no_build = registry.select(&TargetAdapterSelection {
        trace32_release: "2025/09".to_owned(),
        trace32_build: 183_241,
        architecture_package: "arm".to_owned(),
        target_identifier: "test-target".to_owned(),
        probe_identifier: "test-probe".to_owned(),
        discriminator: None,
    });
    assert!(no_build.is_err());

    let duplicated = String::from_utf8(serialized).unwrap().replacen(
        r#""adapter_id":"qualified-test-adapter""#,
        r#""adapter_id":"qualified-test-adapter","adapter_id":"qualified-test-adapter""#,
        1,
    );
    assert!(parse_target_adapter_profile(duplicated.as_bytes()).is_err());
}

#[test]
fn exact_profile_discriminator_resolves_runtime_ambiguity() {
    let first = profile_with_adapter_id("fixture-flow-a");
    let second = profile_with_adapter_id("fixture-flow-b");
    let mut registry = TargetAdapterRegistry::new();
    registry
        .register(first.clone(), &qualification_receipt(&first))
        .unwrap();
    registry
        .register(second.clone(), &qualification_receipt(&second))
        .unwrap();
    let runtime = || TargetAdapterSelection {
        trace32_release: "2025/09".to_owned(),
        trace32_build: 183_242,
        architecture_package: "arm".to_owned(),
        target_identifier: "test-target".to_owned(),
        probe_identifier: "test-probe".to_owned(),
        discriminator: None,
    };
    assert!(matches!(
        registry.select(&runtime()),
        Err(t32perf_trace32::TargetAdapterError::AmbiguousAdapter { .. })
    ));

    let mut exact = runtime();
    exact.discriminator = Some(TargetAdapterSelectionDiscriminator {
        adapter_id: second.adapter_id.clone(),
        profile_sha256: second.digest().unwrap(),
    });
    assert_eq!(
        registry.select(&exact).unwrap().profile.adapter_id,
        second.adapter_id
    );

    exact.discriminator = Some(TargetAdapterSelectionDiscriminator {
        adapter_id: "missing-flow-profile".to_owned(),
        profile_sha256: second.digest().unwrap(),
    });
    assert!(registry.select(&exact).is_err());
    exact.discriminator = Some(TargetAdapterSelectionDiscriminator {
        adapter_id: second.adapter_id.clone(),
        profile_sha256: digest('f'),
    });
    assert!(registry.select(&exact).is_err());

    let discriminator = TargetAdapterSelectionDiscriminator {
        adapter_id: second.adapter_id.clone(),
        profile_sha256: second.digest().unwrap(),
    };
    let bytes = serde_json::to_vec(&discriminator).unwrap();
    assert_eq!(
        serde_json::from_slice::<TargetAdapterSelectionDiscriminator>(&bytes).unwrap(),
        discriminator
    );
    let mut unknown: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    unknown["extra"] = serde_json::json!(true);
    assert!(serde_json::from_value::<TargetAdapterSelectionDiscriminator>(unknown).is_err());
}

#[test]
fn both_initial_states_follow_the_closed_seven_operation_sequence() {
    for initial in [
        ControllerTargetState::Running,
        ControllerTargetState::Halted,
    ] {
        let profile = profile();
        let capture = &profile
            .scenario(TargetAdapterScenario::Normal)
            .unwrap()
            .capture;
        let mut run = TargetAdapterRun::new(&profile, TargetAdapterScenario::Normal).unwrap();
        run.accept_evidence(&capabilities_v2(&profile, capture, initial))
            .unwrap();
        run.accept_evidence(&configure(initial)).unwrap();
        run.accept_evidence(&start_v2(initial)).unwrap();
        assert!(run.accept_evidence(&stop(initial)).is_err());
        assert_eq!(run.phase(), TargetAdapterPhase::Capturing);
        run.accept_evidence_artifact(&stop(initial), &digest('d'))
            .unwrap();
        assert!(run.accept_evidence(&legacy_program_flow_health()).is_err());
        assert_eq!(run.phase(), TargetAdapterPhase::Stopped);
        run.accept_evidence(&health(false, false)).unwrap();
        run.accept_export(&export_response()).unwrap();
        run.accept_evidence(&cleanup()).unwrap();
        assert_eq!(run.phase(), TargetAdapterPhase::Cleaned);
    }
}

#[test]
fn overflow_and_flow_error_must_be_observed_by_build_gated_health() {
    for (scenario, expected_health) in [
        (TargetAdapterScenario::TraceOverflow, health(true, false)),
        (TargetAdapterScenario::FlowError, health(false, true)),
    ] {
        let profile = profile();
        let mut run = TargetAdapterRun::new(&profile, scenario).unwrap();
        run.accept_evidence(&capabilities()).unwrap();
        run.accept_evidence(&configure(ControllerTargetState::Running))
            .unwrap();
        run.accept_evidence(&start(ControllerTargetState::Running))
            .unwrap();
        run.accept_evidence_artifact(&stop(ControllerTargetState::Running), &digest('d'))
            .unwrap();
        for invalid in [
            health(false, false),
            health(true, true),
            health_facts(
                scenario == TargetAdapterScenario::TraceOverflow,
                scenario == TargetAdapterScenario::FlowError,
                true,
                false,
                false,
                true,
                false,
            ),
            health_facts(
                scenario == TargetAdapterScenario::TraceOverflow,
                scenario == TargetAdapterScenario::FlowError,
                false,
                true,
                false,
                true,
                false,
            ),
            health_facts(
                scenario == TargetAdapterScenario::TraceOverflow,
                scenario == TargetAdapterScenario::FlowError,
                false,
                false,
                true,
                true,
                false,
            ),
            health_facts(
                scenario == TargetAdapterScenario::TraceOverflow,
                scenario == TargetAdapterScenario::FlowError,
                false,
                false,
                false,
                false,
                false,
            ),
            health_facts(
                scenario == TargetAdapterScenario::TraceOverflow,
                scenario == TargetAdapterScenario::FlowError,
                false,
                false,
                false,
                true,
                true,
            ),
        ] {
            assert!(run.accept_evidence(&invalid).is_err());
            assert_eq!(run.phase(), TargetAdapterPhase::Stopped);
        }
        run.accept_evidence(&expected_health).unwrap();
        assert_eq!(run.phase(), TargetAdapterPhase::HealthVerified);
    }
}

#[test]
fn normal_program_flow_rejects_every_adverse_health_fact() {
    for adverse in [
        health(true, false),
        health(false, true),
        health_facts(false, false, true, false, false, true, false),
        health_facts(false, false, false, true, false, true, false),
        health_facts(false, false, false, false, true, true, false),
        health_facts(false, false, false, false, false, false, false),
        health_facts(false, false, false, false, false, true, false),
    ] {
        let profile = profile();
        let mut run = TargetAdapterRun::new(&profile, TargetAdapterScenario::Normal).unwrap();
        run.accept_evidence(&capabilities()).unwrap();
        run.accept_evidence(&configure(ControllerTargetState::Running))
            .unwrap();
        run.accept_evidence(&start(ControllerTargetState::Running))
            .unwrap();
        run.accept_evidence_artifact(&stop(ControllerTargetState::Running), &digest('d'))
            .unwrap();
        assert!(run.accept_evidence(&adverse).is_err());
        assert_eq!(run.phase(), TargetAdapterPhase::Stopped);
    }
}

#[test]
fn interrupted_run_requires_exact_recovery_and_never_resumes_the_session() {
    let profile = profile();
    let mut run = TargetAdapterRun::new(&profile, TargetAdapterScenario::CmmAbort).unwrap();
    run.accept_evidence(&capabilities()).unwrap();
    run.accept_evidence(&configure(ControllerTargetState::Halted))
        .unwrap();
    run.record_failure(
        PerfOperation::Start,
        binding(),
        TargetAdapterFailureKind::CmmAbort,
        ControllerTargetState::Halted,
    )
    .unwrap();
    assert_eq!(run.phase(), TargetAdapterPhase::RecoveryRequired);

    let mut recovery = TargetAdapterRecoveryEvidence {
        schema: TargetAdapterRecoveryEvidenceSchemaVersion::V1,
        profile_sha256: profile.qualification_identity_digest().unwrap(),
        binding_sha256: binding(),
        failed_operation: PerfOperation::Start,
        failure_kind: TargetAdapterFailureKind::CmmAbort,
        initial_target_state: ControllerTargetState::Halted,
        restored_target_state: ControllerTargetState::Halted,
        adapter_state_restored: true,
        sampling: None,
        upstream_abort_confirmed: false,
        upstream_abort_receipt_sha256: None,
        files_deleted: false,
        new_session_required: true,
    };
    assert!(run.accept_recovery(&recovery).is_err());
    recovery.upstream_abort_confirmed = true;
    recovery.upstream_abort_receipt_sha256 = Some(digest('b'));
    run.accept_recovery(&recovery).unwrap();
    assert_eq!(run.phase(), TargetAdapterPhase::RecoveredTerminal);
    assert!(
        run.accept_evidence(&start(ControllerTargetState::Halted))
            .is_err()
    );
}

#[test]
fn normal_operation_failure_has_an_explicit_terminal_recovery_path() {
    let profile = profile();
    let mut run = TargetAdapterRun::new(&profile, TargetAdapterScenario::Normal).unwrap();
    run.accept_evidence(&capabilities()).unwrap();
    run.accept_evidence(&configure(ControllerTargetState::Running))
        .unwrap();
    run.record_operation_failure(
        PerfOperation::Start,
        binding(),
        ControllerTargetState::Running,
    )
    .unwrap();
    let recovery = TargetAdapterRecoveryEvidence {
        schema: TargetAdapterRecoveryEvidenceSchemaVersion::V1,
        profile_sha256: profile.qualification_identity_digest().unwrap(),
        binding_sha256: binding(),
        failed_operation: PerfOperation::Start,
        failure_kind: TargetAdapterFailureKind::OperationFailure,
        initial_target_state: ControllerTargetState::Running,
        restored_target_state: ControllerTargetState::Running,
        adapter_state_restored: true,
        sampling: None,
        upstream_abort_confirmed: true,
        upstream_abort_receipt_sha256: Some(digest('b')),
        files_deleted: false,
        new_session_required: true,
    };
    run.accept_recovery(&recovery).unwrap();
    assert_eq!(run.phase(), TargetAdapterPhase::RecoveredTerminal);
}

#[test]
fn fault_point_and_failure_kind_cannot_be_relabelled() {
    let profile = profile();
    let mut run =
        TargetAdapterRun::new(&profile, TargetAdapterScenario::Trace32Disconnect).unwrap();
    run.accept_evidence(&capabilities()).unwrap();
    run.accept_evidence(&configure(ControllerTargetState::Running))
        .unwrap();
    run.accept_evidence(&start(ControllerTargetState::Running))
        .unwrap();
    assert!(
        run.record_failure(
            PerfOperation::Stop,
            binding(),
            TargetAdapterFailureKind::DriverDisconnect,
            ControllerTargetState::Running,
        )
        .is_err()
    );
}

#[test]
fn target_adapter_schemas_are_closed_and_versioned() {
    let schemas = target_adapter_schema_documents();
    assert_eq!(
        schemas["target-adapter-profile.schema.json"]["$id"],
        TARGET_ADAPTER_PROFILE_SCHEMA
    );
    assert_eq!(
        schemas["target-adapter-recovery-evidence.schema.json"]["$id"],
        TARGET_ADAPTER_RECOVERY_EVIDENCE_SCHEMA
    );
    assert_eq!(
        schemas["target-adapter-qualification-receipt.schema.json"]["$id"],
        TARGET_ADAPTER_QUALIFICATION_RECEIPT_SCHEMA
    );
    assert_eq!(
        schemas["target-adapter-scenario.schema.json"]["$id"],
        TARGET_ADAPTER_SCENARIO_SELECTION_SCHEMA
    );
    assert_eq!(
        schemas["target-adapter-profile.schema.json"]["additionalProperties"],
        false
    );
    assert_eq!(
        schemas["target-adapter-recovery-evidence.schema.json"]["additionalProperties"],
        false
    );
    assert_eq!(
        CONTROLLER_CAPABILITIES_EVIDENCE_SCHEMA,
        "t32perf.controller-capabilities-evidence/v1"
    );
    assert_eq!(
        CONTROLLER_CAPABILITIES_EVIDENCE_V2_SCHEMA,
        "t32perf.controller-capabilities-evidence/v2"
    );
}

#[test]
fn scenario_selection_is_strict_and_closed() {
    assert!(parse_target_adapter_scenario_selection(
        br#"{"schema":"t32perf.target-adapter-scenario/v1","scenario":"cmm_abort","evidence_only":true}"#,
    )
    .is_ok());
    assert!(parse_target_adapter_scenario_selection(
        br#"{"schema":"t32perf.target-adapter-scenario/v1","scenario":"cmm_abort","evidence_only":true,"extra":false}"#,
    )
    .is_err());
}

#[test]
fn raw_ascii_export_uses_the_fixed_tc234l_item_profile() {
    let script = include_str!(
        "../../../skill-trace32-perf/scripts/adapters/tc234l-build190766/perf_export.cmm"
    );
    assert!(script.contains(
        "SNOOPer.EXPORT.Ascii \"&output\" Address CYcle %TimeFixed TIme.Zero sYmbol /ShowRecord"
    ));
    assert!(
        !script
            .lines()
            .any(|line| line.trim() == "SNOOPer.EXPORT.Ascii \"&output\"")
    );
    let root = include_str!("../../../skill-trace32-perf/scripts/perf_export.cmm");
    assert!(!root.contains("Trace.EXPORT.TASKEVENTS \"&output\""));
    assert!(!script.contains("/NoDummy"));
}

#[test]
fn discovered_tc234l_profile_is_exact_but_unqualified() {
    let candidate = tc234l_build190766_candidate_profile();
    candidate.validate().unwrap();
    assert!(!candidate.has_qualification_claim());
    assert_eq!(
        candidate.controller_protocol,
        TargetAdapterControllerProtocol::V1
    );
    assert!(candidate.custom_event_collector.is_none());
    assert_eq!(
        candidate.capabilities.custom_events.support,
        MetricSupportLevel::Unavailable
    );
    assert_eq!(candidate.build_gate.minimum_build, 190_766);
    assert_eq!(candidate.build_gate.maximum_build, 190_766);
    assert_eq!(candidate.target_identifier, "infineon-tc234l-core0");
    assert_eq!(candidate.scenarios[0].capture.covered_cores, vec![0]);

    let mut registry = TargetAdapterRegistry::new();
    assert!(registry.register(candidate, b"").is_err());
}

#[test]
fn legacy_v1_profile_without_custom_event_fields_decodes_as_v1() {
    let profile = tc234l_build190766_candidate_profile();
    let legacy_bytes = serde_json::to_vec(&profile).unwrap();
    let legacy: serde_json::Value = serde_json::from_slice(&legacy_bytes).unwrap();
    assert!(legacy.get("controller_protocol").is_none());
    assert!(legacy.get("custom_event_collector").is_none());

    let decoded = parse_target_adapter_profile(&legacy_bytes).unwrap();
    assert_eq!(
        decoded.controller_protocol,
        TargetAdapterControllerProtocol::V1
    );
    assert!(decoded.custom_event_collector.is_none());
    decoded.validate().unwrap();
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), legacy_bytes);
    assert_eq!(
        decoded.digest().unwrap().as_str(),
        "5f75195dffce414c657e6fad37096e3d3926beff95dbd0a0c4ac11eeb9a6ae81"
    );
}

#[test]
fn v2_custom_event_collector_contract_is_explicit_and_valid() {
    let profile = v2_custom_event_profile();
    profile.validate().unwrap();
    let serialized = serde_json::to_value(&profile).unwrap();
    assert_eq!(
        serialized["controller_protocol"],
        serde_json::json!("v2_custom_events_export")
    );
    assert!(serialized["custom_event_collector"].is_object());
    assert_eq!(
        profile.controller_protocol,
        TargetAdapterControllerProtocol::V2CustomEventsExport
    );
    let collector = profile.custom_event_collector.as_ref().unwrap();
    assert_eq!(
        collector.wire_protocol,
        TargetAdapterCustomEventWireProtocol::CWireV1
    );
    assert_eq!(
        collector.merge_order,
        TargetAdapterCustomEventMergeOrder::RejectAmbiguousTies
    );
    assert_eq!(collector.clock.clock_id, "fixture-trace-clock/v1");
    assert_eq!(
        profile.capabilities.custom_events.support,
        MetricSupportLevel::Exact
    );
    assert_eq!(
        profile.capabilities.counters.support,
        MetricSupportLevel::Exact
    );
}

#[test]
fn controller_protocol_and_custom_event_capability_must_match() {
    let mut v1_with_capability = profile();
    v1_with_capability.qualification_sha256 = None;
    v1_with_capability.capabilities.custom_events =
        MetricSupportEntry::new(MetricSupportLevel::Exact);
    assert!(v1_with_capability.validate().is_err());

    let mut v1_with_collector = v2_custom_event_profile();
    v1_with_collector.controller_protocol = TargetAdapterControllerProtocol::V1;
    assert!(v1_with_collector.validate().is_err());

    let mut v2_without_collector = v2_custom_event_profile();
    v2_without_collector.custom_event_collector = None;
    assert!(v2_without_collector.validate().is_err());

    for support in [
        MetricSupportLevel::Statistical,
        MetricSupportLevel::Unavailable,
    ] {
        let mut profile = v2_custom_event_profile();
        profile.capabilities.custom_events = match support {
            MetricSupportLevel::Statistical => MetricSupportEntry {
                support,
                reasons: vec!["not-exact".to_owned()],
            },
            MetricSupportLevel::Unavailable => MetricSupportEntry::unavailable("not-supported"),
            _ => unreachable!(),
        };
        assert!(profile.validate().is_err());
    }

    for support in [
        MetricSupportLevel::Statistical,
        MetricSupportLevel::Unavailable,
    ] {
        let mut counters_not_exact = v2_custom_event_profile();
        counters_not_exact.capabilities.counters = match support {
            MetricSupportLevel::Statistical => MetricSupportEntry {
                support,
                reasons: vec!["not-exact".to_owned()],
            },
            MetricSupportLevel::Unavailable => MetricSupportEntry::unavailable("not-supported"),
            _ => unreachable!(),
        };
        assert!(counters_not_exact.validate().is_err());
    }
}

#[test]
fn v2_custom_event_collector_requires_program_flow_core_and_shared_clock() {
    let mut sampling = tc234l_build190766_candidate_profile();
    sampling.controller_protocol = TargetAdapterControllerProtocol::V2CustomEventsExport;
    sampling.custom_event_collector = Some(custom_event_collector());
    sampling.capabilities.custom_events = MetricSupportEntry::new(MetricSupportLevel::Exact);
    assert!(sampling.validate().is_err());

    let mut wrong_core = v2_custom_event_profile();
    wrong_core.custom_event_collector.as_mut().unwrap().core_id = 1;
    assert!(wrong_core.validate().is_err());

    let mut wrong_clock = v2_custom_event_profile();
    wrong_clock
        .custom_event_collector
        .as_mut()
        .unwrap()
        .clock
        .clock_id = "different-clock/v1".to_owned();
    assert!(wrong_clock.validate().is_err());
}

#[test]
fn v2_custom_event_collector_rejects_invalid_clock_artifacts_and_output_bound() {
    for mutate in [
        |collector: &mut TargetAdapterCustomEventCollectorContract| {
            collector.clock.frequency_hz = 0;
        },
        |collector: &mut TargetAdapterCustomEventCollectorContract| {
            collector.clock.frequency_hz = MAX_CUSTOM_EVENT_CLOCK_FREQUENCY_HZ + 1;
        },
        |collector: &mut TargetAdapterCustomEventCollectorContract| {
            collector.clock.timestamp_modulus = 1;
        },
        |collector: &mut TargetAdapterCustomEventCollectorContract| {
            collector.clock.max_forward_ticks = collector.clock.timestamp_modulus;
        },
        |collector: &mut TargetAdapterCustomEventCollectorContract| {
            collector.clock.origin_ticks = collector.clock.timestamp_modulus;
        },
        |collector: &mut TargetAdapterCustomEventCollectorContract| {
            collector.clock.origin_ns = 1;
        },
    ] {
        let mut profile = v2_custom_event_profile();
        mutate(profile.custom_event_collector.as_mut().unwrap());
        assert!(profile.validate().is_err());
    }

    let mut nonportable_mapping = v2_custom_event_profile();
    nonportable_mapping
        .custom_event_collector
        .as_mut()
        .unwrap()
        .mapping_artifact_id = "not/portable".to_owned();
    assert!(nonportable_mapping.validate().is_err());

    let mut duplicate_artifacts = v2_custom_event_profile();
    let collector = duplicate_artifacts.custom_event_collector.as_mut().unwrap();
    collector.instrumentation_overhead_artifact_id = collector.mapping_artifact_id.clone();
    assert!(duplicate_artifacts.validate().is_err());

    for max_output_bytes in [0, MAX_CUSTOM_EVENT_COLLECTOR_OUTPUT_BYTES + 1] {
        let mut profile = v2_custom_event_profile();
        profile
            .custom_event_collector
            .as_mut()
            .unwrap()
            .max_output_bytes = max_output_bytes;
        assert!(profile.validate().is_err());
    }
}

#[test]
fn sampling_profiles_cannot_claim_program_flow_fault_scenarios() {
    let mut profile = tc234l_build190766_candidate_profile();
    let capture = profile
        .scenario(TargetAdapterScenario::Normal)
        .unwrap()
        .capture
        .clone();
    profile
        .health_signals
        .push(ControllerHealthSignal::TraceOverflow);
    profile.scenarios.push(TargetAdapterScenarioContract {
        scenario: TargetAdapterScenario::TraceOverflow,
        fault_point: None,
        capture,
    });
    assert!(profile.validate().is_err());
}

#[test]
fn sampling_health_requires_a_positive_firmware_match_before_export() {
    for (scenario, pre_stop_state, recorded_records) in [
        (
            TargetAdapterScenario::Normal,
            ControllerSamplingPreStopState::Arm,
            128,
        ),
        (
            TargetAdapterScenario::SamplingBufferFull,
            ControllerSamplingPreStopState::Break,
            32,
        ),
    ] {
        let profile = tc234l_build190766_candidate_profile();
        let capture = profile
            .scenarios
            .iter()
            .find(|contract| contract.scenario == scenario)
            .unwrap()
            .capture
            .clone();
        let mut run = TargetAdapterRun::new(&profile, scenario).unwrap();
        accept_sampling_until_stopped(
            &mut run,
            &profile,
            &capture,
            ControllerTargetState::Running,
            pre_stop_state,
            recorded_records,
        );

        for firmware_match in [None, Some(false)] {
            assert!(
                run.accept_evidence(&sampling_health(
                    &profile,
                    pre_stop_state,
                    sampling_capacity(&capture),
                    recorded_records,
                    firmware_match,
                ))
                .is_err()
            );
            assert_eq!(run.phase(), TargetAdapterPhase::Stopped);
            assert!(run.accept_export(&sampling_export_response()).is_err());
        }

        run.accept_evidence(&sampling_health(
            &profile,
            pre_stop_state,
            sampling_capacity(&capture),
            recorded_records,
            Some(true),
        ))
        .unwrap();
        assert_eq!(run.phase(), TargetAdapterPhase::HealthVerified);
    }
}

#[test]
fn sampling_health_rejects_a_firmware_claim_not_declared_by_the_profile() {
    let mut profile = tc234l_build190766_candidate_profile();
    profile
        .health_signals
        .retain(|signal| *signal != ControllerHealthSignal::ElfMismatch);
    let capture = profile
        .scenarios
        .iter()
        .find(|contract| contract.scenario == TargetAdapterScenario::Normal)
        .unwrap()
        .capture
        .clone();
    let mut run = TargetAdapterRun::new(&profile, TargetAdapterScenario::Normal).unwrap();
    accept_sampling_until_stopped(
        &mut run,
        &profile,
        &capture,
        ControllerTargetState::Running,
        ControllerSamplingPreStopState::Arm,
        128,
    );

    assert!(
        run.accept_evidence(&sampling_health(
            &profile,
            ControllerSamplingPreStopState::Arm,
            sampling_capacity(&capture),
            128,
            Some(true),
        ))
        .is_err()
    );
    assert_eq!(run.phase(), TargetAdapterPhase::Stopped);
    assert!(run.accept_export(&sampling_export_response()).is_err());

    run.accept_evidence(&sampling_health(
        &profile,
        ControllerSamplingPreStopState::Arm,
        sampling_capacity(&capture),
        128,
        None,
    ))
    .unwrap();
    assert_eq!(run.phase(), TargetAdapterPhase::HealthVerified);
}

#[test]
fn tc234l_sampling_replays_v2_evidence_for_both_initial_states() {
    let profile = tc234l_build190766_candidate_profile();
    let normal = profile
        .scenarios
        .iter()
        .find(|contract| contract.scenario == TargetAdapterScenario::Normal)
        .unwrap();
    let mut v1_run = TargetAdapterRun::new(&profile, TargetAdapterScenario::Normal).unwrap();
    assert!(v1_run.accept_evidence(&capabilities()).is_err());
    let mut mismatched_state_run =
        TargetAdapterRun::new(&profile, TargetAdapterScenario::Normal).unwrap();
    mismatched_state_run
        .accept_evidence(&capabilities_v2(
            &profile,
            &normal.capture,
            ControllerTargetState::Running,
        ))
        .unwrap();
    assert!(
        mismatched_state_run
            .accept_evidence(&ControllerEvidence::Configure(
                ControllerConfigureEvidence {
                    schema: ControllerConfigureEvidenceSchemaVersion::V1,
                    operation: ControllerConfigureOperation::V1,
                    binding_sha256: binding(),
                    configuration_sha256: normal.capture.configuration_sha256_by_initial_state
                        [&ControllerTargetState::Halted]
                        .clone(),
                    capture_mode: normal.capture.capture_mode.clone(),
                    trace_sink: normal.capture.trace_sink.clone(),
                    timestamp_enabled: normal.capture.timestamp_enabled,
                    filters_verified: true,
                    trigger_verified: true,
                    initial_target_state: ControllerTargetState::Halted,
                    workload_identity: normal.capture.workload_identity.clone(),
                    covered_cores: normal.capture.covered_cores.clone(),
                },
            ))
            .is_err()
    );

    for initial in [
        ControllerTargetState::Running,
        ControllerTargetState::Halted,
    ] {
        let profile = tc234l_build190766_candidate_profile();
        let normal = profile
            .scenarios
            .iter()
            .find(|contract| contract.scenario == TargetAdapterScenario::Normal)
            .unwrap();
        let mut run = TargetAdapterRun::new(&profile, TargetAdapterScenario::Normal).unwrap();
        run.accept_evidence(&capabilities_v2(&profile, &normal.capture, initial))
            .unwrap();
        run.accept_evidence(&ControllerEvidence::Configure(
            ControllerConfigureEvidence {
                schema: ControllerConfigureEvidenceSchemaVersion::V1,
                operation: ControllerConfigureOperation::V1,
                binding_sha256: binding(),
                configuration_sha256: normal.capture.configuration_sha256_by_initial_state
                    [&initial]
                    .clone(),
                capture_mode: normal.capture.capture_mode.clone(),
                trace_sink: normal.capture.trace_sink.clone(),
                timestamp_enabled: true,
                filters_verified: true,
                trigger_verified: true,
                initial_target_state: initial,
                workload_identity: normal.capture.workload_identity.clone(),
                covered_cores: vec![0],
            },
        ))
        .unwrap();
        run.accept_evidence(&ControllerEvidence::StartV2(ControllerStartEvidenceV2 {
            schema: ControllerStartEvidenceV2SchemaVersion::V1,
            operation: ControllerStartOperation::V1,
            binding_sha256: binding(),
            initial_target_state: initial,
            capture_armed: true,
            workload_owner: ControllerWorkloadOwner::TargetSpecificController,
            workload_identity: normal.capture.workload_identity.clone(),
        }))
        .unwrap();
        run.accept_evidence(&ControllerEvidence::StopV2(ControllerStopEvidenceV2 {
            schema: ControllerStopEvidenceV2SchemaVersion::V1,
            operation: ControllerStopOperation::V1,
            binding_sha256: binding(),
            capture_stopped: true,
            workload_identity: normal.capture.workload_identity.clone(),
            target_state_after_stop: initial,
            pre_stop_state: ControllerSamplingPreStopState::Arm,
            capacity_records: 65_536,
            recorded_records: 128,
            time_origin_zeroed_to_first_record: true,
        }))
        .unwrap();
        run.accept_evidence(&ControllerEvidence::HealthV2(ControllerHealthEvidenceV2 {
            schema: ControllerHealthEvidenceV2SchemaVersion::V1,
            operation: ControllerHealthOperation::V1,
            binding_sha256: binding(),
            capture_stopped: true,
            supported_signals: profile.health_signals.clone(),
            stop_evidence_sha256: digest('c'),
            sampling: ControllerSamplingHealthEvidence {
                method: ControllerSamplingMethod::RealTime,
                object: ControllerSamplingObject::ProgramCounter,
                buffer_mode: ControllerSamplingBufferMode::Stack,
                state: ControllerSamplingState::Off,
                pre_stop_state: ControllerSamplingPreStopState::Arm,
                requested_rate_ns: 1_000_000,
                capacity_records: 65_536,
                recorded_records: 128,
                buffer_full: false,
                unexpected_stop: false,
            },
            elf_matches_firmware: Some(true),
        }))
        .unwrap();
        run.accept_export(&sampling_export_response()).unwrap();
        assert!(run.accept_evidence(&cleanup()).is_err());
        run.accept_evidence(&sampling_cleanup(initial)).unwrap();
        assert_eq!(run.phase(), TargetAdapterPhase::Cleaned);
    }
}

#[test]
fn checked_tc234l_candidate_binds_the_exact_preflight_script() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let directory = root.join("skill-trace32-perf/scripts/adapters/tc234l-build190766");
    let profile_bytes = fs::read(directory.join("profile.json")).unwrap();
    let profile = parse_target_adapter_profile(&profile_bytes).unwrap();
    assert_eq!(profile, tc234l_build190766_candidate_profile());
    assert!(!profile.has_qualification_claim());
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.join("bundle-manifest.json")).unwrap()).unwrap();
    let mut lines = Vec::new();
    let mut previous_path: Option<&str> = None;
    for entry in manifest["files"].as_array().unwrap() {
        let path = entry["path"].as_str().unwrap();
        assert!(
            previous_path.is_none_or(|previous| previous < path),
            "bundle manifest paths must be strictly bytewise sorted and unique"
        );
        previous_path = Some(path);
        let expected = entry["sha256"].as_str().unwrap();
        let actual = Sha256::digest(fs::read(directory.join(path)).unwrap())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(actual, expected);
        lines.push(format!("{path} {expected}"));
    }
    let canonical = format!("{}\n", lines.join("\n"));
    let bundle = Sha256::digest(canonical.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(bundle, manifest["bundle_sha256"]);
    assert_eq!(profile.implementation_sha256.to_string(), bundle);
}

#[test]
fn fixed_snooper_capture_config_digests_are_stable() {
    for (state, capacity, expected) in [
        (
            ControllerTargetState::Running,
            65_536,
            "45ad2a31dcf8558e0155446871c1b4a684f4e769767dc0fcaffa70277eff1dd6",
        ),
        (
            ControllerTargetState::Halted,
            65_536,
            "a4a59ed9aa03965154148ef84c91d0529b99ae41990661ada7f0f83c36bd5a32",
        ),
        (
            ControllerTargetState::Running,
            32,
            "94c2642c43670a1dc80711a319549438bc20680a843d3f213a1cac2f2ef205f0",
        ),
        (
            ControllerTargetState::Halted,
            32,
            "b3863046a6e770fa7e2915324082fff047ac280e0e9ef37c169d6ae60a1cf427",
        ),
    ] {
        let config = tc234l_snooper_capture_config("digest-test", state, capacity);
        config.validate().unwrap();
        let digest = Sha256::digest(config.configuration_identity_bytes().unwrap())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(digest, expected);
    }
    let configure = include_str!(
        "../../../skill-trace32-perf/scripts/adapters/tc234l-build190766/perf_configure.cmm"
    );
    assert!(configure.contains("45ad2a31dcf8558e0155446871c1b4a684f4e769767dc0fcaffa70277eff1dd6"));
}

#[test]
fn sparse_s3_measurement_is_the_only_firmware_runtime_check() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let directory = root.join("skill-trace32-perf/scripts/adapters/tc234l-build190766");
    let template: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.join("capture-config-template.json")).unwrap())
            .unwrap();
    assert_eq!(
        template["firmware_measurement_artifact_id"],
        "trace32-firmware-s3"
    );
    assert_eq!(template["firmware_elf_artifact_id"], "firmware-elf");
    for script_path in [
        "perf_configure.cmm",
        "perf_get_health.cmm",
        "faults/perf_configure_sampling_buffer_full.cmm",
    ] {
        let script = fs::read_to_string(directory.join(script_path)).unwrap();
        assert!(!script.contains("Data.LOAD.auto"));
        assert!(script.contains("Data.LOAD.S3record \"&firmware\" /DIFF"));
        assert!(script.contains(
            "ERROR.RESet\n    ON ERROR CONTinue\n    Data.LOAD.S3record \"&firmware\" /DIFF"
        ));
        assert!(!script.contains("/CRC32"));
    }
}

#[test]
fn public_dispatch_is_known_only_and_main_scripts_never_drive_the_cpu() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let scripts = root.join("skill-trace32-perf/scripts");
    let export = fs::read_to_string(scripts.join("perf_export.cmm")).unwrap();
    assert!(!export.contains("Trace.EXPORT.TASKEVENTS"));
    assert!(export.contains("task_events_export_failed"));
    for name in [
        "perf_get_capabilities.cmm",
        "perf_configure.cmm",
        "perf_start.cmm",
        "perf_stop.cmm",
        "perf_get_health.cmm",
        "perf_export.cmm",
        "perf_cleanup.cmm",
    ] {
        let script =
            fs::read_to_string(scripts.join("adapters/tc234l-build190766").join(name)).unwrap();
        assert!(!script.lines().any(|line| {
            matches!(
                line.trim().to_ascii_lowercase().as_str(),
                "go" | "break" | "wait"
            )
        }));
    }
}

#[test]
fn public_configure_and_start_dispatch_use_closed_argument_sets() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let scripts = root.join("skill-trace32-perf/scripts");
    for (name, required, count_variables, extra_argument) in [
        (
            "perf_configure.cmm",
            [
                "binding_sha256",
                "evidence_output",
                "firmware_s3",
                "initial_target_state",
                "scenario",
            ]
            .as_slice(),
            [
                "binding_count",
                "evidence_count",
                "firmware_count",
                "initial_count",
                "scenario_count",
            ]
            .as_slice(),
            "&arg6",
        ),
        (
            "perf_start.cmm",
            [
                "binding_sha256",
                "evidence_output",
                "initial_target_state",
                "scenario",
                "capacity_records",
            ]
            .as_slice(),
            [
                "binding_count",
                "evidence_count",
                "initial_count",
                "scenario_count",
                "capacity_count",
            ]
            .as_slice(),
            "&arg6",
        ),
        (
            "perf_get_health.cmm",
            [
                "binding_sha256",
                "evidence_output",
                "stop_evidence_sha256",
                "pre_stop_state",
                "recorded_records",
                "capacity_records",
                "firmware_s3",
            ]
            .as_slice(),
            [
                "binding_count",
                "evidence_count",
                "stopsha_count",
                "prestate_count",
                "records_count",
                "capacity_count",
                "firmware_count",
            ]
            .as_slice(),
            "&arg8",
        ),
    ] {
        let script = fs::read_to_string(scripts.join(name)).unwrap();
        let schema_text = script
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("; Schema: "))
            .unwrap();
        let schema: serde_json::Value = serde_json::from_str(schema_text).unwrap();
        assert_eq!(schema["required"], serde_json::json!(required), "{name}");
        assert_eq!(schema["additionalProperties"], false, "{name}");
        assert_eq!(
            schema["properties"].as_object().unwrap().len(),
            required.len(),
            "{name}"
        );
        for variable in count_variables {
            assert!(script.contains(&format!("&{variable}!=1.")), "{name}");
        }
        assert!(
            script.contains(&format!("IF \"{extra_argument}\"!=\"\"")),
            "{name}"
        );
        assert!(
            script
                .lines()
                .any(|line| line.starts_with("ENTRY ") && line.contains(extra_argument)),
            "{name}"
        );
        assert!(script.contains("&unknown_count!=0."), "{name}");
        assert!(
            script.contains("&unknown_count=&unknown_count+1."),
            "{name}"
        );
    }

    let configure = fs::read_to_string(scripts.join("perf_configure.cmm")).unwrap();
    assert!(
        configure
            .contains("perf_configure.cmm \"&binding\" \"&evidence\" \"&firmware\" \"&initial\"")
    );
    assert!(configure.contains(
        "perf_configure_sampling_buffer_full.cmm \"&binding\" \"&evidence\" \"&firmware\" \"&initial\""
    ));
    let start = fs::read_to_string(scripts.join("perf_start.cmm")).unwrap();
    assert!(start.contains("perf_start.cmm \"&binding\" \"&evidence\" \"&initial\" \"&capacity\""));
    assert!(
        start.contains("perf_start_cmm_abort_target.cmm \"&binding\" \"&initial\" \"&capacity\"")
    );
    assert!(!start.contains("trace32_disconnect"));
    assert!(!start.contains("driver_disconnect"));

    let stop = fs::read_to_string(scripts.join("perf_stop.cmm")).unwrap();
    let schema_text = stop
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("; Schema: "))
        .unwrap();
    let schema: serde_json::Value = serde_json::from_str(schema_text).unwrap();
    assert_eq!(
        schema["required"],
        serde_json::json!(["binding_sha256", "evidence_output", "capacity_records"])
    );
    assert_eq!(schema["additionalProperties"], false);
    assert!(stop.contains("ENTRY %LINE &line"));
    for permutation in ["&qbec", "&qbce", "&qebc", "&qecb", "&qcbe", "&qceb"] {
        assert!(stop.contains(permutation));
    }
    assert!(stop.contains("perf_stop.cmm \"&binding\" \"&evidence\" \"&capacity\""));
}

#[test]
fn start_and_stop_scripts_gate_the_scenario_capacity_before_mutation() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let adapter = root.join("skill-trace32-perf/scripts/adapters/tc234l-build190766");
    for (name, entry) in [
        (
            "perf_start.cmm",
            "ENTRY &binding &evidence &initial &capacity",
        ),
        (
            "faults/perf_start_cmm_abort_target.cmm",
            "ENTRY &binding &initial &capacity",
        ),
    ] {
        let script = fs::read_to_string(adapter.join(name)).unwrap();
        assert!(script.contains(entry), "{name}");
        assert!(script.contains("SNOOPer.SIZE()!=&capacity"), "{name}");
        assert!(
            script.find("SNOOPer.SIZE()!=&capacity").unwrap()
                < script.find("SNOOPer.Init").unwrap()
        );
    }
    let stop = fs::read_to_string(adapter.join("perf_stop.cmm")).unwrap();
    assert!(stop.contains("ENTRY &binding &evidence &expected_capacity"));
    assert!(stop.contains("SNOOPer.SIZE()!=&expected_capacity"));
    assert!(stop.find("GOSUB Gate").unwrap() < stop.find("SNOOPer.OFF").unwrap());
    assert!(stop.contains("&capacity!=&expected_capacity"));
}

#[test]
fn target_mutations_are_preceded_by_capabilities_bound_state_gates() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let adapter = root.join("skill-trace32-perf/scripts/adapters/tc234l-build190766");
    for (name, entry, mutation) in [
        (
            "perf_configure.cmm",
            "ENTRY &binding &evidence &firmware &initial",
            "SNOOPer.RESet",
        ),
        (
            "perf_start.cmm",
            "ENTRY &binding &evidence &initial &capacity",
            "SNOOPer.Init",
        ),
        (
            "faults/perf_configure_sampling_buffer_full.cmm",
            "ENTRY &binding &evidence &firmware &initial",
            "SNOOPer.RESet",
        ),
        (
            "faults/perf_start_cmm_abort_target.cmm",
            "ENTRY &binding &initial &capacity",
            "SNOOPer.Init",
        ),
    ] {
        let script = fs::read_to_string(adapter.join(name)).unwrap();
        assert!(script.contains(entry), "{name}");
        let gate = script.find("GOSUB StateGate").unwrap();
        let mutation = script.find(mutation).unwrap();
        assert!(gate < mutation, "{name}");
        assert!(
            script.contains("\"\"status\"\":\"\"INVALID_ARGUMENT\"\""),
            "{name}"
        );
        assert!(
            script.contains("\"\"code\"\":\"\"initial_target_state_drift\"\""),
            "{name}"
        );
        assert!(script.contains("expected_initial_target_state"), "{name}");
        assert!(script.contains("observed_target_state"), "{name}");
        assert!(!script.contains("PRECONDITION_FAILED"), "{name}");
    }
}

#[test]
fn mutation_and_post_configure_failures_never_emit_terminal_frames() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let adapter = root.join("skill-trace32-perf/scripts/adapters/tc234l-build190766");
    for name in [
        "perf_start.cmm",
        "perf_stop.cmm",
        "perf_get_health.cmm",
        "perf_export.cmm",
        "perf_cleanup.cmm",
    ] {
        let script = fs::read_to_string(adapter.join(name)).unwrap();
        assert!(script.contains("T32PERF_MUTATION_RECOVERY_REQUIRED"));
        assert!(!script.contains(r#""status"":""UNSUPPORTED_NEEDS_TRACE32""#));
    }
    for (name, label) in [
        ("perf_configure.cmm", "MutationFailure:"),
        ("perf_start.cmm", "MutationFailure:"),
        ("perf_stop.cmm", "MutationFailure:"),
        ("perf_export.cmm", "MutationFailure:"),
        ("perf_cleanup.cmm", "MutationFailure:"),
        (
            "faults/perf_configure_sampling_buffer_full.cmm",
            "MutationFailure:",
        ),
        ("faults/perf_start_cmm_abort_target.cmm", "RecoverAndFail:"),
    ] {
        let script = fs::read_to_string(adapter.join(name)).unwrap();
        let failure_path = script.split_once(label).unwrap().1;
        assert!(!failure_path.contains("T32PERF_RESULT_BEGIN"), "{name}");
        assert!(!failure_path.contains("GOSUB StateGate"), "{name}");
        assert!(failure_path.contains("WAIT 1.s"), "{name}");
    }
}
