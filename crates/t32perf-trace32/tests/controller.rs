use std::collections::BTreeMap;

use sha2::{Digest as _, Sha256};
use t32perf_model::{Artifact, ArtifactPath, Sha256Digest};
use t32perf_trace32::{
    CONTROLLER_ABORT_RECEIPT_SCHEMA, CONTROLLER_ABORT_REQUEST_SCHEMA,
    CONTROLLER_CAPABILITIES_EVIDENCE_SCHEMA, CONTROLLER_CAPABILITIES_EVIDENCE_V2_SCHEMA,
    CONTROLLER_CLEANUP_EVIDENCE_SCHEMA, CONTROLLER_CLEANUP_EVIDENCE_V2_SCHEMA,
    CONTROLLER_CONFIGURE_EVIDENCE_SCHEMA, CONTROLLER_DRIVER_EVENT_SCHEMA,
    CONTROLLER_HEALTH_EVIDENCE_SCHEMA, CONTROLLER_HEALTH_EVIDENCE_V2_SCHEMA,
    CONTROLLER_HEALTH_EVIDENCE_V3_SCHEMA, CONTROLLER_REQUEST_SCHEMA, CONTROLLER_REQUEST_V2_SCHEMA,
    CONTROLLER_RESPONSE_SCHEMA, CONTROLLER_RESPONSE_V2_SCHEMA, CONTROLLER_START_EVIDENCE_SCHEMA,
    CONTROLLER_START_EVIDENCE_V2_SCHEMA, CONTROLLER_STOP_EVIDENCE_SCHEMA,
    CONTROLLER_STOP_EVIDENCE_V2_SCHEMA, ControllerAbortReason, ControllerAbortRequest,
    ControllerAbortRequestSchemaVersion, ControllerBinding, ControllerCapabilitiesEvidence,
    ControllerCapabilitiesEvidenceSchemaVersion, ControllerCapabilitiesEvidenceV2,
    ControllerCapabilitiesEvidenceV2SchemaVersion, ControllerCapabilitiesOperation,
    ControllerCaptureCompletionEvidence, ControllerContractError, ControllerDriverEvent,
    ControllerDriverEventKind, ControllerDriverEventSchemaVersion, ControllerFaultAction,
    ControllerFirmwareImageBinding, ControllerHealthSignal, ControllerMcpHandoff,
    ControllerOutputReservation, ControllerOutputReservationV2, ControllerOutputRole,
    ControllerOutputRoleV2, ControllerRequest, ControllerRequestSchemaVersion, ControllerRequestV2,
    ControllerRequestV2SchemaVersion, ControllerResponse, ControllerResponseSchemaVersion,
    ControllerResponseV2, ControllerResponseV2SchemaVersion, ControllerScriptResponse,
    ControllerTargetAdapterBinding, ControllerTargetState, ExecutePracticeSkillArguments,
    ExecutePracticeSkillCall, MAX_CONTROLLER_MCP_RESPONSE_BYTES, NoArguments, NoArgumentsToolCall,
    PerfOperation, PerfStatus, T32PERF_SKILL_NAME, T32mcpTool, TargetAdapterCaptureKind,
    TargetAdapterControllerProtocol, TargetAdapterCustomEventClockContract,
    TargetAdapterCustomEventCollectorContract, TargetAdapterCustomEventMergeOrder,
    TargetAdapterCustomEventWireProtocol, compute_controller_binding_sha256,
    controller_schema_documents, parse_controller_evidence,
};

fn binding() -> ControllerBinding {
    let session_request_sha256 = Sha256Digest::new("1".repeat(64)).unwrap();
    let session_id = "controller-test";
    let session_operation_id = "2".repeat(32);
    let transaction_id = "3".repeat(32);
    let nonce = "4".repeat(32);
    let binding_sha256 = compute_controller_binding_sha256(
        session_id,
        &session_operation_id,
        &session_request_sha256,
        &transaction_id,
        &nonce,
    );
    ControllerBinding {
        session_id: session_id.to_owned(),
        session_operation_id,
        session_request_sha256,
        transaction_id,
        nonce,
        binding_sha256,
    }
}

fn target_adapter() -> ControllerTargetAdapterBinding {
    ControllerTargetAdapterBinding {
        adapter_id: "test-adapter".to_owned(),
        adapter_version: "1.0.0".to_owned(),
        trace32_release: "2026.02".to_owned(),
        trace32_build: 190_766,
        architecture_package: "tricore".to_owned(),
        target_identifier: "test-target".to_owned(),
        probe_identifier: "test-probe".to_owned(),
        profile_sha256: Sha256Digest::new("5".repeat(64)).unwrap(),
        implementation_sha256: Sha256Digest::new("6".repeat(64)).unwrap(),
        scenario: t32perf_trace32::TargetAdapterScenario::Normal,
        capture_kind: TargetAdapterCaptureKind::Sampling {
            capacity_records: 65_536,
        },
        controller_protocol: TargetAdapterControllerProtocol::V1,
        custom_event_collector: None,
        qualification_sha256: None,
    }
}

fn custom_event_collector() -> TargetAdapterCustomEventCollectorContract {
    TargetAdapterCustomEventCollectorContract {
        wire_protocol: TargetAdapterCustomEventWireProtocol::CWireV1,
        source_id: "test-custom-events".to_owned(),
        core_id: 0,
        clock: TargetAdapterCustomEventClockContract {
            clock_id: "test-shared-clock".to_owned(),
            frequency_hz: 100_000_000,
            timestamp_modulus: 1_u64 << 32,
            max_forward_ticks: 1_u64 << 31,
            origin_ticks: 0,
            origin_ns: 0,
        },
        transport: "shared-memory-ring-buffer/v1".to_owned(),
        mapping_artifact_id: "test-c-wire-mapping".to_owned(),
        instrumentation_overhead_artifact_id: "test-instrumentation-overhead".to_owned(),
        max_output_bytes: 1024 * 1024,
        merge_order: TargetAdapterCustomEventMergeOrder::RejectAmbiguousTies,
    }
}

fn v2_target_adapter() -> ControllerTargetAdapterBinding {
    let mut adapter = target_adapter();
    adapter.capture_kind = TargetAdapterCaptureKind::ProgramFlowTaskEvents {
        export_profile_id: "test-task-events/v1".to_owned(),
        rtos_awareness: "test-rtos/v1".to_owned(),
        timestamp_clock_id: "test-shared-clock".to_owned(),
        orti_artifact_id: "test-orti".to_owned(),
        task_marker_artifact_id: "test-task-markers".to_owned(),
    };
    adapter.controller_protocol = TargetAdapterControllerProtocol::V2CustomEventsExport;
    adapter.custom_event_collector = Some(custom_event_collector());
    adapter
}

fn request() -> ControllerRequest {
    let binding = binding();
    ControllerRequest {
        schema: ControllerRequestSchemaVersion::V1,
        operation: PerfOperation::GetHotspots,
        adapter_catalog_sha256: Sha256Digest::new("7".repeat(64)).unwrap(),
        target_adapter: None,
        fault_action: None,
        firmware_image: ControllerFirmwareImageBinding {
            source_elf_artifact: Artifact {
                id: "firmware-elf".to_owned(),
                kind: "firmware_elf".to_owned(),
                relative_path: ArtifactPath::new("capture/firmware.elf").unwrap(),
                media_type: "application/x-elf".to_owned(),
                size_bytes: 1,
                sha256: Sha256Digest::new("8".repeat(64)).unwrap(),
                producer: "test-firmware".to_owned(),
                input_artifact_ids: Vec::new(),
            },
            measurement_artifact: Artifact {
                id: "trace32-firmware-s3".to_owned(),
                kind: "trace32_firmware_measurement".to_owned(),
                relative_path: ArtifactPath::new("capture/trace32-firmware.s3").unwrap(),
                media_type: "application/vnd.motorola-s-record".to_owned(),
                size_bytes: 1,
                sha256: Sha256Digest::new("9".repeat(64)).unwrap(),
                producer: "t32perf-controller-firmware-image/v1".to_owned(),
                input_artifact_ids: vec!["firmware-elf".to_owned()],
            },
            script_input_path: "E:/staging/firmware.s3".to_owned(),
        },
        mcp: ControllerMcpHandoff {
            execute: ExecutePracticeSkillCall {
                tool: T32mcpTool::ExecutePracticeSkill,
                arguments: ExecutePracticeSkillArguments {
                    skill_name: T32PERF_SKILL_NAME.to_owned(),
                    script_name: PerfOperation::GetHotspots.script_name().to_owned(),
                    script_args: BTreeMap::from([(
                        "binding_sha256".to_owned(),
                        binding.binding_sha256.to_string(),
                    )]),
                },
            },
            collect: NoArgumentsToolCall {
                tool: T32mcpTool::CollectPracticeSkillResponse,
                arguments: NoArguments::default(),
            },
            abort: NoArgumentsToolCall {
                tool: T32mcpTool::AbortPracticeSkill,
                arguments: NoArguments::default(),
            },
        },
        binding,
        response_staging_path: ArtifactPath::new(format!(
            "controller/{}.mcp-response.txt",
            "3".repeat(32)
        ))
        .unwrap(),
        max_response_bytes: MAX_CONTROLLER_MCP_RESPONSE_BYTES,
        output: None,
    }
}

fn request_artifact(request: &ControllerRequest) -> Artifact {
    Artifact {
        id: format!("controller-request-{}", request.binding.transaction_id),
        kind: "controller_request".to_owned(),
        relative_path: ArtifactPath::new(format!(
            "logs/controller/requests/{}.json",
            request.binding.transaction_id
        ))
        .unwrap(),
        media_type: "application/json".to_owned(),
        size_bytes: 1,
        sha256: Sha256Digest::new("a".repeat(64)).unwrap(),
        producer: "t32perf-controller/v1".to_owned(),
        input_artifact_ids: Vec::new(),
    }
}

fn raw_response_artifact(request_artifact: &Artifact) -> Artifact {
    Artifact {
        id: "controller-raw-response".to_owned(),
        kind: "controller_mcp_response".to_owned(),
        relative_path: ArtifactPath::new("logs/controller/raw/v2.txt").unwrap(),
        media_type: "text/plain".to_owned(),
        size_bytes: 1,
        sha256: Sha256Digest::new("b".repeat(64)).unwrap(),
        producer: "t32perf-controller/v1".to_owned(),
        input_artifact_ids: vec![request_artifact.id.clone()],
    }
}

fn v1_response(request: &ControllerRequest, request_artifact: &Artifact) -> ControllerResponse {
    ControllerResponse {
        schema: ControllerResponseSchemaVersion::V1,
        binding: request.binding.clone(),
        request_artifact_id: request_artifact.id.clone(),
        request_artifact_sha256: request_artifact.sha256.clone(),
        script_response: ControllerScriptResponse {
            operation: request.operation,
            status: PerfStatus::HostProcessingRequired,
            code: "raw_trace_analysis_required".to_owned(),
            files_deleted: None,
        },
        raw_response_artifact: raw_response_artifact(request_artifact),
        output_artifact: None,
    }
}

fn v2_slot(role: ControllerOutputRoleV2, name: &str) -> ControllerOutputReservationV2 {
    ControllerOutputReservationV2 {
        role,
        staged_relative_path: ArtifactPath::new(format!("controller/v2-{name}.bin")).unwrap(),
        script_output_path: format!("E:/staging/v2-{name}.bin"),
        artifact_id: format!("controller-v2-{name}"),
        destination_relative_path: ArtifactPath::new(format!("capture/raw/v2-{name}.bin")).unwrap(),
        kind: format!("controller_{name}"),
        media_type: "application/octet-stream".to_owned(),
        producer: "t32perf-controller/v2".to_owned(),
        max_bytes: 1024 * 1024,
    }
}

fn v2_request() -> ControllerRequestV2 {
    let mut base = request();
    base.operation = PerfOperation::Export;
    base.target_adapter = Some(v2_target_adapter());
    base.mcp.execute.arguments.script_name =
        PerfOperation::Export.v2_script_name().unwrap().to_owned();
    let outputs = vec![
        v2_slot(ControllerOutputRoleV2::TraceExport, "trace"),
        v2_slot(ControllerOutputRoleV2::CustomEvents, "custom-events"),
    ];
    let mut script_args = BTreeMap::from([
        (
            "binding_sha256".to_owned(),
            base.binding.binding_sha256.to_string(),
        ),
        (
            "mode".to_owned(),
            "task_events_elf_orti_verified".to_owned(),
        ),
    ]);
    for output in &outputs {
        script_args.insert(
            output.role.script_argument().to_owned(),
            output.script_output_path.clone(),
        );
    }
    base.mcp.execute.arguments.script_args = script_args;
    ControllerRequestV2 {
        schema: ControllerRequestV2SchemaVersion::V2,
        binding: base.binding,
        operation: base.operation,
        adapter_catalog_sha256: base.adapter_catalog_sha256,
        target_adapter: base.target_adapter,
        fault_action: base.fault_action,
        firmware_image: base.firmware_image,
        mcp: base.mcp,
        response_staging_path: base.response_staging_path,
        max_response_bytes: base.max_response_bytes,
        output: None,
        outputs,
    }
}

fn v2_request_artifact(request: &ControllerRequestV2) -> Artifact {
    Artifact {
        id: format!("controller-request-{}", request.binding.transaction_id),
        kind: "controller_request".to_owned(),
        relative_path: ArtifactPath::new(format!(
            "logs/controller/requests/{}.json",
            request.binding.transaction_id
        ))
        .unwrap(),
        media_type: "application/json".to_owned(),
        size_bytes: 1,
        sha256: Sha256Digest::new("c".repeat(64)).unwrap(),
        producer: "t32perf-controller/v2".to_owned(),
        input_artifact_ids: Vec::new(),
    }
}

fn v2_response_artifact(
    reservation: &ControllerOutputReservationV2,
    request_artifact: &Artifact,
    digest_character: char,
) -> Artifact {
    Artifact {
        id: reservation.artifact_id.clone(),
        kind: reservation.kind.clone(),
        relative_path: reservation.destination_relative_path.clone(),
        media_type: reservation.media_type.clone(),
        size_bytes: 1,
        sha256: Sha256Digest::new(digest_character.to_string().repeat(64)).unwrap(),
        producer: reservation.producer.clone(),
        input_artifact_ids: vec![request_artifact.id.clone()],
    }
}

fn v2_response(request: &ControllerRequestV2, request_artifact: &Artifact) -> ControllerResponseV2 {
    ControllerResponseV2 {
        schema: ControllerResponseV2SchemaVersion::V2,
        binding: request.binding.clone(),
        request_artifact_id: request_artifact.id.clone(),
        request_artifact_sha256: request_artifact.sha256.clone(),
        script_response: ControllerScriptResponse {
            operation: request.operation,
            status: PerfStatus::Ok,
            code: "multi_output_exported".to_owned(),
            files_deleted: None,
        },
        raw_response_artifact: raw_response_artifact(request_artifact),
        output_artifact: None,
        output_artifacts: request
            .outputs
            .iter()
            .zip(['d', 'e', 'f', '0'])
            .map(|(reservation, character)| {
                v2_response_artifact(reservation, request_artifact, character)
            })
            .collect(),
    }
}

fn target_stage_request(
    operation: PerfOperation,
    scenario: t32perf_trace32::TargetAdapterScenario,
    script_scenario: &str,
) -> ControllerRequest {
    let mut request = request();
    request.operation = operation;
    let mut adapter = target_adapter();
    adapter.scenario = scenario;
    adapter.capture_kind = if matches!(
        scenario,
        t32perf_trace32::TargetAdapterScenario::TraceOverflow
            | t32perf_trace32::TargetAdapterScenario::FlowError
    ) {
        TargetAdapterCaptureKind::ProgramFlowTaskEvents {
            export_profile_id: "fixture.task-events/v1".to_owned(),
            rtos_awareness: "fixture-rtos-awareness/v1".to_owned(),
            timestamp_clock_id: "fixture-trace-clock/v1".to_owned(),
            orti_artifact_id: "fixture-orti".to_owned(),
            task_marker_artifact_id: "fixture-task-markers".to_owned(),
        }
    } else {
        TargetAdapterCaptureKind::Sampling {
            capacity_records: if scenario
                == t32perf_trace32::TargetAdapterScenario::SamplingBufferFull
            {
                32
            } else {
                65_536
            },
        }
    };
    request.target_adapter = Some(adapter);
    request.fault_action = match (operation, scenario) {
        (PerfOperation::Start, t32perf_trace32::TargetAdapterScenario::CmmAbort) => {
            Some(ControllerFaultAction::CmmAbortAtStart)
        }
        _ => None,
    };
    request.mcp.execute.arguments.script_name = operation.script_name().to_owned();
    request.output = Some(ControllerOutputReservation {
        role: ControllerOutputRole::MachineEvidence,
        staged_relative_path: ArtifactPath::new("controller/stage.json").unwrap(),
        script_output_path: "E:/staging/stage.json".to_owned(),
        artifact_id: "controller-stage-evidence".to_owned(),
        destination_relative_path: ArtifactPath::new("controller/stage.json").unwrap(),
        kind: "controller_evidence".to_owned(),
        media_type: "application/json".to_owned(),
        producer: "controller".to_owned(),
        max_bytes: 65_536,
    });
    let mut script_args = BTreeMap::from([
        (
            "binding_sha256".to_owned(),
            request.binding.binding_sha256.to_string(),
        ),
        (
            "evidence_output".to_owned(),
            request.output.as_ref().unwrap().script_output_path.clone(),
        ),
        ("scenario".to_owned(), script_scenario.to_owned()),
    ]);
    if operation == PerfOperation::Configure {
        script_args.insert("initial_target_state".to_owned(), "running".to_owned());
        script_args.insert(
            "firmware_s3".to_owned(),
            request.firmware_image.script_input_path.clone(),
        );
    }
    if operation == PerfOperation::Start {
        script_args.insert("initial_target_state".to_owned(), "running".to_owned());
        if let Some(capacity_records) = request
            .target_adapter
            .as_ref()
            .unwrap()
            .capture_kind
            .sampling_capacity_records()
        {
            script_args.insert("capacity_records".to_owned(), capacity_records.to_string());
        }
    }
    request.mcp.execute.arguments.script_args = script_args;
    request
}

#[test]
fn binding_digest_covers_session_request_operation_transaction_and_nonce() {
    let original = binding();
    original.validate().unwrap();

    let changed = compute_controller_binding_sha256(
        "controller-test-other",
        &original.session_operation_id,
        &original.session_request_sha256,
        &original.transaction_id,
        &original.nonce,
    );
    assert_ne!(changed, original.binding_sha256);

    let mut invalid = original;
    invalid.nonce = "5".repeat(32);
    assert!(matches!(
        invalid.validate(),
        Err(ControllerContractError::BindingDigestMismatch { .. })
    ));
}

#[test]
fn driver_event_is_strictly_bound_to_request_abort_plan_and_event_context() {
    let request = request();
    let request_record = request_artifact(&request);
    let dispatch = ControllerDriverEvent {
        schema: ControllerDriverEventSchemaVersion::V1,
        event: ControllerDriverEventKind::DispatchIntent,
        binding: request.binding.clone(),
        request_artifact_id: request_record.id.clone(),
        request_artifact_sha256: request_record.sha256.clone(),
        operation: request.operation,
        fault_action: request.fault_action,
        abort_reason: None,
        abort_request_artifact_id: None,
        abort_request_artifact_sha256: None,
        initial_target_state: None,
        workload_identity: None,
        performance_run_deployment_binding_artifact_id: None,
        performance_run_deployment_binding_artifact_sha256: None,
        performance_run_deployment_sha256: None,
        workload_executable_sha256: None,
    };
    dispatch
        .validate_for(&request, &request_record, None)
        .unwrap();

    let mut mismatched = dispatch.clone();
    mismatched.request_artifact_sha256 = Sha256Digest::new("b".repeat(64)).unwrap();
    assert_eq!(
        mismatched.validate_for(&request, &request_record, None),
        Err(ControllerContractError::InvalidDriverEventBinding)
    );

    let abort = ControllerAbortRequest {
        schema: ControllerAbortRequestSchemaVersion::V1,
        binding: request.binding.clone(),
        request_artifact_id: request_record.id.clone(),
        request_artifact_sha256: request_record.sha256.clone(),
        mcp: request.mcp.abort.clone(),
        reason: ControllerAbortReason::Timeout,
    };
    let abort_artifact = Artifact {
        id: format!("controller-abort-{}", request.binding.transaction_id),
        kind: "controller_abort_request".to_owned(),
        relative_path: ArtifactPath::new(format!(
            "logs/controller/aborts/{}.json",
            request.binding.transaction_id
        ))
        .unwrap(),
        media_type: "application/json".to_owned(),
        size_bytes: 1,
        sha256: Sha256Digest::new("c".repeat(64)).unwrap(),
        producer: "t32perf-controller/v1".to_owned(),
        input_artifact_ids: vec![request_record.id.clone()],
    };
    let observed = ControllerDriverEvent {
        event: ControllerDriverEventKind::AbortSuccessObserved,
        abort_reason: Some(abort.reason),
        abort_request_artifact_id: Some(abort_artifact.id.clone()),
        abort_request_artifact_sha256: Some(abort_artifact.sha256.clone()),
        ..dispatch
    };
    observed
        .validate_for(&request, &request_record, Some((&abort, &abort_artifact)))
        .unwrap();

    let fault_request = target_stage_request(
        PerfOperation::Start,
        t32perf_trace32::TargetAdapterScenario::CmmAbort,
        "cmm_abort",
    );
    let fault_request_artifact = request_artifact(&fault_request);
    let fault_abort = ControllerAbortRequest {
        schema: ControllerAbortRequestSchemaVersion::V1,
        binding: fault_request.binding.clone(),
        request_artifact_id: fault_request_artifact.id.clone(),
        request_artifact_sha256: fault_request_artifact.sha256.clone(),
        mcp: fault_request.mcp.abort.clone(),
        reason: ControllerAbortReason::TransportFailure,
    };
    let fault_abort_artifact = Artifact {
        id: format!("controller-abort-{}", fault_request.binding.transaction_id),
        kind: "controller_abort_request".to_owned(),
        relative_path: ArtifactPath::new(format!(
            "logs/controller/aborts/{}.json",
            fault_request.binding.transaction_id
        ))
        .unwrap(),
        media_type: "application/json".to_owned(),
        size_bytes: 1,
        sha256: Sha256Digest::new("d".repeat(64)).unwrap(),
        producer: "t32perf-controller/v1".to_owned(),
        input_artifact_ids: vec![fault_request_artifact.id.clone()],
    };
    let triggered = ControllerDriverEvent {
        schema: ControllerDriverEventSchemaVersion::V1,
        event: ControllerDriverEventKind::FaultTriggered,
        binding: fault_request.binding.clone(),
        request_artifact_id: fault_request_artifact.id.clone(),
        request_artifact_sha256: fault_request_artifact.sha256.clone(),
        operation: fault_request.operation,
        fault_action: fault_request.fault_action,
        abort_reason: Some(fault_abort.reason),
        abort_request_artifact_id: Some(fault_abort_artifact.id.clone()),
        abort_request_artifact_sha256: Some(fault_abort_artifact.sha256.clone()),
        initial_target_state: None,
        workload_identity: None,
        performance_run_deployment_binding_artifact_id: None,
        performance_run_deployment_binding_artifact_sha256: None,
        performance_run_deployment_sha256: None,
        workload_executable_sha256: None,
    };
    triggered
        .validate_for(
            &fault_request,
            &fault_request_artifact,
            Some((&fault_abort, &fault_abort_artifact)),
        )
        .unwrap();
    assert_eq!(
        triggered.validate_for(&fault_request, &fault_request_artifact, None),
        Err(ControllerContractError::InvalidDriverEventContext)
    );

    let duplicated = serde_json::to_string(&observed).unwrap().replacen(
        r#""event":"abort_success_observed""#,
        r#""event":"abort_success_observed","event":"abort_success_observed""#,
        1,
    );
    assert!(serde_json::from_str::<ControllerDriverEvent>(&duplicated).is_err());
}

#[test]
fn legacy_v1_request_target_adapter_decodes_and_remains_journal_compatible() {
    let request = target_stage_request(
        PerfOperation::Configure,
        t32perf_trace32::TargetAdapterScenario::Normal,
        "normal",
    );
    let legacy_bytes = serde_json::to_vec(&request).unwrap();
    let legacy: serde_json::Value = serde_json::from_slice(&legacy_bytes).unwrap();
    let target_adapter = legacy["target_adapter"]
        .as_object()
        .expect("target-stage request has a target-adapter binding");
    assert!(!target_adapter.contains_key("controller_protocol"));
    assert!(!target_adapter.contains_key("custom_event_collector"));

    let decoded: ControllerRequest = serde_json::from_slice(&legacy_bytes).unwrap();
    decoded.validate().unwrap();
    let adapter = decoded.target_adapter.as_ref().unwrap();
    assert_eq!(
        adapter.controller_protocol,
        TargetAdapterControllerProtocol::V1
    );
    assert!(adapter.custom_event_collector.is_none());

    let persisted = serde_json::to_vec(&decoded).unwrap();
    assert_eq!(persisted, legacy_bytes);
    let persisted_sha256 = Sha256::digest(&persisted)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        persisted_sha256,
        "ecb3309d61d483517a336e835b46c98b621bb373420733db4710e0ef29d60438"
    );
    let recovered: ControllerRequest = serde_json::from_slice(&persisted).unwrap();
    recovered.validate().unwrap();
    assert_eq!(recovered, decoded);

    let request_record = request_artifact(&recovered);
    let dispatch = ControllerDriverEvent {
        schema: ControllerDriverEventSchemaVersion::V1,
        event: ControllerDriverEventKind::DispatchIntent,
        binding: recovered.binding.clone(),
        request_artifact_id: request_record.id.clone(),
        request_artifact_sha256: request_record.sha256.clone(),
        operation: recovered.operation,
        fault_action: recovered.fault_action,
        abort_reason: None,
        abort_request_artifact_id: None,
        abort_request_artifact_sha256: None,
        initial_target_state: None,
        workload_identity: None,
        performance_run_deployment_binding_artifact_id: None,
        performance_run_deployment_binding_artifact_sha256: None,
        performance_run_deployment_sha256: None,
        workload_executable_sha256: None,
    };
    dispatch
        .validate_for(&recovered, &request_record, None)
        .unwrap();
}

#[test]
fn driver_event_v2_uses_the_same_request_and_abort_invariants() {
    let request = v2_request();
    let request_record = v2_request_artifact(&request);
    let dispatch = ControllerDriverEvent {
        schema: ControllerDriverEventSchemaVersion::V1,
        event: ControllerDriverEventKind::DispatchIntent,
        binding: request.binding.clone(),
        request_artifact_id: request_record.id.clone(),
        request_artifact_sha256: request_record.sha256.clone(),
        operation: request.operation,
        fault_action: request.fault_action,
        abort_reason: None,
        abort_request_artifact_id: None,
        abort_request_artifact_sha256: None,
        initial_target_state: None,
        workload_identity: None,
        performance_run_deployment_binding_artifact_id: None,
        performance_run_deployment_binding_artifact_sha256: None,
        performance_run_deployment_sha256: None,
        workload_executable_sha256: None,
    };
    dispatch
        .validate_for_v2(&request, &request_record, None)
        .unwrap();

    let mut mismatched_operation = dispatch.clone();
    mismatched_operation.operation = PerfOperation::Stop;
    assert_eq!(
        mismatched_operation.validate_for_v2(&request, &request_record, None),
        Err(ControllerContractError::InvalidDriverEventBinding)
    );

    let mut mismatched_fault = dispatch.clone();
    mismatched_fault.fault_action = Some(ControllerFaultAction::DriverDisconnectAtExport);
    assert_eq!(
        mismatched_fault.validate_for_v2(&request, &request_record, None),
        Err(ControllerContractError::InvalidDriverEventBinding)
    );

    let mut mismatched_binding = dispatch.clone();
    let mut alternate_binding = request.binding.clone();
    alternate_binding.session_id = "controller-test-v2-other".to_owned();
    alternate_binding.binding_sha256 = compute_controller_binding_sha256(
        &alternate_binding.session_id,
        &alternate_binding.session_operation_id,
        &alternate_binding.session_request_sha256,
        &alternate_binding.transaction_id,
        &alternate_binding.nonce,
    );
    mismatched_binding.binding = alternate_binding;
    assert_eq!(
        mismatched_binding.validate_for_v2(&request, &request_record, None),
        Err(ControllerContractError::InvalidDriverEventBinding)
    );

    let abort = ControllerAbortRequest {
        schema: ControllerAbortRequestSchemaVersion::V1,
        binding: request.binding.clone(),
        request_artifact_id: request_record.id.clone(),
        request_artifact_sha256: request_record.sha256.clone(),
        mcp: request.mcp.abort.clone(),
        reason: ControllerAbortReason::Timeout,
    };
    let abort_artifact = Artifact {
        id: format!("controller-abort-{}", request.binding.transaction_id),
        kind: "controller_abort_request".to_owned(),
        relative_path: ArtifactPath::new(format!(
            "logs/controller/aborts/{}.json",
            request.binding.transaction_id
        ))
        .unwrap(),
        media_type: "application/json".to_owned(),
        size_bytes: 1,
        sha256: Sha256Digest::new("f".repeat(64)).unwrap(),
        producer: "t32perf-controller/v2".to_owned(),
        input_artifact_ids: vec![request_record.id.clone()],
    };
    let abort_attempt = ControllerDriverEvent {
        event: ControllerDriverEventKind::AbortAttempt,
        abort_reason: Some(abort.reason),
        abort_request_artifact_id: Some(abort_artifact.id.clone()),
        abort_request_artifact_sha256: Some(abort_artifact.sha256.clone()),
        ..dispatch
    };
    abort_attempt
        .validate_for_v2(&request, &request_record, Some((&abort, &abort_artifact)))
        .unwrap();

    let mut mismatched_abort = abort.clone();
    mismatched_abort.request_artifact_id = "different-request".to_owned();
    assert_eq!(
        abort_attempt.validate_for_v2(
            &request,
            &request_record,
            Some((&mismatched_abort, &abort_artifact)),
        ),
        Err(ControllerContractError::InvalidDriverEventContext)
    );
}

#[test]
fn exact_official_tool_sequence_and_fixed_script_are_required() {
    let valid = request();
    valid.validate().unwrap();

    let mut wrong_tool = valid.clone();
    wrong_tool.mcp.collect.tool = T32mcpTool::AbortPracticeSkill;
    assert_eq!(
        wrong_tool.validate(),
        Err(ControllerContractError::InvalidToolSequence)
    );

    let mut wrong_script = valid;
    wrong_script.mcp.execute.arguments.script_name = "user.cmm".to_owned();
    assert_eq!(
        wrong_script.validate(),
        Err(ControllerContractError::InvalidScriptAddress)
    );
}

#[test]
fn v1_request_and_response_serialization_remain_byte_stable() {
    use sha2::{Digest as _, Sha256};

    let request = request();
    let request_artifact = request_artifact(&request);
    for (expected, bytes) in [
        (
            "0d03728a168a98f5ac0fa063b0014b62448339871590b0d69db78312d0ac7bce",
            serde_json::to_vec(&request).unwrap(),
        ),
        (
            "40e892c8e5cc73cdb0aa6f9faa6a1c1ac2a6bebd4ad172cd29365a58b23420f3",
            serde_json::to_vec(&v1_response(&request, &request_artifact)).unwrap(),
        ),
    ] {
        let digest = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(digest, expected);
    }
}

#[test]
fn v2_request_requires_bounded_unique_ordered_slots_and_closed_arguments() {
    let valid = v2_request();
    valid.validate().unwrap();

    let mut missing = valid.clone();
    missing.outputs.clear();
    assert!(matches!(
        missing.validate(),
        Err(ControllerContractError::InvalidMultiOutputContract { .. })
    ));

    let mut too_many = valid.clone();
    too_many
        .outputs
        .push(v2_slot(ControllerOutputRoleV2::Counters, "counters"));
    too_many.outputs.push(v2_slot(
        ControllerOutputRoleV2::ResourceCounters,
        "resource-counters",
    ));
    too_many.outputs.push(v2_slot(
        ControllerOutputRoleV2::MachineEvidence,
        "machine-evidence",
    ));
    too_many.outputs.push(v2_slot(
        ControllerOutputRoleV2::MachineEvidence,
        "machine-evidence-extra",
    ));
    assert!(matches!(
        too_many.validate(),
        Err(ControllerContractError::InvalidMultiOutputContract { .. })
    ));

    for duplicate in ["artifact", "staged", "destination", "script"] {
        let mut request = valid.clone();
        match duplicate {
            "artifact" => request.outputs[1].artifact_id = request.outputs[0].artifact_id.clone(),
            "staged" => {
                request.outputs[1].staged_relative_path =
                    request.outputs[0].staged_relative_path.clone();
            }
            "destination" => {
                request.outputs[1].destination_relative_path =
                    request.outputs[0].destination_relative_path.clone();
            }
            "script" => {
                request.outputs[1].script_output_path =
                    request.outputs[0].script_output_path.clone();
            }
            _ => unreachable!(),
        }
        assert!(
            matches!(
                request.validate(),
                Err(ControllerContractError::InvalidMultiOutputContract { .. })
            ),
            "duplicate {duplicate}"
        );
    }

    let mut unordered = valid.clone();
    unordered.outputs.swap(0, 1);
    assert!(matches!(
        unordered.validate(),
        Err(ControllerContractError::InvalidMultiOutputContract { .. })
    ));

    let mut missing_argument = valid.clone();
    missing_argument
        .mcp
        .execute
        .arguments
        .script_args
        .remove(ControllerOutputRoleV2::CustomEvents.script_argument());
    assert_eq!(
        missing_argument.validate(),
        Err(ControllerContractError::InvalidScriptArguments)
    );

    let mut extra_argument = valid.clone();
    extra_argument
        .mcp
        .execute
        .arguments
        .script_args
        .insert("caller_output".to_owned(), "E:/caller.bin".to_owned());
    assert_eq!(
        extra_argument.validate(),
        Err(ControllerContractError::InvalidScriptArguments)
    );

    let mut mixed = valid.clone();
    mixed.output = Some(ControllerOutputReservation {
        role: ControllerOutputRole::TraceExport,
        staged_relative_path: ArtifactPath::new("controller/legacy.bin").unwrap(),
        script_output_path: "E:/staging/legacy.bin".to_owned(),
        artifact_id: "controller-legacy".to_owned(),
        destination_relative_path: ArtifactPath::new("capture/raw/legacy.bin").unwrap(),
        kind: "raw_trace".to_owned(),
        media_type: "application/octet-stream".to_owned(),
        producer: "t32perf-controller/v1".to_owned(),
        max_bytes: 1,
    });
    assert_eq!(
        mixed.validate(),
        Err(ControllerContractError::InvalidScriptArguments)
    );

    let mut oversized = valid.clone();
    oversized.outputs[0].max_bytes = u64::MAX;
    assert!(matches!(
        oversized.validate(),
        Err(ControllerContractError::InvalidMultiOutputContract { .. })
    ));

    let mut nonportable = valid.clone();
    nonportable.outputs[0].script_output_path = "E:\\staging\\trace.bin".to_owned();
    nonportable.mcp.execute.arguments.script_args.insert(
        ControllerOutputRoleV2::TraceExport
            .script_argument()
            .to_owned(),
        nonportable.outputs[0].script_output_path.clone(),
    );
    assert!(matches!(
        nonportable.validate(),
        Err(ControllerContractError::InvalidMultiOutputContract { .. })
    ));

    let v1_bytes = serde_json::to_vec(&request()).unwrap();
    assert!(serde_json::from_slice::<ControllerRequestV2>(&v1_bytes).is_err());
    let v2_bytes = serde_json::to_vec(&valid).unwrap();
    assert!(serde_json::from_slice::<ControllerRequest>(&v2_bytes).is_err());
}

#[test]
fn target_adapter_binding_enforces_explicit_custom_event_protocol() {
    let valid = v2_request();
    valid.validate().unwrap();
    let serialized = serde_json::to_value(&valid).unwrap();
    assert_eq!(
        serialized["target_adapter"]["controller_protocol"],
        serde_json::json!("v2_custom_events_export")
    );
    assert!(serialized["target_adapter"]["custom_event_collector"].is_object());
    let binding = valid.target_adapter.as_ref().unwrap();
    assert_eq!(
        binding.controller_protocol,
        TargetAdapterControllerProtocol::V2CustomEventsExport
    );
    assert_eq!(
        binding.custom_event_collector.as_ref().unwrap(),
        &custom_event_collector()
    );

    let mut v1_with_collector = valid.clone();
    v1_with_collector
        .target_adapter
        .as_mut()
        .unwrap()
        .controller_protocol = TargetAdapterControllerProtocol::V1;
    assert_eq!(
        v1_with_collector.validate(),
        Err(ControllerContractError::InvalidScriptArguments)
    );

    let mut missing_collector = valid.clone();
    missing_collector
        .target_adapter
        .as_mut()
        .unwrap()
        .custom_event_collector = None;
    assert_eq!(
        missing_collector.validate(),
        Err(ControllerContractError::InvalidScriptArguments)
    );

    let mut sampling = valid.clone();
    sampling.target_adapter.as_mut().unwrap().capture_kind = TargetAdapterCaptureKind::Sampling {
        capacity_records: 32,
    };
    assert_eq!(
        sampling.validate(),
        Err(ControllerContractError::InvalidScriptArguments)
    );

    let mut wrong_clock = valid.clone();
    wrong_clock
        .target_adapter
        .as_mut()
        .unwrap()
        .custom_event_collector
        .as_mut()
        .unwrap()
        .clock
        .clock_id = "other-clock".to_owned();
    assert_eq!(
        wrong_clock.validate(),
        Err(ControllerContractError::InvalidScriptArguments)
    );

    let mut duplicate_artifacts = valid;
    let collector = duplicate_artifacts
        .target_adapter
        .as_mut()
        .unwrap()
        .custom_event_collector
        .as_mut()
        .unwrap();
    collector.instrumentation_overhead_artifact_id = collector.mapping_artifact_id.clone();
    assert_eq!(
        duplicate_artifacts.validate(),
        Err(ControllerContractError::InvalidScriptArguments)
    );

    let mut v1_with_v2_binding = target_stage_request(
        PerfOperation::Configure,
        t32perf_trace32::TargetAdapterScenario::Normal,
        "normal",
    );
    v1_with_v2_binding.target_adapter = Some(v2_target_adapter());
    assert_eq!(
        v1_with_v2_binding.validate(),
        Err(ControllerContractError::InvalidScriptArguments)
    );

    let mut v2_with_v1_binding = v2_request();
    v2_with_v1_binding.target_adapter = Some(target_adapter());
    assert_eq!(
        v2_with_v1_binding.validate(),
        Err(ControllerContractError::InvalidScriptArguments)
    );
}

#[test]
fn v2_custom_event_export_slots_are_exact_and_collector_bounded() {
    let valid = v2_request();
    valid.validate().unwrap();

    let mut missing_custom_events = valid.clone();
    missing_custom_events.outputs.pop();
    missing_custom_events
        .mcp
        .execute
        .arguments
        .script_args
        .remove(ControllerOutputRoleV2::CustomEvents.script_argument());
    assert!(matches!(
        missing_custom_events.validate(),
        Err(ControllerContractError::InvalidMultiOutputContract { .. })
    ));

    let mut extra_counters = valid.clone();
    let counters = v2_slot(ControllerOutputRoleV2::Counters, "counters");
    extra_counters.mcp.execute.arguments.script_args.insert(
        ControllerOutputRoleV2::Counters
            .script_argument()
            .to_owned(),
        counters.script_output_path.clone(),
    );
    extra_counters.outputs.push(counters);
    assert!(matches!(
        extra_counters.validate(),
        Err(ControllerContractError::InvalidMultiOutputContract { .. })
    ));

    let mut wrong_bound = valid;
    wrong_bound.outputs[1].max_bytes -= 1;
    assert!(matches!(
        wrong_bound.validate(),
        Err(ControllerContractError::InvalidMultiOutputContract { .. })
    ));
}

#[test]
fn v2_response_is_all_or_nothing_and_exactly_ordered() {
    let v2_request_value = v2_request();
    let v2_request_record = v2_request_artifact(&v2_request_value);
    let valid = v2_response(&v2_request_value, &v2_request_record);
    valid
        .validate_for(&v2_request_value, &v2_request_record)
        .unwrap();

    let mut partial = valid.clone();
    partial.output_artifacts.pop();
    assert!(matches!(
        partial.validate_for(&v2_request_value, &v2_request_record),
        Err(ControllerContractError::InvalidMultiOutputResponse { .. })
    ));

    let mut extra = valid.clone();
    extra
        .output_artifacts
        .push(extra.output_artifacts[0].clone());
    assert!(matches!(
        extra.validate_for(&v2_request_value, &v2_request_record),
        Err(ControllerContractError::InvalidMultiOutputResponse { .. })
    ));

    let mut reordered = valid.clone();
    reordered.output_artifacts.swap(0, 1);
    assert!(matches!(
        reordered.validate_for(&v2_request_value, &v2_request_record),
        Err(ControllerContractError::InvalidMultiOutputResponse { .. })
    ));

    let mut wrong_envelope = valid.clone();
    wrong_envelope.output_artifacts[1].kind = "caller_kind".to_owned();
    assert!(matches!(
        wrong_envelope.validate_for(&v2_request_value, &v2_request_record),
        Err(ControllerContractError::InvalidMultiOutputResponse { .. })
    ));

    let mut wrong_provenance = valid.clone();
    wrong_provenance.output_artifacts[1]
        .input_artifact_ids
        .push("caller-input".to_owned());
    assert!(matches!(
        wrong_provenance.validate_for(&v2_request_value, &v2_request_record),
        Err(ControllerContractError::InvalidMultiOutputResponse { .. })
    ));

    let mut mixed = valid.clone();
    mixed.output_artifact = Some(mixed.output_artifacts[0].clone());
    assert!(matches!(
        mixed.validate_for(&v2_request_value, &v2_request_record),
        Err(ControllerContractError::InvalidMultiOutputResponse { .. })
    ));

    let mut failed = valid.clone();
    failed.script_response.status = PerfStatus::InvalidArgument;
    assert!(matches!(
        failed.validate_for(&v2_request_value, &v2_request_record),
        Err(ControllerContractError::InvalidMultiOutputResponse { .. })
    ));
    failed.output_artifacts.clear();
    failed
        .validate_for(&v2_request_value, &v2_request_record)
        .unwrap();

    let v1_request = request();
    let v1_request_artifact = request_artifact(&v1_request);
    let v1_bytes = serde_json::to_vec(&v1_response(&v1_request, &v1_request_artifact)).unwrap();
    assert!(serde_json::from_slice::<ControllerResponseV2>(&v1_bytes).is_err());
    let v2_bytes = serde_json::to_vec(&valid).unwrap();
    assert!(serde_json::from_slice::<ControllerResponse>(&v2_bytes).is_err());
}

#[test]
fn configure_request_binds_the_observed_initial_target_state() {
    let mut configure = request();
    configure.operation = PerfOperation::Configure;
    configure.target_adapter = Some(target_adapter());
    configure.mcp.execute.arguments.script_name = PerfOperation::Configure.script_name().to_owned();
    configure.output = Some(ControllerOutputReservation {
        role: ControllerOutputRole::MachineEvidence,
        staged_relative_path: ArtifactPath::new("controller/configure.json").unwrap(),
        script_output_path: "E:/staging/configure.json".to_owned(),
        artifact_id: "controller-configure-evidence".to_owned(),
        destination_relative_path: ArtifactPath::new("controller/configure.json").unwrap(),
        kind: "controller_evidence".to_owned(),
        media_type: "application/json".to_owned(),
        producer: "controller".to_owned(),
        max_bytes: 65_536,
    });
    let output = configure.output.as_ref().unwrap();
    configure.mcp.execute.arguments.script_args = BTreeMap::from([
        (
            "binding_sha256".to_owned(),
            configure.binding.binding_sha256.to_string(),
        ),
        (
            "evidence_output".to_owned(),
            output.script_output_path.clone(),
        ),
        ("initial_target_state".to_owned(), "running".to_owned()),
        ("scenario".to_owned(), "normal".to_owned()),
        (
            "firmware_s3".to_owned(),
            configure.firmware_image.script_input_path.clone(),
        ),
    ]);
    configure.validate().unwrap();

    configure
        .mcp
        .execute
        .arguments
        .script_args
        .remove("initial_target_state");
    assert_eq!(
        configure.validate(),
        Err(ControllerContractError::InvalidScriptArguments)
    );
}

#[test]
fn fault_action_is_closed_and_bound_to_its_scenario_and_operation() {
    let mut request = request();
    request.operation = PerfOperation::Start;
    let mut adapter = target_adapter();
    adapter.scenario = t32perf_trace32::TargetAdapterScenario::CmmAbort;
    request.target_adapter = Some(adapter);
    request.fault_action = Some(ControllerFaultAction::CmmAbortAtStart);
    request.mcp.execute.arguments.script_name = PerfOperation::Start.script_name().to_owned();
    request.output = Some(ControllerOutputReservation {
        role: ControllerOutputRole::MachineEvidence,
        staged_relative_path: ArtifactPath::new("controller/start.json").unwrap(),
        script_output_path: "E:/staging/start.json".to_owned(),
        artifact_id: "controller-start-evidence".to_owned(),
        destination_relative_path: ArtifactPath::new("controller/start.json").unwrap(),
        kind: "controller_evidence".to_owned(),
        media_type: "application/json".to_owned(),
        producer: "controller".to_owned(),
        max_bytes: 65_536,
    });
    request.mcp.execute.arguments.script_args = BTreeMap::from([
        (
            "binding_sha256".to_owned(),
            request.binding.binding_sha256.to_string(),
        ),
        (
            "evidence_output".to_owned(),
            request.output.as_ref().unwrap().script_output_path.clone(),
        ),
        ("initial_target_state".to_owned(), "running".to_owned()),
        ("scenario".to_owned(), "cmm_abort".to_owned()),
        ("capacity_records".to_owned(), "65536".to_owned()),
    ]);
    assert!(request.requires_interruption());
    request.validate().unwrap();

    request.fault_action = None;
    assert_eq!(
        request.validate(),
        Err(ControllerContractError::InvalidScriptArguments)
    );
}

#[test]
fn stop_request_binds_the_scenario_capacity() {
    let mut request = request();
    request.operation = PerfOperation::Stop;
    request.target_adapter = Some(target_adapter());
    request.mcp.execute.arguments.script_name = PerfOperation::Stop.script_name().to_owned();
    request.output = Some(ControllerOutputReservation {
        role: ControllerOutputRole::MachineEvidence,
        staged_relative_path: ArtifactPath::new("controller/stop.json").unwrap(),
        script_output_path: "E:/staging/stop.json".to_owned(),
        artifact_id: "controller-stop-evidence".to_owned(),
        destination_relative_path: ArtifactPath::new("controller/stop.json").unwrap(),
        kind: "controller_evidence".to_owned(),
        media_type: "application/json".to_owned(),
        producer: "controller".to_owned(),
        max_bytes: 65_536,
    });
    request.mcp.execute.arguments.script_args = BTreeMap::from([
        (
            "binding_sha256".to_owned(),
            request.binding.binding_sha256.to_string(),
        ),
        (
            "evidence_output".to_owned(),
            request.output.as_ref().unwrap().script_output_path.clone(),
        ),
        ("capacity_records".to_owned(), "65536".to_owned()),
    ]);
    request.validate().unwrap();

    request
        .mcp
        .execute
        .arguments
        .script_args
        .insert("capacity_records".to_owned(), "32".to_owned());
    assert_eq!(
        request.validate(),
        Err(ControllerContractError::InvalidScriptArguments)
    );
}

#[test]
fn target_scenarios_use_only_the_closed_root_cmm_stage_vocabulary() {
    use t32perf_trace32::TargetAdapterScenario::{
        CmmAbort, DriverDisconnect, FlowError, SamplingBufferFull, Trace32Disconnect, TraceOverflow,
    };

    for (scenario, configure_scenario, start_scenario) in [
        (SamplingBufferFull, "sampling_buffer_full", "normal"),
        (Trace32Disconnect, "normal", "normal"),
        (DriverDisconnect, "normal", "normal"),
        (CmmAbort, "normal", "cmm_abort"),
        (TraceOverflow, "trace_overflow", "normal"),
        (FlowError, "flow_error", "normal"),
    ] {
        let configure =
            target_stage_request(PerfOperation::Configure, scenario, configure_scenario);
        assert_eq!(
            configure
                .target_adapter
                .as_ref()
                .unwrap()
                .script_scenario_for(PerfOperation::Configure),
            Some(configure_scenario)
        );
        configure.validate().unwrap();

        let mut forged_configure = configure;
        forged_configure.mcp.execute.arguments.script_args.insert(
            "scenario".to_owned(),
            if configure_scenario == "normal" {
                "sampling_buffer_full".to_owned()
            } else {
                "normal".to_owned()
            },
        );
        assert_eq!(
            forged_configure.validate(),
            Err(ControllerContractError::InvalidScriptArguments)
        );

        let start = target_stage_request(PerfOperation::Start, scenario, start_scenario);
        assert_eq!(
            start
                .target_adapter
                .as_ref()
                .unwrap()
                .script_scenario_for(PerfOperation::Start),
            Some(start_scenario)
        );
        start.validate().unwrap();

        let mut forged_start = start;
        forged_start.mcp.execute.arguments.script_args.insert(
            "scenario".to_owned(),
            if start_scenario == "normal" {
                "cmm_abort".to_owned()
            } else {
                "normal".to_owned()
            },
        );
        assert_eq!(
            forged_start.validate(),
            Err(ControllerContractError::InvalidScriptArguments)
        );

        let mut forged_initial_state =
            target_stage_request(PerfOperation::Start, scenario, start_scenario);
        forged_initial_state
            .mcp
            .execute
            .arguments
            .script_args
            .insert("initial_target_state".to_owned(), "not_a_state".to_owned());
        assert_eq!(
            forged_initial_state.validate(),
            Err(ControllerContractError::InvalidScriptArguments)
        );

        let mut forged_capacity =
            target_stage_request(PerfOperation::Start, scenario, start_scenario);
        forged_capacity.mcp.execute.arguments.script_args.insert(
            "capacity_records".to_owned(),
            if scenario == SamplingBufferFull {
                "65536".to_owned()
            } else {
                "32".to_owned()
            },
        );
        assert_eq!(
            forged_capacity.validate(),
            Err(ControllerContractError::InvalidScriptArguments)
        );
    }
}

#[test]
fn program_flow_binding_requires_taskevents_export_and_stop_bound_completion_evidence() {
    let mut export_request = request();
    export_request.operation = PerfOperation::Export;
    let mut adapter = target_adapter();
    adapter.capture_kind = TargetAdapterCaptureKind::ProgramFlowTaskEvents {
        export_profile_id: "fixture.task-events/v1".to_owned(),
        rtos_awareness: "fixture-rtos-awareness/v1".to_owned(),
        timestamp_clock_id: "fixture-trace-clock/v1".to_owned(),
        orti_artifact_id: "fixture-orti".to_owned(),
        task_marker_artifact_id: "fixture-task-markers".to_owned(),
    };
    export_request.target_adapter = Some(adapter.clone());
    export_request.output = Some(ControllerOutputReservation {
        role: ControllerOutputRole::TraceExport,
        staged_relative_path: ArtifactPath::new("controller/task-events.csv").unwrap(),
        script_output_path: "E:/staging/task-events.csv".to_owned(),
        artifact_id: "controller-task-events".to_owned(),
        destination_relative_path: ArtifactPath::new("capture/raw/task-events.csv").unwrap(),
        kind: "raw_trace".to_owned(),
        media_type: "text/csv".to_owned(),
        producer: "controller".to_owned(),
        max_bytes: 65_536,
    });
    export_request.mcp.execute.arguments.script_name =
        PerfOperation::Export.script_name().to_owned();
    export_request.mcp.execute.arguments.script_args = BTreeMap::from([
        (
            "binding_sha256".to_owned(),
            export_request.binding.binding_sha256.to_string(),
        ),
        (
            "mode".to_owned(),
            "task_events_elf_orti_verified".to_owned(),
        ),
        (
            "output".to_owned(),
            export_request
                .output
                .as_ref()
                .unwrap()
                .script_output_path
                .clone(),
        ),
    ]);
    export_request.validate().unwrap();

    export_request
        .mcp
        .execute
        .arguments
        .script_args
        .insert("mode".to_owned(), "raw_ascii".to_owned());
    assert_eq!(
        export_request.validate(),
        Err(ControllerContractError::InvalidScriptArguments)
    );

    let mut health_request = request();
    health_request.operation = PerfOperation::GetHealth;
    health_request.target_adapter = Some(adapter.clone());
    health_request.output = Some(ControllerOutputReservation {
        role: ControllerOutputRole::MachineEvidence,
        staged_relative_path: ArtifactPath::new("controller/flow-health.json").unwrap(),
        script_output_path: "E:/staging/flow-health.json".to_owned(),
        artifact_id: "controller-flow-health".to_owned(),
        destination_relative_path: ArtifactPath::new("logs/controller/flow-health.json").unwrap(),
        kind: "controller_evidence".to_owned(),
        media_type: "application/json".to_owned(),
        producer: "controller".to_owned(),
        max_bytes: 65_536,
    });
    health_request.mcp.execute.arguments.script_name =
        PerfOperation::GetHealth.script_name().to_owned();
    let stop_artifact_sha256 = Sha256Digest::new("d".repeat(64)).unwrap();
    health_request.mcp.execute.arguments.script_args = BTreeMap::from([
        (
            "binding_sha256".to_owned(),
            health_request.binding.binding_sha256.to_string(),
        ),
        (
            "evidence_output".to_owned(),
            health_request
                .output
                .as_ref()
                .unwrap()
                .script_output_path
                .clone(),
        ),
        (
            "firmware_s3".to_owned(),
            health_request.firmware_image.script_input_path.clone(),
        ),
        (
            "stop_evidence_sha256".to_owned(),
            stop_artifact_sha256.to_string(),
        ),
    ]);
    health_request.validate().unwrap();
    health_request
        .mcp
        .execute
        .arguments
        .script_args
        .insert("capacity_records".to_owned(), "65536".to_owned());
    assert_eq!(
        health_request.validate(),
        Err(ControllerContractError::InvalidScriptArguments)
    );

    let stop = t32perf_trace32::ControllerEvidence::Stop(t32perf_trace32::ControllerStopEvidence {
        schema: t32perf_trace32::ControllerStopEvidenceSchemaVersion::V1,
        operation: t32perf_trace32::ControllerStopOperation::V1,
        binding_sha256: binding().binding_sha256,
        capture_stopped: true,
        workload_completed: true,
        workload_identity: "fixture-workload/v1".to_owned(),
        target_state_after_stop: ControllerTargetState::Running,
    });
    let health = t32perf_trace32::ControllerEvidence::HealthV3(
        t32perf_trace32::ControllerProgramFlowHealthEvidence {
            schema: t32perf_trace32::ControllerProgramFlowHealthEvidenceSchemaVersion::V1,
            operation: t32perf_trace32::ControllerHealthOperation::V1,
            binding_sha256: binding().binding_sha256,
            capture_stopped: true,
            supported_signals: t32perf_trace32::PROGRAM_FLOW_HEALTH_SIGNALS.to_vec(),
            stop_evidence_sha256: stop_artifact_sha256.clone(),
            trace_overflow: false,
            flow_error: false,
            trace_gap: false,
            truncated: false,
            timestamp_discontinuity: false,
            elf_matches_firmware: true,
            program_flow_closed: true,
        },
    );
    let health_bytes = match &health {
        t32perf_trace32::ControllerEvidence::HealthV3(document) => {
            serde_json::to_vec(document).unwrap()
        }
        _ => unreachable!(),
    };
    let parsed = parse_controller_evidence(PerfOperation::GetHealth, &health_bytes).unwrap();
    assert!(matches!(
        &parsed,
        t32perf_trace32::ControllerEvidence::HealthV3(_)
    ));
    parsed
        .validate_for(PerfOperation::GetHealth, &binding().binding_sha256)
        .unwrap();
    assert!(matches!(
        ControllerCaptureCompletionEvidence::from_evidence(
            &adapter.capture_kind,
            &stop,
            &stop_artifact_sha256,
            &health
        )
        .unwrap(),
        ControllerCaptureCompletionEvidence::ProgramFlowTaskEvents { .. }
    ));
    let sampling_kind = TargetAdapterCaptureKind::Sampling {
        capacity_records: 65_536,
    };
    assert!(
        ControllerCaptureCompletionEvidence::from_evidence(
            &sampling_kind,
            &stop,
            &stop_artifact_sha256,
            &health
        )
        .is_err()
    );
    assert!(
        ControllerCaptureCompletionEvidence::from_evidence(
            &adapter.capture_kind,
            &stop,
            &Sha256Digest::new("e".repeat(64)).unwrap(),
            &health
        )
        .is_err()
    );

    let legacy_health =
        t32perf_trace32::ControllerEvidence::Health(t32perf_trace32::ControllerHealthEvidence {
            schema: t32perf_trace32::ControllerHealthEvidenceSchemaVersion::V1,
            operation: t32perf_trace32::ControllerHealthOperation::V1,
            binding_sha256: binding().binding_sha256,
            capture_stopped: true,
            trace_overflow: false,
            flow_error: false,
            trace_gap: false,
            truncated: false,
            timestamp_discontinuity: false,
            elf_matches_firmware: true,
            program_flow_closed: true,
        });
    assert!(
        ControllerCaptureCompletionEvidence::from_evidence(
            &adapter.capture_kind,
            &stop,
            &stop_artifact_sha256,
            &legacy_health
        )
        .is_err()
    );
}

#[test]
fn controller_schemas_are_versioned_and_complete() {
    let documents = controller_schema_documents();
    assert_eq!(documents.len(), 19);
    assert_eq!(
        documents["controller-request.schema.json"]["$id"],
        CONTROLLER_REQUEST_SCHEMA
    );
    assert_eq!(
        documents["controller-response.schema.json"]["$id"],
        CONTROLLER_RESPONSE_SCHEMA
    );
    assert_eq!(
        documents["controller-request-v2.schema.json"]["$id"],
        CONTROLLER_REQUEST_V2_SCHEMA
    );
    assert_eq!(
        documents["controller-response-v2.schema.json"]["$id"],
        CONTROLLER_RESPONSE_V2_SCHEMA
    );
    assert!(
        documents["controller-request.schema.json"]["properties"]
            .get("outputs")
            .is_none()
    );
    assert!(
        documents["controller-response.schema.json"]["properties"]
            .get("output_artifacts")
            .is_none()
    );
    assert!(
        documents["controller-request-v2.schema.json"]["properties"]
            .get("outputs")
            .is_some()
    );
    assert!(
        documents["controller-response-v2.schema.json"]["properties"]
            .get("output_artifacts")
            .is_some()
    );
    assert_eq!(
        documents["controller-abort-request.schema.json"]["$id"],
        CONTROLLER_ABORT_REQUEST_SCHEMA
    );
    assert_eq!(
        documents["controller-abort-receipt.schema.json"]["$id"],
        CONTROLLER_ABORT_RECEIPT_SCHEMA
    );
    assert_eq!(
        documents["controller-driver-event.schema.json"]["$id"],
        CONTROLLER_DRIVER_EVENT_SCHEMA
    );
    for (filename, schema) in [
        (
            "controller-capabilities-evidence.schema.json",
            CONTROLLER_CAPABILITIES_EVIDENCE_SCHEMA,
        ),
        (
            "controller-capabilities-evidence-v2.schema.json",
            CONTROLLER_CAPABILITIES_EVIDENCE_V2_SCHEMA,
        ),
        (
            "controller-configure-evidence.schema.json",
            CONTROLLER_CONFIGURE_EVIDENCE_SCHEMA,
        ),
        (
            "controller-start-evidence.schema.json",
            CONTROLLER_START_EVIDENCE_SCHEMA,
        ),
        (
            "controller-start-evidence-v2.schema.json",
            CONTROLLER_START_EVIDENCE_V2_SCHEMA,
        ),
        (
            "controller-stop-evidence.schema.json",
            CONTROLLER_STOP_EVIDENCE_SCHEMA,
        ),
        (
            "controller-stop-evidence-v2.schema.json",
            CONTROLLER_STOP_EVIDENCE_V2_SCHEMA,
        ),
        (
            "controller-health-evidence.schema.json",
            CONTROLLER_HEALTH_EVIDENCE_SCHEMA,
        ),
        (
            "controller-health-evidence-v2.schema.json",
            CONTROLLER_HEALTH_EVIDENCE_V2_SCHEMA,
        ),
        (
            "controller-health-evidence-v3.schema.json",
            CONTROLLER_HEALTH_EVIDENCE_V3_SCHEMA,
        ),
        (
            "controller-cleanup-evidence.schema.json",
            CONTROLLER_CLEANUP_EVIDENCE_SCHEMA,
        ),
        (
            "controller-cleanup-evidence-v2.schema.json",
            CONTROLLER_CLEANUP_EVIDENCE_V2_SCHEMA,
        ),
    ] {
        assert_eq!(documents[filename]["$id"], schema);
    }
}

#[test]
fn capability_evidence_is_strict_operation_and_binding_bound() {
    let binding = binding();
    let evidence = ControllerCapabilitiesEvidence {
        schema: ControllerCapabilitiesEvidenceSchemaVersion::V1,
        operation: ControllerCapabilitiesOperation::V1,
        binding_sha256: binding.binding_sha256.clone(),
        trace32_release: "2026.02".to_owned(),
        trace32_build: 183_242,
        architecture_package: "arm".to_owned(),
        target_identifier: "target-a".to_owned(),
        probe_identifier: "probe-a".to_owned(),
        license_features: vec!["etm".to_owned()],
        trace_routing: vec!["trace-port-a".to_owned()],
        capture_modes: vec!["etm".to_owned()],
        trace_sinks: vec!["probe_buffer".to_owned()],
        covered_cores: vec![0],
        timestamp_supported: true,
        rtos_awareness: Some("freertos-orti-v1".to_owned()),
        health_signals: vec![
            ControllerHealthSignal::TraceOverflow,
            ControllerHealthSignal::FlowError,
        ],
    };
    let bytes = serde_json::to_vec(&evidence).unwrap();
    let parsed = parse_controller_evidence(PerfOperation::GetCapabilities, &bytes).unwrap();
    parsed
        .validate_for(PerfOperation::GetCapabilities, &binding.binding_sha256)
        .unwrap();
    assert!(
        parsed
            .validate_for(PerfOperation::Configure, &binding.binding_sha256)
            .is_err()
    );
    let other_binding = Sha256Digest::new("f".repeat(64)).unwrap();
    assert!(
        parsed
            .validate_for(PerfOperation::GetCapabilities, &other_binding)
            .is_err()
    );

    let duplicated = String::from_utf8(bytes).unwrap().replacen(
        r#""trace32_build":183242"#,
        r#""trace32_build":183242,"trace32_build":183242"#,
        1,
    );
    assert!(
        parse_controller_evidence(PerfOperation::GetCapabilities, duplicated.as_bytes()).is_err()
    );
}

#[test]
fn capability_evidence_v2_requires_and_preserves_initial_target_state() {
    let binding = binding();
    let evidence = ControllerCapabilitiesEvidenceV2 {
        schema: ControllerCapabilitiesEvidenceV2SchemaVersion::V1,
        operation: ControllerCapabilitiesOperation::V1,
        binding_sha256: binding.binding_sha256.clone(),
        trace32_release: "2026.02".to_owned(),
        trace32_build: 190_766,
        architecture_package: "tricore".to_owned(),
        target_identifier: "target-a".to_owned(),
        probe_identifier: "probe-a".to_owned(),
        license_features: vec!["tricore".to_owned()],
        trace_routing: vec!["jtag".to_owned()],
        capture_modes: vec!["snooper-pc-realtime-stack".to_owned()],
        trace_sinks: vec!["snooper-stack".to_owned()],
        covered_cores: vec![0],
        timestamp_supported: true,
        rtos_awareness: None,
        health_signals: vec![ControllerHealthSignal::SamplingBufferFull],
        initial_target_state: ControllerTargetState::Running,
    };
    let bytes = serde_json::to_vec(&evidence).unwrap();
    let parsed = parse_controller_evidence(PerfOperation::GetCapabilities, &bytes).unwrap();
    assert!(matches!(
        parsed,
        t32perf_trace32::ControllerEvidence::CapabilitiesV2(_)
    ));
    parsed
        .validate_for(PerfOperation::GetCapabilities, &binding.binding_sha256)
        .unwrap();

    let missing_initial = String::from_utf8(bytes)
        .unwrap()
        .replace(r#","initial_target_state":"running""#, "");
    assert!(
        parse_controller_evidence(PerfOperation::GetCapabilities, missing_initial.as_bytes())
            .is_err()
    );
}

#[test]
fn target_control_evidence_rejects_unverified_transition_claims() {
    let binding = binding();
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schema": "t32perf.controller-start-evidence/v1",
        "operation": "perf_start",
        "binding_sha256": binding.binding_sha256.clone(),
        "initial_target_state": "running",
        "capture_started": false,
        "workload_owned": true,
        "workload_identity": "golden-workload-v1"
    }))
    .unwrap();
    let parsed = parse_controller_evidence(PerfOperation::Start, &bytes).unwrap();
    assert!(
        parsed
            .validate_for(PerfOperation::Start, &binding.binding_sha256)
            .is_err()
    );
}

#[test]
fn controller_documents_reject_duplicate_top_level_fields() {
    let serialized = serde_json::to_string(&request()).unwrap();
    let duplicated = serialized.replacen(
        r#""schema":"t32perf.controller-request/v1""#,
        r#""schema":"t32perf.controller-request/v1","schema":"t32perf.controller-request/v1""#,
        1,
    );
    assert!(serde_json::from_str::<ControllerRequest>(&duplicated).is_err());
}
