//! Durable append-only markers for host-driver intent and observations.

use std::io::{Read as _, Write as _};

use t32perf_model::{Artifact, ArtifactPath, strict_json};
use t32perf_session::{ArtifactSpec, Session, SessionLock};
use t32perf_trace32::{
    ControllerAbortRequest, ControllerDriverEvent, ControllerDriverEventKind,
    MAX_CONTROLLER_DRIVER_EVENT_BYTES,
};

use crate::{app::AppError, controller::ControllerRequestEnvelope};

/// Reserved artifact kind for durable driver journal markers.
pub(crate) const CONTROLLER_DRIVER_EVENT_KIND: &str = "controller_driver_event";
/// Reserved artifact identifier prefix for durable driver journal markers.
pub(crate) const CONTROLLER_DRIVER_EVENT_ID_PREFIX: &str = "controller-driver-event-";
/// Reserved artifact path prefix for durable driver journal markers.
pub(crate) const CONTROLLER_DRIVER_EVENT_PATH_PREFIX: &str = "logs/controller/driver-events/";
/// Host-only producer for durable driver journal markers.
pub(crate) const CONTROLLER_DRIVER_EVENT_PRODUCER: &str = "t32perf-controller-driver-journal/v1";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DriverEventProjection {
    pub(crate) dispatch_intent_recorded: bool,
    pub(crate) fault_intent_recorded: bool,
    pub(crate) fault_triggered_recorded: bool,
    pub(crate) abort_attempted: bool,
    pub(crate) abort_success_observed: bool,
    pub(crate) workload_intent_recorded: bool,
    pub(crate) workload_complete_recorded: bool,
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) fn record_event(
    session: &Session,
    lock: &SessionLock,
    artifacts: &[Artifact],
    request_artifact: &Artifact,
    request: &t32perf_trace32::ControllerRequest,
    abort_plan: Option<(&ControllerAbortRequest, &Artifact)>,
    event: &ControllerDriverEvent,
) -> Result<(), AppError> {
    record_event_envelope(
        session,
        lock,
        artifacts,
        request_artifact,
        &ControllerRequestEnvelope::V1(request.clone()),
        abort_plan,
        event,
    )
}

#[cfg(test)]
pub(crate) fn projection(
    session: &Session,
    artifacts: &[Artifact],
    request_artifact: &Artifact,
    request: &t32perf_trace32::ControllerRequest,
    abort_plan: Option<(&ControllerAbortRequest, &Artifact)>,
) -> Result<DriverEventProjection, AppError> {
    projection_envelope(
        session,
        artifacts,
        request_artifact,
        &ControllerRequestEnvelope::V1(request.clone()),
        abort_plan,
    )
}

pub(crate) fn event_artifact_id(transaction_id: &str, event: ControllerDriverEventKind) -> String {
    format!(
        "{CONTROLLER_DRIVER_EVENT_ID_PREFIX}{transaction_id}-{}",
        event.as_str()
    )
}

fn event_artifact_path(
    transaction_id: &str,
    event: ControllerDriverEventKind,
) -> Result<ArtifactPath, AppError> {
    ArtifactPath::new(format!(
        "{CONTROLLER_DRIVER_EVENT_PATH_PREFIX}{transaction_id}/{}.json",
        event.as_str()
    ))
    .map_err(AppError::operational)
}

fn validate_event(
    event: &ControllerDriverEvent,
    request: &ControllerRequestEnvelope,
    request_artifact: &Artifact,
    abort_plan: Option<(&ControllerAbortRequest, &Artifact)>,
) -> Result<(), AppError> {
    match request {
        ControllerRequestEnvelope::V1(request) => event
            .validate_for(request, request_artifact, abort_plan)
            .map_err(AppError::operational),
        ControllerRequestEnvelope::V2(request) => event
            .validate_for_v2(request, request_artifact, abort_plan)
            .map_err(AppError::operational),
    }
}

pub(crate) fn event_exists_exact_envelope(
    session: &Session,
    artifacts: &[Artifact],
    request_artifact: &Artifact,
    request: &ControllerRequestEnvelope,
    abort_plan: Option<(&ControllerAbortRequest, &Artifact)>,
    expected: &ControllerDriverEvent,
) -> Result<bool, AppError> {
    validate_event(expected, request, request_artifact, abort_plan)?;
    let id = event_artifact_id(&request.binding().transaction_id, expected.event);
    let Some(artifact) = artifacts.iter().find(|artifact| artifact.id == id) else {
        return Ok(false);
    };
    validate_artifact_envelope(artifact, expected)?;
    let actual = read_event(session, artifact)?;
    validate_event(&actual, request, request_artifact, abort_plan)?;
    if &actual != expected {
        return Err(AppError::operational(format!(
            "controller driver event `{id}` conflicts with its exact immutable retry"
        )));
    }
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn record_event_envelope(
    session: &Session,
    lock: &SessionLock,
    artifacts: &[Artifact],
    request_artifact: &Artifact,
    request: &ControllerRequestEnvelope,
    abort_plan: Option<(&ControllerAbortRequest, &Artifact)>,
    event: &ControllerDriverEvent,
) -> Result<(), AppError> {
    if event_exists_exact_envelope(
        session,
        artifacts,
        request_artifact,
        request,
        abort_plan,
        event,
    )? {
        return Ok(());
    }
    let mut bytes = serde_json::to_vec_pretty(event).map_err(AppError::operational)?;
    bytes.push(b'\n');
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual > MAX_CONTROLLER_DRIVER_EVENT_BYTES {
        return Err(AppError::operational(format!(
            "controller driver event is {actual} bytes; maximum is {MAX_CONTROLLER_DRIVER_EVENT_BYTES}"
        )));
    }
    let mut writer = session
        .create_artifact(
            lock,
            ArtifactSpec {
                id: event_artifact_id(&request.binding().transaction_id, event.event),
                kind: CONTROLLER_DRIVER_EVENT_KIND.to_owned(),
                relative_path: event_artifact_path(&request.binding().transaction_id, event.event)?,
                media_type: "application/json".to_owned(),
                producer: CONTROLLER_DRIVER_EVENT_PRODUCER.to_owned(),
                input_artifact_ids: event_input_artifact_ids(event),
            },
        )
        .map_err(AppError::operational)?;
    writer.write_all(&bytes).map_err(AppError::operational)?;
    session
        .commit_artifact(lock, writer)
        .map_err(AppError::operational)?;
    Ok(())
}

pub(crate) fn projection_envelope(
    session: &Session,
    artifacts: &[Artifact],
    request_artifact: &Artifact,
    request: &ControllerRequestEnvelope,
    abort_plan: Option<(&ControllerAbortRequest, &Artifact)>,
) -> Result<DriverEventProjection, AppError> {
    let mut projection = DriverEventProjection::default();
    for event in [
        ControllerDriverEventKind::DispatchIntent,
        ControllerDriverEventKind::FaultIntent,
        ControllerDriverEventKind::FaultTriggered,
        ControllerDriverEventKind::AbortAttempt,
        ControllerDriverEventKind::AbortSuccessObserved,
        ControllerDriverEventKind::WorkloadIntent,
        ControllerDriverEventKind::WorkloadComplete,
    ] {
        let id = event_artifact_id(&request.binding().transaction_id, event);
        let Some(artifact) = artifacts.iter().find(|artifact| artifact.id == id) else {
            continue;
        };
        let actual = read_event(session, artifact)?;
        validate_artifact_envelope(artifact, &actual)?;
        validate_event(&actual, request, request_artifact, abort_plan)?;
        match event {
            ControllerDriverEventKind::DispatchIntent => {
                projection.dispatch_intent_recorded = true;
            }
            ControllerDriverEventKind::FaultIntent => {
                projection.fault_intent_recorded = true;
            }
            ControllerDriverEventKind::FaultTriggered => {
                projection.fault_triggered_recorded = true;
            }
            ControllerDriverEventKind::AbortAttempt => projection.abort_attempted = true,
            ControllerDriverEventKind::AbortSuccessObserved => {
                projection.abort_success_observed = true;
            }
            ControllerDriverEventKind::WorkloadIntent => {
                projection.workload_intent_recorded = true;
            }
            ControllerDriverEventKind::WorkloadComplete => {
                projection.workload_complete_recorded = true;
            }
        }
    }
    if projection.abort_success_observed && !projection.abort_attempted {
        return Err(AppError::operational(
            "controller driver abort success is recorded without a preceding abort attempt",
        ));
    }
    if projection.fault_triggered_recorded && !projection.fault_intent_recorded {
        return Err(AppError::operational(
            "controller driver fault trigger is recorded without a preceding fault intent",
        ));
    }
    if projection.workload_complete_recorded && !projection.workload_intent_recorded {
        return Err(AppError::operational(
            "controller driver workload completion is recorded without a preceding workload intent",
        ));
    }
    Ok(projection)
}

/// Proves that the one-shot workload markers reference the exact immutable
/// performance deployment that owns the external workload executable.
pub(crate) fn require_performance_run_workload_deployment_binding(
    session: &Session,
    artifacts: &[Artifact],
    binding_artifact: &Artifact,
    deployment_sha256: &t32perf_model::Sha256Digest,
    workload_executable_sha256: &t32perf_model::Sha256Digest,
) -> Result<(), AppError> {
    let mut intent = false;
    let mut complete = false;
    for artifact in artifacts
        .iter()
        .filter(|artifact| artifact.kind == CONTROLLER_DRIVER_EVENT_KIND)
    {
        let event = read_event(session, artifact)?;
        if !matches!(
            event.event,
            ControllerDriverEventKind::WorkloadIntent | ControllerDriverEventKind::WorkloadComplete
        ) {
            continue;
        }
        if event
            .performance_run_deployment_binding_artifact_id
            .as_deref()
            != Some(binding_artifact.id.as_str())
            || event
                .performance_run_deployment_binding_artifact_sha256
                .as_ref()
                != Some(&binding_artifact.sha256)
            || event.performance_run_deployment_sha256.as_ref() != Some(deployment_sha256)
            || event.workload_executable_sha256.as_ref() != Some(workload_executable_sha256)
            || !artifact
                .input_artifact_ids
                .iter()
                .any(|id| id == &binding_artifact.id)
        {
            return Err(AppError::operational(
                "performance-run workload journal does not reference the exact deployment binding",
            ));
        }
        match event.event {
            ControllerDriverEventKind::WorkloadIntent => intent = true,
            ControllerDriverEventKind::WorkloadComplete => complete = true,
            _ => unreachable!(),
        }
    }
    if intent && complete {
        Ok(())
    } else {
        Err(AppError::operational(
            "performance-run requires durable workload intent and completion bound to its deployment",
        ))
    }
}

fn validate_artifact_envelope(
    artifact: &Artifact,
    event: &ControllerDriverEvent,
) -> Result<(), AppError> {
    let expected_id = event_artifact_id(&event.binding.transaction_id, event.event);
    let expected_path = event_artifact_path(&event.binding.transaction_id, event.event)?;
    if artifact.id != expected_id
        || artifact.kind != CONTROLLER_DRIVER_EVENT_KIND
        || artifact.relative_path != expected_path
        || artifact.media_type != "application/json"
        || artifact.producer != CONTROLLER_DRIVER_EVENT_PRODUCER
        || artifact.input_artifact_ids != event_input_artifact_ids(event)
        || artifact.size_bytes == 0
        || artifact.size_bytes > MAX_CONTROLLER_DRIVER_EVENT_BYTES
    {
        return Err(AppError::operational(format!(
            "controller driver event `{expected_id}` has an invalid reserved artifact envelope"
        )));
    }
    Ok(())
}

fn event_input_artifact_ids(event: &ControllerDriverEvent) -> Vec<String> {
    let mut inputs = vec![event.request_artifact_id.clone()];
    if let Some(abort) = &event.abort_request_artifact_id {
        inputs.push(abort.clone());
    }
    if let Some(binding) = &event.performance_run_deployment_binding_artifact_id {
        inputs.push(binding.clone());
    }
    inputs
}

fn read_event(session: &Session, artifact: &Artifact) -> Result<ControllerDriverEvent, AppError> {
    let mut file = session
        .open_artifact(artifact)
        .map_err(AppError::operational)?;
    let mut bytes = Vec::with_capacity(usize::try_from(artifact.size_bytes).unwrap_or(0));
    (&mut file)
        .take(MAX_CONTROLLER_DRIVER_EVENT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(AppError::operational)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CONTROLLER_DRIVER_EVENT_BYTES {
        return Err(AppError::operational(format!(
            "controller driver event `{}` exceeds its read bound",
            artifact.id
        )));
    }
    strict_json::from_slice(&bytes).map_err(AppError::operational)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;
    use t32perf_model::{Artifact, ArtifactPath, Sha256Digest};
    use t32perf_session::{ArtifactRoot, ArtifactSpec, SessionLimits};
    use t32perf_trace32::{
        ControllerBinding, ControllerDriverEvent, ControllerDriverEventKind,
        ControllerDriverEventSchemaVersion, ControllerFirmwareImageBinding, ControllerMcpHandoff,
        ControllerRequest, ControllerRequestSchemaVersion, ControllerTargetState,
        ExecutePracticeSkillArguments, ExecutePracticeSkillCall, MAX_CONTROLLER_MCP_RESPONSE_BYTES,
        NoArguments, NoArgumentsToolCall, PerfOperation, T32PERF_SKILL_NAME, T32mcpTool,
        compute_controller_binding_sha256,
    };

    use super::{projection, record_event};

    fn placeholder_artifact(id: &str, kind: &str, path: &str, digest: char) -> Artifact {
        Artifact {
            id: id.to_owned(),
            kind: kind.to_owned(),
            relative_path: ArtifactPath::new(path).unwrap(),
            media_type: "application/octet-stream".to_owned(),
            producer: "test/v1".to_owned(),
            input_artifact_ids: Vec::new(),
            size_bytes: 1,
            sha256: Sha256Digest::new(digest.to_string().repeat(64)).unwrap(),
        }
    }

    #[test]
    fn workload_markers_project_in_order_and_conflicting_retry_is_rejected() {
        let temporary = tempfile::tempdir().unwrap();
        let root = ArtifactRoot::open(temporary.path().join("sessions"), SessionLimits::default())
            .unwrap();
        let session = root.create_session(&json!({})).unwrap();
        let lock = session.try_lock().unwrap();
        let state = session.read_state().unwrap();
        let request_sha256 = session.request_sha256().unwrap();
        let transaction_id = "3".repeat(32);
        let nonce = "4".repeat(32);
        let binding = ControllerBinding {
            session_id: session.id().to_string(),
            session_operation_id: state.operation_id.clone(),
            session_request_sha256: request_sha256.clone(),
            transaction_id: transaction_id.clone(),
            nonce: nonce.clone(),
            binding_sha256: compute_controller_binding_sha256(
                session.id().as_str(),
                &state.operation_id,
                &request_sha256,
                &transaction_id,
                &nonce,
            ),
        };
        let request = ControllerRequest {
            schema: ControllerRequestSchemaVersion::V1,
            binding: binding.clone(),
            operation: PerfOperation::Start,
            adapter_catalog_sha256: Sha256Digest::new("5".repeat(64)).unwrap(),
            target_adapter: None,
            fault_action: None,
            firmware_image: ControllerFirmwareImageBinding {
                source_elf_artifact: placeholder_artifact(
                    "firmware-elf",
                    "firmware_elf",
                    "capture/firmware.elf",
                    '6',
                ),
                measurement_artifact: Artifact {
                    id: "trace32-firmware-s3".to_owned(),
                    kind: "trace32_firmware_measurement".to_owned(),
                    relative_path: ArtifactPath::new("capture/trace32-firmware.s3").unwrap(),
                    media_type: "application/vnd.motorola-s-record".to_owned(),
                    producer: "t32perf-controller-firmware-image/v1".to_owned(),
                    input_artifact_ids: vec!["firmware-elf".to_owned()],
                    size_bytes: 1,
                    sha256: Sha256Digest::new("7".repeat(64)).unwrap(),
                },
                script_input_path: "E:/capture/trace32-firmware.s3".to_owned(),
            },
            mcp: ControllerMcpHandoff {
                execute: ExecutePracticeSkillCall {
                    tool: T32mcpTool::ExecutePracticeSkill,
                    arguments: ExecutePracticeSkillArguments {
                        skill_name: T32PERF_SKILL_NAME.to_owned(),
                        script_name: PerfOperation::Start.script_name().to_owned(),
                        script_args: BTreeMap::new(),
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
            response_staging_path: ArtifactPath::new(format!(
                "controller/{transaction_id}.mcp-response.txt"
            ))
            .unwrap(),
            max_response_bytes: MAX_CONTROLLER_MCP_RESPONSE_BYTES,
            output: None,
        };
        let request_artifact = session
            .write_json_artifact(
                &lock,
                ArtifactSpec {
                    id: format!("controller-request-{transaction_id}"),
                    kind: "controller_request".to_owned(),
                    relative_path: ArtifactPath::new(format!(
                        "logs/controller/requests/{transaction_id}.json"
                    ))
                    .unwrap(),
                    media_type: "application/json".to_owned(),
                    producer: "t32perf-controller/v1".to_owned(),
                    input_artifact_ids: Vec::new(),
                },
                &request,
            )
            .unwrap();
        let intent = ControllerDriverEvent {
            schema: ControllerDriverEventSchemaVersion::V1,
            event: ControllerDriverEventKind::WorkloadIntent,
            binding,
            request_artifact_id: request_artifact.id.clone(),
            request_artifact_sha256: request_artifact.sha256.clone(),
            operation: PerfOperation::Start,
            fault_action: None,
            abort_reason: None,
            abort_request_artifact_id: None,
            abort_request_artifact_sha256: None,
            initial_target_state: Some(ControllerTargetState::Halted),
            workload_identity: Some("external-owner-sampling-window/v1".to_owned()),
            performance_run_deployment_binding_artifact_id: None,
            performance_run_deployment_binding_artifact_sha256: None,
            performance_run_deployment_sha256: None,
            workload_executable_sha256: None,
        };
        let artifacts = session.registered_artifacts(false).unwrap();
        record_event(
            &session,
            &lock,
            &artifacts,
            &request_artifact,
            &request,
            None,
            &intent,
        )
        .unwrap();
        let artifacts = session.registered_artifacts(false).unwrap();
        record_event(
            &session,
            &lock,
            &artifacts,
            &request_artifact,
            &request,
            None,
            &intent,
        )
        .unwrap();
        let projected =
            projection(&session, &artifacts, &request_artifact, &request, None).unwrap();
        assert!(projected.workload_intent_recorded);
        assert!(!projected.workload_complete_recorded);

        let mut conflicting = intent.clone();
        conflicting.workload_identity = Some("different-workload/v1".to_owned());
        assert!(
            record_event(
                &session,
                &lock,
                &artifacts,
                &request_artifact,
                &request,
                None,
                &conflicting,
            )
            .is_err()
        );

        let complete = ControllerDriverEvent {
            event: ControllerDriverEventKind::WorkloadComplete,
            ..intent
        };
        record_event(
            &session,
            &lock,
            &artifacts,
            &request_artifact,
            &request,
            None,
            &complete,
        )
        .unwrap();
        let artifacts = session.registered_artifacts(false).unwrap();
        let projected =
            projection(&session, &artifacts, &request_artifact, &request, None).unwrap();
        assert!(projected.workload_intent_recorded);
        assert!(projected.workload_complete_recorded);
    }
}
