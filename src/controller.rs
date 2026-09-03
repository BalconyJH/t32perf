use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read as _, Write as _},
};

use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use t32perf_model::{
    Artifact, ArtifactPath, CaptureConfigDocument, InitialTargetState, PerfArtifactReference,
    PerfCapturePhase as SurfaceCapturePhase, PerfCollectCall, PerfControlPayload,
    PerfControlStatus, PerfControllerOperation, PerfExecuteArguments, PerfExecuteCall, PerfMcpTool,
    PerfNextAction, PerfNoArguments, PerfResponseHandoff, PerfResumeAction, PerfSurfaceOperation,
    SessionError, SessionStatus, Sha256Digest, strict_json,
};
use t32perf_session::{ArtifactRoot, ArtifactSpec, Session, SessionId, SessionLock};
use t32perf_trace32::{
    AdmittedTargetAdapter, ControllerAbortAcknowledgement, ControllerAbortReason,
    ControllerAbortReceipt, ControllerAbortReceiptSchemaVersion, ControllerAbortRequest,
    ControllerAbortRequestSchemaVersion, ControllerBinding, ControllerCaptureCompletionEvidence,
    ControllerDriverEvent, ControllerDriverEventKind, ControllerDriverEventSchemaVersion,
    ControllerEvidence, ControllerFaultAction, ControllerFirmwareImageBinding,
    ControllerHealthEvidenceV2, ControllerMcpHandoff, ControllerOutputReservation,
    ControllerOutputReservationV2, ControllerOutputRole, ControllerOutputRoleV2,
    ControllerProgramFlowHealthEvidence, ControllerRequest, ControllerRequestSchemaVersion,
    ControllerRequestV2, ControllerResponse, ControllerResponseSchemaVersion, ControllerResponseV2,
    ControllerScriptResponse, ControllerStopEvidenceV2, ControllerTargetAdapterBinding,
    ControllerTargetState, ExecutePracticeSkillArguments, ExecutePracticeSkillCall,
    MAX_CONTROLLER_EVIDENCE_BYTES, MAX_CONTROLLER_MCP_RESPONSE_BYTES, MAX_CONTROLLER_REQUEST_BYTES,
    MAX_CONTROLLER_RESPONSE_BYTES, MAX_TRICORE_FIRMWARE_ELF_BYTES, MAX_TRICORE_S3_OUTPUT_BYTES,
    NoArguments, NoArgumentsToolCall, PerfFrameError, PerfFrameLimits, PerfOperation,
    PerfScriptResponse, PerfStatus, T32PERF_PROTOCOL, T32PERF_SKILL_NAME, T32mcpTool,
    TargetAdapterAdmissionCatalog, TargetAdapterCaptureContract, TargetAdapterCaptureKind,
    TargetAdapterFailureKind, TargetAdapterProfile, TargetAdapterQualificationReceipt,
    TargetAdapterRecoveryEvidence, TargetAdapterRun, TargetAdapterScenario,
    TargetAdapterScenarioSelection, TargetAdapterScenarioSelectionSchemaVersion,
    TargetAdapterSelection, TargetAdapterSelectionDiscriminator, compute_controller_binding_sha256,
    measure_registered_tricore_elf_to_s3, parse_controller_evidence, parse_t32mcp_perf_response,
    parse_target_adapter_qualification_receipt, parse_target_adapter_scenario_selection,
    verify_registered_tricore_elf_s3_measurement,
};
use uuid::Uuid;

use crate::app::{AppError, CommandOutcome, EXIT_OPERATIONAL, EXIT_SUCCESS, EXIT_UNSUPPORTED};
use crate::controller_qualification::validate_firmware_artifact_envelope;

pub const CONTROLLER_ARTIFACT_ID_PREFIX: &str = "controller-";
pub const CONTROLLER_ARTIFACT_PATH_PREFIX: &str = "logs/controller/";
pub const CONTROLLER_PRODUCER: &str = "t32perf-controller/v1";
pub const CONTROLLER_REQUEST_KIND: &str = "controller_request";
pub const CONTROLLER_RAW_RESPONSE_KIND: &str = "controller_mcp_response";
pub const CONTROLLER_RESPONSE_KIND: &str = "controller_response";
pub const CONTROLLER_ABORT_REQUEST_KIND: &str = "controller_abort_request";
pub const CONTROLLER_ABORT_RECEIPT_KIND: &str = "controller_abort_receipt";
pub const TARGET_ADAPTER_QUALIFICATION_ARTIFACT_ID: &str = "target-adapter-qualification";
pub const TARGET_ADAPTER_QUALIFICATION_KIND: &str = "target_adapter_qualification";
pub const TARGET_ADAPTER_QUALIFICATION_PRODUCER: &str = "t32perf-deployment-qualification/v1";
pub const TARGET_ADAPTER_SCENARIO_ARTIFACT_ID: &str = "target-adapter-scenario";
pub const TARGET_ADAPTER_SCENARIO_KIND: &str = "target_adapter_scenario";
pub const TARGET_ADAPTER_SCENARIO_PRODUCER: &str = "t32perf-deployment-scenario/v1";
pub const TARGET_ADAPTER_SCENARIO_PATH: &str = "capture/deployment/target-adapter-scenario.json";

const MAX_STATUS_TRANSACTIONS: usize = 32;

/// Constructs the only deployable scenario-selection shape. Candidate fault
/// exercises are evidence-only and bind the registered firmware; qualified
/// runs bind the immutable admission snapshot chain instead.
pub(crate) fn provision_target_adapter_scenario(
    scenario: TargetAdapterScenario,
    profile: &TargetAdapterProfile,
    admission_provenance: &[Artifact],
    allowed_scenarios: &[TargetAdapterScenario],
) -> Result<(TargetAdapterScenarioSelection, Vec<String>), AppError> {
    if profile
        .scenarios
        .iter()
        .all(|contract| contract.scenario != scenario)
    {
        return Err(AppError::operational(
            "deployment-selected scenario is not implemented by the target adapter profile",
        ));
    }
    let qualified = !admission_provenance.is_empty();
    if qualified && !allowed_scenarios.contains(&scenario) {
        return Err(AppError::operational(
            "deployment-selected scenario is not authorized by qualified admission",
        ));
    }
    let inputs = if qualified {
        admission_provenance
            .iter()
            .map(|artifact| artifact.id.clone())
            .collect()
    } else {
        vec![FIRMWARE_ELF_ARTIFACT_ID.to_owned()]
    };
    Ok((
        TargetAdapterScenarioSelection {
            schema: TargetAdapterScenarioSelectionSchemaVersion::V1,
            scenario,
            evidence_only: !qualified,
        },
        inputs,
    ))
}

const CONTROLLER_CAPTURE_SEQUENCE: [PerfOperation; 7] = [
    PerfOperation::GetCapabilities,
    PerfOperation::Configure,
    PerfOperation::Start,
    PerfOperation::Stop,
    PerfOperation::GetHealth,
    PerfOperation::Export,
    PerfOperation::Cleanup,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControllerCapturePhase {
    Capabilities,
    Configure,
    Start,
    Stop,
    Health,
    Export,
    Cleanup,
    Complete,
}

impl ControllerCapturePhase {
    pub(crate) const fn expected_operation(self) -> Option<PerfOperation> {
        match self {
            Self::Capabilities => Some(PerfOperation::GetCapabilities),
            Self::Configure => Some(PerfOperation::Configure),
            Self::Start => Some(PerfOperation::Start),
            Self::Stop => Some(PerfOperation::Stop),
            Self::Health => Some(PerfOperation::GetHealth),
            Self::Export => Some(PerfOperation::Export),
            Self::Cleanup => Some(PerfOperation::Cleanup),
            Self::Complete => None,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Capabilities => "capabilities_required",
            Self::Configure => "configure_required",
            Self::Start => "start_required",
            Self::Stop => "stop_required",
            Self::Health => "health_required",
            Self::Export => "export_required",
            Self::Cleanup => "cleanup_required",
            Self::Complete => "capture_complete",
        }
    }
}

#[derive(Debug)]
pub(crate) struct ControllerProgress {
    pub(crate) state: SessionStatus,
    pub(crate) phase: ControllerCapturePhase,
    pub(crate) completed_operations: BTreeSet<PerfOperation>,
    pub(crate) pending: Option<(String, PerfOperation)>,
}

#[derive(Debug)]
struct ControllerRequestAdmissionContext {
    catalog: TargetAdapterAdmissionCatalog,
    provenance: Vec<Artifact>,
    selected_scenario: Option<TargetAdapterScenario>,
    selection_artifact: Option<Artifact>,
}

/// Strict schema-directed view of an immutable controller request.
///
/// The host parses the duplicate-checked `schema` discriminator before it
/// deserializes either concrete document. It never attempts a V1 fallback for
/// a V2 document (or vice versa).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerRequestEnvelope {
    V1(ControllerRequest),
    V2(ControllerRequestV2),
}

impl ControllerRequestEnvelope {
    pub fn parse(bytes: &[u8]) -> Result<Self, AppError> {
        let value = strict_json::value_from_slice(bytes).map_err(AppError::operational)?;
        let schema = value
            .get("schema")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                AppError::operational("controller request has no schema discriminator")
            })?;
        match schema {
            t32perf_trace32::CONTROLLER_REQUEST_SCHEMA => {
                let request: ControllerRequest =
                    serde_json::from_value(value).map_err(AppError::operational)?;
                request.validate().map_err(AppError::operational)?;
                let envelope = Self::V1(request);
                envelope.validate_common()?;
                Ok(envelope)
            }
            t32perf_trace32::CONTROLLER_REQUEST_V2_SCHEMA => {
                let request: ControllerRequestV2 =
                    serde_json::from_value(value).map_err(AppError::operational)?;
                request.validate().map_err(AppError::operational)?;
                let envelope = Self::V2(request);
                envelope.validate_common()?;
                Ok(envelope)
            }
            _ => Err(AppError::operational(format!(
                "unsupported controller request schema `{schema}`"
            ))),
        }
    }

    pub fn binding(&self) -> &ControllerBinding {
        match self {
            Self::V1(request) => &request.binding,
            Self::V2(request) => &request.binding,
        }
    }
    pub const fn operation(&self) -> PerfOperation {
        match self {
            Self::V1(request) => request.operation,
            Self::V2(request) => request.operation,
        }
    }
    pub fn adapter_catalog_sha256(&self) -> &Sha256Digest {
        match self {
            Self::V1(request) => &request.adapter_catalog_sha256,
            Self::V2(request) => &request.adapter_catalog_sha256,
        }
    }
    pub fn target_adapter(&self) -> Option<&ControllerTargetAdapterBinding> {
        match self {
            Self::V1(request) => request.target_adapter.as_ref(),
            Self::V2(request) => request.target_adapter.as_ref(),
        }
    }
    pub const fn fault_action(&self) -> Option<ControllerFaultAction> {
        match self {
            Self::V1(request) => request.fault_action,
            Self::V2(request) => request.fault_action,
        }
    }
    pub fn firmware_image(&self) -> &ControllerFirmwareImageBinding {
        match self {
            Self::V1(request) => &request.firmware_image,
            Self::V2(request) => &request.firmware_image,
        }
    }
    pub fn mcp(&self) -> &ControllerMcpHandoff {
        match self {
            Self::V1(request) => &request.mcp,
            Self::V2(request) => &request.mcp,
        }
    }
    pub fn response_staging_path(&self) -> &ArtifactPath {
        match self {
            Self::V1(request) => &request.response_staging_path,
            Self::V2(request) => &request.response_staging_path,
        }
    }
    pub const fn max_response_bytes(&self) -> u64 {
        match self {
            Self::V1(request) => request.max_response_bytes,
            Self::V2(request) => request.max_response_bytes,
        }
    }
    pub const fn requires_interruption(&self) -> bool {
        match self {
            Self::V1(request) => request.requires_interruption(),
            Self::V2(request) => request.requires_interruption(),
        }
    }
    fn validate_common(&self) -> Result<(), AppError> {
        self.binding().validate().map_err(AppError::operational)?;
        if self.operation().as_str().is_empty()
            || self.adapter_catalog_sha256().as_str().is_empty()
            || self.response_staging_path().as_str().is_empty()
            || self.max_response_bytes() == 0
            || self.mcp().execute.arguments.script_name.is_empty()
            || self.firmware_image().script_input_path.is_empty()
            || self.requires_interruption() != self.fault_action().is_some()
        {
            return Err(AppError::operational(
                "controller request common envelope is invalid",
            ));
        }
        if self
            .target_adapter()
            .is_some_and(|adapter| adapter.adapter_id.is_empty())
        {
            return Err(AppError::operational(
                "controller request target adapter is invalid",
            ));
        }
        Ok(())
    }
}

/// Strict schema-directed view of an accepted controller response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerResponseEnvelope {
    V1(ControllerResponse),
    V2(ControllerResponseV2),
}

impl ControllerResponseEnvelope {
    pub fn parse(bytes: &[u8]) -> Result<Self, AppError> {
        let value = strict_json::value_from_slice(bytes).map_err(AppError::operational)?;
        let schema = value
            .get("schema")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                AppError::operational("controller response has no schema discriminator")
            })?;
        match schema {
            t32perf_trace32::CONTROLLER_RESPONSE_SCHEMA => {
                let envelope =
                    Self::V1(serde_json::from_value(value).map_err(AppError::operational)?);
                envelope.validate_common()?;
                Ok(envelope)
            }
            t32perf_trace32::CONTROLLER_RESPONSE_V2_SCHEMA => {
                let envelope =
                    Self::V2(serde_json::from_value(value).map_err(AppError::operational)?);
                envelope.validate_common()?;
                Ok(envelope)
            }
            _ => Err(AppError::operational(format!(
                "unsupported controller response schema `{schema}`"
            ))),
        }
    }
    pub fn binding(&self) -> &ControllerBinding {
        match self {
            Self::V1(response) => &response.binding,
            Self::V2(response) => &response.binding,
        }
    }
    pub fn request_artifact_id(&self) -> &str {
        match self {
            Self::V1(response) => &response.request_artifact_id,
            Self::V2(response) => &response.request_artifact_id,
        }
    }
    pub fn request_artifact_sha256(&self) -> &Sha256Digest {
        match self {
            Self::V1(response) => &response.request_artifact_sha256,
            Self::V2(response) => &response.request_artifact_sha256,
        }
    }
    pub fn script_response(&self) -> &ControllerScriptResponse {
        match self {
            Self::V1(response) => &response.script_response,
            Self::V2(response) => &response.script_response,
        }
    }
    pub fn raw_response_artifact(&self) -> &Artifact {
        match self {
            Self::V1(response) => &response.raw_response_artifact,
            Self::V2(response) => &response.raw_response_artifact,
        }
    }
    pub fn output_artifacts(&self) -> Vec<&Artifact> {
        match self {
            Self::V1(response) => response.output_artifact.iter().collect(),
            Self::V2(response) => response.output_artifacts.iter().collect(),
        }
    }
    fn validate_common(&self) -> Result<(), AppError> {
        self.binding().validate().map_err(AppError::operational)?;
        if self.request_artifact_id().is_empty()
            || self.request_artifact_sha256().as_str().is_empty()
            || self.script_response().code.is_empty()
            || self.raw_response_artifact().id.is_empty()
            || self
                .output_artifacts()
                .iter()
                .any(|artifact| artifact.id.is_empty())
        {
            return Err(AppError::operational(
                "controller response common envelope is invalid",
            ));
        }
        Ok(())
    }
}

fn read_controller_request_envelope(
    session: &Session,
    artifact: &Artifact,
) -> Result<ControllerRequestEnvelope, AppError> {
    ControllerRequestEnvelope::parse(&read_bounded_bytes_artifact(
        session,
        artifact,
        MAX_CONTROLLER_REQUEST_BYTES,
    )?)
}

fn read_controller_response_envelope(
    session: &Session,
    artifact: &Artifact,
) -> Result<ControllerResponseEnvelope, AppError> {
    ControllerResponseEnvelope::parse(&read_bounded_bytes_artifact(
        session,
        artifact,
        MAX_CONTROLLER_RESPONSE_BYTES,
    )?)
}

/// The only controller transaction state the host driver may inspect.
///
/// The immutable request is returned only after its Session, transaction, and
/// root-wide ownership have been revalidated.  The booleans are observations,
/// not authority to ingest or accept a response.
#[derive(Debug, Clone)]
pub(crate) struct DriverTransactionState {
    pub(crate) request: ControllerRequestEnvelope,
    pub(crate) response_staged: bool,
    pub(crate) response_accepted: bool,
    pub(crate) dispatch_intent_recorded: bool,
    pub(crate) fault_intent_recorded: bool,
    pub(crate) fault_triggered_recorded: bool,
    pub(crate) abort_planned: bool,
    pub(crate) abort_attempted: bool,
    pub(crate) abort_success_observed: bool,
    pub(crate) abort_confirmed: bool,
}

/// Workload facts reconstructed from accepted StartV2 evidence.
///
/// The host driver cannot supply or override any of these values; they remain
/// bound to the immutable controller request and accepted evidence chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DriverWorkloadContext {
    pub(crate) initial_target_state: ControllerTargetState,
    pub(crate) workload_identity: String,
    pub(crate) start_binding_sha256: Sha256Digest,
    pub(crate) start_transaction_id: String,
    pub(crate) duration_ns: Option<u64>,
    pub(crate) intent_recorded: bool,
    pub(crate) complete_recorded: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ControllerHealthBinding {
    pub(crate) artifact: Artifact,
    pub(crate) evidence: AcceptedControllerHealthEvidence,
}

#[derive(Debug, Clone)]
pub(crate) enum AcceptedControllerHealthEvidence {
    ProgramFlow(ControllerProgramFlowHealthEvidence),
    Sampling(ControllerHealthEvidenceV2),
}

#[derive(Debug, Clone)]
pub(crate) struct AcceptedTrace32RuntimeBinding {
    pub(crate) trace32_release: String,
    pub(crate) trace32_build: u64,
    pub(crate) architecture_package: String,
    pub(crate) target_identifier: String,
    pub(crate) probe_identifier: String,
    pub(crate) initial_target_state: ControllerTargetState,
    pub(crate) target_adapter: ControllerTargetAdapterBinding,
    pub(crate) capture_contract: TargetAdapterCaptureContract,
    pub(crate) qualification_artifact: Option<Artifact>,
    /// Qualified deployments extend this in canonical policy/HIL/receipt/
    /// admission-snapshot order. Candidate runs deliberately expose no claims.
    pub(crate) qualification_provenance_artifacts: Vec<Artifact>,
    pub(crate) qualification_receipt: Option<TargetAdapterQualificationReceipt>,
    pub(crate) firmware_elf_artifact: Artifact,
    pub(crate) firmware_measurement_artifact: Artifact,
    pub(crate) capabilities_artifact: Artifact,
    pub(crate) configure_artifact: Artifact,
    pub(crate) start_artifact: Artifact,
    pub(crate) health_artifact: Artifact,
    pub(crate) stop_artifact: Artifact,
    pub(crate) export_artifact: Artifact,
    /// V2 program-flow exports bind this separately ordered custom-event stream.
    pub(crate) custom_event_artifact: Option<Artifact>,
    pub(crate) cleanup_artifact: Artifact,
    pub(crate) export_response: ControllerScriptResponse,
    pub(crate) completion: ControllerCaptureCompletionEvidence,
}

/// A fully accepted Controller chain, including evidence-only fault scenarios.
/// This type is sufficient for immutable capture-config/HIL provenance, but it
/// is not by itself authorization for quantitative normalization.
#[derive(Debug, Clone)]
pub(crate) struct AcceptedTrace32CompletedBinding(AcceptedTrace32RuntimeBinding);

impl AcceptedTrace32CompletedBinding {
    /// Returns the accepted control-chain claims for immutable provenance.
    ///
    /// Callers must not treat these claims as a runtime binding: that requires
    /// the healthy-normal gate in `accepted_trace32_runtime_binding`.
    pub(crate) fn control(&self) -> &AcceptedTrace32RuntimeBinding {
        &self.0
    }

    fn into_inner(self) -> AcceptedTrace32RuntimeBinding {
        self.0
    }
}

/// Wraps a fully constructed typed runtime binding for crate-local pure builder tests.
///
/// This helper is absent from production builds and does not alter catalog selection,
/// evidence replay, or the public accepted-binding reconstruction path.
#[cfg(test)]
pub(crate) fn completed_binding_for_test(
    binding: AcceptedTrace32RuntimeBinding,
) -> AcceptedTrace32CompletedBinding {
    AcceptedTrace32CompletedBinding(binding)
}

pub(crate) struct QuarantinedTargetRecoveryClaims<'a> {
    pub(crate) failed_session_id: &'a str,
    pub(crate) failed_session_operation_id: &'a str,
    pub(crate) failed_transaction_id: &'a str,
    pub(crate) failed_operation: PerfOperation,
    pub(crate) failed_binding_sha256: &'a Sha256Digest,
    pub(crate) request_artifact_id: &'a str,
    pub(crate) request_artifact_sha256: &'a Sha256Digest,
    pub(crate) abort_request_artifact_id: &'a str,
    pub(crate) abort_request_artifact_sha256: &'a Sha256Digest,
    pub(crate) abort_receipt_artifact_id: &'a str,
    pub(crate) abort_receipt_artifact_sha256: &'a Sha256Digest,
    pub(crate) target_adapter: &'a ControllerTargetAdapterBinding,
    pub(crate) recovery_scenario: TargetAdapterScenario,
}

pub fn prepare(
    root: &ArtifactRoot,
    session_id: &str,
    operation: &str,
    mode: Option<&str>,
) -> Result<CommandOutcome, AppError> {
    let operation = PerfOperation::parse(operation).ok_or_else(|| {
        AppError::operational(format!(
            "unknown fixed TRACE32 performance operation `{operation}`"
        ))
    })?;
    validate_mode(operation, mode)?;
    let namespace = root.try_namespace_lock().map_err(AppError::operational)?;
    let session = open_session(root, session_id)?;
    let lock = session
        .try_lock_in_namespace(&namespace)
        .map_err(AppError::operational)?;
    let state = session.read_state().map_err(AppError::operational)?;
    if !matches!(
        state.status,
        SessionStatus::Created | SessionStatus::Capturing | SessionStatus::Captured
    ) {
        return Err(AppError::operational(format!(
            "session `{}` cannot prepare `{}` while its status is {:?}",
            session.id(),
            operation.as_str(),
            state.status
        )));
    }

    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    let progress = controller_progress_from_artifacts(Some(root), &session, &artifacts)?;
    if let Some((transaction, pending_operation)) = &progress.pending {
        return Err(AppError {
            code: "CONTROLLER_TRANSACTION_PENDING",
            message: format!(
                "session `{}` already has pending controller transaction `{transaction}` for `{}`",
                session.id(),
                pending_operation.as_str()
            ),
            details: json!({
                "session_id": session.id().as_str(),
                "transaction_id": transaction,
                "operation": pending_operation,
                "capture_phase": progress.phase.as_str(),
            }),
            exit_code: EXIT_OPERATIONAL,
        });
    }
    if let Some((owner_session, transaction)) = root_active_transaction(root)? {
        return Err(AppError {
            code: "CONTROLLER_ROOT_BUSY",
            message: format!(
                "artifact root already owns active t32mcp transaction `{transaction}` in Session `{owner_session}`"
            ),
            details: json!({
                "owner_session_id": owner_session,
                "transaction_id": transaction,
                "scope": "artifact_root",
            }),
            exit_code: EXIT_OPERATIONAL,
        });
    }
    if let Some((owner_session, phase)) = root_capture_lease(root)?
        && owner_session != session.id().as_str()
    {
        return Err(AppError {
            code: "CONTROLLER_ROOT_BUSY",
            message: format!(
                "artifact root is leased by incomplete controller capture in Session `{owner_session}`"
            ),
            details: json!({
                "owner_session_id": owner_session,
                "capture_phase": phase.as_str(),
                "scope": "artifact_root_capture",
            }),
            exit_code: EXIT_OPERATIONAL,
        });
    }
    ensure_driver_workload_completion_before_stop(&session, &artifacts, &progress, operation)?;
    ensure_operation_matches_progress(&session, state.status, operation, &progress)?;

    let transaction_id = Uuid::now_v7().simple().to_string();
    let nonce = Uuid::now_v7().simple().to_string();
    let session_request_sha256 = session.request_sha256().map_err(AppError::operational)?;
    let binding_sha256 = compute_controller_binding_sha256(
        session.id().as_str(),
        &state.operation_id,
        &session_request_sha256,
        &transaction_id,
        &nonce,
    );
    let binding = ControllerBinding {
        session_id: session.id().to_string(),
        session_operation_id: state.operation_id.clone(),
        session_request_sha256,
        transaction_id: transaction_id.clone(),
        nonce,
        binding_sha256,
    };
    let admission = controller_request_admission_context(&session, &artifacts, operation)?;
    let adapter_catalog_sha256 = admission.catalog.digest().map_err(AppError::operational)?;
    let target_adapter = if !operation_uses_target_adapter(operation) {
        None
    } else {
        let binding =
            selected_target_adapter_binding(&session, &artifacts, &progress, &admission.catalog)?;
        if Some(binding.scenario) != admission.selected_scenario {
            return Err(AppError::operational(
                "target-adapter selection changed while preparing the immutable request",
            ));
        }
        Some(binding)
    };
    let firmware_image = ensure_firmware_image(&session, &lock, &artifacts)?;
    if let Some(adapter) = target_adapter.as_ref() {
        let admitted = admission.catalog.get(&adapter.adapter_id).ok_or_else(|| {
            AppError::operational("selected target adapter disappeared before firmware binding")
        })?;
        if firmware_image.source_elf_artifact.sha256 != admitted.profile.firmware_elf_sha256 {
            return Err(AppError::operational(
                "registered firmware ELF does not match the selected target-adapter profile",
            ));
        }
    }
    crate::controller_recovery::ensure_not_quarantined(
        root,
        &adapter_catalog_sha256,
        target_adapter.as_ref(),
    )?;

    let response_staging_path =
        ArtifactPath::new(format!("controller/{transaction_id}.mcp-response.txt"))
            .map_err(AppError::operational)?;
    let response_absolute = session
        .prepare_staging_path(&lock, &response_staging_path)
        .map_err(AppError::operational)?;
    ensure_unallocated(&response_absolute, "controller response")?;

    let v2 = target_adapter.as_ref().is_some_and(|adapter| {
        adapter.controller_protocol
            == t32perf_trace32::TargetAdapterControllerProtocol::V2CustomEventsExport
    });
    let output = prepare_output(&session, &lock, operation, mode, &transaction_id)?;
    let outputs = if v2 {
        prepare_v2_outputs(
            &session,
            &lock,
            operation,
            &transaction_id,
            output.as_ref(),
            target_adapter.as_ref(),
        )?
    } else {
        Vec::new()
    };
    let mut script_args = BTreeMap::from([(
        "binding_sha256".to_owned(),
        binding.binding_sha256.to_string(),
    )]);
    if v2 {
        for output in &outputs {
            script_args.insert(
                output.role.script_argument().to_owned(),
                output.script_output_path.clone(),
            );
        }
        if operation == PerfOperation::Export {
            script_args.insert(
                "mode".to_owned(),
                mode.expect("export mode checked").to_owned(),
            );
        }
        if operation == PerfOperation::GetHealth
            && let Some((stop_artifact, stop)) =
                accepted_controller_evidence(&session, &artifacts, &progress, PerfOperation::Stop)?
        {
            script_args.insert(
                "stop_evidence_sha256".to_owned(),
                stop_artifact.sha256.to_string(),
            );
            if let ControllerEvidence::StopV2(stop) = stop {
                let state = match stop.pre_stop_state {
                    t32perf_trace32::ControllerSamplingPreStopState::Arm => "arm",
                    t32perf_trace32::ControllerSamplingPreStopState::Break => "break",
                };
                script_args.insert("pre_stop_state".to_owned(), state.to_owned());
                script_args.insert(
                    "recorded_records".to_owned(),
                    stop.recorded_records.to_string(),
                );
                script_args.insert(
                    "capacity_records".to_owned(),
                    stop.capacity_records.to_string(),
                );
            }
        }
        if matches!(operation, PerfOperation::Configure | PerfOperation::Start)
            && let Some((_, ControllerEvidence::CapabilitiesV2(capabilities))) =
                accepted_controller_evidence(
                    &session,
                    &artifacts,
                    &progress,
                    PerfOperation::GetCapabilities,
                )?
        {
            script_args.insert(
                "initial_target_state".to_owned(),
                controller_target_state_name(capabilities.initial_target_state).to_owned(),
            );
        }
        if operation == PerfOperation::Cleanup
            && let Some((_, ControllerEvidence::Configure(configure))) =
                accepted_controller_evidence(
                    &session,
                    &artifacts,
                    &progress,
                    PerfOperation::Configure,
                )?
        {
            script_args.insert(
                "initial_target_state".to_owned(),
                match configure.initial_target_state {
                    ControllerTargetState::Running => "running",
                    ControllerTargetState::Halted => "halted",
                }
                .to_owned(),
            );
        }
    } else if let Some(output) = &output {
        match output.role {
            ControllerOutputRole::TraceExport => {
                script_args.insert(
                    "mode".to_owned(),
                    mode.expect("export mode checked").to_owned(),
                );
                script_args.insert("output".to_owned(), output.script_output_path.clone());
            }
            ControllerOutputRole::MachineEvidence => {
                script_args.insert(
                    "evidence_output".to_owned(),
                    output.script_output_path.clone(),
                );
                if operation == PerfOperation::GetHealth
                    && let Some((stop_artifact, stop)) = accepted_controller_evidence(
                        &session,
                        &artifacts,
                        &progress,
                        PerfOperation::Stop,
                    )?
                {
                    script_args.insert(
                        "stop_evidence_sha256".to_owned(),
                        stop_artifact.sha256.to_string(),
                    );
                    if let ControllerEvidence::StopV2(stop) = stop {
                        let state = match stop.pre_stop_state {
                            t32perf_trace32::ControllerSamplingPreStopState::Arm => "arm",
                            t32perf_trace32::ControllerSamplingPreStopState::Break => "break",
                        };
                        script_args.insert("pre_stop_state".to_owned(), state.to_owned());
                        script_args.insert(
                            "recorded_records".to_owned(),
                            stop.recorded_records.to_string(),
                        );
                        script_args.insert(
                            "capacity_records".to_owned(),
                            stop.capacity_records.to_string(),
                        );
                    }
                }
                if matches!(operation, PerfOperation::Configure | PerfOperation::Start)
                    && let Some((_, ControllerEvidence::CapabilitiesV2(capabilities))) =
                        accepted_controller_evidence(
                            &session,
                            &artifacts,
                            &progress,
                            PerfOperation::GetCapabilities,
                        )?
                {
                    script_args.insert(
                        "initial_target_state".to_owned(),
                        controller_target_state_name(capabilities.initial_target_state).to_owned(),
                    );
                }
                if operation == PerfOperation::Cleanup
                    && let Some((_, ControllerEvidence::Configure(configure))) =
                        accepted_controller_evidence(
                            &session,
                            &artifacts,
                            &progress,
                            PerfOperation::Configure,
                        )?
                {
                    script_args.insert(
                        "initial_target_state".to_owned(),
                        match configure.initial_target_state {
                            ControllerTargetState::Running => "running",
                            ControllerTargetState::Halted => "halted",
                        }
                        .to_owned(),
                    );
                }
            }
        }
    }
    if matches!(operation, PerfOperation::Configure | PerfOperation::Start)
        && let Some(adapter) = target_adapter.as_ref()
        && let Some(scenario) = adapter.script_scenario_for(operation)
    {
        script_args.insert("scenario".to_owned(), scenario.to_owned());
    }
    if matches!(operation, PerfOperation::Start | PerfOperation::Stop)
        && let Some(adapter) = target_adapter.as_ref()
        && let Some(capacity_records) = adapter.capture_kind.sampling_capacity_records()
    {
        script_args.insert("capacity_records".to_owned(), capacity_records.to_string());
    }
    if matches!(
        operation,
        PerfOperation::Configure | PerfOperation::GetHealth
    ) {
        script_args.insert(
            "firmware_s3".to_owned(),
            firmware_image.script_input_path.clone(),
        );
    }
    let fault_action = match (
        operation,
        target_adapter.as_ref().map(|binding| binding.scenario),
    ) {
        (PerfOperation::Stop, Some(TargetAdapterScenario::Trace32Disconnect)) => {
            Some(ControllerFaultAction::Trace32DisconnectAtStop)
        }
        (PerfOperation::Export, Some(TargetAdapterScenario::DriverDisconnect)) => {
            Some(ControllerFaultAction::DriverDisconnectAtExport)
        }
        (PerfOperation::Start, Some(TargetAdapterScenario::CmmAbort)) => {
            Some(ControllerFaultAction::CmmAbortAtStart)
        }
        _ => None,
    };
    let request = ControllerRequest {
        schema: ControllerRequestSchemaVersion::V1,
        binding,
        operation,
        adapter_catalog_sha256,
        target_adapter,
        fault_action,
        firmware_image: firmware_image.clone(),
        mcp: ControllerMcpHandoff {
            execute: ExecutePracticeSkillCall {
                tool: T32mcpTool::ExecutePracticeSkill,
                arguments: ExecutePracticeSkillArguments {
                    skill_name: T32PERF_SKILL_NAME.to_owned(),
                    script_name: if v2 {
                        operation
                            .v2_script_name()
                            .expect("V2 selection excludes capabilities and hotspots")
                    } else {
                        operation.script_name()
                    }
                    .to_owned(),
                    script_args,
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
        response_staging_path,
        max_response_bytes: MAX_CONTROLLER_MCP_RESPONSE_BYTES,
        output,
    };
    let request = if v2 {
        let request = ControllerRequestV2 {
            schema: t32perf_trace32::ControllerRequestV2SchemaVersion::V2,
            binding: request.binding,
            operation: request.operation,
            adapter_catalog_sha256: request.adapter_catalog_sha256,
            target_adapter: request.target_adapter,
            fault_action: request.fault_action,
            firmware_image: request.firmware_image,
            mcp: request.mcp,
            response_staging_path: request.response_staging_path,
            max_response_bytes: request.max_response_bytes,
            output: None,
            outputs,
        };
        request.validate().map_err(AppError::operational)?;
        ControllerRequestEnvelope::V2(request)
    } else {
        request.validate().map_err(AppError::operational)?;
        ControllerRequestEnvelope::V1(request)
    };

    let request_spec = ArtifactSpec {
        id: request_artifact_id(&transaction_id),
        kind: CONTROLLER_REQUEST_KIND.to_owned(),
        relative_path: request_artifact_path(&transaction_id)?,
        media_type: "application/json".to_owned(),
        producer: CONTROLLER_PRODUCER.to_owned(),
        input_artifact_ids: controller_request_inputs(
            &firmware_image,
            &admission.provenance,
            admission.selection_artifact.as_ref(),
        ),
    };
    let request_artifact = match &request {
        ControllerRequestEnvelope::V1(request) => write_bounded_json(
            &session,
            &lock,
            request_spec,
            request,
            MAX_CONTROLLER_REQUEST_BYTES,
        )?,
        ControllerRequestEnvelope::V2(request) => write_bounded_json(
            &session,
            &lock,
            request_spec,
            request,
            MAX_CONTROLLER_REQUEST_BYTES,
        )?,
    };
    let mut result = json!({
        "session_id": session.id().as_str(),
        "state": state.status,
        "capture_phase": progress.phase.as_str(),
        "next_required_operation": progress.phase.expected_operation(),
        "transaction_id": transaction_id,
        "binding_sha256": request.binding().binding_sha256,
        "request_artifact": request_artifact,
        "fault_action": request.fault_action(),
        "mcp": request.mcp(),
        "response_handoff": {
            "path": response_absolute,
            "max_bytes": request.max_response_bytes(),
            "instruction": "write the exact final <FINISHED>/<CONTENT> wrapper returned by execute or collect; do not write <NOT FINISHED>"
        },
    });
    let (output_key, output_value) = match &request {
        ControllerRequestEnvelope::V1(request) => (
            "output_reservation",
            serde_json::to_value(&request.output).map_err(AppError::operational)?,
        ),
        ControllerRequestEnvelope::V2(request) => (
            "output_reservations",
            serde_json::to_value(&request.outputs).map_err(AppError::operational)?,
        ),
    };
    result[output_key] = output_value;
    success("controller.prepare", result)
}

/// Validates the fixed controller operation and its mode without touching the
/// artifact root or Session.  App uses this before perf-run lease discovery;
/// `prepare` deliberately repeats the validation at its mutation boundary.
pub(crate) fn preflight_prepare(operation: &str, mode: Option<&str>) -> Result<(), AppError> {
    let operation = PerfOperation::parse(operation).ok_or_else(|| {
        AppError::operational(format!(
            "unknown fixed TRACE32 performance operation `{operation}`"
        ))
    })?;
    validate_mode(operation, mode)
}

/// Validates an externally supplied transaction identifier before app opens a
/// Session for performance-run lease discovery.
pub(crate) fn preflight_transaction_id(transaction_id: &str) -> Result<(), AppError> {
    validate_transaction_id(transaction_id)
}

/// Validates one closed abort request before app opens its Session.
pub(crate) fn preflight_abort(transaction_id: &str, reason: &str) -> Result<(), AppError> {
    validate_transaction_id(transaction_id)?;
    parse_abort_reason(reason).map(|_| ())
}

pub(crate) fn preflight_confirm_abort(
    transaction_id: &str,
    acknowledge_unbound_success: bool,
) -> Result<(), AppError> {
    validate_transaction_id(transaction_id)?;
    if !acknowledge_unbound_success {
        return Err(AppError::operational(
            "confirm-abort requires --acknowledge-unbound-success after the trusted caller observes abort_practice_skill return success",
        ));
    }
    Ok(())
}

const fn operation_uses_target_adapter(operation: PerfOperation) -> bool {
    !matches!(
        operation,
        PerfOperation::GetCapabilities | PerfOperation::GetHotspots
    )
}

/// Loads one driver-owned transaction without granting artifact-ingest or
/// response-accept authority.  Pending work must still own the root-wide
/// controller slot; an already accepted response is readable only as an
/// immutable terminal result.
pub(crate) fn driver_transaction(
    root: &ArtifactRoot,
    session_id: &str,
    transaction_id: &str,
) -> Result<DriverTransactionState, AppError> {
    validate_transaction_id(transaction_id)?;
    let namespace = root.try_namespace_lock().map_err(AppError::operational)?;
    let session = open_session(root, session_id)?;
    let _lock = session
        .try_lock_in_namespace(&namespace)
        .map_err(AppError::operational)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    let (request_artifact, request) = driver_request(&session, &artifacts, transaction_id)?;
    let accepted = driver_accepted_response(&session, &artifacts, request_artifact, &request)?;
    let abort_plan = driver_abort_plan(&session, &artifacts, request_artifact, &request)?;
    let abort_plan_ref = abort_plan
        .as_ref()
        .map(|(artifact, abort)| (abort, *artifact));
    let journal = crate::controller_journal::projection_envelope(
        &session,
        &artifacts,
        request_artifact,
        &request,
        abort_plan_ref,
    )?;
    let abort_confirmed = driver_abort_confirmed(
        &session,
        &artifacts,
        request_artifact,
        &request,
        abort_plan.as_ref(),
    )?;
    if !accepted && !abort_confirmed {
        ensure_driver_transaction_ownership(root, &session, transaction_id)?;
    }
    Ok(DriverTransactionState {
        response_staged: staged_response_exists(&session, &request)?,
        request,
        response_accepted: accepted,
        dispatch_intent_recorded: journal.dispatch_intent_recorded,
        fault_intent_recorded: journal.fault_intent_recorded,
        fault_triggered_recorded: journal.fault_triggered_recorded,
        abort_planned: abort_plan.is_some(),
        abort_attempted: journal.abort_attempted,
        abort_success_observed: journal.abort_success_observed,
        abort_confirmed,
    })
}

fn driver_abort_plan<'a>(
    session: &Session,
    artifacts: &'a [Artifact],
    request_artifact: &Artifact,
    request: &ControllerRequestEnvelope,
) -> Result<Option<(&'a Artifact, ControllerAbortRequest)>, AppError> {
    let Some(artifact) = find_artifact(
        artifacts,
        &abort_artifact_id(&request.binding().transaction_id),
    ) else {
        return Ok(None);
    };
    if artifact.kind != CONTROLLER_ABORT_REQUEST_KIND || artifact.producer != CONTROLLER_PRODUCER {
        return Err(AppError::operational(
            "controller abort plan has an invalid reserved artifact envelope",
        ));
    }
    let abort: ControllerAbortRequest =
        read_bounded_json_artifact(session, artifact, MAX_CONTROLLER_REQUEST_BYTES)?;
    if abort.binding != *request.binding()
        || abort.request_artifact_id != request_artifact.id
        || abort.request_artifact_sha256 != request_artifact.sha256
        || abort.mcp.tool != T32mcpTool::AbortPracticeSkill
    {
        return Err(AppError::operational(
            "controller abort plan is not bound to its immutable request",
        ));
    }
    Ok(Some((artifact, abort)))
}

fn driver_abort_confirmed(
    session: &Session,
    artifacts: &[Artifact],
    request_artifact: &Artifact,
    request: &ControllerRequestEnvelope,
    abort_plan: Option<&(&Artifact, ControllerAbortRequest)>,
) -> Result<bool, AppError> {
    let Some(receipt_artifact) = find_artifact(
        artifacts,
        &abort_receipt_artifact_id(&request.binding().transaction_id),
    ) else {
        return Ok(false);
    };
    if receipt_artifact.kind != CONTROLLER_ABORT_RECEIPT_KIND
        || receipt_artifact.producer != CONTROLLER_PRODUCER
    {
        return Err(AppError::operational(
            "controller abort receipt has an invalid reserved artifact envelope",
        ));
    }
    let Some((abort_artifact, abort)) = abort_plan else {
        return Err(AppError::operational(
            "controller abort receipt exists without its immutable abort plan",
        ));
    };
    let receipt: ControllerAbortReceipt =
        read_bounded_json_artifact(session, receipt_artifact, MAX_CONTROLLER_RESPONSE_BYTES)?;
    validate_abort_receipt_envelope(request, request_artifact, abort, abort_artifact, &receipt)?;
    Ok(true)
}

/// Writes exact response bytes to the immutable request's host-owned staging
/// path.  This deliberately does not ingest, parse, or accept the response.
pub(crate) fn stage_driver_response(
    root: &ArtifactRoot,
    session_id: &str,
    transaction_id: &str,
    bytes: &[u8],
) -> Result<(), AppError> {
    validate_transaction_id(transaction_id)?;
    let namespace = root.try_namespace_lock().map_err(AppError::operational)?;
    let session = open_session(root, session_id)?;
    let lock = session
        .try_lock_in_namespace(&namespace)
        .map_err(AppError::operational)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    let (request_artifact, request) = driver_request(&session, &artifacts, transaction_id)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > request.max_response_bytes() {
        return Err(AppError::operational(format!(
            "driver response is {} bytes; immutable request maximum is {}",
            bytes.len(),
            request.max_response_bytes()
        )));
    }
    if driver_accepted_response(&session, &artifacts, request_artifact, &request)? {
        let raw_artifact = find_required_artifact(
            &artifacts,
            &raw_response_artifact_id(transaction_id),
            CONTROLLER_RAW_RESPONSE_KIND,
        )?;
        let accepted_bytes =
            read_bounded_bytes_artifact(&session, raw_artifact, request.max_response_bytes())?;
        if accepted_bytes == bytes {
            return Ok(());
        }
        return Err(AppError::operational(
            "controller response is already accepted; driver may only retry its exact immutable bytes",
        ));
    }
    ensure_driver_transaction_ownership(root, &session, transaction_id)?;
    session
        .ensure_staged_exact(
            &lock,
            request.response_staging_path(),
            bytes,
            request.max_response_bytes(),
        )
        .map_err(AppError::operational)
}

/// Durably records selection of an immutable request before upstream dispatch.
pub(crate) fn record_driver_dispatch_intent(
    root: &ArtifactRoot,
    session_id: &str,
    transaction_id: &str,
) -> Result<(), AppError> {
    record_driver_transaction_event(
        root,
        session_id,
        transaction_id,
        ControllerDriverEventKind::DispatchIntent,
    )
}

/// Durably records selection of the request-bound external fault action.
pub(crate) fn record_driver_fault_intent(
    root: &ArtifactRoot,
    session_id: &str,
    transaction_id: &str,
) -> Result<(), AppError> {
    record_driver_transaction_event(
        root,
        session_id,
        transaction_id,
        ControllerDriverEventKind::FaultIntent,
    )
}

/// Durably records successful completion of the request-bound one-shot fault.
pub(crate) fn record_driver_fault_triggered(
    root: &ArtifactRoot,
    session_id: &str,
    transaction_id: &str,
) -> Result<(), AppError> {
    record_driver_transaction_event(
        root,
        session_id,
        transaction_id,
        ControllerDriverEventKind::FaultTriggered,
    )
}

/// Durably records that the host is about to invoke the upstream abort tool.
pub(crate) fn record_driver_abort_attempt(
    root: &ArtifactRoot,
    session_id: &str,
    transaction_id: &str,
) -> Result<(), AppError> {
    record_driver_transaction_event(
        root,
        session_id,
        transaction_id,
        ControllerDriverEventKind::AbortAttempt,
    )
}

/// Durably records that the host observed upstream abort-tool success.
pub(crate) fn record_driver_abort_success(
    root: &ArtifactRoot,
    session_id: &str,
    transaction_id: &str,
) -> Result<(), AppError> {
    record_driver_transaction_event(
        root,
        session_id,
        transaction_id,
        ControllerDriverEventKind::AbortSuccessObserved,
    )
}

fn record_driver_transaction_event(
    root: &ArtifactRoot,
    session_id: &str,
    transaction_id: &str,
    event_kind: ControllerDriverEventKind,
) -> Result<(), AppError> {
    validate_transaction_id(transaction_id)?;
    let namespace = root.try_namespace_lock().map_err(AppError::operational)?;
    let session = open_session(root, session_id)?;
    let lock = session
        .try_lock_in_namespace(&namespace)
        .map_err(AppError::operational)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    let (request_artifact, request) = driver_request(&session, &artifacts, transaction_id)?;
    let abort_plan = driver_abort_plan(&session, &artifacts, request_artifact, &request)?;
    let abort_plan_ref = abort_plan
        .as_ref()
        .map(|(artifact, abort)| (abort, *artifact));
    let event = driver_transaction_event(request_artifact, &request, abort_plan_ref, event_kind)?;
    if crate::controller_journal::event_exists_exact_envelope(
        &session,
        &artifacts,
        request_artifact,
        &request,
        abort_plan_ref,
        &event,
    )? {
        return Ok(());
    }
    if driver_accepted_response(&session, &artifacts, request_artifact, &request)? {
        return Err(AppError::operational(
            "an accepted controller response cannot acquire a new driver journal intent",
        ));
    }
    ensure_driver_transaction_ownership(root, &session, transaction_id)?;
    let projection = crate::controller_journal::projection_envelope(
        &session,
        &artifacts,
        request_artifact,
        &request,
        abort_plan_ref,
    )?;
    match event_kind {
        ControllerDriverEventKind::DispatchIntent => {}
        ControllerDriverEventKind::FaultIntent => {
            if request.fault_action().is_none() {
                return Err(AppError::operational(
                    "driver fault intent requires an immutable request fault action",
                ));
            }
        }
        ControllerDriverEventKind::FaultTriggered => {
            ensure_driver_fault_triggerable(
                request.fault_action().is_some(),
                projection.fault_intent_recorded,
                abort_plan.is_some(),
            )?;
        }
        ControllerDriverEventKind::AbortAttempt => {
            if abort_plan.is_none() {
                return Err(AppError::operational(
                    "driver abort attempt requires an immutable abort plan",
                ));
            }
        }
        ControllerDriverEventKind::AbortSuccessObserved => {
            if !projection.abort_attempted {
                return Err(AppError::operational(
                    "driver abort success cannot be observed before its durable abort attempt",
                ));
            }
        }
        ControllerDriverEventKind::WorkloadIntent | ControllerDriverEventKind::WorkloadComplete => {
            return Err(AppError::operational(
                "workload events require accepted StartV2 workload authority",
            ));
        }
    }
    crate::controller_journal::record_event_envelope(
        &session,
        &lock,
        &artifacts,
        request_artifact,
        &request,
        abort_plan_ref,
        &event,
    )
}

fn ensure_driver_fault_triggerable(
    has_fault_action: bool,
    fault_intent_recorded: bool,
    abort_planned: bool,
) -> Result<(), AppError> {
    if has_fault_action && fault_intent_recorded && abort_planned {
        Ok(())
    } else {
        Err(AppError::operational(
            "driver fault trigger requires a durable request-bound fault intent and immutable abort plan",
        ))
    }
}

fn driver_transaction_event(
    request_artifact: &Artifact,
    request: &ControllerRequestEnvelope,
    abort_plan: Option<(&ControllerAbortRequest, &Artifact)>,
    event: ControllerDriverEventKind,
) -> Result<ControllerDriverEvent, AppError> {
    let (abort_reason, abort_request_artifact_id, abort_request_artifact_sha256) = if matches!(
        event,
        ControllerDriverEventKind::FaultTriggered
            | ControllerDriverEventKind::AbortAttempt
            | ControllerDriverEventKind::AbortSuccessObserved
    ) {
        let Some((abort, artifact)) = abort_plan else {
            return Err(AppError::operational(
                "driver event requires an immutable abort plan",
            ));
        };
        (
            Some(abort.reason),
            Some(artifact.id.clone()),
            Some(artifact.sha256.clone()),
        )
    } else {
        (None, None, None)
    };
    Ok(ControllerDriverEvent {
        schema: ControllerDriverEventSchemaVersion::V1,
        event,
        binding: request.binding().clone(),
        request_artifact_id: request_artifact.id.clone(),
        request_artifact_sha256: request_artifact.sha256.clone(),
        operation: request.operation(),
        fault_action: request.fault_action(),
        abort_reason,
        abort_request_artifact_id,
        abort_request_artifact_sha256,
        initial_target_state: None,
        workload_identity: None,
        performance_run_deployment_binding_artifact_id: None,
        performance_run_deployment_binding_artifact_sha256: None,
        performance_run_deployment_sha256: None,
        workload_executable_sha256: None,
    })
}

/// Confirms after durable observed success, or retries an existing trusted receipt.
pub(crate) fn confirm_driver_abort(
    root: &ArtifactRoot,
    session_id: &str,
    transaction_id: &str,
) -> Result<CommandOutcome, AppError> {
    let state = driver_transaction(root, session_id, transaction_id)?;
    if state.abort_confirmed {
        return confirm_abort(root, session_id, transaction_id, true);
    }
    if !state.abort_success_observed {
        return Err(AppError::operational(
            "driver abort confirmation requires a durable abort_success_observed event",
        ));
    }
    confirm_abort(root, session_id, transaction_id, true)
}

/// Reconstructs target-controller workload authority only after an accepted
/// StartV2 and before any accepted Stop completion.
pub(crate) fn driver_workload_context(
    root: &ArtifactRoot,
    session_id: &str,
) -> Result<DriverWorkloadContext, AppError> {
    let namespace = root.try_namespace_lock().map_err(AppError::operational)?;
    let session = open_session(root, session_id)?;
    let _lock = session
        .try_lock_in_namespace(&namespace)
        .map_err(AppError::operational)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    let workload = driver_workload_binding(root, &session, &artifacts)?;
    let journal = crate::controller_journal::projection_envelope(
        &session,
        &artifacts,
        &workload.request_artifact,
        &workload.request,
        None,
    )?;
    Ok(DriverWorkloadContext {
        initial_target_state: workload.initial_target_state,
        workload_identity: workload.workload_identity,
        start_binding_sha256: workload.request.binding().binding_sha256.clone(),
        start_transaction_id: workload.request.binding().transaction_id.clone(),
        duration_ns: crate::controller_capture_config::strict_performance_run_duration(&session)
            .map_err(AppError::operational)?,
        intent_recorded: journal.workload_intent_recorded,
        complete_recorded: journal.workload_complete_recorded,
    })
}

#[derive(Debug)]
struct DriverWorkloadBinding {
    request_artifact: Artifact,
    request: ControllerRequestEnvelope,
    initial_target_state: ControllerTargetState,
    workload_identity: String,
}

fn driver_workload_binding(
    root: &ArtifactRoot,
    session: &Session,
    artifacts: &[Artifact],
) -> Result<DriverWorkloadBinding, AppError> {
    let progress = controller_progress_from_artifacts(Some(root), session, artifacts)?;
    if progress.phase != ControllerCapturePhase::Stop
        || progress.completed_operations.contains(&PerfOperation::Stop)
    {
        return Err(AppError::operational(
            "driver workload context requires accepted StartV2 while Stop is the current incomplete capture phase",
        ));
    }
    accepted_start_workload_binding(session, artifacts, &progress)
}

/// Stops are unsafe to prepare after the deployment driver selected an
/// externally owned workload but before it durably proved completion.  A
/// manual caller may still use the ordinary diagnostic resume path when no
/// driver workload intent exists.
fn ensure_driver_workload_completion_before_stop(
    session: &Session,
    artifacts: &[Artifact],
    progress: &ControllerProgress,
    operation: PerfOperation,
) -> Result<(), AppError> {
    if operation != PerfOperation::Stop || progress.phase != ControllerCapturePhase::Stop {
        return Ok(());
    }
    let Some((_, ControllerEvidence::StartV2(_))) =
        accepted_controller_evidence(session, artifacts, progress, PerfOperation::Start)?
    else {
        // Pre-driver/manual Start evidence retains the public diagnostic
        // resume semantics.  Only the driver-owned StartV2 journal can make
        // workload execution ambiguous.
        return Ok(());
    };
    let workload = accepted_start_workload_binding(session, artifacts, progress)?;
    let journal = crate::controller_journal::projection_envelope(
        session,
        artifacts,
        &workload.request_artifact,
        &workload.request,
        None,
    )?;
    let strict_performance_run =
        crate::controller_capture_config::strict_performance_run_duration(session)
            .map_err(AppError::operational)?
            .is_some();
    ensure_driver_workload_completion_proven(
        journal.workload_intent_recorded,
        journal.workload_complete_recorded,
        strict_performance_run,
        session.id().as_str(),
        &workload.request.binding().transaction_id,
    )
}

/// Applies the durable host gate used by both the public workload resume and
/// the low-level Stop preparation path.
fn ensure_driver_workload_completion_proven(
    intent_recorded: bool,
    complete_recorded: bool,
    strict_performance_run: bool,
    session_id: &str,
    transaction_id: &str,
) -> Result<(), AppError> {
    if intent_recorded && !complete_recorded {
        Err(driver_workload_completion_ambiguous_error(
            session_id,
            transaction_id,
        ))
    } else if strict_performance_run && !complete_recorded {
        Err(driver_resume_required_error(session_id, transaction_id))
    } else {
        Ok(())
    }
}

fn driver_resume_required_error(session_id: &str, transaction_id: &str) -> AppError {
    AppError {
        code: "DRIVER_RESUME_REQUIRED",
        message: format!(
            "strict performance-run Session requires the controller driver to resume Start transaction `{transaction_id}` and durably complete its workload before Stop"
        ),
        details: json!({
            "session_id": session_id,
            "start_transaction_id": transaction_id,
            "required_action": "resume the strict perf_run controller driver",
        }),
        exit_code: EXIT_OPERATIONAL,
    }
}

fn driver_workload_completion_ambiguous_error(session_id: &str, transaction_id: &str) -> AppError {
    AppError {
        code: "CONTROLLER_DRIVER_WORKLOAD_AMBIGUOUS",
        message: format!(
            "controller driver selected the workload for Start transaction `{transaction_id}` without durable completion proof; Stop cannot be prepared"
        ),
        details: json!({
            "session_id": session_id,
            "start_transaction_id": transaction_id,
            "required_action": "recover the driver workload completion evidence before preparing Stop",
        }),
        exit_code: EXIT_OPERATIONAL,
    }
}

fn accepted_start_workload_binding(
    session: &Session,
    artifacts: &[Artifact],
    progress: &ControllerProgress,
) -> Result<DriverWorkloadBinding, AppError> {
    let (start_artifact, start_evidence) =
        accepted_controller_evidence(session, artifacts, progress, PerfOperation::Start)?
            .ok_or_else(|| {
                AppError::operational("driver workload context requires accepted StartV2 evidence")
            })?;
    let ControllerEvidence::StartV2(start) = start_evidence else {
        return Err(AppError::operational(
            "driver workload context requires accepted StartV2 evidence",
        ));
    };
    let transaction_id = start_artifact_transaction_id(session, artifacts, &start_artifact)?;
    let (request_artifact, request) = driver_request(session, artifacts, &transaction_id)?;
    if request.operation() != PerfOperation::Start
        || request.binding().binding_sha256 != start.binding_sha256
    {
        return Err(AppError::operational(
            "accepted StartV2 evidence is not bound to its immutable start request",
        ));
    }
    Ok(DriverWorkloadBinding {
        request_artifact: request_artifact.clone(),
        request,
        initial_target_state: start.initial_target_state,
        workload_identity: start.workload_identity,
    })
}

/// Durably records selection of the accepted StartV2 workload hook.
pub(crate) fn record_driver_workload_intent(
    root: &ArtifactRoot,
    session_id: &str,
) -> Result<(), AppError> {
    record_driver_workload_event(root, session_id, ControllerDriverEventKind::WorkloadIntent)
}

/// Durably records successful completion of the accepted StartV2 workload hook.
pub(crate) fn record_driver_workload_complete(
    root: &ArtifactRoot,
    session_id: &str,
) -> Result<(), AppError> {
    record_driver_workload_event(
        root,
        session_id,
        ControllerDriverEventKind::WorkloadComplete,
    )
}

fn record_driver_workload_event(
    root: &ArtifactRoot,
    session_id: &str,
    event_kind: ControllerDriverEventKind,
) -> Result<(), AppError> {
    let namespace = root.try_namespace_lock().map_err(AppError::operational)?;
    let session = open_session(root, session_id)?;
    let lock = session
        .try_lock_in_namespace(&namespace)
        .map_err(AppError::operational)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    let progress = controller_progress_from_artifacts(Some(root), &session, &artifacts)?;
    let workload = accepted_start_workload_binding(&session, &artifacts, &progress)?;
    let deployment = crate::target_adapter_provisioning::workload_deployment_binding_claim(
        &session, &artifacts,
    )?;
    let event = ControllerDriverEvent {
        schema: ControllerDriverEventSchemaVersion::V1,
        event: event_kind,
        binding: workload.request.binding().clone(),
        request_artifact_id: workload.request_artifact.id.clone(),
        request_artifact_sha256: workload.request_artifact.sha256.clone(),
        operation: workload.request.operation(),
        fault_action: workload.request.fault_action(),
        abort_reason: None,
        abort_request_artifact_id: None,
        abort_request_artifact_sha256: None,
        initial_target_state: Some(workload.initial_target_state),
        workload_identity: Some(workload.workload_identity),
        performance_run_deployment_binding_artifact_id: deployment
            .as_ref()
            .map(|(artifact, _)| artifact.id.clone()),
        performance_run_deployment_binding_artifact_sha256: deployment
            .as_ref()
            .map(|(artifact, _)| artifact.sha256.clone()),
        performance_run_deployment_sha256: deployment
            .as_ref()
            .map(|(_, binding)| binding.performance_run_deployment_sha256.clone()),
        workload_executable_sha256: deployment
            .as_ref()
            .map(|(_, binding)| binding.workload_executable_sha256.clone()),
    };
    if crate::controller_journal::event_exists_exact_envelope(
        &session,
        &artifacts,
        &workload.request_artifact,
        &workload.request,
        None,
        &event,
    )? {
        return Ok(());
    }
    if progress.phase != ControllerCapturePhase::Stop
        || progress.completed_operations.contains(&PerfOperation::Stop)
    {
        return Err(AppError::operational(
            "new driver workload events require accepted StartV2 while Stop is the current incomplete capture phase",
        ));
    }
    let projection = crate::controller_journal::projection_envelope(
        &session,
        &artifacts,
        &workload.request_artifact,
        &workload.request,
        None,
    )?;
    match event_kind {
        ControllerDriverEventKind::WorkloadIntent => {}
        ControllerDriverEventKind::WorkloadComplete => {
            if !projection.workload_intent_recorded {
                return Err(AppError::operational(
                    "driver workload completion requires a durable workload intent",
                ));
            }
        }
        _ => {
            return Err(AppError::operational(
                "transaction event cannot use workload journal authority",
            ));
        }
    }
    crate::controller_journal::record_event_envelope(
        &session,
        &lock,
        &artifacts,
        &workload.request_artifact,
        &workload.request,
        None,
        &event,
    )
}

pub fn accept(
    root: &ArtifactRoot,
    session_id: &str,
    transaction_id: &str,
) -> Result<CommandOutcome, AppError> {
    validate_transaction_id(transaction_id)?;
    let namespace = root.try_namespace_lock().map_err(AppError::operational)?;
    let session = open_session(root, session_id)?;
    let lock = session
        .try_lock_in_namespace(&namespace)
        .map_err(AppError::operational)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    let request_artifact = find_required_artifact(
        &artifacts,
        &request_artifact_id(transaction_id),
        CONTROLLER_REQUEST_KIND,
    )?;
    let request = read_controller_request_envelope(&session, request_artifact)?;
    validate_request_context_envelope(&session, request_artifact, &request, transaction_id)?;
    if let ControllerRequestEnvelope::V2(request) = request {
        return accept_v2(
            &session,
            &lock,
            &artifacts,
            request_artifact,
            &request,
            transaction_id,
        );
    }
    let ControllerRequestEnvelope::V1(request) = request else {
        unreachable!("V2 requests return through accept_v2")
    };

    if let Some(response_artifact) =
        find_artifact(&artifacts, &response_artifact_id(transaction_id))
    {
        let response: ControllerResponse =
            read_bounded_json_artifact(&session, response_artifact, MAX_CONTROLLER_RESPONSE_BYTES)?;
        validate_response_v1(&session, request_artifact, &request, &response)?;
        validate_response_artifact_identity_v1(response_artifact, &response)?;
        let state = reconcile_state_for_response(&session, &lock, &response)?;
        ensure_capture_config_after_cleanup(&session, &lock, &response)?;
        return render_response(response_artifact, &response, state.status);
    }

    let state = session.read_state().map_err(AppError::operational)?;
    if matches!(
        state.status,
        SessionStatus::Complete | SessionStatus::Failed
    ) {
        return Err(AppError::operational(format!(
            "terminal session `{}` has no accepted response for controller transaction `{transaction_id}`",
            session.id()
        )));
    }

    let raw_id = raw_response_artifact_id(transaction_id);
    let existing_raw = find_artifact(&artifacts, &raw_id).cloned();
    let staged_snapshot = if existing_raw.is_none() {
        let bytes = match session
            .read_staged_bounded(&request.response_staging_path, request.max_response_bytes)
        {
            Ok(bytes) => bytes,
            Err(error) => {
                return Err(transaction_pending_error(
                    "CONTROLLER_RESPONSE_READ_FAILED",
                    error.to_string(),
                    json!({
                        "session_id": session.id().as_str(),
                        "transaction_id": transaction_id,
                    }),
                ));
            }
        };
        if let Ok(wrapper) = std::str::from_utf8(&bytes)
            && matches!(
                parse_t32mcp_perf_response(
                    wrapper,
                    PerfFrameLimits {
                        max_payload_bytes: 4 * 1024,
                    },
                ),
                Err(PerfFrameError::NotFinished)
            )
        {
            return Err(transaction_pending_error(
                "CONTROLLER_RESPONSE_NOT_FINISHED",
                "t32mcp reports that the fixed PRACTICE script is still running; collect again and replace the controller-owned response staging file with the final wrapper",
                json!({
                    "session_id": session.id().as_str(),
                    "transaction_id": transaction_id,
                    "collect": request.mcp.collect,
                    "abort": request.mcp.abort,
                }),
            ));
        }
        Some(bytes)
    } else {
        None
    };
    let raw_response_artifact = if let Some(existing) = existing_raw {
        if existing.kind != CONTROLLER_RAW_RESPONSE_KIND
            || existing.producer != CONTROLLER_PRODUCER
            || existing.relative_path != raw_response_artifact_path(transaction_id)?
            || existing.input_artifact_ids != [request_artifact.id.clone()]
        {
            return Err(AppError::operational(
                "immutable controller raw response artifact has invalid identity or provenance",
            ));
        }
        existing
    } else {
        match session.ingest_staged_bounded(
            &lock,
            &request.response_staging_path,
            ArtifactSpec {
                id: raw_id,
                kind: CONTROLLER_RAW_RESPONSE_KIND.to_owned(),
                relative_path: raw_response_artifact_path(transaction_id)?,
                media_type: "text/plain".to_owned(),
                producer: CONTROLLER_PRODUCER.to_owned(),
                input_artifact_ids: vec![request_artifact.id.clone()],
            },
            request.max_response_bytes,
        ) {
            Ok(artifact) => artifact,
            Err(error) => {
                return Err(transaction_pending_error(
                    "CONTROLLER_RESPONSE_INGEST_FAILED",
                    error.to_string(),
                    json!({
                        "session_id": session.id().as_str(),
                        "transaction_id": transaction_id,
                    }),
                ));
            }
        }
    };
    let raw_bytes =
        read_bounded_bytes_artifact(&session, &raw_response_artifact, request.max_response_bytes)?;
    if staged_snapshot
        .as_ref()
        .is_some_and(|snapshot| raw_bytes.as_slice() != snapshot.as_slice())
    {
        return Err(transaction_pending_error(
            "CONTROLLER_RESPONSE_CHANGED",
            "controller response staging bytes changed between bounded inspection and immutable ingest",
            json!({
                "transaction_id": transaction_id,
                "raw_response_artifact": raw_response_artifact,
            }),
        ));
    }
    let wrapper = match String::from_utf8(raw_bytes) {
        Ok(wrapper) => wrapper,
        Err(error) => {
            return Err(transaction_pending_error(
                "CONTROLLER_RESPONSE_INVALID_UTF8",
                error.to_string(),
                json!({
                    "transaction_id": transaction_id,
                    "raw_response_artifact": raw_response_artifact,
                }),
            ));
        }
    };
    let parsed = match parse_t32mcp_perf_response(
        &wrapper,
        PerfFrameLimits {
            max_payload_bytes: 4 * 1024,
        },
    ) {
        Ok(parsed) => parsed,
        Err(error) => {
            return Err(transaction_pending_error(
                "CONTROLLER_RESPONSE_INVALID",
                error.to_string(),
                json!({
                    "transaction_id": transaction_id,
                    "raw_response_artifact": raw_response_artifact,
                }),
            ));
        }
    };
    if parsed.operation != request.operation
        || parsed.binding_sha256 != request.binding.binding_sha256.as_str()
    {
        return Err(transaction_pending_error(
            "CONTROLLER_RESPONSE_BINDING_MISMATCH",
            "collected response does not match the immutable request operation and binding",
            json!({
                "transaction_id": transaction_id,
                "expected_operation": request.operation,
                "actual_operation": parsed.operation,
                "expected_binding_sha256": request.binding.binding_sha256,
                "actual_binding_sha256": parsed.binding_sha256,
                "raw_response_artifact": raw_response_artifact,
            }),
        ));
    }
    if request.requires_interruption()
        && let Some(fault_action) = request.fault_action
    {
        return Err(transaction_pending_error(
            "CONTROLLER_FAULT_ACTION_NOT_OBSERVED",
            "a closed fault-action request produced a final script response; the deployment driver must interrupt at the bound fault point and complete two-phase abort/recovery",
            json!({
                "session_id": session.id().as_str(),
                "transaction_id": transaction_id,
                "operation": request.operation,
                "fault_action": fault_action,
                "status": parsed.status,
                "code": parsed.code,
                "raw_response_artifact": raw_response_artifact,
                "required_action": "complete the two-phase controller abort; do not accept or synthesize a successful fault response",
                "root_slot_released": false,
            }),
        ));
    }
    if matches!(
        parsed.status,
        PerfStatus::UnsupportedNeedsTrace32 | PerfStatus::InvalidArgument
    ) && request.target_adapter.is_some()
        && !matches!(
            request.operation,
            PerfOperation::Configure | PerfOperation::GetHotspots
        )
    {
        return Err(transaction_pending_error(
            "CONTROLLER_TARGET_RECOVERY_REQUIRED",
            "a selected target adapter cannot terminate an incomplete physical capture with a rejection frame; complete the two-phase abort and typed recovery",
            json!({
                "session_id": session.id().as_str(),
                "transaction_id": transaction_id,
                "operation": request.operation,
                "status": parsed.status,
                "code": parsed.code,
                "raw_response_artifact": raw_response_artifact,
                "root_slot_released": false,
            }),
        ));
    }
    if parsed.status == PerfStatus::HostProcessingRequired {
        return Err(transaction_pending_error(
            "CONTROLLER_V2_HOST_PROCESSING_FORBIDDEN",
            "Controller V2 permits only final OK responses; host processing is reserved for V1 perf_get_hotspots",
            json!({"transaction_id": transaction_id, "operation": request.operation}),
        ));
    }

    let output_artifact = if parsed.status == PerfStatus::Ok {
        accept_output_artifact(
            &session,
            &lock,
            &artifacts,
            request_artifact,
            &request,
            &raw_response_artifact,
        )?
    } else {
        None
    };

    let response = ControllerResponse {
        schema: ControllerResponseSchemaVersion::V1,
        binding: request.binding.clone(),
        request_artifact_id: request_artifact.id.clone(),
        request_artifact_sha256: request_artifact.sha256.clone(),
        script_response: (&parsed).into(),
        raw_response_artifact: raw_response_artifact.clone(),
        output_artifact: output_artifact.clone(),
    };
    validate_response_v1(&session, request_artifact, &request, &response)?;
    validate_candidate_evidence_chain(&session, &artifacts, &request, &response).map_err(
        |error| {
            transaction_pending_error(
                "CONTROLLER_EVIDENCE_CHAIN_MISMATCH",
                error.message,
                json!({
                    "transaction_id": transaction_id,
                    "operation": request.operation,
                    "raw_response_artifact": raw_response_artifact.clone(),
                    "evidence_artifact": output_artifact.clone(),
                    "required_action": "complete the two-phase controller abort; contradictory immutable evidence cannot advance capture phase",
                }),
            )
        },
    )?;
    let mut response_inputs = vec![
        request_artifact.id.clone(),
        raw_response_artifact.id.clone(),
    ];
    if let Some(output) = &output_artifact {
        response_inputs.push(output.id.clone());
    }
    let response_artifact = write_bounded_json(
        &session,
        &lock,
        ArtifactSpec {
            id: response_artifact_id(transaction_id),
            kind: CONTROLLER_RESPONSE_KIND.to_owned(),
            relative_path: response_artifact_path(transaction_id)?,
            media_type: "application/json".to_owned(),
            producer: CONTROLLER_PRODUCER.to_owned(),
            input_artifact_ids: response_inputs,
        },
        &response,
        MAX_CONTROLLER_RESPONSE_BYTES,
    )?;
    validate_response_artifact_identity_v1(&response_artifact, &response)?;

    let state = match parsed.status {
        PerfStatus::UnsupportedNeedsTrace32 | PerfStatus::InvalidArgument => session
            .transition(
                &lock,
                SessionStatus::Failed,
                Some(SessionError {
                    code: "CONTROLLER_SCRIPT_REJECTED".to_owned(),
                    message: format!(
                        "{} returned {} / {}",
                        request.operation.as_str(),
                        parsed.status.as_str(),
                        parsed.code
                    ),
                    details: Default::default(),
                }),
            )
            .map_err(AppError::operational)?,
        PerfStatus::Ok | PerfStatus::HostProcessingRequired => {
            reconcile_state_for_response(&session, &lock, &response)?
        }
    };
    ensure_capture_config_after_cleanup(&session, &lock, &response)?;
    render_response(&response_artifact, &response, state.status)
}

fn accept_v2(
    session: &Session,
    lock: &SessionLock,
    artifacts: &[Artifact],
    request_artifact: &Artifact,
    request: &ControllerRequestV2,
    transaction_id: &str,
) -> Result<CommandOutcome, AppError> {
    if let Some(response_artifact) = find_artifact(artifacts, &response_artifact_id(transaction_id))
    {
        let response = read_controller_response_envelope(session, response_artifact)?;
        let request_envelope = ControllerRequestEnvelope::V2(request.clone());
        validate_response(session, request_artifact, &request_envelope, &response)?;
        validate_response_artifact_identity(response_artifact, &response)?;
        let state = reconcile_state_for_response_v2(session, lock, &response)?;
        ensure_capture_config_after_cleanup_v2(session, lock, &response)?;
        return render_response_v2(response_artifact, &response, state.status);
    }
    let state = session.read_state().map_err(AppError::operational)?;
    if matches!(
        state.status,
        SessionStatus::Complete | SessionStatus::Failed
    ) {
        return Err(AppError::operational(format!(
            "terminal session `{}` has no accepted response for controller transaction `{transaction_id}`",
            session.id()
        )));
    }
    let raw_id = raw_response_artifact_id(transaction_id);
    let existing_raw = find_artifact(artifacts, &raw_id).cloned();
    let staged_snapshot = if existing_raw.is_none() {
        let bytes = session
            .read_staged_bounded(&request.response_staging_path, request.max_response_bytes)
            .map_err(|error| {
                transaction_pending_error(
                    "CONTROLLER_RESPONSE_READ_FAILED",
                    error.to_string(),
                    json!({
                        "session_id": session.id().as_str(), "transaction_id": transaction_id,
                    }),
                )
            })?;
        if let Ok(wrapper) = std::str::from_utf8(&bytes)
            && matches!(
                parse_t32mcp_perf_response(
                    wrapper,
                    PerfFrameLimits {
                        max_payload_bytes: 4 * 1024
                    },
                ),
                Err(PerfFrameError::NotFinished)
            )
        {
            return Err(transaction_pending_error(
                "CONTROLLER_RESPONSE_NOT_FINISHED",
                "t32mcp reports that the fixed PRACTICE script is still running; collect again and replace the controller-owned response staging file with the final wrapper",
                json!({
                    "session_id": session.id().as_str(),
                    "transaction_id": transaction_id,
                    "collect": request.mcp.collect,
                    "abort": request.mcp.abort,
                }),
            ));
        }
        Some(bytes)
    } else {
        None
    };
    let raw_response_artifact = if let Some(existing) = existing_raw {
        if existing.kind != CONTROLLER_RAW_RESPONSE_KIND
            || existing.producer != CONTROLLER_PRODUCER
            || existing.relative_path != raw_response_artifact_path(transaction_id)?
            || existing.input_artifact_ids != [request_artifact.id.clone()]
        {
            return Err(AppError::operational(
                "immutable controller raw response artifact has invalid identity or provenance",
            ));
        }
        existing
    } else {
        session
            .ingest_staged_bounded(
                lock,
                &request.response_staging_path,
                ArtifactSpec {
                    id: raw_id,
                    kind: CONTROLLER_RAW_RESPONSE_KIND.to_owned(),
                    relative_path: raw_response_artifact_path(transaction_id)?,
                    media_type: "text/plain".to_owned(),
                    producer: CONTROLLER_PRODUCER.to_owned(),
                    input_artifact_ids: vec![request_artifact.id.clone()],
                },
                request.max_response_bytes,
            )
            .map_err(|error| {
                transaction_pending_error(
                    "CONTROLLER_RESPONSE_INGEST_FAILED",
                    error.to_string(),
                    json!({"transaction_id": transaction_id}),
                )
            })?
    };
    let raw_bytes =
        read_bounded_bytes_artifact(session, &raw_response_artifact, request.max_response_bytes)?;
    if staged_snapshot
        .as_ref()
        .is_some_and(|snapshot| snapshot.as_slice() != raw_bytes.as_slice())
    {
        return Err(transaction_pending_error(
            "CONTROLLER_RESPONSE_CHANGED",
            "controller response staging bytes changed between bounded inspection and immutable ingest",
            json!({"transaction_id": transaction_id}),
        ));
    }
    let wrapper = String::from_utf8(raw_bytes).map_err(|error| {
        transaction_pending_error(
            "CONTROLLER_RESPONSE_INVALID_UTF8",
            error.to_string(),
            json!({"transaction_id": transaction_id}),
        )
    })?;
    let parsed = parse_t32mcp_perf_response(
        &wrapper,
        PerfFrameLimits {
            max_payload_bytes: 4 * 1024,
        },
    )
    .map_err(|error| {
        transaction_pending_error(
            "CONTROLLER_RESPONSE_INVALID",
            error.to_string(),
            json!({"transaction_id": transaction_id}),
        )
    })?;
    if parsed.operation != request.operation
        || parsed.binding_sha256 != request.binding.binding_sha256.as_str()
    {
        return Err(transaction_pending_error(
            "CONTROLLER_RESPONSE_BINDING_MISMATCH",
            "collected response does not match the immutable request operation and binding",
            json!({"transaction_id": transaction_id}),
        ));
    }
    if request.requires_interruption() {
        return Err(transaction_pending_error(
            "CONTROLLER_FAULT_ACTION_NOT_OBSERVED",
            "a closed fault-action request cannot accept a final script response",
            json!({"transaction_id": transaction_id}),
        ));
    }
    if matches!(
        parsed.status,
        PerfStatus::UnsupportedNeedsTrace32 | PerfStatus::InvalidArgument
    ) {
        return Err(transaction_pending_error(
            "CONTROLLER_TARGET_RECOVERY_REQUIRED",
            "a selected V2 target adapter cannot terminate an incomplete physical capture with a rejection frame",
            json!({"transaction_id": transaction_id}),
        ));
    }
    let output_artifacts = if parsed.status == PerfStatus::Ok {
        accept_output_artifacts_v2(
            session,
            lock,
            artifacts,
            request_artifact,
            request,
            &raw_response_artifact,
        )?
    } else {
        Vec::new()
    };
    let response = ControllerResponseV2 {
        schema: t32perf_trace32::ControllerResponseV2SchemaVersion::V2,
        binding: request.binding.clone(),
        request_artifact_id: request_artifact.id.clone(),
        request_artifact_sha256: request_artifact.sha256.clone(),
        script_response: (&parsed).into(),
        raw_response_artifact: raw_response_artifact.clone(),
        output_artifact: None,
        output_artifacts,
    };
    let request_envelope = ControllerRequestEnvelope::V2(request.clone());
    let response_envelope = ControllerResponseEnvelope::V2(response.clone());
    validate_response(
        session,
        request_artifact,
        &request_envelope,
        &response_envelope,
    )?;
    validate_candidate_evidence_chain_v2(session, artifacts, request, &response)?;
    let mut response_inputs = vec![
        request_artifact.id.clone(),
        raw_response_artifact.id.clone(),
    ];
    response_inputs.extend(
        response
            .output_artifacts
            .iter()
            .map(|artifact| artifact.id.clone()),
    );
    let response_artifact = write_bounded_json(
        session,
        lock,
        ArtifactSpec {
            id: response_artifact_id(transaction_id),
            kind: CONTROLLER_RESPONSE_KIND.to_owned(),
            relative_path: response_artifact_path(transaction_id)?,
            media_type: "application/json".to_owned(),
            producer: CONTROLLER_PRODUCER.to_owned(),
            input_artifact_ids: response_inputs,
        },
        &response,
        MAX_CONTROLLER_RESPONSE_BYTES,
    )?;
    validate_response_artifact_identity(&response_artifact, &response_envelope)?;
    let state = reconcile_state_for_response_v2(session, lock, &response_envelope)?;
    ensure_capture_config_after_cleanup_v2(session, lock, &response_envelope)?;
    render_response_v2(&response_artifact, &response_envelope, state.status)
}

/// Cleanup is the terminal accepted operation of the Controller chain. Keep
/// capture-config materialization in the same namespace/session lock scope so
/// a successful cleanup never leaves a completed capture without its
/// authoritative host-derived configuration. The materializer is exact and
/// idempotent, which also repairs a process crash after response acceptance.
fn ensure_capture_config_after_cleanup(
    session: &Session,
    lock: &SessionLock,
    response: &ControllerResponse,
) -> Result<(), AppError> {
    if response.script_response.status != PerfStatus::Ok
        || response.script_response.operation != PerfOperation::Cleanup
    {
        return Ok(());
    }
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    let binding = accepted_trace32_completed_binding(session, &artifacts)?.ok_or_else(|| {
        AppError::operational("accepted cleanup did not produce a complete TRACE32 runtime binding")
    })?;
    crate::controller_capture_config::materialize(session, lock, &binding)
        .map_err(AppError::operational)?;
    Ok(())
}

fn ensure_capture_config_after_cleanup_v2(
    session: &Session,
    lock: &SessionLock,
    response: &ControllerResponseEnvelope,
) -> Result<(), AppError> {
    if response.script_response().status != PerfStatus::Ok
        || response.script_response().operation != PerfOperation::Cleanup
    {
        return Ok(());
    }
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    let binding = accepted_trace32_completed_binding(session, &artifacts)?.ok_or_else(|| {
        AppError::operational("accepted cleanup did not produce a complete TRACE32 runtime binding")
    })?;
    crate::controller_capture_config::materialize(session, lock, &binding)
        .map(|_| ())
        .map_err(AppError::operational)
}

pub fn abort(
    root: &ArtifactRoot,
    session_id: &str,
    transaction_id: &str,
    reason: &str,
) -> Result<CommandOutcome, AppError> {
    validate_transaction_id(transaction_id)?;
    let reason = parse_abort_reason(reason)?;
    let namespace = root.try_namespace_lock().map_err(AppError::operational)?;
    let session = open_session(root, session_id)?;
    let lock = session
        .try_lock_in_namespace(&namespace)
        .map_err(AppError::operational)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    let request_artifact = find_required_artifact(
        &artifacts,
        &request_artifact_id(transaction_id),
        CONTROLLER_REQUEST_KIND,
    )?;
    let request = read_controller_request_envelope(&session, request_artifact)?;
    validate_request_context_envelope(&session, request_artifact, &request, transaction_id)?;
    if find_artifact(&artifacts, &response_artifact_id(transaction_id)).is_some() {
        return Err(AppError::operational(
            "an accepted controller response cannot be aborted",
        ));
    }
    let abort_id = abort_artifact_id(transaction_id);
    if let Some(existing) = find_artifact(&artifacts, &abort_id) {
        let abort: ControllerAbortRequest =
            read_bounded_json_artifact(&session, existing, MAX_CONTROLLER_REQUEST_BYTES)?;
        if abort.binding != *request.binding()
            || abort.request_artifact_id != request_artifact.id
            || abort.request_artifact_sha256 != request_artifact.sha256
            || abort.mcp.tool != T32mcpTool::AbortPracticeSkill
        {
            return Err(AppError::operational(
                "existing controller abort plan is not bound to its immutable request",
            ));
        }
        if abort.reason != reason {
            return Err(AppError::operational(format!(
                "controller abort plan already binds reason `{}` and cannot be retried as `{}`",
                abort_reason_name(abort.reason),
                abort_reason_name(reason)
            )));
        }
        return success(
            "controller.abort",
            json!({
                "session_id": session.id().as_str(),
                "state": session.read_state().map_err(AppError::operational)?.status,
                "transaction_id": transaction_id,
                "abort_request_artifact": existing,
                "mcp": abort.mcp,
                "abort_executed": false,
                "root_slot_released": false,
            }),
        );
    }
    match root_active_transaction(root)? {
        Some((owner_session, owner_transaction))
            if owner_session == session.id().as_str() && owner_transaction == transaction_id => {}
        Some((owner_session, owner_transaction)) => {
            return Err(AppError {
                code: "CONTROLLER_ABORT_OWNERSHIP_MISMATCH",
                message: "abort_practice_skill has no upstream ownership token; refusing to abort while another root transaction owns the single t32mcp slot"
                    .to_owned(),
                details: json!({
                    "requested_session_id": session.id().as_str(),
                    "requested_transaction_id": transaction_id,
                    "owner_session_id": owner_session,
                    "owner_transaction_id": owner_transaction,
                }),
                exit_code: EXIT_OPERATIONAL,
            });
        }
        None => {
            return Err(AppError::operational(
                "controller transaction no longer owns an active root-wide t32mcp slot",
            ));
        }
    }
    let state = session.read_state().map_err(AppError::operational)?;
    if matches!(
        state.status,
        SessionStatus::Complete | SessionStatus::Failed
    ) {
        return Err(AppError::operational(
            "terminal session cannot create a controller abort request",
        ));
    }
    let abort = ControllerAbortRequest {
        schema: ControllerAbortRequestSchemaVersion::V1,
        binding: request.binding().clone(),
        request_artifact_id: request_artifact.id.clone(),
        request_artifact_sha256: request_artifact.sha256.clone(),
        mcp: NoArgumentsToolCall {
            tool: T32mcpTool::AbortPracticeSkill,
            arguments: NoArguments::default(),
        },
        reason,
    };
    let abort_artifact = write_bounded_json(
        &session,
        &lock,
        ArtifactSpec {
            id: abort_id,
            kind: CONTROLLER_ABORT_REQUEST_KIND.to_owned(),
            relative_path: abort_artifact_path(transaction_id)?,
            media_type: "application/json".to_owned(),
            producer: CONTROLLER_PRODUCER.to_owned(),
            input_artifact_ids: vec![request_artifact.id.clone()],
        },
        &abort,
        MAX_CONTROLLER_REQUEST_BYTES,
    )?;
    success(
        "controller.abort",
        json!({
            "session_id": session.id().as_str(),
            "state": state.status,
            "transaction_id": transaction_id,
            "abort_request_artifact": abort_artifact,
            "mcp": abort.mcp,
            "abort_executed": false,
            "root_slot_released": false,
            "warning": "invoke abort_practice_skill on the same trusted single-tenant t32mcp instance; upstream provides no transaction ownership token or bound acknowledgement"
        }),
    )
}

pub fn confirm_abort(
    root: &ArtifactRoot,
    session_id: &str,
    transaction_id: &str,
    acknowledge_unbound_success: bool,
) -> Result<CommandOutcome, AppError> {
    preflight_confirm_abort(transaction_id, acknowledge_unbound_success)?;
    let namespace = root.try_namespace_lock().map_err(AppError::operational)?;
    let session = open_session(root, session_id)?;
    let lock = session
        .try_lock_in_namespace(&namespace)
        .map_err(AppError::operational)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    let request_artifact = find_required_artifact(
        &artifacts,
        &request_artifact_id(transaction_id),
        CONTROLLER_REQUEST_KIND,
    )?;
    let request = read_controller_request_envelope(&session, request_artifact)?;
    validate_request_context_envelope(&session, request_artifact, &request, transaction_id)?;
    let abort_request_artifact = find_required_artifact(
        &artifacts,
        &abort_artifact_id(transaction_id),
        CONTROLLER_ABORT_REQUEST_KIND,
    )?;
    let abort_request: ControllerAbortRequest = read_bounded_json_artifact(
        &session,
        abort_request_artifact,
        MAX_CONTROLLER_REQUEST_BYTES,
    )?;
    if abort_request.binding != *request.binding()
        || abort_request.request_artifact_id != request_artifact.id
        || abort_request.request_artifact_sha256 != request_artifact.sha256
        || abort_request.mcp.tool != T32mcpTool::AbortPracticeSkill
    {
        return Err(AppError::operational(
            "controller abort plan is not bound to its immutable request",
        ));
    }

    let receipt_id = abort_receipt_artifact_id(transaction_id);
    let receipt_artifact = if let Some(existing) = find_artifact(&artifacts, &receipt_id) {
        let receipt: ControllerAbortReceipt =
            read_bounded_json_artifact(&session, existing, MAX_CONTROLLER_RESPONSE_BYTES)?;
        validate_abort_receipt_envelope(
            &request,
            request_artifact,
            &abort_request,
            abort_request_artifact,
            &receipt,
        )?;
        existing.clone()
    } else {
        match root_active_transaction(root)? {
            Some((owner_session, owner_transaction))
                if owner_session == session.id().as_str()
                    && owner_transaction == transaction_id => {}
            Some((owner_session, owner_transaction)) => {
                return Err(AppError {
                    code: "CONTROLLER_ABORT_OWNERSHIP_MISMATCH",
                    message: "unbound abort acknowledgement does not belong to the active root-wide transaction"
                        .to_owned(),
                    details: json!({
                        "requested_session_id": session.id().as_str(),
                        "requested_transaction_id": transaction_id,
                        "owner_session_id": owner_session,
                        "owner_transaction_id": owner_transaction,
                    }),
                    exit_code: EXIT_OPERATIONAL,
                });
            }
            None => {
                return Err(AppError::operational(
                    "controller transaction is not the active root-wide abort owner",
                ));
            }
        }
        let receipt = ControllerAbortReceipt {
            schema: ControllerAbortReceiptSchemaVersion::V1,
            binding: request.binding().clone(),
            request_artifact_id: request_artifact.id.clone(),
            request_artifact_sha256: request_artifact.sha256.clone(),
            abort_request_artifact_id: abort_request_artifact.id.clone(),
            abort_request_artifact_sha256: abort_request_artifact.sha256.clone(),
            acknowledgement: ControllerAbortAcknowledgement::UnboundSingleTenantToolSuccess,
        };
        write_bounded_json(
            &session,
            &lock,
            ArtifactSpec {
                id: receipt_id,
                kind: CONTROLLER_ABORT_RECEIPT_KIND.to_owned(),
                relative_path: abort_receipt_artifact_path(transaction_id)?,
                media_type: "application/json".to_owned(),
                producer: CONTROLLER_PRODUCER.to_owned(),
                input_artifact_ids: vec![
                    request_artifact.id.clone(),
                    abort_request_artifact.id.clone(),
                ],
            },
            &receipt,
            MAX_CONTROLLER_RESPONSE_BYTES,
        )?
    };

    crate::controller_recovery::quarantine_confirmed_abort(
        root,
        &request,
        request_artifact,
        &abort_request,
        abort_request_artifact,
        &receipt_artifact,
    )?;

    let state = session.read_state().map_err(AppError::operational)?;
    let state = if state.status == SessionStatus::Failed {
        state
    } else {
        session
            .transition(
                &lock,
                SessionStatus::Failed,
                Some(SessionError {
                    code: "CONTROLLER_ABORT_CONFIRMED".to_owned(),
                    message: "trusted single-tenant caller confirmed successful unbound abort_practice_skill result"
                        .to_owned(),
                    details: Default::default(),
                }),
            )
            .map_err(AppError::operational)?
    };
    success(
        "controller.confirm-abort",
        json!({
            "session_id": session.id().as_str(),
            "state": state.status,
            "transaction_id": transaction_id,
            "abort_request_artifact": abort_request_artifact,
            "abort_receipt_artifact": receipt_artifact,
            "acknowledgement": "unbound_single_tenant_tool_success",
            "root_slot_released": false,
            "target_quarantined": true,
        }),
    )
}

pub fn status(root: &ArtifactRoot, session_id: &str) -> Result<CommandOutcome, AppError> {
    let session = open_session(root, session_id)?;
    let state = session.read_state().map_err(AppError::operational)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    let progress = controller_progress_from_artifacts(Some(root), &session, &artifacts)?;
    let mut transactions = controller_transaction_ids(&artifacts);
    let total = transactions.len();
    transactions.truncate(MAX_STATUS_TRANSACTIONS);
    let reported = transactions
        .into_iter()
        .map(|transaction| {
            json!({
                "transaction_id": transaction,
                "request_artifact_id": request_artifact_id(&transaction),
                "response_artifact_id": find_artifact(&artifacts, &response_artifact_id(&transaction)).map(|artifact| artifact.id.clone()),
                "abort_request_artifact_id": find_artifact(&artifacts, &abort_artifact_id(&transaction)).map(|artifact| artifact.id.clone()),
                "abort_receipt_artifact_id": find_artifact(&artifacts, &abort_receipt_artifact_id(&transaction)).map(|artifact| artifact.id.clone()),
                "pending": find_artifact(&artifacts, &response_artifact_id(&transaction)).is_none()
                    && find_artifact(&artifacts, &abort_receipt_artifact_id(&transaction)).is_none(),
            })
        })
        .collect::<Vec<_>>();
    success(
        "controller.status",
        json!({
            "session_id": session.id().as_str(),
            "state": state.status,
            "capture_phase": progress.phase.as_str(),
            "next_required_operation": progress.phase.expected_operation(),
            "completed_operations": progress.completed_operations,
            "pending_operation": progress.pending.as_ref().map(|(_, operation)| operation),
            "transaction_count": total,
            "reported_transaction_count": reported.len(),
            "transactions_truncated": total > reported.len(),
            "transactions": reported,
        }),
    )
}

pub fn ensure_no_pending_transaction(
    root: &ArtifactRoot,
    session: &Session,
) -> Result<(), AppError> {
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    if let Some(transaction) = pending_transactions(root, session, &artifacts)?
        .into_iter()
        .next()
    {
        return Err(AppError {
            code: "CONTROLLER_TRANSACTION_PENDING",
            message: format!(
                "session `{}` cannot mutate while controller transaction `{transaction}` awaits an accepted response or confirmed abort",
                session.id()
            ),
            details: json!({
                "session_id": session.id().as_str(),
                "transaction_id": transaction,
                "root_slot_released": false,
            }),
            exit_code: EXIT_OPERATIONAL,
        });
    }
    Ok(())
}

/// Prevents maintenance relocation from discarding the durable evidence that
/// owns the single TRACE32 endpoint. A nonterminal controller capture remains
/// leased until its fixed Cleanup response is accepted. A failed transaction
/// remains pending unless its abort is terminal and durably quarantined.
pub fn ensure_controller_session_releasable(
    root: &ArtifactRoot,
    session: &Session,
) -> Result<(), AppError> {
    ensure_no_pending_transaction(root, session)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    let has_controller_artifacts = artifacts.iter().any(|artifact| {
        artifact.id.starts_with(CONTROLLER_ARTIFACT_ID_PREFIX)
            || artifact
                .relative_path
                .as_str()
                .starts_with(CONTROLLER_ARTIFACT_PATH_PREFIX)
    });
    if !has_controller_artifacts {
        return Ok(());
    }
    let state = session.read_state().map_err(AppError::operational)?;
    if state.status == SessionStatus::Failed {
        return Ok(());
    }
    let progress = controller_progress_from_artifacts(Some(root), session, &artifacts)?;
    if progress.phase != ControllerCapturePhase::Complete {
        return Err(AppError {
            code: "CONTROLLER_CAPTURE_LEASE_ACTIVE",
            message: format!(
                "session `{}` still owns the TRACE32 endpoint until cleanup completes",
                session.id()
            ),
            details: json!({
                "session_id": session.id().as_str(),
                "capture_phase": progress.phase.as_str(),
                "root_slot_released": false,
            }),
            exit_code: EXIT_OPERATIONAL,
        });
    }
    Ok(())
}

fn prepare_output(
    session: &Session,
    lock: &SessionLock,
    operation: PerfOperation,
    mode: Option<&str>,
    transaction_id: &str,
) -> Result<Option<ControllerOutputReservation>, AppError> {
    if operation == PerfOperation::GetHotspots {
        return Ok(None);
    }
    let (role, suffix, kind, media_type, max_bytes, destination) = match operation {
        PerfOperation::Export => {
            let suffix = match mode.expect("export mode checked") {
                "raw_ascii" => "trace32-ascii.txt",
                "task_events_elf_orti_verified" => "trace32-task-events.txt",
                _ => unreachable!("export mode checked"),
            };
            (
                ControllerOutputRole::TraceExport,
                suffix.to_owned(),
                "raw_trace",
                "text/plain",
                session.limits().max_file_bytes,
                format!("capture/raw/controller-{transaction_id}.{suffix}"),
            )
        }
        operation => {
            let suffix = format!("{}.evidence.json", operation.as_str());
            (
                ControllerOutputRole::MachineEvidence,
                suffix.clone(),
                "trace32_control_evidence",
                "application/json",
                MAX_CONTROLLER_EVIDENCE_BYTES.min(session.limits().max_file_bytes),
                format!("capture/control/controller-{transaction_id}.{suffix}"),
            )
        }
    };
    let staged_relative_path = ArtifactPath::new(format!("controller/{transaction_id}.{suffix}"))
        .map_err(AppError::operational)?;
    let absolute = session
        .prepare_staging_path(lock, &staged_relative_path)
        .map_err(AppError::operational)?;
    ensure_unallocated(&absolute, "TRACE32 export")?;
    let script_output_path = practice_output_path(&absolute)?;
    let reservation = ControllerOutputReservation {
        role,
        staged_relative_path,
        script_output_path,
        artifact_id: output_artifact_id(transaction_id),
        destination_relative_path: ArtifactPath::new(destination).map_err(AppError::operational)?,
        kind: kind.to_owned(),
        media_type: media_type.to_owned(),
        producer: CONTROLLER_PRODUCER.to_owned(),
        max_bytes,
    };
    Ok(Some(reservation))
}

/// Converts the controller-owned V1 reservation shape into the closed V2
/// slots, allocating the additional custom-event destination only for the
/// admitted V2 adapter.  The trace slot deliberately retains the V1 path and
/// artifact identity so existing trace consumers do not need a migration.
fn prepare_v2_outputs(
    session: &Session,
    lock: &SessionLock,
    operation: PerfOperation,
    transaction_id: &str,
    output: Option<&ControllerOutputReservation>,
    target_adapter: Option<&ControllerTargetAdapterBinding>,
) -> Result<Vec<ControllerOutputReservationV2>, AppError> {
    let output = output.ok_or_else(|| {
        AppError::operational("V2 controller request requires a primary output reservation")
    })?;
    let role = match output.role {
        ControllerOutputRole::TraceExport => ControllerOutputRoleV2::TraceExport,
        ControllerOutputRole::MachineEvidence => ControllerOutputRoleV2::MachineEvidence,
    };
    let mut outputs = vec![ControllerOutputReservationV2 {
        role,
        staged_relative_path: output.staged_relative_path.clone(),
        script_output_path: output.script_output_path.clone(),
        artifact_id: output.artifact_id.clone(),
        destination_relative_path: output.destination_relative_path.clone(),
        kind: output.kind.clone(),
        media_type: output.media_type.clone(),
        producer: output.producer.clone(),
        max_bytes: output.max_bytes,
    }];
    if operation != PerfOperation::Export {
        return Ok(outputs);
    }
    let collector = target_adapter
        .and_then(|adapter| adapter.custom_event_collector.as_ref())
        .ok_or_else(|| {
            AppError::operational("V2 export requires the admitted custom-event collector")
        })?;
    let staged_relative_path =
        ArtifactPath::new(format!("controller/{transaction_id}.custom-events.bin"))
            .map_err(AppError::operational)?;
    let absolute = session
        .prepare_staging_path(lock, &staged_relative_path)
        .map_err(AppError::operational)?;
    ensure_unallocated(&absolute, "controller custom-event export")?;
    let script_output_path = practice_output_path(&absolute)?;
    outputs.push(ControllerOutputReservationV2 {
        role: ControllerOutputRoleV2::CustomEvents,
        staged_relative_path,
        script_output_path,
        artifact_id: custom_event_output_artifact_id(transaction_id),
        destination_relative_path: ArtifactPath::new(format!(
            "capture/raw/controller-{transaction_id}.custom-events.bin"
        ))
        .map_err(AppError::operational)?,
        kind: "custom_events".to_owned(),
        media_type: "application/octet-stream".to_owned(),
        producer: CONTROLLER_PRODUCER.to_owned(),
        max_bytes: collector.max_output_bytes,
    });
    Ok(outputs)
}

/// Converts the host filesystem spelling into the portable PRACTICE argument
/// spelling.  Session ownership remains checked against the native path, but
/// TRACE32 contracts always carry forward-slash paths even on Windows.
fn practice_output_path(path: &std::path::Path) -> Result<String, AppError> {
    let mut value = path
        .to_str()
        .ok_or_else(|| AppError::operational("controller output path is not UTF-8"))?
        .replace('\\', "/");
    // Windows APIs may expose an extended-length `\\?\` filesystem spelling.
    // It is not a portable PRACTICE path; remove only that local-path prefix
    // before enforcing the forward-slash contract.
    if let Some(stripped) = value.strip_prefix("//?/") {
        value = stripped.to_owned();
    }
    if value.is_empty() || value.contains("//") {
        return Err(AppError::operational(
            "controller output path is not a portable PRACTICE path",
        ));
    }
    Ok(value)
}

fn validate_mode(operation: PerfOperation, mode: Option<&str>) -> Result<(), AppError> {
    match (operation, mode) {
        (PerfOperation::Export, Some("raw_ascii" | "task_events_elf_orti_verified")) => Ok(()),
        (PerfOperation::Export, Some(mode)) => Err(AppError::operational(format!(
            "unsupported fixed export mode `{mode}`"
        ))),
        (PerfOperation::Export, None) => Err(AppError::operational(
            "perf_export requires the exact export mode selected by the admitted adapter",
        )),
        (_, None) => Ok(()),
        (_, Some(_)) => Err(AppError::operational(
            "--mode is accepted only for perf_export",
        )),
    }
}

fn validate_request_context(
    session: &Session,
    request_artifact: &Artifact,
    request: &ControllerRequest,
    transaction_id: &str,
) -> Result<(), AppError> {
    request.validate().map_err(AppError::operational)?;
    let session_artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    let admission =
        controller_request_admission_context(session, &session_artifacts, request.operation)?;
    if request.adapter_catalog_sha256
        != admission.catalog.digest().map_err(AppError::operational)?
    {
        return Err(AppError::operational(
            "immutable controller request is not bound to its operation-specific adapter catalog",
        ));
    }
    let expected_inputs = controller_request_inputs(
        &request.firmware_image,
        &admission.provenance,
        admission.selection_artifact.as_ref(),
    );
    if request_artifact.input_artifact_ids != expected_inputs {
        return Err(AppError::operational(
            "controller request artifact inputs do not bind the Session admission provenance",
        ));
    }
    if let Some(binding) = &request.target_adapter {
        let admitted = admission.catalog.get(&binding.adapter_id).ok_or_else(|| {
            AppError::operational("controller request selected an adapter absent from the catalog")
        })?;
        if binding != &target_adapter_binding(admitted, binding.scenario)? {
            return Err(AppError::operational(
                "immutable controller request is not bound to the selected profile and executable bundle",
            ));
        }
    }
    let state = session.read_state().map_err(AppError::operational)?;
    let request_sha256 = session.request_sha256().map_err(AppError::operational)?;
    if request.binding.session_id != session.id().as_str()
        || request.binding.session_operation_id != state.operation_id
        || request.binding.session_request_sha256 != request_sha256
        || request.binding.transaction_id != transaction_id
        || request_artifact.id != request_artifact_id(transaction_id)
        || request_artifact.relative_path != request_artifact_path(transaction_id)?
        || request_artifact.kind != CONTROLLER_REQUEST_KIND
        || request_artifact.producer != CONTROLLER_PRODUCER
    {
        return Err(AppError::operational(
            "immutable controller request does not match its Session, operation, request digest, transaction, or artifact identity",
        ));
    }
    let expected_response =
        ArtifactPath::new(format!("controller/{transaction_id}.mcp-response.txt"))
            .map_err(AppError::operational)?;
    if request.response_staging_path != expected_response {
        return Err(AppError::operational(
            "controller response staging reservation does not match its transaction",
        ));
    }
    if let Some(output) = &request.output {
        let expected_absolute = session
            .staging_path(&output.staged_relative_path)
            .map_err(AppError::operational)?;
        if practice_output_path(&expected_absolute)? != output.script_output_path
            || output.artifact_id != output_artifact_id(transaction_id)
        {
            return Err(AppError::operational(
                "controller export reservation does not match its Session-owned path",
            ));
        }
    }
    Ok(())
}

fn validate_request_context_envelope(
    session: &Session,
    request_artifact: &Artifact,
    request: &ControllerRequestEnvelope,
    transaction_id: &str,
) -> Result<(), AppError> {
    if let ControllerRequestEnvelope::V1(request) = request {
        return validate_request_context(session, request_artifact, request, transaction_id);
    }
    let session_artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    let admission =
        controller_request_admission_context(session, &session_artifacts, request.operation())?;
    if request.adapter_catalog_sha256()
        != &admission.catalog.digest().map_err(AppError::operational)?
    {
        return Err(AppError::operational(
            "immutable controller request is not bound to its operation-specific adapter catalog",
        ));
    }
    let expected_inputs = controller_request_inputs(
        request.firmware_image(),
        &admission.provenance,
        admission.selection_artifact.as_ref(),
    );
    if request_artifact.input_artifact_ids != expected_inputs {
        return Err(AppError::operational(
            "controller request artifact inputs do not bind the Session admission provenance",
        ));
    }
    if let Some(binding) = request.target_adapter() {
        let admitted = admission.catalog.get(&binding.adapter_id).ok_or_else(|| {
            AppError::operational("controller request selected an adapter absent from the catalog")
        })?;
        if binding != &target_adapter_binding(admitted, binding.scenario)? {
            return Err(AppError::operational(
                "immutable controller request is not bound to the selected profile and executable bundle",
            ));
        }
    }
    let state = session.read_state().map_err(AppError::operational)?;
    let request_sha256 = session.request_sha256().map_err(AppError::operational)?;
    let binding = request.binding();
    if binding.session_id != session.id().as_str()
        || binding.session_operation_id != state.operation_id
        || binding.session_request_sha256 != request_sha256
        || binding.transaction_id != transaction_id
        || request_artifact.id != request_artifact_id(transaction_id)
        || request_artifact.relative_path != request_artifact_path(transaction_id)?
        || request_artifact.kind != CONTROLLER_REQUEST_KIND
        || request_artifact.producer != CONTROLLER_PRODUCER
    {
        return Err(AppError::operational(
            "immutable controller request does not match its Session, operation, request digest, transaction, or artifact identity",
        ));
    }
    let expected_response =
        ArtifactPath::new(format!("controller/{transaction_id}.mcp-response.txt"))
            .map_err(AppError::operational)?;
    if request.response_staging_path() != &expected_response {
        return Err(AppError::operational(
            "controller response staging reservation does not match its transaction",
        ));
    }
    if let ControllerRequestEnvelope::V2(request) = request {
        validate_v2_output_reservations(session, request, transaction_id)?;
        for output in &request.outputs {
            let expected_absolute = session
                .staging_path(&output.staged_relative_path)
                .map_err(AppError::operational)?;
            if practice_output_path(&expected_absolute)? != output.script_output_path {
                return Err(AppError::operational(
                    "controller V2 output reservation does not match its Session-owned path",
                ));
            }
        }
        match (request.operation, request.outputs.as_slice()) {
            (PerfOperation::Export, [trace, custom])
                if trace.role == ControllerOutputRoleV2::TraceExport
                    && trace.artifact_id == output_artifact_id(transaction_id)
                    && custom.role == ControllerOutputRoleV2::CustomEvents
                    && custom.artifact_id == custom_event_output_artifact_id(transaction_id)
                    && custom.staged_relative_path.as_str()
                        == format!("controller/{transaction_id}.custom-events.bin")
                    && custom.destination_relative_path.as_str()
                        == format!("capture/raw/controller-{transaction_id}.custom-events.bin")
                    && custom.kind == "custom_events"
                    && custom.media_type == "application/octet-stream"
                    && custom.producer == CONTROLLER_PRODUCER => {}
            (PerfOperation::Export, _) => {
                return Err(AppError::operational(
                    "V2 export does not retain the fixed trace/custom-event output envelopes",
                ));
            }
            (_, [evidence])
                if evidence.role == ControllerOutputRoleV2::MachineEvidence
                    && evidence.artifact_id == output_artifact_id(transaction_id) => {}
            _ => {
                return Err(AppError::operational(
                    "V2 non-export request does not retain its machine-evidence output envelope",
                ));
            }
        }
    }
    Ok(())
}

fn validate_v2_output_reservations(
    session: &Session,
    request: &ControllerRequestV2,
    transaction_id: &str,
) -> Result<(), AppError> {
    let expected = |role: ControllerOutputRoleV2,
                    suffix: String,
                    kind: &str,
                    media: &str,
                    max: u64,
                    destination: String| {
        let staged = ArtifactPath::new(format!("controller/{transaction_id}.{suffix}"))
            .map_err(AppError::operational)?;
        Ok::<_, AppError>((
            role,
            staged.clone(),
            practice_output_path(
                &session
                    .staging_path(&staged)
                    .map_err(AppError::operational)?,
            )?,
            ArtifactPath::new(destination).map_err(AppError::operational)?,
            kind.to_owned(),
            media.to_owned(),
            max,
        ))
    };
    let expected_slots = match request.operation {
        PerfOperation::Export => {
            let adapter = request
                .target_adapter
                .as_ref()
                .ok_or_else(|| AppError::operational("V2 export has no adapter"))?;
            let suffix = match adapter.capture_kind {
                TargetAdapterCaptureKind::Sampling { .. } => "trace32-ascii.txt",
                TargetAdapterCaptureKind::ProgramFlowTaskEvents { .. } => "trace32-task-events.txt",
            };
            let collector = adapter
                .custom_event_collector
                .as_ref()
                .ok_or_else(|| AppError::operational("V2 export has no collector"))?;
            vec![
                expected(
                    ControllerOutputRoleV2::TraceExport,
                    suffix.to_owned(),
                    "raw_trace",
                    "text/plain",
                    session.limits().max_file_bytes,
                    format!("capture/raw/controller-{transaction_id}.{suffix}"),
                )?,
                expected(
                    ControllerOutputRoleV2::CustomEvents,
                    "custom-events.bin".to_owned(),
                    "custom_events",
                    "application/octet-stream",
                    collector.max_output_bytes,
                    format!("capture/raw/controller-{transaction_id}.custom-events.bin"),
                )?,
            ]
        }
        operation => {
            let suffix = format!("{}.evidence.json", operation.as_str());
            vec![expected(
                ControllerOutputRoleV2::MachineEvidence,
                suffix.clone(),
                "trace32_control_evidence",
                "application/json",
                MAX_CONTROLLER_EVIDENCE_BYTES.min(session.limits().max_file_bytes),
                format!("capture/control/controller-{transaction_id}.{suffix}"),
            )?]
        }
    };
    if request.outputs.len() != expected_slots.len() {
        return Err(AppError::operational(
            "V2 output slot count does not match host reservation",
        ));
    }
    for (slot, (role, staged, script, destination, kind, media, max)) in
        request.outputs.iter().zip(expected_slots)
    {
        if slot.role != role
            || slot.staged_relative_path != staged
            || slot.script_output_path != script
            || slot.destination_relative_path != destination
            || slot.kind != kind
            || slot.media_type != media
            || slot.producer != CONTROLLER_PRODUCER
            || slot.max_bytes != max
            || slot.artifact_id
                != if role == ControllerOutputRoleV2::CustomEvents {
                    custom_event_output_artifact_id(transaction_id)
                } else {
                    output_artifact_id(transaction_id)
                }
        {
            return Err(AppError::operational(
                "V2 output reservation does not match its host-owned envelope",
            ));
        }
    }
    Ok(())
}

fn driver_request<'a>(
    session: &Session,
    artifacts: &'a [Artifact],
    transaction_id: &str,
) -> Result<(&'a Artifact, ControllerRequestEnvelope), AppError> {
    let request_artifact = find_required_artifact(
        artifacts,
        &request_artifact_id(transaction_id),
        CONTROLLER_REQUEST_KIND,
    )?;
    let request = read_controller_request_envelope(session, request_artifact)?;
    validate_request_context_envelope(session, request_artifact, &request, transaction_id)?;
    Ok((request_artifact, request))
}

fn driver_accepted_response(
    session: &Session,
    artifacts: &[Artifact],
    request_artifact: &Artifact,
    request: &ControllerRequestEnvelope,
) -> Result<bool, AppError> {
    let Some(response_artifact) = find_artifact(
        artifacts,
        &response_artifact_id(&request.binding().transaction_id),
    ) else {
        return Ok(false);
    };
    let response = read_controller_response_envelope(session, response_artifact)?;
    validate_response(session, request_artifact, request, &response)?;
    validate_response_artifact_identity(response_artifact, &response)?;
    Ok(true)
}

fn ensure_driver_transaction_ownership(
    root: &ArtifactRoot,
    session: &Session,
    transaction_id: &str,
) -> Result<(), AppError> {
    match root_active_transaction(root)? {
        Some((owner_session, owner_transaction))
            if owner_session == session.id().as_str() && owner_transaction == transaction_id =>
        {
            Ok(())
        }
        Some((owner_session, owner_transaction)) => Err(AppError {
            code: "CONTROLLER_TRANSACTION_OWNERSHIP_MISMATCH",
            message: "driver transaction does not own the active root-wide t32mcp slot".to_owned(),
            details: json!({
                "requested_session_id": session.id().as_str(),
                "requested_transaction_id": transaction_id,
                "owner_session_id": owner_session,
                "owner_transaction_id": owner_transaction,
            }),
            exit_code: EXIT_OPERATIONAL,
        }),
        None => Err(AppError::operational(
            "driver transaction no longer owns an active root-wide t32mcp slot",
        )),
    }
}

fn staged_response_exists(
    session: &Session,
    request: &ControllerRequestEnvelope,
) -> Result<bool, AppError> {
    let path = session
        .staging_path(request.response_staging_path())
        .map_err(AppError::operational)?;
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            session
                .read_staged_bounded(
                    request.response_staging_path(),
                    request.max_response_bytes(),
                )
                .map_err(AppError::operational)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(AppError::operational(error)),
    }
}

fn start_artifact_transaction_id(
    session: &Session,
    artifacts: &[Artifact],
    start_evidence_artifact: &Artifact,
) -> Result<String, AppError> {
    let mut transaction = None;
    for candidate in controller_transaction_ids(artifacts) {
        let request_artifact = find_required_artifact(
            artifacts,
            &request_artifact_id(&candidate),
            CONTROLLER_REQUEST_KIND,
        )?;
        let request = read_controller_request_envelope(session, request_artifact)?;
        validate_request_context_envelope(session, request_artifact, &request, &candidate)?;
        let Some(response_artifact) = find_artifact(artifacts, &response_artifact_id(&candidate))
        else {
            continue;
        };
        let response = read_controller_response_envelope(session, response_artifact)?;
        validate_response(session, request_artifact, &request, &response)?;
        validate_response_artifact_identity(response_artifact, &response)?;
        if response
            .output_artifacts()
            .into_iter()
            .any(|artifact| artifact == start_evidence_artifact)
            && transaction.replace(candidate).is_some()
        {
            return Err(AppError::operational(
                "accepted StartV2 evidence is referenced by more than one controller response",
            ));
        }
    }
    transaction.ok_or_else(|| {
        AppError::operational("accepted StartV2 evidence has no immutable controller response")
    })
}

struct CapabilitiesView<'a> {
    capture_modes: &'a [String],
    trace_sinks: &'a [String],
    covered_cores: &'a [u32],
    timestamp_supported: bool,
    initial_target_state: Option<ControllerTargetState>,
}

fn capabilities_view(evidence: &ControllerEvidence) -> Result<CapabilitiesView<'_>, AppError> {
    match evidence {
        ControllerEvidence::Capabilities(value) => Ok(CapabilitiesView {
            capture_modes: &value.capture_modes,
            trace_sinks: &value.trace_sinks,
            covered_cores: &value.covered_cores,
            timestamp_supported: value.timestamp_supported,
            initial_target_state: None,
        }),
        ControllerEvidence::CapabilitiesV2(value) => Ok(CapabilitiesView {
            capture_modes: &value.capture_modes,
            trace_sinks: &value.trace_sinks,
            covered_cores: &value.covered_cores,
            timestamp_supported: value.timestamp_supported,
            initial_target_state: Some(value.initial_target_state),
        }),
        _ => Err(AppError::operational(
            "controller evidence is not a capabilities document",
        )),
    }
}

fn target_adapter_selection_from_capabilities(
    evidence: &ControllerEvidence,
    admission_profile: &TargetAdapterProfile,
) -> Result<TargetAdapterSelection, AppError> {
    let discriminator = Some(TargetAdapterSelectionDiscriminator {
        adapter_id: admission_profile.adapter_id.clone(),
        profile_sha256: admission_profile.digest().map_err(AppError::operational)?,
    });
    match evidence {
        ControllerEvidence::Capabilities(value) => Ok(TargetAdapterSelection {
            trace32_release: value.trace32_release.clone(),
            trace32_build: value.trace32_build,
            architecture_package: value.architecture_package.clone(),
            target_identifier: value.target_identifier.clone(),
            probe_identifier: value.probe_identifier.clone(),
            discriminator,
        }),
        ControllerEvidence::CapabilitiesV2(value) => Ok(TargetAdapterSelection {
            trace32_release: value.trace32_release.clone(),
            trace32_build: value.trace32_build,
            architecture_package: value.architecture_package.clone(),
            target_identifier: value.target_identifier.clone(),
            probe_identifier: value.probe_identifier.clone(),
            discriminator,
        }),
        _ => Err(AppError::operational(
            "target-adapter selection requires capabilities evidence",
        )),
    }
}

const fn controller_target_state_name(state: ControllerTargetState) -> &'static str {
    match state {
        ControllerTargetState::Running => "running",
        ControllerTargetState::Halted => "halted",
    }
}

fn controller_request_admission_context(
    session: &Session,
    artifacts: &[Artifact],
    operation: PerfOperation,
) -> Result<ControllerRequestAdmissionContext, AppError> {
    if !operation_uses_target_adapter(operation) {
        return Ok(ControllerRequestAdmissionContext {
            catalog: crate::controller_qualification::compiled_candidate_admission_catalog()?,
            provenance: Vec::new(),
            selected_scenario: None,
            selection_artifact: None,
        });
    }

    let (profile, catalog, provenance, allowed_scenarios) =
        crate::controller_qualification::load_session_admission(session, artifacts)?;
    let (selected_scenario, selection_artifact) = selected_target_adapter_scenario(
        session,
        artifacts,
        &profile,
        &provenance,
        &allowed_scenarios,
    )?;
    Ok(ControllerRequestAdmissionContext {
        catalog,
        provenance,
        selected_scenario: Some(selected_scenario),
        selection_artifact,
    })
}

fn selected_target_adapter_scenario(
    session: &Session,
    artifacts: &[Artifact],
    admission_profile: &TargetAdapterProfile,
    admission_provenance: &[Artifact],
    allowed: &[TargetAdapterScenario],
) -> Result<(TargetAdapterScenario, Option<Artifact>), AppError> {
    let admitted_scenarios = if admission_provenance.is_empty() {
        admission_profile
            .scenarios
            .iter()
            .map(|contract| contract.scenario)
            .collect::<Vec<_>>()
    } else {
        allowed.to_vec()
    };
    let Some(artifact) = artifacts
        .iter()
        .find(|artifact| artifact.id == TARGET_ADAPTER_SCENARIO_ARTIFACT_ID)
    else {
        if !admitted_scenarios.contains(&TargetAdapterScenario::Normal) {
            return Err(AppError::operational(
                "Session admission does not authorize the required default normal scenario",
            ));
        }
        return Ok((TargetAdapterScenario::Normal, None));
    };
    if artifact.kind != TARGET_ADAPTER_SCENARIO_KIND
        || artifact.relative_path.as_str() != TARGET_ADAPTER_SCENARIO_PATH
        || artifact.media_type != "application/json"
        || artifact.producer != TARGET_ADAPTER_SCENARIO_PRODUCER
    {
        return Err(AppError::operational(
            "target-adapter scenario artifact has an invalid reserved identity",
        ));
    }
    let selection = parse_target_adapter_scenario_selection(&read_bounded_bytes_artifact(
        session,
        artifact,
        MAX_CONTROLLER_EVIDENCE_BYTES,
    )?)
    .map_err(AppError::operational)?;
    selection
        .validate_for_allowed(&admitted_scenarios)
        .map_err(AppError::operational)?;
    let expected_inputs = if admission_provenance.is_empty() {
        vec![FIRMWARE_ELF_ARTIFACT_ID.to_owned()]
    } else {
        admission_provenance
            .iter()
            .map(|artifact| artifact.id.clone())
            .collect()
    };
    if artifact.input_artifact_ids != expected_inputs
        || selection.evidence_only != admission_provenance.is_empty()
    {
        return Err(AppError::operational(
            "target-adapter scenario artifact provenance or evidence-only claim is invalid",
        ));
    }
    Ok((selection.scenario, Some(artifact.clone())))
}

fn target_adapter_binding(
    admitted: &AdmittedTargetAdapter,
    scenario: TargetAdapterScenario,
) -> Result<ControllerTargetAdapterBinding, AppError> {
    let profile = &admitted.profile;
    let capture_kind = profile
        .scenario(scenario)
        .ok_or_else(|| AppError::operational("selected target-adapter scenario disappeared"))?
        .capture
        .capture_kind
        .clone();
    Ok(ControllerTargetAdapterBinding {
        adapter_id: profile.adapter_id.clone(),
        adapter_version: profile.adapter_version.clone(),
        trace32_release: profile.build_gate.trace32_release.clone(),
        trace32_build: profile.build_gate.minimum_build,
        architecture_package: profile.build_gate.architecture_package.clone(),
        target_identifier: profile.target_identifier.clone(),
        probe_identifier: profile.probe_identifier.clone(),
        profile_sha256: profile.digest().map_err(AppError::operational)?,
        implementation_sha256: profile.implementation_sha256.clone(),
        scenario,
        capture_kind,
        controller_protocol: profile.controller_protocol,
        custom_event_collector: profile.custom_event_collector.clone(),
        qualification_sha256: profile.qualification_sha256.clone(),
    })
}

/// Rebuilds the exact admitted target profile for a persisted controller
/// binding. Recovery uses this rather than any compiled default profile.
pub(crate) fn admitted_profile_for_binding(
    session: &Session,
    artifacts: &[Artifact],
    binding: &ControllerTargetAdapterBinding,
) -> Result<TargetAdapterProfile, AppError> {
    let (_, catalog, _, _) =
        crate::controller_qualification::load_session_admission(session, artifacts)?;
    let admitted = catalog.get(&binding.adapter_id).ok_or_else(|| {
        AppError::operational(
            "failed controller binding adapter is absent from its admission catalog",
        )
    })?;
    let expected = target_adapter_binding(admitted, binding.scenario)?;
    if binding != &expected {
        return Err(AppError::operational(
            "failed controller binding does not match its exact admitted target profile",
        ));
    }
    Ok(admitted.profile.clone())
}

fn selected_target_adapter_binding(
    session: &Session,
    artifacts: &[Artifact],
    progress: &ControllerProgress,
    catalog: &TargetAdapterAdmissionCatalog,
) -> Result<ControllerTargetAdapterBinding, AppError> {
    let (_, capabilities) =
        accepted_controller_evidence(session, artifacts, progress, PerfOperation::GetCapabilities)?
            .ok_or_else(|| {
                AppError::operational("target-adapter selection requires capabilities evidence")
            })?;
    let (admission_profile, _, admission_provenance, allowed_scenarios) =
        crate::controller_qualification::load_session_admission(session, artifacts)?;
    let selection = target_adapter_selection_from_capabilities(&capabilities, &admission_profile)?;
    let admitted = catalog.select(&selection).map_err(AppError::operational)?;
    let (scenario, _) = selected_target_adapter_scenario(
        session,
        artifacts,
        &admission_profile,
        &admission_provenance,
        &allowed_scenarios,
    )?;
    target_adapter_binding(admitted, scenario)
}

/// Returns the one export mode owned by the admitted profile/scenario.
pub(crate) fn selected_capture_export_mode(
    root: &ArtifactRoot,
    session_id: &str,
) -> Result<&'static str, AppError> {
    let session = open_session(root, session_id)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    let (profile, _, admission_provenance, allowed_scenarios) =
        crate::controller_qualification::load_session_admission(&session, &artifacts)?;
    let (scenario, _) = selected_target_adapter_scenario(
        &session,
        &artifacts,
        &profile,
        &admission_provenance,
        &allowed_scenarios,
    )?;
    let capture_kind = &profile
        .scenario(scenario)
        .ok_or_else(|| AppError::operational("selected target-adapter scenario disappeared"))?
        .capture
        .capture_kind;
    Ok(match capture_kind {
        TargetAdapterCaptureKind::Sampling { .. } => "raw_ascii",
        TargetAdapterCaptureKind::ProgramFlowTaskEvents { .. } => "task_events_elf_orti_verified",
    })
}

pub(crate) fn validate_quarantined_target_recovery(
    root: &ArtifactRoot,
    claims: QuarantinedTargetRecoveryClaims<'_>,
    evidence: &TargetAdapterRecoveryEvidence,
) -> Result<(), AppError> {
    let QuarantinedTargetRecoveryClaims {
        failed_session_id,
        failed_session_operation_id,
        failed_transaction_id,
        failed_operation,
        failed_binding_sha256,
        request_artifact_id: request_artifact_id_value,
        request_artifact_sha256,
        abort_request_artifact_id: abort_request_artifact_id_value,
        abort_request_artifact_sha256,
        abort_receipt_artifact_id: abort_receipt_artifact_id_value,
        abort_receipt_artifact_sha256,
        target_adapter,
        recovery_scenario,
    } = claims;
    let session = open_session(root, failed_session_id)?;
    let state = session.read_state().map_err(AppError::operational)?;
    if state.operation_id != failed_session_operation_id || state.status != SessionStatus::Failed {
        return Err(AppError::operational(
            "target recovery does not name the terminal failed Session operation",
        ));
    }
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    let request_artifact = find_required_artifact(
        &artifacts,
        request_artifact_id_value,
        CONTROLLER_REQUEST_KIND,
    )?;
    if &request_artifact.sha256 != request_artifact_sha256
        || request_artifact.id != request_artifact_id(failed_transaction_id)
    {
        return Err(AppError::operational(
            "target recovery request artifact claim is invalid",
        ));
    }
    let request = read_controller_request_envelope(&session, request_artifact)?;
    validate_request_context_envelope(&session, request_artifact, &request, failed_transaction_id)?;
    if request.operation() != failed_operation
        || &request.binding().binding_sha256 != failed_binding_sha256
        || request.target_adapter() != Some(target_adapter)
    {
        return Err(AppError::operational(
            "target recovery is not bound to the failed controller request",
        ));
    }
    let abort_request_artifact = find_required_artifact(
        &artifacts,
        abort_request_artifact_id_value,
        CONTROLLER_ABORT_REQUEST_KIND,
    )?;
    if &abort_request_artifact.sha256 != abort_request_artifact_sha256
        || abort_request_artifact.id != abort_artifact_id(failed_transaction_id)
    {
        return Err(AppError::operational(
            "target recovery abort-request artifact claim is invalid",
        ));
    }
    let abort_request: ControllerAbortRequest = read_bounded_json_artifact(
        &session,
        abort_request_artifact,
        MAX_CONTROLLER_REQUEST_BYTES,
    )?;
    let abort_receipt_artifact = find_required_artifact(
        &artifacts,
        abort_receipt_artifact_id_value,
        CONTROLLER_ABORT_RECEIPT_KIND,
    )?;
    if &abort_receipt_artifact.sha256 != abort_receipt_artifact_sha256
        || abort_receipt_artifact.id != abort_receipt_artifact_id(failed_transaction_id)
    {
        return Err(AppError::operational(
            "target recovery abort-receipt artifact claim is invalid",
        ));
    }
    let abort_receipt: ControllerAbortReceipt = read_bounded_json_artifact(
        &session,
        abort_receipt_artifact,
        MAX_CONTROLLER_RESPONSE_BYTES,
    )?;
    validate_abort_receipt_envelope(
        &request,
        request_artifact,
        &abort_request,
        abort_request_artifact,
        &abort_receipt,
    )?;
    if evidence.upstream_abort_receipt_sha256.as_ref() != Some(abort_receipt_artifact_sha256) {
        return Err(AppError::operational(
            "target recovery evidence is not bound to the immutable abort receipt",
        ));
    }

    let profile = admitted_profile_for_binding(&session, &artifacts, target_adapter)?;
    let failure_kind = match recovery_scenario {
        TargetAdapterScenario::Normal => TargetAdapterFailureKind::OperationFailure,
        TargetAdapterScenario::CmmAbort => TargetAdapterFailureKind::CmmAbort,
        TargetAdapterScenario::Trace32Disconnect => TargetAdapterFailureKind::Trace32Disconnect,
        TargetAdapterScenario::DriverDisconnect => TargetAdapterFailureKind::DriverDisconnect,
        _ => {
            return Err(AppError::operational(
                "target recovery scenario is not an explicit interruption contract",
            ));
        }
    };
    let accepted = accepted_evidence_from_artifacts(&session, &artifacts)?;
    let configure = accepted
        .evidence
        .get(&PerfOperation::Configure)
        .and_then(|evidence| match evidence {
            ControllerEvidence::Configure(configure) => Some(configure),
            _ => None,
        });
    let capabilities_initial_target_state =
        match accepted.evidence.get(&PerfOperation::GetCapabilities) {
            Some(evidence) => capabilities_view(evidence)?.initial_target_state,
            None => None,
        };
    let observed_initial_target_state = if failed_operation == PerfOperation::Configure {
        capabilities_initial_target_state.ok_or_else(|| {
            AppError::operational(
                "configure recovery requires initial-state-bound capabilities evidence v2",
            )
        })?
    } else {
        configure
            .map(|configure| configure.initial_target_state)
            .ok_or_else(|| {
                AppError::operational("target recovery cannot prove the configured initial state")
            })?
    };
    let accepted_responses = accepted_script_responses_from_artifacts(&session, &artifacts)?;
    let mut run =
        TargetAdapterRun::new(&profile, recovery_scenario).map_err(AppError::operational)?;
    for operation in [
        PerfOperation::GetCapabilities,
        PerfOperation::Configure,
        PerfOperation::Start,
        PerfOperation::Stop,
        PerfOperation::GetHealth,
        PerfOperation::Export,
        PerfOperation::Cleanup,
    ] {
        if operation == failed_operation {
            break;
        }
        if operation == PerfOperation::Export {
            let response = accepted_responses.get(&operation).ok_or_else(|| {
                AppError::operational(
                    "target recovery replay is missing the accepted export response",
                )
            })?;
            run.accept_export(response).map_err(AppError::operational)?;
            continue;
        }
        if operation == PerfOperation::Cleanup {
            return Err(AppError::operational(
                "target recovery cannot replay a completed cleanup before its declared failure",
            ));
        }
        let step = accepted.evidence.get(&operation).ok_or_else(|| {
            AppError::operational(format!(
                "target recovery replay is missing accepted `{}` evidence",
                operation.as_str()
            ))
        })?;
        if operation == PerfOperation::Stop {
            let artifact = accepted.artifacts.get(&operation).ok_or_else(|| {
                AppError::operational(
                    "target recovery replay is missing the accepted Stop artifact binding",
                )
            })?;
            run.accept_evidence_artifact(step, &artifact.sha256)
                .map_err(AppError::operational)?;
        } else {
            run.accept_evidence(step).map_err(AppError::operational)?;
        }
    }
    if failure_kind == TargetAdapterFailureKind::OperationFailure {
        run.record_operation_failure(
            failed_operation,
            failed_binding_sha256.clone(),
            observed_initial_target_state,
        )
        .map_err(AppError::operational)?;
    } else {
        run.record_failure(
            failed_operation,
            failed_binding_sha256.clone(),
            failure_kind,
            observed_initial_target_state,
        )
        .map_err(AppError::operational)?;
    }
    run.accept_recovery(evidence).map_err(AppError::operational)
}

fn validate_response_v1(
    session: &Session,
    request_artifact: &Artifact,
    request: &ControllerRequest,
    response: &ControllerResponse,
) -> Result<(), AppError> {
    if request.requires_interruption() {
        return Err(AppError::operational(
            "a fault-action controller request cannot have an accepted final response",
        ));
    }
    response.binding.validate().map_err(AppError::operational)?;
    if response.binding != request.binding
        || response.request_artifact_id != request_artifact.id
        || response.request_artifact_sha256 != request_artifact.sha256
        || response.script_response.operation != request.operation
        || response.raw_response_artifact.id
            != raw_response_artifact_id(&request.binding.transaction_id)
        || response.raw_response_artifact.kind != CONTROLLER_RAW_RESPONSE_KIND
        || response.raw_response_artifact.relative_path
            != raw_response_artifact_path(&request.binding.transaction_id)?
        || response.raw_response_artifact.producer != CONTROLLER_PRODUCER
        || response.raw_response_artifact.input_artifact_ids != [request_artifact.id.clone()]
    {
        return Err(AppError::operational(
            "controller response is not bound to its immutable request",
        ));
    }
    session
        .verify_artifact(&response.raw_response_artifact, true)
        .map_err(AppError::operational)?;
    match (response.script_response.status, &response.output_artifact) {
        (PerfStatus::Ok, Some(output)) => {
            let reservation = request.output.as_ref().ok_or_else(|| {
                AppError::operational("successful controller response lacks an output reservation")
            })?;
            validate_output_artifact_identity(output, reservation, request_artifact)?;
            session
                .verify_artifact(output, true)
                .map_err(AppError::operational)?;
            if reservation.role == ControllerOutputRole::MachineEvidence {
                validate_evidence_artifact(session, request, output)?;
            }
        }
        (PerfStatus::Ok, None) => {
            return Err(AppError::operational(
                "successful target-control or export response is missing its output artifact",
            ));
        }
        (PerfStatus::HostProcessingRequired, None) => {
            if request.operation != PerfOperation::GetHotspots {
                return Err(AppError::operational(
                    "host-processing response is valid only for perf_get_hotspots",
                ));
            }
        }
        (PerfStatus::UnsupportedNeedsTrace32 | PerfStatus::InvalidArgument, None) => {}
        (_, Some(_)) => {
            return Err(AppError::operational(
                "non-successful controller response contains an output artifact",
            ));
        }
    }
    Ok(())
}

fn validate_response(
    session: &Session,
    request_artifact: &Artifact,
    request: &ControllerRequestEnvelope,
    response: &ControllerResponseEnvelope,
) -> Result<(), AppError> {
    match (request, response) {
        (ControllerRequestEnvelope::V1(request), ControllerResponseEnvelope::V1(response)) => {
            validate_response_v1(session, request_artifact, request, response)
        }
        (ControllerRequestEnvelope::V2(request), ControllerResponseEnvelope::V2(response)) => {
            response
                .validate_for(request, request_artifact)
                .map_err(AppError::operational)?;
            if response.raw_response_artifact.id
                != raw_response_artifact_id(&request.binding.transaction_id)
                || response.raw_response_artifact.kind != CONTROLLER_RAW_RESPONSE_KIND
                || response.raw_response_artifact.relative_path
                    != raw_response_artifact_path(&request.binding.transaction_id)?
                || response.raw_response_artifact.producer != CONTROLLER_PRODUCER
            {
                return Err(AppError::operational(
                    "controller V2 raw response artifact does not match its immutable request",
                ));
            }
            session
                .verify_artifact(&response.raw_response_artifact, true)
                .map_err(AppError::operational)?;
            for (slot, artifact) in request.outputs.iter().zip(&response.output_artifacts) {
                session
                    .verify_artifact(artifact, true)
                    .map_err(AppError::operational)?;
                if slot.role == ControllerOutputRoleV2::MachineEvidence {
                    validate_evidence_artifact_for_operation(
                        session,
                        request.operation,
                        &request.binding.binding_sha256,
                        artifact,
                    )?;
                }
            }
            Ok(())
        }
        _ => Err(AppError::operational(
            "controller request and response use different immutable protocol versions",
        )),
    }
}

fn validate_evidence_artifact_for_operation(
    session: &Session,
    operation: PerfOperation,
    binding_sha256: &Sha256Digest,
    artifact: &Artifact,
) -> Result<(), AppError> {
    let bytes = read_bounded_bytes_artifact(session, artifact, MAX_CONTROLLER_EVIDENCE_BYTES)?;
    let evidence = parse_controller_evidence(operation, &bytes)
        .map_err(|error| AppError::operational(error.to_string()))?;
    evidence
        .validate_for(operation, binding_sha256)
        .map_err(AppError::operational)
}

fn validate_response_artifact_identity_v1(
    artifact: &Artifact,
    response: &ControllerResponse,
) -> Result<(), AppError> {
    let transaction = &response.binding.transaction_id;
    let mut expected_inputs = vec![
        response.request_artifact_id.clone(),
        response.raw_response_artifact.id.clone(),
    ];
    if let Some(output) = &response.output_artifact {
        expected_inputs.push(output.id.clone());
    }
    if artifact.id != response_artifact_id(transaction)
        || artifact.kind != CONTROLLER_RESPONSE_KIND
        || artifact.relative_path != response_artifact_path(transaction)?
        || artifact.producer != CONTROLLER_PRODUCER
        || artifact.input_artifact_ids != expected_inputs
    {
        return Err(AppError::operational(
            "controller response artifact does not match its bound response document",
        ));
    }
    Ok(())
}

fn validate_response_artifact_identity(
    artifact: &Artifact,
    response: &ControllerResponseEnvelope,
) -> Result<(), AppError> {
    match response {
        ControllerResponseEnvelope::V1(response) => {
            validate_response_artifact_identity_v1(artifact, response)
        }
        ControllerResponseEnvelope::V2(response) => {
            let mut expected_inputs = vec![
                response.request_artifact_id.clone(),
                response.raw_response_artifact.id.clone(),
            ];
            expected_inputs.extend(
                response
                    .output_artifacts
                    .iter()
                    .map(|output| output.id.clone()),
            );
            if artifact.id != response_artifact_id(&response.binding.transaction_id)
                || artifact.kind != CONTROLLER_RESPONSE_KIND
                || artifact.relative_path
                    != response_artifact_path(&response.binding.transaction_id)?
                || artifact.producer != CONTROLLER_PRODUCER
                || artifact.input_artifact_ids != expected_inputs
            {
                return Err(AppError::operational(
                    "controller response artifact does not match its bound response document",
                ));
            }
            Ok(())
        }
    }
}

fn accepted_machine_evidence_artifact<'a>(
    request: &'a ControllerRequestEnvelope,
    response: &'a ControllerResponseEnvelope,
) -> Result<Option<&'a Artifact>, AppError> {
    if response.script_response().status != PerfStatus::Ok {
        return Ok(None);
    }
    match (request, response) {
        (ControllerRequestEnvelope::V1(request), ControllerResponseEnvelope::V1(response)) => {
            if request
                .output
                .as_ref()
                .is_some_and(|output| output.role == ControllerOutputRole::MachineEvidence)
            {
                return response.output_artifact.as_ref().map(Some).ok_or_else(|| {
                    AppError::operational("accepted target-control response is missing evidence")
                });
            }
            Ok(None)
        }
        (ControllerRequestEnvelope::V2(request), ControllerResponseEnvelope::V2(response)) => {
            if request.operation == PerfOperation::Export {
                return Ok(None);
            }
            match (
                request.outputs.as_slice(),
                response.output_artifacts.as_slice(),
            ) {
                ([reservation], [artifact])
                    if reservation.role == ControllerOutputRoleV2::MachineEvidence =>
                {
                    Ok(Some(artifact))
                }
                _ => Err(AppError::operational(
                    "successful non-export V2 response must have exactly one machine-evidence artifact",
                )),
            }
        }
        _ => Err(AppError::operational(
            "controller request and response use different immutable protocol versions",
        )),
    }
}

fn read_envelope_evidence_artifact(
    session: &Session,
    request: &ControllerRequestEnvelope,
    artifact: &Artifact,
) -> Result<ControllerEvidence, AppError> {
    let bytes = read_bounded_bytes_artifact(session, artifact, MAX_CONTROLLER_EVIDENCE_BYTES)?;
    let evidence = parse_controller_evidence(request.operation(), &bytes)
        .map_err(|error| AppError::operational(error.to_string()))?;
    evidence
        .validate_for(request.operation(), &request.binding().binding_sha256)
        .map_err(AppError::operational)?;
    Ok(evidence)
}

fn validate_candidate_evidence_chain(
    session: &Session,
    artifacts: &[Artifact],
    request: &ControllerRequest,
    response: &ControllerResponse,
) -> Result<(), AppError> {
    if response.script_response.status != PerfStatus::Ok {
        return Ok(());
    }
    let mut accepted = accepted_evidence_from_artifacts(session, artifacts)?;
    if request
        .output
        .as_ref()
        .is_some_and(|output| output.role == ControllerOutputRole::MachineEvidence)
    {
        let output = response.output_artifact.as_ref().ok_or_else(|| {
            AppError::operational("successful target-control response is missing evidence")
        })?;
        if accepted
            .evidence
            .insert(
                request.operation,
                read_evidence_artifact(session, request, output)?,
            )
            .is_some()
        {
            return Err(AppError::operational(format!(
                "controller operation `{}` already has accepted evidence",
                request.operation.as_str()
            )));
        }
        accepted.artifacts.insert(request.operation, output.clone());
    }
    let mut responses = accepted_script_responses_from_artifacts(session, artifacts)?;
    if responses
        .insert(
            request.operation,
            PerfScriptResponse {
                protocol: T32PERF_PROTOCOL,
                operation: response.script_response.operation,
                status: response.script_response.status,
                code: response.script_response.code.clone(),
                binding_sha256: request.binding.binding_sha256.to_string(),
                files_deleted: response.script_response.files_deleted,
            },
        )
        .is_some()
    {
        return Err(AppError::operational(format!(
            "controller operation `{}` already has an accepted response",
            request.operation.as_str()
        )));
    }
    validate_controller_evidence_chain(
        session,
        artifacts,
        &accepted.evidence,
        &accepted.artifacts,
        &responses,
    )?;
    validate_sampling_evidence_chain(session, artifacts, &accepted.evidence)
}

fn validate_candidate_evidence_chain_v2(
    session: &Session,
    artifacts: &[Artifact],
    request: &ControllerRequestV2,
    response: &ControllerResponseV2,
) -> Result<(), AppError> {
    if response.script_response.status != PerfStatus::Ok {
        return Ok(());
    }
    let mut accepted = accepted_evidence_from_artifacts(session, artifacts)?;
    if request.operation != PerfOperation::Export {
        let evidence = response.output_artifacts.first().ok_or_else(|| {
            AppError::operational("successful V2 control response is missing evidence")
        })?;
        if accepted
            .evidence
            .insert(
                request.operation,
                read_envelope_evidence_artifact(
                    session,
                    &ControllerRequestEnvelope::V2(request.clone()),
                    evidence,
                )?,
            )
            .is_some()
        {
            return Err(AppError::operational(format!(
                "controller operation `{}` already has accepted evidence",
                request.operation.as_str()
            )));
        }
        accepted
            .artifacts
            .insert(request.operation, evidence.clone());
    }
    let mut responses = accepted_script_responses_from_artifacts(session, artifacts)?;
    if responses
        .insert(
            request.operation,
            PerfScriptResponse {
                protocol: T32PERF_PROTOCOL,
                operation: response.script_response.operation,
                status: response.script_response.status,
                code: response.script_response.code.clone(),
                binding_sha256: request.binding.binding_sha256.to_string(),
                files_deleted: response.script_response.files_deleted,
            },
        )
        .is_some()
    {
        return Err(AppError::operational(format!(
            "controller operation `{}` already has an accepted response",
            request.operation.as_str()
        )));
    }
    validate_controller_evidence_chain(
        session,
        artifacts,
        &accepted.evidence,
        &accepted.artifacts,
        &responses,
    )?;
    validate_sampling_evidence_chain(session, artifacts, &accepted.evidence)
}

struct AcceptedControllerEvidenceSet {
    evidence: BTreeMap<PerfOperation, ControllerEvidence>,
    artifacts: BTreeMap<PerfOperation, Artifact>,
}

fn accepted_evidence_from_artifacts(
    session: &Session,
    artifacts: &[Artifact],
) -> Result<AcceptedControllerEvidenceSet, AppError> {
    let mut evidence = BTreeMap::new();
    let mut evidence_artifacts = BTreeMap::new();
    for transaction in controller_transaction_ids(artifacts) {
        let request_artifact = find_required_artifact(
            artifacts,
            &request_artifact_id(&transaction),
            CONTROLLER_REQUEST_KIND,
        )?;
        let request = read_controller_request_envelope(session, request_artifact)?;
        let Some(response_artifact) = find_artifact(artifacts, &response_artifact_id(&transaction))
        else {
            continue;
        };
        let response = read_controller_response_envelope(session, response_artifact)?;
        validate_response(session, request_artifact, &request, &response)?;
        validate_response_artifact_identity(response_artifact, &response)?;
        let Some(output) = accepted_machine_evidence_artifact(&request, &response)? else {
            continue;
        };
        if evidence
            .insert(
                request.operation(),
                read_envelope_evidence_artifact(session, &request, output)?,
            )
            .is_some()
        {
            return Err(AppError::operational(format!(
                "controller operation `{}` has duplicate accepted evidence",
                request.operation().as_str()
            )));
        }
        evidence_artifacts.insert(request.operation(), output.clone());
    }
    Ok(AcceptedControllerEvidenceSet {
        evidence,
        artifacts: evidence_artifacts,
    })
}

fn accepted_script_responses_from_artifacts(
    session: &Session,
    artifacts: &[Artifact],
) -> Result<BTreeMap<PerfOperation, PerfScriptResponse>, AppError> {
    let mut responses = BTreeMap::new();
    for transaction in controller_transaction_ids(artifacts) {
        let request_artifact = find_required_artifact(
            artifacts,
            &request_artifact_id(&transaction),
            CONTROLLER_REQUEST_KIND,
        )?;
        let request = read_controller_request_envelope(session, request_artifact)?;
        let Some(response_artifact) = find_artifact(artifacts, &response_artifact_id(&transaction))
        else {
            continue;
        };
        let response = read_controller_response_envelope(session, response_artifact)?;
        validate_response(session, request_artifact, &request, &response)?;
        validate_response_artifact_identity(response_artifact, &response)?;
        if response.script_response().status != PerfStatus::Ok {
            continue;
        }
        let script_response = PerfScriptResponse {
            protocol: T32PERF_PROTOCOL,
            operation: response.script_response().operation,
            status: response.script_response().status,
            code: response.script_response().code.clone(),
            binding_sha256: request.binding().binding_sha256.to_string(),
            files_deleted: response.script_response().files_deleted,
        };
        if responses
            .insert(request.operation(), script_response)
            .is_some()
        {
            return Err(AppError::operational(format!(
                "controller operation `{}` has duplicate accepted responses",
                request.operation().as_str()
            )));
        }
    }
    Ok(responses)
}

fn accept_output_artifact(
    session: &Session,
    lock: &SessionLock,
    artifacts: &[Artifact],
    request_artifact: &Artifact,
    request: &ControllerRequest,
    raw_response_artifact: &Artifact,
) -> Result<Option<Artifact>, AppError> {
    let reservation = request.output.as_ref().ok_or_else(|| {
        transaction_pending_error(
            "CONTROLLER_OUTPUT_RESERVATION_MISSING",
            "successful fixed-script response has no immutable output reservation",
            json!({
                "transaction_id": request.binding.transaction_id,
                "raw_response_artifact": raw_response_artifact,
            }),
        )
    })?;
    let output = if let Some(existing) = find_artifact(artifacts, &reservation.artifact_id) {
        validate_output_artifact_identity(existing, reservation, request_artifact)?;
        session
            .verify_artifact(existing, true)
            .map_err(AppError::operational)?;
        existing.clone()
    } else {
        session
            .ingest_staged_bounded(
                lock,
                &reservation.staged_relative_path,
                ArtifactSpec {
                    id: reservation.artifact_id.clone(),
                    kind: reservation.kind.clone(),
                    relative_path: reservation.destination_relative_path.clone(),
                    media_type: reservation.media_type.clone(),
                    producer: reservation.producer.clone(),
                    input_artifact_ids: vec![request_artifact.id.clone()],
                },
                reservation.max_bytes,
            )
            .map_err(|error| {
                transaction_pending_error(
                    "CONTROLLER_OUTPUT_INGEST_FAILED",
                    error.to_string(),
                    json!({
                        "transaction_id": request.binding.transaction_id,
                        "raw_response_artifact": raw_response_artifact,
                    }),
                )
            })?
    };
    if reservation.role == ControllerOutputRole::MachineEvidence {
        validate_evidence_artifact(session, request, &output).map_err(|error| {
            transaction_pending_error(
                "CONTROLLER_EVIDENCE_INVALID",
                error.message,
                json!({
                    "transaction_id": request.binding.transaction_id,
                    "operation": request.operation,
                    "raw_response_artifact": raw_response_artifact,
                    "evidence_artifact": output,
                    "required_action": "complete the two-phase controller abort; invalid immutable evidence cannot advance capture phase",
                }),
            )
        })?;
    }
    Ok(Some(output))
}

/// V2 output acceptance is all-or-nothing at the response level.  Every
/// missing producer file is checked for plain-file readiness before the first
/// ingest; `ingest_staged_bounded` then supplies the durable intent/private
/// copy/identity-and-hash checks for each slot. A crash may leave an immutable
/// prefix, but no response exists until every slot is accepted and retries use
/// the exact existing artifacts.
fn accept_output_artifacts_v2(
    session: &Session,
    lock: &SessionLock,
    artifacts: &[Artifact],
    request_artifact: &Artifact,
    request: &ControllerRequestV2,
    raw_response_artifact: &Artifact,
) -> Result<Vec<Artifact>, AppError> {
    for slot in &request.outputs {
        if let Some(existing) = find_artifact(artifacts, &slot.artifact_id) {
            validate_output_artifact_identity_v2(existing, slot, request_artifact)?;
            session
                .verify_artifact(existing, true)
                .map_err(AppError::operational)?;
        } else {
            preflight_staged_output(session, &slot.staged_relative_path, slot.max_bytes).map_err(
                |error| {
                    transaction_pending_error(
                        "CONTROLLER_OUTPUT_PREFLIGHT_FAILED",
                        error.message,
                        json!({
                            "transaction_id": request.binding.transaction_id,
                            "raw_response_artifact": raw_response_artifact,
                            "output_role": slot.role,
                        }),
                    )
                },
            )?;
        }
    }
    let mut accepted = Vec::with_capacity(request.outputs.len());
    for slot in &request.outputs {
        let artifact = if let Some(existing) = find_artifact(artifacts, &slot.artifact_id) {
            existing.clone()
        } else {
            session
                .ingest_staged_bounded(
                    lock,
                    &slot.staged_relative_path,
                    ArtifactSpec {
                        id: slot.artifact_id.clone(),
                        kind: slot.kind.clone(),
                        relative_path: slot.destination_relative_path.clone(),
                        media_type: slot.media_type.clone(),
                        producer: slot.producer.clone(),
                        input_artifact_ids: vec![request_artifact.id.clone()],
                    },
                    slot.max_bytes,
                )
                .map_err(|error| {
                    transaction_pending_error(
                        "CONTROLLER_OUTPUT_INGEST_FAILED",
                        error.to_string(),
                        json!({
                            "transaction_id": request.binding.transaction_id,
                            "raw_response_artifact": raw_response_artifact,
                            "output_role": slot.role,
                        }),
                    )
                })?
        };
        validate_output_artifact_identity_v2(&artifact, slot, request_artifact)?;
        if slot.role == ControllerOutputRoleV2::MachineEvidence {
            validate_evidence_artifact_for_operation(
                session,
                request.operation,
                &request.binding.binding_sha256,
                &artifact,
            )
            .map_err(|error| {
                transaction_pending_error(
                    "CONTROLLER_EVIDENCE_INVALID",
                    error.message,
                    json!({
                        "transaction_id": request.binding.transaction_id,
                        "evidence_artifact": artifact,
                    }),
                )
            })?;
        }
        accepted.push(artifact);
    }
    Ok(accepted)
}

fn preflight_staged_output(
    session: &Session,
    staged_relative_path: &ArtifactPath,
    maximum: u64,
) -> Result<(), AppError> {
    let path = session
        .staging_path(staged_relative_path)
        .map_err(AppError::operational)?;
    let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
        AppError::operational(format!(
            "cannot inspect controller staged output `{}`: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(AppError::operational(format!(
            "controller staged output `{}` is not a plain file",
            path.display()
        )));
    }
    if metadata.len() > maximum {
        return Err(AppError::operational(format!(
            "controller staged output `{}` is {} bytes; maximum is {maximum}",
            path.display(),
            metadata.len()
        )));
    }
    Ok(())
}

fn validate_output_artifact_identity(
    output: &Artifact,
    reservation: &ControllerOutputReservation,
    request_artifact: &Artifact,
) -> Result<(), AppError> {
    if output.id != reservation.artifact_id
        || output.kind != reservation.kind
        || output.relative_path != reservation.destination_relative_path
        || output.media_type != reservation.media_type
        || output.producer != reservation.producer
        || output.input_artifact_ids != [request_artifact.id.clone()]
        || output.size_bytes > reservation.max_bytes
    {
        return Err(AppError::operational(
            "controller output artifact does not match its immutable reservation",
        ));
    }
    Ok(())
}

fn validate_output_artifact_identity_v2(
    output: &Artifact,
    reservation: &ControllerOutputReservationV2,
    request_artifact: &Artifact,
) -> Result<(), AppError> {
    if output.id != reservation.artifact_id
        || output.kind != reservation.kind
        || output.relative_path != reservation.destination_relative_path
        || output.media_type != reservation.media_type
        || output.producer != reservation.producer
        || output.input_artifact_ids != [request_artifact.id.clone()]
        || output.size_bytes > reservation.max_bytes
    {
        return Err(AppError::operational(
            "controller V2 output artifact does not match its immutable reservation",
        ));
    }
    Ok(())
}

fn validate_evidence_artifact(
    session: &Session,
    request: &ControllerRequest,
    artifact: &Artifact,
) -> Result<(), AppError> {
    read_evidence_artifact(session, request, artifact).map(|_| ())
}

fn read_evidence_artifact(
    session: &Session,
    request: &ControllerRequest,
    artifact: &Artifact,
) -> Result<ControllerEvidence, AppError> {
    let bytes = read_bounded_bytes_artifact(session, artifact, MAX_CONTROLLER_EVIDENCE_BYTES)?;
    let evidence = parse_controller_evidence(request.operation, &bytes)
        .map_err(|error| AppError::operational(error.to_string()))?;
    evidence
        .validate_for(request.operation, &request.binding.binding_sha256)
        .map_err(AppError::operational)?;
    Ok(evidence)
}

fn reconcile_state_for_response(
    session: &Session,
    lock: &SessionLock,
    response: &ControllerResponse,
) -> Result<t32perf_model::SessionState, AppError> {
    let state = session.read_state().map_err(AppError::operational)?;
    match response.script_response.status {
        PerfStatus::UnsupportedNeedsTrace32 | PerfStatus::InvalidArgument => {
            if state.status == SessionStatus::Failed {
                return Ok(state);
            }
            return session
                .transition(
                    lock,
                    SessionStatus::Failed,
                    Some(SessionError {
                        code: "CONTROLLER_SCRIPT_REJECTED".to_owned(),
                        message: format!(
                            "{} returned {} / {}",
                            response.script_response.operation.as_str(),
                            response.script_response.status.as_str(),
                            response.script_response.code
                        ),
                        details: Default::default(),
                    }),
                )
                .map_err(AppError::operational);
        }
        PerfStatus::HostProcessingRequired => return Ok(state),
        PerfStatus::Ok => {}
    }
    match (response.script_response.operation, state.status) {
        (PerfOperation::Start, SessionStatus::Created) => session
            .transition(lock, SessionStatus::Capturing, None)
            .map_err(AppError::operational),
        (PerfOperation::Start, SessionStatus::Capturing) => Ok(state),
        (PerfOperation::Stop, SessionStatus::Capturing) => session
            .transition(lock, SessionStatus::Captured, None)
            .map_err(AppError::operational),
        (PerfOperation::Stop, SessionStatus::Captured) => Ok(state),
        (PerfOperation::GetCapabilities | PerfOperation::Configure, SessionStatus::Created)
        | (
            PerfOperation::GetHealth
            | PerfOperation::Export
            | PerfOperation::GetHotspots
            | PerfOperation::Cleanup,
            SessionStatus::Captured,
        ) => Ok(state),
        (operation, status) => Err(AppError::operational(format!(
            "accepted controller operation `{}` is inconsistent with Session state {status:?}",
            operation.as_str()
        ))),
    }
}

fn reconcile_state_for_response_v2(
    session: &Session,
    lock: &SessionLock,
    response: &ControllerResponseEnvelope,
) -> Result<t32perf_model::SessionState, AppError> {
    let state = session.read_state().map_err(AppError::operational)?;
    match response.script_response().status {
        PerfStatus::UnsupportedNeedsTrace32 | PerfStatus::InvalidArgument => {
            if state.status == SessionStatus::Failed {
                return Ok(state);
            }
            return session
                .transition(
                    lock,
                    SessionStatus::Failed,
                    Some(SessionError {
                        code: "CONTROLLER_SCRIPT_REJECTED".to_owned(),
                        message: format!(
                            "{} returned {} / {}",
                            response.script_response().operation.as_str(),
                            response.script_response().status.as_str(),
                            response.script_response().code
                        ),
                        details: Default::default(),
                    }),
                )
                .map_err(AppError::operational);
        }
        PerfStatus::HostProcessingRequired => return Ok(state),
        PerfStatus::Ok => {}
    }
    match (response.script_response().operation, state.status) {
        (PerfOperation::Start, SessionStatus::Created) => session
            .transition(lock, SessionStatus::Capturing, None)
            .map_err(AppError::operational),
        (PerfOperation::Start, SessionStatus::Capturing) => Ok(state),
        (PerfOperation::Stop, SessionStatus::Capturing) => session
            .transition(lock, SessionStatus::Captured, None)
            .map_err(AppError::operational),
        (PerfOperation::Stop, SessionStatus::Captured) => Ok(state),
        (PerfOperation::GetCapabilities | PerfOperation::Configure, SessionStatus::Created)
        | (
            PerfOperation::GetHealth
            | PerfOperation::Export
            | PerfOperation::GetHotspots
            | PerfOperation::Cleanup,
            SessionStatus::Captured,
        ) => Ok(state),
        (operation, status) => Err(AppError::operational(format!(
            "accepted controller operation `{}` is inconsistent with Session state {status:?}",
            operation.as_str()
        ))),
    }
}

fn validate_abort_receipt_envelope(
    request: &ControllerRequestEnvelope,
    request_artifact: &Artifact,
    abort_request: &ControllerAbortRequest,
    abort_request_artifact: &Artifact,
    receipt: &ControllerAbortReceipt,
) -> Result<(), AppError> {
    receipt.binding.validate().map_err(AppError::operational)?;
    if receipt.binding != *request.binding()
        || abort_request.binding != *request.binding()
        || receipt.request_artifact_id != request_artifact.id
        || receipt.request_artifact_sha256 != request_artifact.sha256
        || receipt.abort_request_artifact_id != abort_request_artifact.id
        || receipt.abort_request_artifact_sha256 != abort_request_artifact.sha256
        || receipt.acknowledgement != ControllerAbortAcknowledgement::UnboundSingleTenantToolSuccess
    {
        return Err(AppError::operational(
            "controller abort receipt is not bound to its request and abort plan",
        ));
    }
    Ok(())
}

fn render_response(
    response_artifact: &Artifact,
    response: &ControllerResponse,
    state: SessionStatus,
) -> Result<CommandOutcome, AppError> {
    let result = json!({
        "session_id": response.binding.session_id,
        "state": state,
        "transaction_id": response.binding.transaction_id,
        "request_artifact_id": response.request_artifact_id,
        "request_artifact_sha256": response.request_artifact_sha256,
        "response_artifact": response_artifact,
        "script_response": response.script_response,
        "raw_response_artifact": response.raw_response_artifact,
        "output_artifact": response.output_artifact,
    });
    match response.script_response.status {
        PerfStatus::UnsupportedNeedsTrace32 => Err(AppError {
            code: "UNSUPPORTED",
            message: format!(
                "TRACE32 skill operation `{}` requires verified target-specific support: {}",
                response.script_response.operation.as_str(),
                response.script_response.code
            ),
            details: result,
            exit_code: EXIT_UNSUPPORTED,
        }),
        PerfStatus::InvalidArgument => Err(AppError {
            code: "CONTROLLER_SCRIPT_REJECTED",
            message: format!(
                "TRACE32 skill rejected the immutable controller arguments: {}",
                response.script_response.code
            ),
            details: result,
            exit_code: EXIT_OPERATIONAL,
        }),
        PerfStatus::Ok | PerfStatus::HostProcessingRequired => success("controller.accept", result),
    }
}

fn render_response_v2(
    response_artifact: &Artifact,
    response: &ControllerResponseEnvelope,
    state: SessionStatus,
) -> Result<CommandOutcome, AppError> {
    let result = json!({
        "session_id": response.binding().session_id,
        "state": state,
        "transaction_id": response.binding().transaction_id,
        "request_artifact_id": response.request_artifact_id(),
        "request_artifact_sha256": response.request_artifact_sha256(),
        "response_artifact": response_artifact,
        "script_response": response.script_response(),
        "raw_response_artifact": response.raw_response_artifact(),
        "output_artifacts": response.output_artifacts(),
    });
    match response.script_response().status {
        PerfStatus::UnsupportedNeedsTrace32 => Err(AppError {
            code: "UNSUPPORTED",
            message: format!(
                "TRACE32 skill operation `{}` requires verified target-specific support: {}",
                response.script_response().operation.as_str(),
                response.script_response().code
            ),
            details: result,
            exit_code: EXIT_UNSUPPORTED,
        }),
        PerfStatus::InvalidArgument => Err(AppError {
            code: "CONTROLLER_SCRIPT_REJECTED",
            message: format!(
                "TRACE32 skill rejected the immutable controller arguments: {}",
                response.script_response().code
            ),
            details: result,
            exit_code: EXIT_OPERATIONAL,
        }),
        PerfStatus::Ok | PerfStatus::HostProcessingRequired => success("controller.accept", result),
    }
}

fn transaction_pending_error(
    code: &'static str,
    message: impl Into<String>,
    mut details: serde_json::Value,
) -> AppError {
    if let Some(object) = details.as_object_mut() {
        object.insert("root_slot_released".to_owned(), json!(false));
        object.insert(
            "recovery".to_owned(),
            json!("collect a final bound response or complete the two-phase controller abort"),
        );
    }
    AppError {
        code,
        message: message.into(),
        details,
        exit_code: EXIT_OPERATIONAL,
    }
}

fn write_bounded_json<T: Serialize>(
    session: &Session,
    lock: &SessionLock,
    spec: ArtifactSpec,
    value: &T,
    limit: u64,
) -> Result<Artifact, AppError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(AppError::operational)?;
    bytes.push(b'\n');
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual > limit {
        return Err(AppError::operational(format!(
            "controller JSON document is {actual} bytes; maximum is {limit}"
        )));
    }
    let mut writer = session
        .create_artifact(lock, spec)
        .map_err(AppError::operational)?;
    writer.write_all(&bytes).map_err(AppError::operational)?;
    session
        .commit_artifact(lock, writer)
        .map_err(AppError::operational)
}

const FIRMWARE_ELF_ARTIFACT_ID: &str = "firmware-elf";
pub(crate) const FIRMWARE_S3_ARTIFACT_ID: &str = "trace32-firmware-s3";
pub(crate) const FIRMWARE_S3_ARTIFACT_KIND: &str = "trace32_firmware_measurement";
pub(crate) const FIRMWARE_S3_ARTIFACT_PATH: &str = "capture/trace32-firmware.s3";
pub(crate) const FIRMWARE_S3_PRODUCER: &str = "t32perf-controller-firmware-image/v1";
const FIRMWARE_S3_STAGING_PATH: &str = "controller/trace32-firmware.s3";

/// Derives the one canonical target-load representation from the immutable ELF
/// before any controller request is persisted. Repeated preparation verifies
/// the existing result byte-for-byte instead of accepting another S-record
/// spelling or overwriting an immutable catalog entry.
fn ensure_firmware_image(
    session: &Session,
    lock: &SessionLock,
    artifacts: &[Artifact],
) -> Result<ControllerFirmwareImageBinding, AppError> {
    let source = find_artifact(artifacts, FIRMWARE_ELF_ARTIFACT_ID)
        .ok_or_else(|| AppError::operational("registered firmware-elf artifact is absent"))?
        .clone();
    validate_firmware_artifact_envelope(&source)?;
    let elf_bytes = read_bounded_bytes_artifact(
        session,
        &source,
        u64::try_from(MAX_TRICORE_FIRMWARE_ELF_BYTES).expect("firmware limit fits u64"),
    )?;
    let measurement = measure_registered_tricore_elf_to_s3(&elf_bytes, &source.sha256)
        .map_err(AppError::operational)?;
    let expected_path =
        ArtifactPath::new(FIRMWARE_S3_ARTIFACT_PATH).map_err(AppError::operational)?;
    let measurement_artifact = if let Some(existing) =
        find_artifact(artifacts, FIRMWARE_S3_ARTIFACT_ID)
    {
        if existing.kind != FIRMWARE_S3_ARTIFACT_KIND
            || existing.relative_path != expected_path
            || existing.media_type != "application/vnd.motorola-s-record"
            || existing.producer != FIRMWARE_S3_PRODUCER
            || existing.input_artifact_ids != [source.id.clone()]
            || existing.sha256 != measurement.s3_sha256
        {
            return Err(AppError::operational(
                "registered trace32 firmware S3 measurement does not match its fixed identity or source ELF",
            ));
        }
        let s3_bytes = read_bounded_bytes_artifact(
            session,
            existing,
            u64::try_from(MAX_TRICORE_S3_OUTPUT_BYTES).expect("S3 limit fits u64"),
        )?;
        verify_registered_tricore_elf_s3_measurement(
            &elf_bytes,
            &source.sha256,
            &s3_bytes,
            &existing.sha256,
        )
        .map_err(AppError::operational)?;
        existing.clone()
    } else {
        let staging = ArtifactPath::new(FIRMWARE_S3_STAGING_PATH).map_err(AppError::operational)?;
        let maximum = u64::try_from(MAX_TRICORE_S3_OUTPUT_BYTES).expect("S3 output limit fits u64");
        session
            .ensure_staged_exact(lock, &staging, &measurement.s3_bytes, maximum)
            .map_err(AppError::operational)?;
        session
            .ingest_staged_bounded(
                lock,
                &staging,
                ArtifactSpec {
                    id: FIRMWARE_S3_ARTIFACT_ID.to_owned(),
                    kind: FIRMWARE_S3_ARTIFACT_KIND.to_owned(),
                    relative_path: expected_path,
                    media_type: "application/vnd.motorola-s-record".to_owned(),
                    producer: FIRMWARE_S3_PRODUCER.to_owned(),
                    input_artifact_ids: vec![source.id.clone()],
                },
                maximum,
            )
            .map_err(AppError::operational)?
    };
    let script_input_path = session
        .path()
        .join(measurement_artifact.relative_path.as_str())
        .to_str()
        .ok_or_else(|| AppError::operational("firmware S3 artifact path is not UTF-8"))?
        .to_owned();
    Ok(ControllerFirmwareImageBinding {
        source_elf_artifact: source,
        measurement_artifact,
        script_input_path,
    })
}

fn controller_request_inputs(
    firmware: &ControllerFirmwareImageBinding,
    admission_provenance: &[Artifact],
    selection_artifact: Option<&Artifact>,
) -> Vec<String> {
    let mut inputs = vec![
        firmware.source_elf_artifact.id.clone(),
        firmware.measurement_artifact.id.clone(),
    ];
    inputs.extend(
        admission_provenance
            .iter()
            .map(|artifact| artifact.id.clone()),
    );
    if let Some(selection) = selection_artifact {
        inputs.push(selection.id.clone());
    }
    inputs
}

fn read_bounded_json_artifact<T: DeserializeOwned>(
    session: &Session,
    artifact: &Artifact,
    limit: u64,
) -> Result<T, AppError> {
    if artifact.size_bytes > limit {
        return Err(AppError::operational(format!(
            "controller artifact `{}` is {} bytes; maximum is {limit}",
            artifact.id, artifact.size_bytes
        )));
    }
    let bytes = read_bounded_bytes_artifact(session, artifact, limit)?;
    strict_json::from_slice(&bytes).map_err(AppError::operational)
}

fn read_bounded_bytes_artifact(
    session: &Session,
    artifact: &Artifact,
    limit: u64,
) -> Result<Vec<u8>, AppError> {
    if artifact.size_bytes > limit {
        return Err(AppError::operational(format!(
            "controller artifact `{}` is {} bytes; maximum is {limit}",
            artifact.id, artifact.size_bytes
        )));
    }
    let mut file = session
        .open_artifact(artifact)
        .map_err(AppError::operational)?;
    let mut bytes = Vec::with_capacity(usize::try_from(artifact.size_bytes).unwrap_or(0));
    (&mut file)
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(AppError::operational)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(AppError::operational(format!(
            "controller artifact `{}` grew beyond {limit} bytes while reading",
            artifact.id
        )));
    }
    Ok(bytes)
}

pub(crate) fn controller_capture_progress(
    root: &ArtifactRoot,
    session_id: &str,
) -> Result<ControllerProgress, AppError> {
    let session = open_session(root, session_id)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    controller_progress_from_artifacts(Some(root), &session, &artifacts)
}

pub(crate) fn validate_capture_config_against_controller(
    session: &Session,
    artifacts: &[Artifact],
    document: &CaptureConfigDocument,
    configuration_sha256: &Sha256Digest,
) -> Result<(), AppError> {
    let progress = controller_progress_from_artifacts(None, session, artifacts)?;
    let has_controller_artifacts = artifacts.iter().any(|artifact| {
        artifact.id.starts_with(CONTROLLER_ARTIFACT_ID_PREFIX)
            || artifact
                .relative_path
                .as_str()
                .starts_with(CONTROLLER_ARTIFACT_PATH_PREFIX)
    });
    if !has_controller_artifacts {
        return Ok(());
    }
    if progress.phase != ControllerCapturePhase::Complete {
        return Err(AppError::operational(
            "capture-config cannot bind an incomplete controller chain; cleanup evidence is required",
        ));
    }
    let Some((_, configure)) =
        accepted_controller_evidence(session, artifacts, &progress, PerfOperation::Configure)?
    else {
        return Err(AppError::operational(
            "complete controller chain is missing configure evidence",
        ));
    };
    let ControllerEvidence::Configure(configure) = configure else {
        return Err(AppError::operational(
            "accepted configure response contains the wrong evidence type",
        ));
    };
    let Some((_, start)) =
        accepted_controller_evidence(session, artifacts, &progress, PerfOperation::Start)?
    else {
        return Err(AppError::operational(
            "accepted configure evidence cannot bind capture-config before capture-start evidence",
        ));
    };
    let (start_initial_target_state, start_workload_identity) = match start {
        ControllerEvidence::Start(start) => (start.initial_target_state, start.workload_identity),
        ControllerEvidence::StartV2(start) => (start.initial_target_state, start.workload_identity),
        _ => {
            return Err(AppError::operational(
                "accepted start response contains the wrong evidence type",
            ));
        }
    };

    let expected_initial_state = match document.initial_target_state {
        InitialTargetState::Running => Some(ControllerTargetState::Running),
        InitialTargetState::Halted => Some(ControllerTargetState::Halted),
        InitialTargetState::Unknown => None,
    };
    let configured_cores = configure
        .covered_cores
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let document_cores = document
        .covered_cores
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut mismatches = Vec::new();
    if configuration_sha256 != &configure.configuration_sha256 {
        mismatches.push("configuration_sha256");
    }
    if document.mode != configure.capture_mode {
        mismatches.push("mode");
    }
    if document.sink.kind != configure.trace_sink {
        mismatches.push("sink.kind");
    }
    if document.timestamp.enabled != configure.timestamp_enabled {
        mismatches.push("timestamp.enabled");
    }
    if document_cores != configured_cores {
        mismatches.push("covered_cores");
    }
    if expected_initial_state != Some(configure.initial_target_state)
        || expected_initial_state != Some(start_initial_target_state)
    {
        mismatches.push("initial_target_state");
    }
    if document.workload_identity != configure.workload_identity
        || document.workload_identity != start_workload_identity
    {
        mismatches.push("workload_identity");
    }
    let requested_duration =
        crate::controller_capture_config::strict_performance_run_duration(session)
            .map_err(AppError::operational)?;
    if document.duration.duration_ns != requested_duration {
        mismatches.push("duration.duration_ns");
    }
    let (_, catalog, _, _) =
        crate::controller_qualification::load_session_admission(session, artifacts)?;
    let admitted = selected_target_adapter_binding(session, artifacts, &progress, &catalog)?;
    if document.adapter.id != admitted.adapter_id
        || document.adapter.version != admitted.adapter_version
    {
        mismatches.push("adapter");
    }
    if mismatches.is_empty() {
        return Ok(());
    }

    Err(AppError {
        code: "CONTROLLER_CAPTURE_CONFIG_MISMATCH",
        message: format!(
            "authoritative capture-config does not match accepted controller configure/start evidence: {}",
            mismatches.join(", ")
        ),
        details: json!({
            "session_id": session.id().as_str(),
            "mismatched_fields": mismatches,
            "expected_configuration_sha256": configure.configuration_sha256,
            "actual_configuration_sha256": configuration_sha256,
        }),
        exit_code: EXIT_OPERATIONAL,
    })
}

fn accepted_controller_evidence(
    session: &Session,
    artifacts: &[Artifact],
    progress: &ControllerProgress,
    operation: PerfOperation,
) -> Result<Option<(Artifact, ControllerEvidence)>, AppError> {
    if !progress.completed_operations.contains(&operation) {
        return Ok(None);
    }
    for transaction in controller_transaction_ids(artifacts) {
        let request_artifact = find_required_artifact(
            artifacts,
            &request_artifact_id(&transaction),
            CONTROLLER_REQUEST_KIND,
        )?;
        let request = read_controller_request_envelope(session, request_artifact)?;
        if request.operation() != operation {
            continue;
        }
        let Some(response_artifact) = find_artifact(artifacts, &response_artifact_id(&transaction))
        else {
            continue;
        };
        if response_artifact.kind != CONTROLLER_RESPONSE_KIND
            || response_artifact.producer != CONTROLLER_PRODUCER
        {
            return Err(AppError::operational(
                "controller response artifact has invalid kind or producer",
            ));
        }
        let response = read_controller_response_envelope(session, response_artifact)?;
        validate_response(session, request_artifact, &request, &response)?;
        validate_response_artifact_identity(response_artifact, &response)?;
        if response.script_response().status != PerfStatus::Ok {
            continue;
        }
        let output = accepted_machine_evidence_artifact(&request, &response)?
            .ok_or_else(|| AppError::operational("accepted response is missing evidence"))?;
        let evidence = read_envelope_evidence_artifact(session, &request, output)?;
        return Ok(Some((output.clone(), evidence)));
    }
    Err(AppError::operational(format!(
        "controller progress records `{}` completion without a response",
        operation.as_str()
    )))
}

pub(crate) fn controller_health_binding(
    session: &Session,
    artifacts: &[Artifact],
) -> Result<Option<ControllerHealthBinding>, AppError> {
    let progress = controller_progress_from_artifacts(None, session, artifacts)?;
    if !progress
        .completed_operations
        .contains(&PerfOperation::GetHealth)
    {
        return Ok(None);
    }
    let Some((artifact, evidence)) =
        accepted_controller_evidence(session, artifacts, &progress, PerfOperation::GetHealth)?
    else {
        return Ok(None);
    };
    match evidence {
        ControllerEvidence::HealthV3(evidence) => Ok(Some(ControllerHealthBinding {
            artifact,
            evidence: AcceptedControllerHealthEvidence::ProgramFlow(evidence),
        })),
        ControllerEvidence::HealthV2(evidence) => Ok(Some(ControllerHealthBinding {
            artifact,
            evidence: AcceptedControllerHealthEvidence::Sampling(evidence),
        })),
        _ => Err(AppError::operational(
            "accepted health response contains the wrong evidence type",
        )),
    }
}

pub(crate) fn accepted_trace32_completed_binding(
    session: &Session,
    artifacts: &[Artifact],
) -> Result<Option<AcceptedTrace32CompletedBinding>, AppError> {
    let has_controller_artifacts = artifacts.iter().any(|artifact| {
        artifact.id.starts_with(CONTROLLER_ARTIFACT_ID_PREFIX)
            || artifact
                .relative_path
                .as_str()
                .starts_with(CONTROLLER_ARTIFACT_PATH_PREFIX)
    });
    if !has_controller_artifacts {
        return Ok(None);
    }
    let progress = controller_progress_from_artifacts(None, session, artifacts)?;
    if progress.phase != ControllerCapturePhase::Complete {
        return Err(AppError::operational(
            "TRACE32 runtime binding requires accepted export and cleanup completion",
        ));
    }
    let (capabilities_artifact, capabilities) = accepted_controller_evidence(
        session,
        artifacts,
        &progress,
        PerfOperation::GetCapabilities,
    )?
    .ok_or_else(|| {
        AppError::operational("complete controller chain has no capabilities evidence")
    })?;
    let ControllerEvidence::CapabilitiesV2(capabilities) = capabilities else {
        return Err(AppError::operational(
            "complete TC234L controller chain requires capabilities evidence v2",
        ));
    };
    let (configure_artifact, configure) =
        accepted_controller_evidence(session, artifacts, &progress, PerfOperation::Configure)?
            .ok_or_else(|| {
                AppError::operational("complete controller chain has no configure evidence")
            })?;
    if !matches!(configure, ControllerEvidence::Configure(_)) {
        return Err(AppError::operational(
            "complete controller chain requires configure evidence v1",
        ));
    }
    let (start_artifact, start) =
        accepted_controller_evidence(session, artifacts, &progress, PerfOperation::Start)?
            .ok_or_else(|| {
                AppError::operational("complete controller chain has no start evidence")
            })?;
    if !matches!(start, ControllerEvidence::StartV2(_)) {
        return Err(AppError::operational(
            "complete controller chain requires externally-owned start evidence v2",
        ));
    }
    let (cleanup_artifact, cleanup) =
        accepted_controller_evidence(session, artifacts, &progress, PerfOperation::Cleanup)?
            .ok_or_else(|| {
                AppError::operational("complete controller chain has no cleanup evidence")
            })?;
    let (stop_artifact, stop) =
        accepted_controller_evidence(session, artifacts, &progress, PerfOperation::Stop)?
            .ok_or_else(|| {
                AppError::operational("complete controller chain has no stop evidence")
            })?;
    let (health_artifact, health) =
        accepted_controller_evidence(session, artifacts, &progress, PerfOperation::GetHealth)?
            .ok_or_else(|| {
                AppError::operational("complete controller chain has no health evidence")
            })?;
    let (export_artifact, custom_event_artifact, export_response, target_adapter) =
        accepted_export_claim(session, artifacts)?;
    let (_, catalog, admission_provenance, _) =
        crate::controller_qualification::load_session_admission(session, artifacts)?;
    let admitted = selected_target_adapter_binding(session, artifacts, &progress, &catalog)?;
    if target_adapter != admitted {
        return Err(AppError::operational(
            "accepted export is not bound to the admitted target-adapter profile",
        ));
    }
    let profile = catalog
        .get(&target_adapter.adapter_id)
        .ok_or_else(|| AppError::operational("selected adapter disappeared from the catalog"))?
        .profile
        .clone();
    let capture_contract = profile
        .scenario(target_adapter.scenario)
        .ok_or_else(|| {
            AppError::operational("selected adapter scenario disappeared from the catalog")
        })?
        .capture
        .clone();
    if capture_contract.capture_kind != target_adapter.capture_kind {
        return Err(AppError::operational(
            "accepted target-adapter capture kind disagrees with the admitted profile",
        ));
    }
    let completion = ControllerCaptureCompletionEvidence::from_evidence(
        &target_adapter.capture_kind,
        &stop,
        &stop_artifact.sha256,
        &health,
    )
    .map_err(AppError::operational)?;
    match (&completion, &cleanup) {
        (
            ControllerCaptureCompletionEvidence::Sampling { stop, health },
            ControllerEvidence::CleanupV2(_),
        ) => {
            if !stop.time_origin_zeroed_to_first_record {
                return Err(AppError::operational(
                    "sampling completion requires first-record ZERO stop evidence",
                ));
            }
            let expected_capacity_records = target_adapter
                .capture_kind
                .sampling_capacity_records()
                .expect("sampling completion has sampling capture kind");
            validate_completed_sampling_state(
                target_adapter.scenario,
                expected_capacity_records,
                health,
                stop,
            )?;
        }
        (
            ControllerCaptureCompletionEvidence::ProgramFlowTaskEvents { health, .. },
            ControllerEvidence::Cleanup(_),
        ) => validate_completed_program_flow_state(target_adapter.scenario, health)?,
        (ControllerCaptureCompletionEvidence::Sampling { .. }, _) => {
            return Err(AppError::operational(
                "sampling completion requires cleanup evidence v2",
            ));
        }
        (ControllerCaptureCompletionEvidence::ProgramFlowTaskEvents { .. }, _) => {
            return Err(AppError::operational(
                "TASKEVENTS program-flow completion requires cleanup evidence v1",
            ));
        }
    }
    let (qualification_artifact, qualification_receipt) =
        validated_qualification_claim(session, artifacts, &profile, &target_adapter)?;
    if let Some(receipt) = qualification_artifact.as_ref()
        && admission_provenance.get(2) != Some(receipt)
    {
        return Err(AppError::operational(
            "qualified runtime binding receipt is not the canonical admission provenance entry",
        ));
    }
    let qualification_provenance_artifacts = admission_provenance;
    let firmware_elf_artifact = find_artifact(artifacts, FIRMWARE_ELF_ARTIFACT_ID)
        .ok_or_else(|| AppError::operational("complete controller chain has no firmware ELF"))?
        .clone();
    let firmware_measurement_artifact = find_artifact(artifacts, FIRMWARE_S3_ARTIFACT_ID)
        .ok_or_else(|| {
            AppError::operational("complete controller chain has no sparse firmware measurement")
        })?
        .clone();
    validate_firmware_artifact_envelope(&firmware_elf_artifact)?;
    if firmware_measurement_artifact.kind != FIRMWARE_S3_ARTIFACT_KIND
        || firmware_measurement_artifact.media_type != "application/vnd.motorola-s-record"
        || firmware_measurement_artifact.producer != FIRMWARE_S3_PRODUCER
        || firmware_measurement_artifact.input_artifact_ids != [firmware_elf_artifact.id.clone()]
    {
        return Err(AppError::operational(
            "complete controller chain firmware artifacts have invalid identity or provenance",
        ));
    }
    if target_adapter.capture_kind.is_sampling() {
        let elf_bytes = read_bounded_bytes_artifact(
            session,
            &firmware_elf_artifact,
            u64::try_from(MAX_TRICORE_FIRMWARE_ELF_BYTES).expect("firmware limit fits u64"),
        )?;
        let s3_bytes = read_bounded_bytes_artifact(
            session,
            &firmware_measurement_artifact,
            u64::try_from(MAX_TRICORE_S3_OUTPUT_BYTES).expect("S3 limit fits u64"),
        )?;
        verify_registered_tricore_elf_s3_measurement(
            &elf_bytes,
            &firmware_elf_artifact.sha256,
            &s3_bytes,
            &firmware_measurement_artifact.sha256,
        )
        .map_err(AppError::operational)?;
    }
    Ok(Some(AcceptedTrace32CompletedBinding(
        AcceptedTrace32RuntimeBinding {
            trace32_release: capabilities.trace32_release,
            trace32_build: capabilities.trace32_build,
            architecture_package: capabilities.architecture_package,
            target_identifier: capabilities.target_identifier,
            probe_identifier: capabilities.probe_identifier,
            initial_target_state: capabilities.initial_target_state,
            target_adapter,
            capture_contract,
            qualification_artifact,
            qualification_provenance_artifacts,
            qualification_receipt,
            firmware_elf_artifact,
            firmware_measurement_artifact,
            capabilities_artifact,
            configure_artifact,
            start_artifact,
            health_artifact,
            stop_artifact,
            export_artifact,
            custom_event_artifact,
            cleanup_artifact,
            export_response,
            completion,
        },
    )))
}

pub(crate) fn accepted_trace32_runtime_binding(
    session: &Session,
    artifacts: &[Artifact],
) -> Result<Option<AcceptedTrace32RuntimeBinding>, AppError> {
    let Some(binding) = accepted_trace32_completed_binding(session, artifacts)? else {
        return Ok(None);
    };
    let control = binding.control();
    if control.target_adapter.controller_protocol
        == t32perf_trace32::TargetAdapterControllerProtocol::V2CustomEventsExport
        && control.custom_event_artifact.is_none()
    {
        return Err(AppError::operational(
            "V2 TRACE32 runtime binding requires its ordered custom-event export artifact",
        ));
    }
    match &control.completion {
        ControllerCaptureCompletionEvidence::Sampling { health, .. } => {
            validate_runtime_sampling_state(control.target_adapter.scenario, health)?;
        }
        ControllerCaptureCompletionEvidence::ProgramFlowTaskEvents { health, .. } => {
            validate_runtime_program_flow_state(control.target_adapter.scenario, health)?;
        }
    }
    Ok(Some(binding.into_inner()))
}

fn validate_runtime_sampling_state(
    scenario: TargetAdapterScenario,
    health: &ControllerHealthEvidenceV2,
) -> Result<(), AppError> {
    if scenario != TargetAdapterScenario::Normal
        || health.sampling.buffer_full
        || health.sampling.unexpected_stop
        || health.elf_matches_firmware != Some(true)
    {
        return Err(AppError::operational(
            "TRACE32 runtime binding requires a healthy normal capture scenario",
        ));
    }
    Ok(())
}

fn validate_completed_sampling_state(
    scenario: TargetAdapterScenario,
    expected_capacity_records: u64,
    health: &ControllerHealthEvidenceV2,
    stop: &ControllerStopEvidenceV2,
) -> Result<(), AppError> {
    if health.elf_matches_firmware != Some(true)
        || health.sampling.unexpected_stop
        || health.sampling.capacity_records != expected_capacity_records
        || stop.capacity_records != expected_capacity_records
    {
        return Err(AppError::operational(
            "completed TRACE32 controller binding has incomplete or contradictory sampling health",
        ));
    }
    match scenario {
        TargetAdapterScenario::Normal if health.sampling.buffer_full => Err(AppError::operational(
            "normal TRACE32 controller binding cannot contain buffer-full health",
        )),
        TargetAdapterScenario::SamplingBufferFull if !health.sampling.buffer_full => {
            Err(AppError::operational(
                "sampling-buffer-full controller binding did not observe exact capacity",
            ))
        }
        TargetAdapterScenario::Normal | TargetAdapterScenario::SamplingBufferFull => Ok(()),
        _ => Err(AppError::operational(
            "interruption fault scenario cannot complete the normal Controller chain",
        )),
    }
}

fn validate_runtime_program_flow_state(
    scenario: TargetAdapterScenario,
    health: &ControllerProgramFlowHealthEvidence,
) -> Result<(), AppError> {
    validate_completed_program_flow_state(scenario, health)?;
    if scenario != TargetAdapterScenario::Normal {
        return Err(AppError::operational(
            "TRACE32 runtime binding requires a healthy normal program-flow scenario",
        ));
    }
    Ok(())
}

fn validate_completed_program_flow_state(
    scenario: TargetAdapterScenario,
    health: &ControllerProgramFlowHealthEvidence,
) -> Result<(), AppError> {
    if !health.capture_stopped
        || health.trace_gap
        || health.truncated
        || health.timestamp_discontinuity
        || !health.elf_matches_firmware
    {
        return Err(AppError::operational(
            "completed TASKEVENTS binding contains an unsupported adverse health fact",
        ));
    }
    let exact = match scenario {
        TargetAdapterScenario::Normal => {
            !health.trace_overflow && !health.flow_error && health.program_flow_closed
        }
        TargetAdapterScenario::TraceOverflow => {
            health.trace_overflow && !health.flow_error && !health.program_flow_closed
        }
        TargetAdapterScenario::FlowError => {
            !health.trace_overflow && health.flow_error && !health.program_flow_closed
        }
        _ => false,
    };
    if !exact {
        return Err(AppError::operational(
            "completed TASKEVENTS binding does not match the exact scenario health truth table",
        ));
    }
    Ok(())
}

fn validated_qualification_claim(
    session: &Session,
    artifacts: &[Artifact],
    profile: &TargetAdapterProfile,
    binding: &ControllerTargetAdapterBinding,
) -> Result<(Option<Artifact>, Option<TargetAdapterQualificationReceipt>), AppError> {
    let Some(expected_sha256) = binding.qualification_sha256.as_ref() else {
        return Ok((None, None));
    };
    let artifact = required_deployment_qualification_artifact(artifacts, expected_sha256)?.clone();
    let bytes = read_bounded_bytes_artifact(session, &artifact, 64 * 1024)?;
    let receipt =
        parse_target_adapter_qualification_receipt(&bytes).map_err(AppError::operational)?;
    receipt
        .validate_for(profile, &bytes)
        .map_err(AppError::operational)?;
    Ok((Some(artifact), Some(receipt)))
}

/// Finds the receipt emitted by deployment qualification rather than a
/// controller-owned artifact. Its fixed envelope mirrors the qualification
/// provisioner's immutable contract; controller artifacts intentionally retain
/// their stricter, separate `find_required_artifact` producer rule.
fn required_deployment_qualification_artifact<'a>(
    artifacts: &'a [Artifact],
    expected_sha256: &Sha256Digest,
) -> Result<&'a Artifact, AppError> {
    let artifact = find_artifact(artifacts, TARGET_ADAPTER_QUALIFICATION_ARTIFACT_ID).ok_or_else(
        || {
            AppError::operational(format!(
                "deployment qualification artifact `{TARGET_ADAPTER_QUALIFICATION_ARTIFACT_ID}` is absent"
            ))
        },
    )?;
    let mut expected_inputs = vec![
        crate::controller_qualification::QUALIFICATION_POLICY_ARTIFACT_ID.to_owned(),
        crate::controller_qualification::HIL_VERIFICATION_ARTIFACT_ID.to_owned(),
    ];
    if artifacts.iter().any(|artifact| {
        artifact.id == crate::controller_qualification::HIL_RECOVERY_EVIDENCE_ARTIFACT_ID
    }) {
        expected_inputs
            .push(crate::controller_qualification::HIL_RECOVERY_EVIDENCE_ARTIFACT_ID.to_owned());
    }
    if artifact.kind != TARGET_ADAPTER_QUALIFICATION_KIND
        || artifact.producer != TARGET_ADAPTER_QUALIFICATION_PRODUCER
        || artifact.relative_path.as_str() != crate::controller_qualification::QUALIFICATION_PATH
        || artifact.media_type != "application/json"
        || &artifact.sha256 != expected_sha256
        || artifact.input_artifact_ids != expected_inputs
    {
        return Err(AppError::operational(
            "deployment qualification artifact has invalid identity or provenance",
        ));
    }
    Ok(artifact)
}

fn accepted_export_claim(
    session: &Session,
    artifacts: &[Artifact],
) -> Result<
    (
        Artifact,
        Option<Artifact>,
        ControllerScriptResponse,
        ControllerTargetAdapterBinding,
    ),
    AppError,
> {
    let mut accepted = None;
    for transaction in controller_transaction_ids(artifacts) {
        let request_artifact = find_required_artifact(
            artifacts,
            &request_artifact_id(&transaction),
            CONTROLLER_REQUEST_KIND,
        )?;
        let request = read_controller_request_envelope(session, request_artifact)?;
        if request.operation() != PerfOperation::Export {
            continue;
        }
        validate_request_context_envelope(session, request_artifact, &request, &transaction)?;
        let Some(response_artifact) = find_artifact(artifacts, &response_artifact_id(&transaction))
        else {
            continue;
        };
        let response = read_controller_response_envelope(session, response_artifact)?;
        validate_response(session, request_artifact, &request, &response)?;
        validate_response_artifact_identity(response_artifact, &response)?;
        if response.script_response().status != PerfStatus::Ok {
            continue;
        }
        let target_adapter = request.target_adapter().cloned().ok_or_else(|| {
            AppError::operational("accepted export request has no selected target adapter")
        })?;
        let (expected_code, expected_suffix) = match &target_adapter.capture_kind {
            TargetAdapterCaptureKind::Sampling { .. } => {
                ("raw_ascii_exported", "trace32-ascii.txt")
            }
            TargetAdapterCaptureKind::ProgramFlowTaskEvents { .. } => {
                ("task_events_exported", "trace32-task-events.txt")
            }
        };
        if response.script_response().code != expected_code {
            return Err(AppError::operational(
                "accepted export response code does not match the selected capture kind",
            ));
        }
        let (output, custom_event_artifact) = match (&request, &response) {
            (ControllerRequestEnvelope::V1(_request), ControllerResponseEnvelope::V1(response)) => {
                let output = response.output_artifact.clone().ok_or_else(|| {
                    AppError::operational("accepted export has no immutable output artifact")
                })?;
                let expected_path = ArtifactPath::new(format!(
                    "capture/raw/controller-{transaction}.{expected_suffix}"
                ))
                .map_err(AppError::operational)?;
                if output.kind != "raw_trace"
                    || output.media_type != "text/plain"
                    || output.producer != CONTROLLER_PRODUCER
                    || output.relative_path != expected_path
                    || output.input_artifact_ids != [request_artifact.id.clone()]
                {
                    return Err(AppError::operational(
                        "accepted export artifact envelope does not match the selected capture kind",
                    ));
                }
                (output, None)
            }
            (ControllerRequestEnvelope::V2(request), ControllerResponseEnvelope::V2(response)) => {
                match (
                    request.outputs.as_slice(),
                    response.output_artifacts.as_slice(),
                ) {
                    ([trace, custom], [trace_artifact, custom_artifact])
                        if trace.role == ControllerOutputRoleV2::TraceExport
                            && custom.role == ControllerOutputRoleV2::CustomEvents =>
                    {
                        (trace_artifact.clone(), Some(custom_artifact.clone()))
                    }
                    _ => {
                        return Err(AppError::operational(
                            "accepted V2 export must retain exact ordered TraceExport and CustomEvents artifacts",
                        ));
                    }
                }
            }
            _ => {
                return Err(AppError::operational(
                    "controller request and response use different immutable protocol versions",
                ));
            }
        };
        if accepted
            .replace((
                output,
                custom_event_artifact,
                response.script_response().clone(),
                target_adapter,
            ))
            .is_some()
        {
            return Err(AppError::operational(
                "controller chain has more than one accepted export claim",
            ));
        }
    }
    accepted
        .ok_or_else(|| AppError::operational("complete controller chain has no accepted export"))
}

pub(crate) fn perf_capabilities(
    root: &ArtifactRoot,
    session_id: &str,
) -> Result<CommandOutcome, AppError> {
    ensure_public_surface_normal_scenario(root, session_id)?;
    let progress = controller_capture_progress(root, session_id)?;
    if progress
        .completed_operations
        .contains(&PerfOperation::GetCapabilities)
    {
        let payload = control_payload(
            root,
            session_id,
            &progress,
            PerfControlStatus::CapabilitiesComplete,
            None,
            None,
            PerfNextAction::Invoke {
                operation: PerfSurfaceOperation::Capture,
                required_controller_operation: progress
                    .phase
                    .expected_operation()
                    .map(surface_controller_operation),
            },
        )?;
        return surface_control_success("perf_capabilities", payload);
    }
    if progress.phase != ControllerCapturePhase::Capabilities {
        return Err(AppError::operational(format!(
            "session `{session_id}` cannot run perf_capabilities from phase `{}`",
            progress.phase.as_str()
        )));
    }
    if let Some((transaction_id, operation)) = progress.pending {
        return resume_or_render_pending(root, session_id, transaction_id, operation, true);
    }
    prepare_surface_operation(
        root,
        session_id,
        PerfOperation::GetCapabilities,
        None,
        "perf_capabilities",
    )
}

pub(crate) fn perf_capture(
    root: &ArtifactRoot,
    session_id: &str,
    mode: Option<&str>,
    workload_complete: bool,
) -> Result<CommandOutcome, AppError> {
    ensure_public_surface_normal_scenario(root, session_id)?;
    let progress = controller_capture_progress(root, session_id)?;
    if let Some((transaction_id, operation)) = progress.pending {
        if workload_complete {
            return Err(AppError::operational(
                "--workload-complete cannot be acknowledged while a controller transaction is pending",
            ));
        }
        return resume_or_render_pending(root, session_id, transaction_id, operation, false);
    }

    if progress.phase == ControllerCapturePhase::Complete {
        if workload_complete {
            return Err(AppError::operational(
                "--workload-complete is only valid while stop is the required capture phase",
            ));
        }
        if mode.is_some() {
            return Err(AppError::operational(
                "--mode is only valid while export is the required capture phase",
            ));
        }
        return render_capture_control_complete(root, session_id, &progress);
    }

    let operation = progress
        .phase
        .expected_operation()
        .expect("nonterminal controller phase has an operation");
    if progress.phase == ControllerCapturePhase::Stop && !workload_complete {
        if mode.is_some() {
            return Err(AppError::operational(
                "--mode is only valid while export is the required capture phase",
            ));
        }
        let payload = control_payload(
            root,
            session_id,
            &progress,
            PerfControlStatus::WorkloadRequired,
            None,
            None,
            PerfNextAction::RunWorkload {
                ownership: "target_specific_controller".to_owned(),
                resume: PerfResumeAction {
                    operation: PerfSurfaceOperation::Capture,
                    arguments: vec!["--workload-complete".to_owned()],
                },
            },
        )?;
        return surface_control_success("perf_capture", payload);
    }
    if workload_complete && progress.phase != ControllerCapturePhase::Stop {
        return Err(AppError::operational(
            "--workload-complete is only valid while stop is the required capture phase",
        ));
    }
    if progress.phase != ControllerCapturePhase::Export && mode.is_some() {
        return Err(AppError::operational(
            "--mode is only valid while export is the required capture phase",
        ));
    }
    let selected_mode = if progress.phase == ControllerCapturePhase::Export {
        let expected = selected_capture_export_mode(root, session_id)?;
        match mode {
            None => Some(expected),
            Some(actual) if actual == expected => Some(expected),
            Some(actual) => {
                return Err(AppError::operational(format!(
                    "export mode `{actual}` does not match admitted adapter mode `{expected}`"
                )));
            }
        }
    } else {
        mode
    };
    prepare_surface_operation(root, session_id, operation, selected_mode, "perf_capture")
}

/// The performance facade is deliberately a normal-capture API. Deployment
/// fault scenarios are selected only through the low-level controller command
/// and must never turn a public `perf_*` resume/collect request into a fault
/// injection primitive.
fn ensure_public_surface_normal_scenario(
    root: &ArtifactRoot,
    session_id: &str,
) -> Result<(), AppError> {
    let session = open_session(root, session_id)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    let Some(artifact) = artifacts
        .iter()
        .find(|artifact| artifact.id == TARGET_ADAPTER_SCENARIO_ARTIFACT_ID)
    else {
        return Ok(());
    };
    if artifact.kind != TARGET_ADAPTER_SCENARIO_KIND
        || artifact.relative_path.as_str() != TARGET_ADAPTER_SCENARIO_PATH
        || artifact.media_type != "application/json"
        || artifact.producer != TARGET_ADAPTER_SCENARIO_PRODUCER
    {
        return Err(AppError::operational(
            "target-adapter scenario artifact has an invalid reserved identity",
        ));
    }
    let selection = parse_target_adapter_scenario_selection(&read_bounded_bytes_artifact(
        &session,
        artifact,
        MAX_CONTROLLER_EVIDENCE_BYTES,
    )?)
    .map_err(AppError::operational)?;
    if selection.scenario != TargetAdapterScenario::Normal {
        return Err(AppError {
            code: "PERF_SURFACE_FAULT_SCENARIO_FORBIDDEN",
            message:
                "fault-injection scenarios are available only through low-level controller commands"
                    .to_owned(),
            details: json!({
                "session_id": session.id().as_str(),
                "scenario": selection.scenario,
                "required_surface": "controller",
            }),
            exit_code: EXIT_OPERATIONAL,
        });
    }
    Ok(())
}

fn prepare_surface_operation(
    root: &ArtifactRoot,
    session_id: &str,
    operation: PerfOperation,
    mode: Option<&str>,
    command: &'static str,
) -> Result<CommandOutcome, AppError> {
    prepare(root, session_id, operation.as_str(), mode)?;
    let progress = controller_capture_progress(root, session_id)?;
    let (transaction_id, pending_operation) = progress.pending.clone().ok_or_else(|| {
        AppError::operational("controller prepare did not create a pending transaction")
    })?;
    if pending_operation != operation {
        return Err(AppError::operational(
            "controller prepare created a transaction for the wrong operation",
        ));
    }
    let (request, request_artifact, response_handoff) =
        pending_request(root, session_id, &transaction_id)?;
    let next_action = PerfNextAction::Execute {
        mcp: surface_execute_call(&request),
        response_handoff,
    };
    let payload = control_payload(
        root,
        session_id,
        &progress,
        PerfControlStatus::Prepared,
        Some(surface_controller_operation(operation)),
        Some((transaction_id, request_artifact)),
        next_action,
    )?;
    surface_control_success(command, payload)
}

fn resume_or_render_pending(
    root: &ArtifactRoot,
    session_id: &str,
    transaction_id: String,
    operation: PerfOperation,
    capabilities_only: bool,
) -> Result<CommandOutcome, AppError> {
    let (_request, request_artifact, response_handoff) =
        pending_request(root, session_id, &transaction_id)?;
    let progress = controller_capture_progress(root, session_id)?;
    let response_path = std::path::PathBuf::from(&response_handoff.path);
    match std::fs::symlink_metadata(&response_path) {
        Ok(_) => {
            accept(root, session_id, &transaction_id)?;
            let progress = controller_capture_progress(root, session_id)?;
            let next_action = if capabilities_only {
                PerfNextAction::Invoke {
                    operation: PerfSurfaceOperation::Capture,
                    required_controller_operation: progress
                        .phase
                        .expected_operation()
                        .map(surface_controller_operation),
                }
            } else {
                next_capture_action(&progress)
            };
            let payload = control_payload(
                root,
                session_id,
                &progress,
                PerfControlStatus::OperationCompleted,
                None,
                None,
                next_action,
            )?;
            surface_control_success(
                if capabilities_only {
                    "perf_capabilities"
                } else {
                    "perf_capture"
                },
                payload,
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let next_action = PerfNextAction::Collect {
                mcp: PerfCollectCall {
                    tool: PerfMcpTool::CollectPracticeSkillResponse,
                    arguments: PerfNoArguments::default(),
                },
                response_handoff,
                abort_available: true,
            };
            let payload = control_payload(
                root,
                session_id,
                &progress,
                PerfControlStatus::Pending,
                Some(surface_controller_operation(operation)),
                Some((transaction_id, request_artifact)),
                next_action,
            )?;
            surface_control_success(
                if capabilities_only {
                    "perf_capabilities"
                } else {
                    "perf_capture"
                },
                payload,
            )
        }
        Err(error) => Err(AppError::operational(format!(
            "cannot inspect controller response staging path `{}`: {error}",
            response_path.display()
        ))),
    }
}

fn next_capture_action(progress: &ControllerProgress) -> PerfNextAction {
    match progress.phase {
        ControllerCapturePhase::Stop => PerfNextAction::RunWorkload {
            ownership: "target_specific_controller".to_owned(),
            resume: PerfResumeAction {
                operation: PerfSurfaceOperation::Capture,
                arguments: vec!["--workload-complete".to_owned()],
            },
        },
        ControllerCapturePhase::Complete => PerfNextAction::Invoke {
            operation: PerfSurfaceOperation::Capture,
            required_controller_operation: None,
        },
        phase => PerfNextAction::Invoke {
            operation: PerfSurfaceOperation::Capture,
            required_controller_operation: phase
                .expected_operation()
                .map(surface_controller_operation),
        },
    }
}

fn render_capture_control_complete(
    root: &ArtifactRoot,
    session_id: &str,
    progress: &ControllerProgress,
) -> Result<CommandOutcome, AppError> {
    let next_action = if progress.phase == ControllerCapturePhase::Complete {
        PerfNextAction::CaptureConfigReady {
            capture_config: PerfArtifactReference::from(
                &crate::controller_capture_config::ensure_for_completed_session(root, session_id)?,
            ),
        }
    } else {
        next_capture_action(progress)
    };
    let payload = control_payload(
        root,
        session_id,
        progress,
        PerfControlStatus::ControlComplete,
        None,
        None,
        next_action,
    )?;
    surface_control_success("perf_capture", payload)
}

fn pending_request(
    root: &ArtifactRoot,
    session_id: &str,
    transaction_id: &str,
) -> Result<(ControllerRequestEnvelope, Artifact, PerfResponseHandoff), AppError> {
    let session = open_session(root, session_id)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    let request_artifact = find_required_artifact(
        &artifacts,
        &request_artifact_id(transaction_id),
        CONTROLLER_REQUEST_KIND,
    )?
    .clone();
    let request = read_controller_request_envelope(&session, &request_artifact)?;
    validate_request_context_envelope(&session, &request_artifact, &request, transaction_id)?;
    let response_path = session
        .staging_path(request.response_staging_path())
        .map_err(AppError::operational)?;
    let handoff = PerfResponseHandoff {
        path: response_path
            .to_str()
            .ok_or_else(|| AppError::operational("controller response path is not UTF-8"))?
            .to_owned(),
        max_bytes: request.max_response_bytes(),
        instruction: "write only the exact final <FINISHED>/<CONTENT> wrapper, then invoke this perf surface again".to_owned(),
    };
    Ok((request, request_artifact, handoff))
}

fn surface_execute_call(request: &ControllerRequestEnvelope) -> PerfExecuteCall {
    PerfExecuteCall {
        tool: PerfMcpTool::ExecutePracticeSkill,
        arguments: PerfExecuteArguments {
            skill_name: request.mcp().execute.arguments.skill_name.clone(),
            script_name: request.mcp().execute.arguments.script_name.clone(),
            script_args: request.mcp().execute.arguments.script_args.clone(),
        },
    }
}

fn control_payload(
    root: &ArtifactRoot,
    session_id: &str,
    progress: &ControllerProgress,
    status: PerfControlStatus,
    pending_operation: Option<PerfControllerOperation>,
    transaction: Option<(String, Artifact)>,
    next_action: PerfNextAction,
) -> Result<PerfControlPayload, AppError> {
    let (transaction_id, request_artifact) = transaction
        .map(|(transaction_id, artifact)| (Some(transaction_id), Some(artifact)))
        .unwrap_or((None, None));
    let completed_operations = CONTROLLER_CAPTURE_SEQUENCE
        .iter()
        .chain([PerfOperation::GetHotspots].iter())
        .filter(|operation| progress.completed_operations.contains(operation))
        .copied()
        .map(surface_controller_operation)
        .collect();
    Ok(PerfControlPayload {
        session_id: session_id.to_owned(),
        state: progress.state,
        capture_phase: surface_capture_phase(progress.phase),
        status,
        completed_operations,
        pending_operation,
        transaction_id,
        request_artifact,
        capture_artifacts: surface_capture_artifacts(root, session_id)?,
        next_action,
    })
}

fn surface_capture_artifacts(
    root: &ArtifactRoot,
    session_id: &str,
) -> Result<Vec<Artifact>, AppError> {
    let session = open_session(root, session_id)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    let mut selected = Vec::new();
    for artifact in &artifacts {
        match artifact.kind.as_str() {
            "raw_trace" | "trace32_control_evidence" => selected.push(artifact.clone()),
            "custom_events" if accepted_custom_event_artifact(&session, &artifacts, artifact)? => {
                selected.push(artifact.clone());
            }
            "custom_events" => {}
            _ => {}
        }
    }
    if selected.len() > 8 {
        return Err(AppError::operational(
            "controller capture artifact count exceeds the typed façade bound",
        ));
    }
    Ok(selected)
}

fn accepted_custom_event_artifact(
    session: &Session,
    artifacts: &[Artifact],
    artifact: &Artifact,
) -> Result<bool, AppError> {
    if artifact.producer != CONTROLLER_PRODUCER || artifact.input_artifact_ids.len() != 1 {
        return Ok(false);
    }
    let Some(transaction) = artifact.input_artifact_ids[0].strip_prefix("controller-request-")
    else {
        return Ok(false);
    };
    let request_artifact = find_required_artifact(
        artifacts,
        &request_artifact_id(transaction),
        CONTROLLER_REQUEST_KIND,
    )?;
    let request = read_controller_request_envelope(session, request_artifact)?;
    validate_request_context_envelope(session, request_artifact, &request, transaction)?;
    let Some(response_artifact) = find_artifact(artifacts, &response_artifact_id(transaction))
    else {
        return Ok(false);
    };
    let response = read_controller_response_envelope(session, response_artifact)?;
    validate_response(session, request_artifact, &request, &response)?;
    validate_response_artifact_identity(response_artifact, &response)?;
    Ok(matches!(request, ControllerRequestEnvelope::V2(_))
        && request.operation() == PerfOperation::Export
        && response.script_response().status == PerfStatus::Ok
        && response
            .output_artifacts()
            .into_iter()
            .any(|output| output.id == artifact.id))
}

const fn surface_capture_phase(phase: ControllerCapturePhase) -> SurfaceCapturePhase {
    match phase {
        ControllerCapturePhase::Capabilities => SurfaceCapturePhase::CapabilitiesRequired,
        ControllerCapturePhase::Configure => SurfaceCapturePhase::ConfigureRequired,
        ControllerCapturePhase::Start => SurfaceCapturePhase::StartRequired,
        ControllerCapturePhase::Stop => SurfaceCapturePhase::StopRequired,
        ControllerCapturePhase::Health => SurfaceCapturePhase::HealthRequired,
        ControllerCapturePhase::Export => SurfaceCapturePhase::ExportRequired,
        ControllerCapturePhase::Cleanup => SurfaceCapturePhase::CleanupRequired,
        ControllerCapturePhase::Complete => SurfaceCapturePhase::CaptureComplete,
    }
}

const fn surface_controller_operation(operation: PerfOperation) -> PerfControllerOperation {
    match operation {
        PerfOperation::GetCapabilities => PerfControllerOperation::GetCapabilities,
        PerfOperation::Configure => PerfControllerOperation::Configure,
        PerfOperation::Start => PerfControllerOperation::Start,
        PerfOperation::Stop => PerfControllerOperation::Stop,
        PerfOperation::GetHealth => PerfControllerOperation::GetHealth,
        PerfOperation::Export => PerfControllerOperation::Export,
        PerfOperation::GetHotspots => PerfControllerOperation::GetHotspots,
        PerfOperation::Cleanup => PerfControllerOperation::Cleanup,
    }
}

fn surface_control_success(
    command: &'static str,
    payload: PerfControlPayload,
) -> Result<CommandOutcome, AppError> {
    success(
        command,
        serde_json::to_value(payload).map_err(AppError::operational)?,
    )
}

fn controller_progress_from_artifacts(
    root: Option<&ArtifactRoot>,
    session: &Session,
    artifacts: &[Artifact],
) -> Result<ControllerProgress, AppError> {
    let state = session.read_state().map_err(AppError::operational)?;
    let mut completed_operations = BTreeSet::new();
    let mut accepted_evidence = BTreeMap::new();
    let mut accepted_evidence_artifacts = BTreeMap::new();
    let mut accepted_responses = BTreeMap::new();
    let mut selected_target_adapter = None;
    let mut pending = None;
    let mut accepted_cleanup_transaction = None;
    for transaction in controller_transaction_ids(artifacts) {
        let request_artifact = find_required_artifact(
            artifacts,
            &request_artifact_id(&transaction),
            CONTROLLER_REQUEST_KIND,
        )?;
        let request = read_controller_request_envelope(session, request_artifact)?;
        validate_request_context_envelope(session, request_artifact, &request, &transaction)?;
        if let Some(binding) = request.target_adapter()
            && selected_target_adapter
                .replace(binding.clone())
                .is_some_and(|selected| selected != *binding)
        {
            return Err(AppError::operational(
                "controller requests do not reuse one immutable target-adapter selection",
            ));
        }
        let response_artifact = find_artifact(artifacts, &response_artifact_id(&transaction));
        let abort_receipt_artifact =
            find_artifact(artifacts, &abort_receipt_artifact_id(&transaction));
        if response_artifact.is_some() && abort_receipt_artifact.is_some() {
            return Err(AppError::operational(format!(
                "controller transaction `{transaction}` has both a response and abort receipt"
            )));
        }
        if let Some(response_artifact) = response_artifact {
            if response_artifact.kind != CONTROLLER_RESPONSE_KIND
                || response_artifact.producer != CONTROLLER_PRODUCER
            {
                return Err(AppError::operational(format!(
                    "controller response artifact for transaction `{transaction}` has invalid identity"
                )));
            }
            let response = read_controller_response_envelope(session, response_artifact)?;
            validate_response(session, request_artifact, &request, &response)?;
            validate_response_artifact_identity(response_artifact, &response)?;
            let completed = match response.script_response().status {
                PerfStatus::Ok => true,
                PerfStatus::HostProcessingRequired => {
                    request.operation() == PerfOperation::GetHotspots
                }
                PerfStatus::UnsupportedNeedsTrace32 | PerfStatus::InvalidArgument => false,
            };
            if completed && !completed_operations.insert(request.operation()) {
                return Err(AppError::operational(format!(
                    "controller operation `{}` has more than one accepted completion",
                    request.operation().as_str()
                )));
            }
            if completed && request.operation() == PerfOperation::Cleanup {
                accepted_cleanup_transaction = Some(transaction.clone());
            }
            if response.script_response().status == PerfStatus::Ok {
                let script_response = PerfScriptResponse {
                    protocol: T32PERF_PROTOCOL,
                    operation: response.script_response().operation,
                    status: response.script_response().status,
                    code: response.script_response().code.clone(),
                    binding_sha256: request.binding().binding_sha256.to_string(),
                    files_deleted: response.script_response().files_deleted,
                };
                if accepted_responses
                    .insert(request.operation(), script_response)
                    .is_some()
                {
                    return Err(AppError::operational(format!(
                        "controller operation `{}` has duplicate accepted responses",
                        request.operation().as_str()
                    )));
                }
            }
            if let Some(output) = accepted_machine_evidence_artifact(&request, &response)? {
                let evidence = read_envelope_evidence_artifact(session, &request, output)?;
                if accepted_evidence
                    .insert(request.operation(), evidence)
                    .is_some()
                {
                    return Err(AppError::operational(format!(
                        "controller operation `{}` has duplicate accepted evidence",
                        request.operation().as_str()
                    )));
                }
                accepted_evidence_artifacts.insert(request.operation(), output.clone());
            }
            continue;
        }
        if let Some(receipt_artifact) = abort_receipt_artifact {
            let abort_request_artifact = find_required_artifact(
                artifacts,
                &abort_artifact_id(&transaction),
                CONTROLLER_ABORT_REQUEST_KIND,
            )?;
            let abort_request: ControllerAbortRequest = read_bounded_json_artifact(
                session,
                abort_request_artifact,
                MAX_CONTROLLER_REQUEST_BYTES,
            )?;
            let receipt: ControllerAbortReceipt = read_bounded_json_artifact(
                session,
                receipt_artifact,
                MAX_CONTROLLER_RESPONSE_BYTES,
            )?;
            validate_abort_receipt_envelope(
                &request,
                request_artifact,
                &abort_request,
                abort_request_artifact,
                &receipt,
            )?;
            let abort_closed = if state.status == SessionStatus::Failed {
                match root {
                    Some(root) => crate::controller_recovery::has_durable_abort_quarantine(
                        root,
                        session.id().as_str(),
                        &transaction,
                    )?,
                    None => false,
                }
            } else {
                false
            };
            if !abort_closed {
                return Err(AppError {
                    code: "CONTROLLER_ABORT_RECOVERY_REQUIRED",
                    message: "abort receipt exists without a terminal failed Session and durable quarantine"
                        .to_owned(),
                    details: json!({
                        "session_id": session.id().as_str(),
                        "transaction_id": transaction,
                    }),
                    exit_code: EXIT_OPERATIONAL,
                });
            }
            continue;
        }
        if pending
            .replace((transaction.clone(), request.operation()))
            .is_some()
        {
            return Err(AppError::operational(
                "Session contains more than one pending controller transaction",
            ));
        }
    }

    let mut completed_prefix = 0_usize;
    while completed_prefix < CONTROLLER_CAPTURE_SEQUENCE.len()
        && completed_operations.contains(&CONTROLLER_CAPTURE_SEQUENCE[completed_prefix])
    {
        completed_prefix += 1;
    }
    if CONTROLLER_CAPTURE_SEQUENCE[completed_prefix..]
        .iter()
        .any(|operation| completed_operations.contains(operation))
    {
        return Err(AppError::operational(
            "controller capture completions do not form the required ordered prefix",
        ));
    }
    let main_complete = completed_prefix == CONTROLLER_CAPTURE_SEQUENCE.len();
    for optional in [PerfOperation::GetHotspots] {
        if completed_operations.contains(&optional) && !main_complete {
            return Err(AppError::operational(format!(
                "optional controller operation `{}` completed before the capture chain",
                optional.as_str()
            )));
        }
    }
    validate_controller_evidence_chain(
        session,
        artifacts,
        &accepted_evidence,
        &accepted_evidence_artifacts,
        &accepted_responses,
    )?;
    if let (Some(capabilities), Some(selected_target_adapter)) = (
        accepted_evidence.get(&PerfOperation::GetCapabilities),
        selected_target_adapter.as_ref(),
    ) {
        let (admission_profile, catalog, _, _) =
            crate::controller_qualification::load_session_admission(session, artifacts)?;
        let scenario = selected_target_adapter.scenario;
        let expected = target_adapter_binding(
            catalog
                .select(&target_adapter_selection_from_capabilities(
                    capabilities,
                    &admission_profile,
                )?)
                .map_err(AppError::operational)?,
            scenario,
        )?;
        if selected_target_adapter != &expected {
            return Err(AppError::operational(
                "controller target-adapter selection does not match accepted capabilities",
            ));
        }
    }
    let phase = match completed_prefix {
        0 => ControllerCapturePhase::Capabilities,
        1 => ControllerCapturePhase::Configure,
        2 => ControllerCapturePhase::Start,
        3 => ControllerCapturePhase::Stop,
        4 => ControllerCapturePhase::Health,
        5 => ControllerCapturePhase::Export,
        6 => ControllerCapturePhase::Cleanup,
        7 => ControllerCapturePhase::Complete,
        _ => unreachable!("fixed capture sequence length"),
    };
    let capture_config_ready = if phase == ControllerCapturePhase::Complete && root.is_some() {
        authoritative_controller_capture_config_exists(session, artifacts)?
    } else {
        true
    };
    let (phase, pending) = gate_completed_capture_config(
        phase,
        pending,
        accepted_cleanup_transaction,
        capture_config_ready,
    )?;
    if let Some((transaction, operation)) = &pending {
        let allowed = phase.expected_operation() == Some(*operation)
            || (phase == ControllerCapturePhase::Complete
                && matches!(operation, PerfOperation::GetHotspots)
                && !completed_operations.contains(operation));
        if !allowed {
            return Err(AppError::operational(format!(
                "pending controller transaction `{transaction}` for `{}` does not match capture phase `{}`",
                operation.as_str(),
                phase.as_str()
            )));
        }
    }
    Ok(ControllerProgress {
        state: state.status,
        phase,
        completed_operations,
        pending,
    })
}

fn gate_completed_capture_config(
    phase: ControllerCapturePhase,
    pending: Option<(String, PerfOperation)>,
    accepted_cleanup_transaction: Option<String>,
    capture_config_ready: bool,
) -> Result<(ControllerCapturePhase, Option<(String, PerfOperation)>), AppError> {
    if phase != ControllerCapturePhase::Complete || capture_config_ready {
        return Ok((phase, pending));
    }
    if pending.is_some() {
        return Err(AppError::operational(
            "controller capture has accepted cleanup without capture-config while another transaction is pending",
        ));
    }
    let transaction = accepted_cleanup_transaction.ok_or_else(|| {
        AppError::operational(
            "controller capture completion has no immutable cleanup transaction identity",
        )
    })?;
    Ok((
        ControllerCapturePhase::Cleanup,
        Some((transaction, PerfOperation::Cleanup)),
    ))
}

fn authoritative_controller_capture_config_exists(
    session: &Session,
    artifacts: &[Artifact],
) -> Result<bool, AppError> {
    let Some(artifact) = find_artifact(artifacts, crate::capture_config::CAPTURE_CONFIG_ID) else {
        return Ok(false);
    };
    if artifact.producer != crate::controller_capture_config::CONTROLLER_CAPTURE_CONFIG_PRODUCER {
        return Err(AppError::operational(
            "completed Controller capture has a capture-config with invalid producer authority",
        ));
    }
    crate::capture_config::registered_capture_config(session, artifacts)
        .map_err(AppError::operational)?;
    Ok(true)
}

fn validate_controller_evidence_chain(
    session: &Session,
    artifacts: &[Artifact],
    evidence: &BTreeMap<PerfOperation, ControllerEvidence>,
    evidence_artifacts: &BTreeMap<PerfOperation, Artifact>,
    responses: &BTreeMap<PerfOperation, PerfScriptResponse>,
) -> Result<(), AppError> {
    if let (Some(capabilities), Some(ControllerEvidence::Configure(configure))) = (
        evidence.get(&PerfOperation::GetCapabilities),
        evidence.get(&PerfOperation::Configure),
    ) {
        let capabilities = capabilities_view(capabilities)?;
        if !capabilities.capture_modes.contains(&configure.capture_mode)
            || !capabilities.trace_sinks.contains(&configure.trace_sink)
            || configure
                .covered_cores
                .iter()
                .any(|core| !capabilities.covered_cores.contains(core))
            || (configure.timestamp_enabled && !capabilities.timestamp_supported)
            || capabilities
                .initial_target_state
                .is_some_and(|initial| initial != configure.initial_target_state)
        {
            return Err(AppError::operational(
                "accepted configure evidence exceeds the preceding capability evidence",
            ));
        }
    }
    if let Some(ControllerEvidence::Configure(configure)) = evidence.get(&PerfOperation::Configure)
    {
        let mismatch = match evidence.get(&PerfOperation::Start) {
            Some(ControllerEvidence::Start(start)) => {
                configure.initial_target_state != start.initial_target_state
                    || configure.workload_identity != start.workload_identity
            }
            Some(ControllerEvidence::StartV2(start)) => {
                configure.initial_target_state != start.initial_target_state
                    || configure.workload_identity != start.workload_identity
            }
            _ => false,
        };
        if mismatch {
            return Err(AppError::operational(
                "accepted start evidence does not match the configured target state and workload",
            ));
        }
    }
    if let Some(start_workload) =
        evidence
            .get(&PerfOperation::Start)
            .and_then(|start| match start {
                ControllerEvidence::Start(start) => Some(start.workload_identity.as_str()),
                ControllerEvidence::StartV2(start) => Some(start.workload_identity.as_str()),
                _ => None,
            })
    {
        match evidence.get(&PerfOperation::Stop) {
            Some(ControllerEvidence::Stop(stop)) if start_workload != stop.workload_identity => {
                return Err(AppError::operational(
                    "accepted stop evidence does not match the started workload",
                ));
            }
            Some(ControllerEvidence::StopV2(stop)) if start_workload != stop.workload_identity => {
                return Err(AppError::operational(
                    "accepted sampling stop evidence does not match the started workload",
                ));
            }
            _ => {}
        }
    }
    if let (Some(ControllerEvidence::Configure(configure)), Some(ControllerEvidence::StopV2(stop))) = (
        evidence.get(&PerfOperation::Configure),
        evidence.get(&PerfOperation::Stop),
    ) && configure.initial_target_state != stop.target_state_after_stop
    {
        return Err(AppError::operational(
            "sampling adapter changed target execution state across capture",
        ));
    }
    validate_selected_target_adapter_chain(
        session,
        artifacts,
        evidence,
        evidence_artifacts,
        responses,
    )
}

fn validate_selected_target_adapter_chain(
    session: &Session,
    artifacts: &[Artifact],
    evidence: &BTreeMap<PerfOperation, ControllerEvidence>,
    evidence_artifacts: &BTreeMap<PerfOperation, Artifact>,
    responses: &BTreeMap<PerfOperation, PerfScriptResponse>,
) -> Result<(), AppError> {
    let Some(capabilities) = evidence.get(&PerfOperation::GetCapabilities) else {
        return Ok(());
    };
    let has_target_evidence = [
        PerfOperation::Configure,
        PerfOperation::Start,
        PerfOperation::Stop,
        PerfOperation::GetHealth,
        PerfOperation::Cleanup,
    ]
    .iter()
    .any(|operation| evidence.contains_key(operation))
        || responses.contains_key(&PerfOperation::Export);
    if !has_target_evidence {
        return Ok(());
    }
    let (admission_profile, catalog, admission_provenance, allowed_scenarios) =
        crate::controller_qualification::load_session_admission(session, artifacts)?;
    let admitted = catalog
        .select(&target_adapter_selection_from_capabilities(
            capabilities,
            &admission_profile,
        )?)
        .map_err(AppError::operational)?;
    let profile = &admitted.profile;
    let (scenario, _) = selected_target_adapter_scenario(
        session,
        artifacts,
        &admission_profile,
        &admission_provenance,
        &allowed_scenarios,
    )?;
    let mut run = TargetAdapterRun::new(profile, scenario).map_err(AppError::operational)?;
    for operation in [
        PerfOperation::GetCapabilities,
        PerfOperation::Configure,
        PerfOperation::Start,
        PerfOperation::Stop,
        PerfOperation::GetHealth,
    ] {
        if let Some(step) = evidence.get(&operation) {
            if operation == PerfOperation::Stop {
                let artifact = evidence_artifacts.get(&operation).ok_or_else(|| {
                    AppError::operational("accepted Stop evidence has no immutable artifact digest")
                })?;
                run.accept_evidence_artifact(step, &artifact.sha256)
                    .map_err(AppError::operational)?;
            } else {
                run.accept_evidence(step).map_err(AppError::operational)?;
            }
        } else {
            break;
        }
    }
    if let Some(export) = responses.get(&PerfOperation::Export) {
        run.accept_export(export).map_err(AppError::operational)?;
    }
    if let Some(cleanup) = evidence.get(&PerfOperation::Cleanup) {
        run.accept_evidence(cleanup)
            .map_err(AppError::operational)?;
    }
    Ok(())
}

fn validate_sampling_evidence_chain(
    session: &Session,
    artifacts: &[Artifact],
    evidence: &BTreeMap<PerfOperation, ControllerEvidence>,
) -> Result<(), AppError> {
    let Some(ControllerEvidence::HealthV2(health)) = evidence.get(&PerfOperation::GetHealth) else {
        return Ok(());
    };
    let progress = controller_progress_from_artifacts(None, session, artifacts)?;
    let Some((stop_artifact, ControllerEvidence::StopV2(stop))) =
        accepted_controller_evidence(session, artifacts, &progress, PerfOperation::Stop)?
    else {
        return Err(AppError::operational(
            "sampling health requires accepted sampling stop evidence",
        ));
    };
    let expected_buffer_full = stop.pre_stop_state
        == t32perf_trace32::ControllerSamplingPreStopState::Break
        && stop.recorded_records == stop.capacity_records;
    let expected_unexpected_stop = stop.pre_stop_state
        == t32perf_trace32::ControllerSamplingPreStopState::Break
        && stop.recorded_records < stop.capacity_records;
    if health.stop_evidence_sha256 != stop_artifact.sha256
        || health.sampling.pre_stop_state != stop.pre_stop_state
        || health.sampling.recorded_records != stop.recorded_records
        || health.sampling.capacity_records != stop.capacity_records
        || health.sampling.buffer_full != expected_buffer_full
        || health.sampling.unexpected_stop != expected_unexpected_stop
    {
        return Err(AppError::operational(
            "sampling health does not match immutable stop evidence",
        ));
    }
    Ok(())
}

fn ensure_operation_matches_progress(
    session: &Session,
    state: SessionStatus,
    operation: PerfOperation,
    progress: &ControllerProgress,
) -> Result<(), AppError> {
    let state_allowed = match progress.phase {
        ControllerCapturePhase::Capabilities | ControllerCapturePhase::Configure => {
            state == SessionStatus::Created
        }
        ControllerCapturePhase::Start => state == SessionStatus::Created,
        ControllerCapturePhase::Stop => state == SessionStatus::Capturing,
        ControllerCapturePhase::Health
        | ControllerCapturePhase::Export
        | ControllerCapturePhase::Cleanup
        | ControllerCapturePhase::Complete => state == SessionStatus::Captured,
    };
    if !state_allowed {
        return Err(AppError::operational(format!(
            "controller capture phase `{}` cannot run while Session state is {state:?}; retry the accepted stage transaction if state reconciliation was interrupted",
            progress.phase.as_str()
        )));
    }
    if let Some(expected) = progress.phase.expected_operation() {
        if operation != expected {
            return Err(AppError {
                code: "CONTROLLER_OPERATION_OUT_OF_SEQUENCE",
                message: format!(
                    "session `{}` requires `{}` before `{}`",
                    session.id(),
                    expected.as_str(),
                    operation.as_str()
                ),
                details: json!({
                    "session_id": session.id().as_str(),
                    "capture_phase": progress.phase.as_str(),
                    "next_required_operation": expected,
                    "requested_operation": operation,
                }),
                exit_code: EXIT_OPERATIONAL,
            });
        }
        return Ok(());
    }
    if !matches!(operation, PerfOperation::GetHotspots) {
        return Err(AppError {
            code: "CONTROLLER_CAPTURE_ALREADY_COMPLETE",
            message: format!(
                "session `{}` has already completed the controller capture chain",
                session.id()
            ),
            details: json!({
                "session_id": session.id().as_str(),
                "capture_phase": progress.phase.as_str(),
                "requested_operation": operation,
            }),
            exit_code: EXIT_OPERATIONAL,
        });
    }
    if progress.completed_operations.contains(&operation) {
        return Err(AppError {
            code: "CONTROLLER_OPERATION_ALREADY_COMPLETE",
            message: format!(
                "optional controller operation `{}` already has an accepted completion",
                operation.as_str()
            ),
            details: json!({
                "session_id": session.id().as_str(),
                "capture_phase": progress.phase.as_str(),
                "requested_operation": operation,
            }),
            exit_code: EXIT_OPERATIONAL,
        });
    }
    Ok(())
}

fn pending_transactions(
    root: &ArtifactRoot,
    session: &Session,
    artifacts: &[Artifact],
) -> Result<Vec<String>, AppError> {
    let mut pending = Vec::new();
    for transaction in controller_transaction_ids(artifacts) {
        if find_artifact(artifacts, &response_artifact_id(&transaction)).is_some() {
            continue;
        }
        let abort_closed = find_artifact(artifacts, &abort_receipt_artifact_id(&transaction))
            .is_some()
            && session.read_state().map_err(AppError::operational)?.status == SessionStatus::Failed
            && crate::controller_recovery::has_durable_abort_quarantine(
                root,
                session.id().as_str(),
                &transaction,
            )?;
        if !abort_closed {
            pending.push(transaction);
        }
    }
    Ok(pending)
}

fn root_active_transaction(root: &ArtifactRoot) -> Result<Option<(String, String)>, AppError> {
    for session_id in root.list_sessions().map_err(AppError::operational)? {
        let session = root.session(&session_id).map_err(AppError::operational)?;
        let artifacts = session
            .registered_artifacts(false)
            .map_err(AppError::operational)?;
        let state = session.read_state().map_err(AppError::operational)?;
        for transaction in controller_transaction_ids(&artifacts) {
            if find_artifact(&artifacts, &response_artifact_id(&transaction)).is_some() {
                let request_artifact = find_required_artifact(
                    &artifacts,
                    &request_artifact_id(&transaction),
                    CONTROLLER_REQUEST_KIND,
                )?;
                let request = read_controller_request_envelope(&session, request_artifact)?;
                validate_request_context_envelope(
                    &session,
                    request_artifact,
                    &request,
                    &transaction,
                )?;
                if request.operation() == PerfOperation::Cleanup
                    && !authoritative_controller_capture_config_exists(&session, &artifacts)?
                {
                    return Ok(Some((session_id.to_string(), transaction)));
                }
                continue;
            }
            if find_artifact(&artifacts, &abort_receipt_artifact_id(&transaction)).is_some()
                && state.status == SessionStatus::Failed
                && crate::controller_recovery::has_durable_abort_quarantine(
                    root,
                    session_id.as_str(),
                    &transaction,
                )?
            {
                continue;
            }
            let request_artifact = find_required_artifact(
                &artifacts,
                &request_artifact_id(&transaction),
                CONTROLLER_REQUEST_KIND,
            )?;
            let request = read_controller_request_envelope(&session, request_artifact)?;
            validate_request_context_envelope(&session, request_artifact, &request, &transaction)?;
            return Ok(Some((session_id.to_string(), transaction)));
        }
    }
    Ok(None)
}

/// Reconstructs the durable root-wide capture lease from immutable controller
/// responses and Session state. A successful capabilities response claims the
/// single TRACE32 endpoint until Cleanup completes. Pending requests remain
/// governed by `root_active_transaction`, while failed Sessions are governed
/// by durable quarantine and typed recovery.
fn root_capture_lease(
    root: &ArtifactRoot,
) -> Result<Option<(String, ControllerCapturePhase)>, AppError> {
    let mut owner: Option<(String, ControllerCapturePhase)> = None;
    for session_id in root.list_sessions().map_err(AppError::operational)? {
        let session = root.session(&session_id).map_err(AppError::operational)?;
        let state = session.read_state().map_err(AppError::operational)?;
        let artifacts = session
            .registered_artifacts(false)
            .map_err(AppError::operational)?;
        let has_accepted_response = artifacts.iter().any(|artifact| {
            artifact.id.starts_with("controller-response-")
                && artifact.kind == CONTROLLER_RESPONSE_KIND
                && artifact.producer == CONTROLLER_PRODUCER
        });
        if !has_accepted_response {
            continue;
        }
        let progress = controller_progress_from_artifacts(Some(root), &session, &artifacts)?;
        if progress.phase == ControllerCapturePhase::Complete {
            continue;
        }
        if state.status == SessionStatus::Failed {
            let mut has_durably_closed_abort = false;
            for transaction in controller_transaction_ids(&artifacts) {
                if find_artifact(&artifacts, &abort_receipt_artifact_id(&transaction)).is_some()
                    && crate::controller_recovery::has_durable_abort_quarantine(
                        root,
                        session.id().as_str(),
                        &transaction,
                    )?
                {
                    has_durably_closed_abort = true;
                    break;
                }
            }
            if has_durably_closed_abort
                || !progress
                    .completed_operations
                    .contains(&PerfOperation::Configure)
            {
                continue;
            }
        }
        let candidate = (session_id.to_string(), progress.phase);
        if let Some((existing_session, existing_phase)) = &owner {
            return Err(AppError {
                code: "CONTROLLER_ROOT_OWNERSHIP_CONFLICT",
                message: "multiple nonterminal Sessions claim the single TRACE32 capture endpoint"
                    .to_owned(),
                details: json!({
                    "first_owner_session_id": existing_session,
                    "first_owner_phase": existing_phase.as_str(),
                    "second_owner_session_id": candidate.0,
                    "second_owner_phase": candidate.1.as_str(),
                    "scope": "artifact_root_capture",
                }),
                exit_code: EXIT_OPERATIONAL,
            });
        }
        owner = Some(candidate);
    }
    Ok(owner)
}

fn controller_transaction_ids(artifacts: &[Artifact]) -> Vec<String> {
    artifacts
        .iter()
        .filter_map(|artifact| {
            artifact
                .id
                .strip_prefix("controller-request-")
                .filter(|transaction| is_transaction_id(transaction))
                .map(str::to_owned)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn find_required_artifact<'a>(
    artifacts: &'a [Artifact],
    id: &str,
    kind: &str,
) -> Result<&'a Artifact, AppError> {
    let artifact = find_artifact(artifacts, id)
        .ok_or_else(|| AppError::operational(format!("controller artifact `{id}` is absent")))?;
    if artifact.kind != kind || artifact.producer != CONTROLLER_PRODUCER {
        return Err(AppError::operational(format!(
            "controller artifact `{id}` has an invalid kind or producer"
        )));
    }
    Ok(artifact)
}

fn find_artifact<'a>(artifacts: &'a [Artifact], id: &str) -> Option<&'a Artifact> {
    artifacts.iter().find(|artifact| artifact.id == id)
}

fn open_session(root: &ArtifactRoot, value: &str) -> Result<Session, AppError> {
    let id = SessionId::new(value.to_owned()).map_err(AppError::operational)?;
    root.session(&id).map_err(AppError::operational)
}

fn ensure_unallocated(path: &std::path::Path, label: &str) -> Result<(), AppError> {
    if path.try_exists().map_err(AppError::operational)? {
        return Err(AppError::operational(format!(
            "{label} path already exists: `{}`",
            path.display()
        )));
    }
    Ok(())
}

fn validate_transaction_id(value: &str) -> Result<(), AppError> {
    if is_transaction_id(value) {
        Ok(())
    } else {
        Err(AppError::operational(
            "controller transaction id must be 32 lowercase hexadecimal characters",
        ))
    }
}

fn is_transaction_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_abort_reason(value: &str) -> Result<ControllerAbortReason, AppError> {
    match value {
        "timeout" => Ok(ControllerAbortReason::Timeout),
        "transport_failure" => Ok(ControllerAbortReason::TransportFailure),
        "operator_request" => Ok(ControllerAbortReason::OperatorRequest),
        _ => Err(AppError::operational(format!(
            "unknown controller abort reason `{value}`"
        ))),
    }
}

const fn abort_reason_name(reason: ControllerAbortReason) -> &'static str {
    match reason {
        ControllerAbortReason::Timeout => "timeout",
        ControllerAbortReason::TransportFailure => "transport_failure",
        ControllerAbortReason::OperatorRequest => "operator_request",
    }
}

fn request_artifact_id(transaction: &str) -> String {
    format!("controller-request-{transaction}")
}

fn raw_response_artifact_id(transaction: &str) -> String {
    format!("controller-mcp-response-{transaction}")
}

fn response_artifact_id(transaction: &str) -> String {
    format!("controller-response-{transaction}")
}

fn abort_artifact_id(transaction: &str) -> String {
    format!("controller-abort-{transaction}")
}

fn abort_receipt_artifact_id(transaction: &str) -> String {
    format!("controller-abort-receipt-{transaction}")
}

fn output_artifact_id(transaction: &str) -> String {
    format!("controller-export-{transaction}")
}

fn custom_event_output_artifact_id(transaction: &str) -> String {
    format!("controller-custom-events-{transaction}")
}

fn request_artifact_path(transaction: &str) -> Result<ArtifactPath, AppError> {
    ArtifactPath::new(format!("logs/controller/requests/{transaction}.json"))
        .map_err(AppError::operational)
}

fn raw_response_artifact_path(transaction: &str) -> Result<ArtifactPath, AppError> {
    ArtifactPath::new(format!("logs/controller/raw/{transaction}.txt"))
        .map_err(AppError::operational)
}

fn response_artifact_path(transaction: &str) -> Result<ArtifactPath, AppError> {
    ArtifactPath::new(format!("logs/controller/responses/{transaction}.json"))
        .map_err(AppError::operational)
}

fn abort_artifact_path(transaction: &str) -> Result<ArtifactPath, AppError> {
    ArtifactPath::new(format!("logs/controller/aborts/{transaction}.json"))
        .map_err(AppError::operational)
}

fn abort_receipt_artifact_path(transaction: &str) -> Result<ArtifactPath, AppError> {
    ArtifactPath::new(format!("logs/controller/abort-receipts/{transaction}.json"))
        .map_err(AppError::operational)
}

fn success(command: &'static str, result: serde_json::Value) -> Result<CommandOutcome, AppError> {
    Ok(CommandOutcome {
        command,
        result,
        exit_code: EXIT_SUCCESS,
    })
}

#[cfg(test)]
mod tests {
    use super::CONTROLLER_ABORT_RECEIPT_KIND;
    use std::collections::BTreeMap;
    use std::io::Write as _;

    use serde_json::json;
    use sha2::{Digest as _, Sha256};
    use t32perf_model::{
        Artifact, ArtifactPath, CaptureCapabilities, MetricSupportEntry, MetricSupportLevel,
        Sha256Digest,
    };
    use t32perf_session::{ArtifactRoot, ArtifactSpec, SessionId, SessionLimits};
    use t32perf_trace32::{
        ControllerDriverEvent, ControllerEvidence, ControllerTargetState, PerfOperation,
        TargetAdapterCaptureContract, TargetAdapterCaptureKind, TargetAdapterControllerProtocol,
        TargetAdapterCustomEventClockContract, TargetAdapterCustomEventCollectorContract,
        TargetAdapterCustomEventMergeOrder, TargetAdapterCustomEventWireProtocol,
        TargetAdapterProfile, TargetAdapterQualificationReceipt,
        TargetAdapterQualificationReceiptSchemaVersion, TargetAdapterScenario,
        TargetAdapterScenarioContract, parse_controller_evidence,
        tc234l_build190766_candidate_profile,
    };

    use crate::controller_qualification::FIRMWARE_ELF_ARTIFACT_PRODUCER;

    use super::{
        ControllerCapturePhase, ControllerRequestEnvelope, ControllerResponseEnvelope,
        FIRMWARE_ELF_ARTIFACT_ID, FIRMWARE_S3_ARTIFACT_ID, FIRMWARE_S3_ARTIFACT_PATH,
        FIRMWARE_S3_PRODUCER, FIRMWARE_S3_STAGING_PATH, TARGET_ADAPTER_QUALIFICATION_ARTIFACT_ID,
        TARGET_ADAPTER_QUALIFICATION_KIND, TARGET_ADAPTER_QUALIFICATION_PRODUCER, abort, accept,
        confirm_abort, confirm_driver_abort, controller_capture_progress, driver_transaction,
        ensure_driver_fault_triggerable, ensure_driver_workload_completion_proven,
        ensure_firmware_image, gate_completed_capture_config, operation_uses_target_adapter,
        pending_request, perf_capture, prepare, provision_target_adapter_scenario,
        read_controller_response_envelope, record_driver_abort_attempt,
        record_driver_abort_success, record_driver_dispatch_intent,
        required_deployment_qualification_artifact, root_active_transaction,
        selected_capture_export_mode, validate_completed_program_flow_state,
        validate_completed_sampling_state, validate_runtime_program_flow_state,
        validate_runtime_sampling_state,
    };

    fn sha256(bytes: &[u8]) -> Sha256Digest {
        Sha256Digest::new(
            Sha256::digest(bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
        .unwrap()
    }

    fn v2_program_flow_profile(firmware: Sha256Digest) -> TargetAdapterProfile {
        let mut profile = tc234l_build190766_candidate_profile();
        profile.adapter_id = "controller-v2-program-flow-fixture".to_owned();
        profile.firmware_elf_sha256 = firmware;
        profile.health_signals = t32perf_trace32::PROGRAM_FLOW_HEALTH_SIGNALS.to_vec();
        let exact = MetricSupportEntry::new(MetricSupportLevel::Exact);
        profile.capabilities = CaptureCapabilities {
            function_events: exact.clone(),
            context_switches: exact.clone(),
            interrupt_events: exact.clone(),
            samples: MetricSupportEntry::unavailable("fixture-program-flow"),
            custom_events: exact.clone(),
            counters: exact,
        };
        profile.controller_protocol = TargetAdapterControllerProtocol::V2CustomEventsExport;
        profile.custom_event_collector = Some(TargetAdapterCustomEventCollectorContract {
            wire_protocol: TargetAdapterCustomEventWireProtocol::CWireV1,
            source_id: "controller-v2-fixture-events".to_owned(),
            core_id: 0,
            clock: TargetAdapterCustomEventClockContract {
                clock_id: "controller-v2-fixture-clock".to_owned(),
                frequency_hz: 100_000_000,
                timestamp_modulus: 1_u64 << 32,
                max_forward_ticks: 1_u64 << 31,
                origin_ticks: 0,
                origin_ns: 0,
            },
            transport: "fixture-c-wire/v1".to_owned(),
            mapping_artifact_id: "controller-v2-fixture-mapping".to_owned(),
            instrumentation_overhead_artifact_id: "controller-v2-fixture-overhead".to_owned(),
            max_output_bytes: 1024 * 1024,
            merge_order: TargetAdapterCustomEventMergeOrder::RejectAmbiguousTies,
        });
        profile.scenarios = vec![TargetAdapterScenarioContract {
            scenario: TargetAdapterScenario::Normal,
            fault_point: None,
            capture: TargetAdapterCaptureContract {
                configuration_sha256_by_initial_state: BTreeMap::from([
                    (
                        ControllerTargetState::Running,
                        Sha256Digest::new("1".repeat(64)).unwrap(),
                    ),
                    (
                        ControllerTargetState::Halted,
                        Sha256Digest::new("2".repeat(64)).unwrap(),
                    ),
                ]),
                capture_mode: "fixture-task-events".to_owned(),
                trace_sink: "fixture-trace-sink".to_owned(),
                capture_kind: TargetAdapterCaptureKind::ProgramFlowTaskEvents {
                    export_profile_id: "fixture-task-events-export/v1".to_owned(),
                    rtos_awareness: "fixture-orti/v1".to_owned(),
                    timestamp_clock_id: "controller-v2-fixture-clock".to_owned(),
                    orti_artifact_id: "fixture-orti".to_owned(),
                    task_marker_artifact_id: "fixture-task-markers".to_owned(),
                },
                timestamp_enabled: true,
                workload_identity: "fixture-program-flow-workload/v1".to_owned(),
                covered_cores: vec![0],
                supported_initial_states: vec![
                    ControllerTargetState::Running,
                    ControllerTargetState::Halted,
                ],
            },
        }];
        profile.validate().unwrap();
        profile
    }

    fn fixture_stage(session: &t32perf_session::Session, path: &ArtifactPath, bytes: &[u8]) {
        let lock = session.try_lock().unwrap();
        let staged = session.prepare_staging_path(&lock, path).unwrap();
        std::fs::write(staged, bytes).unwrap();
    }

    fn finished_wrapper(operation: PerfOperation, binding: &Sha256Digest) -> Vec<u8> {
        let code = match operation {
            PerfOperation::GetCapabilities => "capabilities_exported",
            PerfOperation::Configure => "configured",
            PerfOperation::Start => "started",
            PerfOperation::Stop => "stopped",
            PerfOperation::GetHealth => "health_exported",
            PerfOperation::Export => "task_events_exported",
            PerfOperation::GetHotspots => unreachable!("fixture only exercises capture operations"),
            PerfOperation::Cleanup => "cleanup_completed",
        };
        format!(
            "<FINISHED>\n<CONTENT>\nT32PERF_RESULT_BEGIN\n{}\nT32PERF_RESULT_END\n",
            json!({
                "protocol": "t32perf/1",
                "operation": operation.as_str(),
                "status": "OK",
                "code": code,
                "binding_sha256": binding,
            })
        )
        .into_bytes()
    }

    fn fixture_qualified_admission(
        root: &ArtifactRoot,
        session: &t32perf_session::Session,
        profile: &TargetAdapterProfile,
    ) {
        let categories = [
            "artifact_binding",
            "function",
            "task",
            "isr",
            "context_switch",
            "interrupt",
            "function_activation",
        ];
        let hil = json!({
            "schema": "t32perf.hil-verification-receipt/v1",
            "source": "host-reconstructed-session-artifacts",
            "kind": "native_timeline",
            "scenario": null,
            "board_id": "fixture-board",
            "session_id": session.id().as_str(),
            "driver_reference_sha256": "3".repeat(64),
            "recovery_evidence": null,
            "tolerance": {
                "timestamp_absolute_ns": 0.0, "timestamp_relative": 0.0,
                "continuous_relative": 0.0, "continuous_absolute": 0.0,
                "integer_absolute": 0.0,
            },
            "artifact_bindings": [
                {"role":"manifest", "artifact_id": null, "sha256":"4".repeat(64)},
                {"role":"health", "artifact_id":"fixture-health", "sha256":"5".repeat(64)},
                {"role":"observations", "artifact_id":"fixture-observations", "sha256":"6".repeat(64)},
                {"role":"analysis_summary", "artifact_id":"fixture-summary", "sha256":"7".repeat(64)},
                {"role":"hotspots", "artifact_id":"fixture-hotspots", "sha256":"8".repeat(64)},
                {"role":"derived", "artifact_id":"fixture-derived", "sha256":"9".repeat(64)},
            ],
            "checks": {"total": 7, "passed": 7, "failed": 0},
            "check_categories": categories.into_iter().map(|category| json!({
                "category": category, "counts": {"total": 1, "passed": 1, "failed": 0}
            })).collect::<Vec<_>>(),
            "max_error": {"check": null, "absolute": 0.0, "relative": 0.0},
            "failure_count": 0,
            "failures": [],
            "failures_truncated": false,
            "verdict": "PASS",
        });
        let hil_bytes = serde_json::to_vec(&hil).unwrap();
        let receipt = TargetAdapterQualificationReceipt {
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
            hil_verification_receipt_sha256: sha256(&hil_bytes),
        };
        let receipt_bytes = serde_json::to_vec(&receipt).unwrap();
        let mut qualified = profile.clone();
        qualified.qualification_sha256 = Some(sha256(&receipt_bytes));
        let policy = t32perf_trace32::TargetAdapterQualificationPolicy {
            schema: t32perf_trace32::TargetAdapterQualificationPolicySchemaVersion::V1,
            policy_id: "fixture-policy".to_owned(),
            adapter_id: profile.adapter_id.clone(),
            adapter_version: profile.adapter_version.clone(),
            candidate_profile_sha256: profile.qualification_identity_digest().unwrap(),
            qualified_profile_sha256: qualified.digest().unwrap(),
            implementation_sha256: profile.implementation_sha256.clone(),
            firmware_elf_sha256: profile.firmware_elf_sha256.clone(),
            trace32_release: profile.build_gate.trace32_release.clone(),
            trace32_build: profile.build_gate.minimum_build,
            architecture_package: profile.build_gate.architecture_package.clone(),
            target_identifier: profile.target_identifier.clone(),
            probe_identifier: profile.probe_identifier.clone(),
            qualification_receipt_sha256: sha256(&receipt_bytes),
            hil_verification_receipt_sha256: sha256(&hil_bytes),
            board_id: "fixture-board".to_owned(),
            t32mcp_version: "0.2.2".to_owned(),
            expected_hil_kind: t32perf_trace32::HilVerificationKind::NativeTimeline,
            expected_hil_scenario: None,
            allowed_scenarios: vec![TargetAdapterScenario::Normal],
        };
        let policy_bytes = serde_json::to_vec(&policy).unwrap();
        let deployment = root.path().join(".t32perf-control/deployment");
        std::fs::create_dir_all(deployment.join("target-adapter-policies")).unwrap();
        std::fs::write(
            deployment.join("target-adapter-policies/fixture-policy.json"),
            &policy_bytes,
        )
        .unwrap();
        std::fs::write(
            deployment.join("target-adapter-qualification-trust-store.json"),
            serde_json::to_vec(&json!({
                "schema": "t32perf.target-adapter-qualification-trust-store/v1",
                "entries": [{"policy_id": "fixture-policy", "policy_sha256": sha256(&policy_bytes)}],
            }))
            .unwrap(),
        )
        .unwrap();
        fixture_stage(
            session,
            &ArtifactPath::new("fixture-qualification.json").unwrap(),
            &receipt_bytes,
        );
        fixture_stage(
            session,
            &ArtifactPath::new("fixture-hil.json").unwrap(),
            &hil_bytes,
        );
        crate::controller_qualification::provision(
            root,
            crate::cli::ControllerProvisionQualificationArgs {
                session: session.id().to_string(),
                policy_id: "fixture-policy".to_owned(),
                qualification_staged: "fixture-qualification.json".to_owned(),
                hil_staged: "fixture-hil.json".to_owned(),
                recovery_staged: None,
            },
        )
        .unwrap();
    }

    fn deployment_qualification_artifact() -> Artifact {
        Artifact {
            id: TARGET_ADAPTER_QUALIFICATION_ARTIFACT_ID.to_owned(),
            kind: TARGET_ADAPTER_QUALIFICATION_KIND.to_owned(),
            relative_path: ArtifactPath::new("capture/target-adapter-qualification.json").unwrap(),
            media_type: "application/json".to_owned(),
            producer: TARGET_ADAPTER_QUALIFICATION_PRODUCER.to_owned(),
            input_artifact_ids: vec![
                "target-adapter-qualification-policy".to_owned(),
                "target-adapter-hil-verification".to_owned(),
            ],
            size_bytes: 1,
            sha256: Sha256Digest::new("a".repeat(64)).unwrap(),
        }
    }

    #[test]
    fn deployment_qualification_envelope_is_exact_and_not_controller_owned() {
        let expected = Sha256Digest::new("a".repeat(64)).unwrap();
        let valid = deployment_qualification_artifact();
        assert!(
            required_deployment_qualification_artifact(std::slice::from_ref(&valid), &expected)
                .is_ok()
        );

        for mut invalid in [
            {
                let mut artifact = valid.clone();
                artifact.kind = "controller_response".to_owned();
                artifact
            },
            {
                let mut artifact = valid.clone();
                artifact.producer = "t32perf-controller/v1".to_owned();
                artifact
            },
            {
                let mut artifact = valid.clone();
                artifact.relative_path =
                    ArtifactPath::new("logs/controller/qualification.json").unwrap();
                artifact
            },
            {
                let mut artifact = valid.clone();
                artifact.input_artifact_ids = vec!["caller-controlled".to_owned()];
                artifact
            },
        ] {
            assert!(
                required_deployment_qualification_artifact(
                    std::slice::from_mut(&mut invalid),
                    &expected,
                )
                .is_err()
            );
        }
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
        elf
    }

    fn controller_root_with_firmware() -> (tempfile::TempDir, ArtifactRoot, String) {
        let temporary = tempfile::tempdir().unwrap();
        let root = ArtifactRoot::open(temporary.path().join("sessions"), SessionLimits::default())
            .unwrap();
        let session = root.create_session(&json!({})).unwrap();
        let session_id = session.id().to_string();
        let lock = session.try_lock().unwrap();
        let mut writer = session
            .create_artifact(
                &lock,
                ArtifactSpec {
                    id: FIRMWARE_ELF_ARTIFACT_ID.to_owned(),
                    kind: "firmware_elf".to_owned(),
                    relative_path: ArtifactPath::new("capture/firmware.elf").unwrap(),
                    media_type: "application/x-elf".to_owned(),
                    producer: FIRMWARE_ELF_ARTIFACT_PRODUCER.to_owned(),
                    input_artifact_ids: Vec::new(),
                },
            )
            .unwrap();
        writer.write_all(&minimal_tricore_elf()).unwrap();
        session.commit_artifact(&lock, writer).unwrap();
        drop(lock);
        (temporary, root, session_id)
    }

    #[test]
    fn driver_journal_is_request_bound_exactly_idempotent_and_abort_observation_gated() {
        let (_temporary, root, session_id) = controller_root_with_firmware();
        let prepared = prepare(
            &root,
            &session_id,
            PerfOperation::GetCapabilities.as_str(),
            None,
        )
        .unwrap();
        let transaction = prepared.result["transaction_id"]
            .as_str()
            .unwrap()
            .to_owned();

        record_driver_dispatch_intent(&root, &session_id, &transaction).unwrap();
        record_driver_dispatch_intent(&root, &session_id, &transaction).unwrap();
        let state = driver_transaction(&root, &session_id, &transaction).unwrap();
        assert!(state.dispatch_intent_recorded);
        assert!(!state.abort_planned);
        let session = root
            .session(&SessionId::new(session_id.clone()).unwrap())
            .unwrap();
        let artifacts = session.registered_artifacts(false).unwrap();
        let request_artifact = artifacts
            .iter()
            .find(|artifact| artifact.id == format!("controller-request-{transaction}"))
            .unwrap();
        let event_artifact = artifacts
            .iter()
            .find(|artifact| {
                artifact.id
                    == crate::controller_journal::event_artifact_id(
                        &transaction,
                        t32perf_trace32::ControllerDriverEventKind::DispatchIntent,
                    )
            })
            .unwrap();
        let event: ControllerDriverEvent = super::read_bounded_json_artifact(
            &session,
            event_artifact,
            t32perf_trace32::MAX_CONTROLLER_DRIVER_EVENT_BYTES,
        )
        .unwrap();
        assert_eq!(event.request_artifact_id, request_artifact.id);
        assert_eq!(event.request_artifact_sha256, request_artifact.sha256);
        assert_eq!(event.binding, *state.request.binding());

        abort(&root, &session_id, &transaction, "timeout").unwrap();
        assert!(abort(&root, &session_id, &transaction, "operator_request").is_err());
        assert!(record_driver_abort_success(&root, &session_id, &transaction).is_err());
        record_driver_abort_attempt(&root, &session_id, &transaction).unwrap();
        record_driver_abort_attempt(&root, &session_id, &transaction).unwrap();
        record_driver_abort_success(&root, &session_id, &transaction).unwrap();
        record_driver_abort_success(&root, &session_id, &transaction).unwrap();
        let state = driver_transaction(&root, &session_id, &transaction).unwrap();
        assert!(state.abort_planned);
        assert!(state.abort_attempted);
        assert!(state.abort_success_observed);
        assert!(!state.abort_confirmed);

        confirm_driver_abort(&root, &session_id, &transaction).unwrap();
        confirm_driver_abort(&root, &session_id, &transaction).unwrap();
        assert!(
            driver_transaction(&root, &session_id, &transaction)
                .unwrap()
                .abort_confirmed
        );
    }

    #[test]
    fn completed_cleanup_remains_a_repairable_pending_phase_until_capture_config_exists() {
        let transaction = "a".repeat(32);
        let (phase, pending) = gate_completed_capture_config(
            ControllerCapturePhase::Complete,
            None,
            Some(transaction.clone()),
            false,
        )
        .unwrap();
        assert_eq!(phase, ControllerCapturePhase::Cleanup);
        assert_eq!(pending, Some((transaction, PerfOperation::Cleanup)));

        let (phase, pending) = gate_completed_capture_config(
            ControllerCapturePhase::Complete,
            None,
            Some("b".repeat(32)),
            true,
        )
        .unwrap();
        assert_eq!(phase, ControllerCapturePhase::Complete);
        assert!(pending.is_none());
    }

    #[test]
    fn fault_trigger_requires_both_intent_and_abort_plan() {
        assert!(ensure_driver_fault_triggerable(true, true, true).is_ok());
        for invalid in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
        ] {
            assert!(ensure_driver_fault_triggerable(invalid.0, invalid.1, invalid.2).is_err());
        }
    }

    #[test]
    fn driver_workload_intent_without_completion_blocks_public_resume_and_stop_prepare() {
        for path in [
            "public --workload-complete resume",
            "low-level prepare Stop",
        ] {
            let error = ensure_driver_workload_completion_proven(
                true,
                false,
                true,
                "workload-gate",
                "a1b2c3d4",
            )
            .unwrap_err();
            assert_eq!(error.code, "CONTROLLER_DRIVER_WORKLOAD_AMBIGUOUS", "{path}");
            assert!(
                error.message.contains("Stop cannot be prepared"),
                "{path}: {}",
                error.message
            );
            assert_eq!(error.details["start_transaction_id"], "a1b2c3d4", "{path}");
        }
    }

    #[test]
    fn completed_driver_workload_allows_stop_prepare_recovery() {
        assert!(
            ensure_driver_workload_completion_proven(
                true,
                true,
                true,
                "workload-gate",
                "a1b2c3d4",
            )
            .is_ok()
        );
    }

    #[test]
    fn strict_performance_run_without_workload_markers_requires_driver_resume() {
        let error = ensure_driver_workload_completion_proven(
            false,
            false,
            true,
            "workload-gate",
            "a1b2c3d4",
        )
        .unwrap_err();
        assert_eq!(error.code, "DRIVER_RESUME_REQUIRED");
        assert_eq!(
            error.details["required_action"],
            "resume the strict perf_run controller driver"
        );
    }

    #[test]
    fn manual_workload_diagnostic_without_driver_intent_remains_allowed() {
        assert!(
            ensure_driver_workload_completion_proven(
                false,
                false,
                false,
                "workload-gate",
                "a1b2c3d4",
            )
            .is_ok()
        );
    }

    #[test]
    fn driver_confirmation_retries_a_trusted_manual_abort_receipt() {
        let (_temporary, root, session_id) = controller_root_with_firmware();
        let prepared = prepare(
            &root,
            &session_id,
            PerfOperation::GetCapabilities.as_str(),
            None,
        )
        .unwrap();
        let transaction = prepared.result["transaction_id"].as_str().unwrap();
        abort(&root, &session_id, transaction, "operator_request").unwrap();
        confirm_abort(&root, &session_id, transaction, true).unwrap();
        assert!(
            driver_transaction(&root, &session_id, transaction)
                .unwrap()
                .abort_confirmed
        );
        confirm_driver_abort(&root, &session_id, transaction).unwrap();
    }

    #[test]
    fn capabilities_and_hotspots_are_endpoint_only_operations() {
        assert!(!operation_uses_target_adapter(
            PerfOperation::GetCapabilities
        ));
        assert!(!operation_uses_target_adapter(PerfOperation::GetHotspots));
        for operation in [
            PerfOperation::Configure,
            PerfOperation::Start,
            PerfOperation::Stop,
            PerfOperation::GetHealth,
            PerfOperation::Export,
            PerfOperation::Cleanup,
        ] {
            assert!(operation_uses_target_adapter(operation));
        }
    }

    #[test]
    fn practice_output_paths_normalize_windows_extended_prefix() {
        let path = std::path::Path::new(r"\\?\E:\t32perf\sessions\capture\staging\out.bin");
        assert_eq!(
            super::practice_output_path(path).unwrap(),
            "E:/t32perf/sessions/capture/staging/out.bin"
        );
    }

    #[test]
    fn performance_surface_export_mode_comes_from_the_admitted_profile() {
        let firmware = minimal_tricore_elf();
        let mut profile = tc234l_build190766_candidate_profile();
        profile.firmware_elf_sha256 = sha256(&firmware);
        crate::controller_qualification::with_test_compiled_target_adapter_profiles(
            vec![profile],
            || {
                let (_temporary, root, session_id) = controller_root_with_firmware();
                assert_eq!(
                    selected_capture_export_mode(&root, &session_id).unwrap(),
                    "raw_ascii"
                );
            },
        );
    }

    #[test]
    fn buffer_full_is_a_completed_control_binding_but_not_a_runtime_binding() {
        let binding = "0".repeat(64);
        let stop = serde_json::to_vec(&json!({
            "schema": "t32perf.controller-stop-evidence/v2",
            "operation": "perf_stop",
            "binding_sha256": binding,
            "capture_stopped": true,
            "workload_identity": "external-owner-sampling-window/v1",
            "target_state_after_stop": "halted",
            "pre_stop_state": "break",
            "capacity_records": 32,
            "recorded_records": 32,
            "time_origin_zeroed_to_first_record": true
        }))
        .unwrap();
        let ControllerEvidence::StopV2(stop) =
            parse_controller_evidence(PerfOperation::Stop, &stop).unwrap()
        else {
            panic!("expected sampling stop evidence");
        };
        let health = serde_json::to_vec(&json!({
            "schema": "t32perf.controller-health-evidence/v2",
            "operation": "perf_get_health",
            "binding_sha256": "0".repeat(64),
            "capture_stopped": true,
            "supported_signals": [
                "sampling_buffer_full",
                "sampling_unexpected_stop",
                "elf_mismatch"
            ],
            "stop_evidence_sha256": "1".repeat(64),
            "sampling": {
                "method": "real_time",
                "object": "program_counter",
                "buffer_mode": "stack",
                "state": "off",
                "pre_stop_state": "break",
                "requested_rate_ns": 1000000,
                "capacity_records": 32,
                "recorded_records": 32,
                "buffer_full": true,
                "unexpected_stop": false
            },
            "elf_matches_firmware": true
        }))
        .unwrap();
        let ControllerEvidence::HealthV2(health) =
            parse_controller_evidence(PerfOperation::GetHealth, &health).unwrap()
        else {
            panic!("expected sampling health evidence");
        };

        validate_completed_sampling_state(
            TargetAdapterScenario::SamplingBufferFull,
            32,
            &health,
            &stop,
        )
        .unwrap();
        assert!(
            validate_runtime_sampling_state(TargetAdapterScenario::SamplingBufferFull, &health)
                .is_err()
        );
        assert!(
            validate_completed_sampling_state(TargetAdapterScenario::Normal, 32, &health, &stop,)
                .is_err()
        );
    }

    #[test]
    fn program_flow_fault_health_is_completed_evidence_but_never_a_runtime_binding() {
        let health = |trace_overflow, flow_error, trace_gap, program_flow_closed| {
            let bytes = serde_json::to_vec(&json!({
                "schema": "t32perf.controller-health-evidence/v3",
                "operation": "perf_get_health",
                "binding_sha256": "0".repeat(64),
                "capture_stopped": true,
                "supported_signals": [
                    "trace_overflow",
                    "flow_error",
                    "trace_gap",
                    "truncation",
                    "timestamp_discontinuity",
                    "elf_mismatch",
                    "program_flow_closure"
                ],
                "stop_evidence_sha256": "1".repeat(64),
                "trace_overflow": trace_overflow,
                "flow_error": flow_error,
                "trace_gap": trace_gap,
                "truncated": false,
                "timestamp_discontinuity": false,
                "elf_matches_firmware": true,
                "program_flow_closed": program_flow_closed
            }))
            .unwrap();
            let ControllerEvidence::HealthV3(health) =
                parse_controller_evidence(PerfOperation::GetHealth, &bytes).unwrap()
            else {
                panic!("expected program-flow health evidence v3");
            };
            health
        };

        let normal = health(false, false, false, true);
        validate_completed_program_flow_state(TargetAdapterScenario::Normal, &normal).unwrap();
        validate_runtime_program_flow_state(TargetAdapterScenario::Normal, &normal).unwrap();

        let overflow = health(true, false, false, false);
        validate_completed_program_flow_state(TargetAdapterScenario::TraceOverflow, &overflow)
            .unwrap();
        assert!(
            validate_runtime_program_flow_state(TargetAdapterScenario::TraceOverflow, &overflow)
                .is_err()
        );

        let flow_error = health(false, true, false, false);
        validate_completed_program_flow_state(TargetAdapterScenario::FlowError, &flow_error)
            .unwrap();
        assert!(
            validate_runtime_program_flow_state(TargetAdapterScenario::FlowError, &flow_error)
                .is_err()
        );

        assert!(
            validate_completed_program_flow_state(
                TargetAdapterScenario::TraceOverflow,
                &health(true, false, true, false),
            )
            .is_err()
        );
        assert!(
            validate_completed_program_flow_state(
                TargetAdapterScenario::FlowError,
                &health(true, true, false, false),
            )
            .is_err()
        );
    }

    #[test]
    fn firmware_s3_materialization_is_exact_and_durable_on_retry() {
        let temporary = tempfile::tempdir().unwrap();
        let root = ArtifactRoot::open(temporary.path().join("sessions"), SessionLimits::default())
            .unwrap();
        let session = root.create_session(&json!({})).unwrap();
        let lock = session.try_lock().unwrap();
        let mut writer = session
            .create_artifact(
                &lock,
                ArtifactSpec {
                    id: FIRMWARE_ELF_ARTIFACT_ID.to_owned(),
                    kind: "firmware_elf".to_owned(),
                    relative_path: ArtifactPath::new("capture/firmware.elf").unwrap(),
                    media_type: "application/x-elf".to_owned(),
                    producer: FIRMWARE_ELF_ARTIFACT_PRODUCER.to_owned(),
                    input_artifact_ids: Vec::new(),
                },
            )
            .unwrap();
        writer.write_all(&minimal_tricore_elf()).unwrap();
        session.commit_artifact(&lock, writer).unwrap();
        let artifacts = session.registered_artifacts(false).unwrap();
        let mut forged = artifacts.clone();
        forged[0].producer = "caller-controlled/v1".to_owned();
        assert!(ensure_firmware_image(&session, &lock, &forged).is_err());
        let first = ensure_firmware_image(&session, &lock, &artifacts).unwrap();
        assert_eq!(first.measurement_artifact.id, FIRMWARE_S3_ARTIFACT_ID);
        assert_eq!(
            first.measurement_artifact.relative_path.as_str(),
            FIRMWARE_S3_ARTIFACT_PATH
        );
        assert_eq!(first.measurement_artifact.producer, FIRMWARE_S3_PRODUCER);
        assert!(
            session
                .staging_path(&ArtifactPath::new(FIRMWARE_S3_STAGING_PATH).unwrap())
                .unwrap()
                .is_file()
        );
        let artifacts = session.registered_artifacts(false).unwrap();
        let second = ensure_firmware_image(&session, &lock, &artifacts).unwrap();
        assert_eq!(
            first.measurement_artifact.sha256,
            second.measurement_artifact.sha256
        );
    }

    #[test]
    fn candidate_fault_selection_is_evidence_only_and_profile_bounded() {
        let profile = tc234l_build190766_candidate_profile();
        let (selection, inputs) = provision_target_adapter_scenario(
            TargetAdapterScenario::CmmAbort,
            &profile,
            &[],
            &[TargetAdapterScenario::Normal],
        )
        .unwrap();
        assert!(selection.evidence_only);
        assert_eq!(selection.scenario, TargetAdapterScenario::CmmAbort);
        assert_eq!(inputs, vec![FIRMWARE_ELF_ARTIFACT_ID]);
        assert!(
            provision_target_adapter_scenario(
                TargetAdapterScenario::CmmAbort,
                &profile,
                &[],
                &[TargetAdapterScenario::Normal],
            )
            .is_ok()
        );
        assert!(
            provision_target_adapter_scenario(
                TargetAdapterScenario::CmmAbort,
                &profile,
                &[t32perf_model::Artifact {
                    id: "admission".to_owned(),
                    kind: "test".to_owned(),
                    relative_path: ArtifactPath::new("capture/admission.json").unwrap(),
                    media_type: "application/json".to_owned(),
                    producer: "test".to_owned(),
                    input_artifact_ids: Vec::new(),
                    size_bytes: 1,
                    sha256: t32perf_model::Sha256Digest::new("00".repeat(32),).unwrap(),
                }],
                &[TargetAdapterScenario::Normal],
            )
            .is_err()
        );
    }

    #[test]
    fn v2_program_flow_prepare_uses_the_real_firmware_admission_and_fixed_multi_output_envelope() {
        let firmware = minimal_tricore_elf();
        let profile = v2_program_flow_profile(sha256(&firmware));
        crate::controller_qualification::with_test_compiled_target_adapter_profiles(
            vec![profile.clone()],
            || {
                let temporary = tempfile::tempdir().unwrap();
                let root =
                    ArtifactRoot::open(temporary.path().join("sessions"), SessionLimits::default())
                        .unwrap();
                let session = root.create_session(&json!({})).unwrap();
                let session_id = session.id().to_string();
                let firmware_staged = ArtifactPath::new("fixture-firmware.elf").unwrap();
                fixture_stage(&session, &firmware_staged, &firmware);
                crate::controller_qualification::provision_firmware(
                    &root,
                    &session_id,
                    &firmware_staged,
                )
                .unwrap();
                fixture_qualified_admission(&root, &session, &profile);
                crate::controller_qualification::select_scenario(
                    &root,
                    crate::cli::ControllerSelectScenarioArgs {
                        session: session_id.clone(),
                        scenario: "normal".to_owned(),
                    },
                )
                .unwrap();

                let capabilities = prepare(
                    &root,
                    &session_id,
                    PerfOperation::GetCapabilities.as_str(),
                    None,
                )
                .unwrap();
                let transaction = capabilities.result["transaction_id"].as_str().unwrap();
                let (request, _, _) = pending_request(&root, &session_id, transaction).unwrap();
                let ControllerRequestEnvelope::V1(request) = request else {
                    panic!("capabilities must retain the V1 endpoint request")
                };
                let evidence = json!({
                    "schema": "t32perf.controller-capabilities-evidence/v2",
                    "operation": "perf_get_capabilities",
                    "binding_sha256": request.binding.binding_sha256,
                    "trace32_release": profile.build_gate.trace32_release,
                    "trace32_build": profile.build_gate.minimum_build,
                    "architecture_package": profile.build_gate.architecture_package,
                    "target_identifier": profile.target_identifier,
                    "probe_identifier": profile.probe_identifier,
                    "license_features": profile.license_features,
                    "trace_routing": profile.trace_routing,
                    "capture_modes": ["fixture-task-events"],
                    "trace_sinks": ["fixture-trace-sink"],
                    "covered_cores": [0],
                    "timestamp_supported": true,
                    "rtos_awareness": "fixture-orti/v1",
                    "health_signals": t32perf_trace32::PROGRAM_FLOW_HEALTH_SIGNALS,
                    "initial_target_state": "running"
                });
                fixture_stage(
                    &session,
                    &request.response_staging_path,
                    &finished_wrapper(request.operation, &request.binding.binding_sha256),
                );
                fixture_stage(
                    &session,
                    &request.output.as_ref().unwrap().staged_relative_path,
                    &serde_json::to_vec(&evidence).unwrap(),
                );
                accept(&root, &session_id, transaction).unwrap();

                let configured =
                    prepare(&root, &session_id, PerfOperation::Configure.as_str(), None).unwrap();
                let configured_transaction = configured.result["transaction_id"].as_str().unwrap();
                let (request, _, _) =
                    pending_request(&root, &session_id, configured_transaction).unwrap();
                let ControllerRequestEnvelope::V2(request) = request else {
                    panic!("qualified V2 ProgramFlow adapter must select ControllerRequestV2")
                };
                assert_eq!(
                    request.mcp.execute.arguments.script_name,
                    "perf_configure_v2.cmm"
                );
                assert_eq!(request.outputs.len(), 1);
                let output = &request.outputs[0];
                assert_eq!(
                    output.role,
                    t32perf_trace32::ControllerOutputRoleV2::MachineEvidence
                );
                assert_eq!(
                    request.mcp.execute.arguments.script_args,
                    BTreeMap::from([
                        (
                            "binding_sha256".to_owned(),
                            request.binding.binding_sha256.to_string()
                        ),
                        (
                            "machine_evidence_output".to_owned(),
                            output.script_output_path.clone()
                        ),
                        (
                            "firmware_s3".to_owned(),
                            request.firmware_image.script_input_path.clone()
                        ),
                        ("initial_target_state".to_owned(), "running".to_owned()),
                        ("scenario".to_owned(), "normal".to_owned()),
                    ])
                );

                let configure_evidence = json!({
                    "schema": "t32perf.controller-configure-evidence/v1",
                    "operation": "perf_configure",
                    "binding_sha256": request.binding.binding_sha256,
                    "configuration_sha256": "1".repeat(64),
                    "capture_mode": "fixture-task-events",
                    "trace_sink": "fixture-trace-sink",
                    "timestamp_enabled": true,
                    "filters_verified": true,
                    "trigger_verified": true,
                    "initial_target_state": "running",
                    "workload_identity": "fixture-program-flow-workload/v1",
                    "covered_cores": [0],
                });
                fixture_stage(
                    &session,
                    &request.response_staging_path,
                    &finished_wrapper(request.operation, &request.binding.binding_sha256),
                );
                fixture_stage(
                    &session,
                    &request.outputs[0].staged_relative_path,
                    &serde_json::to_vec(&configure_evidence).unwrap(),
                );
                accept(&root, &session_id, configured_transaction).unwrap();

                let started =
                    prepare(&root, &session_id, PerfOperation::Start.as_str(), None).unwrap();
                let started_transaction = started.result["transaction_id"].as_str().unwrap();
                let (request, _, _) =
                    pending_request(&root, &session_id, started_transaction).unwrap();
                let ControllerRequestEnvelope::V2(request) = request else {
                    panic!("start must use ControllerRequestV2")
                };
                assert_eq!(
                    request.mcp.execute.arguments.script_name,
                    "perf_start_v2.cmm"
                );
                assert_eq!(request.outputs.len(), 1);
                assert_eq!(
                    request
                        .mcp
                        .execute
                        .arguments
                        .script_args
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>(),
                    vec![
                        "binding_sha256",
                        "initial_target_state",
                        "machine_evidence_output",
                        "scenario"
                    ]
                );
                let start_evidence = json!({
                    "schema": "t32perf.controller-start-evidence/v2",
                    "operation": "perf_start",
                    "binding_sha256": request.binding.binding_sha256,
                    "initial_target_state": "running",
                    "capture_armed": true,
                    "workload_owner": "target_specific_controller",
                    "workload_identity": "fixture-program-flow-workload/v1",
                });
                fixture_stage(
                    &session,
                    &request.response_staging_path,
                    b"<NOT FINISHED>\n<CONTENT>\n",
                );
                let Err(pending) = accept(&root, &session_id, started_transaction) else {
                    panic!("NotFinished response must remain pending")
                };
                assert_eq!(pending.code, "CONTROLLER_RESPONSE_NOT_FINISHED");
                assert!(
                    session
                        .registered_artifacts(false)
                        .unwrap()
                        .iter()
                        .all(|artifact| artifact.id
                            != format!("controller-mcp-response-{started_transaction}"))
                );
                fixture_stage(
                    &session,
                    &request.response_staging_path,
                    &finished_wrapper(request.operation, &request.binding.binding_sha256),
                );
                fixture_stage(
                    &session,
                    &request.outputs[0].staged_relative_path,
                    &serde_json::to_vec(&start_evidence).unwrap(),
                );
                accept(&root, &session_id, started_transaction).unwrap();

                let stopped =
                    prepare(&root, &session_id, PerfOperation::Stop.as_str(), None).unwrap();
                let stopped_transaction = stopped.result["transaction_id"].as_str().unwrap();
                let (request, _, _) =
                    pending_request(&root, &session_id, stopped_transaction).unwrap();
                let ControllerRequestEnvelope::V2(request) = request else {
                    panic!("stop must use ControllerRequestV2")
                };
                assert_eq!(
                    request.mcp.execute.arguments.script_name,
                    "perf_stop_v2.cmm"
                );
                assert_eq!(
                    request
                        .mcp
                        .execute
                        .arguments
                        .script_args
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>(),
                    vec!["binding_sha256", "machine_evidence_output"]
                );
                let stop_evidence = json!({
                    "schema": "t32perf.controller-stop-evidence/v1",
                    "operation": "perf_stop",
                    "binding_sha256": request.binding.binding_sha256,
                    "capture_stopped": true,
                    "workload_completed": true,
                    "workload_identity": "fixture-program-flow-workload/v1",
                    "target_state_after_stop": "running",
                });
                fixture_stage(
                    &session,
                    &request.response_staging_path,
                    &finished_wrapper(request.operation, &request.binding.binding_sha256),
                );
                fixture_stage(
                    &session,
                    &request.outputs[0].staged_relative_path,
                    &serde_json::to_vec(&stop_evidence).unwrap(),
                );
                accept(&root, &session_id, stopped_transaction).unwrap();
                let session_artifacts = session.registered_artifacts(false).unwrap();
                let stop_artifact = session_artifacts
                    .iter()
                    .find(|artifact| {
                        artifact.id == format!("controller-export-{stopped_transaction}")
                    })
                    .unwrap();

                let healthy =
                    prepare(&root, &session_id, PerfOperation::GetHealth.as_str(), None).unwrap();
                let healthy_transaction = healthy.result["transaction_id"].as_str().unwrap();
                let (request, _, _) =
                    pending_request(&root, &session_id, healthy_transaction).unwrap();
                let ControllerRequestEnvelope::V2(request) = request else {
                    panic!("health must use ControllerRequestV2")
                };
                assert_eq!(
                    request.mcp.execute.arguments.script_name,
                    "perf_get_health_v2.cmm"
                );
                assert_eq!(
                    request
                        .mcp
                        .execute
                        .arguments
                        .script_args
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>(),
                    vec![
                        "binding_sha256",
                        "firmware_s3",
                        "machine_evidence_output",
                        "stop_evidence_sha256"
                    ]
                );
                let health_evidence = json!({
                    "schema": "t32perf.controller-health-evidence/v3",
                    "operation": "perf_get_health",
                    "binding_sha256": request.binding.binding_sha256,
                    "capture_stopped": true,
                    "supported_signals": t32perf_trace32::PROGRAM_FLOW_HEALTH_SIGNALS,
                    "stop_evidence_sha256": stop_artifact.sha256,
                    "trace_overflow": false,
                    "flow_error": false,
                    "trace_gap": false,
                    "truncated": false,
                    "timestamp_discontinuity": false,
                    "elf_matches_firmware": true,
                    "program_flow_closed": true,
                });
                fixture_stage(
                    &session,
                    &request.response_staging_path,
                    &finished_wrapper(request.operation, &request.binding.binding_sha256),
                );
                fixture_stage(
                    &session,
                    &request.outputs[0].staged_relative_path,
                    &serde_json::to_vec(&health_evidence).unwrap(),
                );
                accept(&root, &session_id, healthy_transaction).unwrap();

                let exported = prepare(
                    &root,
                    &session_id,
                    PerfOperation::Export.as_str(),
                    Some("task_events_elf_orti_verified"),
                )
                .unwrap();
                let export_transaction = exported.result["transaction_id"].as_str().unwrap();
                let (request, request_artifact, _) =
                    pending_request(&root, &session_id, export_transaction).unwrap();
                let ControllerRequestEnvelope::V2(request) = request else {
                    panic!("export must use ControllerRequestV2")
                };
                assert_eq!(
                    request.mcp.execute.arguments.script_name,
                    "perf_export_v2.cmm"
                );
                assert_eq!(request.outputs.len(), 2);
                assert_eq!(
                    request.outputs[0].role,
                    t32perf_trace32::ControllerOutputRoleV2::TraceExport
                );
                assert_eq!(
                    request.outputs[1].role,
                    t32perf_trace32::ControllerOutputRoleV2::CustomEvents
                );
                assert_eq!(
                    request
                        .mcp
                        .execute
                        .arguments
                        .script_args
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>(),
                    vec![
                        "binding_sha256",
                        "custom_events_output",
                        "mode",
                        "trace_export_output"
                    ]
                );
                fixture_stage(
                    &session,
                    &request.response_staging_path,
                    &finished_wrapper(request.operation, &request.binding.binding_sha256),
                );
                fixture_stage(
                    &session,
                    &request.outputs[0].staged_relative_path,
                    b"# fixture TASKEVENTS\n",
                );
                let lock = session.try_lock().unwrap();
                let trace = session
                    .ingest_staged_bounded(
                        &lock,
                        &request.outputs[0].staged_relative_path,
                        ArtifactSpec {
                            id: request.outputs[0].artifact_id.clone(),
                            kind: request.outputs[0].kind.clone(),
                            relative_path: request.outputs[0].destination_relative_path.clone(),
                            media_type: request.outputs[0].media_type.clone(),
                            producer: request.outputs[0].producer.clone(),
                            input_artifact_ids: vec![request_artifact.id.clone()],
                        },
                        request.outputs[0].max_bytes,
                    )
                    .unwrap();
                drop(lock);
                let Err(pending) = accept(&root, &session_id, export_transaction) else {
                    panic!("missing custom output must keep V2 export pending")
                };
                assert_eq!(pending.code, "CONTROLLER_OUTPUT_PREFLIGHT_FAILED");
                assert!(
                    session
                        .registered_artifacts(false)
                        .unwrap()
                        .iter()
                        .all(|artifact| artifact.id
                            != format!("controller-response-{export_transaction}"))
                );
                fixture_stage(
                    &session,
                    &request.outputs[1].staged_relative_path,
                    b"fixture-c-wire",
                );
                accept(&root, &session_id, export_transaction).unwrap();
                accept(&root, &session_id, export_transaction).unwrap();
                let artifacts = session.registered_artifacts(false).unwrap();
                let response_artifact = artifacts
                    .iter()
                    .find(|artifact| {
                        artifact.id == format!("controller-response-{export_transaction}")
                    })
                    .unwrap();
                let response =
                    read_controller_response_envelope(&session, response_artifact).unwrap();
                let ControllerResponseEnvelope::V2(response) = response else {
                    panic!("export response must be V2")
                };
                assert_eq!(response.output_artifacts.len(), 2);
                assert_eq!(response.output_artifacts[0].sha256, trace.sha256);
                assert_eq!(response.output_artifacts[0].kind, "raw_trace");
                assert_eq!(response.output_artifacts[1].kind, "custom_events");
                let public = perf_capture(&root, &session_id, None, false).unwrap();
                assert_eq!(
                    public.result["capture_artifacts"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter(|artifact| artifact["kind"] == "custom_events")
                        .count(),
                    1
                );
            },
        );
    }

    #[test]
    fn v2_start_abort_confirmation_releases_root_and_rebuilds_failed_progress() {
        let firmware = minimal_tricore_elf();
        let profile = v2_program_flow_profile(sha256(&firmware));
        crate::controller_qualification::with_test_compiled_target_adapter_profiles(
            vec![profile.clone()],
            || {
                let temporary = tempfile::tempdir().unwrap();
                let root =
                    ArtifactRoot::open(temporary.path().join("sessions"), SessionLimits::default())
                        .unwrap();
                let session = root.create_session(&json!({})).unwrap();
                let session_id = session.id().to_string();
                let firmware_staged = ArtifactPath::new("fixture-firmware.elf").unwrap();
                fixture_stage(&session, &firmware_staged, &firmware);
                crate::controller_qualification::provision_firmware(
                    &root,
                    &session_id,
                    &firmware_staged,
                )
                .unwrap();
                fixture_qualified_admission(&root, &session, &profile);
                crate::controller_qualification::select_scenario(
                    &root,
                    crate::cli::ControllerSelectScenarioArgs {
                        session: session_id.clone(),
                        scenario: "normal".to_owned(),
                    },
                )
                .unwrap();

                let capabilities = prepare(
                    &root,
                    &session_id,
                    PerfOperation::GetCapabilities.as_str(),
                    None,
                )
                .unwrap();
                let capabilities_transaction =
                    capabilities.result["transaction_id"].as_str().unwrap();
                let (request, _, _) =
                    pending_request(&root, &session_id, capabilities_transaction).unwrap();
                let ControllerRequestEnvelope::V1(request) = request else {
                    panic!("capabilities remains V1")
                };
                let evidence = json!({
                    "schema": "t32perf.controller-capabilities-evidence/v2", "operation": "perf_get_capabilities",
                    "binding_sha256": request.binding.binding_sha256,
                    "trace32_release": profile.build_gate.trace32_release, "trace32_build": profile.build_gate.minimum_build,
                    "architecture_package": profile.build_gate.architecture_package, "target_identifier": profile.target_identifier,
                    "probe_identifier": profile.probe_identifier, "license_features": profile.license_features,
                    "trace_routing": profile.trace_routing, "capture_modes": ["fixture-task-events"],
                    "trace_sinks": ["fixture-trace-sink"], "covered_cores": [0], "timestamp_supported": true,
                    "rtos_awareness": "fixture-orti/v1", "health_signals": t32perf_trace32::PROGRAM_FLOW_HEALTH_SIGNALS,
                    "initial_target_state": "running",
                });
                fixture_stage(
                    &session,
                    &request.response_staging_path,
                    &finished_wrapper(request.operation, &request.binding.binding_sha256),
                );
                fixture_stage(
                    &session,
                    &request.output.as_ref().unwrap().staged_relative_path,
                    &serde_json::to_vec(&evidence).unwrap(),
                );
                accept(&root, &session_id, capabilities_transaction).unwrap();

                let configured =
                    prepare(&root, &session_id, PerfOperation::Configure.as_str(), None).unwrap();
                let configured_transaction = configured.result["transaction_id"].as_str().unwrap();
                let (request, _, _) =
                    pending_request(&root, &session_id, configured_transaction).unwrap();
                let ControllerRequestEnvelope::V2(request) = request else {
                    panic!("configure must be V2")
                };
                let evidence = json!({
                    "schema": "t32perf.controller-configure-evidence/v1", "operation": "perf_configure",
                    "binding_sha256": request.binding.binding_sha256, "configuration_sha256": "1".repeat(64),
                    "capture_mode": "fixture-task-events", "trace_sink": "fixture-trace-sink", "timestamp_enabled": true,
                    "filters_verified": true, "trigger_verified": true, "initial_target_state": "running",
                    "workload_identity": "fixture-program-flow-workload/v1", "covered_cores": [0],
                });
                fixture_stage(
                    &session,
                    &request.response_staging_path,
                    &finished_wrapper(request.operation, &request.binding.binding_sha256),
                );
                fixture_stage(
                    &session,
                    &request.outputs[0].staged_relative_path,
                    &serde_json::to_vec(&evidence).unwrap(),
                );
                accept(&root, &session_id, configured_transaction).unwrap();

                let started =
                    prepare(&root, &session_id, PerfOperation::Start.as_str(), None).unwrap();
                let transaction = started.result["transaction_id"].as_str().unwrap();
                let (request, request_artifact, _) =
                    pending_request(&root, &session_id, transaction).unwrap();
                let ControllerRequestEnvelope::V2(request) = request else {
                    panic!("start must be V2")
                };
                let start_binding_sha256 = request.binding.binding_sha256.clone();
                let admitted_profile_sha256 = request
                    .target_adapter
                    .as_ref()
                    .unwrap()
                    .profile_sha256
                    .clone();
                abort(&root, &session_id, transaction, "operator_request").unwrap();
                confirm_abort(&root, &session_id, transaction, true).unwrap();
                let artifacts = session.registered_artifacts(false).unwrap();
                let receipt = artifacts
                    .iter()
                    .find(|artifact| {
                        artifact.id == format!("controller-abort-receipt-{transaction}")
                    })
                    .unwrap();
                assert_eq!(receipt.kind, CONTROLLER_ABORT_RECEIPT_KIND);
                assert_eq!(
                    receipt.input_artifact_ids,
                    vec![
                        request_artifact.id.clone(),
                        format!("controller-abort-{transaction}")
                    ]
                );
                let progress = controller_capture_progress(&root, &session_id).unwrap();
                assert_eq!(progress.state, t32perf_model::SessionStatus::Failed);
                assert!(progress.pending.is_none());
                assert!(root_active_transaction(&root).unwrap().is_none());

                let recovery = crate::controller_recovery::prepare_recovery(
                    &root,
                    &session_id,
                    transaction,
                    crate::controller_recovery::RecoveryScopeArgument::Target,
                )
                .unwrap();
                let candidate_profile_sha256 = profile.qualification_identity_digest().unwrap();
                assert_eq!(
                    recovery.result["evidence_expectation"]["profile_sha256"],
                    candidate_profile_sha256.as_str()
                );
                assert_ne!(candidate_profile_sha256, admitted_profile_sha256);
                let recovery_evidence = json!({
                    "schema": "t32perf.target-adapter-recovery-evidence/v1",
                    "profile_sha256": candidate_profile_sha256,
                    "binding_sha256": start_binding_sha256,
                    "failed_operation": "perf_start",
                    "failure_kind": "operation_failure",
                    "initial_target_state": "running",
                    "restored_target_state": "running",
                    "adapter_state_restored": true,
                    "upstream_abort_confirmed": true,
                    "upstream_abort_receipt_sha256": receipt.sha256,
                    "files_deleted": false,
                    "new_session_required": true
                });
                std::fs::write(
                    recovery.result["evidence_handoff_path"].as_str().unwrap(),
                    serde_json::to_vec(&recovery_evidence).unwrap(),
                )
                .unwrap();
                let reservation_id = recovery.result["reservation_id"].as_str().unwrap();
                let accepted =
                    crate::controller_recovery::accept_recovery(&root, reservation_id).unwrap();
                assert_eq!(accepted.result["already_recovered"], false);
                let repeated =
                    crate::controller_recovery::accept_recovery(&root, reservation_id).unwrap();
                assert_eq!(repeated.result["already_recovered"], true);
                assert_eq!(
                    crate::controller_recovery::root_quarantine_status(&root).unwrap()["active_quarantine_count"],
                    0
                );
                assert_eq!(
                    session.read_state().unwrap().status,
                    t32perf_model::SessionStatus::Failed
                );
            },
        );
    }
}
