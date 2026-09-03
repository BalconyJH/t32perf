//! Immutable deployment build-resource admission for `perf_run`.
//!
//! This boundary deliberately copies only deployment-configured, revalidated
//! files into a Created Session.  It does not infer collection capability from
//! a file: program-flow inputs are accepted only for a program-flow profile,
//! and custom-event inputs are accepted only when the selected compiled
//! adapter owns their collection and export contract.

use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Read as _,
    path::Path,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use t32perf_model::{
    Artifact, ArtifactPath, InstrumentationOverheadEvidenceDocument, SessionStatus, Sha256Digest,
    strict_json,
};
use t32perf_session::{
    ArtifactRoot, ArtifactSpec, Session, SessionLock, verify_opened_plain_file_identity,
};
use t32perf_trace32::{
    DriverPerformanceRunCustomEventResources, DriverPerformanceRunResourceInput,
    DriverPerformanceRunResources, ELF_SECTIONS_V1_FLAVOR, GNU_LD_MAP_V1_FLAVOR,
    MAX_C_WIRE_COUNTER_MAPPING_DOCUMENT_BYTES, TargetAdapterCaptureKind,
    TargetAdapterControllerProtocol, TargetAdapterCustomEventCollectorContract,
    TargetAdapterProfile, TargetAdapterScenario, parse_c_wire_counter_mapping,
    parse_target_adapter_scenario_selection, parse_trace32_task_events_mapping_template,
};

use crate::{
    app::AppError,
    controller_driver::{LoadedDriverConfig, require_performance_run_config},
    controller_qualification::{
        FIRMWARE_ELF_ARTIFACT_ID, load_session_admission, validate_firmware_artifact_envelope,
    },
};

pub(crate) const LINKER_MAP_ARTIFACT_ID: &str = "perf-run-linker-map";
pub(crate) const STACK_USAGE_ARTIFACT_ID: &str = "perf-run-stack-usage";
pub(crate) const STATIC_RAM_CONFIG_ARTIFACT_ID: &str = "perf-run-static-ram-config";
pub(crate) const TASK_EVENTS_MAPPING_TEMPLATE_ARTIFACT_ID: &str =
    "perf-run-task-events-mapping-template";
pub(crate) const BUILD_RESOURCE_PRODUCER: &str = "t32perf-target-adapter-provisioning/v1";
pub(crate) const PERFORMANCE_RUN_DEPLOYMENT_BINDING_ID: &str = "performance-run-deployment-binding";
pub(crate) const PERFORMANCE_RUN_DEPLOYMENT_BINDING_KIND: &str =
    "performance_run_deployment_binding";
pub(crate) const PERFORMANCE_RUN_DEPLOYMENT_BINDING_PATH: &str =
    "capture/deployment/performance-run-deployment-binding.json";
pub(crate) const PERFORMANCE_RUN_DEPLOYMENT_BINDING_PRODUCER: &str =
    "t32perf-performance-run-deployment/v1";
pub(crate) const PERFORMANCE_RUN_PROVISIONING_RECEIPT_ID: &str =
    "performance-run-provisioning-receipt";
pub(crate) const PERFORMANCE_RUN_PROVISIONING_RECEIPT_KIND: &str =
    "performance_run_provisioning_receipt";
pub(crate) const PERFORMANCE_RUN_PROVISIONING_RECEIPT_PATH: &str =
    "capture/deployment/performance-run-provisioning-receipt.json";
pub(crate) const PERFORMANCE_RUN_PROVISIONING_RECEIPT_PRODUCER: &str =
    "t32perf-performance-run-provisioning/v1";

const LINKER_MAP_PATH: &str = "capture/deployment/build-resources/linker.map";
const STACK_USAGE_PATH: &str = "capture/deployment/build-resources/stack-usage.su";
const STATIC_RAM_CONFIG_PATH: &str = "capture/deployment/build-resources/static-ram-config.json";
pub(crate) const ORTI_KIND: &str = "trace32_orti";
pub(crate) const ORTI_PATH: &str = "capture/deployment/program-flow/orti.bin";
pub(crate) const ORTI_MEDIA_TYPE: &str = "application/octet-stream";
pub(crate) const TASK_MARKERS_KIND: &str = "trace32_task_markers";
pub(crate) const TASK_MARKERS_PATH: &str = "capture/deployment/program-flow/task-markers.bin";
pub(crate) const TASK_MARKERS_MEDIA_TYPE: &str = "application/octet-stream";
pub(crate) const TASK_EVENTS_MAPPING_TEMPLATE_KIND: &str = "trace32_task_events_mapping_template";
pub(crate) const TASK_EVENTS_MAPPING_TEMPLATE_PATH: &str =
    "capture/deployment/program-flow/task-events-mapping-template.json";
pub(crate) const TASK_EVENTS_MAPPING_TEMPLATE_MEDIA_TYPE: &str = "application/json";
pub(crate) const CUSTOM_EVENT_MAPPING_KIND: &str = "c_wire_counter_mapping_source";
pub(crate) const CUSTOM_EVENT_MAPPING_PATH: &str =
    "capture/deployment/custom-events/c-wire-counter-mapping.json";
pub(crate) const CUSTOM_EVENT_OVERHEAD_KIND: &str = "instrumentation_overhead";
pub(crate) const CUSTOM_EVENT_OVERHEAD_PATH: &str =
    "capture/deployment/custom-events/instrumentation-overhead.json";

const MAX_LINKER_MAP_BYTES: u64 = 256 * 1024 * 1024;
const MAX_STACK_USAGE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_STATIC_RAM_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_ORTI_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TASK_MARKERS_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TASK_EVENTS_MAPPING_BYTES: u64 = 16 * 1024 * 1024;
const MAX_INSTRUMENTATION_OVERHEAD_BYTES: u64 = 1024 * 1024;
const MAX_DEPLOYMENT_BINDING_BYTES: u64 = 4 * 1024;
const MAX_PROVISIONING_RECEIPT_BYTES: u64 = 16 * 1024;

const STRICT_PERFORMANCE_RUN_RESERVED_ARTIFACT_IDS: &[&str] = &[
    "observations",
    "capture-config",
    "performance-run-normalize-config",
    "trace32-task-events-mapping",
    "capture-attestation",
    "capture-receipt",
    "attestation-signing-request",
    "attestation-signer-dispatch-intent",
    "analysis-request",
    "analysis-stage",
    "derived",
    "health",
    "analysis-summary",
    "hotspots",
    "static-ram",
    "stack-usage",
    "perfetto",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum PerformanceRunDeploymentBindingSchemaVersion {
    #[serde(rename = "t32perf.performance-run-deployment-binding/v1")]
    V1,
}

/// Non-secret Session binding for the complete deployment configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PerformanceRunDeploymentBinding {
    schema: PerformanceRunDeploymentBindingSchemaVersion,
    pub(crate) session_id: String,
    pub(crate) session_request_sha256: Sha256Digest,
    /// Digest of the complete t32mcp deployment configuration, including MCP
    /// executable and bundle gates as well as the performance-run block.
    pub(crate) driver_config_sha256: Sha256Digest,
    pub(crate) performance_run_deployment_sha256: Sha256Digest,
    pub(crate) policy_id: String,
    pub(crate) key_id: String,
    pub(crate) signer_executable_sha256: Sha256Digest,
    pub(crate) workload_executable_sha256: Sha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum PerformanceRunProvisioningReceiptSchemaVersion {
    #[serde(rename = "t32perf.performance-run-provisioning-receipt/v1")]
    V1,
}

/// One exact, terminal claim about the immutable deployment artifacts that
/// existed before the first controller request.  The receipt is deliberately
/// published last: its presence is the authority that provisioning completed,
/// while a prefix of these artifacts is only a resumable checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PerformanceRunProvisioningReceipt {
    schema: PerformanceRunProvisioningReceiptSchemaVersion,
    session_id: String,
    session_request_sha256: Sha256Digest,
    driver_config_sha256: Sha256Digest,
    performance_run_deployment_sha256: Sha256Digest,
    artifact_claims: Vec<ProvisioningArtifactClaim>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisioningArtifactClaim {
    id: String,
    sha256: Sha256Digest,
}

#[derive(Debug, Clone)]
pub(crate) struct PerformanceRunCustomEventResourceBinding {
    pub(crate) collector: TargetAdapterCustomEventCollectorContract,
    pub(crate) mapping_artifact: Artifact,
    pub(crate) overhead_artifact: Artifact,
    pub(crate) overhead_document: InstrumentationOverheadEvidenceDocument,
}

#[derive(Debug, Clone)]
struct CustomEventResourceContract {
    collector: TargetAdapterCustomEventCollectorContract,
    inputs: DriverPerformanceRunCustomEventResources,
}

#[derive(Debug)]
struct PreparedCustomEventResources {
    contract: CustomEventResourceContract,
    mapping_bytes: Vec<u8>,
    overhead_bytes: Vec<u8>,
    overhead_document: InstrumentationOverheadEvidenceDocument,
    provenance: Vec<String>,
}

/// Persists or exact-revalidates the deployment identity before side effects.
pub(crate) fn ensure_performance_run_deployment_binding(
    session: &Session,
    lock: &SessionLock,
    loaded: &LoadedDriverConfig,
) -> Result<Artifact, AppError> {
    let deployment = require_performance_run_config(loaded).map_err(AppError::operational)?;
    let document = PerformanceRunDeploymentBinding {
        schema: PerformanceRunDeploymentBindingSchemaVersion::V1,
        session_id: session.id().to_string(),
        session_request_sha256: session.request_sha256().map_err(AppError::operational)?,
        driver_config_sha256: driver_config_sha256(loaded)?,
        performance_run_deployment_sha256:
            crate::controller_driver::performance_run_deployment_sha256(loaded)
                .map_err(AppError::operational)?,
        policy_id: deployment.attestation.policy_id.clone(),
        key_id: deployment.attestation.key_id.clone(),
        signer_executable_sha256: deployment
            .attestation
            .signer_command
            .expected_executable_sha256
            .clone(),
        workload_executable_sha256: deployment
            .workload_command
            .expected_executable_sha256
            .clone(),
    };
    let bytes = serde_json::to_vec(&document).map_err(AppError::operational)?;
    let artifacts = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    let spec = ArtifactSpec {
        id: PERFORMANCE_RUN_DEPLOYMENT_BINDING_ID.to_owned(),
        kind: PERFORMANCE_RUN_DEPLOYMENT_BINDING_KIND.to_owned(),
        relative_path: ArtifactPath::new(PERFORMANCE_RUN_DEPLOYMENT_BINDING_PATH)
            .map_err(AppError::operational)?,
        media_type: "application/json".to_owned(),
        producer: PERFORMANCE_RUN_DEPLOYMENT_BINDING_PRODUCER.to_owned(),
        input_artifact_ids: Vec::new(),
    };
    if let Some(existing) = artifacts.iter().find(|artifact| artifact.id == spec.id) {
        session
            .verify_artifact(existing, true)
            .map_err(AppError::operational)?;
        if existing.kind != spec.kind
            || existing.relative_path != spec.relative_path
            || existing.media_type != spec.media_type
            || existing.producer != spec.producer
            || !existing.input_artifact_ids.is_empty()
            || existing.sha256 != digest(&bytes)
        {
            return Err(AppError::operational(
                "immutable performance-run deployment binding conflicts with the revalidated deployment",
            ));
        }
        let registered: PerformanceRunDeploymentBinding =
            read_registered_json(session, existing, MAX_DEPLOYMENT_BINDING_BYTES)?;
        if registered != document {
            return Err(AppError::operational(
                "performance-run deployment binding does not exactly decode to the revalidated deployment",
            ));
        }
        return Ok(existing.clone());
    }
    if session.read_state().map_err(AppError::operational)?.status != SessionStatus::Created {
        return Err(AppError::operational(
            "performance-run deployment binding is absent after Session creation; refusing side effects under an unbound deployment",
        ));
    }
    if !artifacts.is_empty() {
        return Err(AppError::operational(
            "performance-run deployment binding must be the first durable provisioning artifact",
        ));
    }
    let staged = ArtifactPath::new("provisioning/performance-run-deployment-binding.json")
        .map_err(AppError::operational)?;
    let maximum = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    session
        .ensure_staged_exact(lock, &staged, &bytes, maximum)
        .map_err(AppError::operational)?;
    session
        .ingest_staged_bounded(lock, &staged, spec, maximum)
        .map_err(AppError::operational)
}

pub(crate) fn require_performance_run_deployment_binding(
    session: &Session,
    artifacts: &[Artifact],
    loaded: &LoadedDriverConfig,
) -> Result<Artifact, AppError> {
    let artifact = artifacts
        .iter()
        .find(|artifact| artifact.id == PERFORMANCE_RUN_DEPLOYMENT_BINDING_ID)
        .ok_or_else(|| AppError::operational("performance-run deployment binding is absent"))?;
    session
        .verify_artifact(artifact, true)
        .map_err(AppError::operational)?;
    let document: PerformanceRunDeploymentBinding =
        read_registered_json(session, artifact, MAX_DEPLOYMENT_BINDING_BYTES)?;
    let expected = PerformanceRunDeploymentBinding {
        schema: PerformanceRunDeploymentBindingSchemaVersion::V1,
        session_id: session.id().to_string(),
        session_request_sha256: session.request_sha256().map_err(AppError::operational)?,
        driver_config_sha256: driver_config_sha256(loaded)?,
        performance_run_deployment_sha256:
            crate::controller_driver::performance_run_deployment_sha256(loaded)
                .map_err(AppError::operational)?,
        policy_id: require_performance_run_config(loaded)
            .map_err(AppError::operational)?
            .attestation
            .policy_id
            .clone(),
        key_id: require_performance_run_config(loaded)
            .map_err(AppError::operational)?
            .attestation
            .key_id
            .clone(),
        signer_executable_sha256: require_performance_run_config(loaded)
            .map_err(AppError::operational)?
            .attestation
            .signer_command
            .expected_executable_sha256
            .clone(),
        workload_executable_sha256: require_performance_run_config(loaded)
            .map_err(AppError::operational)?
            .workload_command
            .expected_executable_sha256
            .clone(),
    };
    if document != expected
        || artifact.kind != PERFORMANCE_RUN_DEPLOYMENT_BINDING_KIND
        || artifact.relative_path.as_str() != PERFORMANCE_RUN_DEPLOYMENT_BINDING_PATH
        || artifact.media_type != "application/json"
        || artifact.producer != PERFORMANCE_RUN_DEPLOYMENT_BINDING_PRODUCER
        || !artifact.input_artifact_ids.is_empty()
    {
        return Err(AppError::operational(
            "performance-run deployment binding conflicts with the active deployment",
        ));
    }
    Ok(artifact.clone())
}

pub(crate) fn workload_deployment_binding_claim(
    session: &Session,
    artifacts: &[Artifact],
) -> Result<Option<(Artifact, PerformanceRunDeploymentBinding)>, AppError> {
    let Some(artifact) = artifacts
        .iter()
        .find(|artifact| artifact.id == PERFORMANCE_RUN_DEPLOYMENT_BINDING_ID)
    else {
        return Ok(None);
    };
    if artifact.kind != PERFORMANCE_RUN_DEPLOYMENT_BINDING_KIND
        || artifact.relative_path.as_str() != PERFORMANCE_RUN_DEPLOYMENT_BINDING_PATH
        || artifact.media_type != "application/json"
        || artifact.producer != PERFORMANCE_RUN_DEPLOYMENT_BINDING_PRODUCER
        || !artifact.input_artifact_ids.is_empty()
    {
        return Err(AppError::operational(
            "workload deployment binding has an invalid envelope",
        ));
    }
    session
        .verify_artifact(artifact, true)
        .map_err(AppError::operational)?;
    Ok(Some((
        artifact.clone(),
        read_registered_json(session, artifact, MAX_DEPLOYMENT_BINDING_BYTES)?,
    )))
}

/// Publishes the last provisioning checkpoint, or exact-revalidates it on a
/// retry.  Callers must have completed the firmware, qualification, scenario
/// and build-resource substeps first; this function intentionally never
/// interprets a partial prefix as admission to start the controller.
pub(crate) fn ensure_performance_run_provisioning_receipt(
    session: &Session,
    lock: &SessionLock,
    loaded: &LoadedDriverConfig,
) -> Result<Artifact, AppError> {
    let artifacts = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    let document = provisioning_receipt_document(session, &artifacts, loaded)?;
    let bytes = serde_json::to_vec(&document).map_err(AppError::operational)?;
    let spec = ArtifactSpec {
        id: PERFORMANCE_RUN_PROVISIONING_RECEIPT_ID.to_owned(),
        kind: PERFORMANCE_RUN_PROVISIONING_RECEIPT_KIND.to_owned(),
        relative_path: ArtifactPath::new(PERFORMANCE_RUN_PROVISIONING_RECEIPT_PATH)
            .map_err(AppError::operational)?,
        media_type: "application/json".to_owned(),
        producer: PERFORMANCE_RUN_PROVISIONING_RECEIPT_PRODUCER.to_owned(),
        input_artifact_ids: document
            .artifact_claims
            .iter()
            .map(|claim| claim.id.clone())
            .collect(),
    };
    if let Some(existing) = artifacts.iter().find(|artifact| artifact.id == spec.id) {
        return require_performance_run_provisioning_receipt(session, &artifacts, loaded)
            .map(|_| existing.clone());
    }
    if session.read_state().map_err(AppError::operational)?.status != SessionStatus::Created
        || artifacts.iter().any(|artifact| {
            artifact
                .id
                .starts_with(crate::controller::CONTROLLER_ARTIFACT_ID_PREFIX)
        })
    {
        return Err(AppError::operational(
            "performance-run provisioning is incomplete after controller activity; refusing to create a completion receipt",
        ));
    }
    let staged = ArtifactPath::new("provisioning/performance-run-provisioning-receipt.json")
        .map_err(AppError::operational)?;
    let maximum = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    session
        .ensure_staged_exact(lock, &staged, &bytes, maximum)
        .map_err(AppError::operational)?;
    session
        .ingest_staged_bounded(lock, &staged, spec, maximum)
        .map_err(AppError::operational)
}

/// Requires the authority published by
/// [`ensure_performance_run_provisioning_receipt`].  A durable prefix is not
/// equivalent to a completion receipt, even if its artifacts happen to be
/// individually valid.
pub(crate) fn require_performance_run_provisioning_receipt(
    session: &Session,
    artifacts: &[Artifact],
    loaded: &LoadedDriverConfig,
) -> Result<Artifact, AppError> {
    let artifact = artifacts
        .iter()
        .find(|artifact| artifact.id == PERFORMANCE_RUN_PROVISIONING_RECEIPT_ID)
        .ok_or_else(|| {
            AppError::operational("performance-run provisioning completion receipt is absent")
        })?;
    let document = provisioning_receipt_document(session, artifacts, loaded)?;
    let bytes = serde_json::to_vec(&document).map_err(AppError::operational)?;
    if artifact.kind != PERFORMANCE_RUN_PROVISIONING_RECEIPT_KIND
        || artifact.relative_path.as_str() != PERFORMANCE_RUN_PROVISIONING_RECEIPT_PATH
        || artifact.media_type != "application/json"
        || artifact.producer != PERFORMANCE_RUN_PROVISIONING_RECEIPT_PRODUCER
        || artifact.input_artifact_ids
            != document
                .artifact_claims
                .iter()
                .map(|claim| claim.id.clone())
                .collect::<Vec<_>>()
        || artifact.sha256 != digest(&bytes)
    {
        return Err(AppError::operational(
            "performance-run provisioning completion receipt conflicts with durable deployment evidence",
        ));
    }
    let registered: PerformanceRunProvisioningReceipt =
        read_registered_json(session, artifact, MAX_PROVISIONING_RECEIPT_BYTES)?;
    if registered != document {
        return Err(AppError::operational(
            "performance-run provisioning completion receipt does not exactly decode to deployment evidence",
        ));
    }
    let (profile, _catalog, _qualification, _scenarios) =
        load_session_admission(session, artifacts)?;
    let durable_custom = load_provisioned_custom_event_resources(session, artifacts, &profile)?;
    if profile.controller_protocol == TargetAdapterControllerProtocol::V2CustomEventsExport
        && durable_custom.is_none()
    {
        return Err(AppError::operational(
            "Controller V2 provisioning receipt lacks durable custom-event resources",
        ));
    }
    Ok(artifact.clone())
}

fn provisioning_receipt_document(
    session: &Session,
    artifacts: &[Artifact],
    loaded: &LoadedDriverConfig,
) -> Result<PerformanceRunProvisioningReceipt, AppError> {
    let binding = require_performance_run_deployment_binding(session, artifacts, loaded)?;
    let registered_binding: PerformanceRunDeploymentBinding =
        read_registered_json(session, &binding, MAX_DEPLOYMENT_BINDING_BYTES)?;
    let firmware = artifacts
        .iter()
        .find(|artifact| artifact.id == FIRMWARE_ELF_ARTIFACT_ID)
        .ok_or_else(|| AppError::operational("performance-run provisioning lacks firmware"))?;
    validate_firmware_artifact_envelope(firmware)?;
    session
        .verify_artifact(firmware, true)
        .map_err(AppError::operational)?;
    let (profile, _catalog, qualification, allowed_scenarios) =
        load_session_admission(session, artifacts)?;
    if qualification.is_empty() {
        return Err(AppError::operational(
            "performance-run provisioning lacks qualified target-adapter admission",
        ));
    }
    let scenario = artifacts
        .iter()
        .find(|artifact| artifact.id == crate::controller::TARGET_ADAPTER_SCENARIO_ARTIFACT_ID)
        .ok_or_else(|| AppError::operational("performance-run provisioning lacks scenario"))?;
    validate_scenario(
        session,
        scenario,
        &profile,
        &qualification,
        &allowed_scenarios,
    )?;
    let deployment = require_performance_run_config(loaded).map_err(AppError::operational)?;
    let policy = crate::attestation::require_attestation_policy_snapshot(
        session,
        artifacts,
        &deployment.attestation.policy_sha256,
        &deployment.attestation.policy_id,
        &deployment.attestation.key_id,
    )
    .map_err(AppError::operational)?;

    let mut provenance = vec![firmware.id.clone()];
    provenance.extend(qualification.iter().map(|artifact| artifact.id.clone()));
    provenance.push(binding.id.clone());
    let resources = complete_build_resources(session, artifacts, loaded, &profile, &provenance)?;

    let mut claimed = vec![binding, firmware.clone(), scenario.clone(), policy];
    claimed.extend(qualification);
    claimed.extend(resources);
    Ok(PerformanceRunProvisioningReceipt {
        schema: PerformanceRunProvisioningReceiptSchemaVersion::V1,
        session_id: registered_binding.session_id,
        session_request_sha256: registered_binding.session_request_sha256,
        driver_config_sha256: registered_binding.driver_config_sha256,
        performance_run_deployment_sha256: registered_binding.performance_run_deployment_sha256,
        artifact_claims: provisioning_artifact_claims(claimed)?,
    })
}

fn provisioning_artifact_claims(
    mut artifacts: Vec<Artifact>,
) -> Result<Vec<ProvisioningArtifactClaim>, AppError> {
    artifacts.sort_by(|left, right| left.id.cmp(&right.id));
    if artifacts.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return Err(AppError::operational(
            "performance-run provisioning evidence has duplicate artifact identities",
        ));
    }
    Ok(artifacts
        .into_iter()
        .map(|artifact| ProvisioningArtifactClaim {
            id: artifact.id,
            sha256: artifact.sha256,
        })
        .collect())
}

fn validate_scenario(
    session: &Session,
    artifact: &Artifact,
    profile: &t32perf_trace32::TargetAdapterProfile,
    qualification: &[Artifact],
    allowed_scenarios: &[TargetAdapterScenario],
) -> Result<(), AppError> {
    if artifact.kind != crate::controller::TARGET_ADAPTER_SCENARIO_KIND
        || artifact.relative_path.as_str() != crate::controller::TARGET_ADAPTER_SCENARIO_PATH
        || artifact.media_type != "application/json"
        || artifact.producer != crate::controller::TARGET_ADAPTER_SCENARIO_PRODUCER
    {
        return Err(AppError::operational(
            "performance-run provisioning scenario has an invalid envelope",
        ));
    }
    let (expected, inputs) = crate::controller::provision_target_adapter_scenario(
        TargetAdapterScenario::Normal,
        profile,
        qualification,
        allowed_scenarios,
    )?;
    if artifact.input_artifact_ids != inputs {
        return Err(AppError::operational(
            "performance-run provisioning scenario has non-canonical provenance",
        ));
    }
    let bytes = read_registered_bytes(session, artifact, 16 * 1024)?;
    let selected =
        parse_target_adapter_scenario_selection(&bytes).map_err(AppError::operational)?;
    if selected != expected {
        return Err(AppError::operational(
            "performance-run provisioning scenario does not exactly select normal deployment",
        ));
    }
    Ok(())
}

fn custom_event_resource_contract(
    session: &Session,
    artifacts: &[Artifact],
    profile: &TargetAdapterProfile,
    resources: &DriverPerformanceRunResources,
) -> Result<Option<CustomEventResourceContract>, AppError> {
    profile.validate().map_err(AppError::operational)?;
    let configured = resources.custom_events.as_ref();
    match profile.controller_protocol {
        TargetAdapterControllerProtocol::V1 => {
            if configured.is_some() {
                return Err(AppError::unsupported(
                    "performance-run custom_events",
                    "Controller V1 target adapters do not own a custom-event collector contract",
                ));
            }
            if artifacts.iter().any(is_custom_event_resource_artifact) {
                return Err(AppError::operational(
                    "immutable Session contains custom-event deployment artifacts but the selected V1 profile does not configure them",
                ));
            }
            Ok(None)
        }
        TargetAdapterControllerProtocol::V2CustomEventsExport => {
            let collector = profile.custom_event_collector.clone().ok_or_else(|| {
                AppError::operational(
                    "Controller V2 custom-event profile omits its collector contract",
                )
            })?;
            let inputs = configured.cloned().ok_or_else(|| {
                AppError::operational(
                    "Controller V2 custom-event profile requires both deployment custom-event resources",
                )
            })?;
            if resources.program_flow.is_none() {
                return Err(AppError::operational(
                    "Controller V2 custom-event deployment also requires program-flow resources",
                ));
            }
            if collector.max_output_bytes > session.limits().max_file_bytes {
                return Err(AppError::operational(
                    "custom-event collector output bound exceeds the Session file limit",
                ));
            }
            validate_custom_event_resource_ids(profile, &collector)?;
            validate_custom_event_resource_namespace(artifacts, &collector)?;
            Ok(Some(CustomEventResourceContract { collector, inputs }))
        }
    }
}

fn validate_custom_event_resource_ids(
    profile: &TargetAdapterProfile,
    collector: &TargetAdapterCustomEventCollectorContract,
) -> Result<(), AppError> {
    if collector.source_id == "performance-run-trace32-program-flow" {
        return Err(AppError::operational(
            "custom-event collector source_id collides with the fixed TASKEVENTS source",
        ));
    }
    let mut reserved = BTreeSet::from([
        LINKER_MAP_ARTIFACT_ID,
        STACK_USAGE_ARTIFACT_ID,
        STATIC_RAM_CONFIG_ARTIFACT_ID,
        TASK_EVENTS_MAPPING_TEMPLATE_ARTIFACT_ID,
        PERFORMANCE_RUN_DEPLOYMENT_BINDING_ID,
        PERFORMANCE_RUN_PROVISIONING_RECEIPT_ID,
        FIRMWARE_ELF_ARTIFACT_ID,
        crate::controller::FIRMWARE_S3_ARTIFACT_ID,
        crate::controller::TARGET_ADAPTER_SCENARIO_ARTIFACT_ID,
        crate::attestation::CAPTURE_TRUST_POLICY_ID,
    ]);
    if let Some(normal) = profile.scenario(TargetAdapterScenario::Normal)
        && let TargetAdapterCaptureKind::ProgramFlowTaskEvents {
            orti_artifact_id,
            task_marker_artifact_id,
            ..
        } = &normal.capture.capture_kind
    {
        reserved.insert(orti_artifact_id);
        reserved.insert(task_marker_artifact_id);
    }
    for (field, id) in [
        ("mapping_artifact_id", &collector.mapping_artifact_id),
        (
            "instrumentation_overhead_artifact_id",
            &collector.instrumentation_overhead_artifact_id,
        ),
    ] {
        if reserved.contains(id.as_str()) || is_strict_performance_run_reserved_artifact_id(id) {
            return Err(AppError::operational(format!(
                "custom-event collector {field} collides with a fixed or provisioned artifact ID"
            )));
        }
    }
    Ok(())
}

fn is_strict_performance_run_reserved_artifact_id(id: &str) -> bool {
    id.starts_with(crate::controller::CONTROLLER_ARTIFACT_ID_PREFIX)
        || id.starts_with("c-wire-counter-map-")
        || STRICT_PERFORMANCE_RUN_RESERVED_ARTIFACT_IDS.contains(&id)
}

fn validate_custom_event_resource_namespace(
    artifacts: &[Artifact],
    collector: &TargetAdapterCustomEventCollectorContract,
) -> Result<(), AppError> {
    for artifact in artifacts {
        let expected_mapping = artifact.id == collector.mapping_artifact_id;
        let expected_overhead = artifact.id == collector.instrumentation_overhead_artifact_id;
        if expected_mapping
            && (artifact.kind != CUSTOM_EVENT_MAPPING_KIND
                || artifact.relative_path.as_str() != CUSTOM_EVENT_MAPPING_PATH)
        {
            return Err(AppError::operational(
                "custom-event mapping artifact ID is already claimed by a different envelope",
            ));
        }
        if expected_overhead
            && (artifact.kind != CUSTOM_EVENT_OVERHEAD_KIND
                || artifact.relative_path.as_str() != CUSTOM_EVENT_OVERHEAD_PATH)
        {
            return Err(AppError::operational(
                "custom-event overhead artifact ID is already claimed by a different envelope",
            ));
        }
        if artifact.relative_path.as_str() == CUSTOM_EVENT_MAPPING_PATH && !expected_mapping {
            return Err(AppError::operational(
                "custom-event mapping deployment path is claimed by a non-canonical artifact",
            ));
        }
        if artifact.relative_path.as_str() == CUSTOM_EVENT_OVERHEAD_PATH && !expected_overhead {
            return Err(AppError::operational(
                "custom-event overhead deployment path is claimed by a non-canonical artifact",
            ));
        }
        if artifact.kind == CUSTOM_EVENT_MAPPING_KIND && !expected_mapping {
            return Err(AppError::operational(
                "custom-event mapping kind is claimed by a non-canonical artifact",
            ));
        }
        if artifact.kind == CUSTOM_EVENT_OVERHEAD_KIND && !expected_overhead {
            return Err(AppError::operational(
                "custom-event overhead kind is claimed by a non-canonical artifact",
            ));
        }
    }
    Ok(())
}

fn is_custom_event_resource_artifact(artifact: &Artifact) -> bool {
    artifact
        .relative_path
        .as_str()
        .starts_with("capture/deployment/custom-events/")
        || matches!(
            artifact.kind.as_str(),
            CUSTOM_EVENT_MAPPING_KIND | CUSTOM_EVENT_OVERHEAD_KIND
        )
}

fn prepare_custom_event_resources(
    session: &Session,
    artifacts: &[Artifact],
    profile: &TargetAdapterProfile,
    resources: &DriverPerformanceRunResources,
    provenance: &[String],
) -> Result<Option<PreparedCustomEventResources>, AppError> {
    let Some(contract) = custom_event_resource_contract(session, artifacts, profile, resources)?
    else {
        return Ok(None);
    };
    let mapping_maximum = u64::try_from(MAX_C_WIRE_COUNTER_MAPPING_DOCUMENT_BYTES)
        .expect("C-wire mapping bound fits u64");
    let mapping_resource = ResourceSpec {
        id: &contract.collector.mapping_artifact_id,
        kind: CUSTOM_EVENT_MAPPING_KIND,
        path: CUSTOM_EVENT_MAPPING_PATH,
        media_type: "application/json",
        staging_name: "custom-event-c-wire-mapping",
        input: &contract.inputs.c_wire_mapping,
        maximum: mapping_maximum,
        inputs: provenance.to_vec(),
    };
    let overhead_resource = ResourceSpec {
        id: &contract.collector.instrumentation_overhead_artifact_id,
        kind: CUSTOM_EVENT_OVERHEAD_KIND,
        path: CUSTOM_EVENT_OVERHEAD_PATH,
        media_type: "application/json",
        staging_name: "custom-event-instrumentation-overhead",
        input: &contract.inputs.instrumentation_overhead,
        maximum: MAX_INSTRUMENTATION_OVERHEAD_BYTES,
        inputs: provenance.to_vec(),
    };

    // Read both exact snapshots before parsing or publishing either artifact.
    let mapping_bytes = read_existing_or_deployment_resource(
        session,
        artifacts,
        &mapping_resource,
        "custom-event C-wire mapping",
    )?;
    let overhead_bytes = read_existing_or_deployment_resource(
        session,
        artifacts,
        &overhead_resource,
        "custom-event instrumentation overhead",
    )?;
    validate_custom_event_mapping(
        &mapping_bytes,
        &contract.collector,
        "custom-event C-wire mapping",
    )?;
    let overhead_document = validate_custom_event_overhead(
        &overhead_bytes,
        &contract.collector,
        "custom-event instrumentation overhead",
    )?;
    Ok(Some(PreparedCustomEventResources {
        contract,
        mapping_bytes,
        overhead_bytes,
        overhead_document,
        provenance: provenance.to_vec(),
    }))
}

fn validate_custom_event_overhead(
    bytes: &[u8],
    collector: &TargetAdapterCustomEventCollectorContract,
    description: &str,
) -> Result<InstrumentationOverheadEvidenceDocument, AppError> {
    let document: InstrumentationOverheadEvidenceDocument =
        strict_json::from_slice(bytes).map_err(AppError::operational)?;
    document.validate().map_err(AppError::operational)?;
    if document.instrumentation_method != "t32perf-c-wire/v1"
        || document.transport != collector.transport
    {
        return Err(AppError::operational(format!(
            "{description} does not match the collector instrumentation method and transport"
        )));
    }
    Ok(document)
}

fn validate_custom_event_mapping(
    bytes: &[u8],
    collector: &TargetAdapterCustomEventCollectorContract,
    description: &str,
) -> Result<(), AppError> {
    let mapping = parse_c_wire_counter_mapping(bytes).map_err(AppError::operational)?;
    if mapping
        .contexts
        .iter()
        .any(|context| context.core_id != Some(collector.core_id))
    {
        return Err(AppError::operational(format!(
            "{description} contains a context without the collector's exact core affinity"
        )));
    }
    Ok(())
}

fn provision_prepared_custom_event_resources(
    session: &Session,
    lock: &SessionLock,
    artifacts: &[Artifact],
    prepared: PreparedCustomEventResources,
) -> Result<PerformanceRunCustomEventResourceBinding, AppError> {
    let mapping_artifact = provision_bytes(
        session,
        lock,
        artifacts,
        ResourceSpecBytes {
            id: &prepared.contract.collector.mapping_artifact_id,
            kind: CUSTOM_EVENT_MAPPING_KIND,
            path: CUSTOM_EVENT_MAPPING_PATH,
            media_type: "application/json",
            staging_name: "custom-event-c-wire-mapping",
            bytes: prepared.mapping_bytes,
            inputs: prepared.provenance.clone(),
        },
    )?;
    let overhead_artifact = provision_bytes(
        session,
        lock,
        artifacts,
        ResourceSpecBytes {
            id: &prepared
                .contract
                .collector
                .instrumentation_overhead_artifact_id,
            kind: CUSTOM_EVENT_OVERHEAD_KIND,
            path: CUSTOM_EVENT_OVERHEAD_PATH,
            media_type: "application/json",
            staging_name: "custom-event-instrumentation-overhead",
            bytes: prepared.overhead_bytes,
            inputs: prepared.provenance,
        },
    )?;
    Ok(PerformanceRunCustomEventResourceBinding {
        collector: prepared.contract.collector,
        mapping_artifact,
        overhead_artifact,
        overhead_document: prepared.overhead_document,
    })
}

pub(crate) fn load_performance_run_custom_event_resources(
    session: &Session,
    artifacts: &[Artifact],
    loaded: &LoadedDriverConfig,
    profile: &TargetAdapterProfile,
    provenance: &[String],
) -> Result<Option<PerformanceRunCustomEventResourceBinding>, AppError> {
    let deployment = require_performance_run_config(loaded).map_err(AppError::operational)?;
    load_registered_custom_event_resources(
        session,
        artifacts,
        profile,
        &deployment.resources,
        provenance,
    )
}

fn load_registered_custom_event_resources(
    session: &Session,
    artifacts: &[Artifact],
    profile: &TargetAdapterProfile,
    resources: &DriverPerformanceRunResources,
    provenance: &[String],
) -> Result<Option<PerformanceRunCustomEventResourceBinding>, AppError> {
    let Some(contract) = custom_event_resource_contract(session, artifacts, profile, resources)?
    else {
        return Ok(None);
    };
    let mapping_maximum = u64::try_from(MAX_C_WIRE_COUNTER_MAPPING_DOCUMENT_BYTES)
        .expect("C-wire mapping bound fits u64");
    let mapping_resource = ResourceSpec {
        id: &contract.collector.mapping_artifact_id,
        kind: CUSTOM_EVENT_MAPPING_KIND,
        path: CUSTOM_EVENT_MAPPING_PATH,
        media_type: "application/json",
        staging_name: "custom-event-c-wire-mapping",
        input: &contract.inputs.c_wire_mapping,
        maximum: mapping_maximum,
        inputs: provenance.to_vec(),
    };
    let overhead_resource = ResourceSpec {
        id: &contract.collector.instrumentation_overhead_artifact_id,
        kind: CUSTOM_EVENT_OVERHEAD_KIND,
        path: CUSTOM_EVENT_OVERHEAD_PATH,
        media_type: "application/json",
        staging_name: "custom-event-instrumentation-overhead",
        input: &contract.inputs.instrumentation_overhead,
        maximum: MAX_INSTRUMENTATION_OVERHEAD_BYTES,
        inputs: provenance.to_vec(),
    };
    let mapping_artifact =
        validate_existing_external_resource(session, artifacts, &mapping_resource)?
            .ok_or_else(|| AppError::operational("custom-event mapping artifact is absent"))?;
    let overhead_artifact =
        validate_existing_external_resource(session, artifacts, &overhead_resource)?
            .ok_or_else(|| AppError::operational("custom-event overhead artifact is absent"))?;
    let mapping_bytes = read_registered_bytes(session, &mapping_artifact, mapping_maximum)?;
    validate_custom_event_mapping(
        &mapping_bytes,
        &contract.collector,
        "registered custom-event C-wire mapping",
    )?;
    let overhead_bytes = read_registered_bytes(
        session,
        &overhead_artifact,
        MAX_INSTRUMENTATION_OVERHEAD_BYTES,
    )?;
    let overhead_document = validate_custom_event_overhead(
        &overhead_bytes,
        &contract.collector,
        "registered custom-event instrumentation overhead",
    )?;
    Ok(Some(PerformanceRunCustomEventResourceBinding {
        collector: contract.collector,
        mapping_artifact,
        overhead_artifact,
        overhead_document,
    }))
}

pub(crate) fn load_provisioned_custom_event_resources(
    session: &Session,
    artifacts: &[Artifact],
    profile: &TargetAdapterProfile,
) -> Result<Option<PerformanceRunCustomEventResourceBinding>, AppError> {
    profile.validate().map_err(AppError::operational)?;
    let collector = match profile.controller_protocol {
        TargetAdapterControllerProtocol::V1 => {
            if artifacts.iter().any(is_custom_event_resource_artifact) {
                return Err(AppError::operational(
                    "V1 Session contains custom-event deployment artifacts",
                ));
            }
            return Ok(None);
        }
        TargetAdapterControllerProtocol::V2CustomEventsExport => profile
            .custom_event_collector
            .clone()
            .ok_or_else(|| AppError::operational("V2 profile omits its custom-event collector"))?,
    };
    if collector.max_output_bytes > session.limits().max_file_bytes {
        return Err(AppError::operational(
            "custom-event collector output bound exceeds the Session file limit",
        ));
    }
    validate_custom_event_resource_ids(profile, &collector)?;
    validate_custom_event_resource_namespace(artifacts, &collector)?;

    let firmware = artifacts
        .iter()
        .find(|artifact| artifact.id == FIRMWARE_ELF_ARTIFACT_ID)
        .ok_or_else(|| {
            AppError::operational("provisioned custom-event resources lack firmware admission")
        })?;
    validate_firmware_artifact_envelope(firmware)?;
    session
        .verify_artifact(firmware, true)
        .map_err(AppError::operational)?;
    let (admitted_profile, _catalog, qualification, _scenarios) =
        load_session_admission(session, artifacts)?;
    if admitted_profile != *profile || qualification.is_empty() {
        return Err(AppError::operational(
            "provisioned custom-event resources do not match qualified adapter admission",
        ));
    }
    let binding_artifact = artifacts
        .iter()
        .find(|artifact| artifact.id == PERFORMANCE_RUN_DEPLOYMENT_BINDING_ID)
        .ok_or_else(|| {
            AppError::operational("provisioned custom-event resources lack deployment binding")
        })?;
    validate_deployment_binding_envelope(session, binding_artifact)?;
    let binding: PerformanceRunDeploymentBinding =
        read_registered_json(session, binding_artifact, MAX_DEPLOYMENT_BINDING_BYTES)?;
    if binding.schema != PerformanceRunDeploymentBindingSchemaVersion::V1
        || binding.session_id != session.id().as_str()
        || binding.session_request_sha256
            != session.request_sha256().map_err(AppError::operational)?
    {
        return Err(AppError::operational(
            "performance-run deployment binding does not match its Session",
        ));
    }
    let mut provenance = vec![firmware.id.clone()];
    provenance.extend(qualification.into_iter().map(|artifact| artifact.id));
    provenance.push(binding_artifact.id.clone());
    load_provisioned_custom_event_resources_from_evidence(
        session,
        artifacts,
        collector,
        &provenance,
        &binding,
    )
    .map(Some)
}

fn validate_deployment_binding_envelope(
    session: &Session,
    artifact: &Artifact,
) -> Result<(), AppError> {
    session
        .verify_artifact(artifact, true)
        .map_err(AppError::operational)?;
    if artifact.id != PERFORMANCE_RUN_DEPLOYMENT_BINDING_ID
        || artifact.kind != PERFORMANCE_RUN_DEPLOYMENT_BINDING_KIND
        || artifact.relative_path.as_str() != PERFORMANCE_RUN_DEPLOYMENT_BINDING_PATH
        || artifact.media_type != "application/json"
        || artifact.producer != PERFORMANCE_RUN_DEPLOYMENT_BINDING_PRODUCER
        || !artifact.input_artifact_ids.is_empty()
    {
        return Err(AppError::operational(
            "performance-run deployment binding has an invalid immutable envelope",
        ));
    }
    Ok(())
}

fn load_provisioned_custom_event_resources_from_evidence(
    session: &Session,
    artifacts: &[Artifact],
    collector: TargetAdapterCustomEventCollectorContract,
    provenance: &[String],
    binding: &PerformanceRunDeploymentBinding,
) -> Result<PerformanceRunCustomEventResourceBinding, AppError> {
    let mapping_artifact = validate_optional_resource(
        session,
        artifacts,
        &collector.mapping_artifact_id,
        CUSTOM_EVENT_MAPPING_KIND,
        CUSTOM_EVENT_MAPPING_PATH,
        "application/json",
        provenance,
    )?
    .ok_or_else(|| AppError::operational("provisioned custom-event mapping is absent"))?;
    let overhead_artifact = validate_optional_resource(
        session,
        artifacts,
        &collector.instrumentation_overhead_artifact_id,
        CUSTOM_EVENT_OVERHEAD_KIND,
        CUSTOM_EVENT_OVERHEAD_PATH,
        "application/json",
        provenance,
    )?
    .ok_or_else(|| AppError::operational("provisioned custom-event overhead is absent"))?;
    let mapping_maximum = u64::try_from(MAX_C_WIRE_COUNTER_MAPPING_DOCUMENT_BYTES)
        .expect("C-wire mapping bound fits u64");
    let mapping_bytes = read_registered_bytes(session, &mapping_artifact, mapping_maximum)?;
    validate_custom_event_mapping(
        &mapping_bytes,
        &collector,
        "provisioned custom-event C-wire mapping",
    )?;
    let overhead_bytes = read_registered_bytes(
        session,
        &overhead_artifact,
        MAX_INSTRUMENTATION_OVERHEAD_BYTES,
    )?;
    let overhead_document = validate_custom_event_overhead(
        &overhead_bytes,
        &collector,
        "provisioned custom-event instrumentation overhead",
    )?;
    validate_custom_claims_in_provisioning_receipt(
        session,
        artifacts,
        binding,
        [&mapping_artifact, &overhead_artifact],
    )?;
    Ok(PerformanceRunCustomEventResourceBinding {
        collector,
        mapping_artifact,
        overhead_artifact,
        overhead_document,
    })
}

fn validate_custom_claims_in_provisioning_receipt(
    session: &Session,
    artifacts: &[Artifact],
    binding: &PerformanceRunDeploymentBinding,
    custom_artifacts: [&Artifact; 2],
) -> Result<(), AppError> {
    let receipt_artifact = artifacts
        .iter()
        .find(|artifact| artifact.id == PERFORMANCE_RUN_PROVISIONING_RECEIPT_ID)
        .ok_or_else(|| {
            AppError::operational(
                "provisioned custom-event resources lack the provisioning receipt",
            )
        })?;
    session
        .verify_artifact(receipt_artifact, true)
        .map_err(AppError::operational)?;
    let receipt: PerformanceRunProvisioningReceipt =
        read_registered_json(session, receipt_artifact, MAX_PROVISIONING_RECEIPT_BYTES)?;
    let canonical = serde_json::to_vec(&receipt).map_err(AppError::operational)?;
    let claim_ids = receipt
        .artifact_claims
        .iter()
        .map(|claim| claim.id.clone())
        .collect::<Vec<_>>();
    if receipt_artifact.kind != PERFORMANCE_RUN_PROVISIONING_RECEIPT_KIND
        || receipt_artifact.relative_path.as_str() != PERFORMANCE_RUN_PROVISIONING_RECEIPT_PATH
        || receipt_artifact.media_type != "application/json"
        || receipt_artifact.producer != PERFORMANCE_RUN_PROVISIONING_RECEIPT_PRODUCER
        || receipt_artifact.input_artifact_ids != claim_ids
        || receipt_artifact.sha256 != digest(&canonical)
        || receipt.schema != PerformanceRunProvisioningReceiptSchemaVersion::V1
        || receipt.session_id != session.id().as_str()
        || receipt.session_request_sha256 != binding.session_request_sha256
        || receipt.driver_config_sha256 != binding.driver_config_sha256
        || receipt.performance_run_deployment_sha256 != binding.performance_run_deployment_sha256
        || receipt
            .artifact_claims
            .windows(2)
            .any(|pair| pair[0].id >= pair[1].id)
    {
        return Err(AppError::operational(
            "performance-run provisioning receipt is not the exact durable completion claim",
        ));
    }
    for artifact in custom_artifacts {
        if !receipt
            .artifact_claims
            .iter()
            .any(|claim| claim.id == artifact.id && claim.sha256 == artifact.sha256)
        {
            return Err(AppError::operational(format!(
                "performance-run provisioning receipt omits exact custom resource `{}`",
                artifact.id
            )));
        }
    }
    Ok(())
}

fn complete_build_resources(
    session: &Session,
    artifacts: &[Artifact],
    loaded: &LoadedDriverConfig,
    profile: &t32perf_trace32::TargetAdapterProfile,
    provenance: &[String],
) -> Result<Vec<Artifact>, AppError> {
    let deployment = require_performance_run_config(loaded).map_err(AppError::operational)?;
    let mut expected = BTreeSet::new();
    let mut completed = Vec::new();
    for (configured, id, kind, path, media_type) in [
        (
            deployment.resources.linker_map.is_some(),
            LINKER_MAP_ARTIFACT_ID,
            "linker_map",
            LINKER_MAP_PATH,
            "text/plain",
        ),
        (
            deployment.resources.stack_usage.is_some(),
            STACK_USAGE_ARTIFACT_ID,
            "stack_usage",
            STACK_USAGE_PATH,
            "text/plain",
        ),
        (
            deployment.resources.static_ram_config.is_some(),
            STATIC_RAM_CONFIG_ARTIFACT_ID,
            "static_ram_config",
            STATIC_RAM_CONFIG_PATH,
            "application/json",
        ),
    ] {
        if configured {
            expected.insert(id.to_owned());
            completed.push(
                validate_optional_resource(
                    session, artifacts, id, kind, path, media_type, provenance,
                )?
                .ok_or_else(|| {
                    AppError::operational(format!(
                        "performance-run provisioning lacks configured build resource `{id}`"
                    ))
                })?,
            );
        }
    }
    let normal_capture = &profile
        .scenario(TargetAdapterScenario::Normal)
        .ok_or_else(|| AppError::operational("qualified profile has no normal capture contract"))?
        .capture;
    match (
        &normal_capture.capture_kind,
        &deployment.resources.program_flow,
    ) {
        (TargetAdapterCaptureKind::Sampling { .. }, None) => {}
        (TargetAdapterCaptureKind::Sampling { .. }, Some(_)) => {
            return Err(AppError::operational(
                "sampling target-adapter capture rejects configured program_flow resources",
            ));
        }
        (
            TargetAdapterCaptureKind::ProgramFlowTaskEvents {
                orti_artifact_id,
                task_marker_artifact_id,
                ..
            },
            Some(_),
        ) => {
            expected.insert(orti_artifact_id.clone());
            expected.insert(task_marker_artifact_id.clone());
            expected.insert(TASK_EVENTS_MAPPING_TEMPLATE_ARTIFACT_ID.to_owned());
            let orti = validate_optional_resource(
                session,
                artifacts,
                orti_artifact_id,
                ORTI_KIND,
                ORTI_PATH,
                ORTI_MEDIA_TYPE,
                provenance,
            )?
            .ok_or_else(|| AppError::operational("performance-run provisioning lacks ORTI"))?;
            let marker = validate_optional_resource(
                session,
                artifacts,
                task_marker_artifact_id,
                TASK_MARKERS_KIND,
                TASK_MARKERS_PATH,
                TASK_MARKERS_MEDIA_TYPE,
                provenance,
            )?
            .ok_or_else(|| {
                AppError::operational("performance-run provisioning lacks task markers")
            })?;
            let mut template_inputs = provenance.to_vec();
            template_inputs.push(orti.id.clone());
            template_inputs.push(marker.id.clone());
            let template = validate_optional_resource(
                session,
                artifacts,
                TASK_EVENTS_MAPPING_TEMPLATE_ARTIFACT_ID,
                TASK_EVENTS_MAPPING_TEMPLATE_KIND,
                TASK_EVENTS_MAPPING_TEMPLATE_PATH,
                TASK_EVENTS_MAPPING_TEMPLATE_MEDIA_TYPE,
                &template_inputs,
            )?
            .ok_or_else(|| {
                AppError::operational(
                    "performance-run provisioning lacks TASKEVENTS mapping template",
                )
            })?;
            validate_task_events_mapping_template_artifact(&template)?;
            completed.extend([orti, marker, template]);
        }
        (TargetAdapterCaptureKind::ProgramFlowTaskEvents { .. }, None) => {
            return Err(AppError::operational(
                "program-flow target-adapter capture requires ORTI, task-marker, and TASKEVENTS mapping-template resources",
            ));
        }
    }
    if let Some(custom) = load_performance_run_custom_event_resources(
        session, artifacts, loaded, profile, provenance,
    )? {
        if custom.overhead_document.instrumentation_method != "t32perf-c-wire/v1"
            || custom.overhead_document.transport != custom.collector.transport
        {
            return Err(AppError::operational(
                "registered custom-event resources no longer match their collector contract",
            ));
        }
        expected.insert(custom.mapping_artifact.id.clone());
        expected.insert(custom.overhead_artifact.id.clone());
        completed.extend([custom.mapping_artifact, custom.overhead_artifact]);
    }
    for artifact in artifacts {
        let deployment_resource_path = artifact
            .relative_path
            .as_str()
            .starts_with("capture/deployment/build-resources/")
            || artifact
                .relative_path
                .as_str()
                .starts_with("capture/deployment/program-flow/")
            || artifact
                .relative_path
                .as_str()
                .starts_with("capture/deployment/custom-events/");
        if (artifact.producer == BUILD_RESOURCE_PRODUCER || deployment_resource_path)
            && !expected.contains(&artifact.id)
        {
            return Err(AppError::operational(
                "performance-run provisioning has an unconfigured or non-canonical build resource",
            ));
        }
    }
    Ok(completed)
}

fn driver_config_sha256(loaded: &LoadedDriverConfig) -> Result<Sha256Digest, AppError> {
    Ok(loaded.config_sha256.clone())
}

/// Checks the fixed envelope that a post-capture TASKEVENTS materializer may
/// consume.  Dynamic ORTI/marker IDs remain profile-owned, but the template
/// itself never does.
pub(crate) fn validate_task_events_mapping_template_artifact(
    artifact: &Artifact,
) -> Result<(), AppError> {
    if artifact.id != TASK_EVENTS_MAPPING_TEMPLATE_ARTIFACT_ID
        || artifact.kind != TASK_EVENTS_MAPPING_TEMPLATE_KIND
        || artifact.relative_path.as_str() != TASK_EVENTS_MAPPING_TEMPLATE_PATH
        || artifact.media_type != TASK_EVENTS_MAPPING_TEMPLATE_MEDIA_TYPE
        || artifact.producer != BUILD_RESOURCE_PRODUCER
    {
        return Err(AppError::operational(
            "TASKEVENTS mapping-template artifact has an invalid deployment provisioning envelope",
        ));
    }
    Ok(())
}

/// Admits build inputs after firmware and qualification evidence are durable.
pub(crate) fn provision_performance_run_build_resources(
    root: &ArtifactRoot,
    session: &Session,
    loaded: &LoadedDriverConfig,
) -> Result<(), AppError> {
    // Reopen through the supplied root so a caller cannot combine a Session
    // handle with a different artifact-root trust boundary.
    root.session(session.id()).map_err(AppError::operational)?;
    let lock = session.try_lock().map_err(AppError::operational)?;
    if session.read_state().map_err(AppError::operational)?.status != SessionStatus::Created {
        return Err(AppError::operational(
            "performance-run build-resource provisioning is only allowed while the Session is Created",
        ));
    }
    let deployment = require_performance_run_config(loaded).map_err(AppError::operational)?;
    let artifacts = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    let deployment_binding =
        require_performance_run_deployment_binding(session, &artifacts, loaded)?;
    let firmware = artifacts
        .iter()
        .find(|artifact| artifact.id == FIRMWARE_ELF_ARTIFACT_ID)
        .ok_or_else(|| {
            AppError::operational("build-resource provisioning requires durable firmware admission")
        })?;
    let (profile, _catalog, qualification, _scenarios) =
        load_session_admission(session, &artifacts)?;
    if qualification.is_empty() {
        return Err(AppError::operational(
            "build-resource provisioning requires durable target-adapter qualification admission",
        ));
    }
    let mut provenance = vec![firmware.id.clone()];
    provenance.extend(qualification.into_iter().map(|artifact| artifact.id));
    provenance.push(deployment_binding.id);
    let prepared_custom = prepare_custom_event_resources(
        session,
        &artifacts,
        &profile,
        &deployment.resources,
        &provenance,
    )?;

    reject_unconfigured_existing(
        &artifacts,
        deployment.resources.linker_map.is_some(),
        LINKER_MAP_ARTIFACT_ID,
    )?;
    reject_ambiguous_resource_kind(&artifacts, LINKER_MAP_ARTIFACT_ID, "linker_map")?;
    reject_ambiguous_resource_kind(&artifacts, STACK_USAGE_ARTIFACT_ID, "stack_usage")?;
    reject_ambiguous_resource_kind(
        &artifacts,
        STATIC_RAM_CONFIG_ARTIFACT_ID,
        "static_ram_config",
    )?;
    reject_unconfigured_existing(
        &artifacts,
        deployment.resources.stack_usage.is_some(),
        STACK_USAGE_ARTIFACT_ID,
    )?;
    reject_unconfigured_existing(
        &artifacts,
        deployment.resources.static_ram_config.is_some(),
        STATIC_RAM_CONFIG_ARTIFACT_ID,
    )?;

    deployment
        .resources
        .linker_map
        .as_ref()
        .map(|input| {
            provision_external(
                session,
                &lock,
                &artifacts,
                ResourceSpec {
                    id: LINKER_MAP_ARTIFACT_ID,
                    kind: "linker_map",
                    path: LINKER_MAP_PATH,
                    media_type: "text/plain",
                    staging_name: "linker-map",
                    input,
                    maximum: MAX_LINKER_MAP_BYTES,
                    inputs: provenance.clone(),
                },
            )
        })
        .transpose()?;
    deployment
        .resources
        .stack_usage
        .as_ref()
        .map(|input| {
            provision_external(
                session,
                &lock,
                &artifacts,
                ResourceSpec {
                    id: STACK_USAGE_ARTIFACT_ID,
                    kind: "stack_usage",
                    path: STACK_USAGE_PATH,
                    media_type: "text/plain",
                    staging_name: "stack-usage",
                    input,
                    maximum: MAX_STACK_USAGE_BYTES,
                    inputs: provenance.clone(),
                },
            )
        })
        .transpose()?;
    deployment
        .resources
        .static_ram_config
        .as_ref()
        .map(|input| {
            provision_external(
                session,
                &lock,
                &artifacts,
                ResourceSpec {
                    id: STATIC_RAM_CONFIG_ARTIFACT_ID,
                    kind: "static_ram_config",
                    path: STATIC_RAM_CONFIG_PATH,
                    media_type: "application/json",
                    staging_name: "static-ram-config",
                    input,
                    maximum: MAX_STATIC_RAM_CONFIG_BYTES,
                    inputs: provenance.clone(),
                },
            )
        })
        .transpose()?;

    let normal_capture = &profile
        .scenario(t32perf_trace32::TargetAdapterScenario::Normal)
        .ok_or_else(|| AppError::operational("qualified profile has no normal capture contract"))?
        .capture;
    match (
        &normal_capture.capture_kind,
        &deployment.resources.program_flow,
    ) {
        (TargetAdapterCaptureKind::Sampling { .. }, None) => {}
        (TargetAdapterCaptureKind::Sampling { .. }, Some(_)) => {
            return Err(AppError::operational(
                "sampling target-adapter capture rejects configured program_flow resources",
            ));
        }
        (
            TargetAdapterCaptureKind::ProgramFlowTaskEvents {
                export_profile_id,
                orti_artifact_id,
                task_marker_artifact_id,
                ..
            },
            Some(program_flow),
        ) => {
            reject_ambiguous_resource_kind(&artifacts, orti_artifact_id, ORTI_KIND)?;
            reject_ambiguous_resource_kind(&artifacts, task_marker_artifact_id, TASK_MARKERS_KIND)?;
            reject_ambiguous_resource_kind(
                &artifacts,
                TASK_EVENTS_MAPPING_TEMPLATE_ARTIFACT_ID,
                TASK_EVENTS_MAPPING_TEMPLATE_KIND,
            )?;
            let orti = provision_external(
                session,
                &lock,
                &artifacts,
                ResourceSpec {
                    id: orti_artifact_id,
                    kind: ORTI_KIND,
                    path: ORTI_PATH,
                    media_type: ORTI_MEDIA_TYPE,
                    staging_name: "orti",
                    input: &program_flow.orti,
                    maximum: MAX_ORTI_BYTES,
                    inputs: provenance.clone(),
                },
            )?;
            let marker = provision_external(
                session,
                &lock,
                &artifacts,
                ResourceSpec {
                    id: task_marker_artifact_id,
                    kind: TASK_MARKERS_KIND,
                    path: TASK_MARKERS_PATH,
                    media_type: TASK_MARKERS_MEDIA_TYPE,
                    staging_name: "task-markers",
                    input: &program_flow.task_markers,
                    maximum: MAX_TASK_MARKERS_BYTES,
                    inputs: provenance.clone(),
                },
            )?;
            let mut template_inputs = provenance;
            template_inputs.push(orti.id);
            template_inputs.push(marker.id);
            let template_resource = ResourceSpec {
                id: TASK_EVENTS_MAPPING_TEMPLATE_ARTIFACT_ID,
                kind: TASK_EVENTS_MAPPING_TEMPLATE_KIND,
                path: TASK_EVENTS_MAPPING_TEMPLATE_PATH,
                media_type: TASK_EVENTS_MAPPING_TEMPLATE_MEDIA_TYPE,
                staging_name: "task-events-mapping-template",
                input: &program_flow.task_events_mapping_template,
                maximum: MAX_TASK_EVENTS_MAPPING_BYTES,
                inputs: template_inputs.clone(),
            };
            let template_bytes = read_existing_or_deployment_resource(
                session,
                &artifacts,
                &template_resource,
                "TASKEVENTS mapping template",
            )?;
            let template = parse_trace32_task_events_mapping_template(&template_bytes)
                .map_err(AppError::operational)?;
            if template.profile_id != *export_profile_id
                || normal_capture.covered_cores.as_slice() != [template.core_id]
            {
                return Err(AppError::operational(
                    "TASKEVENTS mapping template does not exactly match the selected program-flow profile and covered core",
                ));
            }
            provision_bytes(
                session,
                &lock,
                &artifacts,
                ResourceSpecBytes {
                    id: TASK_EVENTS_MAPPING_TEMPLATE_ARTIFACT_ID,
                    kind: TASK_EVENTS_MAPPING_TEMPLATE_KIND,
                    path: TASK_EVENTS_MAPPING_TEMPLATE_PATH,
                    media_type: TASK_EVENTS_MAPPING_TEMPLATE_MEDIA_TYPE,
                    staging_name: "task-events-mapping-template",
                    bytes: template_bytes,
                    inputs: template_inputs,
                },
            )?;
        }
        (TargetAdapterCaptureKind::ProgramFlowTaskEvents { .. }, None) => {
            return Err(AppError::operational(
                "program-flow target-adapter capture requires ORTI, task-marker, and TASKEVENTS mapping-template resources",
            ));
        }
    };
    if let Some(prepared) = prepared_custom {
        provision_prepared_custom_event_resources(session, &lock, &artifacts, prepared)?;
    }
    Ok(())
}

fn reject_unconfigured_existing(
    artifacts: &[Artifact],
    configured: bool,
    id: &str,
) -> Result<(), AppError> {
    if !configured && artifacts.iter().any(|artifact| artifact.id == id) {
        return Err(AppError::operational(format!(
            "immutable Session already contains build resource `{id}` but the active deployment does not configure it"
        )));
    }
    Ok(())
}

fn reject_ambiguous_resource_kind(
    artifacts: &[Artifact],
    expected_id: &str,
    kind: &str,
) -> Result<(), AppError> {
    if artifacts
        .iter()
        .any(|artifact| artifact.kind == kind && artifact.id != expected_id)
    {
        return Err(AppError::operational(format!(
            "performance-run resource kind `{kind}` is already claimed by a non-canonical artifact"
        )));
    }
    Ok(())
}

/// Rebuilds the static-RAM input choice from durable Session evidence.
///
/// The analysis stage must never retain this decision only in an in-process
/// `perf_run` return value: an interrupted run resumes from its catalog.
pub(crate) fn performance_run_static_ram_flavor(
    root: &ArtifactRoot,
    session: &Session,
) -> Result<&'static str, AppError> {
    root.session(session.id()).map_err(AppError::operational)?;
    let artifacts = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    let firmware = artifacts
        .iter()
        .find(|artifact| artifact.id == FIRMWARE_ELF_ARTIFACT_ID)
        .ok_or_else(|| {
            AppError::operational("performance-run resource evidence lacks firmware admission")
        })?;
    let (_profile, _catalog, qualification, _scenarios) =
        load_session_admission(session, &artifacts)?;
    if qualification.is_empty() {
        return Err(AppError::operational(
            "performance-run resource evidence lacks qualification admission",
        ));
    }
    let mut expected_provenance = vec![firmware.id.clone()];
    expected_provenance.extend(qualification.into_iter().map(|artifact| artifact.id));
    let deployment_binding = artifacts
        .iter()
        .find(|artifact| artifact.id == PERFORMANCE_RUN_DEPLOYMENT_BINDING_ID)
        .ok_or_else(|| {
            AppError::operational("performance-run resource evidence lacks deployment binding")
        })?;
    session
        .verify_artifact(deployment_binding, true)
        .map_err(AppError::operational)?;
    expected_provenance.push(deployment_binding.id.clone());
    let linker = validate_optional_resource(
        session,
        &artifacts,
        LINKER_MAP_ARTIFACT_ID,
        "linker_map",
        LINKER_MAP_PATH,
        "text/plain",
        &expected_provenance,
    )?;
    validate_optional_resource(
        session,
        &artifacts,
        STACK_USAGE_ARTIFACT_ID,
        "stack_usage",
        STACK_USAGE_PATH,
        "text/plain",
        &expected_provenance,
    )?;
    validate_optional_resource(
        session,
        &artifacts,
        STATIC_RAM_CONFIG_ARTIFACT_ID,
        "static_ram_config",
        STATIC_RAM_CONFIG_PATH,
        "application/json",
        &expected_provenance,
    )?;
    if let Some(template) = artifacts
        .iter()
        .find(|artifact| artifact.id == TASK_EVENTS_MAPPING_TEMPLATE_ARTIFACT_ID)
    {
        session
            .verify_artifact(template, true)
            .map_err(AppError::operational)?;
        validate_task_events_mapping_template_artifact(template)?;
    }
    Ok(if linker.is_some() {
        GNU_LD_MAP_V1_FLAVOR
    } else {
        ELF_SECTIONS_V1_FLAVOR
    })
}

fn validate_optional_resource(
    session: &Session,
    artifacts: &[Artifact],
    id: &str,
    kind: &str,
    path: &str,
    media_type: &str,
    expected_provenance: &[String],
) -> Result<Option<Artifact>, AppError> {
    let Some(artifact) = artifacts.iter().find(|artifact| artifact.id == id) else {
        return Ok(None);
    };
    session
        .verify_artifact(artifact, true)
        .map_err(AppError::operational)?;
    if artifact.kind != kind
        || artifact.relative_path.as_str() != path
        || artifact.media_type != media_type
        || artifact.producer != BUILD_RESOURCE_PRODUCER
        || artifact.input_artifact_ids != expected_provenance
    {
        return Err(AppError::operational(format!(
            "performance-run build resource `{id}` has an invalid immutable provisioning envelope"
        )));
    }
    Ok(Some(artifact.clone()))
}

struct ResourceSpec<'a> {
    id: &'a str,
    kind: &'a str,
    path: &'a str,
    media_type: &'a str,
    staging_name: &'a str,
    input: &'a DriverPerformanceRunResourceInput,
    maximum: u64,
    inputs: Vec<String>,
}

fn provision_external(
    session: &Session,
    lock: &SessionLock,
    artifacts: &[Artifact],
    resource: ResourceSpec<'_>,
) -> Result<Artifact, AppError> {
    if let Some(existing) = validate_existing_external_resource(session, artifacts, &resource)? {
        return Ok(existing);
    }
    let bytes = read_revalidated_resource(resource.input, resource.maximum, resource.staging_name)?;
    provision_bytes(
        session,
        lock,
        artifacts,
        ResourceSpecBytes {
            id: resource.id,
            kind: resource.kind,
            path: resource.path,
            media_type: resource.media_type,
            staging_name: resource.staging_name,
            bytes,
            inputs: resource.inputs,
        },
    )
}

fn validate_existing_external_resource(
    session: &Session,
    artifacts: &[Artifact],
    resource: &ResourceSpec<'_>,
) -> Result<Option<Artifact>, AppError> {
    let Some(existing) = artifacts.iter().find(|artifact| artifact.id == resource.id) else {
        return Ok(None);
    };
    session
        .verify_artifact(existing, true)
        .map_err(AppError::operational)?;
    if existing.kind != resource.kind
        || existing.relative_path
            != ArtifactPath::new(resource.path).map_err(AppError::operational)?
        || existing.media_type != resource.media_type
        || existing.producer != BUILD_RESOURCE_PRODUCER
        || existing.input_artifact_ids != resource.inputs
        || existing.sha256 != resource.input.sha256
    {
        return Err(AppError::operational(format!(
            "existing immutable build resource `{}` conflicts with performance-run provisioning",
            resource.id
        )));
    }
    Ok(Some(existing.clone()))
}

fn read_existing_or_deployment_resource(
    session: &Session,
    artifacts: &[Artifact],
    resource: &ResourceSpec<'_>,
    description: &str,
) -> Result<Vec<u8>, AppError> {
    if let Some(existing) = validate_existing_external_resource(session, artifacts, resource)? {
        return read_registered_bytes(session, &existing, resource.maximum);
    }
    read_revalidated_resource(resource.input, resource.maximum, description)
}

struct ResourceSpecBytes<'a> {
    id: &'a str,
    kind: &'a str,
    path: &'a str,
    media_type: &'a str,
    staging_name: &'a str,
    bytes: Vec<u8>,
    inputs: Vec<String>,
}

fn provision_bytes(
    session: &Session,
    lock: &SessionLock,
    artifacts: &[Artifact],
    resource: ResourceSpecBytes<'_>,
) -> Result<Artifact, AppError> {
    let spec = ArtifactSpec {
        id: resource.id.to_owned(),
        kind: resource.kind.to_owned(),
        relative_path: ArtifactPath::new(resource.path).map_err(AppError::operational)?,
        media_type: resource.media_type.to_owned(),
        producer: BUILD_RESOURCE_PRODUCER.to_owned(),
        input_artifact_ids: resource.inputs,
    };
    let expected = digest(&resource.bytes);
    if let Some(existing) = artifacts.iter().find(|artifact| artifact.id == spec.id) {
        session
            .verify_artifact(existing, true)
            .map_err(AppError::operational)?;
        if existing.kind != spec.kind
            || existing.relative_path != spec.relative_path
            || existing.media_type != spec.media_type
            || existing.producer != spec.producer
            || existing.input_artifact_ids != spec.input_artifact_ids
            || existing.sha256 != expected
        {
            return Err(AppError::operational(format!(
                "existing immutable build resource `{}` conflicts with performance-run provisioning",
                resource.id
            )));
        }
        return Ok(existing.clone());
    }
    let staged = ArtifactPath::new(format!("provisioning/{}.bin", resource.staging_name))
        .map_err(AppError::operational)?;
    let maximum = u64::try_from(resource.bytes.len()).unwrap_or(u64::MAX);
    session
        .ensure_staged_exact(lock, &staged, &resource.bytes, maximum)
        .map_err(AppError::operational)?;
    session
        .ingest_staged_bounded(lock, &staged, spec, maximum)
        .map_err(AppError::operational)
}

fn read_revalidated_resource(
    input: &DriverPerformanceRunResourceInput,
    maximum: u64,
    description: &str,
) -> Result<Vec<u8>, AppError> {
    let path = Path::new(&input.path);
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(AppError::operational(format!(
            "{description} path must be absolute and normalized"
        )));
    }
    let metadata = fs::symlink_metadata(path).map_err(AppError::operational)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > maximum
    {
        return Err(AppError::operational(format!(
            "{description} is not a bounded plain file"
        )));
    }
    let mut file = File::open(path).map_err(AppError::operational)?;
    verify_opened_plain_file_identity(path, &file).map_err(AppError::operational)?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.by_ref()
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(AppError::operational)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(AppError::operational(format!(
            "{description} exceeds its fixed bound while reading"
        )));
    }
    verify_opened_plain_file_identity(path, &file).map_err(AppError::operational)?;
    if digest(&bytes) != input.sha256 {
        return Err(AppError::operational(format!(
            "{description} SHA-256 changed or disagrees with the revalidated deployment"
        )));
    }
    Ok(bytes)
}

fn read_registered_json<T: for<'de> Deserialize<'de>>(
    session: &Session,
    artifact: &Artifact,
    maximum: u64,
) -> Result<T, AppError> {
    let bytes = read_registered_bytes(session, artifact, maximum)?;
    t32perf_model::strict_json::from_slice(&bytes).map_err(AppError::operational)
}

fn read_registered_bytes(
    session: &Session,
    artifact: &Artifact,
    maximum: u64,
) -> Result<Vec<u8>, AppError> {
    if artifact.size_bytes > maximum {
        return Err(AppError::operational(
            "registered deployment binding exceeds its fixed bound",
        ));
    }
    let mut file = session
        .open_artifact(artifact)
        .map_err(AppError::operational)?;
    let mut bytes = Vec::with_capacity(usize::try_from(artifact.size_bytes).unwrap_or(0));
    file.by_ref()
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(AppError::operational)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != artifact.size_bytes
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum
        || digest(&bytes) != artifact.sha256
    {
        return Err(AppError::operational(
            "registered deployment binding changed while reading",
        ));
    }
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(lower_hex(Sha256::digest(bytes).as_ref())).expect("SHA-256 encoding is valid")
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs};

    use t32perf_model::{
        ArtifactPath, CaptureCapabilities, InstrumentationOverheadEvidenceDocument,
        InstrumentationOverheadEvidenceSchemaVersion, MetricSupportEntry, MetricSupportLevel,
        Sha256Digest,
    };
    use t32perf_session::{ArtifactRoot, SessionLimits};
    use t32perf_trace32::{
        ControllerHealthSignal, ControllerTargetState, DriverPerformanceRunProgramFlowResources,
        TargetAdapterBuildGate, TargetAdapterCaptureContract,
        TargetAdapterCustomEventClockContract, TargetAdapterCustomEventMergeOrder,
        TargetAdapterCustomEventWireProtocol, TargetAdapterProfileSchemaVersion,
        TargetAdapterScenarioContract,
    };
    use tempfile::tempdir;

    use super::*;

    fn template_artifact() -> Artifact {
        Artifact {
            id: TASK_EVENTS_MAPPING_TEMPLATE_ARTIFACT_ID.to_owned(),
            kind: TASK_EVENTS_MAPPING_TEMPLATE_KIND.to_owned(),
            relative_path: ArtifactPath::new(TASK_EVENTS_MAPPING_TEMPLATE_PATH).unwrap(),
            media_type: TASK_EVENTS_MAPPING_TEMPLATE_MEDIA_TYPE.to_owned(),
            size_bytes: 1,
            sha256: Sha256Digest::new("a".repeat(64)).unwrap(),
            producer: BUILD_RESOURCE_PRODUCER.to_owned(),
            input_artifact_ids: vec![FIRMWARE_ELF_ARTIFACT_ID.to_owned()],
        }
    }

    fn custom_event_profile() -> TargetAdapterProfile {
        let capture = TargetAdapterCaptureContract {
            configuration_sha256_by_initial_state: BTreeMap::from([
                (
                    ControllerTargetState::Running,
                    Sha256Digest::new("3".repeat(64)).unwrap(),
                ),
                (
                    ControllerTargetState::Halted,
                    Sha256Digest::new("4".repeat(64)).unwrap(),
                ),
            ]),
            capture_mode: "etm-program-flow".to_owned(),
            trace_sink: "probe-buffer".to_owned(),
            capture_kind: TargetAdapterCaptureKind::ProgramFlowTaskEvents {
                export_profile_id: "test-task-events/v1".to_owned(),
                rtos_awareness: "test-rtos/v1".to_owned(),
                timestamp_clock_id: "test-shared-clock".to_owned(),
                orti_artifact_id: "test-orti".to_owned(),
                task_marker_artifact_id: "test-task-markers".to_owned(),
            },
            timestamp_enabled: true,
            workload_identity: "test-workload/v1".to_owned(),
            covered_cores: vec![0],
            supported_initial_states: vec![
                ControllerTargetState::Running,
                ControllerTargetState::Halted,
            ],
        };
        let unavailable = MetricSupportEntry::unavailable("not captured");
        let exact = MetricSupportEntry::new(MetricSupportLevel::Exact);
        let profile = TargetAdapterProfile {
            schema: TargetAdapterProfileSchemaVersion::V1,
            adapter_id: "custom-event-test-adapter".to_owned(),
            adapter_version: "1".to_owned(),
            implementation_sha256: Sha256Digest::new("1".repeat(64)).unwrap(),
            qualification_sha256: None,
            build_gate: TargetAdapterBuildGate {
                trace32_release: "2026.02".to_owned(),
                minimum_build: 190_766,
                maximum_build: 190_766,
                architecture_package: "tricore".to_owned(),
            },
            target_identifier: "test-target".to_owned(),
            probe_identifier: "test-probe".to_owned(),
            license_features: vec!["trace".to_owned()],
            trace_routing: vec!["trace-to-probe".to_owned()],
            firmware_elf_sha256: Sha256Digest::new("2".repeat(64)).unwrap(),
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
                function_events: exact.clone(),
                context_switches: exact.clone(),
                interrupt_events: exact.clone(),
                samples: unavailable,
                custom_events: exact.clone(),
                counters: exact,
            },
            controller_protocol: TargetAdapterControllerProtocol::V2CustomEventsExport,
            custom_event_collector: Some(TargetAdapterCustomEventCollectorContract {
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
                mapping_artifact_id: "test-custom-event-mapping".to_owned(),
                instrumentation_overhead_artifact_id: "test-custom-event-overhead".to_owned(),
                max_output_bytes: 16 * 1024 * 1024,
                merge_order: TargetAdapterCustomEventMergeOrder::RejectAmbiguousTies,
            }),
            scenarios: vec![TargetAdapterScenarioContract {
                scenario: TargetAdapterScenario::Normal,
                fault_point: None,
                capture,
            }],
        };
        profile.validate().unwrap();
        profile
    }

    fn mapping_bytes() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": "t32perf.c-wire-counter-mapping/v1",
            "contexts": [],
            "counters": [{
                "event_id": 1,
                "counter_id": "custom:event-count",
                "name": "Custom event count",
                "unit": "count",
                "description": "Test custom event counter.",
                "semantic": "custom.event_count",
                "subject": { "kind": "capture" }
            }]
        }))
        .unwrap()
    }

    fn mapping_bytes_with_context_core(core_id: Option<u32>) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": "t32perf.c-wire-counter-mapping/v1",
            "contexts": [{
                "wire_context_id": 7,
                "context_id": "task:test",
                "name": "test-task",
                "kind": "task",
                "core_id": core_id,
                "priority": 1
            }],
            "counters": [{
                "event_id": 1,
                "counter_id": "custom:event-count",
                "name": "Custom event count",
                "unit": "count",
                "description": "Test custom event counter.",
                "semantic": "custom.event_count",
                "subject": { "kind": "capture" }
            }]
        }))
        .unwrap()
    }

    fn overhead_bytes(transport: &str) -> Vec<u8> {
        serde_json::to_vec(&InstrumentationOverheadEvidenceDocument {
            schema: InstrumentationOverheadEvidenceSchemaVersion,
            instrumentation_method: "t32perf-c-wire/v1".to_owned(),
            transport: transport.to_owned(),
            measurement_method: "controlled-paired-run/v1".to_owned(),
            baseline_duration_ns: 100_000,
            instrumented_duration_ns: 110_000,
            emitted_event_count: 1_000,
        })
        .unwrap()
    }

    fn resource_input(path: &Path, bytes: &[u8]) -> DriverPerformanceRunResourceInput {
        fs::write(path, bytes).unwrap();
        DriverPerformanceRunResourceInput {
            path: path.to_string_lossy().into_owned(),
            sha256: digest(bytes),
        }
    }

    fn custom_resources(
        directory: &Path,
        mapping: &[u8],
        overhead: &[u8],
    ) -> DriverPerformanceRunResources {
        let mapping = resource_input(&directory.join("mapping.json"), mapping);
        let overhead = resource_input(&directory.join("overhead.json"), overhead);
        DriverPerformanceRunResources {
            linker_map: None,
            stack_usage: None,
            static_ram_config: None,
            program_flow: Some(DriverPerformanceRunProgramFlowResources {
                orti: mapping.clone(),
                task_markers: mapping.clone(),
                task_events_mapping_template: mapping.clone(),
            }),
            custom_events: Some(DriverPerformanceRunCustomEventResources {
                c_wire_mapping: mapping,
                instrumentation_overhead: overhead,
            }),
        }
    }

    fn register_base_provenance(session: &Session, lock: &SessionLock) -> Artifact {
        session
            .write_json_artifact(
                lock,
                ArtifactSpec {
                    id: "base-provenance".to_owned(),
                    kind: "test_provenance".to_owned(),
                    relative_path: ArtifactPath::new("capture/deployment/base-provenance.json")
                        .unwrap(),
                    media_type: "application/json".to_owned(),
                    producer: "test/v1".to_owned(),
                    input_artifact_ids: Vec::new(),
                },
                &serde_json::json!({"base": true}),
            )
            .unwrap()
    }

    fn register_custom_provisioning_receipt(
        session: &Session,
        lock: &SessionLock,
        binding: &PerformanceRunDeploymentBinding,
        custom_artifacts: Vec<Artifact>,
    ) -> Artifact {
        let claims = provisioning_artifact_claims(custom_artifacts).unwrap();
        let receipt = PerformanceRunProvisioningReceipt {
            schema: PerformanceRunProvisioningReceiptSchemaVersion::V1,
            session_id: session.id().to_string(),
            session_request_sha256: binding.session_request_sha256.clone(),
            driver_config_sha256: binding.driver_config_sha256.clone(),
            performance_run_deployment_sha256: binding.performance_run_deployment_sha256.clone(),
            artifact_claims: claims.clone(),
        };
        let bytes = serde_json::to_vec(&receipt).unwrap();
        let staged = ArtifactPath::new("provisioning/test-custom-receipt.json").unwrap();
        session
            .ensure_staged_exact(lock, &staged, &bytes, MAX_PROVISIONING_RECEIPT_BYTES)
            .unwrap();
        session
            .ingest_staged_bounded(
                lock,
                &staged,
                ArtifactSpec {
                    id: PERFORMANCE_RUN_PROVISIONING_RECEIPT_ID.to_owned(),
                    kind: PERFORMANCE_RUN_PROVISIONING_RECEIPT_KIND.to_owned(),
                    relative_path: ArtifactPath::new(PERFORMANCE_RUN_PROVISIONING_RECEIPT_PATH)
                        .unwrap(),
                    media_type: "application/json".to_owned(),
                    producer: PERFORMANCE_RUN_PROVISIONING_RECEIPT_PRODUCER.to_owned(),
                    input_artifact_ids: claims.into_iter().map(|claim| claim.id).collect(),
                },
                MAX_PROVISIONING_RECEIPT_BYTES,
            )
            .unwrap()
    }

    #[test]
    fn mapping_template_envelope_is_closed() {
        let artifact = template_artifact();
        validate_task_events_mapping_template_artifact(&artifact).unwrap();
        let mut tampered = artifact;
        tampered.producer = "external/v1".to_owned();
        assert!(validate_task_events_mapping_template_artifact(&tampered).is_err());
    }

    #[test]
    fn digest_is_canonical_lower_hex() {
        assert_eq!(
            digest(b"abc").as_str(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn existing_mapping_template_resume_does_not_read_deleted_source() {
        let temporary = tempdir().unwrap();
        let root = ArtifactRoot::open(temporary.path().join("artifacts"), SessionLimits::default())
            .unwrap();
        let session = root.create_session(&serde_json::json!({})).unwrap();
        let lock = session.try_lock().unwrap();
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema": "t32perf.trace32-task-events-mapping-template/v1",
            "profile_id": "task-events-profile/v1",
            "core_id": 0,
            "contexts": [{
                "export_name": "TaskA",
                "context_id": "task:a",
                "kind": "task",
                "display_name": "Task A",
                "priority": null,
                "entry_function_id": null
            }],
            "functions": [],
            "runnables": []
        }))
        .unwrap();
        parse_trace32_task_events_mapping_template(&bytes).unwrap();
        let artifact = provision_bytes(
            &session,
            &lock,
            &[],
            ResourceSpecBytes {
                id: TASK_EVENTS_MAPPING_TEMPLATE_ARTIFACT_ID,
                kind: TASK_EVENTS_MAPPING_TEMPLATE_KIND,
                path: TASK_EVENTS_MAPPING_TEMPLATE_PATH,
                media_type: TASK_EVENTS_MAPPING_TEMPLATE_MEDIA_TYPE,
                staging_name: "task-events-mapping-template",
                bytes: bytes.clone(),
                inputs: Vec::new(),
            },
        )
        .unwrap();
        let source = temporary.path().join("deleted-template.json");
        fs::write(&source, &bytes).unwrap();
        fs::remove_file(&source).unwrap();
        let input = DriverPerformanceRunResourceInput {
            path: source.to_string_lossy().into_owned(),
            sha256: digest(&bytes),
        };
        let resource = ResourceSpec {
            id: TASK_EVENTS_MAPPING_TEMPLATE_ARTIFACT_ID,
            kind: TASK_EVENTS_MAPPING_TEMPLATE_KIND,
            path: TASK_EVENTS_MAPPING_TEMPLATE_PATH,
            media_type: TASK_EVENTS_MAPPING_TEMPLATE_MEDIA_TYPE,
            staging_name: "task-events-mapping-template",
            input: &input,
            maximum: MAX_TASK_EVENTS_MAPPING_BYTES,
            inputs: Vec::new(),
        };

        assert_eq!(
            read_existing_or_deployment_resource(
                &session,
                &[artifact],
                &resource,
                "TASKEVENTS mapping template",
            )
            .unwrap(),
            bytes
        );
    }

    #[test]
    fn v1_custom_event_configuration_is_unsupported_without_writes() {
        let temporary = tempdir().unwrap();
        let root = ArtifactRoot::open(temporary.path().join("artifacts"), SessionLimits::default())
            .unwrap();
        let session = root.create_session(&serde_json::json!({})).unwrap();
        let lock = session.try_lock().unwrap();
        let base = register_base_provenance(&session, &lock);
        let resources = custom_resources(
            temporary.path(),
            &mapping_bytes(),
            &overhead_bytes("shared-memory-ring-buffer/v1"),
        );
        let before = session.registered_artifacts(true).unwrap();
        let error = prepare_custom_event_resources(
            &session,
            &before,
            &t32perf_trace32::tc234l_build190766_candidate_profile(),
            &resources,
            &[base.id],
        )
        .unwrap_err();
        assert!(format!("{error:?}").contains("Controller V1"));
        assert_eq!(session.registered_artifacts(true).unwrap(), before);
        assert!(
            load_provisioned_custom_event_resources(
                &session,
                &before,
                &t32perf_trace32::tc234l_build190766_candidate_profile(),
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn v2_missing_or_invalid_custom_inputs_create_zero_new_artifacts() {
        for case in [
            "missing_config",
            "missing_source",
            "invalid_mapping",
            "invalid_core",
            "invalid_overhead",
        ] {
            let temporary = tempdir().unwrap();
            let root =
                ArtifactRoot::open(temporary.path().join("artifacts"), SessionLimits::default())
                    .unwrap();
            let session = root.create_session(&serde_json::json!({})).unwrap();
            let lock = session.try_lock().unwrap();
            let base = register_base_provenance(&session, &lock);
            let mapping = if case == "invalid_mapping" {
                br#"{"schema":"t32perf.c-wire-counter-mapping/v1","counters":[]}"#.to_vec()
            } else if case == "invalid_core" {
                mapping_bytes_with_context_core(Some(1))
            } else {
                mapping_bytes()
            };
            let overhead = if case == "invalid_overhead" {
                overhead_bytes("wrong-transport/v1")
            } else {
                overhead_bytes("shared-memory-ring-buffer/v1")
            };
            let mut resources = custom_resources(temporary.path(), &mapping, &overhead);
            if case == "missing_config" {
                resources.custom_events = None;
            } else if case == "missing_source" {
                fs::remove_file(
                    &resources
                        .custom_events
                        .as_ref()
                        .unwrap()
                        .instrumentation_overhead
                        .path,
                )
                .unwrap();
            }
            let before = session.registered_artifacts(true).unwrap();
            prepare_custom_event_resources(
                &session,
                &before,
                &custom_event_profile(),
                &resources,
                &[base.id],
            )
            .unwrap_err();
            assert_eq!(
                session.registered_artifacts(true).unwrap(),
                before,
                "case {case} published an artifact before complete preflight"
            );
        }
    }

    #[test]
    fn valid_custom_resources_provision_resume_load_and_enter_receipt_claims() {
        let temporary = tempdir().unwrap();
        let root = ArtifactRoot::open(temporary.path().join("artifacts"), SessionLimits::default())
            .unwrap();
        let session = root.create_session(&serde_json::json!({})).unwrap();
        let lock = session.try_lock().unwrap();
        let base = register_base_provenance(&session, &lock);
        let profile = custom_event_profile();
        let resources = custom_resources(
            temporary.path(),
            &mapping_bytes(),
            &overhead_bytes("shared-memory-ring-buffer/v1"),
        );
        let provenance = vec![base.id];
        let artifacts = session.registered_artifacts(true).unwrap();
        let prepared =
            prepare_custom_event_resources(&session, &artifacts, &profile, &resources, &provenance)
                .unwrap()
                .unwrap();
        let first =
            provision_prepared_custom_event_resources(&session, &lock, &artifacts, prepared)
                .unwrap();
        assert_eq!(first.mapping_artifact.kind, CUSTOM_EVENT_MAPPING_KIND);
        assert_eq!(
            first.mapping_artifact.relative_path.as_str(),
            CUSTOM_EVENT_MAPPING_PATH
        );
        assert_eq!(first.mapping_artifact.input_artifact_ids, provenance);
        assert_eq!(first.overhead_artifact.kind, CUSTOM_EVENT_OVERHEAD_KIND);
        assert_eq!(
            first.overhead_artifact.relative_path.as_str(),
            CUSTOM_EVENT_OVERHEAD_PATH
        );
        assert_eq!(first.overhead_document.transport, first.collector.transport);

        fs::remove_file(
            &resources
                .custom_events
                .as_ref()
                .unwrap()
                .c_wire_mapping
                .path,
        )
        .unwrap();
        fs::remove_file(
            &resources
                .custom_events
                .as_ref()
                .unwrap()
                .instrumentation_overhead
                .path,
        )
        .unwrap();
        let artifacts = session.registered_artifacts(true).unwrap();
        let resumed =
            prepare_custom_event_resources(&session, &artifacts, &profile, &resources, &provenance)
                .unwrap()
                .unwrap();
        let resumed =
            provision_prepared_custom_event_resources(&session, &lock, &artifacts, resumed)
                .unwrap();
        assert_eq!(resumed.mapping_artifact, first.mapping_artifact);
        assert_eq!(resumed.overhead_artifact, first.overhead_artifact);

        let artifacts = session.registered_artifacts(true).unwrap();
        let loaded = load_registered_custom_event_resources(
            &session,
            &artifacts,
            &profile,
            &resources,
            &provenance,
        )
        .unwrap()
        .unwrap();
        assert_eq!(loaded.mapping_artifact, first.mapping_artifact);
        assert_eq!(loaded.overhead_artifact, first.overhead_artifact);
        let binding = PerformanceRunDeploymentBinding {
            schema: PerformanceRunDeploymentBindingSchemaVersion::V1,
            session_id: session.id().to_string(),
            session_request_sha256: session.request_sha256().unwrap(),
            driver_config_sha256: Sha256Digest::new("a".repeat(64)).unwrap(),
            performance_run_deployment_sha256: Sha256Digest::new("b".repeat(64)).unwrap(),
            policy_id: "test-policy".to_owned(),
            key_id: "test-key".to_owned(),
            signer_executable_sha256: Sha256Digest::new("c".repeat(64)).unwrap(),
            workload_executable_sha256: Sha256Digest::new("d".repeat(64)).unwrap(),
        };
        register_custom_provisioning_receipt(
            &session,
            &lock,
            &binding,
            vec![
                loaded.mapping_artifact.clone(),
                loaded.overhead_artifact.clone(),
            ],
        );
        let artifacts = session.registered_artifacts(true).unwrap();
        let durable = load_provisioned_custom_event_resources_from_evidence(
            &session,
            &artifacts,
            profile.custom_event_collector.clone().unwrap(),
            &provenance,
            &binding,
        )
        .unwrap();
        assert_eq!(durable.mapping_artifact, first.mapping_artifact);
        assert_eq!(durable.overhead_artifact, first.overhead_artifact);
        let claims =
            provisioning_artifact_claims(vec![loaded.mapping_artifact, loaded.overhead_artifact])
                .unwrap();
        assert_eq!(
            claims
                .iter()
                .map(|claim| claim.id.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["test-custom-event-mapping", "test-custom-event-overhead"])
        );
    }

    #[test]
    fn custom_resource_drift_collision_envelope_and_provenance_fail_closed() {
        let temporary = tempdir().unwrap();
        let root = ArtifactRoot::open(temporary.path().join("artifacts"), SessionLimits::default())
            .unwrap();
        let session = root.create_session(&serde_json::json!({})).unwrap();
        let lock = session.try_lock().unwrap();
        let base = register_base_provenance(&session, &lock);
        let profile = custom_event_profile();
        let resources = custom_resources(
            temporary.path(),
            &mapping_bytes(),
            &overhead_bytes("shared-memory-ring-buffer/v1"),
        );
        let provenance = vec![base.id];
        let artifacts = session.registered_artifacts(true).unwrap();
        let prepared =
            prepare_custom_event_resources(&session, &artifacts, &profile, &resources, &provenance)
                .unwrap()
                .unwrap();
        provision_prepared_custom_event_resources(&session, &lock, &artifacts, prepared).unwrap();
        let artifacts = session.registered_artifacts(true).unwrap();
        let mut drifted = resources.clone();
        drifted
            .custom_events
            .as_mut()
            .unwrap()
            .c_wire_mapping
            .sha256 = Sha256Digest::new("f".repeat(64)).unwrap();
        assert!(
            prepare_custom_event_resources(&session, &artifacts, &profile, &drifted, &provenance,)
                .is_err()
        );

        let mut collision = custom_event_profile();
        collision
            .custom_event_collector
            .as_mut()
            .unwrap()
            .mapping_artifact_id = LINKER_MAP_ARTIFACT_ID.to_owned();
        assert!(
            custom_event_resource_contract(&session, &artifacts, &collision, &resources).is_err()
        );

        for case in ["envelope", "provenance"] {
            let temporary = tempdir().unwrap();
            let root =
                ArtifactRoot::open(temporary.path().join("artifacts"), SessionLimits::default())
                    .unwrap();
            let session = root.create_session(&serde_json::json!({})).unwrap();
            let lock = session.try_lock().unwrap();
            let base = register_base_provenance(&session, &lock);
            let profile = custom_event_profile();
            let resources = custom_resources(
                temporary.path(),
                &mapping_bytes(),
                &overhead_bytes("shared-memory-ring-buffer/v1"),
            );
            let mut writer = session
                .create_artifact(
                    &lock,
                    ArtifactSpec {
                        id: profile
                            .custom_event_collector
                            .as_ref()
                            .unwrap()
                            .mapping_artifact_id
                            .clone(),
                        kind: CUSTOM_EVENT_MAPPING_KIND.to_owned(),
                        relative_path: ArtifactPath::new(CUSTOM_EVENT_MAPPING_PATH).unwrap(),
                        media_type: "application/json".to_owned(),
                        producer: if case == "envelope" {
                            "wrong-producer/v1".to_owned()
                        } else {
                            BUILD_RESOURCE_PRODUCER.to_owned()
                        },
                        input_artifact_ids: if case == "provenance" {
                            Vec::new()
                        } else {
                            vec![base.id.clone()]
                        },
                    },
                )
                .unwrap();
            use std::io::Write as _;
            writer.write_all(&mapping_bytes()).unwrap();
            session.commit_artifact(&lock, writer).unwrap();
            let before = session.registered_artifacts(true).unwrap();
            assert!(
                prepare_custom_event_resources(
                    &session,
                    &before,
                    &profile,
                    &resources,
                    &[base.id],
                )
                .is_err()
            );
            assert_eq!(session.registered_artifacts(true).unwrap(), before);
        }

        let temporary = tempdir().unwrap();
        let root = ArtifactRoot::open(temporary.path().join("artifacts"), SessionLimits::default())
            .unwrap();
        let session = root.create_session(&serde_json::json!({})).unwrap();
        let lock = session.try_lock().unwrap();
        let base = register_base_provenance(&session, &lock);
        let profile = custom_event_profile();
        let invalid_mapping = mapping_bytes_with_context_core(None);
        let overhead = overhead_bytes("shared-memory-ring-buffer/v1");
        let resources = custom_resources(temporary.path(), &invalid_mapping, &overhead);
        let provenance = vec![base.id];
        let artifacts = session.registered_artifacts(true).unwrap();
        provision_bytes(
            &session,
            &lock,
            &artifacts,
            ResourceSpecBytes {
                id: &profile
                    .custom_event_collector
                    .as_ref()
                    .unwrap()
                    .mapping_artifact_id,
                kind: CUSTOM_EVENT_MAPPING_KIND,
                path: CUSTOM_EVENT_MAPPING_PATH,
                media_type: "application/json",
                staging_name: "invalid-core-mapping",
                bytes: invalid_mapping,
                inputs: provenance.clone(),
            },
        )
        .unwrap();
        let artifacts = session.registered_artifacts(true).unwrap();
        provision_bytes(
            &session,
            &lock,
            &artifacts,
            ResourceSpecBytes {
                id: &profile
                    .custom_event_collector
                    .as_ref()
                    .unwrap()
                    .instrumentation_overhead_artifact_id,
                kind: CUSTOM_EVENT_OVERHEAD_KIND,
                path: CUSTOM_EVENT_OVERHEAD_PATH,
                media_type: "application/json",
                staging_name: "invalid-core-overhead",
                bytes: overhead,
                inputs: provenance.clone(),
            },
        )
        .unwrap();
        let before = session.registered_artifacts(true).unwrap();
        assert!(
            load_registered_custom_event_resources(
                &session,
                &before,
                &profile,
                &resources,
                &provenance,
            )
            .is_err()
        );
        assert_eq!(session.registered_artifacts(true).unwrap(), before);

        let temporary = tempdir().unwrap();
        let root = ArtifactRoot::open(temporary.path().join("artifacts"), SessionLimits::default())
            .unwrap();
        let session = root.create_session(&serde_json::json!({})).unwrap();
        let lock = session.try_lock().unwrap();
        let base = register_base_provenance(&session, &lock);
        let mut oversized = custom_event_profile();
        oversized
            .custom_event_collector
            .as_mut()
            .unwrap()
            .max_output_bytes = session.limits().max_file_bytes + 1;
        let resources = custom_resources(
            temporary.path(),
            &mapping_bytes(),
            &overhead_bytes("shared-memory-ring-buffer/v1"),
        );
        let before = session.registered_artifacts(true).unwrap();
        assert!(
            prepare_custom_event_resources(&session, &before, &oversized, &resources, &[base.id],)
                .is_err()
        );
        assert_eq!(session.registered_artifacts(true).unwrap(), before);

        for reserved_id in [
            "observations",
            "controller-future-output",
            "attestation-signing-request",
            "analysis-summary",
            "c-wire-counter-map-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            let temporary = tempdir().unwrap();
            let root =
                ArtifactRoot::open(temporary.path().join("artifacts"), SessionLimits::default())
                    .unwrap();
            let session = root.create_session(&serde_json::json!({})).unwrap();
            let lock = session.try_lock().unwrap();
            let base = register_base_provenance(&session, &lock);
            let resources = custom_resources(
                temporary.path(),
                &mapping_bytes(),
                &overhead_bytes("shared-memory-ring-buffer/v1"),
            );
            let mut profile = custom_event_profile();
            profile
                .custom_event_collector
                .as_mut()
                .unwrap()
                .mapping_artifact_id = reserved_id.to_owned();
            let before = session.registered_artifacts(true).unwrap();
            assert!(
                prepare_custom_event_resources(
                    &session,
                    &before,
                    &profile,
                    &resources,
                    &[base.id],
                )
                .is_err()
            );
            assert_eq!(session.registered_artifacts(true).unwrap(), before);
        }

        let temporary = tempdir().unwrap();
        let root = ArtifactRoot::open(temporary.path().join("artifacts"), SessionLimits::default())
            .unwrap();
        let session = root.create_session(&serde_json::json!({})).unwrap();
        let lock = session.try_lock().unwrap();
        let base = register_base_provenance(&session, &lock);
        let resources = custom_resources(
            temporary.path(),
            &mapping_bytes(),
            &overhead_bytes("shared-memory-ring-buffer/v1"),
        );
        let mut source_collision = custom_event_profile();
        source_collision
            .custom_event_collector
            .as_mut()
            .unwrap()
            .source_id = "performance-run-trace32-program-flow".to_owned();
        let before = session.registered_artifacts(true).unwrap();
        assert!(
            prepare_custom_event_resources(
                &session,
                &before,
                &source_collision,
                &resources,
                &[base.id],
            )
            .is_err()
        );
        assert_eq!(session.registered_artifacts(true).unwrap(), before);
    }
}
