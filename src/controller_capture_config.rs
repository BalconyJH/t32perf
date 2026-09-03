//! Authoritative capture-configuration materialization for completed TRACE32 captures.
//!
//! The Controller evidence chain determines the configuration.  This module
//! never infers configuration from a caller-owned document or a health flag.

use std::io::Read as _;

use anyhow::{Context as _, Result, bail, ensure};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use t32perf_model::{
    AdapterInfo, Artifact, ArtifactPath, CaptureConfigDocument, CaptureDurationConfig,
    CaptureRtosAwarenessConfig, CaptureSinkConfig, CaptureTimestampConfig, CaptureTriggerConfig,
    InitialTargetState, PerformanceRunRequest, Sha256Digest,
};
use t32perf_session::{ArtifactRoot, ArtifactSpec, Session, SessionId, SessionLock};
use t32perf_trace32::{
    ControllerTargetAdapterBinding, ControllerTargetState, TC234L_SNOOPER_BUILD190766_S3_SHA256,
    TC234L_SNOOPER_BUILD190766_S3_SIZE_BYTES, TargetAdapterCaptureContract,
    TargetAdapterCaptureKind, TargetAdapterControllerProtocol,
    TargetAdapterCustomEventCollectorContract, TargetAdapterScenario,
    tc234l_snooper_capture_config_for_scenario,
};

use crate::{
    capture_config::{
        CAPTURE_CONFIG_ID, CAPTURE_CONFIG_KIND, CAPTURE_CONFIG_PATH, MAX_CAPTURE_CONFIG_BYTES,
    },
    controller::AcceptedTrace32CompletedBinding,
    target_adapter_provisioning::{
        PerformanceRunCustomEventResourceBinding, load_provisioned_custom_event_resources,
    },
};

/// Producer reserved for Controller-materialized capture configurations.
pub const CONTROLLER_CAPTURE_CONFIG_PRODUCER: &str = "t32perf-controller-capture-config/v1";
const CONTROLLER_CAPTURE_CONFIG_STAGING_PATH: &str = "controller/capture-config.json";

struct ProgramFlowCustomEvents<'a> {
    resources: &'a PerformanceRunCustomEventResourceBinding,
    output_artifact: &'a Artifact,
}

/// Builds the exact configuration contract selected by a completed TRACE32 chain.
pub(crate) fn document_for_binding(
    session: &Session,
    binding: &AcceptedTrace32CompletedBinding,
) -> Result<CaptureConfigDocument> {
    let control = binding.control();
    let capture = &control.capture_contract;
    let duration_ns = strict_performance_run_duration(session)?;
    let document = match &control.target_adapter.capture_kind {
        TargetAdapterCaptureKind::Sampling { capacity_records } => {
            ensure!(
                capture.capture_kind
                    == TargetAdapterCaptureKind::Sampling {
                        capacity_records: *capacity_records,
                    },
                "accepted sampling binding disagrees with its compiled profile"
            );
            ensure!(
                control.target_adapter.adapter_id
                    == "tricore-tc234l-snooper-pc-r2026.02-b190766-v1"
                    && control.target_adapter.adapter_version == "1.0.0",
                "sampling capture-config materialization is not implemented for this adapter"
            );
            if !matches!(
                control.target_adapter.scenario,
                TargetAdapterScenario::Normal | TargetAdapterScenario::SamplingBufferFull
            ) {
                bail!(
                    "sampling scenario `{}` cannot produce an authoritative capture config",
                    control.target_adapter.scenario.as_str()
                );
            }
            let mut document = tc234l_snooper_capture_config_for_scenario(
                session.id().as_str(),
                control.initial_target_state,
                control.target_adapter.scenario,
            );
            document.duration.duration_ns = duration_ns;
            document
        }
        TargetAdapterCaptureKind::ProgramFlowTaskEvents {
            export_profile_id,
            rtos_awareness,
            timestamp_clock_id,
            orti_artifact_id,
            task_marker_artifact_id,
        } => {
            ensure!(
                capture.capture_kind == control.target_adapter.capture_kind,
                "accepted program-flow binding disagrees with its compiled profile"
            );
            let duration_ns = duration_ns.ok_or_else(|| {
                anyhow::anyhow!(
                    "TASKEVENTS program-flow capture requires an exact performance-run request duration"
                )
            })?;
            let registered = session
                .registered_artifacts(true)
                .context("read TASKEVENTS metadata artifacts")?;
            for metadata_id in [orti_artifact_id, task_marker_artifact_id] {
                let artifact = registered
                    .iter()
                    .find(|artifact| artifact.id == *metadata_id)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "TASKEVENTS metadata artifact `{metadata_id}` is not registered"
                        )
                    })?;
                session.verify_artifact(artifact, true).with_context(|| {
                    format!("verify TASKEVENTS metadata artifact `{metadata_id}`")
                })?;
            }
            let (admitted_profile, _, _, _) =
                crate::controller_qualification::load_session_admission(session, &registered)
                    .map_err(|error| anyhow::anyhow!("{}: {}", error.code, error.message))?;
            ensure!(
                admitted_profile.controller_protocol == control.target_adapter.controller_protocol
                    && admitted_profile.custom_event_collector
                        == control.target_adapter.custom_event_collector,
                "accepted program-flow binding disagrees with its admitted Controller protocol or custom-event collector"
            );
            let custom_resources =
                load_provisioned_custom_event_resources(session, &registered, &admitted_profile)
                    .map_err(|error| anyhow::anyhow!("{}: {}", error.code, error.message))?;
            let custom_events = match control.target_adapter.controller_protocol {
                TargetAdapterControllerProtocol::V1 => {
                    ensure!(
                        custom_resources.is_none()
                            && control.target_adapter.custom_event_collector.is_none()
                            && control.custom_event_artifact.is_none(),
                        "V1 program-flow capture cannot bind custom-event resources or output"
                    );
                    None
                }
                TargetAdapterControllerProtocol::V2CustomEventsExport => {
                    let resources = custom_resources.as_ref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "V2 program-flow capture lacks provisioned custom-event resources"
                        )
                    })?;
                    let output_artifact =
                        control.custom_event_artifact.as_ref().ok_or_else(|| {
                            anyhow::anyhow!(
                                "V2 program-flow capture lacks its accepted custom-event output"
                            )
                        })?;
                    ensure!(
                        control.target_adapter.custom_event_collector.as_ref()
                            == Some(&resources.collector),
                        "V2 program-flow capture collector differs from provisioned resources"
                    );
                    Some(ProgramFlowCustomEvents {
                        resources,
                        output_artifact,
                    })
                }
            };
            program_flow_task_events_document(
                session.id().as_str(),
                &control.target_adapter,
                capture,
                control.initial_target_state,
                control.target_adapter.scenario,
                duration_ns,
                export_profile_id,
                rtos_awareness,
                timestamp_clock_id,
                orti_artifact_id,
                task_marker_artifact_id,
                &control.firmware_elf_artifact,
                &control.firmware_measurement_artifact,
                custom_events,
            )?
        }
    };
    document
        .validate()
        .context("validate Controller capture config")?;
    let parameters = &document.adapter_parameters;
    ensure!(
        parameters.get("target_adapter.scenario")
            == Some(&json!(control.target_adapter.scenario.as_str()))
            && parameters.get("firmware.elf_artifact_id")
                == Some(&json!(control.firmware_elf_artifact.id))
            && parameters.get("firmware.elf_sha256")
                == Some(&json!(control.firmware_elf_artifact.sha256))
            && parameters.get("firmware.measurement_artifact_id")
                == Some(&json!(control.firmware_measurement_artifact.id))
            && parameters.get("firmware.measurement_sha256")
                == Some(&json!(control.firmware_measurement_artifact.sha256))
            && parameters.get("firmware.measurement_size_bytes")
                == Some(&json!(control.firmware_measurement_artifact.size_bytes)),
        "authoritative capture config disagrees with the accepted scenario or firmware artifact claims"
    );
    if control.target_adapter.capture_kind.is_sampling() {
        ensure!(
            control.firmware_measurement_artifact.sha256.as_str()
                == TC234L_SNOOPER_BUILD190766_S3_SHA256
                && control.firmware_measurement_artifact.size_bytes
                    == TC234L_SNOOPER_BUILD190766_S3_SIZE_BYTES,
            "accepted firmware sparse S3 artifact disagrees with the fixed TC234L profile"
        );
    }
    Ok(document)
}

/// Returns the duration only when the immutable Session request is a valid,
/// closed performance-run request. A malformed document that claims that
/// schema is rejected rather than silently treated as an untyped request.
pub(crate) fn strict_performance_run_duration(session: &Session) -> Result<Option<u64>> {
    let request = session
        .request()
        .context("read immutable Session request")?;
    let declares_performance_run = request
        .as_object()
        .and_then(|object| object.get("schema"))
        .and_then(serde_json::Value::as_str)
        == Some(t32perf_model::PERFORMANCE_RUN_REQUEST_SCHEMA);
    if !declares_performance_run {
        return Ok(None);
    }
    let request: PerformanceRunRequest =
        serde_json::from_value(request).context("decode strict performance-run Session request")?;
    request
        .validate()
        .context("validate strict performance-run Session request")?;
    Ok(Some(request.duration_ns))
}

#[allow(clippy::too_many_arguments)]
fn program_flow_task_events_document(
    session_id: &str,
    binding: &ControllerTargetAdapterBinding,
    capture: &TargetAdapterCaptureContract,
    initial_target_state: ControllerTargetState,
    scenario: TargetAdapterScenario,
    duration_ns: u64,
    export_profile_id: &str,
    rtos_awareness: &str,
    timestamp_clock_id: &str,
    orti_artifact_id: &str,
    task_marker_artifact_id: &str,
    firmware_elf: &Artifact,
    firmware_measurement: &Artifact,
    custom_events: Option<ProgramFlowCustomEvents<'_>>,
) -> Result<CaptureConfigDocument> {
    ensure!(
        capture.covered_cores.len() == 1,
        "TASKEVENTS requires exactly one covered core"
    );
    ensure!(
        capture.timestamp_enabled,
        "TASKEVENTS requires an enabled timestamp clock"
    );
    ensure!(
        matches!(
            &capture.capture_kind,
            TargetAdapterCaptureKind::ProgramFlowTaskEvents { .. }
        ),
        "program-flow document builder received a non-program-flow contract"
    );
    let mut adapter_parameters = t32perf_model::Properties::from([
        ("export.profile".to_owned(), json!(export_profile_id)),
        (
            "target_adapter.scenario".to_owned(),
            json!(scenario.as_str()),
        ),
        (
            "firmware.elf_artifact_id".to_owned(),
            json!(firmware_elf.id),
        ),
        ("firmware.elf_sha256".to_owned(), json!(firmware_elf.sha256)),
        (
            "firmware.measurement_artifact_id".to_owned(),
            json!(firmware_measurement.id),
        ),
        (
            "firmware.measurement_sha256".to_owned(),
            json!(firmware_measurement.sha256),
        ),
        (
            "firmware.measurement_size_bytes".to_owned(),
            json!(firmware_measurement.size_bytes),
        ),
    ]);
    let instrumentation = if let Some(custom_events) = custom_events {
        let collector = &custom_events.resources.collector;
        validate_custom_event_capture_contract(
            binding,
            capture,
            timestamp_clock_id,
            collector,
            custom_events.output_artifact,
        )?;
        let mapping = &custom_events.resources.mapping_artifact;
        let overhead = &custom_events.resources.overhead_artifact;
        for (key, value) in [
            ("c_wire.counter_mapping_artifact_id", json!(mapping.id)),
            ("c_wire.counter_mapping_sha256", json!(mapping.sha256)),
            (
                "custom_events.instrumentation_overhead_sha256",
                json!(overhead.sha256),
            ),
            (
                "result.custom_events.artifact_id",
                json!(custom_events.output_artifact.id),
            ),
            (
                "result.custom_events.sha256",
                json!(custom_events.output_artifact.sha256),
            ),
            ("custom_events.source_id", json!(collector.source_id)),
            ("custom_events.core_id", json!(collector.core_id)),
            (
                "custom_events.wire_protocol",
                json!(collector.wire_protocol),
            ),
            ("custom_events.clock_id", json!(collector.clock.clock_id)),
            (
                "custom_events.clock_frequency_hz",
                json!(collector.clock.frequency_hz),
            ),
            (
                "custom_events.timestamp_modulus",
                json!(collector.clock.timestamp_modulus),
            ),
            (
                "custom_events.max_forward_ticks",
                json!(collector.clock.max_forward_ticks),
            ),
            (
                "custom_events.origin_ticks",
                json!(collector.clock.origin_ticks),
            ),
            ("custom_events.origin_ns", json!(collector.clock.origin_ns)),
            ("custom_events.transport", json!(collector.transport)),
            ("custom_events.merge_order", json!(collector.merge_order)),
        ] {
            ensure!(
                adapter_parameters.insert(key.to_owned(), value).is_none(),
                "custom-event capture parameter `{key}` collides with an existing parameter"
            );
        }
        Some(
            custom_events
                .resources
                .overhead_document
                .capture_config(overhead.id.clone())
                .context("bind custom-event instrumentation overhead evidence")?,
        )
    } else {
        ensure!(
            binding.controller_protocol == TargetAdapterControllerProtocol::V1
                && binding.custom_event_collector.is_none(),
            "V2 program-flow binding cannot omit its custom-event capture contract"
        );
        None
    };
    let document = CaptureConfigDocument {
        schema: t32perf_model::CaptureConfigSchemaVersion,
        session_id: session_id.to_owned(),
        provider: "trace32".to_owned(),
        adapter: AdapterInfo {
            id: binding.adapter_id.clone(),
            version: binding.adapter_version.clone(),
        },
        mode: capture.capture_mode.clone(),
        covered_cores: capture.covered_cores.clone(),
        sink: CaptureSinkConfig {
            kind: capture.trace_sink.clone(),
            id: capture.trace_sink.clone(),
            capacity_bytes: None,
            stream_destination_identity: None,
        },
        timestamp: CaptureTimestampConfig {
            enabled: true,
            clock_id: Some(timestamp_clock_id.to_owned()),
        },
        filters: Vec::new(),
        trigger: CaptureTriggerConfig {
            kind: "external_owner_completion/v1".to_owned(),
            pre_trigger_ns: None,
            post_trigger_ns: None,
            condition_identity: Some("workload_complete_acknowledgement".to_owned()),
        },
        duration: CaptureDurationConfig {
            duration_ns: Some(duration_ns),
            observation_limit: None,
        },
        workload_identity: capture.workload_identity.clone(),
        initial_target_state: match initial_target_state {
            ControllerTargetState::Running => InitialTargetState::Running,
            ControllerTargetState::Halted => InitialTargetState::Halted,
        },
        rtos_awareness: CaptureRtosAwarenessConfig {
            kind: rtos_awareness.to_owned(),
            metadata_artifact_ids: vec![
                orti_artifact_id.to_owned(),
                task_marker_artifact_id.to_owned(),
            ],
        },
        instrumentation,
        adapter_parameters,
    };
    document
        .validate()
        .context("validate TASKEVENTS capture config")?;
    Ok(document)
}

fn validate_custom_event_capture_contract(
    binding: &ControllerTargetAdapterBinding,
    capture: &TargetAdapterCaptureContract,
    timestamp_clock_id: &str,
    collector: &TargetAdapterCustomEventCollectorContract,
    output_artifact: &Artifact,
) -> Result<()> {
    ensure!(
        binding.controller_protocol == TargetAdapterControllerProtocol::V2CustomEventsExport
            && binding.custom_event_collector.as_ref() == Some(collector),
        "custom-event capture contract is not bound to Controller V2"
    );
    ensure!(
        capture.covered_cores.contains(&collector.core_id)
            && collector.clock.clock_id == timestamp_clock_id,
        "custom-event collector core or clock is outside the accepted program-flow capture"
    );
    ensure!(
        output_artifact.id != collector.mapping_artifact_id
            && output_artifact.id != collector.instrumentation_overhead_artifact_id
            && output_artifact.size_bytes <= collector.max_output_bytes,
        "accepted custom-event output conflicts with deployment resources or exceeds its collector bound"
    );
    Ok(())
}

/// Returns the closed, ordered Controller provenance for a document.
pub(crate) fn expected_input_artifact_ids(
    binding: &AcceptedTrace32CompletedBinding,
    document: &CaptureConfigDocument,
) -> Result<Vec<String>> {
    let control = binding.control();
    let mut control_and_firmware = vec![
        control.capabilities_artifact.id.clone(),
        control.configure_artifact.id.clone(),
        control.start_artifact.id.clone(),
        control.stop_artifact.id.clone(),
        control.health_artifact.id.clone(),
        control.export_artifact.id.clone(),
    ];
    if let Some(custom_event_artifact) = &control.custom_event_artifact {
        control_and_firmware.push(custom_event_artifact.id.clone());
    }
    control_and_firmware.extend([
        control.cleanup_artifact.id.clone(),
        control.firmware_elf_artifact.id.clone(),
        control.firmware_measurement_artifact.id.clone(),
    ]);
    let qualification = control
        .qualification_provenance_artifacts
        .iter()
        .map(|artifact| artifact.id.clone())
        .collect::<Vec<_>>();
    let mut document_inputs = document
        .input_artifact_ids()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if let Some(collector) = &control.target_adapter.custom_event_collector {
        document_inputs.push(collector.mapping_artifact_id.clone());
    }
    expected_input_artifact_ids_from_parts(control_and_firmware, qualification, document_inputs)
}

fn expected_input_artifact_ids_from_parts(
    control_and_firmware: Vec<String>,
    qualification: Vec<String>,
    document_inputs: impl IntoIterator<Item = String>,
) -> Result<Vec<String>> {
    let mut inputs = control_and_firmware;
    inputs.extend(qualification);
    inputs.extend(document_inputs);
    let unique = inputs.iter().collect::<std::collections::BTreeSet<_>>();
    ensure!(
        unique.len() == inputs.len(),
        "Controller capture-config provenance repeats an artifact ID"
    );
    Ok(inputs)
}

fn ensure_registered_provenance(artifacts: &[Artifact], inputs: &[String]) -> Result<()> {
    for input in inputs {
        ensure!(
            artifacts.iter().any(|artifact| artifact.id == *input),
            "Controller capture-config provenance references unregistered artifact `{input}`"
        );
    }
    Ok(())
}

fn verify_materialized_artifact(
    session: &Session,
    artifact: &Artifact,
    spec: &ArtifactSpec,
    expected: &[u8],
    expected_sha256: &Sha256Digest,
) -> Result<()> {
    ensure!(
        artifact.id == spec.id
            && artifact.kind == spec.kind
            && artifact.relative_path == spec.relative_path
            && artifact.media_type == spec.media_type
            && artifact.producer == spec.producer
            && artifact.input_artifact_ids == spec.input_artifact_ids
            && &artifact.sha256 == expected_sha256,
        "existing capture-config conflicts with the completed Controller chain"
    );
    session
        .verify_artifact(artifact, true)
        .context("verify immutable Controller capture config")?;
    let mut file = session
        .open_artifact(artifact)
        .context("open immutable Controller capture config")?;
    let mut actual = Vec::with_capacity(expected.len());
    file.by_ref()
        .take(MAX_CAPTURE_CONFIG_BYTES.saturating_add(1))
        .read_to_end(&mut actual)
        .context("read immutable Controller capture config")?;
    ensure!(
        actual == expected,
        "immutable Controller capture config bytes differ from host materialization"
    );
    Ok(())
}

/// Materializes the authoritative document through the durable staged-ingest protocol.
pub(crate) fn materialize(
    session: &Session,
    lock: &SessionLock,
    binding: &AcceptedTrace32CompletedBinding,
) -> Result<Artifact> {
    let document = document_for_binding(session, binding)?;
    let bytes = serde_json::to_vec(&document).context("serialize Controller capture config")?;
    ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_CAPTURE_CONFIG_BYTES,
        "serialized Controller capture config exceeds its bounded artifact limit"
    );
    let expected_sha256 = sha256(&bytes)?;
    let spec = ArtifactSpec {
        id: CAPTURE_CONFIG_ID.to_owned(),
        kind: CAPTURE_CONFIG_KIND.to_owned(),
        relative_path: ArtifactPath::new(CAPTURE_CONFIG_PATH)
            .context("construct Controller capture-config destination")?,
        media_type: "application/json".to_owned(),
        producer: CONTROLLER_CAPTURE_CONFIG_PRODUCER.to_owned(),
        input_artifact_ids: expected_input_artifact_ids(binding, &document)?,
    };
    let registered = session
        .registered_artifacts(false)
        .context("read capture-config catalog before materialization")?;
    ensure_registered_provenance(&registered, &spec.input_artifact_ids)?;
    let staging = ArtifactPath::new(CONTROLLER_CAPTURE_CONFIG_STAGING_PATH)
        .context("construct Controller capture-config staging path")?;

    if let Some(existing) = registered
        .iter()
        .find(|artifact| artifact.id == CAPTURE_CONFIG_ID)
        .cloned()
    {
        verify_materialized_artifact(session, &existing, &spec, &bytes, &expected_sha256)?;
        validate_registered(session, &registered, &existing, &document)?;
        return Ok(existing);
    }

    write_exact_staging_bytes(session, lock, &staging, &bytes)?;
    let artifact = session
        .ingest_staged_bounded(lock, &staging, spec.clone(), MAX_CAPTURE_CONFIG_BYTES)
        .context("durably ingest Controller capture config")?;
    verify_materialized_artifact(session, &artifact, &spec, &bytes, &expected_sha256)?;
    let registered = session
        .registered_artifacts(false)
        .context("read capture-config catalog after materialization")?;
    validate_registered(session, &registered, &artifact, &document)?;
    Ok(artifact)
}

/// Reconstructs a completed chain and durably ensures its capture-config artifact.
///
/// This is intentionally safe to call after accepting cleanup and again from
/// the completed `perf_capture` rendering path: staged-ingest intent recovery
/// and the exact-existing check make both calls idempotent.
pub(crate) fn ensure_for_completed_session(
    root: &ArtifactRoot,
    session_id: &str,
) -> Result<Artifact, crate::app::AppError> {
    let namespace = root
        .try_namespace_lock()
        .map_err(crate::app::AppError::operational)?;
    let id = SessionId::new(session_id).map_err(crate::app::AppError::operational)?;
    let session = root
        .session(&id)
        .map_err(crate::app::AppError::operational)?;
    let lock = session
        .try_lock_in_namespace(&namespace)
        .map_err(crate::app::AppError::operational)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(crate::app::AppError::operational)?;
    let binding = crate::controller::accepted_trace32_completed_binding(&session, &artifacts)?
        .ok_or_else(|| {
            crate::app::AppError::operational(
                "Controller capture-config materialization requires a completed TRACE32 chain",
            )
        })?;
    materialize(&session, &lock, &binding).map_err(crate::app::AppError::operational)
}

/// Validates a registered Controller-produced configuration against the chain that owns it.
pub(crate) fn validate_registered(
    session: &Session,
    artifacts: &[Artifact],
    artifact: &Artifact,
    document: &CaptureConfigDocument,
) -> Result<()> {
    ensure!(
        artifact.producer == CONTROLLER_CAPTURE_CONFIG_PRODUCER,
        "capture-config is not Controller produced"
    );
    let configuration_sha256 = configuration_sha256(document)?;
    crate::controller::validate_capture_config_against_controller(
        session,
        artifacts,
        document,
        &configuration_sha256,
    )
    .map_err(|error| anyhow::anyhow!("{}: {}", error.code, error.message))?;
    let binding = crate::controller::accepted_trace32_completed_binding(session, artifacts)
        .map_err(|error| anyhow::anyhow!("{}: {}", error.code, error.message))?
        .ok_or_else(|| {
            anyhow::anyhow!("Controller capture-config requires a completed TRACE32 chain")
        })?;
    let expected_document = document_for_binding(session, &binding)?;
    ensure!(
        document == &expected_document,
        "Controller capture-config document differs from the selected profile/scenario/capabilities contract"
    );
    let expected_inputs = expected_input_artifact_ids(&binding, &expected_document)?;
    ensure!(
        artifact.input_artifact_ids == expected_inputs,
        "Controller capture-config provenance is missing, reordered, or has extra inputs"
    );
    Ok(())
}

fn write_exact_staging_bytes(
    session: &Session,
    lock: &SessionLock,
    staging: &ArtifactPath,
    expected: &[u8],
) -> Result<()> {
    session
        .ensure_staged_exact(lock, staging, expected, MAX_CAPTURE_CONFIG_BYTES)
        .context("materialize exact Controller capture-config staging bytes")
}

fn sha256(bytes: &[u8]) -> Result<Sha256Digest> {
    let digest = Sha256::digest(bytes);
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Sha256Digest::new(hex).context("construct capture-config SHA-256")
}

fn configuration_sha256(document: &CaptureConfigDocument) -> Result<Sha256Digest> {
    // Controller Configure binds only the pre-capture adapter configuration.
    // Runtime output claims, measured overhead and deployment-evidence digests
    // are bound by the complete capture-config artifact instead.
    let mut adapter_configuration = document.clone();
    adapter_configuration.session_id.clear();
    adapter_configuration.duration.duration_ns = None;
    adapter_configuration.instrumentation = None;
    adapter_configuration.adapter_parameters.retain(|key, _| {
        !key.starts_with("result.")
            && !matches!(
                key.as_str(),
                "c_wire.counter_mapping_sha256" | "custom_events.instrumentation_overhead_sha256"
            )
    });
    let bytes = serde_json::to_vec(&adapter_configuration)
        .context("serialize static Controller capture-config identity")?;
    sha256(&bytes)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;
    use t32perf_model::{
        ArtifactPath, InstrumentationOverheadEvidenceDocument,
        InstrumentationOverheadEvidenceSchemaVersion, Sha256Digest,
    };
    use t32perf_session::{ArtifactRoot, ArtifactSpec, SessionLimits};
    use t32perf_trace32::{
        ControllerTargetAdapterBinding, ControllerTargetState,
        TC234L_SNOOPER_BUILD190766_S3_SHA256, TC234L_SNOOPER_BUILD190766_S3_SIZE_BYTES,
        TargetAdapterCaptureContract, TargetAdapterCaptureKind, TargetAdapterControllerProtocol,
        TargetAdapterCustomEventClockContract, TargetAdapterCustomEventCollectorContract,
        TargetAdapterCustomEventMergeOrder, TargetAdapterCustomEventWireProtocol,
        TargetAdapterScenario, tc234l_snooper_capture_config_for_scenario,
    };

    use crate::target_adapter_provisioning::PerformanceRunCustomEventResourceBinding;

    use super::{
        CAPTURE_CONFIG_ID, CAPTURE_CONFIG_KIND, CAPTURE_CONFIG_PATH,
        CONTROLLER_CAPTURE_CONFIG_PRODUCER, MAX_CAPTURE_CONFIG_BYTES, ProgramFlowCustomEvents,
        expected_input_artifact_ids_from_parts, program_flow_task_events_document, sha256,
        strict_performance_run_duration, verify_materialized_artifact,
    };

    #[test]
    fn authoritative_builder_covers_running_halted_normal_and_buffer_full() {
        for (state, scenario, records, expected_digest) in [
            (
                ControllerTargetState::Running,
                TargetAdapterScenario::Normal,
                65_536,
                "45ad2a31dcf8558e0155446871c1b4a684f4e769767dc0fcaffa70277eff1dd6",
            ),
            (
                ControllerTargetState::Halted,
                TargetAdapterScenario::Normal,
                65_536,
                "a4a59ed9aa03965154148ef84c91d0529b99ae41990661ada7f0f83c36bd5a32",
            ),
            (
                ControllerTargetState::Running,
                TargetAdapterScenario::SamplingBufferFull,
                32,
                "94c2642c43670a1dc80711a319549438bc20680a843d3f213a1cac2f2ef205f0",
            ),
            (
                ControllerTargetState::Halted,
                TargetAdapterScenario::SamplingBufferFull,
                32,
                "b3863046a6e770fa7e2915324082fff047ac280e0e9ef37c169d6ae60a1cf427",
            ),
        ] {
            let document =
                tc234l_snooper_capture_config_for_scenario("test-session", state, scenario);
            document.validate().unwrap();
            assert_eq!(document.duration.observation_limit, Some(records));
            assert_eq!(
                document.adapter_parameters.get("target_adapter.scenario"),
                Some(&json!(scenario.as_str()))
            );
            assert_eq!(
                document
                    .adapter_parameters
                    .get("firmware.measurement_sha256"),
                Some(&json!(TC234L_SNOOPER_BUILD190766_S3_SHA256))
            );
            assert_eq!(
                document
                    .adapter_parameters
                    .get("firmware.measurement_size_bytes"),
                Some(&json!(TC234L_SNOOPER_BUILD190766_S3_SIZE_BYTES))
            );
            assert_eq!(
                super::configuration_sha256(&document).unwrap().as_str(),
                expected_digest
            );
        }
    }

    #[test]
    fn performance_run_duration_is_authoritative_but_not_a_compiled_adapter_digest_input() {
        let mut document = tc234l_snooper_capture_config_for_scenario(
            "test-session",
            ControllerTargetState::Halted,
            TargetAdapterScenario::Normal,
        );
        let compiled = super::configuration_sha256(&document).unwrap();
        let without_duration = document.configuration_identity_bytes().unwrap();
        document.duration.duration_ns = Some(500_000_000);
        assert_eq!(super::configuration_sha256(&document).unwrap(), compiled);
        assert_ne!(
            document.configuration_identity_bytes().unwrap(),
            without_duration
        );
    }

    #[test]
    fn provenance_is_canonical_for_candidate_and_qualified_bindings() {
        let base: Vec<String> = vec![
            "controller-capabilities",
            "controller-configure",
            "controller-start",
            "controller-stop",
            "controller-health",
            "controller-export",
            "controller-cleanup",
            "firmware-elf",
            "trace32-firmware-s3",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        assert_eq!(
            expected_input_artifact_ids_from_parts(base.clone(), Vec::new(), Vec::new()).unwrap(),
            base
        );
        assert_eq!(
            expected_input_artifact_ids_from_parts(
                base.clone(),
                vec![
                    "target-adapter-policy".to_owned(),
                    "target-adapter-hil".to_owned(),
                    "target-adapter-qualification".to_owned(),
                    "target-adapter-admission".to_owned(),
                ],
                vec![
                    "orti-metadata".to_owned(),
                    "instrumentation-overhead".to_owned()
                ],
            )
            .unwrap(),
            [
                "controller-capabilities",
                "controller-configure",
                "controller-start",
                "controller-stop",
                "controller-health",
                "controller-export",
                "controller-cleanup",
                "firmware-elf",
                "trace32-firmware-s3",
                "target-adapter-policy",
                "target-adapter-hil",
                "target-adapter-qualification",
                "target-adapter-admission",
                "orti-metadata",
                "instrumentation-overhead",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>(),
        );
        let mut v2_base = base.clone();
        v2_base.insert(6, "controller-custom-events".to_owned());
        assert_eq!(
            expected_input_artifact_ids_from_parts(
                v2_base,
                vec![
                    "target-adapter-policy".to_owned(),
                    "target-adapter-hil".to_owned(),
                    "target-adapter-qualification".to_owned(),
                    "target-adapter-admission".to_owned(),
                ],
                vec![
                    "orti-metadata".to_owned(),
                    "task-markers".to_owned(),
                    "instrumentation-overhead".to_owned(),
                    "c-wire-mapping".to_owned(),
                ],
            )
            .unwrap(),
            [
                "controller-capabilities",
                "controller-configure",
                "controller-start",
                "controller-stop",
                "controller-health",
                "controller-export",
                "controller-custom-events",
                "controller-cleanup",
                "firmware-elf",
                "trace32-firmware-s3",
                "target-adapter-policy",
                "target-adapter-hil",
                "target-adapter-qualification",
                "target-adapter-admission",
                "orti-metadata",
                "task-markers",
                "instrumentation-overhead",
                "c-wire-mapping",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>(),
        );
        assert!(
            expected_input_artifact_ids_from_parts(
                base,
                vec!["controller-export".to_owned()],
                Vec::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn materialized_artifact_verification_is_idempotent_and_rejects_conflicts() {
        let temporary = tempfile::tempdir().unwrap();
        let root = ArtifactRoot::open(temporary.path().join("sessions"), SessionLimits::default())
            .unwrap();
        let session = root.create_session(&json!({})).unwrap();
        let lock = session.try_lock().unwrap();
        let bytes = br#"{\"schema\":\"test\"}"#;
        let staging = ArtifactPath::new("controller/capture-config.json").unwrap();
        let spec = ArtifactSpec {
            id: CAPTURE_CONFIG_ID.to_owned(),
            kind: CAPTURE_CONFIG_KIND.to_owned(),
            relative_path: ArtifactPath::new(CAPTURE_CONFIG_PATH).unwrap(),
            media_type: "application/json".to_owned(),
            producer: CONTROLLER_CAPTURE_CONFIG_PRODUCER.to_owned(),
            input_artifact_ids: Vec::new(),
        };
        session
            .ensure_staged_exact(&lock, &staging, bytes, MAX_CAPTURE_CONFIG_BYTES)
            .unwrap();
        let artifact = session
            .ingest_staged_bounded(&lock, &staging, spec.clone(), MAX_CAPTURE_CONFIG_BYTES)
            .unwrap();
        let digest = sha256(bytes).unwrap();

        verify_materialized_artifact(&session, &artifact, &spec, bytes, &digest).unwrap();
        verify_materialized_artifact(&session, &artifact, &spec, bytes, &digest).unwrap();
        assert!(
            verify_materialized_artifact(&session, &artifact, &spec, b"conflict", &digest).is_err()
        );
    }

    #[test]
    fn program_flow_builder_copies_the_typed_contract_without_sampling_fields() {
        let capture = TargetAdapterCaptureContract {
            configuration_sha256_by_initial_state: BTreeMap::from([(
                ControllerTargetState::Running,
                Sha256Digest::new("1".repeat(64)).unwrap(),
            )]),
            capture_mode: "taskevents-program-flow/v1".to_owned(),
            trace_sink: "trace32_taskevents_export/v1".to_owned(),
            capture_kind: TargetAdapterCaptureKind::ProgramFlowTaskEvents {
                export_profile_id: "taskevents-profile/v1".to_owned(),
                rtos_awareness: "autosar-os-awareness/v1".to_owned(),
                timestamp_clock_id: "stm-clock/v1".to_owned(),
                orti_artifact_id: "fixture-orti".to_owned(),
                task_marker_artifact_id: "fixture-task-markers".to_owned(),
            },
            timestamp_enabled: true,
            workload_identity: "program-flow-workload/v1".to_owned(),
            covered_cores: vec![0],
            supported_initial_states: vec![ControllerTargetState::Running],
        };
        let binding = ControllerTargetAdapterBinding {
            adapter_id: "fixture-program-flow".to_owned(),
            adapter_version: "1.0.0".to_owned(),
            trace32_release: "2026.02".to_owned(),
            trace32_build: 1,
            architecture_package: "TriCore".to_owned(),
            target_identifier: "fixture-target".to_owned(),
            probe_identifier: "fixture-probe".to_owned(),
            profile_sha256: Sha256Digest::new("2".repeat(64)).unwrap(),
            implementation_sha256: Sha256Digest::new("3".repeat(64)).unwrap(),
            scenario: TargetAdapterScenario::Normal,
            capture_kind: capture.capture_kind.clone(),
            controller_protocol: t32perf_trace32::TargetAdapterControllerProtocol::V1,
            custom_event_collector: None,
            qualification_sha256: None,
        };
        let artifact = |id: &str, digest: &str, size_bytes| t32perf_model::Artifact {
            id: id.to_owned(),
            kind: "fixture".to_owned(),
            relative_path: ArtifactPath::new(format!("fixture/{id}")).unwrap(),
            media_type: "application/octet-stream".to_owned(),
            size_bytes,
            sha256: Sha256Digest::new(digest.to_owned()).unwrap(),
            producer: "fixture/v1".to_owned(),
            input_artifact_ids: Vec::new(),
        };
        let document = program_flow_task_events_document(
            "session",
            &binding,
            &capture,
            ControllerTargetState::Running,
            TargetAdapterScenario::Normal,
            1_000,
            "taskevents-profile/v1",
            "autosar-os-awareness/v1",
            "stm-clock/v1",
            "fixture-orti",
            "fixture-task-markers",
            &artifact("firmware", &"4".repeat(64), 7),
            &artifact("measurement", &"5".repeat(64), 9),
            None,
        )
        .unwrap();
        assert_eq!(document.mode, capture.capture_mode);
        assert_eq!(document.covered_cores, [0]);
        assert_eq!(document.timestamp.clock_id.as_deref(), Some("stm-clock/v1"));
        assert_eq!(document.rtos_awareness.kind, "autosar-os-awareness/v1");
        assert_eq!(
            document.rtos_awareness.metadata_artifact_ids,
            ["fixture-orti", "fixture-task-markers"]
        );
        assert_eq!(document.duration.duration_ns, Some(1_000));
        assert_eq!(document.duration.observation_limit, None);
        assert_eq!(
            document.adapter_parameters.get("export.profile"),
            Some(&json!("taskevents-profile/v1"))
        );
        assert!(!document.adapter_parameters.contains_key("snooper.object"));
    }

    #[test]
    fn program_flow_v2_binds_instrumentation_collector_mapping_and_custom_output() {
        let capture = TargetAdapterCaptureContract {
            configuration_sha256_by_initial_state: BTreeMap::from([(
                ControllerTargetState::Running,
                Sha256Digest::new("1".repeat(64)).unwrap(),
            )]),
            capture_mode: "taskevents-program-flow/v1".to_owned(),
            trace_sink: "trace32_taskevents_export/v1".to_owned(),
            capture_kind: TargetAdapterCaptureKind::ProgramFlowTaskEvents {
                export_profile_id: "taskevents-profile/v1".to_owned(),
                rtos_awareness: "autosar-os-awareness/v1".to_owned(),
                timestamp_clock_id: "stm-clock/v1".to_owned(),
                orti_artifact_id: "fixture-orti".to_owned(),
                task_marker_artifact_id: "fixture-task-markers".to_owned(),
            },
            timestamp_enabled: true,
            workload_identity: "program-flow-workload/v1".to_owned(),
            covered_cores: vec![0],
            supported_initial_states: vec![ControllerTargetState::Running],
        };
        let collector = TargetAdapterCustomEventCollectorContract {
            wire_protocol: TargetAdapterCustomEventWireProtocol::CWireV1,
            source_id: "fixture-custom-events".to_owned(),
            core_id: 0,
            clock: TargetAdapterCustomEventClockContract {
                clock_id: "stm-clock/v1".to_owned(),
                frequency_hz: 100_000_000,
                timestamp_modulus: 1_u64 << 32,
                max_forward_ticks: 1_u64 << 31,
                origin_ticks: 17,
                origin_ns: 23,
            },
            transport: "fixture-shared-memory/v1".to_owned(),
            mapping_artifact_id: "fixture-c-wire-mapping".to_owned(),
            instrumentation_overhead_artifact_id: "fixture-instrumentation-overhead".to_owned(),
            max_output_bytes: 4_096,
            merge_order: TargetAdapterCustomEventMergeOrder::RejectAmbiguousTies,
        };
        let binding = ControllerTargetAdapterBinding {
            adapter_id: "fixture-program-flow-v2".to_owned(),
            adapter_version: "1.0.0".to_owned(),
            trace32_release: "2026.02".to_owned(),
            trace32_build: 1,
            architecture_package: "TriCore".to_owned(),
            target_identifier: "fixture-target".to_owned(),
            probe_identifier: "fixture-probe".to_owned(),
            profile_sha256: Sha256Digest::new("2".repeat(64)).unwrap(),
            implementation_sha256: Sha256Digest::new("3".repeat(64)).unwrap(),
            scenario: TargetAdapterScenario::Normal,
            capture_kind: capture.capture_kind.clone(),
            controller_protocol: TargetAdapterControllerProtocol::V2CustomEventsExport,
            custom_event_collector: Some(collector.clone()),
            qualification_sha256: Some(Sha256Digest::new("4".repeat(64)).unwrap()),
        };
        let artifact = |id: &str, digest: &str, size_bytes| t32perf_model::Artifact {
            id: id.to_owned(),
            kind: "fixture".to_owned(),
            relative_path: ArtifactPath::new(format!("fixture/{id}")).unwrap(),
            media_type: "application/octet-stream".to_owned(),
            size_bytes,
            sha256: Sha256Digest::new(digest.to_owned()).unwrap(),
            producer: "fixture/v1".to_owned(),
            input_artifact_ids: Vec::new(),
        };
        let mapping = artifact(&collector.mapping_artifact_id, &"5".repeat(64), 101);
        let overhead = artifact(
            &collector.instrumentation_overhead_artifact_id,
            &"6".repeat(64),
            102,
        );
        let output = artifact("controller-custom-events-test", &"7".repeat(64), 103);
        let resources = PerformanceRunCustomEventResourceBinding {
            collector: collector.clone(),
            mapping_artifact: mapping.clone(),
            overhead_artifact: overhead.clone(),
            overhead_document: InstrumentationOverheadEvidenceDocument {
                schema: InstrumentationOverheadEvidenceSchemaVersion,
                instrumentation_method: "t32perf-c-wire/v1".to_owned(),
                transport: collector.transport.clone(),
                measurement_method: "fixture-calibration/v1".to_owned(),
                baseline_duration_ns: 1_000,
                instrumented_duration_ns: 1_250,
                emitted_event_count: 10,
            },
        };
        let document = program_flow_task_events_document(
            "session",
            &binding,
            &capture,
            ControllerTargetState::Running,
            TargetAdapterScenario::Normal,
            1_000,
            "taskevents-profile/v1",
            "autosar-os-awareness/v1",
            "stm-clock/v1",
            "fixture-orti",
            "fixture-task-markers",
            &artifact("firmware", &"8".repeat(64), 7),
            &artifact("measurement", &"9".repeat(64), 9),
            Some(ProgramFlowCustomEvents {
                resources: &resources,
                output_artifact: &output,
            }),
        )
        .unwrap();

        let instrumentation = document.instrumentation.as_ref().unwrap();
        assert_eq!(instrumentation.method, "t32perf-c-wire/v1");
        assert_eq!(instrumentation.transport, collector.transport);
        assert_eq!(instrumentation.overhead.evidence_artifact_id, overhead.id);
        assert_eq!(
            document
                .adapter_parameters
                .get("c_wire.counter_mapping_artifact_id"),
            Some(&json!(mapping.id))
        );
        assert_eq!(
            document
                .adapter_parameters
                .get("result.custom_events.artifact_id"),
            Some(&json!(output.id))
        );
        assert_eq!(
            document.adapter_parameters.get("custom_events.clock_id"),
            Some(&json!(collector.clock.clock_id))
        );
        assert_eq!(
            document.adapter_parameters.get("custom_events.merge_order"),
            Some(&json!("reject_ambiguous_ties"))
        );
        document.validate().unwrap();

        let complete_bytes = serde_json::to_vec(&document).unwrap();
        let configuration_identity = document.configuration_identity_bytes().unwrap();
        let configure_digest = super::configuration_sha256(&document).unwrap();
        let mut another_execution = document.clone();
        another_execution.session_id = "another-session".to_owned();
        another_execution.adapter_parameters.insert(
            "result.custom_events.artifact_id".to_owned(),
            json!("controller-custom-events-random-output"),
        );
        another_execution.adapter_parameters.insert(
            "result.custom_events.sha256".to_owned(),
            json!("a".repeat(64)),
        );
        another_execution.adapter_parameters.insert(
            "result.controller.transaction_id".to_owned(),
            json!("random-controller-transaction"),
        );
        assert_eq!(
            another_execution.configuration_identity_bytes().unwrap(),
            configuration_identity,
            "runtime result claims must not change cross-Session configuration identity"
        );
        assert_eq!(
            super::configuration_sha256(&another_execution).unwrap(),
            configure_digest,
            "runtime result claims must not change the Configure digest"
        );
        assert_ne!(
            serde_json::to_vec(&another_execution).unwrap(),
            complete_bytes,
            "the exact capture-config artifact must retain execution identity"
        );

        let mut mapping_or_evidence_drift = document.clone();
        mapping_or_evidence_drift.adapter_parameters.insert(
            "c_wire.counter_mapping_sha256".to_owned(),
            json!("b".repeat(64)),
        );
        assert_ne!(
            mapping_or_evidence_drift
                .configuration_identity_bytes()
                .unwrap(),
            configuration_identity,
            "mapping evidence drift must change cross-Session configuration identity"
        );
        assert_eq!(
            super::configuration_sha256(&mapping_or_evidence_drift).unwrap(),
            configure_digest,
            "post-deployment mapping evidence must not change the Configure digest"
        );
        mapping_or_evidence_drift.adapter_parameters.insert(
            "custom_events.instrumentation_overhead_sha256".to_owned(),
            json!("c".repeat(64)),
        );
        assert_ne!(
            mapping_or_evidence_drift
                .configuration_identity_bytes()
                .unwrap(),
            configuration_identity,
            "instrumentation evidence drift must change cross-Session configuration identity"
        );
        assert_eq!(
            super::configuration_sha256(&mapping_or_evidence_drift).unwrap(),
            configure_digest,
            "post-capture instrumentation evidence must not change the Configure digest"
        );
        let mut mapping_contract_drift = document.clone();
        mapping_contract_drift.adapter_parameters.insert(
            "c_wire.counter_mapping_artifact_id".to_owned(),
            json!("different-profile-known-mapping"),
        );
        assert_ne!(
            super::configuration_sha256(&mapping_contract_drift).unwrap(),
            configure_digest,
            "the profile-known mapping artifact remains part of static Configure configuration"
        );
        assert!(
            program_flow_task_events_document(
                "session",
                &binding,
                &capture,
                ControllerTargetState::Running,
                TargetAdapterScenario::Normal,
                1_000,
                "taskevents-profile/v1",
                "autosar-os-awareness/v1",
                "stm-clock/v1",
                "fixture-orti",
                "fixture-task-markers",
                &artifact("firmware", &"8".repeat(64), 7),
                &artifact("measurement", &"9".repeat(64), 9),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn performance_run_duration_is_strict_and_never_silently_downgraded() {
        let temporary = tempfile::tempdir().unwrap();
        let root = ArtifactRoot::open(temporary.path().join("sessions"), SessionLimits::default())
            .unwrap();
        let performance_run = root
            .create_session(&json!({
                "schema": "t32perf.performance-run-request/v1",
                "duration_ns": 1_000,
                "top": 1,
                "report_format": "perfetto_json",
            }))
            .unwrap();
        assert_eq!(
            strict_performance_run_duration(&performance_run).unwrap(),
            Some(1_000)
        );
        let malformed = root
            .create_session(&json!({
                "schema": "t32perf.performance-run-request/v1",
                "duration_ns": 0,
                "top": 1,
                "report_format": "perfetto_json",
            }))
            .unwrap();
        assert!(strict_performance_run_duration(&malformed).is_err());
        let untyped = root.create_session(&json!({"request": "other"})).unwrap();
        assert_eq!(strict_performance_run_duration(&untyped).unwrap(), None);
    }
}
