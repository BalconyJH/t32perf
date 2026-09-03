use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    io::{BufReader, Read as _},
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use t32perf_model::{
    Artifact, ArtifactPath, CaptureConfigDocument, DictionaryEntry, ObservationDictionary,
    ObservationStreamHeader, Properties, Quality, SessionError, SessionStatus, strict_json,
};
use t32perf_session::{ArtifactRoot, ArtifactSpec, Session, SessionLock};
use t32perf_trace32::{
    AdapterRequest, C_WIRE_VERSION, CWireObservationSource, CWireSourceConfig,
    CanonicalNdjsonSource, ClockDomainSpec, ControllerCaptureCompletionEvidence,
    ControllerHealthEvidenceV2, ControllerProgramFlowHealthEvidence, ControllerStopEvidence,
    ControllerStopEvidenceV2, CsvAdapterConfig, CsvColumnMap, CsvField,
    DEFAULT_MAX_DICTIONARY_BYTES, DEFAULT_MAX_DICTIONARY_ENTRIES, ExplicitCsvSource,
    HARD_MAX_DICTIONARY_BYTES, HARD_MAX_DICTIONARY_ENTRIES, KWayMerge, LineLimits,
    MAX_C_WIRE_COUNTER_MAPPING_DOCUMENT_BYTES, MAX_TRACE32_FUNCTION_RANGES,
    NdjsonObservationReader, ObservationSource, OrderedObservation, RationalTickScale,
    SourceDescriptor, SourceError, TC234L_SNOOPER_ASCII_PROFILE_V1, TRACE32_SYMBOL_MAPPING_SCHEMA,
    TargetAdapterCaptureKind, TargetAdapterControllerProtocol, TargetAdapterQualificationReceipt,
    TargetAdapterScenario, Trace32SymbolMappingDocument, Trace32TaskEventsMappingDocument,
    Trace32ValidatedAdapterContext as Trace32QualifiedAdapterContext,
    Trace32ValidatedCaptureKind as Trace32QualifiedCaptureKind,
    Trace32ValidatedMapping as Trace32QualifiedMapping,
    Trace32ValidatedRawInputIdentity as Trace32RawInputIdentity,
    Trace32ValidatedRuntime as Trace32QualifiedRuntime, TraceArtifactBinding,
    TraceTaskEventsRuntimeBinding, TraceTaskEventsTrace32Identity, TraceTaskMetadataBinding,
    TraceTaskMetadataRole, ValidatedTargetAdapterReceipt as QualifiedTargetAdapter,
    ValidatedTrace32AdapterRegistry as QualifiedTrace32AdapterRegistry, WireLimits,
    materialize_trace32_task_events_mapping, parse_c_wire_counter_mapping,
    parse_trace32_symbol_mapping, parse_trace32_task_events_mapping,
    parse_trace32_task_events_mapping_template, trace_function_mappings_from_elf,
};

use crate::{
    app::{AppError, CommandOutcome, EXIT_SUCCESS, open_session},
    capture_config::{CAPTURE_CONFIG_ID, RegisteredCaptureConfig, registered_capture_config},
    controller::{AcceptedTrace32RuntimeBinding, accepted_trace32_runtime_binding},
    controller_qualification::load_session_admission,
    target_adapter_provisioning::{
        BUILD_RESOURCE_PRODUCER, TASK_EVENTS_MAPPING_TEMPLATE_ARTIFACT_ID,
    },
};

const NORMALIZE_CONFIG_SCHEMA: &str = "t32perf.normalize-config/v1";
const SINGLE_SOURCE_MODE: &str = "single_source";
const MULTI_SOURCE_MODE: &str = "multi_source";
const NORMALIZE_PRODUCER: &str = "t32perf-normalize/v1";
const NORMALIZE_CONFIG_KIND: &str = "normalization_config";
const PERFORMANCE_RUN_NORMALIZE_CONFIG_ID: &str = "performance-run-normalize-config";
const PERFORMANCE_RUN_NORMALIZE_CONFIG_PATH: &str = "capture/performance-run/normalize-config.json";
const PERFORMANCE_RUN_NORMALIZE_CONFIG_STAGING_PATH: &str = "performance-run/normalize-config.json";
const PERFORMANCE_RUN_NORMALIZE_CONFIG_PRODUCER: &str =
    "t32perf-performance-run-normalize-config/v1";
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_MULTI_SOURCES: usize = 64;
const MAX_CONFIG_LINE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CONFIG_RECORDS: u64 = 1_000_000_000;
const MAX_TRACE32_ELF_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TRACE32_MAPPING_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TRACE32_TASK_EVENTS_TEMPLATE_BYTES: u64 = 16 * 1024 * 1024;
const TRACE32_RELEASE_2026_02: &str = "2026.02";
const TRACE32_BUILD_190766: u64 = 190_766;
const TRACE32_ARCHITECTURE_TRICORE: &str = "tricore";
const TRACE32_TARGET_TC234L_CORE0: &str = "infineon-tc234l-core0";
const TRACE32_TC234L_ADAPTER_ID: &str = "tricore-tc234l-snooper-pc-r2026.02-b190766-v1";
const TRACE32_TC234L_ADAPTER_VERSION: &str = "1.0.0";
const TRACE32_ASCII_CLOCK_DOMAIN: &str = "snooper_host_time";
const TRACE32_ASCII_ADDRESS_CLASS: &str = "P";
const TRACE32_FIRMWARE_ELF_KIND: &str = "firmware_elf";
const TRACE32_FIRMWARE_ELF_MEDIA_TYPE: &str = "application/x-elf";
pub(crate) const TRACE32_SYMBOL_MAPPING_ARTIFACT_ID: &str = "trace32-symbol-mapping";
pub(crate) const TRACE32_SYMBOL_MAPPING_ARTIFACT_KIND: &str = "trace32_symbol_mapping";
pub(crate) const TRACE32_SYMBOL_MAPPING_ARTIFACT_PATH: &str =
    "normalized/trace32-symbol-mapping.json";
pub(crate) const TRACE32_TASK_EVENTS_MAPPING_ARTIFACT_KIND: &str = "trace32_task_events_mapping";
pub(crate) const TRACE32_TASK_EVENTS_MAPPING_ARTIFACT_ID: &str = "trace32-task-events-mapping";
pub(crate) const TRACE32_TASK_EVENTS_MAPPING_ARTIFACT_PATH: &str =
    "normalized/trace32-task-events-mapping.json";
pub(crate) const TRACE32_TASK_EVENTS_MAPPING_PRODUCER: &str = "t32perf-trace32-qualification/v1";
const TRACE32_TASK_EVENTS_MAPPING_STAGING_PATH: &str =
    "performance-run/trace32-task-events-mapping.json";
pub(crate) const C_WIRE_COUNTER_MAPPING_ARTIFACT_KIND: &str = "c_wire_counter_mapping";
pub(crate) const C_WIRE_COUNTER_MAPPING_PRODUCER: &str = "t32perf-c-wire-mapping/v1";
const C_WIRE_COUNTER_MAPPING_SOURCE_KIND: &str = "c_wire_counter_mapping_source";

/// Result of ensuring the immutable normalized observation artifact exists.
///
/// `resumed` proves the pre-existing marker was fully revalidated without a
/// rewrite.  Callers can distinguish that path from a fresh normalization
/// without inferring completion from artifact presence alone.
pub(crate) struct EnsureNormalizedResult {
    pub(crate) outcome: CommandOutcome,
    pub(crate) resumed: bool,
}

/// Immutable Controller-derived inputs for the performance-run normalize stage.
#[derive(Debug, Clone)]
pub(crate) struct PerformanceRunNormalizeInputs {
    pub(crate) config_artifact: Artifact,
    /// Single-source normalization still uses the legacy CLI input argument.
    /// Multi-source configuration owns every input artifact ID and therefore
    /// requires this to remain absent.
    pub(crate) cli_input_artifact_id: Option<String>,
}

/// Materializes the fixed normalization request selected by the accepted capture family.
pub(crate) fn ensure_performance_run_normalize_config(
    root: &ArtifactRoot,
    session_id: &str,
) -> Result<PerformanceRunNormalizeInputs, AppError> {
    let session = open_session(root, session_id)?;
    let lock = session.try_lock().map_err(AppError::from_session_store)?;
    let mut artifacts = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    let binding = accepted_trace32_runtime_binding(&session, &artifacts)?.ok_or_else(|| {
        AppError::operational(
            "performance-run normalization requires a healthy accepted TRACE32 runtime binding",
        )
    })?;
    let input_artifact = artifacts
        .iter()
        .find(|artifact| *artifact == &binding.export_artifact)
        .ok_or_else(|| {
            AppError::operational(
                "accepted TRACE32 export is absent from the immutable Session catalog",
            )
        })?
        .clone();
    session
        .verify_artifact(&input_artifact, true)
        .map_err(AppError::operational)?;

    let limits = json!({
        "max_line_bytes": MAX_CONFIG_LINE_BYTES,
        "max_records": MAX_CONFIG_RECORDS,
        "max_dictionary_entries": HARD_MAX_DICTIONARY_ENTRIES,
        "max_dictionary_bytes": HARD_MAX_DICTIONARY_BYTES,
    });
    let (source, mapping_artifact) = match &binding.target_adapter.capture_kind {
        TargetAdapterCaptureKind::Sampling { .. } => (
            json!({
                "adapter": "trace32_snooper_ascii_v1",
                "source_id": "performance-run-trace32-sampling",
                "expected_profile_id": TC234L_SNOOPER_ASCII_PROFILE_V1,
                "firmware_elf_artifact_id": binding.firmware_elf_artifact.id,
                "limits": limits,
            }),
            None,
        ),
        TargetAdapterCaptureKind::ProgramFlowTaskEvents {
            export_profile_id, ..
        } => {
            let mapping = ensure_performance_run_task_events_mapping(
                &session,
                &lock,
                &artifacts,
                &binding,
                export_profile_id,
            )?;
            (
                json!({
                    "adapter": "trace32_task_events_v1",
                    "source_id": "performance-run-trace32-program-flow",
                    "expected_profile_id": export_profile_id,
                    "firmware_elf_artifact_id": binding.firmware_elf_artifact.id,
                    "mapping_artifact_id": mapping.id,
                    "limits": limits,
                }),
                Some(mapping),
            )
        }
    };
    if let Some(mapping) = &mapping_artifact
        && !artifacts.iter().any(|artifact| artifact.id == mapping.id)
    {
        artifacts.push(mapping.clone());
    }
    let custom_event_artifact = match binding.target_adapter.controller_protocol {
        TargetAdapterControllerProtocol::V1 => {
            if binding.target_adapter.custom_event_collector.is_some()
                || binding.custom_event_artifact.is_some()
            {
                return Err(AppError::operational(
                    "V1 TRACE32 normalization cannot bind custom-event collector or output",
                ));
            }
            None
        }
        TargetAdapterControllerProtocol::V2CustomEventsExport => {
            let TargetAdapterCaptureKind::ProgramFlowTaskEvents {
                timestamp_clock_id, ..
            } = &binding.target_adapter.capture_kind
            else {
                return Err(AppError::operational(
                    "Controller V2 normalization requires a program-flow TASKEVENTS capture",
                ));
            };
            let collector = binding
                .target_adapter
                .custom_event_collector
                .as_ref()
                .ok_or_else(|| {
                    AppError::operational("Controller V2 binding omits custom-event collector")
                })?;
            if collector.clock.clock_id != *timestamp_clock_id
                || !binding
                    .capture_contract
                    .covered_cores
                    .contains(&collector.core_id)
            {
                return Err(AppError::operational(
                    "Controller V2 collector is outside the accepted TASKEVENTS core or clock contract",
                ));
            }
            let output = binding.custom_event_artifact.as_ref().ok_or_else(|| {
                AppError::operational("Controller V2 binding omits accepted custom-event output")
            })?;
            if output.id == binding.export_artifact.id
                || output.id == collector.mapping_artifact_id
                || output.id == collector.instrumentation_overhead_artifact_id
                || output.size_bytes > collector.max_output_bytes
            {
                return Err(AppError::operational(
                    "accepted custom-event output conflicts with its Controller V2 collector contract",
                ));
            }
            session
                .verify_artifact(output, true)
                .map_err(AppError::operational)?;
            Some((collector, output))
        }
    };
    let document = if let Some((collector, custom_output)) = custom_event_artifact {
        let max_payload_bytes = usize::try_from(collector.max_output_bytes).map_err(|_| {
            AppError::operational("custom-event collector output bound exceeds host usize")
        })?;
        json!({
            "schema": NORMALIZE_CONFIG_SCHEMA,
            "mode": MULTI_SOURCE_MODE,
            "sources": [
                {
                    "input_artifact_id": binding.export_artifact.id,
                    "clock_domain": collector.clock.clock_id,
                    "order": "reject_ambiguous_ties",
                    "source": source,
                },
                {
                    "input_artifact_id": custom_output.id,
                    "clock_domain": collector.clock.clock_id,
                    "order": "reject_ambiguous_ties",
                    "source": {
                        "adapter": "c_wire_v1",
                        "wire_version": C_WIRE_VERSION,
                        "source_id": collector.source_id,
                        "core_id": collector.core_id,
                        "clock": {
                            "domain_id": collector.clock.clock_id,
                            "frequency_hz": {"numerator": collector.clock.frequency_hz, "denominator": 1},
                            "wrap": {
                                "modulus": collector.clock.timestamp_modulus,
                                "max_forward_ticks": collector.clock.max_forward_ticks,
                            },
                        },
                        "origin": {
                            "mode": "explicit",
                            "ticks": collector.clock.origin_ticks,
                            "session_ns": collector.clock.origin_ns,
                        },
                        "counter_mapping_artifact_id": collector.mapping_artifact_id,
                        "limits": {"max_payload_bytes": max_payload_bytes, "max_records": MAX_CONFIG_RECORDS},
                    },
                }
            ],
            "output_limits": limits,
        })
    } else {
        json!({
            "schema": NORMALIZE_CONFIG_SCHEMA,
            "mode": SINGLE_SOURCE_MODE,
            "source": source,
            "output_limits": limits,
        })
    };
    let bytes = serde_json::to_vec(&document).map_err(AppError::operational)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CONFIG_BYTES {
        return Err(AppError::operational(
            "performance-run normalization config exceeds its fixed byte limit",
        ));
    }
    let config: NormalizeConfig = decode_config_json(&bytes)?;
    config.validate()?;

    let mut input_artifact_ids = vec![binding.export_artifact.id.clone()];
    if let Some(custom_output) = &binding.custom_event_artifact {
        extend_unique(&mut input_artifact_ids, [custom_output.id.clone()]);
    }
    extend_unique(
        &mut input_artifact_ids,
        [
            binding.firmware_elf_artifact.id.clone(),
            CAPTURE_CONFIG_ID.to_owned(),
            binding.capabilities_artifact.id.clone(),
            binding.stop_artifact.id.clone(),
            binding.health_artifact.id.clone(),
        ],
    );
    extend_unique(
        &mut input_artifact_ids,
        binding
            .qualification_provenance_artifacts
            .iter()
            .map(|artifact| artifact.id.clone()),
    );
    if let Some(mapping) = mapping_artifact {
        extend_unique(&mut input_artifact_ids, [mapping.id]);
    }
    if binding.custom_event_artifact.is_some() {
        let collector = binding
            .target_adapter
            .custom_event_collector
            .as_ref()
            .ok_or_else(|| {
                AppError::operational("custom-event output has no Controller V2 collector")
            })?;
        extend_unique(
            &mut input_artifact_ids,
            [
                collector.mapping_artifact_id.clone(),
                collector.instrumentation_overhead_artifact_id.clone(),
            ],
        );
    }
    for input in &input_artifact_ids {
        required_artifact(&artifacts, input)?;
    }
    let spec = ArtifactSpec {
        id: PERFORMANCE_RUN_NORMALIZE_CONFIG_ID.to_owned(),
        kind: NORMALIZE_CONFIG_KIND.to_owned(),
        relative_path: ArtifactPath::new(PERFORMANCE_RUN_NORMALIZE_CONFIG_PATH)
            .map_err(AppError::operational)?,
        media_type: "application/json".to_owned(),
        producer: PERFORMANCE_RUN_NORMALIZE_CONFIG_PRODUCER.to_owned(),
        input_artifact_ids,
    };
    let config_artifact = if let Some(existing) = artifacts
        .iter()
        .find(|artifact| artifact.id == PERFORMANCE_RUN_NORMALIZE_CONFIG_ID)
    {
        validate_performance_run_normalize_config(&session, existing, &spec, &bytes)?;
        existing.clone()
    } else {
        let staging = ArtifactPath::new(PERFORMANCE_RUN_NORMALIZE_CONFIG_STAGING_PATH)
            .map_err(AppError::operational)?;
        session
            .ensure_staged_exact(&lock, &staging, &bytes, MAX_CONFIG_BYTES)
            .map_err(AppError::operational)?;
        let artifact = session
            .ingest_staged_bounded(&lock, &staging, spec.clone(), MAX_CONFIG_BYTES)
            .map_err(AppError::operational)?;
        validate_performance_run_normalize_config(&session, &artifact, &spec, &bytes)?;
        artifact
    };
    Ok(PerformanceRunNormalizeInputs {
        config_artifact,
        cli_input_artifact_id: binding
            .custom_event_artifact
            .is_none()
            .then(|| input_artifact.id.clone()),
    })
}

/// Completes a qualified TASKEVENTS template with the accepted, immutable
/// controller binding.  The template is deployment input, while the mapping
/// is capture-specific and therefore cannot be registered before Stop/Health
/// evidence exists.
fn ensure_performance_run_task_events_mapping(
    session: &Session,
    lock: &SessionLock,
    artifacts: &[Artifact],
    binding: &AcceptedTrace32RuntimeBinding,
    expected_profile_id: &str,
) -> Result<Artifact, AppError> {
    let (
        TargetAdapterCaptureKind::ProgramFlowTaskEvents {
            export_profile_id,
            rtos_awareness,
            timestamp_clock_id,
            orti_artifact_id,
            task_marker_artifact_id,
        },
        TargetAdapterCaptureKind::ProgramFlowTaskEvents {
            export_profile_id: contract_export_profile_id,
            rtos_awareness: contract_rtos_awareness,
            timestamp_clock_id: contract_timestamp_clock_id,
            orti_artifact_id: contract_orti_artifact_id,
            task_marker_artifact_id: contract_marker_artifact_id,
        },
    ) = (
        &binding.target_adapter.capture_kind,
        &binding.capture_contract.capture_kind,
    )
    else {
        return Err(AppError::operational(
            "TASKEVENTS mapping materialization requires a program-flow capture binding",
        ));
    };
    if export_profile_id != expected_profile_id
        || export_profile_id != contract_export_profile_id
        || rtos_awareness != contract_rtos_awareness
        || timestamp_clock_id != contract_timestamp_clock_id
        || orti_artifact_id != contract_orti_artifact_id
        || task_marker_artifact_id != contract_marker_artifact_id
        || binding.capture_contract.covered_cores.len() != 1
    {
        return Err(AppError::operational(
            "accepted program-flow capture contract is not an exact single-core TASKEVENTS binding",
        ));
    }
    let template = required_artifact(artifacts, TASK_EVENTS_MAPPING_TEMPLATE_ARTIFACT_ID)?;
    if template.kind != "trace32_task_events_mapping_template"
        || template.media_type != "application/json"
        || template.producer != BUILD_RESOURCE_PRODUCER
    {
        return Err(AppError::operational(
            "TASKEVENTS mapping template has an invalid provisioning envelope",
        ));
    }
    session
        .verify_artifact(template, true)
        .map_err(AppError::operational)?;
    let template_bytes = read_bounded_artifact_bytes(
        session,
        template,
        MAX_TRACE32_TASK_EVENTS_TEMPLATE_BYTES,
        "TASKEVENTS mapping template",
    )?;
    let template_document = parse_trace32_task_events_mapping_template(&template_bytes)
        .map_err(AppError::operational)?;
    let core_id = binding.capture_contract.covered_cores[0];
    if template_document.profile_id != *export_profile_id || template_document.core_id != core_id {
        return Err(AppError::operational(
            "TASKEVENTS mapping template does not match the accepted profile and core",
        ));
    }
    let orti = required_artifact(artifacts, orti_artifact_id)?;
    let marker = required_artifact(artifacts, task_marker_artifact_id)?;
    session
        .verify_artifact(orti, true)
        .map_err(AppError::operational)?;
    session
        .verify_artifact(marker, true)
        .map_err(AppError::operational)?;
    let qualification = binding.qualification_artifact.as_ref().ok_or_else(|| {
        AppError::operational(
            "TASKEVENTS mapping materialization requires a durable target-adapter qualification artifact",
        )
    })?;
    required_artifact(artifacts, &qualification.id)?;
    session
        .verify_artifact(qualification, true)
        .map_err(AppError::operational)?;
    let (_, health) = program_flow_completion(binding)?;
    let runtime = TraceTaskEventsRuntimeBinding {
        profile_id: export_profile_id.clone(),
        profile_sha256: binding.target_adapter.profile_sha256.clone(),
        core_id,
        trace32: TraceTaskEventsTrace32Identity {
            release: binding.trace32_release.clone(),
            build: binding.trace32_build,
            architecture_package: binding.architecture_package.clone(),
        },
        target_identifier: binding.target_identifier.clone(),
        elf: artifact_binding(&binding.firmware_elf_artifact),
        metadata_artifacts: vec![
            TraceTaskMetadataBinding {
                role: TraceTaskMetadataRole::Orti,
                artifact: artifact_binding(orti),
            },
            TraceTaskMetadataBinding {
                role: TraceTaskMetadataRole::Markers,
                artifact: artifact_binding(marker),
            },
        ],
        controller_health: artifact_binding(&binding.health_artifact),
        stop_time_origin_evidence: artifact_binding(&binding.stop_artifact),
        qualification_receipt: artifact_binding(qualification),
    };
    // Materialization validates the complete typed runtime binding, including
    // the template profile/core and metadata-role closure.
    let mapping = materialize_trace32_task_events_mapping(&template_document, &runtime)
        .map_err(AppError::operational)?;
    if !health.capture_stopped {
        return Err(AppError::operational(
            "TASKEVENTS mapping materialization requires stopped controller health evidence",
        ));
    }
    let bytes = serde_json::to_vec(&mapping).map_err(AppError::operational)?;
    let mut input_artifact_ids = vec![
        binding.firmware_elf_artifact.id.clone(),
        CAPTURE_CONFIG_ID.to_owned(),
        binding.capabilities_artifact.id.clone(),
        binding.health_artifact.id.clone(),
        binding.stop_artifact.id.clone(),
        binding.export_artifact.id.clone(),
        orti.id.clone(),
        marker.id.clone(),
    ];
    extend_unique(
        &mut input_artifact_ids,
        binding
            .qualification_provenance_artifacts
            .iter()
            .map(|artifact| artifact.id.clone()),
    );
    extend_unique(
        &mut input_artifact_ids,
        [qualification.id.clone(), template.id.clone()],
    );
    let spec = ArtifactSpec {
        id: TRACE32_TASK_EVENTS_MAPPING_ARTIFACT_ID.to_owned(),
        kind: TRACE32_TASK_EVENTS_MAPPING_ARTIFACT_KIND.to_owned(),
        relative_path: ArtifactPath::new(TRACE32_TASK_EVENTS_MAPPING_ARTIFACT_PATH)
            .map_err(AppError::operational)?,
        media_type: "application/json".to_owned(),
        producer: TRACE32_TASK_EVENTS_MAPPING_PRODUCER.to_owned(),
        input_artifact_ids,
    };
    if let Some(existing) = artifacts
        .iter()
        .find(|artifact| artifact.id == TRACE32_TASK_EVENTS_MAPPING_ARTIFACT_ID)
    {
        validate_task_events_mapping_artifact(session, existing, &spec, &bytes)?;
        return Ok(existing.clone());
    }
    let staging = ArtifactPath::new(TRACE32_TASK_EVENTS_MAPPING_STAGING_PATH)
        .map_err(AppError::operational)?;
    session
        .ensure_staged_exact(lock, &staging, &bytes, MAX_TRACE32_MAPPING_BYTES)
        .map_err(AppError::operational)?;
    let artifact = session
        .ingest_staged_bounded(lock, &staging, spec.clone(), MAX_TRACE32_MAPPING_BYTES)
        .map_err(AppError::operational)?;
    validate_task_events_mapping_artifact(session, &artifact, &spec, &bytes)?;
    Ok(artifact)
}

fn validate_task_events_mapping_artifact(
    session: &Session,
    artifact: &Artifact,
    spec: &ArtifactSpec,
    expected: &[u8],
) -> Result<(), AppError> {
    if artifact.id != spec.id
        || artifact.kind != spec.kind
        || artifact.relative_path != spec.relative_path
        || artifact.media_type != spec.media_type
        || artifact.producer != spec.producer
        || artifact.input_artifact_ids != spec.input_artifact_ids
    {
        return Err(AppError::operational(
            "existing TASKEVENTS mapping has conflicting identity or provenance",
        ));
    }
    session
        .verify_artifact(artifact, true)
        .map_err(AppError::operational)?;
    let actual = read_bounded_artifact_bytes(
        session,
        artifact,
        MAX_TRACE32_MAPPING_BYTES,
        "TASKEVENTS mapping",
    )?;
    let parsed = parse_trace32_task_events_mapping(&actual).map_err(AppError::operational)?;
    if actual != expected || parsed.validate().is_err() {
        return Err(AppError::operational(
            "existing TASKEVENTS mapping bytes conflict with the accepted runtime binding",
        ));
    }
    Ok(())
}

fn validate_performance_run_normalize_config(
    session: &Session,
    artifact: &Artifact,
    spec: &ArtifactSpec,
    expected: &[u8],
) -> Result<(), AppError> {
    if artifact.id != spec.id
        || artifact.kind != spec.kind
        || artifact.relative_path != spec.relative_path
        || artifact.media_type != spec.media_type
        || artifact.producer != spec.producer
        || artifact.input_artifact_ids != spec.input_artifact_ids
    {
        return Err(AppError::operational(
            "existing performance-run normalization config has conflicting identity or provenance",
        ));
    }
    session
        .verify_artifact(artifact, true)
        .map_err(AppError::operational)?;
    let actual = read_bounded_artifact_bytes(
        session,
        artifact,
        MAX_CONFIG_BYTES,
        "performance-run normalization config",
    )?;
    if actual != expected {
        return Err(AppError::operational(
            "existing performance-run normalization config bytes conflict with the accepted TRACE32 binding",
        ));
    }
    Ok(())
}

pub fn normalize(
    root: &ArtifactRoot,
    session_id: &str,
    input_artifact_id: Option<&str>,
    config_artifact_id: &str,
) -> Result<CommandOutcome, AppError> {
    let outcome = ensure_normalized(root, session_id, input_artifact_id, config_artifact_id)
        .map(|result| result.outcome);
    if let Err(error) = &outcome {
        if error.is_nonterminal_retryable() {
            return outcome;
        }
        let session = open_session(root, session_id)?;
        let lock = session.try_lock().map_err(AppError::from_session_store)?;
        if session.read_state().map_err(AppError::operational)?.status == SessionStatus::Captured
            && let Err(persistence_error) = mark_failed(&session, &lock, error)
        {
            return Err(persistence_error);
        }
    }
    outcome
}

/// Ensures normalization without applying the CLI's terminal-failure policy.
///
/// This is the recovery-safe entry point for in-process performance flows.
pub(crate) fn ensure_normalized(
    root: &ArtifactRoot,
    session_id: &str,
    input_artifact_id: Option<&str>,
    config_artifact_id: &str,
) -> Result<EnsureNormalizedResult, AppError> {
    let session = open_session(root, session_id)?;
    let lock = session.try_lock().map_err(AppError::from_session_store)?;
    let state = session.read_state().map_err(AppError::operational)?;
    if state.status == SessionStatus::Failed {
        return Err(AppError::operational(format!(
            "failed session `{session_id}` cannot normalize or resume normalized observations"
        )));
    }
    crate::controller::ensure_controller_session_releasable(root, &session)?;
    if state.status != SessionStatus::Captured {
        return Err(AppError::operational(format!(
            "session `{session_id}` must be captured before normalization; current status is {:?}",
            state.status
        )));
    }

    let artifacts = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    let config_artifact = required_artifact(&artifacts, config_artifact_id)?.clone();
    let capture_config =
        registered_capture_config(&session, &artifacts).map_err(AppError::operational)?;
    let config = read_config(&session, &config_artifact)?;
    let inputs =
        resolve_normalization_inputs(&artifacts, &config, input_artifact_id, config_artifact_id)?;
    let expected_mapping_ids = expected_precommitted_mapping_ids(&config, &artifacts)?;
    let observations = artifacts
        .iter()
        .find(|artifact| artifact.id == "observations");
    if let Some(observations) = observations {
        let outcome = validate_existing_normalized_observations(
            &session,
            &lock,
            &artifacts,
            ExistingNormalizedVerification {
                capture_config: &capture_config.document,
                inputs,
                config_artifact,
                config,
                observations,
                expected_mapping_ids: &expected_mapping_ids,
            },
        )?;
        return Ok(EnsureNormalizedResult {
            outcome,
            resumed: true,
        });
    }
    reject_unexpected_incomplete_normalizer_artifacts(&artifacts, &expected_mapping_ids)?;
    let outcome = normalize_captured(
        &session,
        &lock,
        &artifacts,
        &capture_config,
        inputs,
        config_artifact,
        config,
    )?;
    Ok(EnsureNormalizedResult {
        outcome,
        resumed: false,
    })
}

fn resolve_normalization_inputs(
    artifacts: &[Artifact],
    config: &NormalizeConfig,
    input_artifact_id: Option<&str>,
    config_artifact_id: &str,
) -> Result<Vec<Artifact>, AppError> {
    let input_ids = config.input_artifact_ids(input_artifact_id)?;
    let mut unique_input_ids = BTreeSet::new();
    let mut inputs = Vec::with_capacity(input_ids.len());
    for input_id in input_ids {
        if input_id == config_artifact_id || input_id == CAPTURE_CONFIG_ID {
            return Err(AppError::operational(
                "normalization inputs must be distinct from configuration artifacts",
            ));
        }
        if !unique_input_ids.insert(input_id.clone()) {
            return Err(AppError::operational(format!(
                "normalization input artifact `{input_id}` is referenced more than once"
            )));
        }
        inputs.push(required_artifact(artifacts, &input_id)?.clone());
    }
    Ok(inputs)
}

fn expected_precommitted_mapping_ids(
    config: &NormalizeConfig,
    artifacts: &[Artifact],
) -> Result<BTreeSet<String>, AppError> {
    let mut expected = BTreeSet::new();
    for source in config.sources() {
        match source {
            NormalizeSourceConfig::CWireV1 {
                counter_mapping_artifact_id: Some(source_id),
                ..
            } => {
                let source = required_artifact(artifacts, source_id)?;
                expected.insert(format!("c-wire-counter-map-{}", source.sha256));
            }
            NormalizeSourceConfig::Trace32SnooperAsciiV1 { .. } => {
                expected.insert(TRACE32_SYMBOL_MAPPING_ARTIFACT_ID.to_owned());
            }
            NormalizeSourceConfig::CanonicalNdjsonV1 { .. }
            | NormalizeSourceConfig::ExplicitCsvV1 { .. }
            | NormalizeSourceConfig::CWireV1 {
                counter_mapping_artifact_id: None,
                ..
            }
            | NormalizeSourceConfig::Trace32TaskEventsV1 { .. } => {}
        }
    }
    Ok(expected)
}

fn reject_unexpected_incomplete_normalizer_artifacts(
    artifacts: &[Artifact],
    expected_mapping_ids: &BTreeSet<String>,
) -> Result<(), AppError> {
    for artifact in artifacts {
        let normalizer_owned = artifact.producer == NORMALIZE_PRODUCER
            || artifact.producer == C_WIRE_COUNTER_MAPPING_PRODUCER
            || artifact.kind == TRACE32_SYMBOL_MAPPING_ARTIFACT_KIND
            || artifact.kind == C_WIRE_COUNTER_MAPPING_ARTIFACT_KIND
            || artifact.id == TRACE32_SYMBOL_MAPPING_ARTIFACT_ID
            || artifact.id.starts_with("c-wire-counter-map-")
            || artifact
                .relative_path
                .as_str()
                .starts_with("normalized/c-wire-counter-maps/");
        if normalizer_owned
            && artifact.id != "observations"
            && !expected_mapping_ids.contains(&artifact.id)
        {
            return Err(AppError::operational(format!(
                "incomplete normalization has unexpected normalizer-owned artifact `{}`",
                artifact.id
            )));
        }
    }
    Ok(())
}

struct ExistingNormalizedVerification<'a> {
    capture_config: &'a CaptureConfigDocument,
    inputs: Vec<Artifact>,
    config_artifact: Artifact,
    config: NormalizeConfig,
    observations: &'a Artifact,
    expected_mapping_ids: &'a BTreeSet<String>,
}

fn validate_existing_normalized_observations(
    session: &Session,
    lock: &SessionLock,
    artifacts: &[Artifact],
    verification: ExistingNormalizedVerification<'_>,
) -> Result<CommandOutcome, AppError> {
    let ExistingNormalizedVerification {
        capture_config,
        inputs,
        config_artifact,
        config,
        observations,
        expected_mapping_ids,
    } = verification;
    if observations.kind != "observations"
        || observations.relative_path.as_str() != "normalized/observations.ndjson"
        || observations.media_type != "application/x-ndjson"
        || observations.producer != NORMALIZE_PRODUCER
    {
        return Err(AppError::operational(
            "existing observations artifact has an invalid normalizer-owned envelope",
        ));
    }
    reject_unexpected_incomplete_normalizer_artifacts(artifacts, expected_mapping_ids)?;
    for mapping_id in expected_mapping_ids {
        if !artifacts.iter().any(|artifact| &artifact.id == mapping_id) {
            return Err(AppError::operational(format!(
                "completed observations require missing normalizer mapping artifact `{mapping_id}`"
            )));
        }
    }

    let output_limits: LineLimits = config.output_limits().try_into()?;
    let opened =
        open_configured_sources(session, lock, artifacts, capture_config, &inputs, config)?;
    let input_ids = inputs
        .iter()
        .map(|artifact| artifact.id.clone())
        .collect::<Vec<_>>();
    let mut expected_provenance = input_ids.clone();
    expected_provenance.push(config_artifact.id.clone());
    expected_provenance.push(CAPTURE_CONFIG_ID.to_owned());
    extend_unique(
        &mut expected_provenance,
        opened.provenance_artifact_ids.iter().cloned(),
    );
    if observations.input_artifact_ids != expected_provenance {
        return Err(AppError::operational(
            "existing observations artifact provenance does not match the normalization request",
        ));
    }

    let file = session
        .open_artifact(observations)
        .map_err(AppError::operational)?;
    let mut reader = NdjsonObservationReader::new(BufReader::new(file), output_limits)
        .map_err(AppError::operational)?;
    let header = reader.header();
    if header.session_id != session.id().as_str() {
        return Err(AppError::operational(
            "existing observations header session does not match its owning session",
        ));
    }
    require_header_property(
        header,
        "normalization_schema",
        &json!(NORMALIZE_CONFIG_SCHEMA),
    )?;
    require_header_property(header, "adapter", &json!(&opened.adapter_id))?;
    require_header_property(header, "input_artifact_ids", &json!(&input_ids))?;
    if input_ids.len() == 1 {
        require_header_property(header, "input_artifact_id", &json!(&input_ids[0]))?;
    } else if header.properties.contains_key("input_artifact_id") {
        return Err(AppError::operational(
            "existing multi-source observations header unexpectedly claims one input artifact",
        ));
    }
    require_header_property(header, "config_artifact_id", &json!(&config_artifact.id))?;
    for (key, value) in &opened.inherited_properties {
        require_header_property(header, key, value)?;
    }
    if reader.dictionary() != &opened.dictionary {
        return Err(AppError::operational(
            "existing observations dictionary does not match the capture-bound normalization mapping",
        ));
    }

    let mut observation_count = 0_u64;
    for observation in &mut reader {
        observation.map_err(AppError::operational)?;
        observation_count = observation_count.checked_add(1).ok_or_else(|| {
            AppError::operational("normalized observation count exceeds the supported u64 range")
        })?;
    }
    // The reader reached EOF successfully, so the artifact is a complete
    // marker rather than a merely committed prefix.
    Ok(CommandOutcome {
        command: "normalize",
        result: json!({
            "session_id": session.id().as_str(),
            "adapter": opened.adapter_id,
            "mode": opened.mode,
            "observation_count": observation_count,
            "artifact": observations,
            "input_artifact_ids": input_ids,
            "config_artifact_id": config_artifact.id,
        }),
        exit_code: EXIT_SUCCESS,
    })
}

fn require_header_property(
    header: &ObservationStreamHeader,
    key: &str,
    expected: &Value,
) -> Result<(), AppError> {
    match header.properties.get(key) {
        Some(actual) if actual == expected => Ok(()),
        Some(_) => Err(AppError::operational(format!(
            "existing observations header claim `{key}` conflicts with the normalization request"
        ))),
        None => Err(AppError::operational(format!(
            "existing observations header omits required claim `{key}`"
        ))),
    }
}

fn normalize_captured(
    session: &Session,
    lock: &SessionLock,
    artifacts: &[Artifact],
    capture_config: &RegisteredCaptureConfig<'_>,
    inputs: Vec<Artifact>,
    config_artifact: Artifact,
    config: NormalizeConfig,
) -> Result<CommandOutcome, AppError> {
    let output_limits = config.output_limits().try_into()?;
    let mut opened = open_configured_sources(
        session,
        lock,
        artifacts,
        &capture_config.document,
        &inputs,
        config,
    )?;
    let input_ids = inputs
        .iter()
        .map(|artifact| artifact.id.clone())
        .collect::<Vec<_>>();
    let mut provenance = input_ids.clone();
    provenance.push(config_artifact.id.clone());
    provenance.push(CAPTURE_CONFIG_ID.to_owned());
    extend_unique(
        &mut provenance,
        opened.provenance_artifact_ids.iter().cloned(),
    );

    let artifact_writer = session
        .create_artifact(
            lock,
            ArtifactSpec {
                id: "observations".to_owned(),
                kind: "observations".to_owned(),
                relative_path: ArtifactPath::new("normalized/observations.ndjson")
                    .map_err(AppError::operational)?,
                media_type: "application/x-ndjson".to_owned(),
                producer: NORMALIZE_PRODUCER.to_owned(),
                input_artifact_ids: provenance,
            },
        )
        .map_err(AppError::operational)?;
    let mut header = ObservationStreamHeader::ndjson(session.id().as_str());
    header.properties = opened.inherited_properties;
    header.properties.insert(
        "normalization_schema".to_owned(),
        json!(NORMALIZE_CONFIG_SCHEMA),
    );
    header
        .properties
        .insert("adapter".to_owned(), json!(opened.adapter_id));
    header
        .properties
        .insert("input_artifact_ids".to_owned(), json!(input_ids));
    if input_ids.len() == 1 {
        header
            .properties
            .insert("input_artifact_id".to_owned(), json!(input_ids[0]));
    }
    header
        .properties
        .insert("config_artifact_id".to_owned(), json!(config_artifact.id));
    let mut writer = t32perf_trace32::NdjsonObservationWriter::new(
        artifact_writer,
        &header,
        &opened.dictionary,
        output_limits,
    )
    .map_err(AppError::operational)?;

    let mut observation_count = 0_u64;
    while let Some(record) = opened
        .source
        .next_observation()
        .map_err(AppError::operational)?
    {
        writer
            .write_observation(&record.observation)
            .map_err(AppError::operational)?;
        observation_count = observation_count.checked_add(1).ok_or_else(|| {
            AppError::operational("normalized observation count exceeds the supported u64 range")
        })?;
    }
    let artifact_writer = writer.finish().map_err(AppError::operational)?;
    let observations = session
        .commit_artifact(lock, artifact_writer)
        .map_err(AppError::operational)?;

    Ok(CommandOutcome {
        command: "normalize",
        result: json!({
            "session_id": session.id().as_str(),
            "adapter": opened.adapter_id,
            "mode": opened.mode,
            "observation_count": observation_count,
            "artifact": observations,
            "input_artifact_ids": input_ids,
            "config_artifact_id": config_artifact.id,
        }),
        exit_code: EXIT_SUCCESS,
    })
}

fn open_configured_sources(
    session: &Session,
    lock: &SessionLock,
    artifacts: &[Artifact],
    capture_config: &CaptureConfigDocument,
    inputs: &[Artifact],
    config: NormalizeConfig,
) -> Result<OpenedNormalization, AppError> {
    match config {
        NormalizeConfig::SingleSource { source, .. } => {
            let input = inputs.first().ok_or_else(|| {
                AppError::operational("single-source normalization has no input artifact")
            })?;
            let opened = open_source(session, lock, artifacts, capture_config, input, source)?;
            let dictionary = opened
                .source
                .dictionary()
                .cloned()
                .unwrap_or_else(|| ObservationDictionary::new(session.id().as_str()));
            Ok(OpenedNormalization {
                source: opened.source,
                dictionary,
                inherited_properties: opened.inherited_properties,
                provenance_artifact_ids: opened.provenance_artifact_ids,
                adapter_id: opened.adapter_id,
                mode: SINGLE_SOURCE_MODE,
            })
        }
        NormalizeConfig::MultiSource { sources, .. } => {
            if sources.len() != inputs.len() {
                return Err(AppError::operational(
                    "multi-source configuration and resolved input counts differ",
                ));
            }
            let mut opened_sources = Vec::with_capacity(sources.len());
            let mut dictionaries = Vec::with_capacity(sources.len());
            let mut source_ids = BTreeSet::new();
            let mut source_properties = serde_json::Map::new();
            let mut source_contracts = Vec::with_capacity(sources.len());
            let mut provenance_artifact_ids = Vec::new();
            for (configured, input) in sources.into_iter().zip(inputs) {
                let source_id = configured.source.source_id().to_owned();
                if !source_ids.insert(source_id.clone()) {
                    return Err(AppError::operational(format!(
                        "multi-source identifier `{source_id}` is declared more than once"
                    )));
                }
                let opened = open_source(
                    session,
                    lock,
                    artifacts,
                    capture_config,
                    input,
                    configured.source,
                )?;
                if opened.source.descriptor().clock_domain != configured.clock_domain {
                    return Err(AppError::operational(format!(
                        "source `{source_id}` normalized clock domain `{}` does not match declared `{}`",
                        opened.source.descriptor().clock_domain,
                        configured.clock_domain
                    )));
                }
                if let Some(dictionary) = opened.source.dictionary() {
                    dictionaries.push(dictionary.clone());
                }
                source_properties.insert(
                    source_id.clone(),
                    Value::Object(opened.inherited_properties.into_iter().collect()),
                );
                source_contracts.push(json!({
                    "source_id": source_id,
                    "input_artifact_id": input.id,
                    "adapter": opened.adapter_id,
                    "clock_domain": configured.clock_domain,
                    "order": configured.order,
                }));
                extend_unique(
                    &mut provenance_artifact_ids,
                    opened.provenance_artifact_ids.iter().cloned(),
                );
                opened_sources.push(opened.source);
            }
            let dictionary = merge_dictionaries(session.id().as_str(), dictionaries)?;
            let source = KWayMerge::new(opened_sources).map_err(AppError::operational)?;
            let mut inherited_properties = Properties::new();
            inherited_properties.insert(
                "normalization_sources".to_owned(),
                Value::Array(source_contracts),
            );
            inherited_properties.insert(
                "source_properties".to_owned(),
                Value::Object(source_properties),
            );
            Ok(OpenedNormalization {
                source: Box::new(source),
                dictionary,
                inherited_properties,
                provenance_artifact_ids,
                adapter_id: "multi_source_v1".to_owned(),
                mode: MULTI_SOURCE_MODE,
            })
        }
    }
}

fn open_source(
    session: &Session,
    lock: &SessionLock,
    artifacts: &[Artifact],
    capture_config: &CaptureConfigDocument,
    input: &Artifact,
    source: NormalizeSourceConfig,
) -> Result<OpenedSource, AppError> {
    if source.source_id().trim().is_empty() {
        return Err(AppError::operational(
            "normalization source identifier must be nonempty",
        ));
    }
    let file = session
        .open_artifact(input)
        .map_err(AppError::operational)?;
    match source {
        NormalizeSourceConfig::CanonicalNdjsonV1 { source_id, limits } => {
            let source =
                CanonicalNdjsonSource::new(BufReader::new(file), source_id, limits.try_into()?)
                    .map_err(AppError::operational)?;
            if source.header().session_id != session.id().as_str() {
                return Err(AppError::operational(format!(
                    "canonical input session `{}` does not match owning session `{}`",
                    source.header().session_id,
                    session.id()
                )));
            }
            Ok(OpenedSource {
                inherited_properties: source.header().properties.clone(),
                source: Box::new(source),
                provenance_artifact_ids: Vec::new(),
                adapter_id: "canonical_ndjson_v1".to_owned(),
            })
        }
        NormalizeSourceConfig::ExplicitCsvV1 {
            source_id,
            columns,
            ignored_columns,
            clock,
            origin,
            quality,
            limits,
        } => {
            let columns = csv_columns(columns, ignored_columns)?;
            let (origin_ticks, origin_ns) = origin.parts();
            let config = CsvAdapterConfig {
                columns,
                clock: clock.try_into()?,
                origin_ticks,
                origin_ns,
                quality,
                limits: limits.try_into()?,
            };
            let source = ExplicitCsvSource::new(BufReader::new(file), source_id, config)
                .map_err(AppError::operational)?;
            Ok(OpenedSource {
                source: Box::new(source),
                inherited_properties: Properties::new(),
                provenance_artifact_ids: Vec::new(),
                adapter_id: "explicit_csv_v1".to_owned(),
            })
        }
        NormalizeSourceConfig::CWireV1 {
            wire_version,
            source_id,
            core_id,
            clock,
            origin,
            counter_mapping_artifact_id,
            limits,
        } => {
            if wire_version != C_WIRE_VERSION {
                return Err(AppError::unsupported(
                    "normalize.c_wire.version",
                    format!(
                        "C wire configuration version `{wire_version}` is unsupported; expected `{C_WIRE_VERSION}`"
                    ),
                ));
            }
            let (origin_ticks, origin_ns) = origin.parts();
            let config = CWireSourceConfig {
                source_id,
                core_id,
                clock: clock.try_into()?,
                origin_ticks,
                origin_ns,
                limits: limits.try_into()?,
            };
            open_c_wire_source(
                CWireOpenContext {
                    session,
                    lock,
                    artifacts,
                    capture_config,
                    input,
                    file,
                },
                config,
                counter_mapping_artifact_id,
            )
        }
        NormalizeSourceConfig::Trace32SnooperAsciiV1 {
            source_id,
            expected_profile_id,
            firmware_elf_artifact_id,
            limits,
        } => open_trace32_ascii_source(
            Trace32OpenContext {
                session,
                lock,
                artifacts,
                capture_config,
                input,
                file,
            },
            Trace32AsciiSourceRequest {
                source_id,
                expected_profile_id,
                firmware_elf_artifact_id,
                limits: limits.try_into()?,
            },
        ),
        NormalizeSourceConfig::Trace32TaskEventsV1 {
            source_id,
            expected_profile_id,
            firmware_elf_artifact_id,
            mapping_artifact_id,
            limits,
        } => open_trace32_task_events_source(
            Trace32OpenContext {
                session,
                lock,
                artifacts,
                capture_config,
                input,
                file,
            },
            Trace32TaskEventsSourceRequest {
                source_id,
                expected_profile_id,
                firmware_elf_artifact_id,
                mapping_artifact_id,
                limits: limits.try_into()?,
            },
        ),
    }
}

struct CWireOpenContext<'a> {
    session: &'a Session,
    lock: &'a SessionLock,
    artifacts: &'a [Artifact],
    capture_config: &'a CaptureConfigDocument,
    input: &'a Artifact,
    file: std::fs::File,
}

fn open_c_wire_source(
    context: CWireOpenContext<'_>,
    config: CWireSourceConfig,
    counter_mapping_artifact_id: Option<String>,
) -> Result<OpenedSource, AppError> {
    validate_v2_c_wire_input(&context, &config, counter_mapping_artifact_id.as_deref())?;
    let declared_mapping = context
        .capture_config
        .adapter_parameters
        .get("c_wire.counter_mapping_artifact_id");
    let declared_digest = context
        .capture_config
        .adapter_parameters
        .get("c_wire.counter_mapping_sha256");
    let Some(mapping_artifact_id) = counter_mapping_artifact_id else {
        if declared_mapping.is_some() || declared_digest.is_some() {
            return Err(AppError::operational(
                "authoritative capture config declares a C wire counter mapping but normalize config omits its artifact ID",
            ));
        }
        let source =
            CWireObservationSource::new(context.file, config).map_err(AppError::operational)?;
        return Ok(OpenedSource {
            source: Box::new(source),
            inherited_properties: Properties::from([(
                "c_wire_counter_semantics".to_owned(),
                json!("generic_counter_ids_only"),
            )]),
            provenance_artifact_ids: Vec::new(),
            adapter_id: "c_wire_v1".to_owned(),
        });
    };
    let instrumentation = context
        .capture_config
        .instrumentation
        .as_ref()
        .ok_or_else(|| {
            AppError::operational(
                "C wire counter mapping requires authoritative instrumentation configuration",
            )
        })?;
    if instrumentation.method != "t32perf-c-wire/v1" {
        return Err(AppError::operational(format!(
            "C wire counter mapping requires instrumentation method `t32perf-c-wire/v1`; observed `{}`",
            instrumentation.method
        )));
    }
    require_capture_parameter(
        context.capture_config,
        "c_wire.counter_mapping_artifact_id",
        &mapping_artifact_id,
    )?;
    let mapping_source_artifact = required_artifact(context.artifacts, &mapping_artifact_id)?;
    require_capture_parameter(
        context.capture_config,
        "c_wire.counter_mapping_sha256",
        mapping_source_artifact.sha256.as_str(),
    )?;
    if mapping_source_artifact.kind != C_WIRE_COUNTER_MAPPING_SOURCE_KIND
        || mapping_source_artifact.media_type != "application/json"
    {
        return Err(AppError::operational(
            "C wire counter mapping source artifact has invalid kind or media type",
        ));
    }
    let bytes = read_bounded_artifact_bytes(
        context.session,
        mapping_source_artifact,
        u64::try_from(MAX_C_WIRE_COUNTER_MAPPING_DOCUMENT_BYTES).unwrap_or(u64::MAX),
        "C wire counter mapping",
    )?;
    let mapping = parse_c_wire_counter_mapping(&bytes).map_err(AppError::operational)?;
    let mapping_artifact = ensure_c_wire_counter_mapping_artifact(
        context.session,
        context.lock,
        mapping_source_artifact,
        &mapping,
    )?;
    let source = CWireObservationSource::new_with_counter_mapping(
        context.file,
        config,
        context.session.id().as_str(),
        mapping,
    )
    .map_err(AppError::operational)?;
    Ok(OpenedSource {
        source: Box::new(source),
        inherited_properties: Properties::from([
            (
                "c_wire_counter_semantics".to_owned(),
                json!("deployment_mapping"),
            ),
            (
                "c_wire_counter_mapping_artifact_id".to_owned(),
                json!(mapping_artifact.id),
            ),
            (
                "c_wire_counter_mapping_sha256".to_owned(),
                json!(mapping_artifact.sha256),
            ),
            (
                "c_wire_counter_mapping_source_artifact_id".to_owned(),
                json!(mapping_source_artifact.id),
            ),
            (
                "c_wire_counter_mapping_source_sha256".to_owned(),
                json!(mapping_source_artifact.sha256),
            ),
        ]),
        provenance_artifact_ids: vec![
            mapping_source_artifact.id.clone(),
            mapping_artifact.id.clone(),
        ],
        adapter_id: "c_wire_v1".to_owned(),
    })
}

/// Ensures a Controller V2 custom-event wire source is exactly the accepted
/// output and collector contract. Generic C-wire normalization remains usable
/// when no accepted TRACE32 runtime exists.
fn validate_v2_c_wire_input(
    context: &CWireOpenContext<'_>,
    config: &CWireSourceConfig,
    counter_mapping_artifact_id: Option<&str>,
) -> Result<(), AppError> {
    let Some(binding) = accepted_trace32_runtime_binding(context.session, context.artifacts)?
    else {
        return Ok(());
    };
    if binding.target_adapter.controller_protocol
        != TargetAdapterControllerProtocol::V2CustomEventsExport
    {
        return Ok(());
    }
    let collector = binding
        .target_adapter
        .custom_event_collector
        .as_ref()
        .ok_or_else(|| {
            AppError::operational("accepted Controller V2 binding omits custom-event collector")
        })?;
    let output = binding.custom_event_artifact.as_ref().ok_or_else(|| {
        AppError::operational("accepted Controller V2 binding omits custom-event output")
    })?;
    if context.input != output {
        return Err(AppError::operational(
            "C-wire normalization input is not the accepted Controller V2 custom-event output",
        ));
    }
    if context.input.size_bytes > collector.max_output_bytes {
        return Err(AppError::operational(
            "accepted custom-event output exceeds the Controller V2 collector bound",
        ));
    }
    validate_c_wire_config_against_collector(config, collector, counter_mapping_artifact_id)?;
    let capture_config = context.capture_config;
    let instrumentation = capture_config.instrumentation.as_ref().ok_or_else(|| {
        AppError::operational(
            "Controller V2 C-wire normalization requires instrumentation evidence",
        )
    })?;
    if instrumentation.method != "t32perf-c-wire/v1"
        || instrumentation.transport != collector.transport
        || instrumentation.overhead.evidence_artifact_id
            != collector.instrumentation_overhead_artifact_id
    {
        return Err(AppError::operational(
            "authoritative capture config instrumentation does not match the Controller V2 collector",
        ));
    }
    require_capture_parameter(
        capture_config,
        "result.custom_events.artifact_id",
        &output.id,
    )?;
    require_capture_parameter(
        capture_config,
        "result.custom_events.sha256",
        output.sha256.as_str(),
    )?;
    let overhead = required_artifact(
        context.artifacts,
        &collector.instrumentation_overhead_artifact_id,
    )?;
    require_capture_parameter(
        capture_config,
        "custom_events.instrumentation_overhead_sha256",
        overhead.sha256.as_str(),
    )?;
    require_capture_parameter(
        capture_config,
        "custom_events.source_id",
        &collector.source_id,
    )?;
    require_capture_parameter_value(
        capture_config,
        "custom_events.core_id",
        json!(collector.core_id),
    )?;
    require_capture_parameter(capture_config, "custom_events.wire_protocol", "c_wire_v1")?;
    require_capture_parameter(
        capture_config,
        "custom_events.clock_id",
        &collector.clock.clock_id,
    )?;
    require_capture_parameter_value(
        capture_config,
        "custom_events.clock_frequency_hz",
        json!(collector.clock.frequency_hz),
    )?;
    require_capture_parameter_value(
        capture_config,
        "custom_events.timestamp_modulus",
        json!(collector.clock.timestamp_modulus),
    )?;
    require_capture_parameter_value(
        capture_config,
        "custom_events.max_forward_ticks",
        json!(collector.clock.max_forward_ticks),
    )?;
    require_capture_parameter_value(
        capture_config,
        "custom_events.origin_ticks",
        json!(collector.clock.origin_ticks),
    )?;
    require_capture_parameter_value(
        capture_config,
        "custom_events.origin_ns",
        json!(collector.clock.origin_ns),
    )?;
    require_capture_parameter(
        capture_config,
        "custom_events.transport",
        &collector.transport,
    )?;
    require_capture_parameter(
        capture_config,
        "custom_events.merge_order",
        "reject_ambiguous_ties",
    )?;
    Ok(())
}

fn validate_c_wire_config_against_collector(
    config: &CWireSourceConfig,
    collector: &t32perf_trace32::TargetAdapterCustomEventCollectorContract,
    counter_mapping_artifact_id: Option<&str>,
) -> Result<(), AppError> {
    if config.source_id != collector.source_id
        || config.core_id != collector.core_id
        || config.clock.id != collector.clock.clock_id
        || config.clock.scale
            != RationalTickScale::from_hz(collector.clock.frequency_hz)
                .map_err(AppError::operational)?
        || config.clock.timestamp_modulus != Some(collector.clock.timestamp_modulus)
        || config.clock.max_forward_ticks != Some(collector.clock.max_forward_ticks)
        || config.origin_ticks != Some(collector.clock.origin_ticks)
        || config.origin_ns != collector.clock.origin_ns
        || counter_mapping_artifact_id != Some(collector.mapping_artifact_id.as_str())
    {
        return Err(AppError::operational(
            "C-wire normalization config does not match the accepted Controller V2 collector",
        ));
    }
    Ok(())
}

fn ensure_c_wire_counter_mapping_artifact(
    session: &Session,
    lock: &SessionLock,
    source: &Artifact,
    mapping: &t32perf_trace32::CWireCounterMappingDocument,
) -> Result<Artifact, AppError> {
    let digest = source.sha256.as_str();
    let artifact_id = format!("c-wire-counter-map-{digest}");
    let artifact_path = format!("normalized/c-wire-counter-maps/{digest}.json");
    let input_artifact_ids = vec![source.id.clone(), CAPTURE_CONFIG_ID.to_owned()];
    let current_artifacts = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    if let Some(existing) = current_artifacts
        .iter()
        .find(|artifact| artifact.id == artifact_id)
    {
        if existing.kind != C_WIRE_COUNTER_MAPPING_ARTIFACT_KIND
            || existing.relative_path.as_str() != artifact_path
            || existing.media_type != "application/json"
            || existing.producer != C_WIRE_COUNTER_MAPPING_PRODUCER
            || existing.input_artifact_ids != input_artifact_ids
        {
            return Err(AppError::operational(
                "existing C wire counter mapping artifact has invalid identity or provenance",
            ));
        }
        let bytes = read_bounded_artifact_bytes(
            session,
            existing,
            u64::try_from(MAX_C_WIRE_COUNTER_MAPPING_DOCUMENT_BYTES).unwrap_or(u64::MAX),
            "host-owned C wire counter mapping",
        )?;
        let existing_mapping =
            parse_c_wire_counter_mapping(&bytes).map_err(AppError::operational)?;
        if &existing_mapping != mapping {
            return Err(AppError::operational(
                "existing C wire counter mapping does not match its capture-bound source",
            ));
        }
        return Ok(existing.clone());
    }
    session
        .write_json_artifact(
            lock,
            ArtifactSpec {
                id: artifact_id,
                kind: C_WIRE_COUNTER_MAPPING_ARTIFACT_KIND.to_owned(),
                relative_path: ArtifactPath::new(artifact_path).map_err(AppError::operational)?,
                media_type: "application/json".to_owned(),
                producer: C_WIRE_COUNTER_MAPPING_PRODUCER.to_owned(),
                input_artifact_ids,
            },
            mapping,
        )
        .map_err(AppError::operational)
}

struct Trace32OpenContext<'a> {
    session: &'a Session,
    lock: &'a SessionLock,
    artifacts: &'a [Artifact],
    capture_config: &'a CaptureConfigDocument,
    input: &'a Artifact,
    file: std::fs::File,
}

struct Trace32AsciiSourceRequest {
    source_id: String,
    expected_profile_id: String,
    firmware_elf_artifact_id: String,
    limits: LineLimits,
}

struct Trace32TaskEventsSourceRequest {
    source_id: String,
    expected_profile_id: String,
    firmware_elf_artifact_id: String,
    mapping_artifact_id: String,
    limits: LineLimits,
}

fn sampling_completion(
    binding: &AcceptedTrace32RuntimeBinding,
) -> Result<(&ControllerStopEvidenceV2, &ControllerHealthEvidenceV2), AppError> {
    match &binding.completion {
        ControllerCaptureCompletionEvidence::Sampling { stop, health }
            if health.stop_evidence_sha256 == binding.stop_artifact.sha256 =>
        {
            Ok((stop, health))
        }
        ControllerCaptureCompletionEvidence::Sampling { .. } => Err(AppError::operational(
            "sampling health is not bound to the immutable Stop artifact",
        )),
        ControllerCaptureCompletionEvidence::ProgramFlowTaskEvents { .. } => {
            Err(AppError::operational(
                "TRACE32 ASCII normalization requires sampling completion evidence",
            ))
        }
    }
}

fn program_flow_completion(
    binding: &AcceptedTrace32RuntimeBinding,
) -> Result<
    (
        &ControllerStopEvidence,
        &ControllerProgramFlowHealthEvidence,
    ),
    AppError,
> {
    match &binding.completion {
        ControllerCaptureCompletionEvidence::ProgramFlowTaskEvents { stop, health }
            if health.stop_evidence_sha256 == binding.stop_artifact.sha256 =>
        {
            Ok((stop, health))
        }
        ControllerCaptureCompletionEvidence::ProgramFlowTaskEvents { .. } => {
            Err(AppError::operational(
                "program-flow health is not bound to the immutable Stop artifact",
            ))
        }
        ControllerCaptureCompletionEvidence::Sampling { .. } => Err(AppError::operational(
            "TASKEVENTS normalization requires program-flow completion evidence",
        )),
    }
}

fn open_trace32_ascii_source(
    context: Trace32OpenContext<'_>,
    request: Trace32AsciiSourceRequest,
) -> Result<OpenedSource, AppError> {
    let binding = accepted_trace32_runtime_binding(context.session, context.artifacts)?
        .ok_or_else(|| {
            AppError::unsupported(
                "normalize.trace32.runtime_binding",
                "TRACE32 ASCII normalization requires a complete accepted controller capture",
            )
        })?;
    open_trace32_ascii_source_with_binding(context, request, binding)
}

fn open_trace32_ascii_source_with_binding(
    context: Trace32OpenContext<'_>,
    request: Trace32AsciiSourceRequest,
    binding: AcceptedTrace32RuntimeBinding,
) -> Result<OpenedSource, AppError> {
    let (sampling_stop, sampling_health) = sampling_completion(&binding)?;
    let qualification = validate_trace32_ascii_binding(&context, &request, &binding)?;
    let firmware = required_artifact(context.artifacts, &request.firmware_elf_artifact_id)?;
    validate_firmware_elf(context.capture_config, firmware)?;
    if qualification.receipt.firmware_elf_sha256 != firmware.sha256 {
        return Err(AppError::operational(
            "target-adapter qualification receipt does not bind the registered firmware ELF",
        ));
    }
    let elf_bytes = read_bounded_artifact_bytes(
        context.session,
        firmware,
        MAX_TRACE32_ELF_BYTES,
        "firmware ELF",
    )?;
    let functions =
        trace_function_mappings_from_elf(&elf_bytes, &firmware.id, MAX_TRACE32_FUNCTION_RANGES)
            .map_err(AppError::operational)?;
    let mapping = Trace32SymbolMappingDocument {
        schema: TRACE32_SYMBOL_MAPPING_SCHEMA.to_owned(),
        profile_id: request.expected_profile_id.clone(),
        profile_sha256: Some(binding.target_adapter.profile_sha256.clone()),
        trace32_release: binding.trace32_release.clone(),
        trace32_build: binding.trace32_build,
        architecture_package: binding.architecture_package.clone(),
        target_identifier: binding.target_identifier.clone(),
        elf_artifact_id: firmware.id.clone(),
        elf_sha256: firmware.sha256.clone(),
        controller_health: artifact_binding(&binding.health_artifact),
        time_origin_evidence: artifact_binding(&binding.stop_artifact),
        qualification_receipt: artifact_binding(&qualification.artifact),
        address_classes: vec![TRACE32_ASCII_ADDRESS_CLASS.to_owned()],
        functions,
    };
    mapping.validate().map_err(AppError::operational)?;
    let mapping_artifact = ensure_trace32_symbol_mapping_artifact(
        context.session,
        context.lock,
        &binding,
        firmware,
        &mapping,
    )?;
    let source = open_host_validated_trace32_source(
        &context,
        &binding,
        &qualification,
        QualifiedTrace32OpenRequest {
            capture_kind: Trace32QualifiedCaptureKind::AsciiSymbolMapping,
            mapping: Trace32QualifiedMapping::AsciiSymbolMapping(mapping.clone()),
            core_id: 0,
            clock_domain: TRACE32_ASCII_CLOCK_DOMAIN.to_owned(),
            firmware,
            source_id: request.source_id,
            limits: request.limits,
        },
    )?;
    let source = ExpectedObservationCountSource::new(
        QualifiedObservationSource(source),
        sampling_stop.recorded_records,
        "TRACE32 StopV2 recorded_records",
    );
    let mut inherited_properties = Properties::new();
    inherited_properties.insert(
        "trace32_format".to_owned(),
        json!(t32perf_trace32::TRACE_ASCII_FORMAT_V1),
    );
    inherited_properties.insert("trace32_profile_id".to_owned(), json!(mapping.profile_id));
    inherited_properties.insert("trace32_release".to_owned(), json!(mapping.trace32_release));
    inherited_properties.insert("trace32_build".to_owned(), json!(mapping.trace32_build));
    inherited_properties.insert(
        "trace32_architecture_package".to_owned(),
        json!(mapping.architecture_package),
    );
    inherited_properties.insert(
        "trace32_target_identifier".to_owned(),
        json!(mapping.target_identifier),
    );
    inherited_properties.insert(
        "trace32_probe_identifier".to_owned(),
        json!(binding.probe_identifier),
    );
    inherited_properties.insert(
        "trace32_sampling_requested_rate_ns".to_owned(),
        json!(sampling_health.sampling.requested_rate_ns),
    );
    inherited_properties.insert(
        "trace32_symbol_mapping_artifact_id".to_owned(),
        json!(mapping_artifact.id),
    );
    inherited_properties.insert(
        "trace32_symbol_mapping_sha256".to_owned(),
        json!(mapping_artifact.sha256),
    );
    inherited_properties.insert(
        "trace32_firmware_elf_artifact_id".to_owned(),
        json!(firmware.id),
    );
    inherited_properties.insert(
        "trace32_firmware_elf_sha256".to_owned(),
        json!(firmware.sha256),
    );
    inherited_properties.insert(
        "trace32_adapter_qualification_sha256".to_owned(),
        json!(qualification.artifact.sha256),
    );
    inherited_properties.insert(
        "trace32_adapter_qualification_artifact_id".to_owned(),
        json!(qualification.artifact.id),
    );
    let provenance_artifact_ids = vec![
        firmware.id.clone(),
        mapping_artifact.id.clone(),
        binding.capabilities_artifact.id.clone(),
        binding.health_artifact.id.clone(),
        binding.stop_artifact.id.clone(),
        binding.export_artifact.id.clone(),
        qualification.artifact.id.clone(),
    ];
    Ok(OpenedSource {
        source: Box::new(source),
        inherited_properties,
        provenance_artifact_ids,
        adapter_id: "trace32_snooper_ascii_v1".to_owned(),
    })
}

fn validate_trace32_ascii_binding(
    context: &Trace32OpenContext<'_>,
    request: &Trace32AsciiSourceRequest,
    binding: &AcceptedTrace32RuntimeBinding,
) -> Result<ValidatedTrace32Qualification, AppError> {
    if request.expected_profile_id != TC234L_SNOOPER_ASCII_PROFILE_V1 {
        return Err(AppError::unsupported(
            "normalize.trace32.ascii.profile",
            format!(
                "TRACE32 ASCII profile `{}` is unsupported; expected `{TC234L_SNOOPER_ASCII_PROFILE_V1}`",
                request.expected_profile_id
            ),
        ));
    }
    if binding.trace32_release != TRACE32_RELEASE_2026_02
        || binding.trace32_build != TRACE32_BUILD_190766
        || binding.architecture_package != TRACE32_ARCHITECTURE_TRICORE
        || binding.target_identifier != TRACE32_TARGET_TC234L_CORE0
        || binding.target_adapter.adapter_id != TRACE32_TC234L_ADAPTER_ID
        || binding.target_adapter.adapter_version != TRACE32_TC234L_ADAPTER_VERSION
        || binding.target_adapter.trace32_release != binding.trace32_release
        || binding.target_adapter.trace32_build != binding.trace32_build
        || binding.target_adapter.architecture_package != binding.architecture_package
        || binding.target_adapter.target_identifier != binding.target_identifier
        || binding.target_adapter.probe_identifier != binding.probe_identifier
        || binding.target_adapter.scenario != TargetAdapterScenario::Normal
    {
        return Err(AppError::unsupported(
            "normalize.trace32.ascii.compatibility",
            "accepted TRACE32 runtime does not match the fixed TC234L build-190766 profile",
        ));
    }
    let qualification =
        validated_runtime_qualification(binding, "normalize.trace32.ascii.qualification")?;
    let (sampling_stop, _) = sampling_completion(binding)?;
    if !sampling_stop.time_origin_zeroed_to_first_record {
        return Err(AppError::operational(
            "accepted TRACE32 stop evidence does not prove ZERO at the first SNOOPer record",
        ));
    }
    if binding.export_response.code != "raw_ascii_exported"
        || context.input != &binding.export_artifact
        || context.input.kind != "raw_trace"
        || context.input.media_type != "text/plain"
        || context.input.producer != crate::controller::CONTROLLER_PRODUCER
    {
        return Err(AppError::operational(
            "normalization input is not the immutable raw ASCII artifact from the accepted controller export",
        ));
    }
    let capture = context.capture_config;
    if capture.provider != "trace32"
        || capture.adapter.id != TRACE32_TC234L_ADAPTER_ID
        || capture.adapter.version != TRACE32_TC234L_ADAPTER_VERSION
        || capture.mode != "snooper-pc-realtime-stack"
        || capture.covered_cores != [0]
        || !capture.timestamp.enabled
        || capture.timestamp.clock_id.as_deref() != Some(TRACE32_ASCII_CLOCK_DOMAIN)
        || capture.rtos_awareness.kind != "none"
        || !capture.rtos_awareness.metadata_artifact_ids.is_empty()
    {
        return Err(AppError::operational(
            "authoritative capture config does not match the fixed TC234L SNOOPer profile",
        ));
    }
    require_capture_parameter(capture, "export.profile", &request.expected_profile_id)?;
    require_capture_parameter(
        capture,
        "firmware.elf_artifact_id",
        &request.firmware_elf_artifact_id,
    )?;
    require_capture_parameter(capture, "snooper.time_origin", "first_record_zero")?;
    Ok(qualification)
}

struct ValidatedTrace32Qualification {
    artifact: Artifact,
    receipt: TargetAdapterQualificationReceipt,
}

fn validated_runtime_qualification(
    binding: &AcceptedTrace32RuntimeBinding,
    feature: &str,
) -> Result<ValidatedTrace32Qualification, AppError> {
    match (
        binding.target_adapter.qualification_sha256.as_ref(),
        binding.qualification_artifact.as_ref(),
        binding.qualification_receipt.as_ref(),
    ) {
        (None, None, None) => Err(AppError::unsupported(
            feature,
            "the admitted TRACE32 target adapter is an unqualified evidence-only candidate",
        )),
        (Some(expected), Some(artifact), Some(receipt)) if &artifact.sha256 == expected => {
            Ok(ValidatedTrace32Qualification {
                artifact: artifact.clone(),
                receipt: receipt.clone(),
            })
        }
        _ => Err(AppError::operational(
            "accepted TRACE32 runtime has an incomplete or inconsistent qualification claim",
        )),
    }
}

struct QualifiedTrace32OpenRequest<'a> {
    capture_kind: Trace32QualifiedCaptureKind,
    mapping: Trace32QualifiedMapping,
    core_id: u32,
    clock_domain: String,
    firmware: &'a Artifact,
    source_id: String,
    limits: LineLimits,
}

/// Private Host proof assembled only from admitted Session evidence and
/// immutable artifact handles. The inner crate context is structural only.
struct HostQualifiedTrace32Context(Trace32QualifiedAdapterContext);

impl HostQualifiedTrace32Context {
    fn from_trusted_session_context(context: Trace32QualifiedAdapterContext) -> Self {
        Self(context)
    }

    fn into_validated(self) -> Trace32QualifiedAdapterContext {
        self.0
    }
}

/// Opens a TRACE32 parser only after rebuilding the exact deployment admission
/// proof from immutable Session evidence.  The generic registry deliberately
/// cannot open either TRACE32 text format.
fn open_host_validated_trace32_source(
    context: &Trace32OpenContext<'_>,
    binding: &AcceptedTrace32RuntimeBinding,
    qualification: &ValidatedTrace32Qualification,
    request: QualifiedTrace32OpenRequest<'_>,
) -> Result<Box<dyn ObservationSource + Send>, AppError> {
    let (profile, _, _, _) = load_session_admission(context.session, context.artifacts)?;
    validate_qualified_profile_binding(&profile, binding)?;
    let receipt_artifact = required_artifact(context.artifacts, &qualification.artifact.id)?;
    if receipt_artifact != &qualification.artifact {
        return Err(AppError::operational(
            "accepted qualification receipt is not the immutable catalog artifact",
        ));
    }
    let receipt_bytes = read_bounded_artifact_bytes(
        context.session,
        receipt_artifact,
        MAX_TRACE32_MAPPING_BYTES,
        "target-adapter qualification receipt",
    )?;
    let qualified_adapter = QualifiedTargetAdapter::validate_for(
        profile,
        &receipt_bytes,
        artifact_binding(receipt_artifact),
    )
    .map_err(AppError::operational)?;
    if qualified_adapter.receipt() != &qualification.receipt {
        return Err(AppError::operational(
            "qualification receipt bytes do not match the accepted controller runtime claim",
        ));
    }
    let raw_input = artifact_binding(&binding.export_artifact);
    let runtime = Trace32QualifiedRuntime {
        trace32_release: binding.trace32_release.clone(),
        trace32_build: binding.trace32_build,
        architecture_package: binding.architecture_package.clone(),
        target_identifier: binding.target_identifier.clone(),
        core_id: request.core_id,
        clock_domain: request.clock_domain,
        elf: artifact_binding(request.firmware),
        controller_health: artifact_binding(&binding.health_artifact),
        time_origin_evidence: artifact_binding(&binding.stop_artifact),
        raw_input: raw_input.clone(),
    };
    let registry = QualifiedTrace32AdapterRegistry::defaults().map_err(AppError::operational)?;
    registry
        .open(
            HostQualifiedTrace32Context::from_trusted_session_context(
                Trace32QualifiedAdapterContext {
                    validated_receipt: qualified_adapter,
                    raw_input: Trace32RawInputIdentity {
                        artifact: raw_input,
                        capture_kind: request.capture_kind,
                    },
                    mapping: request.mapping,
                    runtime,
                    limits: request.limits,
                },
            )
            .into_validated(),
            AdapterRequest::new(context.session.id().as_str(), request.source_id).with_input(
                BufReader::new(context.file.try_clone().map_err(AppError::operational)?),
            ),
        )
        .map_err(AppError::operational)
}

fn validate_qualified_profile_binding(
    profile: &t32perf_trace32::TargetAdapterProfile,
    binding: &AcceptedTrace32RuntimeBinding,
) -> Result<(), AppError> {
    let profile_sha256 = profile.digest().map_err(AppError::operational)?;
    let Some(capture) = profile.scenario(binding.target_adapter.scenario) else {
        return Err(AppError::operational(
            "admitted target-adapter profile does not authorize the accepted controller scenario",
        ));
    };
    if binding.target_adapter.profile_sha256 != profile_sha256
        || binding.target_adapter.adapter_id != profile.adapter_id
        || binding.target_adapter.adapter_version != profile.adapter_version
        || binding.target_adapter.implementation_sha256 != profile.implementation_sha256
        || binding.target_adapter.qualification_sha256 != profile.qualification_sha256
        || binding.target_adapter.trace32_release != profile.build_gate.trace32_release
        || binding.target_adapter.trace32_build < profile.build_gate.minimum_build
        || binding.target_adapter.trace32_build > profile.build_gate.maximum_build
        || binding.target_adapter.architecture_package != profile.build_gate.architecture_package
        || binding.target_adapter.target_identifier != profile.target_identifier
        || binding.target_adapter.probe_identifier != profile.probe_identifier
        || binding.target_adapter.capture_kind != capture.capture.capture_kind
        || binding.target_adapter.controller_protocol != profile.controller_protocol
        || binding.target_adapter.custom_event_collector != profile.custom_event_collector
    {
        return Err(AppError::operational(
            "accepted controller target-adapter binding does not match the exact admitted profile",
        ));
    }
    Ok(())
}

fn validate_firmware_elf(
    capture_config: &CaptureConfigDocument,
    firmware: &Artifact,
) -> Result<(), AppError> {
    if firmware.kind != TRACE32_FIRMWARE_ELF_KIND
        || firmware.media_type != TRACE32_FIRMWARE_ELF_MEDIA_TYPE
    {
        return Err(AppError::operational(format!(
            "firmware artifact `{}` must have kind `{TRACE32_FIRMWARE_ELF_KIND}` and media type `{TRACE32_FIRMWARE_ELF_MEDIA_TYPE}`",
            firmware.id
        )));
    }
    if firmware.size_bytes == 0 || firmware.size_bytes > MAX_TRACE32_ELF_BYTES {
        return Err(AppError::operational(format!(
            "firmware ELF `{}` must contain 1..={MAX_TRACE32_ELF_BYTES} bytes",
            firmware.id
        )));
    }
    require_capture_parameter(
        capture_config,
        "firmware.elf_sha256",
        firmware.sha256.as_str(),
    )
}

fn ensure_trace32_symbol_mapping_artifact(
    session: &Session,
    lock: &SessionLock,
    binding: &AcceptedTrace32RuntimeBinding,
    firmware: &Artifact,
    mapping: &Trace32SymbolMappingDocument,
) -> Result<Artifact, AppError> {
    let input_artifact_ids = vec![
        firmware.id.clone(),
        CAPTURE_CONFIG_ID.to_owned(),
        binding.capabilities_artifact.id.clone(),
        binding.health_artifact.id.clone(),
        binding.stop_artifact.id.clone(),
        binding.export_artifact.id.clone(),
        mapping.qualification_receipt.artifact_id.clone(),
    ];
    let current_artifacts = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    if let Some(existing) = current_artifacts
        .iter()
        .find(|artifact| artifact.id == TRACE32_SYMBOL_MAPPING_ARTIFACT_ID)
    {
        if existing.kind != TRACE32_SYMBOL_MAPPING_ARTIFACT_KIND
            || existing.relative_path.as_str() != TRACE32_SYMBOL_MAPPING_ARTIFACT_PATH
            || existing.media_type != "application/json"
            || existing.producer != NORMALIZE_PRODUCER
            || existing.input_artifact_ids != input_artifact_ids
        {
            return Err(AppError::operational(
                "existing TRACE32 symbol mapping artifact has invalid identity or provenance",
            ));
        }
        let bytes = read_bounded_artifact_bytes(
            session,
            existing,
            MAX_TRACE32_MAPPING_BYTES,
            "TRACE32 symbol mapping",
        )?;
        let existing_mapping =
            parse_trace32_symbol_mapping(&bytes).map_err(AppError::operational)?;
        if &existing_mapping != mapping {
            return Err(AppError::operational(
                "existing TRACE32 symbol mapping does not match the accepted runtime and firmware ELF",
            ));
        }
        return Ok(existing.clone());
    }
    session
        .write_json_artifact(
            lock,
            ArtifactSpec {
                id: TRACE32_SYMBOL_MAPPING_ARTIFACT_ID.to_owned(),
                kind: TRACE32_SYMBOL_MAPPING_ARTIFACT_KIND.to_owned(),
                relative_path: ArtifactPath::new(TRACE32_SYMBOL_MAPPING_ARTIFACT_PATH)
                    .map_err(AppError::operational)?,
                media_type: "application/json".to_owned(),
                producer: NORMALIZE_PRODUCER.to_owned(),
                input_artifact_ids,
            },
            mapping,
        )
        .map_err(AppError::operational)
}

fn open_trace32_task_events_source(
    context: Trace32OpenContext<'_>,
    request: Trace32TaskEventsSourceRequest,
) -> Result<OpenedSource, AppError> {
    let binding = accepted_trace32_runtime_binding(context.session, context.artifacts)?
        .ok_or_else(|| {
            AppError::unsupported(
                "normalize.trace32.task_events.runtime_binding",
                "TASKEVENTS normalization requires a complete accepted TRACE32 controller capture",
            )
        })?;
    program_flow_completion(&binding)?;
    if binding.export_response.code != "task_events_exported"
        || context.input != &binding.export_artifact
        || context.input.kind != "raw_trace"
        || context.input.media_type != "text/plain"
        || context.input.producer != crate::controller::CONTROLLER_PRODUCER
    {
        return Err(AppError::unsupported(
            "normalize.trace32.task_events.export",
            "the accepted controller capture is not a qualified TASKEVENTS export",
        ));
    }
    let qualification =
        validated_runtime_qualification(&binding, "normalize.trace32.task_events.qualification")?;
    let mapping_artifact = required_artifact(context.artifacts, &request.mapping_artifact_id)?;
    if mapping_artifact.kind != TRACE32_TASK_EVENTS_MAPPING_ARTIFACT_KIND
        || mapping_artifact.relative_path.as_str() != TRACE32_TASK_EVENTS_MAPPING_ARTIFACT_PATH
        || mapping_artifact.media_type != "application/json"
        || mapping_artifact.producer != TRACE32_TASK_EVENTS_MAPPING_PRODUCER
    {
        return Err(AppError::operational(
            "TASKEVENTS mapping artifact is not owned by the deployment qualification stage",
        ));
    }
    let mapping_bytes = read_bounded_artifact_bytes(
        context.session,
        mapping_artifact,
        MAX_TRACE32_MAPPING_BYTES,
        "TRACE32 TASKEVENTS mapping",
    )?;
    let mapping =
        parse_trace32_task_events_mapping(&mapping_bytes).map_err(AppError::operational)?;
    validate_trace32_task_events_binding(
        &context,
        &request,
        &binding,
        &qualification,
        mapping_artifact,
        &mapping,
    )?;
    let firmware = required_artifact(context.artifacts, &request.firmware_elf_artifact_id)?;
    let source = open_host_validated_trace32_source(
        &context,
        &binding,
        &qualification,
        QualifiedTrace32OpenRequest {
            capture_kind: Trace32QualifiedCaptureKind::TaskEventsMapping,
            mapping: Trace32QualifiedMapping::TaskEventsMapping(mapping.clone()),
            core_id: mapping.core_id,
            clock_domain: context
                .capture_config
                .timestamp
                .clock_id
                .clone()
                .expect("validated TASKEVENTS timestamp clock"),
            firmware,
            source_id: request.source_id,
            limits: request.limits,
        },
    )?;
    let mut inherited_properties = Properties::new();
    inherited_properties.insert(
        "trace32_format".to_owned(),
        json!(t32perf_trace32::TRACE_TASK_EVENTS_FORMAT_V1),
    );
    inherited_properties.insert("trace32_profile_id".to_owned(), json!(mapping.profile_id));
    inherited_properties.insert(
        "trace32_profile_sha256".to_owned(),
        json!(mapping.profile_sha256),
    );
    inherited_properties.insert(
        "trace32_task_events_mapping_artifact_id".to_owned(),
        json!(mapping_artifact.id),
    );
    inherited_properties.insert(
        "trace32_task_events_mapping_sha256".to_owned(),
        json!(mapping_artifact.sha256),
    );
    let mut provenance_artifact_ids = vec![
        mapping_artifact.id.clone(),
        binding.capabilities_artifact.id.clone(),
        binding.health_artifact.id.clone(),
        binding.stop_artifact.id.clone(),
        binding.export_artifact.id.clone(),
        request.firmware_elf_artifact_id,
    ];
    extend_unique(
        &mut provenance_artifact_ids,
        mapping
            .metadata_artifacts
            .iter()
            .map(|binding| binding.artifact.artifact_id.clone()),
    );
    provenance_artifact_ids.push(mapping.qualification_receipt.artifact_id.clone());
    Ok(OpenedSource {
        source,
        inherited_properties,
        provenance_artifact_ids,
        adapter_id: "trace32_task_events_v1".to_owned(),
    })
}

fn validate_trace32_task_events_binding(
    context: &Trace32OpenContext<'_>,
    request: &Trace32TaskEventsSourceRequest,
    binding: &AcceptedTrace32RuntimeBinding,
    qualification: &ValidatedTrace32Qualification,
    mapping_artifact: &Artifact,
    mapping: &Trace32TaskEventsMappingDocument,
) -> Result<(), AppError> {
    program_flow_completion(binding)?;
    mapping.validate().map_err(AppError::operational)?;
    let (
        TargetAdapterCaptureKind::ProgramFlowTaskEvents {
            export_profile_id,
            rtos_awareness,
            timestamp_clock_id,
            orti_artifact_id,
            task_marker_artifact_id,
        },
        TargetAdapterCaptureKind::ProgramFlowTaskEvents {
            export_profile_id: contract_export_profile_id,
            rtos_awareness: contract_rtos_awareness,
            timestamp_clock_id: contract_timestamp_clock_id,
            orti_artifact_id: contract_orti_artifact_id,
            task_marker_artifact_id: contract_task_marker_artifact_id,
        },
    ) = (
        &binding.target_adapter.capture_kind,
        &binding.capture_contract.capture_kind,
    )
    else {
        return Err(AppError::operational(
            "TASKEVENTS normalization is not bound to a program-flow profile",
        ));
    };
    if request.expected_profile_id != mapping.profile_id
        || request.expected_profile_id != *export_profile_id
        || export_profile_id != contract_export_profile_id
        || rtos_awareness != contract_rtos_awareness
        || timestamp_clock_id != contract_timestamp_clock_id
        || orti_artifact_id != contract_orti_artifact_id
        || task_marker_artifact_id != contract_task_marker_artifact_id
        || mapping.profile_sha256 != binding.target_adapter.profile_sha256
        || request.firmware_elf_artifact_id != mapping.elf_artifact_id
        || mapping.trace32_release != binding.trace32_release
        || mapping.trace32_build != binding.trace32_build
        || mapping.architecture_package != binding.architecture_package
        || mapping.target_identifier != binding.target_identifier
    {
        return Err(AppError::operational(
            "TASKEVENTS mapping compatibility does not match the accepted controller runtime",
        ));
    }
    if context.capture_config.mode != binding.capture_contract.capture_mode
        || context.capture_config.sink.kind != binding.capture_contract.trace_sink
        || context.capture_config.covered_cores != binding.capture_contract.covered_cores
        || !context.capture_config.timestamp.enabled
        || context.capture_config.timestamp.clock_id.as_deref() != Some(timestamp_clock_id.as_str())
        || context.capture_config.covered_cores != [mapping.core_id]
        || context.capture_config.rtos_awareness.kind != *rtos_awareness
    {
        return Err(AppError::operational(
            "authoritative capture config does not bind the TASKEVENTS core and clock",
        ));
    }
    if context.capture_config.rtos_awareness.metadata_artifact_ids
        != [orti_artifact_id.clone(), task_marker_artifact_id.clone()]
    {
        return Err(AppError::operational(
            "authoritative capture config does not bind the exact TASKEVENTS ORTI and marker metadata",
        ));
    }
    require_capture_parameter(
        context.capture_config,
        "export.profile",
        &request.expected_profile_id,
    )?;
    require_capture_parameter(
        context.capture_config,
        "firmware.elf_artifact_id",
        &request.firmware_elf_artifact_id,
    )?;
    let firmware = required_artifact(context.artifacts, &request.firmware_elf_artifact_id)?;
    validate_firmware_elf(context.capture_config, firmware)?;
    if mapping.elf_sha256 != firmware.sha256 {
        return Err(AppError::operational(
            "TASKEVENTS mapping firmware digest does not match the registered ELF",
        ));
    }
    validate_artifact_binding(
        context.artifacts,
        &mapping.controller_health,
        Some(&binding.health_artifact),
        "controller health",
    )?;
    validate_artifact_binding(
        context.artifacts,
        &mapping.time_origin_evidence,
        Some(&binding.stop_artifact),
        "time-origin stop evidence",
    )?;
    let qualification_artifact = validate_artifact_binding(
        context.artifacts,
        &mapping.qualification_receipt,
        Some(&qualification.artifact),
        "qualification receipt",
    )?;
    if qualification_artifact.kind != crate::controller::TARGET_ADAPTER_QUALIFICATION_KIND
        || qualification_artifact.media_type != "application/json"
        || qualification_artifact.producer
            != crate::controller::TARGET_ADAPTER_QUALIFICATION_PRODUCER
        || qualification.receipt.firmware_elf_sha256 != firmware.sha256
    {
        return Err(AppError::operational(
            "TASKEVENTS qualification receipt does not match the accepted target adapter",
        ));
    }
    let metadata_ids = context
        .capture_config
        .rtos_awareness
        .metadata_artifact_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for metadata in &mapping.metadata_artifacts {
        let artifact = validate_artifact_binding(
            context.artifacts,
            &metadata.artifact,
            None,
            match metadata.role {
                TraceTaskMetadataRole::Orti => "ORTI metadata",
                TraceTaskMetadataRole::Markers => "task marker metadata",
            },
        )?;
        if !metadata_ids.contains(artifact.id.as_str()) {
            return Err(AppError::operational(format!(
                "TASKEVENTS metadata artifact `{}` is absent from authoritative RTOS awareness",
                artifact.id
            )));
        }
        let expected_id = match metadata.role {
            TraceTaskMetadataRole::Orti => orti_artifact_id,
            TraceTaskMetadataRole::Markers => task_marker_artifact_id,
        };
        if artifact.id.as_str() != expected_id {
            return Err(AppError::operational(format!(
                "TASKEVENTS {:?} metadata is not the exact artifact selected by the target adapter",
                metadata.role
            )));
        }
    }
    let mut expected_inputs = vec![
        firmware.id.clone(),
        CAPTURE_CONFIG_ID.to_owned(),
        binding.capabilities_artifact.id.clone(),
        binding.health_artifact.id.clone(),
        binding.stop_artifact.id.clone(),
        binding.export_artifact.id.clone(),
    ];
    expected_inputs.extend(
        mapping
            .metadata_artifacts
            .iter()
            .map(|metadata| metadata.artifact.artifact_id.clone()),
    );
    extend_unique(
        &mut expected_inputs,
        binding
            .qualification_provenance_artifacts
            .iter()
            .map(|artifact| artifact.id.clone()),
    );
    extend_unique(
        &mut expected_inputs,
        [
            mapping.qualification_receipt.artifact_id.clone(),
            TASK_EVENTS_MAPPING_TEMPLATE_ARTIFACT_ID.to_owned(),
        ],
    );
    if mapping_artifact.input_artifact_ids != expected_inputs {
        return Err(AppError::operational(
            "TASKEVENTS mapping catalog provenance does not match its bound evidence",
        ));
    }
    Ok(())
}

fn artifact_binding(artifact: &Artifact) -> TraceArtifactBinding {
    TraceArtifactBinding {
        artifact_id: artifact.id.clone(),
        sha256: artifact.sha256.clone(),
    }
}

fn validate_artifact_binding<'a>(
    artifacts: &'a [Artifact],
    binding: &TraceArtifactBinding,
    expected: Option<&Artifact>,
    label: &str,
) -> Result<&'a Artifact, AppError> {
    let artifact = required_artifact(artifacts, &binding.artifact_id)?;
    if artifact.sha256 != binding.sha256 || expected.is_some_and(|expected| expected != artifact) {
        return Err(AppError::operational(format!(
            "{label} artifact binding does not match the immutable catalog"
        )));
    }
    Ok(artifact)
}

fn require_capture_parameter(
    capture_config: &CaptureConfigDocument,
    key: &str,
    expected: &str,
) -> Result<(), AppError> {
    match capture_config
        .adapter_parameters
        .get(key)
        .and_then(Value::as_str)
    {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(AppError::operational(format!(
            "capture-config adapter parameter `{key}` is `{actual}`; expected `{expected}`"
        ))),
        None => Err(AppError::operational(format!(
            "capture-config omits required string adapter parameter `{key}`"
        ))),
    }
}

fn require_capture_parameter_value(
    capture_config: &CaptureConfigDocument,
    key: &str,
    expected: Value,
) -> Result<(), AppError> {
    match capture_config.adapter_parameters.get(key) {
        Some(actual) if actual == &expected => Ok(()),
        Some(actual) => Err(AppError::operational(format!(
            "capture-config adapter parameter `{key}` is `{actual}`; expected `{expected}`"
        ))),
        None => Err(AppError::operational(format!(
            "capture-config omits required adapter parameter `{key}`"
        ))),
    }
}

fn read_bounded_artifact_bytes(
    session: &Session,
    artifact: &Artifact,
    maximum_bytes: u64,
    label: &str,
) -> Result<Vec<u8>, AppError> {
    if artifact.size_bytes > maximum_bytes {
        return Err(AppError::operational(format!(
            "{label} artifact `{}` exceeds {maximum_bytes} bytes",
            artifact.id
        )));
    }
    let file = session
        .open_artifact(artifact)
        .map_err(AppError::operational)?;
    let capacity = usize::try_from(artifact.size_bytes).map_err(AppError::operational)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(AppError::operational)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum_bytes {
        return Err(AppError::operational(format!(
            "{label} artifact `{}` grew beyond {maximum_bytes} bytes while reading",
            artifact.id
        )));
    }
    Ok(bytes)
}

struct OpenedSource {
    source: Box<dyn ObservationSource + Send>,
    inherited_properties: Properties,
    provenance_artifact_ids: Vec<String>,
    adapter_id: String,
}

/// Newtype needed because the parser registry returns a trait object while the
/// normalized source wrappers remain generic over concrete implementations.
struct QualifiedObservationSource(Box<dyn ObservationSource + Send>);

impl ObservationSource for QualifiedObservationSource {
    fn descriptor(&self) -> &SourceDescriptor {
        self.0.descriptor()
    }

    fn dictionary(&self) -> Option<&ObservationDictionary> {
        self.0.dictionary()
    }

    fn next_observation(&mut self) -> Result<Option<OrderedObservation>, SourceError> {
        self.0.next_observation()
    }
}

struct ExpectedObservationCountSource<S> {
    inner: S,
    expected: u64,
    observed: u64,
    evidence_label: &'static str,
    finished: bool,
}

impl<S> ExpectedObservationCountSource<S> {
    const fn new(inner: S, expected: u64, evidence_label: &'static str) -> Self {
        Self {
            inner,
            expected,
            observed: 0,
            evidence_label,
            finished: false,
        }
    }
}

impl<S: ObservationSource> ObservationSource for ExpectedObservationCountSource<S> {
    fn descriptor(&self) -> &SourceDescriptor {
        self.inner.descriptor()
    }

    fn dictionary(&self) -> Option<&ObservationDictionary> {
        self.inner.dictionary()
    }

    fn next_observation(&mut self) -> Result<Option<OrderedObservation>, SourceError> {
        if self.finished {
            return Ok(None);
        }
        match self.inner.next_observation()? {
            Some(observation) => {
                self.observed =
                    self.observed
                        .checked_add(1)
                        .ok_or_else(|| SourceError::Invariant {
                            message: "source observation count overflow".to_owned(),
                        })?;
                if self.observed > self.expected {
                    self.finished = true;
                    return Err(SourceError::Invariant {
                        message: format!(
                            "source produced more than {} observations declared by {}",
                            self.expected, self.evidence_label
                        ),
                    });
                }
                Ok(Some(observation))
            }
            None => {
                self.finished = true;
                if self.observed != self.expected {
                    return Err(SourceError::Invariant {
                        message: format!(
                            "source produced {} observations but {} declares {}",
                            self.observed, self.evidence_label, self.expected
                        ),
                    });
                }
                Ok(None)
            }
        }
    }
}

struct OpenedNormalization {
    source: Box<dyn ObservationSource + Send>,
    dictionary: ObservationDictionary,
    inherited_properties: Properties,
    provenance_artifact_ids: Vec<String>,
    adapter_id: String,
    mode: &'static str,
}

fn extend_unique<T>(target: &mut Vec<T>, values: impl IntoIterator<Item = T>)
where
    T: PartialEq,
{
    for value in values {
        if !target.contains(&value) {
            target.push(value);
        }
    }
}

fn merge_dictionaries(
    session_id: &str,
    dictionaries: Vec<ObservationDictionary>,
) -> Result<ObservationDictionary, AppError> {
    let mut merged = ObservationDictionary::new(session_id);
    let mut entries = BTreeMap::<(u8, String), DictionaryEntry>::new();
    for dictionary in dictionaries {
        if dictionary.session_id != session_id {
            return Err(AppError::operational(format!(
                "source dictionary session `{}` does not match owning session `{session_id}`",
                dictionary.session_id
            )));
        }
        for entry in dictionary.entries {
            let key = dictionary_key(&entry);
            if let Some(previous) = entries.get(&key) {
                if previous != &entry {
                    return Err(AppError::operational(format!(
                        "multi-source dictionary definition conflicts for `{}`",
                        key.1
                    )));
                }
                continue;
            }
            entries.insert(key, entry);
        }
    }
    merged.entries = entries.into_values().collect();
    merged.validate().map_err(AppError::operational)?;
    Ok(merged)
}

fn dictionary_key(entry: &DictionaryEntry) -> (u8, String) {
    match entry {
        DictionaryEntry::DefineContext { id, .. } => (0, id.clone()),
        DictionaryEntry::DefineFunction { id, .. } => (1, id.clone()),
        DictionaryEntry::DefineCounter { id, .. } => (2, id.clone()),
    }
}

fn read_config(session: &Session, artifact: &Artifact) -> Result<NormalizeConfig, AppError> {
    if artifact.kind != NORMALIZE_CONFIG_KIND || artifact.media_type != "application/json" {
        return Err(AppError::operational(format!(
            "normalization config artifact `{}` must have kind `{NORMALIZE_CONFIG_KIND}` and media type `application/json`",
            artifact.id
        )));
    }
    if artifact.size_bytes > MAX_CONFIG_BYTES {
        return Err(AppError::operational(format!(
            "normalization config artifact `{}` exceeds {MAX_CONFIG_BYTES} bytes",
            artifact.id
        )));
    }
    let file = session
        .open_artifact(artifact)
        .map_err(AppError::operational)?;
    let mut bytes =
        Vec::with_capacity(usize::try_from(artifact.size_bytes).map_err(AppError::operational)?);
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(AppError::operational)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CONFIG_BYTES {
        return Err(AppError::operational(format!(
            "normalization config artifact `{}` grew beyond {MAX_CONFIG_BYTES} bytes while reading",
            artifact.id
        )));
    }

    let value: Value = decode_config_json(&bytes)?;
    let object = value.as_object().ok_or_else(|| {
        AppError::operational("normalization config must contain exactly one JSON object")
    })?;
    match object.get("schema").and_then(Value::as_str) {
        Some(NORMALIZE_CONFIG_SCHEMA) => {}
        Some(schema) => {
            return Err(AppError::unsupported(
                "normalize.config.schema",
                format!("normalization config schema `{schema}` is unsupported"),
            ));
        }
        None => return Err(AppError::operational("normalization config omits `schema`")),
    }
    let mode = object
        .get("mode")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::operational("normalization config omits `mode`"))?;
    let source_values = match mode {
        SINGLE_SOURCE_MODE => vec![
            object
                .get("source")
                .ok_or_else(|| AppError::operational("normalization config omits `source`"))?,
        ],
        MULTI_SOURCE_MODE => object
            .get("sources")
            .and_then(Value::as_array)
            .ok_or_else(|| AppError::operational("multi-source config omits `sources`"))?
            .iter()
            .map(|configured| {
                configured
                    .get("source")
                    .ok_or_else(|| AppError::operational("multi-source entry omits `source`"))
            })
            .collect::<Result<Vec<_>, _>>()?,
        other => {
            return Err(AppError::unsupported(
                "normalize.mode",
                format!("normalization mode `{other}` is unsupported"),
            ));
        }
    };
    for source in source_values {
        let adapter = source
            .as_object()
            .and_then(|source| source.get("adapter"))
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::operational("normalization source omits `adapter`"))?;
        if !matches!(
            adapter,
            "canonical_ndjson_v1"
                | "explicit_csv_v1"
                | "c_wire_v1"
                | "trace32_snooper_ascii_v1"
                | "trace32_task_events_v1"
        ) {
            return Err(AppError::unsupported(
                "normalize.adapter",
                format!(
                    "normalization adapter `{adapter}` is unavailable; undocumented or real TRACE32 formats require a verified adapter"
                ),
            ));
        }
    }

    let config: NormalizeConfig = decode_config_json(&bytes)?;
    if config.schema() != NORMALIZE_CONFIG_SCHEMA {
        return Err(AppError::operational(
            "normalization config identity changed during strict decoding",
        ));
    }
    config.validate()?;
    Ok(config)
}

fn decode_config_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, AppError> {
    strict_json::from_slice(bytes).map_err(AppError::operational)
}

fn csv_columns(
    bindings: Vec<CsvColumnBindingConfig>,
    ignored_columns: Vec<String>,
) -> Result<CsvColumnMap, AppError> {
    let mut fields = BTreeSet::new();
    let mut names = HashSet::new();
    let mut columns = CsvColumnMap::new();
    for binding in bindings {
        if !fields.insert(binding.field) {
            return Err(AppError::operational(format!(
                "CSV semantic field `{:?}` is mapped more than once",
                binding.field
            )));
        }
        if !names.insert(binding.column.clone()) {
            return Err(AppError::operational(format!(
                "CSV input column `{}` is declared more than once",
                binding.column
            )));
        }
        columns.insert(binding.field.into(), binding.column);
    }
    for column in ignored_columns {
        if !names.insert(column.clone()) {
            return Err(AppError::operational(format!(
                "CSV input column `{column}` is declared more than once"
            )));
        }
        columns.ignore(column);
    }
    Ok(columns)
}

fn required_artifact<'a>(artifacts: &'a [Artifact], id: &str) -> Result<&'a Artifact, AppError> {
    artifacts
        .iter()
        .find(|artifact| artifact.id == id)
        .ok_or_else(|| AppError::operational(format!("artifact `{id}` is not registered")))
}

fn mark_failed(session: &Session, lock: &SessionLock, error: &AppError) -> Result<(), AppError> {
    session
        .transition(
            lock,
            SessionStatus::Failed,
            Some(SessionError {
                code: "NORMALIZE_FAILED".to_owned(),
                message: error.message.clone(),
                details: std::collections::BTreeMap::from([
                    ("stage".to_owned(), json!("normalize")),
                    ("exit_code".to_owned(), json!(error.exit_code)),
                ]),
            }),
        )
        .map(|_| ())
        .map_err(|state_error| AppError::state_persistence("normalize", error, state_error))
}

#[derive(Debug, Deserialize)]
#[serde(tag = "mode", deny_unknown_fields)]
enum NormalizeConfig {
    #[serde(rename = "single_source")]
    SingleSource {
        schema: String,
        source: NormalizeSourceConfig,
        output_limits: LineLimitConfig,
    },
    #[serde(rename = "multi_source")]
    MultiSource {
        schema: String,
        sources: Vec<MultiSourceConfig>,
        output_limits: LineLimitConfig,
    },
}

impl NormalizeConfig {
    fn schema(&self) -> &str {
        match self {
            Self::SingleSource { schema, .. } | Self::MultiSource { schema, .. } => schema,
        }
    }

    const fn output_limits(&self) -> LineLimitConfig {
        match self {
            Self::SingleSource { output_limits, .. } | Self::MultiSource { output_limits, .. } => {
                *output_limits
            }
        }
    }

    fn input_artifact_ids(&self, cli_input: Option<&str>) -> Result<Vec<String>, AppError> {
        match self {
            Self::SingleSource { .. } => {
                let input = cli_input.ok_or_else(|| {
                    AppError::operational("single-source normalization requires `--input-artifact`")
                })?;
                Ok(vec![input.to_owned()])
            }
            Self::MultiSource { sources, .. } => {
                if cli_input.is_some() {
                    return Err(AppError::operational(
                        "multi-source normalization takes input artifact IDs only from `sources`; omit `--input-artifact`",
                    ));
                }
                Ok(sources
                    .iter()
                    .map(|source| source.input_artifact_id.clone())
                    .collect())
            }
        }
    }

    fn sources(&self) -> Vec<&NormalizeSourceConfig> {
        match self {
            Self::SingleSource { source, .. } => vec![source],
            Self::MultiSource { sources, .. } => sources
                .iter()
                .map(|configured| &configured.source)
                .collect(),
        }
    }

    fn validate(&self) -> Result<(), AppError> {
        if self.schema() != NORMALIZE_CONFIG_SCHEMA {
            return Err(AppError::operational(format!(
                "normalization config schema `{}` is unsupported",
                self.schema()
            )));
        }
        self.output_limits().validate()?;
        match self {
            Self::SingleSource { source, .. } => source.validate(),
            Self::MultiSource { sources, .. } => {
                if !(2..=MAX_MULTI_SOURCES).contains(&sources.len()) {
                    return Err(AppError::operational(format!(
                        "multi-source normalization requires 2..={MAX_MULTI_SOURCES} sources"
                    )));
                }
                for source in sources {
                    if source.input_artifact_id.trim().is_empty() {
                        return Err(AppError::operational(
                            "multi-source input artifact identifier must be nonempty",
                        ));
                    }
                    if source.clock_domain.trim().is_empty() {
                        return Err(AppError::operational(
                            "multi-source clock domain must be nonempty",
                        ));
                    }
                    source.source.validate()?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MultiSourceConfig {
    input_artifact_id: String,
    clock_domain: String,
    order: MultiSourceOrderConfig,
    source: NormalizeSourceConfig,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MultiSourceOrderConfig {
    RejectAmbiguousTies,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "adapter", deny_unknown_fields)]
enum NormalizeSourceConfig {
    #[serde(rename = "canonical_ndjson_v1")]
    CanonicalNdjsonV1 {
        source_id: String,
        limits: LineLimitConfig,
    },
    #[serde(rename = "explicit_csv_v1")]
    ExplicitCsvV1 {
        source_id: String,
        columns: Vec<CsvColumnBindingConfig>,
        ignored_columns: Vec<String>,
        clock: ClockConfig,
        origin: ClockOriginConfig,
        quality: Quality,
        limits: LineLimitConfig,
    },
    #[serde(rename = "c_wire_v1")]
    CWireV1 {
        wire_version: u8,
        source_id: String,
        core_id: u32,
        clock: ClockConfig,
        origin: ClockOriginConfig,
        #[serde(default)]
        counter_mapping_artifact_id: Option<String>,
        limits: WireLimitConfig,
    },
    #[serde(rename = "trace32_snooper_ascii_v1")]
    Trace32SnooperAsciiV1 {
        source_id: String,
        expected_profile_id: String,
        firmware_elf_artifact_id: String,
        limits: LineLimitConfig,
    },
    #[serde(rename = "trace32_task_events_v1")]
    Trace32TaskEventsV1 {
        source_id: String,
        expected_profile_id: String,
        firmware_elf_artifact_id: String,
        mapping_artifact_id: String,
        limits: LineLimitConfig,
    },
}

impl NormalizeSourceConfig {
    fn source_id(&self) -> &str {
        match self {
            Self::CanonicalNdjsonV1 { source_id, .. }
            | Self::ExplicitCsvV1 { source_id, .. }
            | Self::CWireV1 { source_id, .. }
            | Self::Trace32SnooperAsciiV1 { source_id, .. }
            | Self::Trace32TaskEventsV1 { source_id, .. } => source_id,
        }
    }

    fn validate(&self) -> Result<(), AppError> {
        if self.source_id().trim().is_empty() {
            return Err(AppError::operational(
                "normalization source identifier must be nonempty",
            ));
        }
        match self {
            Self::CanonicalNdjsonV1 { limits, .. } | Self::ExplicitCsvV1 { limits, .. } => {
                limits.validate()
            }
            Self::CWireV1 {
                counter_mapping_artifact_id,
                limits,
                ..
            } => {
                if counter_mapping_artifact_id
                    .as_deref()
                    .is_some_and(|id| id.trim().is_empty())
                {
                    return Err(AppError::operational(
                        "C wire counter mapping artifact identifier must be nonempty",
                    ));
                }
                limits.validate()
            }
            Self::Trace32SnooperAsciiV1 {
                expected_profile_id,
                firmware_elf_artifact_id,
                limits,
                ..
            } => {
                validate_normalize_reference("TRACE32 ASCII profile", expected_profile_id)?;
                validate_normalize_reference(
                    "TRACE32 firmware ELF artifact",
                    firmware_elf_artifact_id,
                )?;
                limits.validate()
            }
            Self::Trace32TaskEventsV1 {
                expected_profile_id,
                firmware_elf_artifact_id,
                mapping_artifact_id,
                limits,
                ..
            } => {
                validate_normalize_reference("TASKEVENTS profile", expected_profile_id)?;
                validate_normalize_reference(
                    "TASKEVENTS firmware ELF artifact",
                    firmware_elf_artifact_id,
                )?;
                validate_normalize_reference("TASKEVENTS mapping artifact", mapping_artifact_id)?;
                limits.validate()
            }
        }
    }
}

fn validate_normalize_reference(label: &str, value: &str) -> Result<(), AppError> {
    if value.trim().is_empty() {
        return Err(AppError::operational(format!(
            "{label} identifier must be nonempty"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct LineLimitConfig {
    max_line_bytes: usize,
    max_records: u64,
    #[serde(default = "default_max_dictionary_entries")]
    max_dictionary_entries: u64,
    #[serde(default = "default_max_dictionary_bytes")]
    max_dictionary_bytes: u64,
}

impl LineLimitConfig {
    fn validate(self) -> Result<(), AppError> {
        if self.max_line_bytes == 0
            || self.max_line_bytes > MAX_CONFIG_LINE_BYTES
            || self.max_records == 0
            || self.max_records > MAX_CONFIG_RECORDS
            || self.max_dictionary_entries == 0
            || self.max_dictionary_entries > HARD_MAX_DICTIONARY_ENTRIES
            || self.max_dictionary_bytes == 0
            || self.max_dictionary_bytes > HARD_MAX_DICTIONARY_BYTES
        {
            return Err(AppError::operational(format!(
                "line limits must satisfy max_line_bytes=1..={MAX_CONFIG_LINE_BYTES}, max_records=1..={MAX_CONFIG_RECORDS}, max_dictionary_entries=1..={HARD_MAX_DICTIONARY_ENTRIES}, and max_dictionary_bytes=1..={HARD_MAX_DICTIONARY_BYTES}"
            )));
        }
        Ok(())
    }
}

impl TryFrom<LineLimitConfig> for LineLimits {
    type Error = AppError;

    fn try_from(value: LineLimitConfig) -> Result<Self, Self::Error> {
        value.validate()?;
        Ok(Self {
            max_line_bytes: value.max_line_bytes,
            max_records: value.max_records,
            max_dictionary_entries: value.max_dictionary_entries,
            max_dictionary_bytes: value.max_dictionary_bytes,
        })
    }
}

const fn default_max_dictionary_entries() -> u64 {
    DEFAULT_MAX_DICTIONARY_ENTRIES
}

const fn default_max_dictionary_bytes() -> u64 {
    DEFAULT_MAX_DICTIONARY_BYTES
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireLimitConfig {
    max_payload_bytes: usize,
    max_records: u64,
}

impl WireLimitConfig {
    fn validate(self) -> Result<(), AppError> {
        if self.max_payload_bytes == 0 || self.max_records == 0 {
            return Err(AppError::operational("wire limits must be nonzero"));
        }
        Ok(())
    }
}

impl TryFrom<WireLimitConfig> for WireLimits {
    type Error = AppError;

    fn try_from(value: WireLimitConfig) -> Result<Self, Self::Error> {
        value.validate()?;
        Ok(Self {
            max_payload_bytes: value.max_payload_bytes,
            max_records: value.max_records,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CsvColumnBindingConfig {
    field: CsvFieldConfig,
    column: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CsvFieldConfig {
    TimestampTicks,
    SourceSequence,
    OrderKey,
    EventType,
    CoreId,
    ContextId,
    PreviousContextId,
    NextContextId,
    FunctionId,
    FrameId,
    InterruptId,
    Priority,
    ActivationId,
    Address,
    WeightNs,
    Name,
    SpanId,
    CorrelationId,
    CounterId,
    Value,
    DurationNs,
    Reason,
    MetadataKey,
    MetadataValue,
}

impl From<CsvFieldConfig> for CsvField {
    fn from(value: CsvFieldConfig) -> Self {
        match value {
            CsvFieldConfig::TimestampTicks => Self::TimestampTicks,
            CsvFieldConfig::SourceSequence => Self::SourceSequence,
            CsvFieldConfig::OrderKey => Self::OrderKey,
            CsvFieldConfig::EventType => Self::EventType,
            CsvFieldConfig::CoreId => Self::CoreId,
            CsvFieldConfig::ContextId => Self::ContextId,
            CsvFieldConfig::PreviousContextId => Self::PreviousContextId,
            CsvFieldConfig::NextContextId => Self::NextContextId,
            CsvFieldConfig::FunctionId => Self::FunctionId,
            CsvFieldConfig::FrameId => Self::FrameId,
            CsvFieldConfig::InterruptId => Self::InterruptId,
            CsvFieldConfig::Priority => Self::Priority,
            CsvFieldConfig::ActivationId => Self::ActivationId,
            CsvFieldConfig::Address => Self::Address,
            CsvFieldConfig::WeightNs => Self::WeightNs,
            CsvFieldConfig::Name => Self::Name,
            CsvFieldConfig::SpanId => Self::SpanId,
            CsvFieldConfig::CorrelationId => Self::CorrelationId,
            CsvFieldConfig::CounterId => Self::CounterId,
            CsvFieldConfig::Value => Self::Value,
            CsvFieldConfig::DurationNs => Self::DurationNs,
            CsvFieldConfig::Reason => Self::Reason,
            CsvFieldConfig::MetadataKey => Self::MetadataKey,
            CsvFieldConfig::MetadataValue => Self::MetadataValue,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClockConfig {
    domain_id: String,
    frequency_hz: RationalFrequencyConfig,
    #[serde(default)]
    wrap: Option<WrapConfig>,
}

impl TryFrom<ClockConfig> for ClockDomainSpec {
    type Error = AppError;

    fn try_from(value: ClockConfig) -> Result<Self, Self::Error> {
        if value.domain_id.trim().is_empty() {
            return Err(AppError::operational(
                "clock domain identifier must be nonempty",
            ));
        }
        let scale = value.frequency_hz.tick_scale()?;
        let (modulus, maximum) = value
            .wrap
            .map(|wrap| (Some(wrap.modulus), Some(wrap.max_forward_ticks)))
            .unwrap_or((None, None));
        ClockDomainSpec::new(value.domain_id, scale, modulus, maximum)
            .map_err(AppError::operational)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RationalFrequencyConfig {
    numerator: u64,
    denominator: u64,
}

impl RationalFrequencyConfig {
    fn tick_scale(&self) -> Result<RationalTickScale, AppError> {
        if self.numerator == 0 || self.denominator == 0 {
            return Err(AppError::operational(
                "clock frequency numerator and denominator must be nonzero",
            ));
        }
        let cross = gcd(1_000_000_000, self.numerator);
        let nanoseconds_base = 1_000_000_000 / cross;
        let tick_denominator = self.numerator / cross;
        let nanoseconds_numerator = nanoseconds_base
            .checked_mul(self.denominator)
            .ok_or_else(|| AppError::operational("clock rational frequency overflows u64"))?;
        RationalTickScale::new(nanoseconds_numerator, tick_denominator)
            .map_err(AppError::operational)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WrapConfig {
    modulus: u64,
    max_forward_ticks: u64,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum ClockOriginConfig {
    FirstRecord { session_ns: i64 },
    Explicit { ticks: u64, session_ns: i64 },
}

impl ClockOriginConfig {
    const fn parts(self) -> (Option<u64>, i64) {
        match self {
            Self::FirstRecord { session_ns } => (None, session_ns),
            Self::Explicit { ticks, session_ns } => (Some(ticks), session_ns),
        }
    }
}

const fn gcd(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        io::{BufReader, Write as _},
    };

    use object::{
        Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope,
        write::{Object, StandardSection, Symbol, SymbolSection},
    };
    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};
    use t32perf_model::{
        AdapterInfo, ArtifactPath, CaptureConfigDocument, CaptureConfigSchemaVersion,
        CaptureDurationConfig, CaptureRtosAwarenessConfig, CaptureSinkConfig,
        CaptureTimestampConfig, CaptureTriggerConfig, ContextKind, InitialTargetState, Quality,
        SessionError, SessionStatus, Sha256Digest,
    };
    use t32perf_session::{ArtifactRoot, ArtifactSpec, Session, SessionId, SessionLimits};
    use t32perf_trace32::{
        AdapterRequest, CWireSourceConfig, ClockDomainSpec, ControllerCaptureCompletionEvidence,
        ControllerHealthEvidenceV2, ControllerProgramFlowHealthEvidence, ControllerScriptResponse,
        ControllerStopEvidence, ControllerStopEvidenceV2, ControllerTargetAdapterBinding,
        ControllerTargetState, PerfOperation, PerfStatus, RationalTickScale,
        TargetAdapterCaptureContract, TargetAdapterCaptureKind,
        TargetAdapterCustomEventCollectorContract, TargetAdapterQualificationReceipt,
        TargetAdapterQualificationReceiptSchemaVersion, TargetAdapterScenario,
        Trace32SymbolMappingDocument, Trace32TaskEventsMappingDocument,
        Trace32TaskEventsMappingTemplateDocument,
        Trace32ValidatedAdapterContext as Trace32QualifiedAdapterContext,
        Trace32ValidatedCaptureKind as Trace32QualifiedCaptureKind,
        Trace32ValidatedMapping as Trace32QualifiedMapping,
        Trace32ValidatedRawInputIdentity as Trace32RawInputIdentity,
        Trace32ValidatedRuntime as Trace32QualifiedRuntime, TraceArtifactBinding,
        TraceContextMapping, TraceTaskMetadataRole,
        ValidatedTargetAdapterReceipt as QualifiedTargetAdapter,
        ValidatedTrace32AdapterRegistry as QualifiedTrace32AdapterRegistry, WireLimits,
        parse_trace32_task_events_mapping, tc234l_build190766_candidate_profile,
        tc234l_snooper_capture_config,
    };
    use tempfile::TempDir;

    use super::{
        AcceptedTrace32RuntimeBinding, BUILD_RESOURCE_PRODUCER, ClockOriginConfig,
        HARD_MAX_DICTIONARY_BYTES, HARD_MAX_DICTIONARY_ENTRIES, LineLimits, MAX_CONFIG_LINE_BYTES,
        MAX_TRACE32_MAPPING_BYTES, MultiSourceOrderConfig, NORMALIZE_CONFIG_SCHEMA,
        NORMALIZE_PRODUCER, NormalizeConfig, NormalizeSourceConfig,
        TASK_EVENTS_MAPPING_TEMPLATE_ARTIFACT_ID, TRACE32_SYMBOL_MAPPING_ARTIFACT_ID,
        Trace32AsciiSourceRequest, Trace32OpenContext, Trace32TaskEventsSourceRequest,
        decode_config_json, ensure_normalized, open_trace32_ascii_source_with_binding,
        read_bounded_artifact_bytes, validate_c_wire_config_against_collector,
        validate_trace32_task_events_binding, validated_runtime_qualification,
    };

    fn executable_elf_fixture() -> Vec<u8> {
        let mut object = Object::new(BinaryFormat::Elf, Architecture::Arm, Endianness::Little);
        let text = object.section_id(StandardSection::Text);
        object.set_section_data(text, vec![0_u8; 64], 4);
        object.add_symbol(Symbol {
            name: b"sampled_function".to_vec(),
            value: 0,
            size: 16,
            kind: SymbolKind::Text,
            scope: SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Section(text),
            flags: SymbolFlags::None,
        });
        let mut bytes = object.write().unwrap();
        bytes[16] = 2;
        bytes[17] = 0;
        bytes
    }

    struct TestArtifactSpec<'a> {
        id: &'a str,
        kind: &'a str,
        path: &'a str,
        media_type: &'a str,
        producer: &'a str,
    }

    fn write_artifact(
        session: &Session,
        lock: &t32perf_session::SessionLock,
        spec: TestArtifactSpec<'_>,
        bytes: &[u8],
    ) -> t32perf_model::Artifact {
        write_artifact_with_inputs(session, lock, spec, Vec::new(), bytes)
    }

    fn write_artifact_with_inputs(
        session: &Session,
        lock: &t32perf_session::SessionLock,
        spec: TestArtifactSpec<'_>,
        input_artifact_ids: Vec<String>,
        bytes: &[u8],
    ) -> t32perf_model::Artifact {
        let mut writer = session
            .create_artifact(
                lock,
                ArtifactSpec {
                    id: spec.id.to_owned(),
                    kind: spec.kind.to_owned(),
                    relative_path: ArtifactPath::new(spec.path).unwrap(),
                    media_type: spec.media_type.to_owned(),
                    producer: spec.producer.to_owned(),
                    input_artifact_ids,
                },
            )
            .unwrap();
        writer.write_all(bytes).unwrap();
        session.commit_artifact(lock, writer).unwrap()
    }

    fn canonical_capture_config(session_id: &str) -> CaptureConfigDocument {
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
                observation_limit: Some(16),
            },
            workload_identity: "normalize-ensure-fixture/v1".to_owned(),
            initial_target_state: InitialTargetState::Running,
            rtos_awareness: CaptureRtosAwarenessConfig {
                kind: "none".to_owned(),
                metadata_artifact_ids: Vec::new(),
            },
            instrumentation: None,
            adapter_parameters: BTreeMap::new(),
        }
    }

    fn ensure_fixture() -> (TempDir, ArtifactRoot, String) {
        let temporary = TempDir::new().unwrap();
        let root = ArtifactRoot::open(temporary.path().join("sessions"), SessionLimits::default())
            .unwrap();
        let session = root
            .create_session_with_id(SessionId::new("normalize-ensure").unwrap(), &json!({}))
            .unwrap();
        let session_id = session.id().to_string();
        let lock = session.try_lock().unwrap();
        session
            .write_json_artifact(
                &lock,
                ArtifactSpec {
                    id: "capture-config".to_owned(),
                    kind: "capture_config".to_owned(),
                    relative_path: ArtifactPath::new("capture/capture-config.json").unwrap(),
                    media_type: "application/json".to_owned(),
                    producer: "t32perf.fixture.synthetic/v1".to_owned(),
                    input_artifact_ids: Vec::new(),
                },
                &canonical_capture_config(&session_id),
            )
            .unwrap();
        write_artifact(
            &session,
            &lock,
            TestArtifactSpec {
                id: "raw-input",
                kind: "raw_observations",
                path: "capture/raw.ndjson",
                media_type: "application/x-ndjson",
                producer: "test.fixture/v1",
            },
            format!(
                concat!(
                    "{{\"schema\":\"t32perf.observation/v1\",\"session_id\":\"{session_id}\",\"encoding\":\"ndjson\",\"time_unit\":\"ns\",\"time_origin\":\"session_relative\",\"properties\":{{}}}}\n",
                    "{{\"source_id\":\"fixture\",\"source_seq\":0,\"quality\":\"exact\",\"type\":\"Instant\",\"ts_ns\":0,\"name\":\"ready\"}}\n"
                ),
                session_id = session_id,
            )
            .as_bytes(),
        );
        session
            .write_json_artifact(
                &lock,
                ArtifactSpec {
                    id: "normalize-config".to_owned(),
                    kind: "normalization_config".to_owned(),
                    relative_path: ArtifactPath::new("capture/normalize-config.json").unwrap(),
                    media_type: "application/json".to_owned(),
                    producer: "test.fixture/v1".to_owned(),
                    input_artifact_ids: Vec::new(),
                },
                &json!({
                    "schema": NORMALIZE_CONFIG_SCHEMA,
                    "mode": "single_source",
                    "source": {
                        "adapter": "canonical_ndjson_v1",
                        "source_id": "fixture",
                        "limits": {"max_line_bytes": 4096, "max_records": 16}
                    },
                    "output_limits": {"max_line_bytes": 4096, "max_records": 16}
                }),
            )
            .unwrap();
        session
            .transition(&lock, SessionStatus::Capturing, None)
            .unwrap();
        session
            .transition(&lock, SessionStatus::Captured, None)
            .unwrap();
        drop(lock);
        (temporary, root, session_id)
    }

    #[test]
    fn ensure_normalized_revalidates_a_complete_marker_without_rewriting_it() {
        let (_temporary, root, session_id) = ensure_fixture();
        let fresh =
            ensure_normalized(&root, &session_id, Some("raw-input"), "normalize-config").unwrap();
        assert!(!fresh.resumed);
        let artifact = fresh.outcome.result["artifact"].clone();
        let output = root
            .path()
            .join(&session_id)
            .join("normalized/observations.ndjson");
        let modified = std::fs::metadata(&output).unwrap().modified().unwrap();

        let resumed =
            ensure_normalized(&root, &session_id, Some("raw-input"), "normalize-config").unwrap();
        assert!(resumed.resumed);
        assert_eq!(resumed.outcome.result["artifact"], artifact);
        assert_eq!(
            std::fs::metadata(output).unwrap().modified().unwrap(),
            modified
        );
    }

    #[test]
    fn ensure_normalized_rejects_tampered_completion_and_failed_state_without_writes() {
        let (_temporary, root, session_id) = ensure_fixture();
        ensure_normalized(&root, &session_id, Some("raw-input"), "normalize-config").unwrap();
        let output = root
            .path()
            .join(&session_id)
            .join("normalized/observations.ndjson");
        let original = std::fs::read(&output).unwrap();
        std::fs::write(&output, b"not canonical ndjson\n").unwrap();
        assert!(
            ensure_normalized(&root, &session_id, Some("raw-input"), "normalize-config").is_err()
        );
        std::fs::write(&output, original).unwrap();

        let session = root
            .session(&SessionId::new(session_id.clone()).unwrap())
            .unwrap();
        let lock = session.try_lock().unwrap();
        let before = session.registered_artifacts(false).unwrap();
        session
            .transition(
                &lock,
                SessionStatus::Failed,
                Some(SessionError {
                    code: "TEST_FAILURE".to_owned(),
                    message: "fixture failure".to_owned(),
                    details: BTreeMap::new(),
                }),
            )
            .unwrap();
        drop(lock);
        assert!(
            ensure_normalized(&root, &session_id, Some("raw-input"), "normalize-config").is_err()
        );
        assert_eq!(session.registered_artifacts(false).unwrap(), before);
    }

    #[test]
    fn ensure_normalized_invalid_input_does_not_transition_the_session_to_failed() {
        let (_temporary, root, session_id) = ensure_fixture();
        assert!(
            ensure_normalized(
                &root,
                &session_id,
                Some("missing-input"),
                "normalize-config"
            )
            .is_err()
        );
        let session = root.session(&SessionId::new(session_id).unwrap()).unwrap();
        assert_eq!(
            session.read_state().unwrap().status,
            SessionStatus::Captured
        );
    }

    #[test]
    fn qualified_trace32_registry_requires_exact_admission_receipt_profile_raw_and_mapping() {
        let mut candidate = tc234l_build190766_candidate_profile();
        let hil_digest = Sha256Digest::new("a".repeat(64)).unwrap();
        let receipt_without_claim = TargetAdapterQualificationReceipt {
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
            hil_verification_receipt_sha256: hil_digest,
        };
        let receipt_bytes = serde_json::to_vec(&receipt_without_claim).unwrap();
        let receipt_binding = TraceArtifactBinding {
            artifact_id: "target-adapter-qualification".to_owned(),
            sha256: t32perf_model::Sha256Digest::new(
                Sha256::digest(&receipt_bytes)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            )
            .unwrap(),
        };
        candidate.qualification_sha256 = Some(receipt_binding.sha256.clone());
        let qualified = QualifiedTargetAdapter::validate_for(
            candidate.clone(),
            &receipt_bytes,
            receipt_binding.clone(),
        )
        .unwrap();
        let raw = TraceArtifactBinding {
            artifact_id: "controller-export".to_owned(),
            sha256: Sha256Digest::new("b".repeat(64)).unwrap(),
        };
        let health = TraceArtifactBinding {
            artifact_id: "controller-health".to_owned(),
            sha256: Sha256Digest::new("c".repeat(64)).unwrap(),
        };
        let stop = TraceArtifactBinding {
            artifact_id: "controller-stop".to_owned(),
            sha256: Sha256Digest::new("d".repeat(64)).unwrap(),
        };
        let mapping = Trace32SymbolMappingDocument {
            schema: t32perf_trace32::TRACE32_SYMBOL_MAPPING_SCHEMA.to_owned(),
            profile_id: t32perf_trace32::TC234L_SNOOPER_ASCII_PROFILE_V1.to_owned(),
            profile_sha256: Some(candidate.digest().unwrap()),
            trace32_release: candidate.build_gate.trace32_release.clone(),
            trace32_build: candidate.build_gate.minimum_build,
            architecture_package: candidate.build_gate.architecture_package.clone(),
            target_identifier: candidate.target_identifier.clone(),
            elf_artifact_id: "firmware-elf".to_owned(),
            elf_sha256: candidate.firmware_elf_sha256.clone(),
            controller_health: health.clone(),
            time_origin_evidence: stop.clone(),
            qualification_receipt: receipt_binding.clone(),
            address_classes: vec!["P".to_owned()],
            functions: t32perf_trace32::trace_function_mappings_from_elf(
                &executable_elf_fixture(),
                "firmware-elf",
                t32perf_trace32::MAX_TRACE32_FUNCTION_RANGES,
            )
            .unwrap(),
        };
        mapping.validate().unwrap();
        let runtime = Trace32QualifiedRuntime {
            trace32_release: candidate.build_gate.trace32_release.clone(),
            trace32_build: candidate.build_gate.minimum_build,
            architecture_package: candidate.build_gate.architecture_package.clone(),
            target_identifier: candidate.target_identifier.clone(),
            core_id: 0,
            clock_domain: "snooper_host_time".to_owned(),
            elf: TraceArtifactBinding {
                artifact_id: "firmware-elf".to_owned(),
                sha256: candidate.firmware_elf_sha256.clone(),
            },
            controller_health: health,
            time_origin_evidence: stop,
            raw_input: raw.clone(),
        };
        let context = || Trace32QualifiedAdapterContext {
            validated_receipt: qualified.clone(),
            raw_input: Trace32RawInputIdentity {
                artifact: raw.clone(),
                capture_kind: Trace32QualifiedCaptureKind::AsciiSymbolMapping,
            },
            mapping: Trace32QualifiedMapping::AsciiSymbolMapping(mapping.clone()),
            runtime: runtime.clone(),
            limits: LineLimits::default(),
        };
        let registry = QualifiedTrace32AdapterRegistry::defaults().unwrap();
        registry
            .open(
                context(),
                AdapterRequest::new("qualified-registry", "ascii")
                    .with_input(BufReader::new(&b""[..])),
            )
            .unwrap();

        let mut raw_drift = context();
        raw_drift.runtime.raw_input.artifact_id = "different-export".to_owned();
        assert!(
            registry
                .open(
                    raw_drift,
                    AdapterRequest::new("qualified-registry", "ascii")
                        .with_input(BufReader::new(&b""[..])),
                )
                .is_err()
        );
        let mut mapping_drift = context();
        let Trace32QualifiedMapping::AsciiSymbolMapping(mapping) = &mut mapping_drift.mapping
        else {
            unreachable!()
        };
        mapping.profile_id = "different-profile".to_owned();
        assert!(
            registry
                .open(
                    mapping_drift,
                    AdapterRequest::new("qualified-registry", "ascii")
                        .with_input(BufReader::new(&b""[..])),
                )
                .is_err()
        );
        let mut profile_drift = candidate.clone();
        profile_drift.adapter_version = "different-version".to_owned();
        assert!(
            QualifiedTargetAdapter::validate_for(
                profile_drift,
                &receipt_bytes,
                receipt_binding.clone()
            )
            .is_err()
        );
        let mut receipt_drift = receipt_bytes.clone();
        receipt_drift.push(b' ');
        assert!(
            QualifiedTargetAdapter::validate_for(
                candidate.clone(),
                &receipt_drift,
                receipt_binding.clone()
            )
            .is_err()
        );
        let unqualified = tc234l_build190766_candidate_profile();
        assert!(
            QualifiedTargetAdapter::validate_for(unqualified, &receipt_bytes, receipt_binding)
                .is_err()
        );
    }

    #[test]
    fn incomplete_ascii_qualification_fixture_is_fail_closed() {
        let temp = TempDir::new().unwrap();
        let artifact_root = ArtifactRoot::open(temp.path(), SessionLimits::default()).unwrap();
        let session = artifact_root
            .create_session_with_id(
                SessionId::new("qualified-ascii-builder").unwrap(),
                &json!({}),
            )
            .unwrap();
        let lock = session.try_lock().unwrap();
        let firmware = write_artifact(
            &session,
            &lock,
            TestArtifactSpec {
                id: "firmware-elf",
                kind: "firmware_elf",
                path: "capture/firmware.elf",
                media_type: "application/x-elf",
                producer: "test.deployment/v1",
            },
            &executable_elf_fixture(),
        );
        let raw = write_artifact(
            &session,
            &lock,
            TestArtifactSpec {
                id: "controller-raw-export",
                kind: "raw_trace",
                path: "capture/raw/trace32-ascii.txt",
                media_type: "text/plain",
                producer: crate::controller::CONTROLLER_PRODUCER,
            },
            b"+00000000000001 P:00000000 snoop 0.000000000s sampled_function\n",
        );
        let capabilities = write_artifact(
            &session,
            &lock,
            TestArtifactSpec {
                id: "controller-capabilities",
                kind: "trace32_control_evidence",
                path: "logs/controller/capabilities.json",
                media_type: "application/json",
                producer: crate::controller::CONTROLLER_PRODUCER,
            },
            b"{}\n",
        );
        let stop = write_artifact(
            &session,
            &lock,
            TestArtifactSpec {
                id: "controller-stop",
                kind: "trace32_control_evidence",
                path: "logs/controller/stop.json",
                media_type: "application/json",
                producer: crate::controller::CONTROLLER_PRODUCER,
            },
            b"{}\n",
        );
        let health = write_artifact(
            &session,
            &lock,
            TestArtifactSpec {
                id: "controller-health",
                kind: "trace32_control_evidence",
                path: "logs/controller/health.json",
                media_type: "application/json",
                producer: crate::controller::CONTROLLER_PRODUCER,
            },
            b"{}\n",
        );
        let receipt: TargetAdapterQualificationReceipt = serde_json::from_value(json!({
            "schema": "t32perf.target-adapter-qualification-receipt/v1",
            "adapter_id": "tricore-tc234l-snooper-pc-r2026.02-b190766-v1",
            "adapter_version": "1.0.0",
            "candidate_profile_sha256": "11".repeat(32),
            "implementation_sha256": "22".repeat(32),
            "trace32_release": "2026.02",
            "trace32_build": 190766,
            "architecture_package": "tricore",
            "target_identifier": "infineon-tc234l-core0",
            "probe_identifier": "test-probe",
            "firmware_elf_sha256": firmware.sha256,
            "t32mcp_version": "0.2.2",
            "hil_verification_receipt_sha256": "33".repeat(32)
        }))
        .unwrap();
        let receipt_bytes = serde_json::to_vec(&receipt).unwrap();
        let qualification = write_artifact(
            &session,
            &lock,
            TestArtifactSpec {
                id: crate::controller::TARGET_ADAPTER_QUALIFICATION_ARTIFACT_ID,
                kind: crate::controller::TARGET_ADAPTER_QUALIFICATION_KIND,
                path: "capture/target-adapter-qualification.json",
                media_type: "application/json",
                producer: crate::controller::TARGET_ADAPTER_QUALIFICATION_PRODUCER,
            },
            &receipt_bytes,
        );
        let mut capture_config = tc234l_snooper_capture_config(
            session.id().as_str(),
            ControllerTargetState::Halted,
            65_536,
        );
        capture_config
            .adapter_parameters
            .insert("firmware.elf_sha256".to_owned(), json!(firmware.sha256));
        session
            .write_json_artifact(
                &lock,
                ArtifactSpec {
                    id: "capture-config".to_owned(),
                    kind: "capture_config".to_owned(),
                    relative_path: ArtifactPath::new("capture/capture-config.json").unwrap(),
                    media_type: "application/json".to_owned(),
                    producer: "test.capture-config/v1".to_owned(),
                    input_artifact_ids: Vec::new(),
                },
                &capture_config,
            )
            .unwrap();
        let sampling_stop: ControllerStopEvidenceV2 = serde_json::from_value(json!({
            "schema": "t32perf.controller-stop-evidence/v2",
            "operation": "perf_stop",
            "binding_sha256": "44".repeat(32),
            "capture_stopped": true,
            "workload_identity": "external-owner-sampling-window/v1",
            "target_state_after_stop": "halted",
            "pre_stop_state": "arm",
            "capacity_records": 65536,
            "recorded_records": 1,
            "time_origin_zeroed_to_first_record": true
        }))
        .unwrap();
        let sampling_health: ControllerHealthEvidenceV2 = serde_json::from_value(json!({
            "schema": "t32perf.controller-health-evidence/v2",
            "operation": "perf_get_health",
            "binding_sha256": "55".repeat(32),
            "capture_stopped": true,
            "supported_signals": [
                "sampling_buffer_full",
                "sampling_unexpected_stop",
                "elf_mismatch"
            ],
            "stop_evidence_sha256": stop.sha256,
            "sampling": {
                "method": "real_time",
                "object": "program_counter",
                "buffer_mode": "stack",
                "state": "off",
                "pre_stop_state": "arm",
                "requested_rate_ns": 1000000,
                "capacity_records": 65536,
                "recorded_records": 1,
                "buffer_full": false,
                "unexpected_stop": false
            },
            "elf_matches_firmware": true
        }))
        .unwrap();
        let capture_contract = tc234l_build190766_candidate_profile()
            .scenario(TargetAdapterScenario::Normal)
            .unwrap()
            .capture
            .clone();
        let binding = AcceptedTrace32RuntimeBinding {
            trace32_release: "2026.02".to_owned(),
            trace32_build: 190_766,
            architecture_package: "tricore".to_owned(),
            target_identifier: "infineon-tc234l-core0".to_owned(),
            probe_identifier: "test-probe".to_owned(),
            initial_target_state: ControllerTargetState::Halted,
            target_adapter: ControllerTargetAdapterBinding {
                adapter_id: "tricore-tc234l-snooper-pc-r2026.02-b190766-v1".to_owned(),
                adapter_version: "1.0.0".to_owned(),
                trace32_release: "2026.02".to_owned(),
                trace32_build: 190_766,
                architecture_package: "tricore".to_owned(),
                target_identifier: "infineon-tc234l-core0".to_owned(),
                probe_identifier: "test-probe".to_owned(),
                profile_sha256: Sha256Digest::new("66".repeat(32)).unwrap(),
                implementation_sha256: receipt.implementation_sha256.clone(),
                scenario: TargetAdapterScenario::Normal,
                capture_kind: TargetAdapterCaptureKind::Sampling {
                    capacity_records: 65_536,
                },
                controller_protocol: t32perf_trace32::TargetAdapterControllerProtocol::V1,
                custom_event_collector: None,
                qualification_sha256: Some(qualification.sha256.clone()),
            },
            capture_contract,
            qualification_artifact: Some(qualification.clone()),
            qualification_provenance_artifacts: vec![qualification.clone()],
            qualification_receipt: Some(receipt),
            firmware_elf_artifact: firmware.clone(),
            firmware_measurement_artifact: firmware.clone(),
            capabilities_artifact: capabilities,
            configure_artifact: stop.clone(),
            start_artifact: stop.clone(),
            health_artifact: health,
            stop_artifact: stop,
            export_artifact: raw.clone(),
            custom_event_artifact: None,
            cleanup_artifact: raw.clone(),
            export_response: ControllerScriptResponse {
                operation: PerfOperation::Export,
                status: PerfStatus::Ok,
                code: "raw_ascii_exported".to_owned(),
                files_deleted: None,
            },
            completion: ControllerCaptureCompletionEvidence::Sampling {
                health: sampling_health,
                stop: sampling_stop,
            },
        };
        let artifacts = session.registered_artifacts(true).unwrap();
        let raw_catalog = artifacts
            .iter()
            .find(|artifact| artifact.id == raw.id)
            .unwrap();
        let legacy_rejected = open_trace32_ascii_source_with_binding(
            Trace32OpenContext {
                session: &session,
                lock: &lock,
                artifacts: &artifacts,
                capture_config: &capture_config,
                input: raw_catalog,
                file: session.open_artifact(raw_catalog).unwrap(),
            },
            Trace32AsciiSourceRequest {
                source_id: "snooper".to_owned(),
                expected_profile_id: "t32perf.trace32-ascii-profile/tc234l-build190766-v1"
                    .to_owned(),
                firmware_elf_artifact_id: "firmware-elf".to_owned(),
                limits: LineLimits::default(),
            },
            binding.clone(),
        )
        .is_err();
        assert!(legacy_rejected);
        if !legacy_rejected {
            let mut opened = open_trace32_ascii_source_with_binding(
                Trace32OpenContext {
                    session: &session,
                    lock: &lock,
                    artifacts: &artifacts,
                    capture_config: &capture_config,
                    input: raw_catalog,
                    file: session.open_artifact(raw_catalog).unwrap(),
                },
                Trace32AsciiSourceRequest {
                    source_id: "snooper".to_owned(),
                    expected_profile_id: "t32perf.trace32-ascii-profile/tc234l-build190766-v1"
                        .to_owned(),
                    firmware_elf_artifact_id: "firmware-elf".to_owned(),
                    limits: LineLimits::default(),
                },
                binding.clone(),
            )
            .unwrap();
            let observation = opened.source.next_observation().unwrap().unwrap();
            assert_eq!(observation.observation.quality, Quality::Statistical);
            assert!(opened.source.next_observation().unwrap().is_none());
            assert!(
                opened.provenance_artifact_ids.contains(
                    &crate::controller::TARGET_ADAPTER_QUALIFICATION_ARTIFACT_ID.to_owned()
                )
            );
            drop(opened);

            let artifacts = session.registered_artifacts(true).unwrap();
            let mapping = artifacts
                .iter()
                .find(|artifact| artifact.id == TRACE32_SYMBOL_MAPPING_ARTIFACT_ID)
                .expect("host-derived symbol mapping");
            assert_eq!(mapping.producer, NORMALIZE_PRODUCER);
            assert!(
                mapping
                    .input_artifact_ids
                    .contains(&binding.stop_artifact.id)
            );
            assert!(mapping.input_artifact_ids.contains(&qualification.id));
            let raw_catalog = artifacts
                .iter()
                .find(|artifact| artifact.id == raw.id)
                .unwrap();
            let reopened = open_trace32_ascii_source_with_binding(
                Trace32OpenContext {
                    session: &session,
                    lock: &lock,
                    artifacts: &artifacts,
                    capture_config: &capture_config,
                    input: raw_catalog,
                    file: session.open_artifact(raw_catalog).unwrap(),
                },
                Trace32AsciiSourceRequest {
                    source_id: "snooper".to_owned(),
                    expected_profile_id: "t32perf.trace32-ascii-profile/tc234l-build190766-v1"
                        .to_owned(),
                    firmware_elf_artifact_id: "firmware-elf".to_owned(),
                    limits: LineLimits::default(),
                },
                binding.clone(),
            )
            .unwrap();
            drop(reopened);
            assert_eq!(
                session
                    .registered_artifacts(true)
                    .unwrap()
                    .iter()
                    .filter(|artifact| artifact.id == TRACE32_SYMBOL_MAPPING_ARTIFACT_ID)
                    .count(),
                1
            );

            // The ASCII runtime family cannot be relabelled as a TASKEVENTS completion.
            let artifacts = session.registered_artifacts(true).unwrap();
            let raw_catalog = artifacts
                .iter()
                .find(|artifact| artifact.id == raw.id)
                .unwrap();
            let task_events_mapping = Trace32TaskEventsMappingDocument {
                schema: t32perf_trace32::TRACE32_TASK_EVENTS_MAPPING_SCHEMA.to_owned(),
                profile_id: "t32perf.trace32-task-events-profile/tc234l-build190766-v1".to_owned(),
                profile_sha256: Sha256Digest::new("77".repeat(32)).unwrap(),
                trace32_release: binding.trace32_release.clone(),
                trace32_build: binding.trace32_build,
                architecture_package: binding.architecture_package.clone(),
                target_identifier: binding.target_identifier.clone(),
                core_id: 0,
                elf_artifact_id: firmware.id.clone(),
                elf_sha256: firmware.sha256.clone(),
                metadata_artifacts: Vec::new(),
                controller_health: TraceArtifactBinding {
                    artifact_id: binding.health_artifact.id.clone(),
                    sha256: binding.health_artifact.sha256.clone(),
                },
                time_origin_evidence: TraceArtifactBinding {
                    artifact_id: binding.stop_artifact.id.clone(),
                    sha256: binding.stop_artifact.sha256.clone(),
                },
                qualification_receipt: TraceArtifactBinding {
                    artifact_id: qualification.id.clone(),
                    sha256: qualification.sha256.clone(),
                },
                contexts: Vec::new(),
                functions: Vec::new(),
                runnables: Vec::new(),
            };
            let task_qualification =
                validated_runtime_qualification(&binding, "test.task-events.qualification")
                    .unwrap();
            let error = validate_trace32_task_events_binding(
                &Trace32OpenContext {
                    session: &session,
                    lock: &lock,
                    artifacts: &artifacts,
                    capture_config: &capture_config,
                    input: raw_catalog,
                    file: session.open_artifact(raw_catalog).unwrap(),
                },
                &Trace32TaskEventsSourceRequest {
                    source_id: "tc234l-taskevents".to_owned(),
                    expected_profile_id:
                        "t32perf.trace32-task-events-profile/tc234l-build190766-v1".to_owned(),
                    firmware_elf_artifact_id: firmware.id.clone(),
                    mapping_artifact_id: "trace32-task-events-mapping".to_owned(),
                    limits: LineLimits::default(),
                },
                &binding,
                &task_qualification,
                raw_catalog,
                &task_events_mapping,
            )
            .expect_err("sampling completion must reject TASKEVENTS normalization");
            assert!(error.message.contains("program-flow completion"));

            let mut mismatched_binding = binding;
            let ControllerCaptureCompletionEvidence::Sampling { stop, .. } =
                &mut mismatched_binding.completion
            else {
                panic!("fixture must remain sampling");
            };
            stop.recorded_records = 2;
            let artifacts = session.registered_artifacts(true).unwrap();
            let raw_catalog = artifacts
                .iter()
                .find(|artifact| artifact.id == raw.id)
                .unwrap();
            let mut mismatched = open_trace32_ascii_source_with_binding(
                Trace32OpenContext {
                    session: &session,
                    lock: &lock,
                    artifacts: &artifacts,
                    capture_config: &capture_config,
                    input: raw_catalog,
                    file: session.open_artifact(raw_catalog).unwrap(),
                },
                Trace32AsciiSourceRequest {
                    source_id: "snooper".to_owned(),
                    expected_profile_id: "t32perf.trace32-ascii-profile/tc234l-build190766-v1"
                        .to_owned(),
                    firmware_elf_artifact_id: "firmware-elf".to_owned(),
                    limits: LineLimits::default(),
                },
                mismatched_binding,
            )
            .unwrap();
            assert!(mismatched.source.next_observation().unwrap().is_some());
            let error = mismatched.source.next_observation().unwrap_err();
            assert!(error.to_string().contains("declares 2"));
        }
    }

    #[test]
    fn qualified_program_flow_binding_requires_exact_profile_metadata_and_stop_health() {
        let temp = TempDir::new().unwrap();
        let artifact_root = ArtifactRoot::open(temp.path(), SessionLimits::default()).unwrap();
        let session = artifact_root
            .create_session_with_id(
                SessionId::new("qualified-program-flow").unwrap(),
                &json!({}),
            )
            .unwrap();
        let lock = session.try_lock().unwrap();
        let firmware = write_artifact(
            &session,
            &lock,
            TestArtifactSpec {
                id: "firmware-elf",
                kind: "firmware_elf",
                path: "capture/firmware.elf",
                media_type: "application/x-elf",
                producer: "test.deployment/v1",
            },
            &executable_elf_fixture(),
        );
        let raw = write_artifact(
            &session,
            &lock,
            TestArtifactSpec {
                id: "controller-task-events-export",
                kind: "raw_trace",
                path: "capture/raw/controller-fixture.trace32-task-events.txt",
                media_type: "text/plain",
                producer: crate::controller::CONTROLLER_PRODUCER,
            },
            b"# Task events trace file\n# time(ns); task name; event;\n0; TaskA; task Start;\n1; TaskA; task Stop;\n",
        );
        let capabilities = write_artifact(
            &session,
            &lock,
            TestArtifactSpec {
                id: "controller-capabilities",
                kind: "trace32_control_evidence",
                path: "capture/control/capabilities.json",
                media_type: "application/json",
                producer: crate::controller::CONTROLLER_PRODUCER,
            },
            b"{}\n",
        );
        let stop_artifact = write_artifact(
            &session,
            &lock,
            TestArtifactSpec {
                id: "controller-stop",
                kind: "trace32_control_evidence",
                path: "capture/control/stop.json",
                media_type: "application/json",
                producer: crate::controller::CONTROLLER_PRODUCER,
            },
            b"{}\n",
        );
        let health_artifact = write_artifact(
            &session,
            &lock,
            TestArtifactSpec {
                id: "controller-health",
                kind: "trace32_control_evidence",
                path: "capture/control/health.json",
                media_type: "application/json",
                producer: crate::controller::CONTROLLER_PRODUCER,
            },
            b"{}\n",
        );
        let orti = write_artifact(
            &session,
            &lock,
            TestArtifactSpec {
                id: "fixture-orti",
                kind: "trace32_orti_metadata",
                path: "capture/deployment/fixture.orti",
                media_type: "text/plain",
                producer: "test.deployment/v1",
            },
            b"fixture ORTI\n",
        );
        let markers = write_artifact(
            &session,
            &lock,
            TestArtifactSpec {
                id: "fixture-task-markers",
                kind: "trace32_task_marker_metadata",
                path: "capture/deployment/fixture-task-markers.json",
                media_type: "application/json",
                producer: "test.deployment/v1",
            },
            b"{}\n",
        );
        let profile_sha256 = Sha256Digest::new("66".repeat(32)).unwrap();
        let receipt: TargetAdapterQualificationReceipt = serde_json::from_value(json!({
            "schema": "t32perf.target-adapter-qualification-receipt/v1",
            "adapter_id": "fixture-program-flow-adapter",
            "adapter_version": "1.0.0",
            "candidate_profile_sha256": profile_sha256,
            "implementation_sha256": "22".repeat(32),
            "trace32_release": "2026.02",
            "trace32_build": 190766,
            "architecture_package": "tricore",
            "target_identifier": "fixture-tc234l-core0",
            "probe_identifier": "fixture-probe",
            "firmware_elf_sha256": firmware.sha256,
            "t32mcp_version": "0.2.2",
            "hil_verification_receipt_sha256": "33".repeat(32)
        }))
        .unwrap();
        let qualification = write_artifact(
            &session,
            &lock,
            TestArtifactSpec {
                id: crate::controller::TARGET_ADAPTER_QUALIFICATION_ARTIFACT_ID,
                kind: crate::controller::TARGET_ADAPTER_QUALIFICATION_KIND,
                path: "capture/target-adapter-qualification.json",
                media_type: "application/json",
                producer: crate::controller::TARGET_ADAPTER_QUALIFICATION_PRODUCER,
            },
            &serde_json::to_vec(&receipt).unwrap(),
        );
        let export_profile_id = "fixture.task-events/v1";
        let rtos_awareness = "fixture-orti-awareness/v1";
        let timestamp_clock_id = "fixture-trace-clock/v1";
        let capture_kind = TargetAdapterCaptureKind::ProgramFlowTaskEvents {
            export_profile_id: export_profile_id.to_owned(),
            rtos_awareness: rtos_awareness.to_owned(),
            timestamp_clock_id: timestamp_clock_id.to_owned(),
            orti_artifact_id: orti.id.clone(),
            task_marker_artifact_id: markers.id.clone(),
        };
        let capture_contract = TargetAdapterCaptureContract {
            configuration_sha256_by_initial_state: BTreeMap::from([(
                ControllerTargetState::Halted,
                Sha256Digest::new("77".repeat(32)).unwrap(),
            )]),
            capture_mode: "fixture-program-flow/v1".to_owned(),
            trace_sink: "fixture-trace-memory/v1".to_owned(),
            capture_kind: capture_kind.clone(),
            timestamp_enabled: true,
            workload_identity: "fixture-program-flow-workload/v1".to_owned(),
            covered_cores: vec![0],
            supported_initial_states: vec![ControllerTargetState::Halted],
        };
        let stop: ControllerStopEvidence = serde_json::from_value(json!({
            "schema": "t32perf.controller-stop-evidence/v1",
            "operation": "perf_stop",
            "binding_sha256": "44".repeat(32),
            "capture_stopped": true,
            "workload_completed": true,
            "workload_identity": capture_contract.workload_identity,
            "target_state_after_stop": "halted"
        }))
        .unwrap();
        let health: ControllerProgramFlowHealthEvidence = serde_json::from_value(json!({
            "schema": "t32perf.controller-health-evidence/v3",
            "operation": "perf_get_health",
            "binding_sha256": "55".repeat(32),
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
            "stop_evidence_sha256": stop_artifact.sha256,
            "trace_overflow": false,
            "flow_error": false,
            "trace_gap": false,
            "truncated": false,
            "timestamp_discontinuity": false,
            "elf_matches_firmware": true,
            "program_flow_closed": true
        }))
        .unwrap();
        let binding = AcceptedTrace32RuntimeBinding {
            trace32_release: "2026.02".to_owned(),
            trace32_build: 190_766,
            architecture_package: "tricore".to_owned(),
            target_identifier: "fixture-tc234l-core0".to_owned(),
            probe_identifier: "fixture-probe".to_owned(),
            initial_target_state: ControllerTargetState::Halted,
            target_adapter: ControllerTargetAdapterBinding {
                adapter_id: "fixture-program-flow-adapter".to_owned(),
                adapter_version: "1.0.0".to_owned(),
                trace32_release: "2026.02".to_owned(),
                trace32_build: 190_766,
                architecture_package: "tricore".to_owned(),
                target_identifier: "fixture-tc234l-core0".to_owned(),
                probe_identifier: "fixture-probe".to_owned(),
                profile_sha256: profile_sha256.clone(),
                implementation_sha256: receipt.implementation_sha256.clone(),
                scenario: TargetAdapterScenario::Normal,
                capture_kind,
                controller_protocol: t32perf_trace32::TargetAdapterControllerProtocol::V1,
                custom_event_collector: None,
                qualification_sha256: Some(qualification.sha256.clone()),
            },
            capture_contract: capture_contract.clone(),
            qualification_artifact: Some(qualification.clone()),
            qualification_provenance_artifacts: vec![qualification.clone()],
            qualification_receipt: Some(receipt),
            firmware_elf_artifact: firmware.clone(),
            firmware_measurement_artifact: firmware.clone(),
            capabilities_artifact: capabilities.clone(),
            configure_artifact: stop_artifact.clone(),
            start_artifact: stop_artifact.clone(),
            health_artifact: health_artifact.clone(),
            stop_artifact: stop_artifact.clone(),
            export_artifact: raw.clone(),
            custom_event_artifact: None,
            cleanup_artifact: raw.clone(),
            export_response: ControllerScriptResponse {
                operation: PerfOperation::Export,
                status: PerfStatus::Ok,
                code: "task_events_exported".to_owned(),
                files_deleted: None,
            },
            completion: ControllerCaptureCompletionEvidence::ProgramFlowTaskEvents { stop, health },
        };
        let mut capture_config = CaptureConfigDocument {
            schema: CaptureConfigSchemaVersion,
            session_id: session.id().to_string(),
            provider: "trace32".to_owned(),
            adapter: AdapterInfo {
                id: binding.target_adapter.adapter_id.clone(),
                version: binding.target_adapter.adapter_version.clone(),
            },
            mode: capture_contract.capture_mode.clone(),
            covered_cores: capture_contract.covered_cores.clone(),
            sink: CaptureSinkConfig {
                kind: capture_contract.trace_sink.clone(),
                id: "fixture-trace".to_owned(),
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
                duration_ns: Some(1_000_000),
                observation_limit: None,
            },
            workload_identity: capture_contract.workload_identity.clone(),
            initial_target_state: InitialTargetState::Halted,
            rtos_awareness: CaptureRtosAwarenessConfig {
                kind: rtos_awareness.to_owned(),
                metadata_artifact_ids: vec![orti.id.clone(), markers.id.clone()],
            },
            instrumentation: None,
            adapter_parameters: BTreeMap::from([
                ("export.profile".to_owned(), json!(export_profile_id)),
                ("firmware.elf_artifact_id".to_owned(), json!(firmware.id)),
                ("firmware.elf_sha256".to_owned(), json!(firmware.sha256)),
            ]),
        };
        capture_config.validate().unwrap();
        let template = Trace32TaskEventsMappingTemplateDocument {
            schema: t32perf_trace32::TRACE32_TASK_EVENTS_MAPPING_TEMPLATE_SCHEMA.to_owned(),
            profile_id: export_profile_id.to_owned(),
            core_id: 0,
            contexts: vec![TraceContextMapping {
                export_name: "TaskA".to_owned(),
                context_id: "task-a".to_owned(),
                kind: ContextKind::Task,
                display_name: "Task A".to_owned(),
                priority: Some(1),
                entry_function_id: None,
            }],
            functions: Vec::new(),
            runnables: Vec::new(),
        };
        template.validate().unwrap();
        write_artifact_with_inputs(
            &session,
            &lock,
            TestArtifactSpec {
                id: TASK_EVENTS_MAPPING_TEMPLATE_ARTIFACT_ID,
                kind: "trace32_task_events_mapping_template",
                path: "capture/deployment/program-flow/task-events-mapping-template.json",
                media_type: "application/json",
                producer: BUILD_RESOURCE_PRODUCER,
            },
            vec![
                firmware.id.clone(),
                qualification.id.clone(),
                orti.id.clone(),
                markers.id.clone(),
            ],
            &serde_json::to_vec(&template).unwrap(),
        );
        let artifacts_before_mapping = session.registered_artifacts(true).unwrap();
        let mapping_artifact = super::ensure_performance_run_task_events_mapping(
            &session,
            &lock,
            &artifacts_before_mapping,
            &binding,
            export_profile_id,
        )
        .unwrap();
        let mapping = parse_trace32_task_events_mapping(
            &read_bounded_artifact_bytes(
                &session,
                &mapping_artifact,
                MAX_TRACE32_MAPPING_BYTES,
                "fixture TASKEVENTS mapping",
            )
            .unwrap(),
        )
        .unwrap();
        let resumed = super::ensure_performance_run_task_events_mapping(
            &session,
            &lock,
            &session.registered_artifacts(true).unwrap(),
            &binding,
            export_profile_id,
        )
        .unwrap();
        assert_eq!(resumed, mapping_artifact, "mapping resume must not rewrite");
        let artifacts = session.registered_artifacts(true).unwrap();
        let raw_catalog = artifacts.iter().find(|item| item.id == raw.id).unwrap();
        let qualification_claim =
            validated_runtime_qualification(&binding, "test.program-flow").unwrap();
        let request = Trace32TaskEventsSourceRequest {
            source_id: "fixture-task-events".to_owned(),
            expected_profile_id: export_profile_id.to_owned(),
            firmware_elf_artifact_id: firmware.id.clone(),
            mapping_artifact_id: mapping_artifact.id.clone(),
            limits: LineLimits::default(),
        };
        let context = Trace32OpenContext {
            session: &session,
            lock: &lock,
            artifacts: &artifacts,
            capture_config: &capture_config,
            input: raw_catalog,
            file: session.open_artifact(raw_catalog).unwrap(),
        };
        validate_trace32_task_events_binding(
            &context,
            &request,
            &binding,
            &qualification_claim,
            &mapping_artifact,
            &mapping,
        )
        .unwrap();

        let mut missing_orti = mapping.clone();
        missing_orti
            .metadata_artifacts
            .retain(|metadata| metadata.role != TraceTaskMetadataRole::Orti);
        assert!(
            validate_trace32_task_events_binding(
                &context,
                &request,
                &binding,
                &qualification_claim,
                &mapping_artifact,
                &missing_orti,
            )
            .unwrap_err()
            .message
            .contains("TASKEVENTS")
        );

        let mut missing_metadata = mapping.clone();
        missing_metadata.metadata_artifacts[0].artifact.artifact_id = "missing-orti".to_owned();
        assert!(
            validate_trace32_task_events_binding(
                &context,
                &request,
                &binding,
                &qualification_claim,
                &mapping_artifact,
                &missing_metadata,
            )
            .is_err()
        );

        let mut wrong_profile = mapping.clone();
        wrong_profile.profile_sha256 = Sha256Digest::new("88".repeat(32)).unwrap();
        assert!(
            validate_trace32_task_events_binding(
                &context,
                &request,
                &binding,
                &qualification_claim,
                &mapping_artifact,
                &wrong_profile,
            )
            .unwrap_err()
            .message
            .contains("mapping compatibility does not match")
        );

        let mut wrong_stop_binding = binding.clone();
        let ControllerCaptureCompletionEvidence::ProgramFlowTaskEvents { health, .. } =
            &mut wrong_stop_binding.completion
        else {
            panic!("fixture must remain program flow");
        };
        health.stop_evidence_sha256 = Sha256Digest::new("99".repeat(32)).unwrap();
        assert!(
            validate_trace32_task_events_binding(
                &context,
                &request,
                &wrong_stop_binding,
                &qualification_claim,
                &mapping_artifact,
                &mapping,
            )
            .unwrap_err()
            .message
            .contains("not bound to the immutable Stop artifact")
        );

        capture_config
            .rtos_awareness
            .metadata_artifact_ids
            .retain(|id| id != &markers.id);
        let missing_capture_metadata_context = Trace32OpenContext {
            session: &session,
            lock: &lock,
            artifacts: &artifacts,
            capture_config: &capture_config,
            input: raw_catalog,
            file: session.open_artifact(raw_catalog).unwrap(),
        };
        assert!(
            validate_trace32_task_events_binding(
                &missing_capture_metadata_context,
                &request,
                &binding,
                &qualification_claim,
                &mapping_artifact,
                &mapping,
            )
            .unwrap_err()
            .message
            .contains("exact TASKEVENTS ORTI and marker metadata")
        );
    }

    fn canonical_source(source_id: &str) -> Value {
        json!({
            "adapter": "canonical_ndjson_v1",
            "source_id": source_id,
            "limits": {"max_line_bytes": 4096, "max_records": 100}
        })
    }

    fn single_config() -> Value {
        json!({
            "schema": "t32perf.normalize-config/v1",
            "mode": "single_source",
            "source": canonical_source("single"),
            "output_limits": {"max_line_bytes": 4096, "max_records": 100}
        })
    }

    fn trace32_ascii_config() -> Value {
        json!({
            "schema": "t32perf.normalize-config/v1",
            "mode": "single_source",
            "source": {
                "adapter": "trace32_snooper_ascii_v1",
                "source_id": "tc234l-snooper",
                "expected_profile_id": "t32perf.trace32-ascii-profile/tc234l-build190766-v1",
                "firmware_elf_artifact_id": "firmware-elf",
                "limits": {"max_line_bytes": 4096, "max_records": 100}
            },
            "output_limits": {"max_line_bytes": 4096, "max_records": 100}
        })
    }

    fn mapped_c_wire_config() -> Value {
        json!({
            "schema": "t32perf.normalize-config/v1",
            "mode": "single_source",
            "source": {
                "adapter": "c_wire_v1",
                "wire_version": 1,
                "source_id": "sdk",
                "core_id": 0,
                "clock": {
                    "domain_id": "sdk-clock",
                    "frequency_hz": {"numerator": 100000000, "denominator": 1}
                },
                "origin": {"mode": "explicit", "ticks": 0, "session_ns": 0},
                "counter_mapping_artifact_id": "c-wire-counter-mapping",
                "limits": {"max_payload_bytes": 256, "max_records": 100}
            },
            "output_limits": {"max_line_bytes": 4096, "max_records": 100}
        })
    }

    fn trace32_task_events_config() -> Value {
        json!({
            "schema": "t32perf.normalize-config/v1",
            "mode": "single_source",
            "source": {
                "adapter": "trace32_task_events_v1",
                "source_id": "tc234l-taskevents",
                "expected_profile_id": "t32perf.trace32-task-events-profile/tc234l-build190766-v1",
                "firmware_elf_artifact_id": "firmware-elf",
                "mapping_artifact_id": "trace32-task-events-mapping",
                "limits": {"max_line_bytes": 4096, "max_records": 100}
            },
            "output_limits": {"max_line_bytes": 4096, "max_records": 100}
        })
    }

    fn multi_config() -> Value {
        json!({
            "schema": "t32perf.normalize-config/v1",
            "mode": "multi_source",
            "sources": [
                {
                    "input_artifact_id": "left",
                    "clock_domain": "session",
                    "order": "reject_ambiguous_ties",
                    "source": canonical_source("left-source")
                },
                {
                    "input_artifact_id": "right",
                    "clock_domain": "session",
                    "order": "reject_ambiguous_ties",
                    "source": canonical_source("right-source")
                }
            ],
            "output_limits": {
                "max_line_bytes": 4096,
                "max_records": 100,
                "max_dictionary_entries": HARD_MAX_DICTIONARY_ENTRIES,
                "max_dictionary_bytes": HARD_MAX_DICTIONARY_BYTES
            }
        })
    }

    fn v2_task_events_c_wire_config() -> Value {
        json!({
            "schema": "t32perf.normalize-config/v1",
            "mode": "multi_source",
            "sources": [
                {
                    "input_artifact_id": "controller-trace-output",
                    "clock_domain": "fixture-trace-clock/v1",
                    "order": "reject_ambiguous_ties",
                    "source": {
                        "adapter": "trace32_task_events_v1",
                        "source_id": "trace32-program-flow",
                        "expected_profile_id": "fixture.task-events/v1",
                        "firmware_elf_artifact_id": "firmware-elf",
                        "mapping_artifact_id": "trace32-task-events-mapping",
                        "limits": {"max_line_bytes": 4096, "max_records": 100}
                    }
                },
                {
                    "input_artifact_id": "controller-custom-events-output",
                    "clock_domain": "fixture-trace-clock/v1",
                    "order": "reject_ambiguous_ties",
                    "source": {
                        "adapter": "c_wire_v1",
                        "wire_version": 1,
                        "source_id": "fixture-c-wire",
                        "core_id": 0,
                        "clock": {
                            "domain_id": "fixture-trace-clock/v1",
                            "frequency_hz": {"numerator": 100000000, "denominator": 1},
                            "wrap": {"modulus": 4294967296u64, "max_forward_ticks": 1000000}
                        },
                        "origin": {"mode": "explicit", "ticks": 77, "session_ns": 11},
                        "counter_mapping_artifact_id": "fixture-c-wire-mapping",
                        "limits": {"max_payload_bytes": 65536, "max_records": 100}
                    }
                }
            ],
            "output_limits": {"max_line_bytes": 4096, "max_records": 100}
        })
    }

    fn rust_accepts(value: &Value) -> bool {
        serde_json::from_value::<NormalizeConfig>(value.clone())
            .ok()
            .is_some_and(|config| config.validate().is_ok())
    }

    #[test]
    fn normalize_config_rejects_duplicate_nested_source_fields() {
        let error = decode_config_json::<Value>(
            br#"{"schema":"t32perf.normalize-config/v1","source":{"limits":{"max_records":1,"max_records":2}}}"#,
        )
        .expect_err("duplicate normalize-config field");

        assert!(
            error
                .message
                .contains("duplicate JSON object member name `max_records`")
        );
    }

    #[test]
    fn checked_in_normalize_schema_and_private_serde_contract_agree_on_corpus() {
        let schema: Value =
            serde_json::from_str(include_str!("../schemas/v1/normalize-config.schema.json"))
                .unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();

        let mut zero_dictionary = single_config();
        zero_dictionary["output_limits"]["max_dictionary_entries"] = json!(0);
        let mut excessive_dictionary = single_config();
        excessive_dictionary["output_limits"]["max_dictionary_bytes"] =
            json!(HARD_MAX_DICTIONARY_BYTES + 1);
        let mut excessive_line = single_config();
        excessive_line["output_limits"]["max_line_bytes"] = json!(MAX_CONFIG_LINE_BYTES + 1);
        let mut one_source = multi_config();
        one_source["sources"].as_array_mut().unwrap().pop();
        let mut missing_order = multi_config();
        missing_order["sources"][0]
            .as_object_mut()
            .unwrap()
            .remove("order");
        let mut unknown_field = single_config();
        unknown_field["future"] = json!(true);
        let mut inline_mapping = trace32_ascii_config();
        inline_mapping["source"]["functions"] = json!([]);
        let mut missing_task_mapping = trace32_task_events_config();
        missing_task_mapping["source"]
            .as_object_mut()
            .unwrap()
            .remove("mapping_artifact_id");
        let mut inline_counter_mapping = mapped_c_wire_config();
        inline_counter_mapping["source"]["counter_mapping"] = json!({"counters": []});
        let mut mismatched_v2_clock = v2_task_events_c_wire_config();
        mismatched_v2_clock["sources"][1]["clock_domain"] = json!("different-clock");

        let corpus = [
            (single_config(), true, "legacy single-source defaults"),
            (multi_config(), true, "explicit multi-source"),
            (
                v2_task_events_c_wire_config(),
                true,
                "Controller V2 TASKEVENTS plus C-wire sources",
            ),
            (
                trace32_ascii_config(),
                true,
                "TRACE32 ASCII artifact references",
            ),
            (
                trace32_task_events_config(),
                true,
                "TRACE32 TASKEVENTS artifact references",
            ),
            (
                mapped_c_wire_config(),
                true,
                "C wire counter mapping artifact reference",
            ),
            (zero_dictionary, false, "zero dictionary entries"),
            (excessive_dictionary, false, "excessive dictionary bytes"),
            (excessive_line, false, "excessive line bytes"),
            (one_source, false, "one multi-source input"),
            (missing_order, false, "missing order contract"),
            (unknown_field, false, "unknown top-level field"),
            (inline_mapping, false, "inline TRACE32 mapping"),
            (
                missing_task_mapping,
                false,
                "missing TASKEVENTS mapping artifact",
            ),
            (
                inline_counter_mapping,
                false,
                "inline C wire counter mapping",
            ),
            (
                mismatched_v2_clock,
                true,
                "config syntax permits a source-domain mismatch; opening rejects it",
            ),
        ];
        for (value, expected, label) in corpus {
            assert_eq!(validator.is_valid(&value), expected, "schema: {label}");
            assert_eq!(rust_accepts(&value), expected, "serde: {label}");
        }
    }

    #[test]
    fn v2_taskevents_c_wire_config_uses_exact_two_source_contract() {
        let config: NormalizeConfig =
            serde_json::from_value(v2_task_events_c_wire_config()).unwrap();
        let NormalizeConfig::MultiSource { sources, .. } = config else {
            panic!("V2 normalization must be multi-source");
        };
        assert_eq!(sources.len(), 2);
        assert!(sources.iter().all(|source| {
            matches!(source.order, MultiSourceOrderConfig::RejectAmbiguousTies)
                && source.clock_domain == "fixture-trace-clock/v1"
        }));
        assert!(matches!(
            &sources[0].source,
            NormalizeSourceConfig::Trace32TaskEventsV1 { .. }
        ));
        let NormalizeSourceConfig::CWireV1 {
            source_id,
            core_id,
            clock,
            origin,
            counter_mapping_artifact_id,
            ..
        } = &sources[1].source
        else {
            panic!("second V2 source must be C-wire");
        };
        assert_eq!(source_id, "fixture-c-wire");
        assert_eq!(*core_id, 0);
        assert_eq!(clock.domain_id, "fixture-trace-clock/v1");
        assert_eq!(clock.frequency_hz.numerator, 100_000_000);
        assert_eq!(clock.frequency_hz.denominator, 1);
        assert_eq!(
            counter_mapping_artifact_id.as_deref(),
            Some("fixture-c-wire-mapping")
        );
        assert!(matches!(
            origin,
            ClockOriginConfig::Explicit {
                ticks: 77,
                session_ns: 11
            }
        ));
    }

    #[test]
    fn v2_c_wire_collector_identity_mismatch_is_rejected() {
        let collector: TargetAdapterCustomEventCollectorContract = serde_json::from_value(json!({
            "wire_protocol": "c_wire_v1",
            "source_id": "fixture-c-wire",
            "core_id": 0,
            "clock": {
                "clock_id": "fixture-trace-clock/v1",
                "frequency_hz": 100000000,
                "timestamp_modulus": 4294967296u64,
                "max_forward_ticks": 1000000,
                "origin_ticks": 77,
                "origin_ns": 11
            },
            "transport": "fixture-c-wire-transport/v1",
            "mapping_artifact_id": "fixture-c-wire-mapping",
            "instrumentation_overhead_artifact_id": "fixture-instrumentation-overhead",
            "max_output_bytes": 65536,
            "merge_order": "reject_ambiguous_ties"
        }))
        .unwrap();
        let mut config = CWireSourceConfig {
            source_id: collector.source_id.clone(),
            core_id: collector.core_id,
            clock: ClockDomainSpec::new(
                collector.clock.clock_id.clone(),
                RationalTickScale::from_hz(collector.clock.frequency_hz).unwrap(),
                Some(collector.clock.timestamp_modulus),
                Some(collector.clock.max_forward_ticks),
            )
            .unwrap(),
            origin_ticks: Some(collector.clock.origin_ticks),
            origin_ns: collector.clock.origin_ns,
            limits: WireLimits {
                max_payload_bytes: 65536,
                max_records: 100,
            },
        };
        validate_c_wire_config_against_collector(
            &config,
            &collector,
            Some(&collector.mapping_artifact_id),
        )
        .unwrap();
        config.clock.id = "other-clock".to_owned();
        assert!(
            validate_c_wire_config_against_collector(
                &config,
                &collector,
                Some(&collector.mapping_artifact_id),
            )
            .unwrap_err()
            .message
            .contains("does not match")
        );
    }
}
