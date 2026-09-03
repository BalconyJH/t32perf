use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{BufReader, Read as _, Write},
    path::Path,
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use t32perf_analysis::{
    Analyzer, AnalyzerConfig, ComparisonInput, ComparisonPolicy, DerivedNdjsonReader,
    DerivedNdjsonWriter, compare_sessions,
};
use t32perf_model::{
    ANALYZER_CONTRACT, AnalysisContracts, AnalysisDiagnosticCounts, AnalysisQuantitativeSummary,
    AnalysisStageReceipt, AnalysisStageSchemaVersion, AnalysisSummaryDocument,
    AnalysisSummarySchemaVersion, Artifact, ArtifactPath, CaptureInfo, CaptureReceipt,
    ComparisonReport, ComparisonSchemaVersion, ComparisonVerdict, DerivedStreamHeader,
    DerivedStreamSchemaVersion, HealthObservation, HealthReport, HealthSchemaVersion,
    HealthVerdict, HotspotReport, HotspotsSchemaVersion, Manifest, ManifestSchemaVersion,
    MetricComparison, MetricComparisonOutcome, MetricSupportEntry, MetricSupportLevel,
    ObservationDictionary, Properties, ResourceMetricComparison, ResourceMetricComparisonOutcome,
    SessionError, SessionStatus, Sha256Digest, StackUsageAnalysisSummary, StageInfo, StageStatus,
    StaticRamAnalysisSummary, StaticRamConfigDocument, StaticRamConfigProvenance,
    StaticRamMetricComparison, ToolInfo, strict_json,
};
use t32perf_perfetto::{ChromeTraceWriter, TraceConfig};
use t32perf_session::{ArtifactRoot, ArtifactSpec, ArtifactWriter, Session, SessionLock};
use t32perf_trace32::{
    ELF_SECTIONS_V1_FLAVOR, GCC_STACK_USAGE_V1_FLAVOR, GNU_LD_MAP_V1_FLAVOR, InputErrorKind,
    LineLimits, NdjsonError, NdjsonErrorKind, NdjsonObservationReader, ObservationOrderError,
    StackUsageReport, StaticRamParserConfig, StaticRamReport, parse_stack_usage_report,
    parse_static_ram_report,
};

use crate::app::{
    AppError, CommandOutcome, EXIT_INCONCLUSIVE, EXIT_REGRESSION, EXIT_SUCCESS, health_exit_code,
    open_session,
};
use crate::attestation::{CAPTURE_RECEIPT_PATH, verify_registered_external_capture};
use crate::capture_config::{
    CAPTURE_CONFIG_ID, SYNTHETIC_CAPTURE_CONFIG_PRODUCER, registered_capture_config,
    validate_capture_config_receipt,
};
use crate::receipt::{
    ANALYSIS_STAGE_ID, ANALYSIS_STAGE_PRODUCER, CAPTURE_RECEIPT_ID, STACK_USAGE_ID, STATIC_RAM_ID,
    SYNTHETIC_RECEIPT_PRODUCER, analyzer_capabilities, static_ram_artifact_kind,
    static_ram_source_kind, validate_analysis_stage_receipt, validate_trusted_synthetic_receipt,
};

const MAX_COMPARISON_STAGE_BYTES: u64 = 1024 * 1024;
const MAX_COMPARISON_HEALTH_BYTES: u64 = 16 * 1024 * 1024;
const MAX_COMPARISON_AGGREGATE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_COMPARISON_HOTSPOT_SUBJECTS: usize = 10_000;
const MAX_COMPARISON_RESOURCE_SUBJECTS: usize = 10_000;
const MAX_COMPARISON_REPORT_ROWS: usize = 100_000;
const MAX_COMPARISON_REASONS: usize = 32;
const MAX_COMPARISON_NESTED_VALUES: usize = 16;
const MAX_COMPARISON_TEXT_BYTES: usize = 512;
const MAX_ANALYSIS_REQUEST_BYTES: u64 = 1024 * 1024;
pub(crate) const ANALYSIS_REQUEST_ID: &str = "analysis-request";
pub(crate) const ANALYSIS_REQUEST_KIND: &str = "analysis_request";
pub(crate) const ANALYSIS_REQUEST_PATH: &str = "analysis/request.json";
pub(crate) const ANALYSIS_REQUEST_PRODUCER: &str = "t32perf-analysis-request/v1";
const ANALYSIS_REQUEST_STAGED_PATH: &str = "host-analysis/analysis-request.json";
const ANALYSIS_REQUEST_SCHEMA: &str = "t32perf.analysis-request/v1";

#[derive(Debug, Clone, Default)]
struct ResourceInputs {
    linker_map: Option<Artifact>,
    firmware_elf: Option<Artifact>,
    static_ram_config: Option<Artifact>,
    stack_usage: Option<Artifact>,
}

#[derive(Debug)]
struct ParsedResourceReports {
    static_ram: Option<ParsedStaticRamReport>,
    stack_usage: Option<(Artifact, StackUsageReport)>,
}

#[derive(Debug)]
struct ParsedStaticRamReport {
    source: Artifact,
    report: StaticRamReport,
    config: StaticRamConfigProvenance,
    config_artifact: Option<Artifact>,
}

#[derive(Debug)]
struct AnalysisInputs {
    observations: Artifact,
    capture_receipt_artifact: Artifact,
    capture_receipt: CaptureReceipt,
    resources: ResourceInputs,
}

/// Immutable Host-owned binding of the analysis invocation to its exact
/// resource selection.  This prevents a Processing retry from silently
/// adopting different flavors or build artifacts after capture.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalysisRequest {
    schema: String,
    session_id: String,
    linker_map_flavor: String,
    stack_usage_flavor: String,
    contracts: AnalysisContracts,
    input_artifacts: Vec<Artifact>,
}

struct AnalysisRequestInputs<'a> {
    artifacts: &'a [Artifact],
    observations: &'a Artifact,
    capture_receipt: &'a Artifact,
    resources: &'a ResourceInputs,
    linker_map_flavor: &'a str,
    stack_usage_flavor: &'a str,
}

struct ObservationInput {
    dictionary: ObservationDictionary,
    reader: Option<NdjsonObservationReader<BufReader<File>>>,
    terminal_health: Option<HealthObservation>,
}

/// Result of an idempotent analysis or conversion ensure operation.
pub(crate) struct EnsureResult {
    /// Reconstructed or newly produced command outcome.
    pub(crate) outcome: CommandOutcome,
    /// Whether an already durable completion marker was reused.
    pub(crate) resumed: bool,
}

/// A writer that either publishes a new artifact or streams deterministic
/// regenerated bytes into an existing immutable-artifact comparator.
struct EnsuredArtifactWriter {
    mode: EnsuredArtifactWriterMode,
}

enum EnsuredArtifactWriterMode {
    New(ArtifactWriter),
    Existing {
        artifact: Artifact,
        hasher: Sha256,
        size_bytes: u64,
    },
}

impl Write for EnsuredArtifactWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        match &mut self.mode {
            EnsuredArtifactWriterMode::New(writer) => writer.write(bytes),
            EnsuredArtifactWriterMode::Existing {
                hasher, size_bytes, ..
            } => {
                *size_bytes = size_bytes
                    .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
                    .ok_or_else(|| std::io::Error::other("regenerated artifact length overflow"))?;
                hasher.update(bytes);
                Ok(bytes.len())
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.mode {
            EnsuredArtifactWriterMode::New(writer) => writer.flush(),
            EnsuredArtifactWriterMode::Existing { .. } => Ok(()),
        }
    }
}

fn ensure_artifact_writer(
    session: &Session,
    lock: &SessionLock,
    spec: ArtifactSpec,
    artifacts: &[Artifact],
) -> Result<EnsuredArtifactWriter, AppError> {
    if let Some(existing) = artifacts.iter().find(|artifact| artifact.id == spec.id) {
        if existing.kind != spec.kind
            || existing.relative_path != spec.relative_path
            || existing.media_type != spec.media_type
            || existing.producer != spec.producer
            || existing.input_artifact_ids != spec.input_artifact_ids
        {
            return Err(AppError::operational(format!(
                "existing artifact `{}` conflicts with its exact publication envelope",
                existing.id
            )));
        }
        return Ok(EnsuredArtifactWriter {
            mode: EnsuredArtifactWriterMode::Existing {
                artifact: existing.clone(),
                hasher: Sha256::new(),
                size_bytes: 0,
            },
        });
    }
    session
        .create_artifact(lock, spec)
        .map(|writer| EnsuredArtifactWriter {
            mode: EnsuredArtifactWriterMode::New(writer),
        })
        .map_err(AppError::operational)
}

fn finish_ensured_artifact(
    session: &Session,
    lock: &SessionLock,
    writer: EnsuredArtifactWriter,
) -> Result<Artifact, AppError> {
    match writer.mode {
        EnsuredArtifactWriterMode::New(writer) => session
            .commit_artifact(lock, writer)
            .map_err(AppError::operational),
        EnsuredArtifactWriterMode::Existing {
            artifact,
            hasher,
            size_bytes,
        } => {
            let digest = Sha256Digest::new(encode_lower_hex(&hasher.finalize()))
                .map_err(AppError::operational)?;
            if artifact.size_bytes != size_bytes || artifact.sha256 != digest {
                return Err(AppError::operational(format!(
                    "existing artifact `{}` bytes do not match the exact regenerated output",
                    artifact.id
                )));
            }
            Ok(artifact)
        }
    }
}

fn write_ensured_json<T: serde::Serialize>(
    session: &Session,
    lock: &SessionLock,
    spec: ArtifactSpec,
    artifacts: &[Artifact],
    value: &T,
) -> Result<Artifact, AppError> {
    let mut writer = ensure_artifact_writer(session, lock, spec, artifacts)?;
    serde_json::to_writer_pretty(&mut writer, value).map_err(AppError::operational)?;
    writer.write_all(b"\n").map_err(AppError::operational)?;
    finish_ensured_artifact(session, lock, writer)
}

const MAX_PARSER_EVIDENCE_CHARS: usize = 512;
const MAX_STATIC_RAM_CONFIG_BYTES: u64 = 1024 * 1024;

pub fn analyze(
    root: &ArtifactRoot,
    session_id: &str,
    linker_map_flavor: &str,
    stack_usage_flavor: &str,
) -> Result<CommandOutcome, AppError> {
    Ok(ensure_analyzed(root, session_id, linker_map_flavor, stack_usage_flavor)?.outcome)
}

/// Validates closed resource-parser flavors before app acquires a Session
/// execution lease. `ensure_analyzed` repeats the validation before work.
pub(crate) fn preflight_analysis_flavors(
    linker_map_flavor: &str,
    stack_usage_flavor: &str,
) -> Result<(), AppError> {
    validate_resource_flavors(linker_map_flavor, stack_usage_flavor)
}

/// Ensures analysis is durably complete, reusing a validated stage receipt.
pub(crate) fn ensure_analyzed(
    root: &ArtifactRoot,
    session_id: &str,
    linker_map_flavor: &str,
    stack_usage_flavor: &str,
) -> Result<EnsureResult, AppError> {
    let session = open_session(root, session_id)?;
    let lock = session.try_lock().map_err(AppError::operational)?;
    crate::controller::ensure_controller_session_releasable(root, &session)?;
    let state = session.read_state().map_err(AppError::operational)?;
    if state.status == SessionStatus::Failed {
        return Err(AppError::operational(format!(
            "session `{session_id}` is failed; analysis ensure performs no writes"
        )));
    }
    let artifacts = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    if !matches!(
        state.status,
        SessionStatus::Captured | SessionStatus::Processing | SessionStatus::Complete
    ) {
        let reason = "session must be captured before analysis";
        return Err(AppError::operational(format!(
            "session `{session_id}` {reason}; current status is {:?}",
            state.status
        )));
    }
    let capture_receipt = trusted_capture_receipt(&session, &artifacts)?;
    let capture_receipt_artifact = required_artifact(&artifacts, CAPTURE_RECEIPT_ID)?.clone();
    let observations_artifact = required_artifact(&artifacts, "observations")?.clone();
    validate_resource_flavors(linker_map_flavor, stack_usage_flavor)?;
    let resource_inputs = resource_inputs(&artifacts)?;

    let allow_request_creation = state.status == SessionStatus::Captured;
    let analysis_request = ensure_analysis_request(
        &session,
        &lock,
        AnalysisRequestInputs {
            artifacts: &artifacts,
            observations: &observations_artifact,
            capture_receipt: &capture_receipt_artifact,
            resources: &resource_inputs,
            linker_map_flavor,
            stack_usage_flavor,
        },
        allow_request_creation,
    )?;
    let artifacts = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    if let Some(stage_artifact) = artifacts
        .iter()
        .find(|artifact| artifact.id == ANALYSIS_STAGE_ID)
    {
        let stage: AnalysisStageReceipt = read_json_artifact(&session, stage_artifact)?;
        validate_analysis_stage_receipt(&stage, stage_artifact, &artifacts, session.id().as_str())?;
        validate_analysis_stage_request_binding(&session, &stage, &analysis_request)?;
        let health_artifact = required_artifact(&artifacts, "health")?;
        let health: HealthReport = read_json_artifact(&session, health_artifact)?;
        validate_health_document(&session, &health, &stage)?;
        let summary_artifact = required_artifact(&artifacts, "analysis-summary")?;
        let summary: AnalysisSummaryDocument = read_json_artifact(&session, summary_artifact)?;
        validate_summary_document(&session, summary_artifact, &summary, &stage, &artifacts)?;
        if stage.health_verdict != HealthVerdict::Valid
            && (artifacts.iter().any(|artifact| artifact.id == "hotspots")
                || summary.quantitative.is_some())
        {
            return Err(AppError::operational(
                "non-valid completed analysis must not publish hotspots or quantitative output",
            ));
        }
        return Ok(EnsureResult {
            outcome: CommandOutcome {
                command: "analyze",
                result: json!({
                    "session_id": session.id().as_str(),
                    "health_verdict": health.verdict,
                    "diagnostics": stage.diagnostics,
                    "artifacts": stage.output_artifacts,
                    "resumed": true,
                }),
                exit_code: health_exit_code(health.verdict),
            },
            resumed: true,
        });
    }

    if state.status == SessionStatus::Complete {
        return Err(AppError::operational(
            "complete Session lacks the immutable analysis stage required for analysis resume",
        ));
    }

    if state.status == SessionStatus::Captured {
        session
            .transition(&lock, SessionStatus::Processing, None)
            .map_err(AppError::operational)?;
    }
    let outcome = analyze_processing(
        &session,
        &lock,
        AnalysisInputs {
            observations: observations_artifact,
            capture_receipt_artifact,
            capture_receipt,
            resources: resource_inputs,
        },
        &artifacts,
        &analysis_request,
        linker_map_flavor,
        stack_usage_flavor,
    );
    match outcome {
        Ok(outcome) => Ok(EnsureResult {
            outcome,
            resumed: false,
        }),
        Err(error) => {
            mark_failed(&session, &lock, "analyze", &error)?;
            Err(error)
        }
    }
}

fn analyze_processing(
    session: &Session,
    lock: &SessionLock,
    inputs: AnalysisInputs,
    existing_artifacts: &[Artifact],
    analysis_request: &Artifact,
    linker_map_flavor: &str,
    stack_usage_flavor: &str,
) -> Result<CommandOutcome, AppError> {
    let AnalysisInputs {
        observations: observations_artifact,
        capture_receipt_artifact,
        capture_receipt,
        resources: resource_inputs,
    } = inputs;
    let resource_reports = parse_resource_reports(
        session,
        &resource_inputs,
        linker_map_flavor,
        stack_usage_flavor,
    )?;
    let core_inputs = vec![
        observations_artifact.id.clone(),
        capture_receipt_artifact.id.clone(),
        analysis_request.id.clone(),
    ];
    let mut stage_input_artifacts = vec![
        observations_artifact.clone(),
        capture_receipt_artifact.clone(),
        analysis_request.clone(),
    ];
    if let Some(parsed) = &resource_reports.static_ram {
        stage_input_artifacts.push(parsed.source.clone());
        if let Some(config_artifact) = &parsed.config_artifact {
            stage_input_artifacts.push(config_artifact.clone());
        }
    }
    if let Some((source, _)) = &resource_reports.stack_usage {
        stage_input_artifacts.push(source.clone());
    }

    let config = AnalyzerConfig {
        capabilities: analyzer_capabilities(&capture_receipt),
        ..AnalyzerConfig::default()
    };
    let ObservationInput {
        dictionary,
        mut reader,
        mut terminal_health,
    } = open_observation_input(session, &observations_artifact)?;
    let mut analyzer = Analyzer::new(session.id().as_str(), config);
    analyzer
        .register_dictionary(&dictionary)
        .map_err(AppError::operational)?;
    let artifact_writer = ensure_artifact_writer(
        session,
        lock,
        artifact_spec(
            "derived",
            "derived",
            "analysis/derived.ndjson",
            "application/x-ndjson",
            core_inputs.clone(),
            ANALYSIS_STAGE_PRODUCER,
        )?,
        existing_artifacts,
    )?;
    let mut derived_header = DerivedStreamHeader::ndjson(session.id().as_str());
    derived_header.input_artifact_ids = core_inputs.clone();
    let mut derived_writer =
        DerivedNdjsonWriter::new(artifact_writer, derived_header).map_err(AppError::operational)?;

    let mut observation_count = 0_u64;
    if let Some(observations) = reader.as_mut() {
        for observation in observations {
            let observation = match observation {
                Ok(observation) => observation,
                Err(error) => {
                    terminal_health = Some(ndjson_health_observation(
                        &observations_artifact.id,
                        &error,
                    )?);
                    break;
                }
            };
            analyzer
                .ingest(&observation)
                .map_err(AppError::operational)?;
            observation_count = observation_count.checked_add(1).ok_or_else(|| {
                AppError::operational("observation count exceeds the supported u64 range")
            })?;
            let completed = analyzer.drain_completed_spans();
            derived_writer
                .write_spans(&completed)
                .map_err(AppError::operational)?;
        }
    }
    if let Some(health_observation) = terminal_health {
        analyzer.record_health_observation(health_observation);
    }
    for health_observation in capture_receipt.health_observations {
        analyzer.record_health_observation(health_observation);
    }
    let result = analyzer.finish(None).map_err(AppError::operational)?;
    derived_writer
        .write_spans(&result.derived.function_spans)
        .map_err(AppError::operational)?;
    let function_span_count = derived_writer.spans_written();
    if observation_count != result.summary.observation_count
        || function_span_count != result.summary.function_span_count
    {
        return Err(AppError::operational(
            "streamed analysis counts do not match analyzer summary",
        ));
    }
    let artifact_writer = derived_writer.finish().map_err(AppError::operational)?;
    let derived = finish_ensured_artifact(session, lock, artifact_writer)?;
    let health = write_ensured_json(
        session,
        lock,
        artifact_spec(
            "health",
            "health",
            "analysis/health.json",
            "application/json",
            core_inputs.clone(),
            ANALYSIS_STAGE_PRODUCER,
        )?,
        existing_artifacts,
        &result.health,
    )?;
    let hotspots = if result.health.verdict == HealthVerdict::Valid {
        Some(write_ensured_json(
            session,
            lock,
            artifact_spec(
                "hotspots",
                "hotspots",
                "analysis/hotspots.json",
                "application/json",
                vec![
                    derived.id.clone(),
                    health.id.clone(),
                    analysis_request.id.clone(),
                ],
                ANALYSIS_STAGE_PRODUCER,
            )?,
            existing_artifacts,
            &result.hotspots,
        )?)
    } else {
        None
    };

    let static_ram = if result.health.verdict == HealthVerdict::Valid {
        resource_reports
            .static_ram
            .map(|parsed| {
                let mut input_ids = vec![parsed.source.id.clone(), analysis_request.id.clone()];
                if let Some(config_artifact) = &parsed.config_artifact {
                    input_ids.push(config_artifact.id.clone());
                }
                let kind = static_ram_artifact_kind(linker_map_flavor).ok_or_else(|| {
                    AppError::unsupported(
                        "analyze.static_ram_flavor",
                        format!("static RAM flavor `{linker_map_flavor}` is unsupported"),
                    )
                })?;
                let artifact = write_ensured_json(
                    session,
                    lock,
                    artifact_spec(
                        STATIC_RAM_ID,
                        kind,
                        "analysis/static-ram.json",
                        "application/json",
                        input_ids,
                        "t32perf-static-ram",
                    )?,
                    existing_artifacts,
                    &parsed.report,
                )?;
                Ok::<_, AppError>((artifact, parsed))
            })
            .transpose()?
    } else {
        None
    };
    let stack_usage = if result.health.verdict == HealthVerdict::Valid {
        resource_reports
            .stack_usage
            .map(|(source, report)| {
                let artifact = write_ensured_json(
                    session,
                    lock,
                    artifact_spec(
                        STACK_USAGE_ID,
                        "stack_usage:gcc-stack-usage-v1",
                        "analysis/stack-usage.json",
                        "application/json",
                        vec![source.id.clone(), analysis_request.id.clone()],
                        "t32perf-stack-usage",
                    )?,
                    existing_artifacts,
                    &report,
                )?;
                Ok::<_, AppError>((artifact, source, report))
            })
            .transpose()?
    } else {
        None
    };

    let diagnostics = AnalysisDiagnosticCounts {
        observation_count,
        function_span_count,
        incomplete_function_span_count: result.summary.incomplete_function_span_count,
        health_observation_count: u64::try_from(result.health.observations.len()).map_err(
            |_| AppError::operational("health observation count exceeds the supported u64 range"),
        )?,
        health_issue_count: u64::try_from(result.health.issues.len()).map_err(|_| {
            AppError::operational("health issue count exceeds the supported u64 range")
        })?,
    };
    let quantitative = if result.health.verdict == HealthVerdict::Valid {
        Some(AnalysisQuantitativeSummary {
            analysis: result.summary.clone(),
            static_ram: static_ram
                .as_ref()
                .map(|(artifact, parsed)| StaticRamAnalysisSummary {
                    artifact_id: artifact.id.clone(),
                    source_artifact_id: parsed.source.id.clone(),
                    flavor: linker_map_flavor.to_owned(),
                    config: Some(parsed.config.clone()),
                    total_bytes: parsed.report.total_bytes,
                    totals: parsed.report.totals.clone(),
                    support: MetricSupportEntry {
                        support: MetricSupportLevel::Inferred,
                        reasons: vec!["build_identity_unbound".to_owned()],
                    },
                }),
            stack_usage: stack_usage
                .as_ref()
                .map(|(artifact, source, report)| -> Result<_, AppError> {
                    Ok(StackUsageAnalysisSummary {
                        artifact_id: artifact.id.clone(),
                        source_artifact_id: source.id.clone(),
                        flavor: stack_usage_flavor.to_owned(),
                        maximum_static_bytes: report.maximum_static_bytes,
                        function_count: u64::try_from(report.functions.len()).map_err(|_| {
                            AppError::operational(
                                "stack usage function count exceeds the supported u64 range",
                            )
                        })?,
                        support: MetricSupportEntry {
                            support: MetricSupportLevel::Inferred,
                            reasons: vec!["build_identity_unbound".to_owned()],
                        },
                    })
                })
                .transpose()?,
        })
    } else {
        None
    };
    let mut summary_input_artifacts = vec![
        observations_artifact.clone(),
        capture_receipt_artifact.clone(),
        analysis_request.clone(),
        derived.clone(),
        health.clone(),
    ];
    if result.health.verdict == HealthVerdict::Valid {
        if let Some((artifact, _)) = &static_ram {
            summary_input_artifacts.push(artifact.clone());
        }
        if let Some((artifact, _, _)) = &stack_usage {
            summary_input_artifacts.push(artifact.clone());
        }
    }
    let summary_document = AnalysisSummaryDocument {
        schema: AnalysisSummarySchemaVersion,
        session_id: session.id().to_string(),
        health_verdict: result.health.verdict,
        metric_support: result.health.metric_support.clone(),
        input_artifacts: summary_input_artifacts.clone(),
        diagnostics: diagnostics.clone(),
        quantitative,
    };
    summary_document.validate().map_err(AppError::operational)?;
    let summary = write_ensured_json(
        session,
        lock,
        artifact_spec(
            "analysis-summary",
            "analysis_summary",
            "analysis/summary.json",
            "application/json",
            summary_input_artifacts
                .iter()
                .map(|artifact| artifact.id.clone())
                .collect(),
            ANALYSIS_STAGE_PRODUCER,
        )?,
        existing_artifacts,
        &summary_document,
    )?;
    let mut output_ids = vec![derived.id.clone(), health.id.clone()];
    if let Some(artifact) = &hotspots {
        output_ids.push(artifact.id.clone());
    }
    output_ids.push(summary.id.clone());
    if static_ram.is_some() {
        output_ids.push(STATIC_RAM_ID.to_owned());
    }
    if stack_usage.is_some() {
        output_ids.push(STACK_USAGE_ID.to_owned());
    }
    let catalog = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    let stage_input_ids = stage_input_artifacts
        .iter()
        .map(|artifact| artifact.id.clone())
        .collect::<Vec<_>>();
    let input_artifacts = artifact_claims(&catalog, &stage_input_ids)?;
    let output_artifacts = artifact_claims(&catalog, &output_ids)?;
    let stage_receipt = AnalysisStageReceipt {
        schema: AnalysisStageSchemaVersion,
        session_id: session.id().to_string(),
        tool: ToolInfo {
            name: "t32perf".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            commit: option_env!("T32PERF_COMMIT").map(str::to_owned),
        },
        contracts: analysis_contracts(),
        health_verdict: result.health.verdict,
        metric_support: result.health.metric_support.clone(),
        diagnostics: diagnostics.clone(),
        input_artifacts,
        output_artifacts: output_artifacts.clone(),
    };
    stage_receipt.validate().map_err(AppError::operational)?;
    let stage_provenance = stage_receipt
        .input_artifacts
        .iter()
        .chain(&stage_receipt.output_artifacts)
        .map(|artifact| artifact.id.clone())
        .collect();
    let analysis_stage = session
        .write_json_artifact(
            lock,
            artifact_spec(
                ANALYSIS_STAGE_ID,
                "analysis_stage",
                "analysis/stage.json",
                "application/json",
                stage_provenance,
                ANALYSIS_STAGE_PRODUCER,
            )?,
            &stage_receipt,
        )
        .map_err(AppError::operational)?;

    let mut response_artifacts = output_artifacts;
    response_artifacts.push(analysis_stage);

    let mut response = Map::from_iter([
        ("session_id".to_owned(), json!(session.id().as_str())),
        ("health_verdict".to_owned(), json!(result.health.verdict)),
        ("diagnostics".to_owned(), json!(diagnostics)),
        ("artifacts".to_owned(), json!(response_artifacts)),
    ]);
    if let Some(quantitative) = summary_document.quantitative {
        response.insert(
            "observation_count".to_owned(),
            json!(diagnostics.observation_count),
        );
        response.insert(
            "function_span_count".to_owned(),
            json!(diagnostics.function_span_count),
        );
        response.insert("summary".to_owned(), json!(quantitative));
    }

    Ok(CommandOutcome {
        command: "analyze",
        result: Value::Object(response),
        exit_code: health_exit_code(result.health.verdict),
    })
}

/// Validates the closed conversion format without opening a Session.
pub(crate) fn preflight_convert_format(format: &str) -> Result<(), AppError> {
    if format != "perfetto-json" {
        return Err(AppError::unsupported(
            "convert.format",
            format!("conversion format `{format}` is unsupported"),
        ));
    }
    Ok(())
}

pub fn convert(root: &ArtifactRoot, session_id: &str) -> Result<CommandOutcome, AppError> {
    Ok(ensure_converted(root, session_id)?.outcome)
}

/// Ensures a validated Perfetto report and manifest finalization are complete.
pub(crate) fn ensure_converted(
    root: &ArtifactRoot,
    session_id: &str,
) -> Result<EnsureResult, AppError> {
    let session = open_session(root, session_id)?;
    let lock = session.try_lock().map_err(AppError::operational)?;
    crate::controller::ensure_controller_session_releasable(root, &session)?;
    let state = session.read_state().map_err(AppError::operational)?;
    if state.status == SessionStatus::Failed {
        return Err(AppError::operational(format!(
            "session `{session_id}` is failed; conversion ensure performs no writes"
        )));
    }
    if !matches!(
        state.status,
        SessionStatus::Processing | SessionStatus::Complete
    ) {
        return Err(AppError::operational(format!(
            "session `{session_id}` must be analyzed before conversion; current status is {:?}",
            state.status
        )));
    }
    let resumed = state.status == SessionStatus::Complete
        || session.manifest().map_err(AppError::operational)?.is_some();
    let outcome = convert_processing(&session, &lock);
    match outcome {
        Ok(mut outcome) => {
            if resumed {
                outcome.result["resumed"] = json!(true);
            }
            Ok(EnsureResult { outcome, resumed })
        }
        Err(error) if state.status == SessionStatus::Processing => {
            mark_failed(&session, &lock, "convert", &error)?;
            Err(error)
        }
        Err(error) => Err(error),
    }
}

fn convert_processing(session: &Session, lock: &SessionLock) -> Result<CommandOutcome, AppError> {
    let mut artifacts = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    let observations_artifact = required_artifact(&artifacts, "observations")?.clone();
    let derived_artifact = required_artifact(&artifacts, "derived")?.clone();
    let health_artifact = required_artifact(&artifacts, "health")?.clone();
    let summary_artifact = required_artifact(&artifacts, "analysis-summary")?.clone();
    let stage_artifact = required_artifact(&artifacts, ANALYSIS_STAGE_ID)?.clone();
    let request_artifact = required_artifact(&artifacts, ANALYSIS_REQUEST_ID)?.clone();
    let stage: AnalysisStageReceipt = read_json_artifact(session, &stage_artifact)?;
    validate_analysis_stage_receipt(&stage, &stage_artifact, &artifacts, session.id().as_str())?;
    validate_analysis_stage_request_binding(session, &stage, &request_artifact)?;
    let health: HealthReport = read_json_artifact(session, &health_artifact)?;
    let summary: AnalysisSummaryDocument = read_json_artifact(session, &summary_artifact)?;
    validate_health_document(session, &health, &stage)?;
    validate_summary_document(session, &summary_artifact, &summary, &stage, &artifacts)?;
    let _hotspots = if stage.health_verdict == HealthVerdict::Valid {
        let artifact = required_artifact(&artifacts, "hotspots")?;
        let document: HotspotReport = read_json_artifact(session, artifact)?;
        document.validate().map_err(AppError::operational)?;
        if document.schema != stage.contracts.hotspots_schema
            || document.session_id != session.id().as_str()
        {
            return Err(AppError::operational(
                "hotspot report schema or session does not match the completed analysis stage",
            ));
        }
        Some(document)
    } else {
        None
    };
    let derived = open_derived(session, &derived_artifact)?;
    if derived.header().schema != stage.contracts.derived_stream_schema
        || derived.header().input_artifact_ids != derived_artifact.input_artifact_ids
    {
        return Err(AppError::operational(
            "derived stream schema or inputs do not match the analysis stage contract",
        ));
    }
    drop(derived);

    let writer = ensure_artifact_writer(
        session,
        lock,
        artifact_spec(
            "perfetto",
            "perfetto",
            "report/trace.json",
            "application/json",
            vec![
                observations_artifact.id.clone(),
                derived_artifact.id.clone(),
                health_artifact.id.clone(),
                stage_artifact.id.clone(),
                request_artifact.id.clone(),
            ],
            "t32perf-perfetto",
        )?,
        &artifacts,
    )?;
    let ObservationInput {
        dictionary,
        mut reader,
        terminal_health,
    } = open_observation_input(session, &observations_artifact)?;
    if let Some(observation) = &terminal_health {
        require_recorded_parser_health(&health, observation)?;
    }
    let mut derived = open_derived(session, &derived_artifact)?;
    if derived.header().schema != stage.contracts.derived_stream_schema
        || derived.header().input_artifact_ids != derived_artifact.input_artifact_ids
    {
        return Err(AppError::operational(
            "derived stream schema or inputs do not match the analysis stage contract",
        ));
    }
    let mut trace = ChromeTraceWriter::new(
        writer,
        TraceConfig::new(session.id().as_str(), health.verdict),
    )
    .map_err(AppError::operational)?;
    trace
        .register_dictionary(&dictionary)
        .map_err(AppError::operational)?;
    let mut function_span_count = 0_u64;
    for span in &mut derived {
        let span = span.map_err(AppError::operational)?;
        trace
            .write_function_span(&span)
            .map_err(AppError::operational)?;
        function_span_count = function_span_count.checked_add(1).ok_or_else(|| {
            AppError::operational("derived function span count exceeds the supported u64 range")
        })?;
    }
    if function_span_count != stage.diagnostics.function_span_count {
        return Err(AppError::operational(
            "derived stream span count does not match the analysis stage receipt",
        ));
    }
    let mut observation_count = 0_u64;
    if let Some(observations) = reader.as_mut() {
        for observation in observations {
            let observation = match observation {
                Ok(observation) => observation,
                Err(error) => {
                    let diagnostic = ndjson_health_observation(&observations_artifact.id, &error)?;
                    require_recorded_parser_health(&health, &diagnostic)?;
                    break;
                }
            };
            trace
                .write_observation(&observation)
                .map_err(AppError::operational)?;
            observation_count = observation_count.checked_add(1).ok_or_else(|| {
                AppError::operational("source observation count exceeds the supported u64 range")
            })?;
        }
    }
    if observation_count != stage.diagnostics.observation_count {
        return Err(AppError::operational(
            "source observation count does not match the analysis stage receipt",
        ));
    }
    let writer = trace.finish().map_err(AppError::operational)?;
    let perfetto = finish_ensured_artifact(session, lock, writer)?;

    artifacts = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    let manifest = match session.manifest().map_err(AppError::operational)? {
        Some(manifest) => manifest,
        None => build_manifest(session, artifacts.clone())?,
    };
    let final_state = session
        .finalize(lock, &manifest)
        .map_err(AppError::operational)?;

    Ok(CommandOutcome {
        command: "convert",
        result: json!({
            "session_id": session.id().as_str(),
            "format": "perfetto-json",
        "health_verdict": health.verdict,
            "status": final_state.status,
            "artifact": perfetto,
            "manifest_committed": true,
        }),
        exit_code: health_exit_code(health.verdict),
    })
}

pub fn compare(
    root: &ArtifactRoot,
    baseline_id: &str,
    candidate_id: &str,
    policy_name: &str,
    allow_inconclusive: bool,
    top: usize,
) -> Result<CommandOutcome, AppError> {
    let policy = comparison_policy(policy_name)?;
    let control_plane = crate::operations::comparison_control_plane(root)?;
    let baseline = comparison_documents(root, baseline_id)?;
    let distinct_candidate = if baseline_id == candidate_id {
        None
    } else {
        Some(comparison_documents(root, candidate_id)?)
    };
    let candidate = distinct_candidate.as_ref().unwrap_or(&baseline);
    validate_comparison_scale(&baseline, "baseline")?;
    validate_comparison_scale(candidate, "candidate")?;
    let report = match (&baseline.hotspots, &candidate.hotspots) {
        (Some(baseline_hotspots), Some(candidate_hotspots)) => compare_sessions(
            ComparisonInput {
                manifest: &baseline.manifest,
                health: &baseline.health,
                hotspots: baseline_hotspots,
                summary: &baseline.summary,
            },
            ComparisonInput {
                manifest: &candidate.manifest,
                health: &candidate.health,
                hotspots: candidate_hotspots,
                summary: &candidate.summary,
            },
            &policy,
        ),
        _ => ComparisonReport {
            schema: ComparisonSchemaVersion,
            baseline_session_id: baseline.manifest.session_id.clone(),
            candidate_session_id: candidate.manifest.session_id.clone(),
            baseline_health: baseline.health.verdict,
            candidate_health: candidate.health.verdict,
            verdict: ComparisonVerdict::Inconclusive,
            metrics: Vec::new(),
            resource_metrics: Vec::new(),
            static_ram_metrics: Vec::new(),
            reasons: vec!["quantitative_hotspots_unavailable_for_nonvalid_input".to_owned()],
        },
    };
    report.validate().map_err(AppError::operational)?;
    let row_count = report
        .metrics
        .len()
        .saturating_add(report.resource_metrics.len())
        .saturating_add(report.static_ram_metrics.len());
    if row_count > MAX_COMPARISON_REPORT_ROWS {
        return Err(AppError::unsupported(
            "compare.report_rows",
            format!(
                "comparison produced {row_count} rows; maximum is {MAX_COMPARISON_REPORT_ROWS}"
            ),
        ));
    }
    let artifact =
        control_plane.persist_report(&policy, &baseline.claims, &candidate.claims, &report)?;
    let exit_code = match report.verdict {
        ComparisonVerdict::Regressed => EXIT_REGRESSION,
        ComparisonVerdict::Inconclusive if !allow_inconclusive => EXIT_INCONCLUSIVE,
        ComparisonVerdict::Improved
        | ComparisonVerdict::Unchanged
        | ComparisonVerdict::Inconclusive => EXIT_SUCCESS,
    };
    Ok(CommandOutcome {
        command: "compare",
        result: json!({
            "policy": comparison_policy_source(policy_name),
            "verdict": report.verdict,
            "inconclusive_allowed": allow_inconclusive,
            "report": comparison_report_projection(&report, top),
            "report_artifact": artifact,
        }),
        exit_code,
    })
}

struct ComparisonDocuments {
    manifest: Manifest,
    health: HealthReport,
    hotspots: Option<HotspotReport>,
    summary: AnalysisSummaryDocument,
    claims: crate::operations::ComparisonInputClaims,
    _lock: SessionLock,
}

fn comparison_documents(
    root: &ArtifactRoot,
    session_id: &str,
) -> Result<ComparisonDocuments, AppError> {
    let session = open_session(root, session_id)?;
    let lock = session.try_lock().map_err(AppError::operational)?;
    let manifest = session
        .manifest()
        .map_err(AppError::operational)?
        .ok_or_else(|| {
            AppError::operational(format!(
                "session `{session_id}` has no committed manifest; run convert first"
            ))
        })?;
    session
        .validate_manifest(&manifest, true)
        .map_err(AppError::operational)?;
    let stage_artifact = required_artifact(&manifest.artifacts, ANALYSIS_STAGE_ID)?;
    let stage: AnalysisStageReceipt = read_bounded_comparison_json(
        &session,
        stage_artifact,
        MAX_COMPARISON_STAGE_BYTES,
        "analysis stage",
    )?;
    validate_analysis_stage_receipt(
        &stage,
        stage_artifact,
        &manifest.artifacts,
        session.id().as_str(),
    )?;
    let health_artifact = required_artifact(&manifest.artifacts, "health")?;
    let health: HealthReport = read_bounded_comparison_json(
        &session,
        health_artifact,
        MAX_COMPARISON_HEALTH_BYTES,
        "health",
    )?;
    validate_health_document(&session, &health, &stage)?;
    let summary_artifact = required_artifact(&manifest.artifacts, "analysis-summary")?;
    let summary: AnalysisSummaryDocument = read_bounded_comparison_json(
        &session,
        summary_artifact,
        MAX_COMPARISON_AGGREGATE_BYTES,
        "analysis summary",
    )?;
    validate_summary_document(
        &session,
        summary_artifact,
        &summary,
        &stage,
        &manifest.artifacts,
    )?;
    let (hotspots, hotspots_artifact) = if health.verdict == HealthVerdict::Valid {
        let hotspots_artifact = required_artifact(&manifest.artifacts, "hotspots")?;
        let hotspots: HotspotReport = read_bounded_comparison_json(
            &session,
            hotspots_artifact,
            MAX_COMPARISON_AGGREGATE_BYTES,
            "hotspots",
        )?;
        hotspots.validate().map_err(AppError::operational)?;
        if hotspots.session_id != session.id().as_str()
            || hotspots.schema != stage.contracts.hotspots_schema
        {
            return Err(AppError::operational(
                "comparison hotspot report does not match its completed analysis stage",
            ));
        }
        (Some(hotspots), Some(hotspots_artifact))
    } else {
        (None, None)
    };
    let claims = crate::operations::comparison_input_claims(
        &manifest,
        stage_artifact,
        health_artifact,
        hotspots_artifact,
        summary_artifact,
    )?;
    Ok(ComparisonDocuments {
        manifest,
        health,
        hotspots,
        summary,
        claims,
        _lock: lock,
    })
}

fn validate_comparison_scale(documents: &ComparisonDocuments, role: &str) -> Result<(), AppError> {
    if let Some(hotspots) = &documents.hotspots {
        let subjects = hotspots
            .functions
            .len()
            .saturating_add(hotspots.sampling.len());
        if subjects > MAX_COMPARISON_HOTSPOT_SUBJECTS {
            return Err(AppError::unsupported(
                "compare.hotspot_subjects",
                format!(
                    "{role} has {subjects} hotspot subjects; maximum is {MAX_COMPARISON_HOTSPOT_SUBJECTS}"
                ),
            ));
        }
    }
    if let Some(quantitative) = &documents.summary.quantitative {
        let subjects = quantitative
            .analysis
            .resources
            .counters
            .len()
            .saturating_add(quantitative.analysis.resources.derived.len());
        if subjects > MAX_COMPARISON_RESOURCE_SUBJECTS {
            return Err(AppError::unsupported(
                "compare.resource_subjects",
                format!(
                    "{role} has {subjects} resource subjects; maximum is {MAX_COMPARISON_RESOURCE_SUBJECTS}"
                ),
            ));
        }
    }
    Ok(())
}

fn comparison_policy_source(value: &str) -> Value {
    match value {
        "default" | "strict" | "relaxed" => json!({
            "kind": "named",
            "name": value,
        }),
        value if value.trim_start().starts_with('{') => json!({"kind": "inline"}),
        _ => json!({"kind": "file"}),
    }
}

fn comparison_report_projection(report: &ComparisonReport, top: usize) -> Value {
    let mut metrics = report.metrics.iter().collect::<Vec<_>>();
    metrics.sort_by(|left, right| {
        metric_outcome_rank(left.outcome)
            .cmp(&metric_outcome_rank(right.outcome))
            .then_with(|| metric_magnitude(right).total_cmp(&metric_magnitude(left)))
            .then_with(|| left.subject.id.cmp(&right.subject.id))
    });
    let mut resource_metrics = report.resource_metrics.iter().collect::<Vec<_>>();
    resource_metrics.sort_by(|left, right| {
        resource_outcome_rank(left.outcome)
            .cmp(&resource_outcome_rank(right.outcome))
            .then_with(|| resource_magnitude(right).total_cmp(&resource_magnitude(left)))
            .then_with(|| left.semantic.cmp(&right.semantic))
            .then_with(|| left.subject.cmp(&right.subject))
    });
    let mut static_ram_metrics = report.static_ram_metrics.iter().collect::<Vec<_>>();
    static_ram_metrics.sort_by(|left, right| {
        metric_outcome_rank(left.outcome)
            .cmp(&metric_outcome_rank(right.outcome))
            .then_with(|| {
                right
                    .candidate_bytes
                    .abs_diff(right.baseline_bytes)
                    .cmp(&left.candidate_bytes.abs_diff(left.baseline_bytes))
            })
            .then_with(|| left.metric.cmp(&right.metric))
    });

    let reasons = report
        .reasons
        .iter()
        .take(MAX_COMPARISON_REASONS)
        .map(|reason| bounded_comparison_text(reason))
        .collect::<Vec<_>>();
    let metric_values = metrics
        .iter()
        .take(top)
        .map(|row| bounded_comparison_row(*row))
        .collect::<Vec<_>>();
    let resource_values = resource_metrics
        .iter()
        .take(top)
        .map(|row| bounded_comparison_row(*row))
        .collect::<Vec<_>>();
    let static_ram_values = static_ram_metrics
        .iter()
        .take(top)
        .map(|row| bounded_comparison_row(*row))
        .collect::<Vec<_>>();
    let reasons_returned_count = reasons.len();
    let metrics_returned_count = metric_values.len();
    let resource_metrics_returned_count = resource_values.len();
    let static_ram_metrics_returned_count = static_ram_values.len();

    json!({
        "schema": report.schema,
        "baseline_session_id": bounded_comparison_text(&report.baseline_session_id),
        "candidate_session_id": bounded_comparison_text(&report.candidate_session_id),
        "baseline_health": report.baseline_health,
        "candidate_health": report.candidate_health,
        "verdict": report.verdict,
        "requested_top": top,
        "reasons": reasons,
        "reasons_total_count": report.reasons.len(),
        "reasons_returned_count": reasons_returned_count,
        "reasons_truncated": report.reasons.len() > reasons_returned_count,
        "metrics": metric_values,
        "metrics_total_count": report.metrics.len(),
        "metrics_returned_count": metrics_returned_count,
        "metrics_truncated": report.metrics.len() > metrics_returned_count,
        "resource_metrics": resource_values,
        "resource_metrics_total_count": report.resource_metrics.len(),
        "resource_metrics_returned_count": resource_metrics_returned_count,
        "resource_metrics_truncated": report.resource_metrics.len() > resource_metrics_returned_count,
        "static_ram_metrics": static_ram_values,
        "static_ram_metrics_total_count": report.static_ram_metrics.len(),
        "static_ram_metrics_returned_count": static_ram_metrics_returned_count,
        "static_ram_metrics_truncated": report.static_ram_metrics.len() > static_ram_metrics_returned_count,
        "outcome_counts": {
            "metrics": metric_outcome_counts(&report.metrics),
            "resource_metrics": resource_outcome_counts(&report.resource_metrics),
            "static_ram_metrics": static_ram_outcome_counts(&report.static_ram_metrics),
        },
    })
}

fn metric_outcome_rank(outcome: MetricComparisonOutcome) -> u8 {
    match outcome {
        MetricComparisonOutcome::Regressed => 0,
        MetricComparisonOutcome::Inconclusive => 1,
        MetricComparisonOutcome::Improved => 2,
        MetricComparisonOutcome::Unchanged => 3,
    }
}

fn resource_outcome_rank(outcome: ResourceMetricComparisonOutcome) -> u8 {
    match outcome {
        ResourceMetricComparisonOutcome::Regressed => 0,
        ResourceMetricComparisonOutcome::Inconclusive => 1,
        ResourceMetricComparisonOutcome::Improved => 2,
        ResourceMetricComparisonOutcome::Unchanged => 3,
        ResourceMetricComparisonOutcome::Informational => 4,
    }
}

fn metric_magnitude(metric: &MetricComparison) -> f64 {
    metric.relative_change.map_or(metric.delta.abs(), f64::abs)
}

fn resource_magnitude(metric: &ResourceMetricComparison) -> f64 {
    metric.relative_change.map_or(metric.delta.abs(), f64::abs)
}

fn metric_outcome_counts(metrics: &[MetricComparison]) -> Value {
    let mut improved = 0_usize;
    let mut unchanged = 0_usize;
    let mut regressed = 0_usize;
    let mut inconclusive = 0_usize;
    for metric in metrics {
        match metric.outcome {
            MetricComparisonOutcome::Improved => improved += 1,
            MetricComparisonOutcome::Unchanged => unchanged += 1,
            MetricComparisonOutcome::Regressed => regressed += 1,
            MetricComparisonOutcome::Inconclusive => inconclusive += 1,
        }
    }
    json!({
        "total": metrics.len(),
        "improved": improved,
        "unchanged": unchanged,
        "regressed": regressed,
        "inconclusive": inconclusive,
    })
}

fn resource_outcome_counts(metrics: &[ResourceMetricComparison]) -> Value {
    let mut improved = 0_usize;
    let mut unchanged = 0_usize;
    let mut regressed = 0_usize;
    let mut inconclusive = 0_usize;
    let mut informational = 0_usize;
    for metric in metrics {
        match metric.outcome {
            ResourceMetricComparisonOutcome::Improved => improved += 1,
            ResourceMetricComparisonOutcome::Unchanged => unchanged += 1,
            ResourceMetricComparisonOutcome::Regressed => regressed += 1,
            ResourceMetricComparisonOutcome::Inconclusive => inconclusive += 1,
            ResourceMetricComparisonOutcome::Informational => informational += 1,
        }
    }
    json!({
        "total": metrics.len(),
        "improved": improved,
        "unchanged": unchanged,
        "regressed": regressed,
        "inconclusive": inconclusive,
        "informational": informational,
    })
}

fn static_ram_outcome_counts(metrics: &[StaticRamMetricComparison]) -> Value {
    let mut improved = 0_usize;
    let mut unchanged = 0_usize;
    let mut regressed = 0_usize;
    let mut inconclusive = 0_usize;
    for metric in metrics {
        match metric.outcome {
            MetricComparisonOutcome::Improved => improved += 1,
            MetricComparisonOutcome::Unchanged => unchanged += 1,
            MetricComparisonOutcome::Regressed => regressed += 1,
            MetricComparisonOutcome::Inconclusive => inconclusive += 1,
        }
    }
    json!({
        "total": metrics.len(),
        "improved": improved,
        "unchanged": unchanged,
        "regressed": regressed,
        "inconclusive": inconclusive,
    })
}

fn bounded_comparison_row(value: &impl serde::Serialize) -> Value {
    let mut value = serde_json::to_value(value).expect("validated comparison row is serializable");
    let truncated = constrain_comparison_projection(&mut value);
    if truncated && let Some(object) = value.as_object_mut() {
        object.insert("projection_truncated".to_owned(), Value::Bool(true));
    }
    value
}

fn constrain_comparison_projection(value: &mut Value) -> bool {
    match value {
        Value::String(text) => truncate_comparison_text(text),
        Value::Array(values) => {
            let mut truncated = false;
            if values.len() > MAX_COMPARISON_NESTED_VALUES {
                values.truncate(MAX_COMPARISON_NESTED_VALUES);
                truncated = true;
            }
            values.iter_mut().fold(truncated, |changed, value| {
                constrain_comparison_projection(value) || changed
            })
        }
        Value::Object(object) => {
            let keys = object.keys().cloned().collect::<Vec<_>>();
            let mut additions = Vec::new();
            let mut truncated = false;
            for key in keys {
                let Some(child) = object.get_mut(&key) else {
                    continue;
                };
                if let Value::Array(values) = child {
                    let total_count = values.len();
                    if total_count > MAX_COMPARISON_NESTED_VALUES {
                        values.truncate(MAX_COMPARISON_NESTED_VALUES);
                        additions.push((format!("{key}_total_count"), json!(total_count)));
                        additions.push((format!("{key}_truncated"), Value::Bool(true)));
                        truncated = true;
                    }
                }
                truncated = constrain_comparison_projection(child) || truncated;
            }
            object.extend(additions);
            truncated
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn bounded_comparison_text(value: &str) -> String {
    let mut value = value.to_owned();
    truncate_comparison_text(&mut value);
    value
}

fn truncate_comparison_text(value: &mut String) -> bool {
    if value.len() <= MAX_COMPARISON_TEXT_BYTES {
        return false;
    }
    let suffix = "...";
    let mut boundary = MAX_COMPARISON_TEXT_BYTES.saturating_sub(suffix.len());
    while !value.is_char_boundary(boundary) {
        boundary = boundary.saturating_sub(1);
    }
    value.truncate(boundary);
    value.push_str(suffix);
    true
}

fn read_bounded_comparison_json<T: DeserializeOwned>(
    session: &Session,
    artifact: &Artifact,
    limit: u64,
    document: &str,
) -> Result<T, AppError> {
    if artifact.size_bytes > limit {
        return Err(AppError::unsupported(
            "compare.input_size",
            format!(
                "{document} artifact `{}` is {} bytes; comparison limit is {limit} bytes",
                artifact.id, artifact.size_bytes
            ),
        ));
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
        return Err(AppError::unsupported(
            "compare.input_size",
            format!(
                "{document} artifact `{}` grew beyond the comparison limit of {limit} bytes while reading",
                artifact.id
            ),
        ));
    }
    strict_json::from_slice(&bytes).map_err(AppError::operational)
}

/// Checks the untrusted policy source before callers open comparison Sessions.
/// `compare` invokes this same parser again when it needs the policy, so a
/// file changed after preflight cannot affect the input-ordering guarantee.
pub(crate) fn preflight_comparison_policy(value: &str) -> Result<(), AppError> {
    comparison_policy(value).map(|_| ())
}

fn comparison_policy(value: &str) -> Result<ComparisonPolicy, AppError> {
    let policy = match value {
        "default" | "strict" => ComparisonPolicy::default(),
        "relaxed" => {
            let mut policy = ComparisonPolicy {
                relative_threshold: 0.10,
                absolute_time_threshold_ns: 0,
                absolute_count_threshold: 0,
                require_exact_metrics: false,
                require_matching_request: false,
                require_same_adapter_version: true,
                compare_statistical_metrics: true,
                require_complete_provenance: true,
                ..ComparisonPolicy::default()
            };
            for rule in &mut policy.resource_rules {
                rule.relative_threshold = 0.10;
            }
            policy
        }
        value if value.trim_start().starts_with('{') => parse_policy_json(value.as_bytes())?,
        path => read_policy_file(Path::new(path))?,
    };
    if !policy.relative_threshold.is_finite() || policy.relative_threshold < 0.0 {
        return Err(AppError::operational(
            "comparison relative_threshold must be finite and nonnegative",
        ));
    }
    let mut selectors = BTreeSet::new();
    for rule in &policy.resource_rules {
        if !rule.absolute_threshold.is_finite()
            || rule.absolute_threshold < 0.0
            || !rule.relative_threshold.is_finite()
            || rule.relative_threshold < 0.0
            || rule.subject.as_ref().is_some_and(|subject| {
                subject.validate().is_err()
                    || rule
                        .semantic
                        .standard_spec()
                        .is_some_and(|spec| subject.kind() != Some(spec.subject_kind))
            })
            || !selectors.insert((rule.semantic.clone(), rule.subject.clone()))
        {
            return Err(AppError::operational(
                "comparison resource rules must have unique selectors, valid subjects, and finite nonnegative thresholds",
            ));
        }
    }
    Ok(policy)
}

fn read_policy_file(path: &Path) -> Result<ComparisonPolicy, AppError> {
    const MAX_POLICY_BYTES: u64 = 64 * 1024;

    let metadata = fs::symlink_metadata(path).map_err(AppError::operational)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_windows_reparse(&metadata) {
        return Err(AppError::operational(format!(
            "comparison policy `{}` must be a plain regular file",
            path.display()
        )));
    }
    if metadata.len() > MAX_POLICY_BYTES {
        return Err(AppError::operational(format!(
            "comparison policy `{}` exceeds {MAX_POLICY_BYTES} bytes",
            path.display()
        )));
    }
    let file = File::open(path).map_err(AppError::operational)?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(MAX_POLICY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(AppError::operational)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_POLICY_BYTES {
        return Err(AppError::operational(format!(
            "comparison policy `{}` grew beyond {MAX_POLICY_BYTES} bytes while reading",
            path.display()
        )));
    }
    parse_policy_json(&bytes)
}

fn parse_policy_json(bytes: &[u8]) -> Result<ComparisonPolicy, AppError> {
    const FIELDS: &[&str] = &[
        "relative_threshold",
        "absolute_time_threshold_ns",
        "absolute_count_threshold",
        "require_exact_metrics",
        "require_matching_request",
        "require_same_adapter_version",
        "require_same_firmware_identity",
        "require_same_health_policy_version",
        "require_same_tool_contract",
        "allow_function_set_changes",
        "resource_rules",
        "allow_resource_subject_set_changes",
        "compare_statistical_metrics",
        "require_complete_provenance",
    ];

    let value: Value = strict_json::from_slice(bytes).map_err(AppError::operational)?;
    let object = value.as_object().ok_or_else(|| {
        AppError::operational("comparison policy JSON must contain exactly one object")
    })?;
    if let Some(unknown) = object.keys().find(|key| !FIELDS.contains(&key.as_str())) {
        return Err(AppError::operational(format!(
            "comparison policy contains unknown field `{unknown}`"
        )));
    }
    strict_json::from_slice(bytes).map_err(AppError::operational)
}

fn is_windows_reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        false
    }
}

fn build_manifest(session: &Session, artifacts: Vec<Artifact>) -> Result<Manifest, AppError> {
    let state = session.read_state().map_err(AppError::operational)?;
    let receipt = trusted_capture_receipt(session, &artifacts)?;
    let capture_config =
        registered_capture_config(session, &artifacts).map_err(AppError::operational)?;
    let stage_artifact = required_artifact(&artifacts, ANALYSIS_STAGE_ID)?;
    let stage_receipt: AnalysisStageReceipt = read_json_artifact(session, stage_artifact)?;
    validate_analysis_stage_receipt(
        &stage_receipt,
        stage_artifact,
        &artifacts,
        session.id().as_str(),
    )?;
    let capture_outputs = artifacts
        .iter()
        .filter(|artifact| {
            !stage_receipt
                .output_artifacts
                .iter()
                .any(|output| output.id == artifact.id)
                && artifact.id != ANALYSIS_STAGE_ID
                && artifact.id != ANALYSIS_REQUEST_ID
                && artifact.id != "perfetto"
        })
        .map(|artifact| artifact.id.clone())
        .collect::<Vec<_>>();
    let analysis_outputs = stage_receipt
        .output_artifacts
        .iter()
        .map(|artifact| artifact.id.clone())
        .chain([ANALYSIS_REQUEST_ID.to_owned(), ANALYSIS_STAGE_ID.to_owned()])
        .collect::<Vec<_>>();
    let convert_outputs = artifacts
        .iter()
        .filter(|artifact| artifact.id == "perfetto")
        .map(|artifact| artifact.id.clone())
        .collect::<Vec<_>>();

    Ok(Manifest {
        schema: ManifestSchemaVersion,
        session_id: session.id().to_string(),
        created_at: state.created_at,
        tool: ToolInfo {
            name: "t32perf".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            commit: option_env!("T32PERF_COMMIT").map(str::to_owned),
        },
        capture: CaptureInfo {
            provider: Some(receipt.provider.clone()),
            mode: receipt.mode.clone(),
            adapter: receipt.adapter.clone(),
            target: receipt.target.clone(),
            trace32: receipt.trace32.clone(),
            request_sha256: Some(receipt.request_sha256.clone()),
            covered_cores: receipt.covered_cores.clone(),
            capabilities: Some(receipt.capabilities.clone()),
            capture_config: receipt.capture_config.clone(),
            instrumentation: capture_config.document.instrumentation.clone(),
        },
        firmware: receipt.firmware.clone(),
        clocks: receipt.clocks.clone(),
        stages: vec![
            StageInfo {
                name: "capture".to_owned(),
                status: StageStatus::Complete,
                started_at: None,
                completed_at: None,
                input_artifact_ids: Vec::new(),
                output_artifact_ids: capture_outputs,
                message: None,
            },
            StageInfo {
                name: "analyze".to_owned(),
                status: StageStatus::Complete,
                started_at: None,
                completed_at: None,
                input_artifact_ids: stage_receipt
                    .input_artifacts
                    .into_iter()
                    .map(|artifact| artifact.id)
                    .collect(),
                output_artifact_ids: analysis_outputs,
                message: None,
            },
            StageInfo {
                name: "convert".to_owned(),
                status: StageStatus::Complete,
                started_at: None,
                completed_at: None,
                input_artifact_ids: vec![
                    "observations".to_owned(),
                    "derived".to_owned(),
                    "health".to_owned(),
                    ANALYSIS_STAGE_ID.to_owned(),
                ],
                output_artifact_ids: convert_outputs,
                message: None,
            },
        ],
        artifacts,
    })
}

fn trusted_capture_receipt(
    session: &Session,
    artifacts: &[Artifact],
) -> Result<CaptureReceipt, AppError> {
    let artifact = artifacts
        .iter()
        .find(|artifact| artifact.id == CAPTURE_RECEIPT_ID)
        .ok_or_else(|| {
            AppError::unsupported(
                "capture.receipt",
                "analysis requires a trusted capture-receipt artifact; external ingest without one is not trusted",
            )
        })?;
    if artifact.producer == SYNTHETIC_RECEIPT_PRODUCER {
        let capture_config =
            registered_capture_config(session, artifacts).map_err(AppError::operational)?;
        if artifact.kind != "capture_receipt"
            || artifact.relative_path.as_str() != CAPTURE_RECEIPT_PATH
            || artifact.media_type != "application/json"
            || artifact.input_artifact_ids
                != ["observations".to_owned(), CAPTURE_CONFIG_ID.to_owned()]
        {
            return Err(AppError::operational(
                "synthetic capture receipt catalog identity or provenance is invalid",
            ));
        }
        if capture_config.artifact.producer != SYNTHETIC_CAPTURE_CONFIG_PRODUCER {
            return Err(AppError::operational(
                "synthetic capture config producer is invalid",
            ));
        }
        let receipt: CaptureReceipt = read_json_artifact(session, artifact)?;
        let request_sha256 = session.request_sha256().map_err(AppError::operational)?;
        validate_trusted_synthetic_receipt(&receipt, session.id().as_str(), &request_sha256)?;
        validate_capture_config_receipt(&capture_config, &receipt)
            .map_err(AppError::operational)?;
        return Ok(receipt);
    }

    verify_registered_external_capture(session, artifacts, artifact)
        .map(|verified| verified.receipt)
        .map_err(AppError::operational)
}

fn validate_resource_flavors(
    linker_map_flavor: &str,
    stack_usage_flavor: &str,
) -> Result<(), AppError> {
    if !matches!(
        linker_map_flavor,
        GNU_LD_MAP_V1_FLAVOR | ELF_SECTIONS_V1_FLAVOR
    ) {
        return Err(AppError::unsupported(
            "analyze.static_ram_flavor",
            format!("static RAM flavor `{linker_map_flavor}` is unsupported"),
        ));
    }
    if stack_usage_flavor != GCC_STACK_USAGE_V1_FLAVOR {
        return Err(AppError::unsupported(
            "analyze.stack_usage_flavor",
            format!("stack usage flavor `{stack_usage_flavor}` is unsupported"),
        ));
    }
    Ok(())
}

fn analysis_contracts() -> AnalysisContracts {
    AnalysisContracts {
        analyzer: ANALYZER_CONTRACT.to_owned(),
        health_policy: "t32perf.health-policy/v1".to_owned(),
        health_schema: HealthSchemaVersion,
        derived_stream_schema: DerivedStreamSchemaVersion,
        hotspots_schema: HotspotsSchemaVersion,
        analysis_summary_schema: AnalysisSummarySchemaVersion,
    }
}

fn selected_analysis_input_claims(
    observations: &Artifact,
    capture_receipt: &Artifact,
    resources: &ResourceInputs,
    linker_map_flavor: &str,
) -> Result<Vec<Artifact>, AppError> {
    let selected_static_source = match linker_map_flavor {
        GNU_LD_MAP_V1_FLAVOR => resources.linker_map.as_ref(),
        ELF_SECTIONS_V1_FLAVOR => resources.firmware_elf.as_ref(),
        _ => None,
    };
    if selected_static_source.is_none() {
        let mismatched = match linker_map_flavor {
            GNU_LD_MAP_V1_FLAVOR => resources.firmware_elf.as_ref(),
            ELF_SECTIONS_V1_FLAVOR => resources.linker_map.as_ref(),
            _ => None,
        };
        if mismatched.is_some() {
            return Err(AppError::operational(format!(
                "analysis selects static RAM flavor `{linker_map_flavor}` but the matching source artifact kind `{}` is absent",
                static_ram_source_kind(linker_map_flavor).unwrap_or("unsupported")
            )));
        }
    }
    let mut claims = vec![observations.clone(), capture_receipt.clone()];
    if let Some(source) = selected_static_source {
        claims.push(source.clone());
        if let Some(config) = &resources.static_ram_config {
            claims.push(config.clone());
        }
    }
    if let Some(stack_usage) = &resources.stack_usage {
        claims.push(stack_usage.clone());
    }
    Ok(claims)
}

fn expected_analysis_request(
    session: &Session,
    observations: &Artifact,
    capture_receipt: &Artifact,
    resources: &ResourceInputs,
    linker_map_flavor: &str,
    stack_usage_flavor: &str,
) -> Result<AnalysisRequest, AppError> {
    Ok(AnalysisRequest {
        schema: ANALYSIS_REQUEST_SCHEMA.to_owned(),
        session_id: session.id().to_string(),
        linker_map_flavor: linker_map_flavor.to_owned(),
        stack_usage_flavor: stack_usage_flavor.to_owned(),
        contracts: analysis_contracts(),
        input_artifacts: selected_analysis_input_claims(
            observations,
            capture_receipt,
            resources,
            linker_map_flavor,
        )?,
    })
}

fn analysis_request_spec(input_ids: Vec<String>) -> Result<ArtifactSpec, AppError> {
    artifact_spec(
        ANALYSIS_REQUEST_ID,
        ANALYSIS_REQUEST_KIND,
        ANALYSIS_REQUEST_PATH,
        "application/json",
        input_ids,
        ANALYSIS_REQUEST_PRODUCER,
    )
}

fn ensure_analysis_request(
    session: &Session,
    lock: &SessionLock,
    inputs: AnalysisRequestInputs<'_>,
    allow_create: bool,
) -> Result<Artifact, AppError> {
    let request = expected_analysis_request(
        session,
        inputs.observations,
        inputs.capture_receipt,
        inputs.resources,
        inputs.linker_map_flavor,
        inputs.stack_usage_flavor,
    )?;
    let input_ids = request
        .input_artifacts
        .iter()
        .map(|artifact| artifact.id.clone())
        .collect();
    let spec = analysis_request_spec(input_ids)?;
    if let Some(existing) = inputs
        .artifacts
        .iter()
        .find(|artifact| artifact.id == ANALYSIS_REQUEST_ID)
    {
        if existing.kind != spec.kind
            || existing.relative_path != spec.relative_path
            || existing.media_type != spec.media_type
            || existing.producer != spec.producer
            || existing.input_artifact_ids != spec.input_artifact_ids
        {
            return Err(AppError::operational(
                "analysis request artifact identity or provenance does not match the requested analysis",
            ));
        }
        session
            .verify_artifact(existing, true)
            .map_err(AppError::operational)?;
        let decoded: AnalysisRequest = read_json_artifact(session, existing)?;
        if decoded != request {
            return Err(AppError::operational(
                "analysis request artifact does not exactly bind this analysis invocation",
            ));
        }
        return Ok(existing.clone());
    }
    if !allow_create {
        return Err(AppError::operational(
            "Processing Session lacks the immutable analysis request required for recovery",
        ));
    }
    let bytes = serde_json::to_vec(&request).map_err(AppError::operational)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_ANALYSIS_REQUEST_BYTES {
        return Err(AppError::operational(
            "analysis request exceeds its fixed size bound",
        ));
    }
    let staged = ArtifactPath::new(ANALYSIS_REQUEST_STAGED_PATH).map_err(AppError::operational)?;
    session
        .ensure_staged_exact(lock, &staged, &bytes, MAX_ANALYSIS_REQUEST_BYTES)
        .map_err(AppError::operational)?;
    let artifact = session
        .ingest_staged_bounded(lock, &staged, spec, MAX_ANALYSIS_REQUEST_BYTES)
        .map_err(AppError::operational)?;
    Ok(artifact)
}

fn validate_analysis_stage_request_binding(
    session: &Session,
    stage: &AnalysisStageReceipt,
    request_artifact: &Artifact,
) -> Result<(), AppError> {
    if !stage
        .input_artifacts
        .iter()
        .any(|artifact| artifact == request_artifact)
    {
        return Err(AppError::operational(
            "analysis stage receipt does not claim the immutable analysis request",
        ));
    }
    let request: AnalysisRequest = read_json_artifact(session, request_artifact)?;
    let mut expected_stage_inputs = request.input_artifacts.clone();
    // Analysis execution records the immutable request directly after the
    // capture core, before optional resource claims. Keep recovery validation
    // in that same canonical order.
    expected_stage_inputs.insert(2, request_artifact.clone());
    if request.schema != ANALYSIS_REQUEST_SCHEMA
        || request.session_id != session.id().as_str()
        || request.contracts != stage.contracts
        || expected_stage_inputs != stage.input_artifacts
    {
        return Err(AppError::operational(
            "analysis stage receipt does not match the immutable analysis request binding",
        ));
    }
    Ok(())
}

fn resource_inputs(artifacts: &[Artifact]) -> Result<ResourceInputs, AppError> {
    let inputs = ResourceInputs {
        linker_map: unique_artifact_by_kind(artifacts, "linker_map")?,
        firmware_elf: unique_artifact_by_kind(artifacts, "firmware_elf")?,
        static_ram_config: unique_artifact_by_kind(artifacts, "static_ram_config")?,
        stack_usage: unique_artifact_by_kind(artifacts, "stack_usage")?,
    };
    if inputs.static_ram_config.is_some()
        && inputs.linker_map.is_none()
        && inputs.firmware_elf.is_none()
    {
        return Err(AppError::operational(
            "a static_ram_config artifact requires a linker_map or firmware_elf artifact",
        ));
    }
    Ok(inputs)
}

fn unique_artifact_by_kind(
    artifacts: &[Artifact],
    kind: &str,
) -> Result<Option<Artifact>, AppError> {
    let mut matches = artifacts.iter().filter(|artifact| artifact.kind == kind);
    let first = matches.next().cloned();
    if matches.next().is_some() {
        return Err(AppError::operational(format!(
            "multiple `{kind}` artifacts are registered; analysis requires an unambiguous input"
        )));
    }
    Ok(first)
}

fn parse_resource_reports(
    session: &Session,
    inputs: &ResourceInputs,
    linker_map_flavor: &str,
    stack_usage_flavor: &str,
) -> Result<ParsedResourceReports, AppError> {
    let static_ram_source = match linker_map_flavor {
        GNU_LD_MAP_V1_FLAVOR => inputs.linker_map.as_ref(),
        ELF_SECTIONS_V1_FLAVOR => inputs.firmware_elf.as_ref(),
        _ => None,
    };
    if static_ram_source.is_none() {
        let mismatched_source = match linker_map_flavor {
            GNU_LD_MAP_V1_FLAVOR => inputs.firmware_elf.as_ref(),
            ELF_SECTIONS_V1_FLAVOR => inputs.linker_map.as_ref(),
            _ => None,
        };
        if mismatched_source.is_some() {
            return Err(AppError::operational(format!(
                "analysis selects static RAM flavor `{linker_map_flavor}` but the matching source artifact kind `{}` is absent",
                static_ram_source_kind(linker_map_flavor).unwrap_or("unsupported")
            )));
        }
    }
    let static_ram = static_ram_source
        .map(|artifact| {
            let (document, config_artifact) = match inputs.static_ram_config.as_ref() {
                Some(config_artifact) => {
                    if config_artifact.size_bytes > MAX_STATIC_RAM_CONFIG_BYTES {
                        return Err(AppError::unsupported(
                            "analyze.static_ram_config_size",
                            format!(
                                "static RAM config artifact `{}` is {} bytes; maximum is {MAX_STATIC_RAM_CONFIG_BYTES} bytes",
                                config_artifact.id, config_artifact.size_bytes
                            ),
                        ));
                    }
                    let document: StaticRamConfigDocument =
                        read_json_artifact(session, config_artifact)?;
                    document.validate().map_err(AppError::operational)?;
                    (document, Some(config_artifact.clone()))
                }
                None => (
                    match linker_map_flavor {
                        GNU_LD_MAP_V1_FLAVOR => StaticRamConfigDocument::gnu_ld_map_v1(),
                        ELF_SECTIONS_V1_FLAVOR => StaticRamConfigDocument::elf_sections_v1(),
                        _ => unreachable!("resource flavors were validated before parsing"),
                    },
                    None,
                ),
            };
            if document.flavor != linker_map_flavor {
                return Err(AppError::operational(format!(
                    "static RAM configuration flavor `{}` does not match requested flavor `{linker_map_flavor}`",
                    document.flavor
                )));
            }
            let config =
                StaticRamParserConfig::from_document(&document).map_err(AppError::operational)?;
            let provenance = static_ram_config_provenance(&document, config_artifact.as_ref())?;
            let file = session
                .open_artifact(artifact)
                .map_err(AppError::operational)?;
            let report = parse_static_ram_report(
                linker_map_flavor,
                BufReader::new(file),
                &config,
            )
            .map_err(AppError::operational)?;
            Ok::<_, AppError>(ParsedStaticRamReport {
                source: artifact.clone(),
                report,
                config: provenance,
                config_artifact,
            })
        })
        .transpose()?;
    let stack_usage = inputs
        .stack_usage
        .as_ref()
        .map(|artifact| {
            let file = session
                .open_artifact(artifact)
                .map_err(AppError::operational)?;
            let report = parse_stack_usage_report(
                stack_usage_flavor,
                BufReader::new(file),
                LineLimits::default(),
            )
            .map_err(AppError::operational)?;
            Ok::<_, AppError>((artifact.clone(), report))
        })
        .transpose()?;
    Ok(ParsedResourceReports {
        static_ram,
        stack_usage,
    })
}

fn static_ram_config_provenance(
    document: &StaticRamConfigDocument,
    artifact: Option<&Artifact>,
) -> Result<StaticRamConfigProvenance, AppError> {
    let sha256 = match artifact {
        Some(artifact) => artifact.sha256.clone(),
        None => {
            let bytes = serde_json::to_vec(document).map_err(AppError::operational)?;
            Sha256Digest::new(encode_lower_hex(&Sha256::digest(bytes)))
                .map_err(AppError::operational)?
        }
    };
    Ok(StaticRamConfigProvenance {
        artifact_id: artifact.map(|artifact| artifact.id.clone()),
        sha256,
    })
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub(crate) fn validate_health_document(
    session: &Session,
    health: &HealthReport,
    stage: &AnalysisStageReceipt,
) -> Result<(), AppError> {
    health.validate().map_err(AppError::operational)?;
    if health.session_id != session.id().as_str() {
        return Err(AppError::operational(
            "health report session does not match the owning session",
        ));
    }
    let observation_count = u64::try_from(health.observations.len())
        .map_err(|_| AppError::operational("health observation count exceeds u64"))?;
    let issue_count = u64::try_from(health.issues.len())
        .map_err(|_| AppError::operational("health issue count exceeds u64"))?;
    if stage.contracts.health_schema != health.schema
        || stage.health_verdict != health.verdict
        || stage.metric_support != health.metric_support
        || stage.contracts.health_policy != health.policy_version
        || stage.diagnostics.health_observation_count != observation_count
        || stage.diagnostics.health_issue_count != issue_count
    {
        return Err(AppError::operational(
            "health report does not match the completed analysis stage receipt",
        ));
    }
    Ok(())
}

pub(crate) fn validate_summary_document(
    session: &Session,
    summary_artifact: &Artifact,
    summary: &AnalysisSummaryDocument,
    stage: &AnalysisStageReceipt,
    catalog: &[Artifact],
) -> Result<(), AppError> {
    summary.validate().map_err(AppError::operational)?;
    if summary.session_id != session.id().as_str() {
        return Err(AppError::operational(
            "analysis summary session does not match the owning session",
        ));
    }
    if stage.contracts.analysis_summary_schema != summary.schema
        || summary.health_verdict != stage.health_verdict
        || summary.metric_support != stage.metric_support
        || summary.diagnostics != stage.diagnostics
    {
        return Err(AppError::operational(
            "analysis summary health, support, or diagnostic counts do not match the completed analysis stage",
        ));
    }
    for claim in &summary.input_artifacts {
        let registered = required_artifact(catalog, &claim.id)?;
        if registered != claim {
            return Err(AppError::operational(format!(
                "analysis summary input claim for artifact `{}` does not exactly match the catalog",
                claim.id
            )));
        }
    }
    let input_ids = summary
        .input_artifacts
        .iter()
        .map(|artifact| artifact.id.clone())
        .collect::<Vec<_>>();
    if summary_artifact.input_artifact_ids != input_ids {
        return Err(AppError::operational(
            "analysis summary artifact provenance does not exactly match its embedded input claims",
        ));
    }
    let input_set = input_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if !["observations", CAPTURE_RECEIPT_ID, "derived", "health"]
        .into_iter()
        .all(|required| input_set.contains(required))
    {
        return Err(AppError::operational(
            "analysis summary omits a required observations, receipt, derived, or health input claim",
        ));
    }
    if let Some(quantitative) = &summary.quantitative {
        if let Some(static_ram) = &quantitative.static_ram {
            let report_artifact = required_artifact(catalog, &static_ram.artifact_id)?;
            let source_artifact = required_artifact(catalog, &static_ram.source_artifact_id)?;
            let expected_report_kind =
                static_ram_artifact_kind(&static_ram.flavor).ok_or_else(|| {
                    AppError::unsupported(
                        "analysis_summary.static_ram.flavor",
                        format!(
                            "static RAM summary flavor `{}` is unsupported",
                            static_ram.flavor
                        ),
                    )
                })?;
            let expected_source_kind =
                static_ram_source_kind(&static_ram.flavor).ok_or_else(|| {
                    AppError::unsupported(
                        "analysis_summary.static_ram.flavor",
                        format!(
                            "static RAM summary flavor `{}` is unsupported",
                            static_ram.flavor
                        ),
                    )
                })?;
            if report_artifact.id != STATIC_RAM_ID
                || report_artifact.kind != expected_report_kind
                || source_artifact.kind != expected_source_kind
                || !report_artifact
                    .input_artifact_ids
                    .contains(&source_artifact.id)
                || !stage
                    .output_artifacts
                    .iter()
                    .any(|artifact| artifact == report_artifact)
                || !stage
                    .input_artifacts
                    .iter()
                    .any(|artifact| artifact == source_artifact)
            {
                return Err(AppError::operational(
                    "static RAM summary does not match stage input/output provenance",
                ));
            }
            let config = static_ram.config.as_ref().ok_or_else(|| {
                AppError::operational("static RAM summary omits parser configuration provenance")
            })?;
            if let Some(config_id) = &config.artifact_id {
                let config_artifact = stage
                    .input_artifacts
                    .iter()
                    .find(|artifact| artifact.id == *config_id)
                    .ok_or_else(|| {
                        AppError::operational(
                            "static RAM configuration is not an analysis-stage input",
                        )
                    })?;
                if config_artifact.kind != "static_ram_config"
                    || config_artifact.sha256 != config.sha256
                    || !report_artifact.input_artifact_ids.contains(config_id)
                {
                    return Err(AppError::operational(
                        "static RAM configuration digest or artifact provenance is inconsistent",
                    ));
                }
            }
        }
        if let Some(stack_usage) = &quantitative.stack_usage
            && (!stage
                .output_artifacts
                .iter()
                .any(|artifact| artifact.id == stack_usage.artifact_id)
                || !stage
                    .input_artifacts
                    .iter()
                    .any(|artifact| artifact.id == stack_usage.source_artifact_id))
        {
            return Err(AppError::operational(
                "compiler stack-usage summary does not match stage input/output provenance",
            ));
        }
    }
    Ok(())
}

fn mark_failed(
    session: &Session,
    lock: &SessionLock,
    stage: &str,
    error: &AppError,
) -> Result<(), AppError> {
    let mut details = BTreeMap::from([
        ("stage".to_owned(), json!(stage)),
        ("exit_code".to_owned(), json!(error.exit_code)),
    ]);
    if let Some(error_details) = error.details.as_object() {
        details.extend(
            error_details
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
    }
    session
        .transition(
            lock,
            SessionStatus::Failed,
            Some(SessionError {
                code: format!("{}_FAILED", stage.to_ascii_uppercase()),
                message: error.message.clone(),
                details,
            }),
        )
        .map(|_| ())
        .map_err(|state_error| AppError::state_persistence(stage, error, state_error))
}

fn required_artifact<'a>(artifacts: &'a [Artifact], id: &str) -> Result<&'a Artifact, AppError> {
    artifacts
        .iter()
        .find(|artifact| artifact.id == id)
        .ok_or_else(|| AppError::operational(format!("required artifact `{id}` is not registered")))
}

fn artifact_claims(artifacts: &[Artifact], ids: &[String]) -> Result<Vec<Artifact>, AppError> {
    ids.iter()
        .map(|id| required_artifact(artifacts, id).cloned())
        .collect()
}

fn artifact_spec(
    id: &str,
    kind: &str,
    relative_path: &str,
    media_type: &str,
    input_artifact_ids: Vec<String>,
    producer: &str,
) -> Result<ArtifactSpec, AppError> {
    Ok(ArtifactSpec {
        id: id.to_owned(),
        kind: kind.to_owned(),
        relative_path: ArtifactPath::new(relative_path).map_err(AppError::operational)?,
        media_type: media_type.to_owned(),
        producer: producer.to_owned(),
        input_artifact_ids,
    })
}

fn read_json_artifact<T: DeserializeOwned>(
    session: &Session,
    artifact: &Artifact,
) -> Result<T, AppError> {
    if artifact.size_bytes > MAX_COMPARISON_AGGREGATE_BYTES {
        return Err(AppError::operational(format!(
            "JSON artifact `{}` is {} bytes; maximum is {MAX_COMPARISON_AGGREGATE_BYTES}",
            artifact.id, artifact.size_bytes
        )));
    }
    let mut file = session
        .open_artifact(artifact)
        .map_err(AppError::operational)?;
    let mut bytes = Vec::with_capacity(usize::try_from(artifact.size_bytes).unwrap_or(0));
    (&mut file)
        .take(MAX_COMPARISON_AGGREGATE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(AppError::operational)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_COMPARISON_AGGREGATE_BYTES {
        return Err(AppError::operational(format!(
            "JSON artifact `{}` grew beyond {MAX_COMPARISON_AGGREGATE_BYTES} bytes while reading",
            artifact.id
        )));
    }
    strict_json::from_slice(&bytes).map_err(AppError::operational)
}

pub(crate) fn open_derived(
    session: &Session,
    artifact: &Artifact,
) -> Result<DerivedNdjsonReader<BufReader<File>>, AppError> {
    let file = session
        .open_artifact(artifact)
        .map_err(AppError::operational)?;
    DerivedNdjsonReader::new(BufReader::new(file), session.id().as_str())
        .map_err(AppError::operational)
}

fn open_observation_input(
    session: &Session,
    artifact: &Artifact,
) -> Result<ObservationInput, AppError> {
    let file = session
        .open_artifact(artifact)
        .map_err(AppError::operational)?;
    let default_limits = LineLimits::default();
    let reader = match NdjsonObservationReader::new(
        BufReader::new(file),
        LineLimits {
            max_line_bytes: default_limits.max_line_bytes,
            max_records: u64::MAX,
            ..default_limits
        },
    ) {
        Ok(reader) => reader,
        Err(error) => {
            return Ok(ObservationInput {
                dictionary: ObservationDictionary::new(session.id().as_str()),
                reader: None,
                terminal_health: Some(ndjson_health_observation(&artifact.id, &error)?),
            });
        }
    };
    if reader.header().session_id != session.id().as_str() {
        return Ok(ObservationInput {
            dictionary: ObservationDictionary::new(session.id().as_str()),
            reader: None,
            terminal_health: Some(HealthObservation {
                code: "malformed_input".to_owned(),
                source: "t32perf-trace32.ndjson".to_owned(),
                artifact_id: Some(artifact.id.clone()),
                record: Some(0),
                start_ns: None,
                end_ns: None,
                evidence: Properties::from([
                    ("byte_offset".to_owned(), json!(0)),
                    ("line".to_owned(), json!(1)),
                    ("record".to_owned(), json!(0)),
                    ("parser_error_kind".to_owned(), json!("session_mismatch")),
                    (
                        "expected_session_id".to_owned(),
                        json!(session.id().as_str()),
                    ),
                    (
                        "actual_session_id".to_owned(),
                        json!(reader.header().session_id),
                    ),
                ]),
            }),
        });
    }
    Ok(ObservationInput {
        dictionary: reader.dictionary().clone(),
        reader: Some(reader),
        terminal_health: None,
    })
}

fn ndjson_health_observation(
    artifact_id: &str,
    error: &NdjsonError,
) -> Result<HealthObservation, AppError> {
    let (code, parser_error_kind) = match &error.kind {
        NdjsonErrorKind::Input(InputErrorKind::TruncatedLine)
        | NdjsonErrorKind::MissingRecord { .. } => ("truncated_input", "truncated_input"),
        NdjsonErrorKind::Ordering(ObservationOrderError::SourceSequence { .. }) => {
            ("out_of_order_sequence", "source_sequence")
        }
        NdjsonErrorKind::Ordering(
            ObservationOrderError::SourceTimestamp { .. }
            | ObservationOrderError::GlobalTimestamp { .. },
        ) => ("out_of_order_timestamp", "timestamp"),
        NdjsonErrorKind::Input(InputErrorKind::NonCanonicalLineEnding) => {
            ("malformed_input", "non_canonical_line_ending")
        }
        NdjsonErrorKind::InvalidUtf8 => ("malformed_input", "invalid_utf8"),
        NdjsonErrorKind::InvalidJson { .. } => ("malformed_input", "invalid_json"),
        NdjsonErrorKind::UnknownField { .. } => ("malformed_input", "unknown_field"),
        NdjsonErrorKind::InvalidEncoding => ("malformed_input", "invalid_encoding"),
        NdjsonErrorKind::SessionMismatch { .. } => ("malformed_input", "session_mismatch"),
        NdjsonErrorKind::DictionaryAfterObservation { .. } => {
            ("malformed_input", "dictionary_after_observation")
        }
        NdjsonErrorKind::InvalidDictionary { .. } => ("malformed_input", "invalid_dictionary"),
        NdjsonErrorKind::InvalidObservation { .. } => ("malformed_input", "invalid_observation"),
        NdjsonErrorKind::UnsupportedSchema { message } => {
            return Err(AppError::unsupported(
                "observations.schema",
                format!(
                    "observation artifact `{artifact_id}` declares an unsupported schema at byte {}, line {}, record {}: {}",
                    error.location.byte_offset,
                    error.location.line,
                    error.location.record,
                    bounded_text(message, MAX_PARSER_EVIDENCE_CHARS),
                ),
            ));
        }
        NdjsonErrorKind::Input(InputErrorKind::Io { .. }) | NdjsonErrorKind::Io { .. } => {
            return Err(AppError::operational(format!(
                "failed to read observation artifact `{artifact_id}` at byte {}, line {}, record {}: {}",
                error.location.byte_offset,
                error.location.line,
                error.location.record,
                bounded_text(&error.kind.to_string(), MAX_PARSER_EVIDENCE_CHARS),
            )));
        }
        NdjsonErrorKind::Input(
            InputErrorKind::InvalidLimit
            | InputErrorKind::DictionaryEntryLimitTooLarge { .. }
            | InputErrorKind::DictionaryByteLimitTooLarge { .. }
            | InputErrorKind::LineTooLong { .. }
            | InputErrorKind::RecordLimitExceeded { .. },
        )
        | NdjsonErrorKind::DictionaryEntryLimitExceeded { .. }
        | NdjsonErrorKind::DictionaryByteLimitExceeded { .. } => {
            return Err(AppError::operational(format!(
                "observation artifact `{artifact_id}` exceeded a parser resource limit at byte {}, line {}, record {}: {}",
                error.location.byte_offset,
                error.location.line,
                error.location.record,
                bounded_text(&error.kind.to_string(), MAX_PARSER_EVIDENCE_CHARS),
            )));
        }
        NdjsonErrorKind::Serialization { .. } => {
            return Err(AppError::operational(format!(
                "observation parser reached an internal serialization path: {}",
                bounded_text(&error.kind.to_string(), MAX_PARSER_EVIDENCE_CHARS),
            )));
        }
    };

    Ok(HealthObservation {
        code: code.to_owned(),
        source: "t32perf-trace32.ndjson".to_owned(),
        artifact_id: Some(artifact_id.to_owned()),
        record: Some(error.location.record),
        start_ns: None,
        end_ns: None,
        evidence: Properties::from([
            ("byte_offset".to_owned(), json!(error.location.byte_offset)),
            ("line".to_owned(), json!(error.location.line)),
            ("record".to_owned(), json!(error.location.record)),
            ("parser_error_kind".to_owned(), json!(parser_error_kind)),
            (
                "message".to_owned(),
                json!(bounded_text(
                    &error.kind.to_string(),
                    MAX_PARSER_EVIDENCE_CHARS
                )),
            ),
        ]),
    })
}

fn require_recorded_parser_health(
    health: &HealthReport,
    observation: &HealthObservation,
) -> Result<(), AppError> {
    if health
        .observations
        .iter()
        .any(|recorded| recorded == observation)
    {
        Ok(())
    } else {
        Err(AppError::operational(
            "observation parsing failed during conversion without an identical parser health observation in the completed analysis stage",
        ))
    }
}

fn bounded_text(value: &str, max_chars: usize) -> String {
    let mut characters = value.chars();
    let output = characters.by_ref().take(max_chars).collect::<String>();
    if characters.next().is_none() {
        return output;
    }
    if max_chars <= 3 {
        return ".".repeat(max_chars);
    }
    let mut output = value.chars().take(max_chars - 3).collect::<String>();
    output.push_str("...");
    output
}

#[cfg(test)]
mod tests {
    use std::io::{self, BufRead, Read, Write};

    use serde_json::json;
    use sha2::{Digest as _, Sha256};
    use t32perf_model::{
        ANALYZER_CONTRACT, AdapterInfo, AnalysisContracts, AnalysisDiagnosticCounts,
        AnalysisStageReceipt, AnalysisStageSchemaVersion, AnalysisSummarySchemaVersion, Artifact,
        ArtifactPath, CaptureInfo, ComparisonMetricKind, ComparisonReport, ComparisonSchemaVersion,
        ComparisonSubject, ComparisonSubjectKind, ComparisonVerdict, DerivedStreamSchemaVersion,
        FirmwareInfo, HealthReport, HealthSchemaVersion, HealthVerdict, HotspotsSchemaVersion,
        Manifest, ManifestSchemaVersion, MetricComparison, MetricComparisonOutcome, MetricSupport,
        MetricSupportLevel, Quality, SessionStatus, Sha256Digest, ToolInfo,
    };
    use t32perf_session::{ArtifactRoot, SessionId, SessionLimits};
    use t32perf_trace32::{
        ELF_SECTIONS_V1_FLAVOR, GNU_LD_MAP_V1_FLAVOR, LineLimits, NdjsonObservationReader,
    };
    use tempfile::TempDir;

    use super::{
        EnsuredArtifactWriter, EnsuredArtifactWriterMode, MAX_COMPARISON_HEALTH_BYTES,
        ResourceInputs, bounded_text, comparison_report_projection, encode_lower_hex,
        finish_ensured_artifact, mark_failed, ndjson_health_observation, parse_policy_json,
        read_bounded_comparison_json, selected_analysis_input_claims, validate_health_document,
    };
    use crate::app::AppError;

    #[test]
    fn comparison_policy_rejects_duplicate_members_recursively() {
        let error = parse_policy_json(
            br#"{"resource_rules":[{"semantic":"stack.peak_bytes","subject":{"kind":"stack","id":"main","id":"shadow"}}]}"#,
        )
        .expect_err("duplicate comparison-policy member");

        assert!(
            error
                .message
                .contains("duplicate JSON object member name `id`")
        );
    }

    #[test]
    fn health_document_from_another_session_is_rejected() {
        let temp = TempDir::new().expect("temporary directory");
        let root =
            ArtifactRoot::open(temp.path(), SessionLimits::default()).expect("open artifact root");
        let session = root
            .create_session_with_id(
                SessionId::new("session-a").expect("session ID"),
                &serde_json::json!({}),
            )
            .expect("create session");
        let support = MetricSupport::uniform(MetricSupportLevel::Exact);
        let diagnostics = AnalysisDiagnosticCounts {
            observation_count: 0,
            function_span_count: 0,
            incomplete_function_span_count: 0,
            health_observation_count: 0,
            health_issue_count: 0,
        };
        let stage = AnalysisStageReceipt {
            schema: AnalysisStageSchemaVersion,
            session_id: "session-a".to_owned(),
            tool: ToolInfo {
                name: "t32perf".to_owned(),
                version: "0.1.0".to_owned(),
                commit: None,
            },
            contracts: AnalysisContracts {
                analyzer: ANALYZER_CONTRACT.to_owned(),
                health_policy: "t32perf.health-policy/v1".to_owned(),
                health_schema: HealthSchemaVersion,
                derived_stream_schema: DerivedStreamSchemaVersion,
                hotspots_schema: HotspotsSchemaVersion,
                analysis_summary_schema: AnalysisSummarySchemaVersion,
            },
            health_verdict: HealthVerdict::Valid,
            metric_support: support.clone(),
            diagnostics,
            input_artifacts: Vec::new(),
            output_artifacts: Vec::new(),
        };
        let health = HealthReport {
            schema: HealthSchemaVersion,
            session_id: "session-b".to_owned(),
            verdict: HealthVerdict::Valid,
            policy_version: "t32perf.health-policy/v1".to_owned(),
            observations: Vec::new(),
            issues: Vec::new(),
            metric_support: support,
        };

        let error = validate_health_document(&session, &health, &stage).unwrap_err();
        assert!(error.message.contains("session does not match"));
    }

    #[test]
    fn parser_io_failures_remain_operational() {
        let error = match NdjsonObservationReader::new(FailingReader, LineLimits::default()) {
            Ok(_) => panic!("failing reader unexpectedly opened"),
            Err(error) => error,
        };
        let app_error = ndjson_health_observation("observations", &error)
            .expect_err("I/O must not become a health-gated input diagnosis");
        assert_eq!(app_error.code, "OPERATIONAL_ERROR");
        assert!(
            app_error
                .message
                .contains("failed to read observation artifact")
        );
    }

    #[test]
    fn parser_evidence_text_respects_its_character_bound() {
        let bounded = bounded_text(&"x".repeat(1_024), 512);
        assert_eq!(bounded.chars().count(), 512);
        assert!(bounded.ends_with("..."));
    }

    #[test]
    fn existing_artifact_comparator_accepts_exact_bytes_and_rejects_tampering() {
        let temp = TempDir::new().expect("temporary directory");
        let root = ArtifactRoot::open(temp.path(), SessionLimits::default()).expect("root");
        let session = root
            .create_session_with_id(SessionId::new("ensure-comparator").expect("id"), &json!({}))
            .expect("session");
        let lock = session.try_lock().expect("lock");
        let bytes = b"streamed-output";
        let artifact = Artifact {
            id: "derived".to_owned(),
            kind: "derived".to_owned(),
            relative_path: ArtifactPath::new("analysis/derived.ndjson").expect("path"),
            media_type: "application/x-ndjson".to_owned(),
            size_bytes: bytes.len() as u64,
            sha256: Sha256Digest::new(encode_lower_hex(&Sha256::digest(bytes))).expect("digest"),
            producer: "test".to_owned(),
            input_artifact_ids: Vec::new(),
        };
        let mut writer = EnsuredArtifactWriter {
            mode: EnsuredArtifactWriterMode::Existing {
                artifact: artifact.clone(),
                hasher: Sha256::new(),
                size_bytes: 0,
            },
        };
        writer.write_all(bytes).expect("write comparator");
        assert_eq!(
            finish_ensured_artifact(&session, &lock, writer).unwrap(),
            artifact
        );

        let mut tampered = EnsuredArtifactWriter {
            mode: EnsuredArtifactWriterMode::Existing {
                artifact,
                hasher: Sha256::new(),
                size_bytes: 0,
            },
        };
        tampered.write_all(b"tampered").expect("write comparator");
        assert!(finish_ensured_artifact(&session, &lock, tampered).is_err());
    }

    #[test]
    fn analysis_request_selects_exact_resource_flavor_and_rejects_drift() {
        let artifact = |id: &str, kind: &str| Artifact {
            id: id.to_owned(),
            kind: kind.to_owned(),
            relative_path: ArtifactPath::new(format!("capture/{id}.bin")).unwrap(),
            media_type: "application/octet-stream".to_owned(),
            size_bytes: 1,
            sha256: Sha256Digest::new("a".repeat(64)).unwrap(),
            producer: "test".to_owned(),
            input_artifact_ids: Vec::new(),
        };
        let observations = artifact("observations", "observations");
        let receipt = artifact("capture-receipt", "capture_receipt");
        let linker = artifact("linker-map", "linker_map");
        let elf = artifact("firmware-elf", "firmware_elf");
        let config = artifact("static-config", "static_ram_config");
        let stack = artifact("stack", "stack_usage");
        let resources = ResourceInputs {
            linker_map: Some(linker),
            firmware_elf: Some(elf),
            static_ram_config: Some(config),
            stack_usage: Some(stack),
        };

        let gnu = selected_analysis_input_claims(
            &observations,
            &receipt,
            &resources,
            GNU_LD_MAP_V1_FLAVOR,
        )
        .unwrap();
        assert_eq!(
            gnu.iter()
                .map(|artifact| artifact.id.as_str())
                .collect::<Vec<_>>(),
            [
                "observations",
                "capture-receipt",
                "linker-map",
                "static-config",
                "stack"
            ]
        );
        let elf = selected_analysis_input_claims(
            &observations,
            &receipt,
            &resources,
            ELF_SECTIONS_V1_FLAVOR,
        )
        .unwrap();
        assert_eq!(elf[2].id, "firmware-elf");

        let mismatch = ResourceInputs {
            linker_map: None,
            firmware_elf: resources.firmware_elf.clone(),
            static_ram_config: None,
            stack_usage: None,
        };
        assert!(
            selected_analysis_input_claims(
                &observations,
                &receipt,
                &mismatch,
                GNU_LD_MAP_V1_FLAVOR,
            )
            .is_err()
        );
    }

    #[test]
    fn comparison_stdout_projection_is_bounded_and_prioritizes_regressions() {
        let metric = |id: &str, outcome| MetricComparison {
            subject: ComparisonSubject {
                kind: ComparisonSubjectKind::Function,
                id: id.to_owned(),
                context_id: None,
            },
            metric: ComparisonMetricKind::InclusiveActiveNs,
            baseline: 10.0,
            candidate: 20.0,
            delta: 10.0,
            relative_change: Some(1.0),
            quality: Quality::Exact,
            outcome,
            reasons: vec!["x".repeat(1_024); 20],
        };
        let report = ComparisonReport {
            schema: ComparisonSchemaVersion,
            baseline_session_id: "baseline".to_owned(),
            candidate_session_id: "candidate".to_owned(),
            baseline_health: HealthVerdict::Valid,
            candidate_health: HealthVerdict::Valid,
            verdict: ComparisonVerdict::Regressed,
            metrics: vec![
                metric("unchanged", MetricComparisonOutcome::Unchanged),
                metric("regressed", MetricComparisonOutcome::Regressed),
                metric("improved", MetricComparisonOutcome::Improved),
            ],
            resource_metrics: Vec::new(),
            static_ram_metrics: Vec::new(),
            reasons: vec!["reason".to_owned(); 40],
        };

        let projection = comparison_report_projection(&report, 1);
        assert_eq!(projection["metrics_total_count"], 3);
        assert_eq!(projection["metrics_returned_count"], 1);
        assert_eq!(projection["metrics_truncated"], true);
        assert_eq!(projection["metrics"][0]["subject"]["id"], "regressed");
        assert_eq!(projection["metrics"][0]["projection_truncated"], true);
        assert_eq!(projection["metrics"][0]["reasons_total_count"], 20);
        assert_eq!(projection["metrics"][0]["reasons_truncated"], true);
        assert_eq!(projection["reasons_total_count"], 40);
        assert_eq!(projection["reasons_returned_count"], 32);
        assert_eq!(projection["reasons_truncated"], true);
    }

    #[test]
    fn comparison_input_limit_is_independent_of_session_file_quota() {
        let temp = TempDir::new().expect("temporary directory");
        let root =
            ArtifactRoot::open(temp.path(), SessionLimits::default()).expect("open artifact root");
        let session = root
            .create_session_with_id(
                SessionId::new("comparison-input-limit").expect("session ID"),
                &serde_json::json!({}),
            )
            .expect("create session");
        let artifact = Artifact {
            id: "health".to_owned(),
            kind: "health".to_owned(),
            relative_path: ArtifactPath::new("analysis/health.json").expect("artifact path"),
            media_type: "application/json".to_owned(),
            size_bytes: MAX_COMPARISON_HEALTH_BYTES + 1,
            sha256: Sha256Digest::new("0".repeat(64)).expect("digest"),
            producer: "test".to_owned(),
            input_artifact_ids: Vec::new(),
        };

        let error = read_bounded_comparison_json::<serde_json::Value>(
            &session,
            &artifact,
            MAX_COMPARISON_HEALTH_BYTES,
            "health",
        )
        .expect_err("comparison must reject the oversized aggregate before opening it");
        assert_eq!(error.code, "UNSUPPORTED");
        assert_eq!(error.details["feature"], "compare.input_size");
    }

    #[test]
    fn failure_state_persistence_errors_replace_the_original_error() {
        let temp = TempDir::new().expect("temporary directory");
        let root =
            ArtifactRoot::open(temp.path(), SessionLimits::default()).expect("open artifact root");
        let session = root
            .create_session_with_id(
                SessionId::new("complete-session").expect("session ID"),
                &serde_json::json!({}),
            )
            .expect("create session");
        let lock = session.try_lock().expect("lock session");
        session
            .transition(&lock, SessionStatus::Capturing, None)
            .expect("start capture");
        let captured = session
            .transition(&lock, SessionStatus::Captured, None)
            .expect("finish capture");
        let manifest = Manifest {
            schema: ManifestSchemaVersion,
            session_id: session.id().to_string(),
            created_at: captured.created_at,
            tool: ToolInfo {
                name: "t32perf-test".to_owned(),
                version: "0.1.0".to_owned(),
                commit: None,
            },
            capture: CaptureInfo {
                provider: None,
                mode: "synthetic".to_owned(),
                adapter: AdapterInfo {
                    id: "synthetic-v1".to_owned(),
                    version: "1".to_owned(),
                },
                target: None,
                trace32: None,
                request_sha256: None,
                covered_cores: Vec::new(),
                capabilities: None,
                capture_config: None,
                instrumentation: None,
            },
            firmware: FirmwareInfo {
                elf_path: None,
                elf_sha256: None,
                build_id: None,
            },
            clocks: Vec::new(),
            stages: Vec::new(),
            artifacts: Vec::new(),
        };
        session
            .finalize(&lock, &manifest)
            .expect("complete session");

        let original = AppError::operational("conversion failed");
        let persistence = mark_failed(&session, &lock, "convert", &original)
            .expect_err("complete sessions cannot transition to failed");
        assert_eq!(persistence.code, "STATE_PERSISTENCE_FAILED");
        assert_eq!(
            persistence.details["original_error"]["message"],
            "conversion failed"
        );
        assert_eq!(
            session.read_state().expect("read state").status,
            SessionStatus::Complete
        );
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("injected read failure"))
        }
    }

    impl BufRead for FailingReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Err(io::Error::other("injected read failure"))
        }

        fn consume(&mut self, _amount: usize) {}
    }
}
