use std::{cmp::Ordering, io::Read as _};

use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use t32perf_model::{
    AnalysisQuantitativeSummary, AnalysisReport, AnalysisStageReceipt, AnalysisSummary,
    AnalysisSummaryDocument, Artifact, ContextCpuSummary, ContextKind, CounterSubject,
    FunctionHotspot, HealthIssue, HealthReport, HotspotReport, MetricSupport, MetricSupportEntry,
    ReportArtifactLink, ReportSchemaVersion, ReportSummary, ResourceClass, ResourceCounterSummary,
    SamplingHotspot, SessionStatus, StackRole, StackUsageAnalysisSummary, StaticRamAnalysisSummary,
    strict_json,
};
use t32perf_session::{ArtifactRoot, Session};

use crate::{
    app::{AppError, CommandOutcome, health_exit_code, open_session},
    capture_config::registered_capture_config,
    pipeline::{open_derived, validate_health_document, validate_summary_document},
    receipt::{
        ANALYSIS_STAGE_ID, ANALYSIS_STAGE_PRODUCER, CAPTURE_RECEIPT_ID, STACK_USAGE_ID,
        STATIC_RAM_ID, validate_analysis_stage_receipt,
    },
};

const MAX_STAGE_BYTES: u64 = 1024 * 1024;
const MAX_HEALTH_BYTES: u64 = 16 * 1024 * 1024;
const MAX_AGGREGATE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DIAGNOSTICS: usize = 64;
const MAX_SUPPORT_REASONS: usize = 8;
const MAX_TEXT_CHARS: usize = 512;

pub fn summary(
    root: &ArtifactRoot,
    session_id: &str,
    top: usize,
) -> Result<CommandOutcome, AppError> {
    if !(1..=100).contains(&top) {
        return Err(AppError::operational(
            "summary --top must be in the inclusive range 1..=100",
        ));
    }
    let session = open_session(root, session_id)?;
    let state = session.read_state().map_err(AppError::operational)?;
    if !matches!(
        state.status,
        SessionStatus::Processing | SessionStatus::Complete
    ) {
        return Err(AppError::operational(format!(
            "session `{session_id}` must have a completed analysis stage before summary; current status is {:?}",
            state.status
        )));
    }
    let artifacts = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    let capture_config =
        registered_capture_config(&session, &artifacts).map_err(AppError::operational)?;
    let stage_artifact = required_artifact(&artifacts, ANALYSIS_STAGE_ID)?;
    let stage: AnalysisStageReceipt =
        read_bounded_json(&session, stage_artifact, MAX_STAGE_BYTES, "analysis stage")?;
    validate_analysis_stage_receipt(&stage, stage_artifact, &artifacts, session.id().as_str())?;
    let derived_artifact = required_analysis_artifact(&artifacts, "derived", "derived")?;
    let derived = open_derived(&session, derived_artifact)?;
    if derived.header().schema != stage.contracts.derived_stream_schema
        || derived.header().input_artifact_ids != derived_artifact.input_artifact_ids
    {
        return Err(AppError::operational(
            "derived stream schema or inputs do not match the analysis stage contract",
        ));
    }

    let health_artifact = required_analysis_artifact(&artifacts, "health", "health")?;
    let health: HealthReport =
        read_bounded_json(&session, health_artifact, MAX_HEALTH_BYTES, "health")?;
    validate_health_document(&session, &health, &stage)?;
    let summary_artifact =
        required_analysis_artifact(&artifacts, "analysis-summary", "analysis_summary")?;
    let summary: AnalysisSummaryDocument = read_bounded_json(
        &session,
        summary_artifact,
        MAX_AGGREGATE_BYTES,
        "analysis summary",
    )?;
    validate_summary_document(&session, summary_artifact, &summary, &stage, &artifacts)?;

    let mut result = Map::from_iter([
        ("session_id".to_owned(), json!(session.id().as_str())),
        ("requested_top".to_owned(), json!(top)),
        (
            "quantitative_available".to_owned(),
            json!(health.verdict.allows_quantitative_results()),
        ),
        ("health".to_owned(), health_json(&health)),
        (
            "artifact_references".to_owned(),
            artifact_references(&artifacts),
        ),
        (
            "capture".to_owned(),
            json!({
                "capture_config_artifact_id": &capture_config.artifact.id,
                "instrumentation": &capture_config.document.instrumentation,
            }),
        ),
    ]);

    if health.verdict.allows_quantitative_results() {
        let hotspots_artifact = required_analysis_artifact(&artifacts, "hotspots", "hotspots")?;
        let mut hotspots: HotspotReport =
            read_bounded_json(&session, hotspots_artifact, MAX_AGGREGATE_BYTES, "hotspots")?;
        hotspots.validate().map_err(AppError::operational)?;
        if hotspots.schema != stage.contracts.hotspots_schema
            || hotspots.session_id != session.id().as_str()
        {
            return Err(AppError::operational(
                "hotspot report schema or session does not match the completed analysis stage",
            ));
        }
        let quantitative = summary.quantitative.ok_or_else(|| {
            AppError::operational("VALID analysis summary omits quantitative results")
        })?;
        let report = analysis_report(
            session.id().as_str(),
            &state.updated_at,
            &health,
            &stage,
            &hotspots,
            &artifacts,
        );
        report.validate().map_err(AppError::operational)?;
        result.insert("report".to_owned(), json!(report));
        result.insert(
            "quantitative".to_owned(),
            quantitative_json(&mut hotspots, quantitative, top),
        );
    }

    Ok(CommandOutcome {
        command: "summary",
        result: Value::Object(result),
        exit_code: health_exit_code(health.verdict),
    })
}

fn analysis_report(
    session_id: &str,
    generated_at: &str,
    health: &HealthReport,
    stage: &AnalysisStageReceipt,
    hotspots: &HotspotReport,
    artifacts: &[Artifact],
) -> AnalysisReport {
    let sample_count = hotspots.sampling.iter().fold(0_u64, |total, hotspot| {
        total.saturating_add(hotspot.sample_count)
    });
    let links = stage
        .output_artifacts
        .iter()
        .filter_map(|claim| {
            artifacts
                .iter()
                .find(|artifact| artifact.id == claim.id)
                .map(|artifact| ReportArtifactLink {
                    artifact_id: artifact.id.clone(),
                    role: match artifact.id.as_str() {
                        "derived" => "timeline",
                        "health" => "health",
                        "hotspots" => "hotspots",
                        "analysis-summary" => "summary",
                        STATIC_RAM_ID | STACK_USAGE_ID => "static_resource",
                        _ => "analysis_output",
                    }
                    .to_owned(),
                })
        })
        .collect();
    AnalysisReport {
        schema: ReportSchemaVersion,
        session_id: session_id.to_owned(),
        generated_at: generated_at.to_owned(),
        title: format!("t32perf analysis for {session_id}"),
        health_verdict: health.verdict,
        summary: ReportSummary {
            capture_duration_ns: None,
            function_span_count: stage.diagnostics.function_span_count,
            sample_count,
            comparison_verdict: None,
        },
        findings: Vec::new(),
        artifacts: links,
    }
}

fn health_json(health: &HealthReport) -> Value {
    let diagnostics = health
        .issues
        .iter()
        .take(MAX_DIAGNOSTICS)
        .map(issue_json)
        .collect::<Vec<_>>();
    json!({
        "verdict": health.verdict,
        "policy_version": bounded_text(&health.policy_version),
        "observation_count": health.observations.len(),
        "issue_count": health.issues.len(),
        "issues_returned": diagnostics.len(),
        "issues_truncated": health.issues.len() > diagnostics.len(),
        "issues": diagnostics,
        "metric_support": metric_support_json(&health.metric_support),
    })
}

fn issue_json(issue: &HealthIssue) -> Value {
    json!({
        "code": bounded_text(&issue.code),
        "severity": issue.severity,
        "source": bounded_text(&issue.source),
        "artifact_id": issue.artifact_id.as_deref().map(bounded_text),
        "record": issue.record,
        "start_ns": issue.start_ns,
        "end_ns": issue.end_ns,
        "message": bounded_text(&issue.message),
    })
}

fn metric_support_json(support: &MetricSupport) -> Value {
    json!({
        "function_timeline": support_entry_json(&support.function_timeline),
        "call_count": support_entry_json(&support.call_count),
        "elapsed": support_entry_json(&support.elapsed),
        "active": support_entry_json(&support.active),
        "self": support_entry_json(&support.self_time),
        "task_timeline": support_entry_json(&support.task_timeline),
        "isr_timeline": support_entry_json(&support.isr_timeline),
        "resource_counters": support_entry_json(&support.resource_counters),
    })
}

fn support_entry_json(entry: &MetricSupportEntry) -> Value {
    let reasons = entry
        .reasons
        .iter()
        .take(MAX_SUPPORT_REASONS)
        .map(|reason| bounded_text(reason))
        .collect::<Vec<_>>();
    json!({
        "support": entry.support,
        "reason_count": entry.reasons.len(),
        "reasons_returned": reasons.len(),
        "reasons_truncated": entry.reasons.len() > reasons.len(),
        "reasons": reasons,
    })
}

fn quantitative_json(
    hotspots: &mut HotspotReport,
    summary: AnalysisQuantitativeSummary,
    top: usize,
) -> Value {
    hotspots.functions.sort_by(function_hotspot_order);
    hotspots.sampling.sort_by(sampling_hotspot_order);
    let function_count = hotspots.functions.len();
    let sampling_count = hotspots.sampling.len();
    let functions = hotspots
        .functions
        .iter()
        .take(top)
        .map(function_hotspot_json)
        .collect::<Vec<_>>();
    let sampling = hotspots
        .sampling
        .iter()
        .take(top)
        .map(sampling_hotspot_json)
        .collect::<Vec<_>>();

    let AnalysisQuantitativeSummary {
        analysis,
        static_ram,
        stack_usage,
    } = summary;
    let execution = execution_json(&analysis, top);
    let resources = resource_json(&analysis, static_ram, stack_usage, top);
    json!({
        "hotspots": {
            "quality": hotspots.quality,
            "function_count": function_count,
            "sampling_count": sampling_count,
            "functions": functions,
            "sampling": sampling,
        },
        "execution": execution,
        "resources": resources,
        "observation_count": analysis.observation_count,
        "function_span_count": analysis.function_span_count,
        "incomplete_function_span_count": analysis.incomplete_function_span_count,
        "call_depth": {
            "max_depth": analysis.call_depth.max_depth,
            "context_id": analysis.call_depth.context_id.as_deref().map(bounded_text),
            "deepest_path": analysis.call_depth.deepest_path.iter().take(top).map(|id| bounded_text(id)).collect::<Vec<_>>(),
            "path_truncated": analysis.call_depth.deepest_path.len() > top,
        },
    })
}

fn function_hotspot_order(left: &FunctionHotspot, right: &FunctionHotspot) -> Ordering {
    right
        .self_active_ns
        .cmp(&left.self_active_ns)
        .then_with(|| right.inclusive_active_ns.cmp(&left.inclusive_active_ns))
        .then_with(|| right.count.cmp(&left.count))
        .then_with(|| left.function_id.cmp(&right.function_id))
        .then_with(|| left.context_id.cmp(&right.context_id))
}

fn function_hotspot_json(hotspot: &FunctionHotspot) -> Value {
    json!({
        "function_id": bounded_text(&hotspot.function_id),
        "context_id": hotspot.context_id.as_deref().map(bounded_text),
        "inclusive_active_ns": hotspot.inclusive_active_ns,
        "self_active_ns": hotspot.self_active_ns,
        "count": hotspot.count,
        "min_active_ns": hotspot.min_active_ns,
        "max_active_ns": hotspot.max_active_ns,
        "avg_active_ns": hotspot.avg_active_ns,
        "incomplete_count": hotspot.incomplete_count,
        "quality": hotspot.quality,
    })
}

fn sampling_hotspot_order(left: &SamplingHotspot, right: &SamplingHotspot) -> Ordering {
    right
        .sample_count
        .cmp(&left.sample_count)
        .then_with(|| right.estimated_share.total_cmp(&left.estimated_share))
        .then_with(|| left.function_id.cmp(&right.function_id))
        .then_with(|| left.address.cmp(&right.address))
        .then_with(|| left.context_id.cmp(&right.context_id))
}

fn sampling_hotspot_json(hotspot: &SamplingHotspot) -> Value {
    json!({
        "function_id": hotspot.function_id.as_deref().map(bounded_text),
        "address": hotspot.address,
        "context_id": hotspot.context_id.as_deref().map(bounded_text),
        "sample_count": hotspot.sample_count,
        "estimated_share": hotspot.estimated_share,
        "quality": hotspot.quality,
    })
}

fn execution_json(summary: &AnalysisSummary, top: usize) -> Value {
    let mut contexts = summary.context_cpu.clone();
    contexts.sort_by(|left, right| {
        right
            .active_ns
            .cmp(&left.active_ns)
            .then_with(|| left.context_id.cmp(&right.context_id))
    });
    let tasks = contexts
        .iter()
        .filter(|context| context.kind == ContextKind::Task)
        .collect::<Vec<_>>();
    let isrs = contexts
        .iter()
        .filter(|context| context.kind == ContextKind::Isr)
        .collect::<Vec<_>>();
    json!({
        "task_cpu_ns": summary.task_cpu_ns,
        "isr_cpu_ns": summary.isr_cpu_ns,
        "idle_cpu_ns": summary.idle_cpu_ns,
        "task_count": tasks.len(),
        "isr_count": isrs.len(),
        "tasks": tasks.into_iter().take(top).map(context_json).collect::<Vec<_>>(),
        "isrs": isrs.into_iter().take(top).map(context_json).collect::<Vec<_>>(),
    })
}

fn context_json(context: &ContextCpuSummary) -> Value {
    json!({
        "context_id": bounded_text(&context.context_id),
        "kind": context.kind,
        "active_ns": context.active_ns,
    })
}

fn resource_json(
    summary: &AnalysisSummary,
    static_ram: Option<StaticRamAnalysisSummary>,
    stack_usage: Option<StackUsageAnalysisSummary>,
    top: usize,
) -> Value {
    let heaps = grouped_counters(&summary.resources.counters, top, |counter| {
        counter.class == ResourceClass::Heap
    });
    let task_stacks = grouped_counters(&summary.resources.counters, top, |counter| {
        stack_role(counter) == Some(StackRole::Task)
    });
    let isr_stacks = grouped_counters(&summary.resources.counters, top, |counter| {
        stack_role(counter) == Some(StackRole::Isr)
    });
    let msp_stacks = grouped_counters(&summary.resources.counters, top, |counter| {
        stack_role(counter) == Some(StackRole::Msp)
    });
    let psp_stacks = grouped_counters(&summary.resources.counters, top, |counter| {
        stack_role(counter) == Some(StackRole::Psp)
    });
    let custom_stacks = grouped_counters(&summary.resources.counters, top, |counter| {
        stack_role(counter) == Some(StackRole::Custom)
    });
    let memory_regions = grouped_counters(&summary.resources.counters, top, |counter| {
        counter.class == ResourceClass::Ram
    });
    let trace_buffers = grouped_counters(&summary.resources.counters, top, |counter| {
        counter.class == ResourceClass::TraceBuffer
    });
    let generic = grouped_counters(&summary.resources.counters, top, |counter| {
        counter.class == ResourceClass::Other
    });
    let mut derived = summary.resources.derived.clone();
    derived.sort_by(|left, right| {
        left.semantic
            .cmp(&right.semantic)
            .then_with(|| left.subject.cmp(&right.subject))
    });
    json!({
        "counter_count": summary.resources.counters.len(),
        "heaps": heaps,
        "stacks": {
            "task": task_stacks,
            "isr": isr_stacks,
            "msp": msp_stacks,
            "psp": psp_stacks,
            "custom": custom_stacks,
        },
        "memory_regions": memory_regions,
        "trace_buffers": trace_buffers,
        "generic": generic,
        "derived": derived.into_iter().take(top).collect::<Vec<_>>(),
        "derived_count": summary.resources.derived.len(),
        "static_ram": static_ram,
        "compiler_stack_usage": stack_usage,
    })
}

fn grouped_counters(
    counters: &[ResourceCounterSummary],
    top: usize,
    predicate: impl Fn(&ResourceCounterSummary) -> bool,
) -> Vec<Value> {
    let mut counters = counters
        .iter()
        .filter(|counter| predicate(counter))
        .collect::<Vec<_>>();
    counters.sort_by(|left, right| {
        left.semantic
            .cmp(&right.semantic)
            .then_with(|| left.subject.cmp(&right.subject))
            .then_with(|| left.counter_id.cmp(&right.counter_id))
    });
    counters
        .into_iter()
        .take(top)
        .map(resource_counter_json)
        .collect()
}

fn stack_role(counter: &ResourceCounterSummary) -> Option<StackRole> {
    if counter.class != ResourceClass::Stack {
        return None;
    }
    match counter.subject.as_ref() {
        Some(CounterSubject::Stack { role, .. }) => Some(*role),
        _ => None,
    }
}

fn resource_counter_json(counter: &ResourceCounterSummary) -> Value {
    json!({
        "counter_id": bounded_text(&counter.counter_id),
        "name": counter.name.as_deref().map(bounded_text),
        "unit": counter.unit.as_deref().map(bounded_text),
        "semantic": counter.semantic,
        "subject": counter.subject,
        "class": counter.class,
        "sample_count": counter.sample_count,
        "first_ts_ns": counter.first_ts_ns,
        "last_ts_ns": counter.last_ts_ns,
        "first": counter.first,
        "latest": counter.latest,
        "min": counter.min,
        "max": counter.max,
        "mean": counter.mean,
        "delta": counter.delta,
        "window_ns": counter.window_ns,
        "rate_per_second": counter.rate_per_second,
        "quality": counter.quality,
        "support": counter.support,
    })
}

fn artifact_references(artifacts: &[Artifact]) -> Value {
    const IDS: &[&str] = &[
        "observations",
        CAPTURE_RECEIPT_ID,
        "derived",
        "health",
        "hotspots",
        "analysis-summary",
        STATIC_RAM_ID,
        STACK_USAGE_ID,
        ANALYSIS_STAGE_ID,
        "perfetto",
    ];
    let mut references = IDS
        .iter()
        .filter_map(|id| artifacts.iter().find(|artifact| artifact.id == *id))
        .map(|artifact| {
            json!({
                "id": artifact.id,
                "kind": bounded_text(&artifact.kind),
                "relative_path": artifact.relative_path,
                "media_type": bounded_text(&artifact.media_type),
                "size_bytes": artifact.size_bytes,
                "sha256": artifact.sha256,
                "producer": bounded_text(&artifact.producer),
            })
        })
        .collect::<Vec<_>>();
    references.extend(
        artifacts
            .iter()
            .filter(|artifact| artifact.kind == "static_ram_config")
            .map(|artifact| {
                json!({
                    "id": artifact.id,
                    "kind": bounded_text(&artifact.kind),
                    "relative_path": artifact.relative_path,
                    "media_type": bounded_text(&artifact.media_type),
                    "size_bytes": artifact.size_bytes,
                    "sha256": artifact.sha256,
                    "producer": bounded_text(&artifact.producer),
                })
            }),
    );
    Value::Array(references)
}

fn read_bounded_json<T: DeserializeOwned>(
    session: &Session,
    artifact: &Artifact,
    limit: u64,
    document: &str,
) -> Result<T, AppError> {
    if artifact.size_bytes > limit {
        return Err(AppError::unsupported(
            "summary.aggregate_size",
            format!(
                "{document} artifact `{}` is {} bytes, above the safe summary limit of {limit} bytes",
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
            "summary.aggregate_size",
            format!(
                "{document} artifact `{}` grew beyond the safe summary limit of {limit} bytes while reading",
                artifact.id
            ),
        ));
    }
    strict_json::from_slice(&bytes).map_err(AppError::operational)
}

fn required_analysis_artifact<'a>(
    artifacts: &'a [Artifact],
    id: &str,
    kind: &str,
) -> Result<&'a Artifact, AppError> {
    let artifact = required_artifact(artifacts, id)?;
    if artifact.kind != kind || artifact.producer != ANALYSIS_STAGE_PRODUCER {
        return Err(AppError::operational(format!(
            "analysis artifact `{id}` has an unexpected kind or producer"
        )));
    }
    Ok(artifact)
}

fn required_artifact<'a>(artifacts: &'a [Artifact], id: &str) -> Result<&'a Artifact, AppError> {
    artifacts
        .iter()
        .find(|artifact| artifact.id == id)
        .ok_or_else(|| AppError::operational(format!("required artifact `{id}` is not registered")))
}

fn bounded_text(value: &str) -> String {
    let mut characters = value.chars();
    let prefix = characters.by_ref().take(MAX_TEXT_CHARS).collect::<String>();
    if characters.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}
