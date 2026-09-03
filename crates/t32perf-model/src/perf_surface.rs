//! Typed machine contracts for the plan-defined `perf_*` façade.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    AnalysisReport, Artifact, ArtifactPath, CaptureInstrumentationConfig, ComparisonSchemaVersion,
    ComparisonVerdict, ContextCpuSummary, FunctionHotspot, HealthSeverity, HealthVerdict,
    MetricSupportLevel, PerfRunPayload, PerfSurfaceSchemaVersion, Quality, SamplingHotspot,
    SessionState, SessionStatus, Sha256Digest,
};

/// One exact operation exposed by the host-side performance façade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum PerfSurfaceOperation {
    /// Inspect or advance the capability-discovery phase.
    #[serde(rename = "perf_capabilities")]
    Capabilities,
    /// Inspect or advance the durable capture workflow.
    #[serde(rename = "perf_capture")]
    Capture,
    /// Read one Session's durable state and trust summary.
    #[serde(rename = "perf_get_status")]
    GetStatus,
    /// Read one bounded, health-gated quantitative summary.
    #[serde(rename = "perf_get_summary")]
    GetSummary,
    /// List bounded artifact references with cursor pagination.
    #[serde(rename = "perf_list_artifacts")]
    ListArtifacts,
    /// Convert one Session to a supported report format.
    #[serde(rename = "perf_convert")]
    Convert,
    /// Compare two completed Sessions under an explicit policy.
    #[serde(rename = "perf_compare")]
    Compare,
    /// Run the closed provision-to-report workflow.
    #[serde(rename = "perf_run")]
    Run,
}

impl PerfSurfaceOperation {
    /// Returns the exact public operation name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Capabilities => "perf_capabilities",
            Self::Capture => "perf_capture",
            Self::GetStatus => "perf_get_status",
            Self::GetSummary => "perf_get_summary",
            Self::ListArtifacts => "perf_list_artifacts",
            Self::Convert => "perf_convert",
            Self::Compare => "perf_compare",
            Self::Run => "perf_run",
        }
    }
}

/// Versioned result returned by every exact `perf_*` host operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfSurfaceEnvelope {
    /// The façade schema version.
    pub schema: PerfSurfaceSchemaVersion,
    /// Operation-specific, tagged response.
    #[serde(flatten)]
    pub response: PerfSurfaceResponse,
}

impl PerfSurfaceEnvelope {
    /// Creates a versioned façade result.
    #[must_use]
    pub const fn new(response: PerfSurfaceResponse) -> Self {
        Self {
            schema: PerfSurfaceSchemaVersion,
            response,
        }
    }

    /// Returns the exact public operation represented by this result.
    #[must_use]
    pub const fn operation(&self) -> PerfSurfaceOperation {
        self.response.operation()
    }
}

/// Tagged operation-specific façade response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "operation", content = "payload")]
pub enum PerfSurfaceResponse {
    /// Capability workflow response.
    #[serde(rename = "perf_capabilities")]
    Capabilities(PerfControlPayload),
    /// Capture workflow response.
    #[serde(rename = "perf_capture")]
    Capture(PerfControlPayload),
    /// Session status response.
    #[serde(rename = "perf_get_status")]
    GetStatus(PerfGetStatusPayload),
    /// Bounded analysis-summary response.
    #[serde(rename = "perf_get_summary")]
    GetSummary(Box<PerfGetSummaryPayload>),
    /// Paginated artifact-list response.
    #[serde(rename = "perf_list_artifacts")]
    ListArtifacts(PerfListArtifactsPayload),
    /// Report conversion response.
    #[serde(rename = "perf_convert")]
    Convert(PerfConvertPayload),
    /// Cross-session comparison response.
    #[serde(rename = "perf_compare")]
    Compare(PerfComparePayload),
    /// Closed performance-run workflow response.
    #[serde(rename = "perf_run")]
    Run(PerfRunPayload),
}

impl PerfSurfaceResponse {
    /// Returns the exact public operation represented by this variant.
    #[must_use]
    pub const fn operation(&self) -> PerfSurfaceOperation {
        match self {
            Self::Capabilities(_) => PerfSurfaceOperation::Capabilities,
            Self::Capture(_) => PerfSurfaceOperation::Capture,
            Self::GetStatus(_) => PerfSurfaceOperation::GetStatus,
            Self::GetSummary(_) => PerfSurfaceOperation::GetSummary,
            Self::ListArtifacts(_) => PerfSurfaceOperation::ListArtifacts,
            Self::Convert(_) => PerfSurfaceOperation::Convert,
            Self::Compare(_) => PerfSurfaceOperation::Compare,
            Self::Run(_) => PerfSurfaceOperation::Run,
        }
    }
}

/// Durable Controller operation exposed by the capture façade.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub enum PerfControllerOperation {
    /// Capability discovery.
    #[serde(rename = "perf_get_capabilities")]
    GetCapabilities,
    /// Target-specific trace configuration.
    #[serde(rename = "perf_configure")]
    Configure,
    /// Capture start.
    #[serde(rename = "perf_start")]
    Start,
    /// Capture stop.
    #[serde(rename = "perf_stop")]
    Stop,
    /// Hardware-health retrieval.
    #[serde(rename = "perf_get_health")]
    GetHealth,
    /// Raw trace export.
    #[serde(rename = "perf_export")]
    Export,
    /// Host-processed hotspot request.
    #[serde(rename = "perf_get_hotspots")]
    GetHotspots,
    /// Target-state cleanup.
    #[serde(rename = "perf_cleanup")]
    Cleanup,
}

/// Capture phase reconstructed from immutable Controller artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PerfCapturePhase {
    /// Capability evidence is required.
    CapabilitiesRequired,
    /// Trace configuration evidence is required.
    ConfigureRequired,
    /// Capture-start evidence is required.
    StartRequired,
    /// Workload completion and capture-stop evidence are required.
    StopRequired,
    /// Hardware-health evidence is required.
    HealthRequired,
    /// Raw trace export is required.
    ExportRequired,
    /// Adapter-owned SNOOPer state must be restored.
    CleanupRequired,
    /// The Controller capture chain is complete.
    CaptureComplete,
}

/// State of one façade call against the durable control workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PerfControlStatus {
    /// A new immutable transaction was prepared.
    Prepared,
    /// A transaction remains pending upstream.
    Pending,
    /// One pending transaction was accepted and committed.
    OperationCompleted,
    /// Capability discovery was already complete.
    CapabilitiesComplete,
    /// The caller must run its fixed workload before stop can be prepared.
    WorkloadRequired,
    /// The Controller capture chain completed and host processing is required.
    ControlComplete,
}

/// Exact official t32mcp tool named by one next action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PerfMcpTool {
    /// Starts one fixed PRACTICE skill script.
    ExecutePracticeSkill,
    /// Collects the globally active PRACTICE response.
    CollectPracticeSkillResponse,
}

/// Typed arguments for `execute_practice_skill`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfExecuteArguments {
    /// Fixed logical skill name.
    pub skill_name: String,
    /// Fixed script filename.
    pub script_name: String,
    /// Bounded Controller-owned script arguments.
    #[schemars(length(max = 8))]
    pub script_args: BTreeMap<String, String>,
}

/// Exact execute call returned to the trusted MCP caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfExecuteCall {
    /// Official tool identifier.
    pub tool: PerfMcpTool,
    /// Typed fixed-skill arguments.
    pub arguments: PerfExecuteArguments,
}

/// Exact no-argument collect call returned to the trusted MCP caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfCollectCall {
    /// Official tool identifier.
    pub tool: PerfMcpTool,
    /// Empty tool arguments.
    pub arguments: PerfNoArguments,
}

/// Structurally empty MCP argument object.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfNoArguments {}

/// Controller-owned response-file handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfResponseHandoff {
    /// Absolute response path allocated by the Controller.
    pub path: String,
    /// Maximum accepted response bytes.
    #[schemars(range(min = 1))]
    pub max_bytes: u64,
    /// Bounded instruction for committing the final wrapper.
    pub instruction: String,
}

/// Explicit resume invocation after an externally owned workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfResumeAction {
    /// Exact façade operation to invoke.
    pub operation: PerfSurfaceOperation,
    /// Fixed arguments required by that invocation.
    #[schemars(length(max = 4))]
    pub arguments: Vec<String>,
}

/// The only next action permitted by one control response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PerfNextAction {
    /// Execute a newly prepared immutable Controller request.
    Execute {
        /// Exact official MCP call.
        mcp: PerfExecuteCall,
        /// Controller-owned response destination.
        response_handoff: PerfResponseHandoff,
    },
    /// Collect the response of an already pending transaction.
    Collect {
        /// Exact official MCP collect call.
        mcp: PerfCollectCall,
        /// Controller-owned response destination.
        response_handoff: PerfResponseHandoff,
        /// Whether the separate two-phase abort path remains available.
        abort_available: bool,
    },
    /// Invoke another exact host façade operation.
    Invoke {
        /// Exact operation to invoke.
        operation: PerfSurfaceOperation,
        /// Required low-level Controller operation, when applicable.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        required_controller_operation: Option<PerfControllerOperation>,
    },
    /// Run the target-specific workload before acknowledging completion.
    RunWorkload {
        /// Component that owns workload execution.
        ownership: String,
        /// Exact resumption call after workload completion.
        resume: PerfResumeAction,
    },
    /// The Controller has durably materialized the authoritative capture configuration.
    CaptureConfigReady {
        /// Immutable host-derived capture configuration.
        capture_config: PerfArtifactReference,
    },
}

/// Typed response shared by capability and capture workflow operations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfControlPayload {
    /// Owning Session.
    pub session_id: String,
    /// Durable Session lifecycle state.
    pub state: SessionStatus,
    /// Reconstructed Controller capture phase.
    pub capture_phase: PerfCapturePhase,
    /// Result of the current façade call.
    pub status: PerfControlStatus,
    /// Completed operations in fixed sequence order.
    #[schemars(length(max = 8))]
    pub completed_operations: Vec<PerfControllerOperation>,
    /// Pending or newly prepared operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_operation: Option<PerfControllerOperation>,
    /// Pending or newly prepared transaction identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    /// Immutable Controller request reference for a prepared transaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_artifact: Option<Artifact>,
    /// Bounded capability/control/export artifact references.
    #[schemars(length(max = 8))]
    pub capture_artifacts: Vec<Artifact>,
    /// The only permitted next action.
    pub next_action: PerfNextAction,
}

/// Trust state reported independently of the Session lifecycle enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PerfTrustStatus {
    /// No completed analysis stage exists.
    NotEvaluated,
    /// Lifecycle/artifact state is incomplete or inconsistent.
    Incomplete,
    /// Quantitative analysis is trusted.
    Valid,
    /// Timeline-only diagnostic use is allowed.
    Degraded,
    /// Only diagnostic output is allowed.
    Invalid,
}

/// Typed result of `perf_get_status`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfGetStatusPayload {
    /// Owning Session.
    pub session_id: String,
    /// Complete durable state document.
    pub state: SessionState,
    /// Whether immutable manifest finalization completed.
    pub manifest_committed: bool,
    /// Number of registered artifacts.
    pub artifact_count: u64,
    /// Trust status derived from lifecycle and analysis artifacts.
    pub trust_status: PerfTrustStatus,
    /// Validated health verdict when an analysis stage exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_verdict: Option<HealthVerdict>,
}

/// Bounded issue returned by `perf_get_summary`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfHealthIssue {
    /// Machine-readable issue code.
    pub code: String,
    /// Policy severity.
    pub severity: HealthSeverity,
    /// Component that produced the issue.
    pub source: String,
    /// Related artifact identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<String>,
    /// Related source record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<u64>,
    /// Affected interval start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_ns: Option<i64>,
    /// Affected interval end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_ns: Option<i64>,
    /// Bounded diagnosis.
    pub message: String,
}

/// Bounded support entry returned by the summary façade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfSupportEntry {
    /// Support level.
    pub support: MetricSupportLevel,
    /// Total underlying reason count.
    pub reason_count: u64,
    /// Returned reason count.
    pub reasons_returned: u64,
    /// Whether reasons were truncated.
    pub reasons_truncated: bool,
    /// Bounded reasons.
    #[schemars(length(max = 8))]
    pub reasons: Vec<String>,
}

/// Complete metric-support projection returned by the summary façade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfMetricSupport {
    /// Function timeline support.
    pub function_timeline: PerfSupportEntry,
    /// Call-count support.
    pub call_count: PerfSupportEntry,
    /// Elapsed-time support.
    pub elapsed: PerfSupportEntry,
    /// Active-time support.
    pub active: PerfSupportEntry,
    /// Self-time support.
    #[serde(rename = "self")]
    pub self_time: PerfSupportEntry,
    /// Task timeline support.
    pub task_timeline: PerfSupportEntry,
    /// ISR timeline support.
    pub isr_timeline: PerfSupportEntry,
    /// Resource-counter support.
    pub resource_counters: PerfSupportEntry,
}

/// Bounded health projection returned by the summary façade.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfHealthSummary {
    /// Validated health verdict.
    pub verdict: HealthVerdict,
    /// Bounded policy identity.
    pub policy_version: String,
    /// Raw health-observation count.
    pub observation_count: u64,
    /// Total issue count.
    pub issue_count: u64,
    /// Returned issue count.
    pub issues_returned: u64,
    /// Whether issues were truncated.
    pub issues_truncated: bool,
    /// Bounded issues.
    #[schemars(length(max = 64))]
    pub issues: Vec<PerfHealthIssue>,
    /// Metric support under the same policy.
    pub metric_support: PerfMetricSupport,
}

/// Stable artifact reference that never includes artifact contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfArtifactReference {
    /// Artifact identity.
    pub id: String,
    /// Artifact kind.
    pub kind: String,
    /// Canonical Session-relative path.
    pub relative_path: ArtifactPath,
    /// Media type.
    pub media_type: String,
    /// Immutable size.
    pub size_bytes: u64,
    /// Immutable SHA-256 digest.
    pub sha256: Sha256Digest,
    /// Producer identity.
    pub producer: String,
}

impl From<&Artifact> for PerfArtifactReference {
    fn from(artifact: &Artifact) -> Self {
        Self {
            id: artifact.id.clone(),
            kind: artifact.kind.clone(),
            relative_path: artifact.relative_path.clone(),
            media_type: artifact.media_type.clone(),
            size_bytes: artifact.size_bytes,
            sha256: artifact.sha256.clone(),
            producer: artifact.producer.clone(),
        }
    }
}

/// Capture provenance projected into a bounded summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfSummaryCapture {
    /// Authoritative capture-config artifact identity.
    pub capture_config_artifact_id: String,
    /// Target instrumentation and measured overhead, when used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instrumentation: Option<CaptureInstrumentationConfig>,
}

/// Bounded hotspot rows returned by the summary façade.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfHotspotSummary {
    /// Aggregate evidence quality.
    pub quality: Quality,
    /// Total function-row count.
    pub function_count: u64,
    /// Total sampling-row count.
    pub sampling_count: u64,
    /// Top function rows.
    #[schemars(length(max = 100))]
    pub functions: Vec<FunctionHotspot>,
    /// Top sampling rows.
    #[schemars(length(max = 100))]
    pub sampling: Vec<SamplingHotspot>,
}

/// Bounded execution-context summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfExecutionSummary {
    /// Total Task CPU time.
    pub task_cpu_ns: u64,
    /// Total ISR CPU time.
    pub isr_cpu_ns: u64,
    /// Total idle CPU time.
    pub idle_cpu_ns: u64,
    /// Total Task context count.
    pub task_count: u64,
    /// Total ISR context count.
    pub isr_count: u64,
    /// Top Task contexts.
    #[schemars(length(max = 100))]
    pub tasks: Vec<ContextCpuSummary>,
    /// Top ISR contexts.
    #[schemars(length(max = 100))]
    pub isrs: Vec<ContextCpuSummary>,
}

/// Bounded maximum-call-depth projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfCallDepthSummary {
    /// Maximum reconstructed depth.
    pub max_depth: u32,
    /// Context containing the deepest path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Bounded deepest path.
    #[schemars(length(max = 100))]
    pub deepest_path: Vec<String>,
    /// Whether the path was truncated.
    pub path_truncated: bool,
}

/// Health-gated quantitative part of `perf_get_summary`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfQuantitativeSummary {
    /// Function and sampling hotspots.
    pub hotspots: PerfHotspotSummary,
    /// Task/ISR execution totals and Top-N rows.
    pub execution: PerfExecutionSummary,
    /// Parsed observation count.
    pub observation_count: u64,
    /// Reconstructed function-span count.
    pub function_span_count: u64,
    /// Incomplete function-span count.
    pub incomplete_function_span_count: u64,
    /// Maximum call-depth summary.
    pub call_depth: PerfCallDepthSummary,
}

/// Typed result of `perf_get_summary`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfGetSummaryPayload {
    /// Owning Session.
    pub session_id: String,
    /// Requested per-family Top-N bound.
    #[schemars(range(min = 1, max = 100))]
    pub requested_top: u64,
    /// Whether quantitative rows are trusted and present.
    pub quantitative_available: bool,
    /// Bounded health projection.
    pub health: PerfHealthSummary,
    /// Capture provenance projection.
    pub capture: PerfSummaryCapture,
    /// Bounded immutable artifact references.
    #[schemars(length(max = 32))]
    pub artifact_references: Vec<PerfArtifactReference>,
    /// Presentation report for VALID analysis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<AnalysisReport>,
    /// Quantitative Top-N projection for VALID analysis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quantitative: Option<PerfQuantitativeSummary>,
}

/// One paginated artifact-list row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfArtifactListEntry {
    /// Artifact identity.
    pub id: String,
    /// Artifact kind.
    pub kind: String,
    /// Canonical Session-relative path.
    pub relative_path: ArtifactPath,
    /// Media type.
    pub media_type: String,
    /// Immutable size.
    pub size_bytes: u64,
    /// Immutable SHA-256 digest.
    pub sha256: Sha256Digest,
    /// Producer identity.
    pub producer: String,
    /// Bounded direct provenance inputs.
    #[schemars(length(max = 16))]
    pub input_artifact_ids: Vec<String>,
    /// Total direct provenance-input count.
    pub input_artifact_ids_total_count: u64,
    /// Returned direct provenance-input count.
    pub input_artifact_ids_returned_count: u64,
    /// Whether provenance inputs were truncated.
    pub input_artifact_ids_truncated: bool,
}

/// Typed result of `perf_list_artifacts`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfListArtifactsPayload {
    /// Owning Session.
    pub session_id: String,
    /// Bounded page rows.
    #[schemars(length(max = 1000))]
    pub artifacts: Vec<PerfArtifactListEntry>,
    /// Total artifact count.
    pub total_count: u64,
    /// Returned row count.
    pub returned_count: u64,
    /// Requested page limit.
    #[schemars(range(min = 1, max = 1000))]
    pub limit: u64,
    /// Exclusive cursor used for this page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    /// Whether more rows remain.
    pub truncated: bool,
    /// Cursor for the next page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_after: Option<String>,
}

/// Typed result of `perf_convert`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfConvertPayload {
    /// Owning Session.
    pub session_id: String,
    /// Exact output format.
    pub format: String,
    /// Validated health verdict.
    pub health_verdict: HealthVerdict,
    /// Final Session status.
    pub status: SessionStatus,
    /// Immutable report artifact.
    pub artifact: Artifact,
    /// Whether immutable manifest finalization completed.
    pub manifest_committed: bool,
}

/// Kind of comparison-policy source accepted by the bounded façade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PerfComparisonPolicyKind {
    /// Built-in named policy.
    Named,
    /// Inline bounded JSON policy.
    Inline,
    /// Bounded policy file.
    File,
}

/// Sanitized comparison-policy source description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfComparisonPolicySource {
    /// Policy-source kind.
    pub kind: PerfComparisonPolicyKind,
    /// Built-in policy name when `kind` is named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Outcome counts for ordinary or static-RAM comparison rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfOutcomeCounts {
    /// Total rows.
    pub total: u64,
    /// Improved rows.
    pub improved: u64,
    /// Unchanged rows.
    pub unchanged: u64,
    /// Regressed rows.
    pub regressed: u64,
    /// Inconclusive rows.
    pub inconclusive: u64,
}

/// Outcome counts for resource comparison rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfResourceOutcomeCounts {
    /// Total rows.
    pub total: u64,
    /// Improved rows.
    pub improved: u64,
    /// Unchanged rows.
    pub unchanged: u64,
    /// Regressed rows.
    pub regressed: u64,
    /// Inconclusive rows.
    pub inconclusive: u64,
    /// Informational rows.
    pub informational: u64,
}

/// Complete outcome-count projection for a comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfComparisonOutcomeCounts {
    /// Function and execution metric rows.
    pub metrics: PerfOutcomeCounts,
    /// Resource metric rows.
    pub resource_metrics: PerfResourceOutcomeCounts,
    /// Static-RAM metric rows.
    pub static_ram_metrics: PerfOutcomeCounts,
}

/// Bounded comparison summary; full rows remain in the control artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfComparisonSummary {
    /// Comparison schema version.
    pub schema: ComparisonSchemaVersion,
    /// Baseline Session.
    pub baseline_session_id: String,
    /// Candidate Session.
    pub candidate_session_id: String,
    /// Baseline health verdict.
    pub baseline_health: HealthVerdict,
    /// Candidate health verdict.
    pub candidate_health: HealthVerdict,
    /// Overall comparison verdict.
    pub verdict: ComparisonVerdict,
    /// Requested Top-N bound used by the internal projection.
    #[schemars(range(min = 1, max = 100))]
    pub requested_top: u64,
    /// Bounded capture-wide reasons.
    #[schemars(length(max = 32))]
    pub reasons: Vec<String>,
    /// Total reason count.
    pub reasons_total_count: u64,
    /// Returned reason count.
    pub reasons_returned_count: u64,
    /// Whether reasons were truncated.
    pub reasons_truncated: bool,
    /// Total ordinary metric-row count.
    pub metrics_total_count: u64,
    /// Total resource metric-row count.
    pub resource_metrics_total_count: u64,
    /// Total static-RAM metric-row count.
    pub static_ram_metrics_total_count: u64,
    /// Complete outcome counts without inlining arbitrary rows.
    pub outcome_counts: PerfComparisonOutcomeCounts,
}

/// Content-addressed control-plane comparison artifact reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfComparisonArtifactReference {
    /// Comparison-artifact schema identity.
    pub schema: String,
    /// Artifact-root-relative control path.
    pub control_path: String,
    /// Immutable content digest.
    pub sha256: Sha256Digest,
    /// Immutable size.
    pub size_bytes: u64,
    /// Exact comparison-policy digest.
    pub policy_sha256: Sha256Digest,
    /// Publication class.
    pub publication: String,
}

/// Typed result of `perf_compare`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfComparePayload {
    /// Sanitized policy source.
    pub policy: PerfComparisonPolicySource,
    /// Overall verdict.
    pub verdict: ComparisonVerdict,
    /// Whether inconclusive was accepted as a zero exit code.
    pub inconclusive_allowed: bool,
    /// Bounded summary without arbitrary comparison rows.
    pub report: PerfComparisonSummary,
    /// Authoritative full report reference.
    pub report_artifact: PerfComparisonArtifactReference,
}
