//! Versioned analysis summaries and stage provenance.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AnalysisStageSchemaVersion, AnalysisSummarySchemaVersion, Artifact, ContextKind,
    CounterSemantic, CounterSubject, DerivedResourceMetricSummary, DerivedStreamSchemaVersion,
    DurationNs, HealthSchemaVersion, HealthVerdict, HotspotsSchemaVersion, MetricSupport,
    MetricSupportEntry, Quality, ResourceClass, StaticRamConfigProvenance, StaticRamKindTotals,
    TimestampNs, ToolInfo,
};

/// Stable analyzer contract implemented by this major version.
pub const ANALYZER_CONTRACT: &str = "t32perf.analyzer/v1";

/// Counts that remain useful for diagnosis even when quantitative results are gated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnalysisDiagnosticCounts {
    /// Number of normalized observations consumed by the analyzer.
    pub observation_count: u64,
    /// Number of derived function-span records emitted, including incomplete spans.
    pub function_span_count: u64,
    /// Number of derived spans excluded from trusted aggregation.
    pub incomplete_function_span_count: u64,
    /// Number of raw health observations retained by the health report.
    pub health_observation_count: u64,
    /// Number of diagnosed health issues retained by the health report.
    pub health_issue_count: u64,
}

/// Deepest reconstructed call path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CallDepthSummary {
    /// Maximum number of simultaneously open function frames.
    pub max_depth: u32,
    /// Context in which the deepest path occurred.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Function identifiers from root to leaf at maximum depth.
    pub deepest_path: Vec<String>,
}

/// Virtual CPU time attributed to one execution context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ContextCpuSummary {
    /// Context dictionary identifier.
    pub context_id: String,
    /// Context kind from the dictionary or analyzer inference.
    pub kind: ContextKind,
    /// Time during which this context was actually running on a core.
    pub active_ns: DurationNs,
}

/// Summary of all numeric counters observed during analysis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResourceSummary {
    /// Per-counter summaries sorted by counter identifier.
    pub counters: Vec<ResourceCounterSummary>,
    /// Evidence-gated metrics derived from explicit source-counter semantics.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derived: Vec<DerivedResourceMetricSummary>,
}

impl ResourceSummary {
    /// Returns summaries belonging to one resource class.
    pub fn by_class(&self, class: ResourceClass) -> impl Iterator<Item = &ResourceCounterSummary> {
        self.counters
            .iter()
            .filter(move |counter| counter.class == class)
    }

    fn validate(&self, ceiling: &MetricSupportEntry) -> Result<(), String> {
        let mut counter_ids = BTreeSet::new();
        let mut identities = BTreeSet::new();
        for counter in &self.counters {
            if !counter_ids.insert(counter.counter_id.as_str()) {
                return Err(format!("duplicate counter id `{}`", counter.counter_id));
            }
            counter.validate(ceiling)?;
            if let (Some(semantic), Some(subject)) = (&counter.semantic, &counter.subject)
                && !identities.insert((semantic, subject))
            {
                return Err(format!(
                    "duplicate resource identity `{semantic}` for subject {subject:?}"
                ));
            }
        }
        for metric in &self.derived {
            metric
                .subject
                .validate()
                .map_err(|error| error.to_string())?;
            let spec = metric.semantic.standard_spec().ok_or_else(|| {
                format!(
                    "derived semantic `{}` is not a standard semantic",
                    metric.semantic
                )
            })?;
            if metric.unit != spec.unit {
                return Err(format!(
                    "derived semantic `{}` requires unit `{}`",
                    metric.semantic, spec.unit
                ));
            }
            if metric
                .value
                .is_some_and(|value| !spec.value_is_valid(value))
            {
                return Err(format!(
                    "derived semantic `{}` contains an invalid value",
                    metric.semantic
                ));
            }
            if !identities.insert((&metric.semantic, &metric.subject)) {
                return Err(format!(
                    "derived semantic `{}` duplicates a resource identity",
                    metric.semantic
                ));
            }
            validate_support(&metric.support)?;
            if support_rank(metric.support.support) < support_rank(ceiling.support) {
                return Err(format!(
                    "derived semantic `{}` exceeds resource support ceiling",
                    metric.semantic
                ));
            }
            if metric.support.is_available() != metric.value.is_some() {
                return Err(format!(
                    "derived semantic `{}` support and value presence disagree",
                    metric.semantic
                ));
            }
            if metric.value.is_some() != metric.quality.is_some() {
                return Err(format!(
                    "derived semantic `{}` quality and value presence disagree",
                    metric.semantic
                ));
            }
            if metric.source_counter_ids.is_empty()
                || metric.source_counter_ids.iter().any(|counter_id| {
                    counter_id.trim().is_empty() || !counter_ids.contains(counter_id.as_str())
                })
                || metric
                    .source_counter_ids
                    .windows(2)
                    .any(|ids| ids[0] >= ids[1])
            {
                return Err(format!(
                    "derived semantic `{}` has no valid source counter",
                    metric.semantic
                ));
            }
            if metric.window_ns == Some(0) {
                return Err(format!(
                    "derived semantic `{}` has a zero window",
                    metric.semantic
                ));
            }
            if metric.first_ts_ns.is_some() != metric.last_ts_ns.is_some()
                || metric.window_ns.is_some() && metric.first_ts_ns.is_none()
                || metric
                    .first_ts_ns
                    .zip(metric.last_ts_ns)
                    .is_some_and(|(first, last)| last < first)
            {
                return Err(format!(
                    "derived semantic `{}` has an invalid evidence window",
                    metric.semantic
                ));
            }
        }
        Ok(())
    }
}

/// Aggregate statistics for one counter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResourceCounterSummary {
    /// Counter dictionary identifier.
    pub counter_id: String,
    /// Human-readable dictionary name when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Unit from the counter dictionary when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    /// Explicit semantic identity, absent for legacy generic counters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic: Option<CounterSemantic>,
    /// Explicit resource identity, absent for legacy generic counters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<CounterSubject>,
    /// Resource class assigned to this counter.
    pub class: ResourceClass,
    /// Number of counter values consumed.
    pub sample_count: u64,
    /// First observation timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_ts_ns: Option<TimestampNs>,
    /// Latest observation timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_ts_ns: Option<TimestampNs>,
    /// First observed value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first: Option<f64>,
    /// Latest observed value.
    pub latest: f64,
    /// Minimum observed value.
    pub min: f64,
    /// Maximum observed value.
    pub max: f64,
    /// Arithmetic mean of observed values.
    pub mean: f64,
    /// `latest - first` when both values exist and the semantic window is valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta: Option<f64>,
    /// Positive duration between first and latest observations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_ns: Option<u64>,
    /// Per-second rate derived only from a valid monotonic count window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_per_second: Option<f64>,
    /// Worst evidence quality among contributing observations.
    pub quality: Quality,
    /// Effective capability, evidence-quality, and health-policy support.
    #[serde(default = "resource_counter_support_not_recorded")]
    pub support: MetricSupportEntry,
}

impl ResourceCounterSummary {
    fn validate(&self, ceiling: &MetricSupportEntry) -> Result<(), String> {
        if self.counter_id.trim().is_empty() || self.sample_count == 0 {
            return Err("counter identity is empty or sample_count is zero".to_owned());
        }
        if [self.latest, self.min, self.max, self.mean]
            .into_iter()
            .any(|value| !value.is_finite())
            || self.first.is_some_and(|value| !value.is_finite())
            || self.delta.is_some_and(|value| !value.is_finite())
            || self.rate_per_second.is_some_and(|value| !value.is_finite())
            || self.rate_per_second.is_some_and(|value| value < 0.0)
        {
            return Err(format!(
                "counter `{}` contains a non-finite aggregate",
                self.counter_id
            ));
        }
        if self.min > self.max
            || self.latest < self.min
            || self.latest > self.max
            || self.mean < self.min
            || self.mean > self.max
        {
            return Err(format!(
                "counter `{}` has inconsistent aggregates",
                self.counter_id
            ));
        }
        match (&self.semantic, &self.subject) {
            (None, None) => {
                if self.class != ResourceClass::Other {
                    return Err(format!(
                        "generic counter `{}` has a semantic resource class",
                        self.counter_id
                    ));
                }
            }
            (Some(semantic), Some(subject)) => {
                subject.validate().map_err(|error| error.to_string())?;
                if let Some(spec) = semantic.standard_spec() {
                    if self.unit.as_deref() != Some(spec.unit)
                        || subject.kind() != Some(spec.subject_kind)
                        || self.class != spec.class
                    {
                        return Err(format!(
                            "counter `{}` does not match semantic `{semantic}`",
                            self.counter_id
                        ));
                    }
                    for value in [
                        Some(self.latest),
                        Some(self.min),
                        Some(self.max),
                        self.first,
                    ]
                    .into_iter()
                    .flatten()
                    {
                        if !spec.value_is_valid(value) {
                            return Err(format!(
                                "counter `{}` contains a value invalid for `{semantic}`",
                                self.counter_id
                            ));
                        }
                    }
                    if self.delta.is_some_and(|delta| {
                        matches!(
                            spec.behavior,
                            crate::CounterBehavior::Monotonic
                                | crate::CounterBehavior::HighWatermark
                        ) && delta < 0.0
                            || spec.behavior == crate::CounterBehavior::Capacity && delta != 0.0
                    }) {
                        return Err(format!(
                            "counter `{}` has an invalid semantic delta",
                            self.counter_id
                        ));
                    }
                } else if self.class != ResourceClass::Other {
                    return Err(format!(
                        "extension counter `{}` has a standard resource class",
                        self.counter_id
                    ));
                }
            }
            _ => {
                return Err(format!(
                    "counter `{}` must pair semantic and subject",
                    self.counter_id
                ));
            }
        }
        if self.first_ts_ns.is_some() != self.last_ts_ns.is_some()
            || self.first_ts_ns.is_some() != self.first.is_some()
            || self.window_ns == Some(0)
            || self.window_ns.is_some() && self.first_ts_ns.is_none()
            || (self.delta.is_some() || self.rate_per_second.is_some()) && self.first.is_none()
            || self
                .first_ts_ns
                .zip(self.last_ts_ns)
                .is_some_and(|(first, last)| last < first)
        {
            return Err(format!(
                "counter `{}` has an invalid observation window",
                self.counter_id
            ));
        }
        validate_support(&self.support)?;
        if support_rank(self.support.support) < support_rank(ceiling.support) {
            return Err(format!(
                "counter `{}` exceeds resource support ceiling",
                self.counter_id
            ));
        }
        Ok(())
    }
}

fn validate_support(entry: &MetricSupportEntry) -> Result<(), String> {
    if entry.support != crate::MetricSupportLevel::Exact && entry.reasons.is_empty() {
        return Err("non-exact resource support has no reason".to_owned());
    }
    let mut reasons = BTreeSet::new();
    for reason in &entry.reasons {
        if reason.trim().is_empty() || !reasons.insert(reason) {
            return Err("resource support contains an empty or duplicate reason".to_owned());
        }
    }
    Ok(())
}

fn support_rank(level: crate::MetricSupportLevel) -> u8 {
    match level {
        crate::MetricSupportLevel::Exact => 0,
        crate::MetricSupportLevel::Inferred => 1,
        crate::MetricSupportLevel::Statistical => 2,
        crate::MetricSupportLevel::Unavailable => 3,
    }
}

fn resource_counter_support_not_recorded() -> MetricSupportEntry {
    MetricSupportEntry::unavailable("resource_counter_support_not_recorded")
}

/// Quantitative execution and dynamic-resource summary.
///
/// This value is trustworthy only when the owning document has a `VALID`
/// health verdict. The versioned document enforces that gate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AnalysisSummary {
    /// Number of normalized observations consumed.
    pub observation_count: u64,
    /// Number of reconstructed function spans.
    pub function_span_count: u64,
    /// Number of spans excluded from trusted aggregation.
    pub incomplete_function_span_count: u64,
    /// Maximum call depth and the path that established it.
    pub call_depth: CallDepthSummary,
    /// Virtual CPU time grouped by execution context.
    pub context_cpu: Vec<ContextCpuSummary>,
    /// Total virtual CPU time attributed to task contexts.
    pub task_cpu_ns: DurationNs,
    /// Total virtual CPU time attributed to ISR contexts.
    pub isr_cpu_ns: DurationNs,
    /// Total virtual CPU time attributed to idle contexts.
    pub idle_cpu_ns: DurationNs,
    /// Numeric counter and resource summaries.
    pub resources: ResourceSummary,
}

/// Static RAM summary linked to its independently persisted source report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StaticRamAnalysisSummary {
    /// ID of the independently persisted parsed static-RAM artifact.
    pub artifact_id: String,
    /// ID of the linker-map artifact consumed by the parser.
    pub source_artifact_id: String,
    /// Versioned linker-map parser flavor.
    pub flavor: String,
    /// Exact parser-configuration provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<StaticRamConfigProvenance>,
    /// Total classified static RAM in bytes.
    pub total_bytes: u64,
    /// Checked totals kept separate for every classification.
    #[serde(default)]
    pub totals: StaticRamKindTotals,
    /// Support for binding the parsed MAP data to the running firmware identity.
    #[serde(default = "static_resource_support_not_recorded")]
    pub support: MetricSupportEntry,
}

/// Static stack-usage summary linked to its independently persisted source report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StackUsageAnalysisSummary {
    /// ID of the independently persisted parsed stack-usage artifact.
    pub artifact_id: String,
    /// ID of the compiler stack-usage artifact consumed by the parser.
    pub source_artifact_id: String,
    /// Versioned stack-usage parser flavor.
    pub flavor: String,
    /// Maximum statically bounded stack frame in bytes, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_static_bytes: Option<u64>,
    /// Number of parsed function entries.
    pub function_count: u64,
    /// Support for binding the compiler report to the running firmware identity.
    #[serde(default = "static_resource_support_not_recorded")]
    pub support: MetricSupportEntry,
}

fn static_resource_support_not_recorded() -> MetricSupportEntry {
    MetricSupportEntry::unavailable("static_resource_support_not_recorded")
}

/// All quantitative values persisted by the analysis-summary document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AnalysisQuantitativeSummary {
    /// Dynamic execution, call-depth, and counter summary.
    #[serde(flatten)]
    pub analysis: AnalysisSummary,
    /// Optional static RAM summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_ram: Option<StaticRamAnalysisSummary>,
    /// Optional static stack-usage summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack_usage: Option<StackUsageAnalysisSummary>,
}

/// Versioned, machine-facing summary of one completed analysis stage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AnalysisSummaryDocument {
    /// The analysis-summary schema version.
    pub schema: AnalysisSummarySchemaVersion,
    /// Session whose observations were analyzed.
    pub session_id: String,
    /// Health verdict that gates the optional quantitative payload.
    pub health_verdict: HealthVerdict,
    /// Metric support determined by the same health-policy evaluation.
    pub metric_support: MetricSupport,
    /// Exact immutable artifact claims consumed by this document.
    pub input_artifacts: Vec<Artifact>,
    /// Counts retained for diagnosis and receipt verification.
    pub diagnostics: AnalysisDiagnosticCounts,
    /// Quantitative results, present only for a `VALID` capture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quantitative: Option<AnalysisQuantitativeSummary>,
}

impl AnalysisSummaryDocument {
    /// Validates identity, artifact claims, health gating, and duplicate inputs.
    pub fn validate(&self) -> Result<(), AnalysisContractValidationError> {
        validate_nonempty("session_id", &self.session_id)?;
        validate_artifact_claims("input_artifacts", &self.input_artifacts)?;
        match (self.health_verdict, self.quantitative.is_some()) {
            (HealthVerdict::Valid, true)
            | (HealthVerdict::Degraded | HealthVerdict::Invalid, false) => {}
            (HealthVerdict::Valid, false) => {
                return Err(AnalysisContractValidationError::MissingQuantitativeSummary);
            }
            (HealthVerdict::Degraded | HealthVerdict::Invalid, true) => {
                return Err(
                    AnalysisContractValidationError::UntrustedQuantitativeSummary {
                        verdict: self.health_verdict,
                    },
                );
            }
        }
        if let Some(quantitative) = &self.quantitative
            && (quantitative.analysis.observation_count != self.diagnostics.observation_count
                || quantitative.analysis.function_span_count
                    != self.diagnostics.function_span_count
                || quantitative.analysis.incomplete_function_span_count
                    != self.diagnostics.incomplete_function_span_count)
        {
            return Err(AnalysisContractValidationError::DiagnosticCountMismatch);
        }
        if let Some(quantitative) = &self.quantitative {
            quantitative
                .analysis
                .resources
                .validate(&self.metric_support.resource_counters)
                .map_err(
                    |message| AnalysisContractValidationError::InvalidResourceSummary { message },
                )?;
            if let Some(static_ram) = &quantitative.static_ram {
                if static_ram.config.is_some()
                    && static_ram.totals.checked_total() != Some(static_ram.total_bytes)
                {
                    return Err(AnalysisContractValidationError::InvalidResourceSummary {
                        message: "static RAM per-kind totals do not match total_bytes".to_owned(),
                    });
                }
                if static_ram
                    .config
                    .as_ref()
                    .and_then(|config| config.artifact_id.as_deref())
                    .is_some_and(|artifact_id| artifact_id.trim().is_empty())
                {
                    return Err(AnalysisContractValidationError::InvalidResourceSummary {
                        message: "static RAM configuration artifact identity is empty".to_owned(),
                    });
                }
                validate_support(&static_ram.support).map_err(|message| {
                    AnalysisContractValidationError::InvalidResourceSummary { message }
                })?;
            }
            if let Some(stack_usage) = &quantitative.stack_usage {
                validate_support(&stack_usage.support).map_err(|message| {
                    AnalysisContractValidationError::InvalidResourceSummary { message }
                })?;
            }
        }
        Ok(())
    }
}

/// Versioned contract identifiers used to interpret one analysis stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalysisContracts {
    /// Analyzer behavior and aggregation contract.
    pub analyzer: String,
    /// Health-policy behavior contract.
    pub health_policy: String,
    /// Health artifact schema interpreted by the stage.
    pub health_schema: HealthSchemaVersion,
    /// Derived NDJSON stream schema written by the stage.
    pub derived_stream_schema: DerivedStreamSchemaVersion,
    /// Hotspot artifact schema supported by the stage.
    pub hotspots_schema: HotspotsSchemaVersion,
    /// Analysis-summary artifact schema written by the stage.
    pub analysis_summary_schema: AnalysisSummarySchemaVersion,
}

/// Immutable receipt binding an analysis run to exact input and output bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalysisStageReceipt {
    /// The analysis-stage receipt schema version.
    pub schema: AnalysisStageSchemaVersion,
    /// Session that owns every claimed artifact.
    pub session_id: String,
    /// Tool build that executed the stage.
    pub tool: ToolInfo,
    /// Versioned contracts used by the stage.
    pub contracts: AnalysisContracts,
    /// Health verdict produced by the declared policy.
    pub health_verdict: HealthVerdict,
    /// Metric support produced by the declared policy.
    pub metric_support: MetricSupport,
    /// Diagnostic counts bound to the output documents.
    pub diagnostics: AnalysisDiagnosticCounts,
    /// Exact immutable external inputs to the analysis stage.
    pub input_artifacts: Vec<Artifact>,
    /// Exact immutable outputs committed before this receipt.
    pub output_artifacts: Vec<Artifact>,
}

impl AnalysisStageReceipt {
    /// Validates identities and complete, disjoint artifact claims.
    pub fn validate(&self) -> Result<(), AnalysisContractValidationError> {
        validate_nonempty("session_id", &self.session_id)?;
        validate_nonempty("tool.name", &self.tool.name)?;
        validate_nonempty("tool.version", &self.tool.version)?;
        validate_nonempty("contracts.analyzer", &self.contracts.analyzer)?;
        validate_nonempty("contracts.health_policy", &self.contracts.health_policy)?;
        validate_artifact_claims("input_artifacts", &self.input_artifacts)?;
        validate_artifact_claims("output_artifacts", &self.output_artifacts)?;

        let inputs = self
            .input_artifacts
            .iter()
            .map(|artifact| artifact.id.as_str())
            .collect::<BTreeSet<_>>();
        if let Some(artifact_id) = self
            .output_artifacts
            .iter()
            .map(|artifact| artifact.id.as_str())
            .find(|artifact_id| inputs.contains(artifact_id))
        {
            return Err(AnalysisContractValidationError::InputOutputOverlap {
                artifact_id: artifact_id.to_owned(),
            });
        }
        Ok(())
    }
}

fn validate_nonempty(
    field: &'static str,
    value: &str,
) -> Result<(), AnalysisContractValidationError> {
    if value.trim().is_empty() {
        return Err(AnalysisContractValidationError::EmptyField { field });
    }
    Ok(())
}

fn validate_artifact_claims(
    field: &'static str,
    artifacts: &[Artifact],
) -> Result<(), AnalysisContractValidationError> {
    let mut ids = BTreeSet::new();
    for artifact in artifacts {
        artifact.validate().map_err(|error| {
            AnalysisContractValidationError::InvalidArtifactClaim {
                artifact_id: artifact.id.clone(),
                message: error.to_string(),
            }
        })?;
        if !ids.insert(artifact.id.as_str()) {
            return Err(AnalysisContractValidationError::DuplicateArtifactClaim {
                field,
                artifact_id: artifact.id.clone(),
            });
        }
    }
    Ok(())
}

/// A semantic invariant violation in an analysis document or receipt.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AnalysisContractValidationError {
    /// A required identity or contract field is empty.
    #[error("analysis contract field `{field}` is empty")]
    EmptyField {
        /// Empty field name.
        field: &'static str,
    },
    /// An artifact claim contains invalid metadata.
    #[error("analysis artifact claim `{artifact_id}` is invalid: {message}")]
    InvalidArtifactClaim {
        /// Artifact identifier.
        artifact_id: String,
        /// Underlying validation detail.
        message: String,
    },
    /// One claim list repeats an artifact identifier.
    #[error("analysis `{field}` contains duplicate artifact `{artifact_id}`")]
    DuplicateArtifactClaim {
        /// Claim-list field.
        field: &'static str,
        /// Duplicated artifact identifier.
        artifact_id: String,
    },
    /// An artifact is claimed as both an input and output.
    #[error("analysis artifact `{artifact_id}` is claimed as both input and output")]
    InputOutputOverlap {
        /// Overlapping artifact identifier.
        artifact_id: String,
    },
    /// A valid analysis omitted its required quantitative summary.
    #[error("a VALID analysis-summary document must contain quantitative results")]
    MissingQuantitativeSummary,
    /// A nonvalid analysis persisted quantitative results.
    #[error(
        "an analysis-summary document with verdict {verdict:?} must not contain quantitative results"
    )]
    UntrustedQuantitativeSummary {
        /// Verdict that failed the trust gate.
        verdict: HealthVerdict,
    },
    /// Quantitative and diagnostic counts disagree.
    #[error("analysis quantitative counts do not match diagnostic counts")]
    DiagnosticCountMismatch,
    /// Dynamic or static resource data violates its semantic contract.
    #[error("analysis resource summary is invalid: {message}")]
    InvalidResourceSummary {
        /// Resource validation detail.
        message: String,
    },
}
