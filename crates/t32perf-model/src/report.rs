//! Cross-session comparisons and human-facing report contracts.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ComparisonSchemaVersion, CounterSemantic, CounterSubject, DurationNs, HealthSeverity,
    HealthVerdict, MetricSupportLevel, Properties, Quality, ReportSchemaVersion,
};

/// Kind of entity to which a compared metric belongs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonSubjectKind {
    /// A function dictionary entry.
    Function,
    /// An RTOS task or thread context.
    Task,
    /// An interrupt context.
    Isr,
    /// The complete capture session.
    Capture,
    /// An extension-defined entity.
    Custom,
}

/// Stable identity of an entity compared across two sessions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ComparisonSubject {
    /// Semantic kind of the entity.
    pub kind: ComparisonSubjectKind,
    /// Dictionary ID or other stable identity.
    pub id: String,
    /// Optional execution-context partition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
}

/// Built-in metric that can be compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonMetricKind {
    /// Inclusive active time in nanoseconds.
    InclusiveActiveNs,
    /// Self active time in nanoseconds.
    SelfActiveNs,
    /// Function activation count.
    Count,
    /// Minimum active activation time in nanoseconds.
    MinActiveNs,
    /// Maximum active activation time in nanoseconds.
    MaxActiveNs,
    /// Mean active activation time in nanoseconds.
    AvgActiveNs,
    /// Statistical sample count.
    SampleCount,
    /// Estimated sampling share in the inclusive range 0 to 1.
    EstimatedShare,
}

/// Outcome assigned to one metric comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MetricComparisonOutcome {
    /// The metric improved according to the configured policy.
    Improved,
    /// The change remains within the configured tolerance.
    Unchanged,
    /// The metric regressed according to the configured policy.
    Regressed,
    /// Health, support, or baseline constraints prevent a conclusion.
    Inconclusive,
}

/// Aggregate selected from one resource-counter summary.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ResourceComparisonAggregate {
    /// Last value observed in the capture.
    Latest,
    /// Minimum value observed in the capture.
    Min,
    /// Maximum value observed in the capture.
    Max,
    /// Arithmetic mean of values observed in the capture.
    Mean,
    /// Last value minus first value in a valid semantic window.
    Delta,
    /// Per-second rate derived from a valid monotonic window.
    RatePerSecond,
}

/// Direction used to interpret a configured resource metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResourceComparisonDirection {
    /// A smaller candidate value is an improvement.
    LowerIsBetter,
    /// A larger candidate value is an improvement.
    HigherIsBetter,
}

/// Policy outcome for one dynamic-resource comparison row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResourceMetricComparisonOutcome {
    /// The configured rule classifies the candidate as improved.
    Improved,
    /// The configured rule classifies the change as within tolerance.
    Unchanged,
    /// The configured rule classifies the candidate as regressed.
    Regressed,
    /// A configured rule could not produce a strict result.
    Inconclusive,
    /// No rule is configured; the row is diagnostic only.
    Informational,
}

/// Diagnostic source of one compared dynamic-resource value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResourceMetricSource {
    /// Direct aggregate from one counter dictionary entry.
    Counter {
        /// Counter dictionary ID used only for diagnosis.
        counter_id: String,
    },
    /// Analyzer-derived value supported by one or more source counters.
    Derived {
        /// Counter dictionary IDs that supplied the evidence.
        source_counter_ids: Vec<String>,
    },
}

impl ResourceMetricSource {
    fn is_valid(&self) -> bool {
        match self {
            Self::Counter { counter_id } => !counter_id.trim().is_empty(),
            Self::Derived { source_counter_ids } => {
                !source_counter_ids.is_empty()
                    && source_counter_ids
                        .iter()
                        .all(|counter_id| !counter_id.trim().is_empty())
                    && source_counter_ids.windows(2).all(|ids| ids[0] < ids[1])
            }
        }
    }
}

/// Comparison of one aggregate for one semantic resource identity.
///
/// The authoritative identity is `(semantic, subject)`. Counter dictionary IDs
/// are retained only to diagnose renames and malformed identity reuse.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResourceMetricComparison {
    /// Explicit counter semantic.
    pub semantic: CounterSemantic,
    /// Exact resource subject.
    pub subject: CounterSubject,
    /// Aggregate selected for comparison.
    pub aggregate: ResourceComparisonAggregate,
    /// Baseline source, absent when an allowed subject addition is compared with zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_source: Option<ResourceMetricSource>,
    /// Candidate source, absent when an allowed subject removal is compared with zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_source: Option<ResourceMetricSource>,
    /// Baseline unit as persisted by the analyzer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_unit: Option<String>,
    /// Candidate unit as persisted by the analyzer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_unit: Option<String>,
    /// Baseline support level, absent when that subject is missing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_support: Option<MetricSupportLevel>,
    /// Candidate support level, absent when that subject is missing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_support: Option<MetricSupportLevel>,
    /// Baseline aggregate value.
    pub baseline: f64,
    /// Candidate aggregate value.
    pub candidate: f64,
    /// `candidate - baseline` in the recorded unit.
    pub delta: f64,
    /// `(candidate - baseline) / baseline`, absent for a zero baseline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relative_change: Option<f64>,
    /// Worst evidence quality of values present on either side.
    pub quality: Quality,
    /// Configured direction, absent for an informational row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<ResourceComparisonDirection>,
    /// Configured absolute threshold, absent for an informational row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub absolute_threshold: Option<f64>,
    /// Configured relative threshold, absent for an informational row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relative_threshold: Option<f64>,
    /// Policy outcome or informational disposition.
    pub outcome: ResourceMetricComparisonOutcome,
    /// Reasons explaining membership, support, unit, or policy behavior.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

impl ResourceMetricComparison {
    /// Validates identity, diagnostics, policy projection, and numeric values.
    pub fn validate(&self) -> Result<(), ComparisonValidationError> {
        self.subject
            .validate()
            .map_err(|_| ComparisonValidationError::InvalidResourceSubject {
                semantic: self.semantic.clone(),
            })?;
        if self
            .baseline_source
            .as_ref()
            .is_some_and(|source| !source.is_valid())
            || self
                .candidate_source
                .as_ref()
                .is_some_and(|source| !source.is_valid())
            || (self.baseline_source.is_none() && self.candidate_source.is_none())
            || self
                .baseline_unit
                .as_deref()
                .is_some_and(|unit| unit.trim().is_empty())
            || self
                .candidate_unit
                .as_deref()
                .is_some_and(|unit| unit.trim().is_empty())
            || self.baseline_source.is_some() != self.baseline_unit.is_some()
            || self.baseline_source.is_some() != self.baseline_support.is_some()
            || self.candidate_source.is_some() != self.candidate_unit.is_some()
            || self.candidate_source.is_some() != self.candidate_support.is_some()
        {
            return Err(ComparisonValidationError::InvalidResourceDiagnostic {
                semantic: self.semantic.clone(),
            });
        }
        if !self.baseline.is_finite()
            || !self.candidate.is_finite()
            || !self.delta.is_finite()
            || self.relative_change.is_some_and(|value| !value.is_finite())
            || self
                .absolute_threshold
                .is_some_and(|value| !value.is_finite() || value < 0.0)
            || self
                .relative_threshold
                .is_some_and(|value| !value.is_finite() || value < 0.0)
        {
            return Err(ComparisonValidationError::NonFiniteResourceMetric {
                semantic: self.semantic.clone(),
                aggregate: self.aggregate,
            });
        }
        if self.baseline == 0.0 && self.relative_change.is_some() {
            return Err(
                ComparisonValidationError::ResourceRelativeChangeWithZeroBaseline {
                    semantic: self.semantic.clone(),
                    aggregate: self.aggregate,
                },
            );
        }
        let configured = self.direction.is_some()
            && self.absolute_threshold.is_some()
            && self.relative_threshold.is_some();
        let informational = self.direction.is_none()
            && self.absolute_threshold.is_none()
            && self.relative_threshold.is_none()
            && self.outcome == ResourceMetricComparisonOutcome::Informational;
        if !configured && !informational
            || configured && self.outcome == ResourceMetricComparisonOutcome::Informational
        {
            return Err(ComparisonValidationError::InvalidResourcePolicyProjection {
                semantic: self.semantic.clone(),
                aggregate: self.aggregate,
            });
        }
        Ok(())
    }
}

/// Static-RAM quantity compared between two analysis summaries.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum StaticRamMetricKind {
    /// Sum of every classified static-RAM kind.
    Total,
    /// Initialized `.data` bytes.
    Data,
    /// Zero-initialized `.bss` bytes.
    Bss,
    /// Non-initialized `.noinit` bytes.
    Noinit,
    /// Explicit DMA-section bytes.
    Dma,
    /// Explicit RTOS-section bytes.
    Rtos,
    /// Explicit custom-section bytes.
    Custom,
}

/// Exact lower-is-better comparison of one static-RAM quantity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StaticRamMetricComparison {
    /// Static-RAM quantity being compared.
    pub metric: StaticRamMetricKind,
    /// Baseline byte count.
    pub baseline_bytes: u64,
    /// Candidate byte count.
    pub candidate_bytes: u64,
    /// Lower-is-better outcome.
    pub outcome: MetricComparisonOutcome,
    /// Explanatory reasons.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

/// Comparison of one metric for one stable subject.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MetricComparison {
    /// Entity being compared.
    pub subject: ComparisonSubject,
    /// Metric being compared.
    pub metric: ComparisonMetricKind,
    /// Baseline metric value.
    pub baseline: f64,
    /// Candidate metric value.
    pub candidate: f64,
    /// `candidate - baseline` in the metric's native unit.
    pub delta: f64,
    /// `(candidate - baseline) / baseline`, absent for a zero baseline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relative_change: Option<f64>,
    /// Evidence quality of the compared values.
    pub quality: Quality,
    /// Policy outcome for this row.
    pub outcome: MetricComparisonOutcome,
    /// Reasons or policy rules that explain the outcome.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

impl MetricComparison {
    /// Validates that all serialized numeric values are finite.
    pub fn validate(&self) -> Result<(), ComparisonValidationError> {
        if !self.baseline.is_finite()
            || !self.candidate.is_finite()
            || !self.delta.is_finite()
            || self.relative_change.is_some_and(|value| !value.is_finite())
        {
            return Err(ComparisonValidationError::NonFiniteMetric {
                subject_id: self.subject.id.clone(),
                metric: self.metric,
            });
        }
        if self.baseline < 0.0 || self.candidate < 0.0 {
            return Err(ComparisonValidationError::NegativeMetric {
                subject_id: self.subject.id.clone(),
                metric: self.metric,
            });
        }
        if self.baseline == 0.0 && self.relative_change.is_some() {
            return Err(ComparisonValidationError::RelativeChangeWithZeroBaseline {
                subject_id: self.subject.id.clone(),
                metric: self.metric,
            });
        }
        Ok(())
    }
}

/// Capture-wide comparison verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonVerdict {
    /// At least one material improvement and no regression were found.
    Improved,
    /// No material regression or improvement was found.
    Unchanged,
    /// At least one material regression was found.
    Regressed,
    /// Health or metric support prevents strict comparison.
    Inconclusive,
}

/// Versioned comparison between a baseline and candidate session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ComparisonReport {
    /// The comparison schema version.
    pub schema: ComparisonSchemaVersion,
    /// Baseline session identifier.
    pub baseline_session_id: String,
    /// Candidate session identifier.
    pub candidate_session_id: String,
    /// Health verdict of the baseline input.
    pub baseline_health: HealthVerdict,
    /// Health verdict of the candidate input.
    pub candidate_health: HealthVerdict,
    /// Capture-wide comparison verdict.
    pub verdict: ComparisonVerdict,
    /// Per-subject metric comparisons.
    pub metrics: Vec<MetricComparison>,
    /// Dynamic-resource comparisons keyed by semantic identity and exact subject.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_metrics: Vec<ResourceMetricComparison>,
    /// Static-RAM total and per-kind comparisons.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub static_ram_metrics: Vec<StaticRamMetricComparison>,
    /// Capture-wide explanatory reasons.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

impl ComparisonReport {
    /// Validates health gating and every metric row.
    pub fn validate(&self) -> Result<(), ComparisonValidationError> {
        let strict = self.baseline_health.allows_strict_comparison()
            && self.candidate_health.allows_strict_comparison();
        if !strict && self.verdict != ComparisonVerdict::Inconclusive {
            return Err(ComparisonValidationError::HealthGateBypassed);
        }
        if !strict
            && (!self.metrics.is_empty()
                || !self.resource_metrics.is_empty()
                || !self.static_ram_metrics.is_empty())
        {
            return Err(ComparisonValidationError::QuantitativeHealthGateBypassed);
        }
        for metric in &self.metrics {
            metric.validate()?;
            if !strict && metric.outcome != MetricComparisonOutcome::Inconclusive {
                return Err(ComparisonValidationError::MetricHealthGateBypassed {
                    subject_id: metric.subject.id.clone(),
                    metric: metric.metric,
                });
            }
        }
        for metric in &self.resource_metrics {
            metric.validate()?;
        }
        Ok(())
    }
}

/// Compact summary embedded in a human-facing report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReportSummary {
    /// Wall-clock capture duration when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_duration_ns: Option<DurationNs>,
    /// Number of reconstructed function spans.
    pub function_span_count: u64,
    /// Number of statistical samples.
    pub sample_count: u64,
    /// Comparison verdict when the report includes a comparison artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comparison_verdict: Option<ComparisonVerdict>,
}

/// One structured report finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReportFinding {
    /// Stable machine-readable finding code.
    pub code: String,
    /// Finding severity.
    pub severity: HealthSeverity,
    /// Short finding title.
    pub title: String,
    /// Concise finding explanation.
    pub message: String,
    /// Structured values supporting the finding.
    pub evidence: Properties,
}

/// A reference from a report to a manifest artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReportArtifactLink {
    /// Referenced manifest artifact identifier.
    pub artifact_id: String,
    /// Artifact role in the report, such as `timeline`, `health`, or `hotspots`.
    pub role: String,
}

/// Versioned, human-facing analysis report metadata.
///
/// This is a non-authoritative, bounded presentation projection emitted by a
/// report surface such as the `summary` command. Stage integrity is established
/// by [`crate::AnalysisStageReceipt`] and [`crate::AnalysisSummaryDocument`];
/// large or independently versioned data remains in artifacts referenced by ID.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AnalysisReport {
    /// The report schema version.
    pub schema: ReportSchemaVersion,
    /// Session summarized by the report.
    pub session_id: String,
    /// RFC 3339 report generation timestamp.
    pub generated_at: String,
    /// Human-readable report title.
    pub title: String,
    /// Health verdict that gates interpretation of the report.
    pub health_verdict: HealthVerdict,
    /// Compact capture and analysis counts.
    pub summary: ReportSummary,
    /// Structured findings in presentation order.
    pub findings: Vec<ReportFinding>,
    /// References to the authoritative report artifacts.
    pub artifacts: Vec<ReportArtifactLink>,
}

impl AnalysisReport {
    /// Validates that this presentation-only quantitative projection passed the health gate.
    pub fn validate(&self) -> Result<(), AnalysisReportValidationError> {
        if self.health_verdict != HealthVerdict::Valid {
            return Err(AnalysisReportValidationError::NonvalidQuantitativeReport {
                verdict: self.health_verdict,
            });
        }
        if self.session_id.trim().is_empty()
            || self.generated_at.trim().is_empty()
            || self.title.trim().is_empty()
        {
            return Err(AnalysisReportValidationError::EmptyIdentity);
        }
        Ok(())
    }
}

/// A semantic invariant violation in a presentation analysis report.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AnalysisReportValidationError {
    /// The projection attempted to present quantitative values for a nonvalid capture.
    #[error(
        "an analysis report with verdict {verdict:?} cannot present quantitative summary values"
    )]
    NonvalidQuantitativeReport {
        /// Verdict that failed the report health gate.
        verdict: HealthVerdict,
    },
    /// A required report identity field is empty.
    #[error("analysis report session, generation time, and title must be nonempty")]
    EmptyIdentity,
}

/// A semantic invariant violation in a comparison report.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum ComparisonValidationError {
    /// A metric row contains NaN or infinity.
    #[error("comparison metric {metric:?} for `{subject_id}` contains a non-finite value")]
    NonFiniteMetric {
        /// Subject containing the invalid value.
        subject_id: String,
        /// Metric containing the invalid value.
        metric: ComparisonMetricKind,
    },
    /// A baseline or candidate metric is negative even though built-in metrics are nonnegative.
    #[error("comparison metric {metric:?} for `{subject_id}` contains a negative input value")]
    NegativeMetric {
        /// Subject containing the invalid value.
        subject_id: String,
        /// Metric containing the invalid value.
        metric: ComparisonMetricKind,
    },
    /// Relative change is defined despite a zero baseline.
    #[error(
        "comparison metric {metric:?} for `{subject_id}` has relative change with zero baseline"
    )]
    RelativeChangeWithZeroBaseline {
        /// Subject containing the invalid value.
        subject_id: String,
        /// Metric containing the invalid value.
        metric: ComparisonMetricKind,
    },
    /// A strict capture verdict was emitted for unhealthy inputs.
    #[error("comparison report bypasses the trace health gate")]
    HealthGateBypassed,
    /// Quantitative comparison rows were emitted for an unhealthy input.
    #[error("comparison report exposes quantitative rows through the trace health gate")]
    QuantitativeHealthGateBypassed,
    /// A conclusive metric outcome was emitted for unhealthy inputs.
    #[error("comparison metric {metric:?} for `{subject_id}` bypasses the trace health gate")]
    MetricHealthGateBypassed {
        /// Subject that bypassed the gate.
        subject_id: String,
        /// Metric that bypassed the gate.
        metric: ComparisonMetricKind,
    },
    /// A resource comparison contains a malformed subject.
    #[error("resource comparison for `{semantic}` contains an invalid subject")]
    InvalidResourceSubject {
        /// Semantic attached to the malformed subject.
        semantic: CounterSemantic,
    },
    /// A resource comparison contains empty or entirely absent diagnostic identity fields.
    #[error("resource comparison for `{semantic}` contains invalid diagnostics")]
    InvalidResourceDiagnostic {
        /// Semantic attached to the malformed diagnostics.
        semantic: CounterSemantic,
    },
    /// A dynamic-resource comparison contains a non-finite value or threshold.
    #[error("resource comparison {aggregate:?} for `{semantic}` contains a non-finite value")]
    NonFiniteResourceMetric {
        /// Resource semantic.
        semantic: CounterSemantic,
        /// Aggregate containing the invalid value.
        aggregate: ResourceComparisonAggregate,
    },
    /// Relative change is defined despite a zero resource baseline.
    #[error(
        "resource comparison {aggregate:?} for `{semantic}` has relative change with zero baseline"
    )]
    ResourceRelativeChangeWithZeroBaseline {
        /// Resource semantic.
        semantic: CounterSemantic,
        /// Aggregate containing the invalid value.
        aggregate: ResourceComparisonAggregate,
    },
    /// Direction and threshold fields do not match the row disposition.
    #[error("resource comparison {aggregate:?} for `{semantic}` has an invalid policy projection")]
    InvalidResourcePolicyProjection {
        /// Resource semantic.
        semantic: CounterSemantic,
        /// Aggregate containing the invalid projection.
        aggregate: ResourceComparisonAggregate,
    },
}
