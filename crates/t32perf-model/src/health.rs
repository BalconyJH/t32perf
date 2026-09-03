//! Trace-health facts, host-policy verdicts, and metric support.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{HealthSchemaVersion, Properties, TimestampNs};

/// Host-policy verdict for the trustworthiness of a capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HealthVerdict {
    /// Quantitative results and strict comparisons are permitted.
    Valid,
    /// Timeline inspection is permitted, but strict comparison is not.
    Degraded,
    /// Only diagnostic output is trustworthy.
    Invalid,
}

impl HealthVerdict {
    /// Returns whether hotspot and timing values may be presented as trustworthy.
    #[must_use]
    pub const fn allows_quantitative_results(self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Returns whether the capture may participate in strict regression comparison.
    #[must_use]
    pub const fn allows_strict_comparison(self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Returns whether a timeline may be rendered for diagnosis.
    #[must_use]
    pub const fn allows_timeline(self) -> bool {
        true
    }
}

/// Severity assigned to a host-policy issue.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum HealthSeverity {
    /// Informational evidence that does not reduce trust.
    Info,
    /// A warning that may constrain interpretation.
    Warning,
    /// A serious problem that invalidates affected quantitative conclusions.
    Error,
    /// A capture-wide failure that makes the trace unusable.
    Fatal,
}

/// A source fact consumed by the versioned host health policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HealthObservation {
    /// Stable machine-readable observation code.
    pub code: String,
    /// Adapter, parser, or analysis component that observed the fact.
    pub source: String,
    /// Related manifest artifact identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<String>,
    /// Related source record number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<u64>,
    /// Start of the affected session-relative interval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_ns: Option<TimestampNs>,
    /// End of the affected session-relative interval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_ns: Option<TimestampNs>,
    /// Structured source evidence used by host policy.
    pub evidence: Properties,
}

/// A diagnosed health issue produced by host policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HealthIssue {
    /// Stable machine-readable issue code.
    pub code: String,
    /// Policy-assigned issue severity.
    pub severity: HealthSeverity,
    /// Component or source observation responsible for the issue.
    pub source: String,
    /// Related manifest artifact identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<String>,
    /// Related source record number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<u64>,
    /// Start of the affected session-relative interval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_ns: Option<TimestampNs>,
    /// End of the affected session-relative interval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_ns: Option<TimestampNs>,
    /// Structured evidence retained for diagnosis and audit.
    pub evidence: Properties,
    /// Concise human-readable diagnosis.
    pub message: String,
}

/// The support level for one analysis metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MetricSupportLevel {
    /// The capture directly supports exact computation.
    Exact,
    /// The metric can be deterministically inferred with documented caveats.
    Inferred,
    /// Only a statistical estimate is available.
    Statistical,
    /// The capture cannot support this metric.
    Unavailable,
}

/// Support and explanatory reasons for one metric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MetricSupportEntry {
    /// Available support level.
    pub support: MetricSupportLevel,
    /// Stable or human-readable reasons for the declared level.
    pub reasons: Vec<String>,
}

impl MetricSupportEntry {
    /// Creates a metric support entry without explanatory reasons.
    #[must_use]
    pub const fn new(support: MetricSupportLevel) -> Self {
        Self {
            support,
            reasons: Vec::new(),
        }
    }

    /// Creates an unavailable support entry with one explanatory reason.
    #[must_use]
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            support: MetricSupportLevel::Unavailable,
            reasons: vec![reason.into()],
        }
    }

    /// Returns whether the metric can be emitted at any quality level.
    #[must_use]
    pub const fn is_available(&self) -> bool {
        !matches!(self.support, MetricSupportLevel::Unavailable)
    }
}

/// Support matrix covering all required timeline and timing metrics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MetricSupport {
    /// Support for reconstructed function timeline slices.
    pub function_timeline: MetricSupportEntry,
    /// Support for exact or estimated function call counts.
    pub call_count: MetricSupportEntry,
    /// Support for wall-clock elapsed function duration.
    pub elapsed: MetricSupportEntry,
    /// Support for active function duration excluding preemption.
    pub active: MetricSupportEntry,
    /// Support for self active function duration excluding children.
    #[serde(rename = "self")]
    pub self_time: MetricSupportEntry,
    /// Support for the task execution timeline.
    pub task_timeline: MetricSupportEntry,
    /// Support for the interrupt execution timeline.
    pub isr_timeline: MetricSupportEntry,
    /// Support for explicitly defined numeric resource counters.
    #[serde(default = "resource_counter_support_not_recorded")]
    pub resource_counters: MetricSupportEntry,
}

impl MetricSupport {
    /// Creates a support matrix with the same level for every metric.
    #[must_use]
    pub fn uniform(level: MetricSupportLevel) -> Self {
        let entry = MetricSupportEntry::new(level);
        Self {
            function_timeline: entry.clone(),
            call_count: entry.clone(),
            elapsed: entry.clone(),
            active: entry.clone(),
            self_time: entry.clone(),
            task_timeline: entry.clone(),
            isr_timeline: entry.clone(),
            resource_counters: entry,
        }
    }
}

fn resource_counter_support_not_recorded() -> MetricSupportEntry {
    MetricSupportEntry::unavailable("resource_counter_support_not_recorded")
}

/// Versioned host-policy health report for one session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HealthReport {
    /// The health schema version.
    pub schema: HealthSchemaVersion,
    /// Session evaluated by the policy.
    pub session_id: String,
    /// Capture-wide policy verdict.
    pub verdict: HealthVerdict,
    /// Version of the host policy that derived issues and verdict.
    pub policy_version: String,
    /// Raw facts supplied to host policy.
    pub observations: Vec<HealthObservation>,
    /// Diagnosed policy issues.
    pub issues: Vec<HealthIssue>,
    /// Metric-specific support determined by the same policy evaluation.
    pub metric_support: MetricSupport,
}

impl HealthReport {
    /// Validates health interval and metric-support invariants.
    pub fn validate(&self) -> Result<(), HealthValidationError> {
        validate_required("session_id", &self.session_id)?;
        validate_required("policy_version", &self.policy_version)?;
        for (index, observation) in self.observations.iter().enumerate() {
            validate_required(&format!("observations[{index}].code"), &observation.code)?;
            validate_required(
                &format!("observations[{index}].source"),
                &observation.source,
            )?;
            validate_optional(
                &format!("observations[{index}].artifact_id"),
                observation.artifact_id.as_deref(),
            )?;
            validate_interval(&observation.code, observation.start_ns, observation.end_ns)?;
        }
        for (index, issue) in self.issues.iter().enumerate() {
            validate_required(&format!("issues[{index}].code"), &issue.code)?;
            validate_required(&format!("issues[{index}].source"), &issue.source)?;
            validate_required(&format!("issues[{index}].message"), &issue.message)?;
            validate_optional(
                &format!("issues[{index}].artifact_id"),
                issue.artifact_id.as_deref(),
            )?;
            validate_interval(&issue.code, issue.start_ns, issue.end_ns)?;
        }
        if let Some(severity) = self.issues.iter().map(|issue| issue.severity).max()
            && !verdict_covers(self.verdict, severity)
        {
            return Err(HealthValidationError::VerdictUnderstatesSeverity {
                verdict: self.verdict,
                severity,
            });
        }
        for (metric, entry) in [
            ("function_timeline", &self.metric_support.function_timeline),
            ("call_count", &self.metric_support.call_count),
            ("elapsed", &self.metric_support.elapsed),
            ("active", &self.metric_support.active),
            ("self", &self.metric_support.self_time),
            ("task_timeline", &self.metric_support.task_timeline),
            ("isr_timeline", &self.metric_support.isr_timeline),
            ("resource_counters", &self.metric_support.resource_counters),
        ] {
            validate_support(metric, entry)?;
        }
        Ok(())
    }
}

fn validate_required(field: &str, value: &str) -> Result<(), HealthValidationError> {
    if value.trim().is_empty() {
        return Err(HealthValidationError::EmptyField {
            field: field.to_owned(),
        });
    }
    Ok(())
}

fn validate_optional(field: &str, value: Option<&str>) -> Result<(), HealthValidationError> {
    if let Some(value) = value {
        validate_required(field, value)?;
    }
    Ok(())
}

fn verdict_covers(verdict: HealthVerdict, severity: HealthSeverity) -> bool {
    match verdict {
        HealthVerdict::Valid => severity == HealthSeverity::Info,
        HealthVerdict::Degraded => severity <= HealthSeverity::Warning,
        HealthVerdict::Invalid => true,
    }
}

fn validate_support(metric: &str, entry: &MetricSupportEntry) -> Result<(), HealthValidationError> {
    if entry.support != MetricSupportLevel::Exact && entry.reasons.is_empty() {
        return if entry.support == MetricSupportLevel::Unavailable {
            Err(HealthValidationError::UnavailableWithoutReason {
                metric: metric.to_owned(),
            })
        } else {
            Err(HealthValidationError::NonExactWithoutReason {
                metric: metric.to_owned(),
                support: entry.support,
            })
        };
    }
    let mut reasons = BTreeSet::new();
    for reason in &entry.reasons {
        if reason.trim().is_empty() {
            return Err(HealthValidationError::EmptySupportReason {
                metric: metric.to_owned(),
            });
        }
        if !reasons.insert(reason) {
            return Err(HealthValidationError::DuplicateSupportReason {
                metric: metric.to_owned(),
                reason: reason.clone(),
            });
        }
    }
    Ok(())
}

fn validate_interval(
    code: &str,
    start_ns: Option<TimestampNs>,
    end_ns: Option<TimestampNs>,
) -> Result<(), HealthValidationError> {
    if let (Some(start_ns), Some(end_ns)) = (start_ns, end_ns)
        && end_ns < start_ns
    {
        return Err(HealthValidationError::InvalidInterval {
            code: code.to_owned(),
            start_ns,
            end_ns,
        });
    }
    Ok(())
}

/// A semantic invariant violation in a health report.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HealthValidationError {
    /// A required identity or diagnostic field is empty.
    #[error("health field `{field}` is empty")]
    EmptyField {
        /// Empty field path.
        field: String,
    },
    /// An affected interval ends before it begins.
    #[error("health record `{code}` has invalid interval {start_ns}..{end_ns}")]
    InvalidInterval {
        /// Observation or issue code.
        code: String,
        /// Declared interval start.
        start_ns: TimestampNs,
        /// Declared interval end.
        end_ns: TimestampNs,
    },
    /// An unavailable metric does not explain why it is unavailable.
    #[error("unavailable metric `{metric}` has no reason")]
    UnavailableWithoutReason {
        /// Metric field with missing reasons.
        metric: String,
    },
    /// An inferred or statistical metric does not explain its lower support.
    #[error("{support:?} metric `{metric}` has no reason")]
    NonExactWithoutReason {
        /// Metric field with missing reasons.
        metric: String,
        /// Declared non-exact support level.
        support: MetricSupportLevel,
    },
    /// A metric-support reason is empty.
    #[error("metric `{metric}` contains an empty support reason")]
    EmptySupportReason {
        /// Metric containing the invalid reason.
        metric: String,
    },
    /// A metric-support reason is duplicated.
    #[error("metric `{metric}` repeats support reason `{reason}`")]
    DuplicateSupportReason {
        /// Metric containing the duplicate.
        metric: String,
        /// Duplicated reason.
        reason: String,
    },
    /// The capture-wide verdict is less severe than a reported issue.
    #[error("health verdict {verdict:?} understates issue severity {severity:?}")]
    VerdictUnderstatesSeverity {
        /// Declared capture-wide verdict.
        verdict: HealthVerdict,
        /// Highest issue severity requiring a stricter verdict.
        severity: HealthSeverity,
    },
}
