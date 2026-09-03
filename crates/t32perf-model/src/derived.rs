//! Host-derived spans and hotspot aggregates.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::DerivedStreamSchemaVersion;
use crate::{DerivedSchemaVersion, DurationNs, HotspotsSchemaVersion, Quality, TimestampNs};

/// Physical encoding of a streaming derived-span artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DerivedStreamEncoding {
    /// One header JSON object followed by one [`FunctionSpan`] object per line.
    Ndjson,
}

/// Header written as the first record of a streaming derived-span artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DerivedStreamHeader {
    /// The derived-stream schema version.
    pub schema: DerivedStreamSchemaVersion,
    /// The Session from which spans were derived.
    pub session_id: String,
    /// The physical stream encoding.
    pub encoding: DerivedStreamEncoding,
    /// Manifest artifact identifiers consumed by analysis.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input_artifact_ids: Vec<String>,
}

impl DerivedStreamHeader {
    /// Creates an NDJSON header for one Session.
    #[must_use]
    pub fn ndjson(session_id: impl Into<String>) -> Self {
        Self {
            schema: DerivedStreamSchemaVersion,
            session_id: session_id.into(),
            encoding: DerivedStreamEncoding::Ndjson,
            input_artifact_ids: Vec::new(),
        }
    }
}

/// Derived host-side event data for one session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DerivedDocument {
    /// The derived-data schema version.
    pub schema: DerivedSchemaVersion,
    /// The session from which this data was derived.
    pub session_id: String,
    /// Manifest artifact identifiers used as analysis inputs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input_artifact_ids: Vec<String>,
    /// Reconstructed function activations.
    pub function_spans: Vec<FunctionSpan>,
}

impl DerivedDocument {
    /// Creates an empty derived-data document.
    #[must_use]
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            schema: DerivedSchemaVersion,
            session_id: session_id.into(),
            input_artifact_ids: Vec::new(),
            function_spans: Vec::new(),
        }
    }

    /// Validates every derived span.
    pub fn validate(&self) -> Result<(), DerivedValidationError> {
        for span in &self.function_spans {
            span.validate()?;
        }
        Ok(())
    }
}

/// A reconstructed function activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FunctionSpan {
    /// Source stream that supplied the activation evidence.
    pub source_id: String,
    /// First source sequence contributing to the span.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_seq_start: Option<u64>,
    /// Last source sequence contributing to the span.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_seq_end: Option<u64>,
    /// Core on which the activation ran.
    pub core_id: u32,
    /// Execution context to which the activation belongs.
    pub context_id: String,
    /// Function dictionary identifier.
    pub function_id: String,
    /// Adapter-provided activation identifier when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_id: Option<String>,
    /// Session-relative start timestamp.
    pub start_ns: TimestampNs,
    /// Session-relative end timestamp.
    pub end_ns: TimestampNs,
    /// Wall-clock time from start to end.
    pub elapsed_ns: DurationNs,
    /// Time for which this activation was executing, including active children.
    pub active_ns: DurationNs,
    /// Active time excluding active child function spans.
    pub self_active_ns: DurationNs,
    /// Time for which this activation was preempted or descheduled.
    pub preempted_ns: DurationNs,
    /// Evidence quality of the reconstructed span.
    pub quality: Quality,
    /// Whether one or both span boundaries required incomplete-trace recovery.
    pub incomplete: bool,
}

impl FunctionSpan {
    /// Validates duration decomposition and timestamp bounds.
    pub fn validate(&self) -> Result<(), DerivedValidationError> {
        if let (Some(start), Some(end)) = (self.source_seq_start, self.source_seq_end)
            && end < start
        {
            return Err(DerivedValidationError::InvalidSourceSequenceRange {
                function_id: self.function_id.clone(),
                start,
                end,
            });
        }

        let bounded_elapsed = u64::try_from(self.end_ns as i128 - self.start_ns as i128)
            .ok()
            .ok_or_else(|| DerivedValidationError::InvalidBounds {
                function_id: self.function_id.clone(),
                start_ns: self.start_ns,
                end_ns: self.end_ns,
            })?;

        if self.elapsed_ns != bounded_elapsed {
            return Err(DerivedValidationError::ElapsedMismatch {
                function_id: self.function_id.clone(),
                expected_ns: bounded_elapsed,
                actual_ns: self.elapsed_ns,
            });
        }

        let decomposed = self
            .active_ns
            .checked_add(self.preempted_ns)
            .ok_or_else(|| DerivedValidationError::DurationOverflow {
                function_id: self.function_id.clone(),
            })?;
        if decomposed > self.elapsed_ns {
            return Err(DerivedValidationError::AttributedTimeExceedsElapsed {
                function_id: self.function_id.clone(),
                elapsed_ns: self.elapsed_ns,
                active_ns: self.active_ns,
                preempted_ns: self.preempted_ns,
            });
        }
        if self.quality == Quality::Exact && !self.incomplete && decomposed != self.elapsed_ns {
            return Err(DerivedValidationError::ExactTimeMismatch {
                function_id: self.function_id.clone(),
                elapsed_ns: self.elapsed_ns,
                active_ns: self.active_ns,
                preempted_ns: self.preempted_ns,
            });
        }
        if self.self_active_ns > self.active_ns {
            return Err(DerivedValidationError::SelfTimeExceedsActive {
                function_id: self.function_id.clone(),
                self_active_ns: self.self_active_ns,
                active_ns: self.active_ns,
            });
        }
        Ok(())
    }
}

/// A hotspot report containing deterministic and sampling-derived sections.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HotspotReport {
    /// The hotspot schema version.
    pub schema: HotspotsSchemaVersion,
    /// Session that was analyzed.
    pub session_id: String,
    /// Overall evidence quality of the report.
    pub quality: Quality,
    /// Exact or inferred function-span aggregates.
    pub functions: Vec<FunctionHotspot>,
    /// Statistical sampling aggregates, kept separate from span aggregates.
    pub sampling: Vec<SamplingHotspot>,
}

impl HotspotReport {
    /// Creates an empty hotspot report.
    #[must_use]
    pub fn new(session_id: impl Into<String>, quality: Quality) -> Self {
        Self {
            schema: HotspotsSchemaVersion,
            session_id: session_id.into(),
            quality,
            functions: Vec::new(),
            sampling: Vec::new(),
        }
    }

    /// Validates every aggregate in the report.
    pub fn validate(&self) -> Result<(), HotspotValidationError> {
        for hotspot in &self.functions {
            hotspot.validate()?;
        }
        for hotspot in &self.sampling {
            hotspot.validate()?;
        }
        Ok(())
    }
}

/// Aggregated active-time metrics for a function and optional context.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FunctionHotspot {
    /// Function dictionary identifier.
    pub function_id: String,
    /// Context dictionary identifier when the report is context-partitioned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Inclusive active time across all activations.
    pub inclusive_active_ns: DurationNs,
    /// Self active time across all activations.
    pub self_active_ns: DurationNs,
    /// Number of activations.
    pub count: u64,
    /// Minimum active duration of one activation.
    pub min_active_ns: DurationNs,
    /// Maximum active duration of one activation.
    pub max_active_ns: DurationNs,
    /// Integer arithmetic mean active duration of one activation.
    pub avg_active_ns: DurationNs,
    /// Number of activations reconstructed from incomplete boundaries.
    pub incomplete_count: u64,
    /// Evidence quality of this aggregate.
    pub quality: Quality,
}

impl FunctionHotspot {
    /// Validates aggregate counts, bounds, and finite average values.
    pub fn validate(&self) -> Result<(), HotspotValidationError> {
        if self.count == 0 {
            return Err(HotspotValidationError::EmptyFunctionAggregate {
                function_id: self.function_id.clone(),
            });
        }
        if self.incomplete_count > self.count {
            return Err(HotspotValidationError::IncompleteCountExceedsCount {
                function_id: self.function_id.clone(),
                incomplete_count: self.incomplete_count,
                count: self.count,
            });
        }
        if self.self_active_ns > self.inclusive_active_ns {
            return Err(HotspotValidationError::SelfTimeExceedsInclusive {
                function_id: self.function_id.clone(),
                self_active_ns: self.self_active_ns,
                inclusive_active_ns: self.inclusive_active_ns,
            });
        }
        if self.min_active_ns > self.max_active_ns
            || self.avg_active_ns < self.min_active_ns
            || self.avg_active_ns > self.max_active_ns
        {
            return Err(HotspotValidationError::InvalidActiveBounds {
                function_id: self.function_id.clone(),
                min_active_ns: self.min_active_ns,
                max_active_ns: self.max_active_ns,
            });
        }
        let expected_avg_active_ns = self.inclusive_active_ns / self.count;
        if self.avg_active_ns != expected_avg_active_ns {
            return Err(HotspotValidationError::AverageMismatch {
                function_id: self.function_id.clone(),
                expected_avg_active_ns,
                actual_avg_active_ns: self.avg_active_ns,
            });
        }
        Ok(())
    }
}

/// Statistical hotspot data obtained from program-counter samples.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SamplingHotspot {
    /// Resolved function identifier when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_id: Option<String>,
    /// Raw sampled address when no function resolution is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<u64>,
    /// Context identifier when the report is context-partitioned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Number of samples attributed to this row.
    pub sample_count: u64,
    /// Estimated fraction of represented samples in the inclusive range 0 to 1.
    #[schemars(range(min = 0.0, max = 1.0))]
    pub estimated_share: f64,
    /// Evidence quality, normally [`Quality::Statistical`].
    pub quality: Quality,
}

impl SamplingHotspot {
    /// Validates identity and estimated-share bounds.
    pub fn validate(&self) -> Result<(), HotspotValidationError> {
        if self.function_id.is_none() && self.address.is_none() {
            return Err(HotspotValidationError::MissingSamplingIdentity);
        }
        if !self.estimated_share.is_finite() || !(0.0..=1.0).contains(&self.estimated_share) {
            return Err(HotspotValidationError::InvalidEstimatedShare {
                estimated_share: self.estimated_share,
            });
        }
        Ok(())
    }
}

/// A semantic invariant violation in derived function-span data.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DerivedValidationError {
    /// Source sequence provenance ends before it begins.
    #[error("function `{function_id}` has invalid source sequence range {start}..{end}")]
    InvalidSourceSequenceRange {
        /// Function containing the invalid span.
        function_id: String,
        /// First contributing source sequence.
        start: u64,
        /// Last contributing source sequence.
        end: u64,
    },
    /// End precedes start or the bound difference cannot be represented.
    #[error("function `{function_id}` has invalid bounds {start_ns}..{end_ns}")]
    InvalidBounds {
        /// Function containing the invalid span.
        function_id: String,
        /// Declared start timestamp.
        start_ns: TimestampNs,
        /// Declared end timestamp.
        end_ns: TimestampNs,
    },
    /// The declared elapsed duration differs from timestamp bounds.
    #[error(
        "function `{function_id}` elapsed duration is {actual_ns} ns, expected {expected_ns} ns"
    )]
    ElapsedMismatch {
        /// Function containing the invalid span.
        function_id: String,
        /// Duration implied by timestamp bounds.
        expected_ns: DurationNs,
        /// Declared elapsed duration.
        actual_ns: DurationNs,
    },
    /// Adding active and preempted time overflowed a duration.
    #[error("function `{function_id}` duration decomposition overflows u64")]
    DurationOverflow {
        /// Function containing the invalid span.
        function_id: String,
    },
    /// Active and preempted time exceed elapsed time.
    #[error(
        "function `{function_id}` active {active_ns} ns plus preempted {preempted_ns} ns exceeds elapsed {elapsed_ns} ns"
    )]
    AttributedTimeExceedsElapsed {
        /// Function containing the invalid span.
        function_id: String,
        /// Declared elapsed duration.
        elapsed_ns: DurationNs,
        /// Declared active duration.
        active_ns: DurationNs,
        /// Declared preempted duration.
        preempted_ns: DurationNs,
    },
    /// A complete exact span has unattributed elapsed time.
    #[error(
        "exact function `{function_id}` elapsed {elapsed_ns} ns does not equal active {active_ns} ns plus preempted {preempted_ns} ns"
    )]
    ExactTimeMismatch {
        /// Function containing the invalid span.
        function_id: String,
        /// Declared elapsed duration.
        elapsed_ns: DurationNs,
        /// Declared active duration.
        active_ns: DurationNs,
        /// Declared preempted duration.
        preempted_ns: DurationNs,
    },
    /// Self active time exceeds inclusive active time.
    #[error(
        "function `{function_id}` self active {self_active_ns} ns exceeds active {active_ns} ns"
    )]
    SelfTimeExceedsActive {
        /// Function containing the invalid span.
        function_id: String,
        /// Declared self active duration.
        self_active_ns: DurationNs,
        /// Declared inclusive active duration.
        active_ns: DurationNs,
    },
}

/// A semantic invariant violation in a hotspot report.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum HotspotValidationError {
    /// A function aggregate has no activations.
    #[error("function hotspot `{function_id}` has a zero count")]
    EmptyFunctionAggregate {
        /// Function containing the invalid aggregate.
        function_id: String,
    },
    /// More incomplete activations were reported than total activations.
    #[error(
        "function hotspot `{function_id}` has {incomplete_count} incomplete spans but only {count} spans"
    )]
    IncompleteCountExceedsCount {
        /// Function containing the invalid aggregate.
        function_id: String,
        /// Number of incomplete activations.
        incomplete_count: u64,
        /// Total activation count.
        count: u64,
    },
    /// Self active time exceeds inclusive active time.
    #[error(
        "function hotspot `{function_id}` self active {self_active_ns} ns exceeds inclusive active {inclusive_active_ns} ns"
    )]
    SelfTimeExceedsInclusive {
        /// Function containing the invalid aggregate.
        function_id: String,
        /// Self active time.
        self_active_ns: DurationNs,
        /// Inclusive active time.
        inclusive_active_ns: DurationNs,
    },
    /// Minimum, maximum, or average active time is inconsistent.
    #[error(
        "function hotspot `{function_id}` has invalid active bounds {min_active_ns}..{max_active_ns}"
    )]
    InvalidActiveBounds {
        /// Function containing the invalid aggregate.
        function_id: String,
        /// Minimum active time.
        min_active_ns: DurationNs,
        /// Maximum active time.
        max_active_ns: DurationNs,
    },
    /// The declared average is not the integer arithmetic mean of inclusive time.
    #[error(
        "function hotspot `{function_id}` average is {actual_avg_active_ns} ns, expected {expected_avg_active_ns} ns"
    )]
    AverageMismatch {
        /// Function containing the invalid aggregate.
        function_id: String,
        /// Integer arithmetic mean implied by inclusive time and count.
        expected_avg_active_ns: DurationNs,
        /// Declared average active time.
        actual_avg_active_ns: DurationNs,
    },
    /// A sampling row has neither a function nor an address.
    #[error("sampling hotspot has neither function_id nor address")]
    MissingSamplingIdentity,
    /// Estimated share is not finite or lies outside 0 to 1.
    #[error("sampling hotspot has invalid estimated share {estimated_share}")]
    InvalidEstimatedShare {
        /// Rejected estimated share.
        estimated_share: f64,
    },
}
