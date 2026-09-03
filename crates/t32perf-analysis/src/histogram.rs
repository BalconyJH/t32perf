//! Analysis helpers for statistical TRACE32 PC-hit histograms.

use std::collections::BTreeMap;

use t32perf_model::{
    Heatmap, HeatmapAgainstHistogramValidationError, HeatmapCell, HeatmapCellKey,
    HeatmapProjectionKind, HeatmapQuality, HeatmapSchemaVersion, MAX_HEATMAP_CELLS, OutOfScopeHits,
    PcHitHistogram, PcHitHistogramValidationError, PcSamplingMethod, QuantitativePolicy,
    QuantitativePolicyValidationError, Sha256Digest,
};
use thiserror::Error;

/// Maximum number of sorted function address ranges accepted for one projection.
pub const MAX_FUNCTION_ADDRESS_RANGES: usize = MAX_HEATMAP_CELLS;

/// One half-open address range belonging to a function in a bound executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionAddressRange {
    /// Stable function identity from the bound executable.
    pub function_id: String,
    /// Human-readable function name.
    pub display_name: String,
    /// Inclusive address.
    pub start_address: u64,
    /// Exclusive address.
    pub end_address: u64,
}

/// Quantitative admissibility failures for a histogram.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum QuantitativeHistogramValidationError {
    /// The underlying histogram contract was invalid.
    #[error("invalid histogram: {0}")]
    Histogram(#[from] PcHitHistogramValidationError),
    /// The supplied quantitative policy was malformed.
    #[error("invalid quantitative policy: {0}")]
    Policy(#[from] QuantitativePolicyValidationError),
    /// Target power was unavailable at a capture boundary.
    #[error("target was not powered at capture {boundary}")]
    TargetNotPowered {
        /// Capture boundary that lacked target power.
        boundary: &'static str,
    },
    /// Target was not running at a capture boundary.
    #[error("target was not running at capture {boundary}")]
    TargetNotRunning {
        /// Capture boundary at which execution was not running.
        boundary: &'static str,
    },
    /// Target was halted at a capture boundary.
    #[error("target was halted at capture {boundary}")]
    TargetHalted {
        /// Capture boundary at which TRACE32 reported a halt.
        boundary: &'static str,
    },
    /// TRACE32 did not report a positive final sampling-rate snapshot.
    #[error("last_sample_rate_hz must be positive for quantitative analysis")]
    ZeroSampleRate,
    /// TRACE32 reported PC-snoop failures during the capture.
    #[error("TRACE32 reported {count} PC-snoop failures")]
    SnoopFailures {
        /// Number of failures reported by TRACE32.
        count: u64,
    },
    /// Too few in-scope PC samples were collected for the selected policy.
    #[error("in_scope_hits {actual} is below the quantitative minimum {minimum}")]
    InsufficientInScopeHits {
        /// Minimum number of samples required by the policy.
        minimum: u64,
        /// Samples observed in the capture.
        actual: u64,
    },
    /// The capture window was too short for the selected policy.
    #[error("observed_duration_ns {actual} is below the quantitative minimum {minimum}")]
    InsufficientObservedDuration {
        /// Minimum observed duration required by the policy.
        minimum: u64,
        /// Duration observed by the host.
        actual: u64,
    },
    /// Stop-and-Go retained too little target runtime for the selected policy.
    #[error(
        "StopAndGo retained runtime {actual_percent}% is below the quantitative minimum {minimum_percent}%"
    )]
    InsufficientRetainedRuntime {
        /// Minimum retained-runtime percentage required by the policy.
        minimum_percent: f64,
        /// Retained-runtime percentage reported by TRACE32.
        actual_percent: f64,
    },
}

/// Invalid function-address attribution input.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FunctionAddressRangeValidationError {
    /// There were more ranges than the bounded projection contract allows.
    #[error("function address ranges has {actual} entries; maximum is {limit}")]
    TooManyRanges {
        /// Contract limit.
        limit: usize,
        /// Supplied range count.
        actual: usize,
    },
    /// A function identifier was empty, overlong, or contained control characters.
    #[error("function range {index} has an invalid function_id")]
    InvalidFunctionId {
        /// Index of the invalid range.
        index: usize,
    },
    /// A display name was empty, overlong, or contained control characters.
    #[error("function range {index} has an invalid display_name")]
    InvalidDisplayName {
        /// Index of the invalid range.
        index: usize,
    },
    /// A range did not use a nonempty half-open interval.
    #[error("function range {index} is not a nonempty half-open interval")]
    NonHalfOpenRange {
        /// Index of the invalid range.
        index: usize,
    },
    /// Ranges were not in monotonically increasing address order.
    #[error("function range {index} starts before the preceding range")]
    UnsortedRanges {
        /// Index of the out-of-order range.
        index: usize,
    },
    /// Two function ranges overlapped, which would make attribution ambiguous.
    #[error("function range {index} overlaps the preceding range")]
    OverlappingRanges {
        /// Index of the overlapping range.
        index: usize,
    },
    /// One stable function identity was supplied with two display names.
    #[error("function_id {function_id:?} has conflicting display names")]
    ConflictingDisplayName {
        /// Stable function identity with incompatible labels.
        function_id: String,
    },
}

/// Failures while projecting a PC-hit histogram into a heatmap.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum HistogramHeatmapError {
    /// The histogram was not quantitatively admissible.
    #[error(transparent)]
    Quantitative(#[from] QuantitativeHistogramValidationError),
    /// Function attribution ranges were ambiguous or malformed.
    #[error(transparent)]
    FunctionRanges(#[from] FunctionAddressRangeValidationError),
    /// The produced heatmap did not bind to the supplied histogram.
    #[error("heatmap validation failed: {0}")]
    Heatmap(#[from] HeatmapAgainstHistogramValidationError),
    /// Adding function hits overflowed `u64`.
    #[error("function hit count overflow for {function_id:?}")]
    FunctionHitCountOverflow {
        /// Function whose aggregate could not fit in `u64`.
        function_id: String,
    },
}

/// Ensures a histogram is safe to use as a quantitative statistical estimate.
///
/// This deliberately accepts both TRACE32 RealTime and StopAndGo methods. The latter remains
/// statistical and intrusive; no duration, coverage, or timestamp is inferred here.
pub fn validate_quantitative_histogram(
    histogram: &PcHitHistogram,
) -> Result<(), QuantitativeHistogramValidationError> {
    validate_quantitative_histogram_with_policy(histogram, &QuantitativePolicy::default())
}

/// Ensures a histogram satisfies an explicit, persisted quantitative policy.
pub fn validate_quantitative_histogram_with_policy(
    histogram: &PcHitHistogram,
    policy: &QuantitativePolicy,
) -> Result<(), QuantitativeHistogramValidationError> {
    histogram.validate()?;
    policy.validate()?;
    for (boundary, state) in [
        ("before", histogram.target_state_before),
        ("after", histogram.target_state_after),
    ] {
        if !state.powered {
            return Err(QuantitativeHistogramValidationError::TargetNotPowered { boundary });
        }
        if state.halted {
            return Err(QuantitativeHistogramValidationError::TargetHalted { boundary });
        }
        if !state.running {
            return Err(QuantitativeHistogramValidationError::TargetNotRunning { boundary });
        }
    }
    if histogram.last_sample_rate_hz == 0 {
        return Err(QuantitativeHistogramValidationError::ZeroSampleRate);
    }
    if histogram.snoop_failures > policy.max_snoop_failures {
        return Err(QuantitativeHistogramValidationError::SnoopFailures {
            count: histogram.snoop_failures,
        });
    }
    if histogram.in_scope_hits < policy.min_in_scope_hits {
        return Err(
            QuantitativeHistogramValidationError::InsufficientInScopeHits {
                minimum: policy.min_in_scope_hits,
                actual: histogram.in_scope_hits,
            },
        );
    }
    if histogram.observed_duration_ns < policy.min_observed_duration_ns {
        return Err(
            QuantitativeHistogramValidationError::InsufficientObservedDuration {
                minimum: policy.min_observed_duration_ns,
                actual: histogram.observed_duration_ns,
            },
        );
    }
    if let PcSamplingMethod::StopAndGo {
        observed_retained_runtime_percent,
        ..
    } = histogram.method
        && observed_retained_runtime_percent < policy.min_stop_and_go_retained_runtime_percent
    {
        return Err(
            QuantitativeHistogramValidationError::InsufficientRetainedRuntime {
                minimum_percent: policy.min_stop_and_go_retained_runtime_percent,
                actual_percent: observed_retained_runtime_percent,
            },
        );
    }
    Ok(())
}

/// Projects every source bucket, including zero-hit buckets, into an address heatmap.
pub fn build_address_heatmap(
    histogram: &PcHitHistogram,
    histogram_sha256: Sha256Digest,
) -> Result<Heatmap, HistogramHeatmapError> {
    let policy = QuantitativePolicy::default();
    validate_quantitative_histogram_with_policy(histogram, &policy)?;
    let heatmap = Heatmap {
        schema: HeatmapSchemaVersion,
        session_id: histogram.session_id.clone(),
        histogram_sha256: histogram_sha256.clone(),
        quality: HeatmapQuality::Statistical,
        projection_kind: HeatmapProjectionKind::AddressRange,
        quantitative_policy: policy,
        denominator_hits: histogram.in_scope_hits,
        attributed_hits: histogram.in_scope_hits,
        unattributed_hits: 0,
        out_of_scope_hits: OutOfScopeHits::Unknown,
        cells: histogram
            .buckets
            .iter()
            .map(|bucket| HeatmapCell {
                key: HeatmapCellKey::AddressRange {
                    start_address: bucket.start_address,
                    end_address: bucket.end_address,
                },
                display_name: format!("{:#x}..{:#x}", bucket.start_address, bucket.end_address),
                hits: bucket.hits,
                debugger_location: histogram
                    .debugger_symbolization
                    .as_ref()
                    .and_then(|symbolization| {
                        symbolization.locations.iter().find(|location| {
                            location.bucket_start_address == bucket.start_address
                                && location.bucket_end_address == bucket.end_address
                        })
                    })
                    .cloned(),
            })
            .collect(),
    };
    heatmap.validate_against(histogram, histogram_sha256)?;
    Ok(heatmap)
}

/// Projects fully contained PC-hit buckets into functions from a verified executable.
///
/// Buckets crossing a function boundary are deliberately left unattributed. They are never
/// proportionally split because a PC-hit count does not establish an intra-bucket distribution.
pub fn build_function_heatmap(
    histogram: &PcHitHistogram,
    histogram_sha256: Sha256Digest,
    ranges: &[FunctionAddressRange],
) -> Result<Heatmap, HistogramHeatmapError> {
    let policy = QuantitativePolicy::default();
    validate_quantitative_histogram_with_policy(histogram, &policy)?;
    validate_function_ranges(ranges)?;

    let mut hits_by_function = BTreeMap::<String, u64>::new();
    let mut names_by_function = BTreeMap::<String, String>::new();
    for range in ranges {
        names_by_function
            .entry(range.function_id.clone())
            .or_insert_with(|| range.display_name.clone());
    }

    let mut range_index = 0;
    let mut unattributed_hits = 0_u64;
    for bucket in &histogram.buckets {
        while range_index < ranges.len() && ranges[range_index].end_address <= bucket.start_address
        {
            range_index += 1;
        }
        let matching_range = ranges.get(range_index).filter(|range| {
            range.start_address <= bucket.start_address && bucket.end_address <= range.end_address
        });
        if let Some(range) = matching_range {
            let function_hits = hits_by_function
                .entry(range.function_id.clone())
                .or_default();
            *function_hits = function_hits.checked_add(bucket.hits).ok_or_else(|| {
                HistogramHeatmapError::FunctionHitCountOverflow {
                    function_id: range.function_id.clone(),
                }
            })?;
        } else {
            unattributed_hits = unattributed_hits.checked_add(bucket.hits).ok_or_else(|| {
                HistogramHeatmapError::FunctionHitCountOverflow {
                    function_id: "<unattributed>".to_owned(),
                }
            })?;
        }
    }

    let mut cells: Vec<_> = hits_by_function
        .into_iter()
        .filter(|(_, hits)| *hits > 0)
        .map(|(function_id, hits)| HeatmapCell {
            display_name: names_by_function
                .remove(&function_id)
                .expect("validated range name"),
            key: HeatmapCellKey::Function { function_id },
            hits,
            debugger_location: None,
        })
        .collect();
    cells.sort_by(|left, right| {
        right
            .hits
            .cmp(&left.hits)
            .then_with(|| match (&left.key, &right.key) {
                (
                    HeatmapCellKey::Function {
                        function_id: left_id,
                    },
                    HeatmapCellKey::Function {
                        function_id: right_id,
                    },
                ) => left_id.cmp(right_id),
                _ => unreachable!("function-only heatmap cells"),
            })
    });
    let attributed_hits = histogram
        .in_scope_hits
        .checked_sub(unattributed_hits)
        .expect("all buckets are accounted for");
    let heatmap = Heatmap {
        schema: HeatmapSchemaVersion,
        session_id: histogram.session_id.clone(),
        histogram_sha256: histogram_sha256.clone(),
        quality: HeatmapQuality::Statistical,
        projection_kind: HeatmapProjectionKind::Function,
        quantitative_policy: policy,
        denominator_hits: histogram.in_scope_hits,
        attributed_hits,
        unattributed_hits,
        out_of_scope_hits: OutOfScopeHits::Unknown,
        cells,
    };
    heatmap.validate_against(histogram, histogram_sha256)?;
    Ok(heatmap)
}

fn validate_function_ranges(
    ranges: &[FunctionAddressRange],
) -> Result<(), FunctionAddressRangeValidationError> {
    if ranges.len() > MAX_FUNCTION_ADDRESS_RANGES {
        return Err(FunctionAddressRangeValidationError::TooManyRanges {
            limit: MAX_FUNCTION_ADDRESS_RANGES,
            actual: ranges.len(),
        });
    }
    let mut display_names = BTreeMap::<&str, &str>::new();
    let mut previous_end = None;
    for (index, range) in ranges.iter().enumerate() {
        if !valid_text(&range.function_id) {
            return Err(FunctionAddressRangeValidationError::InvalidFunctionId { index });
        }
        if !valid_text(&range.display_name) {
            return Err(FunctionAddressRangeValidationError::InvalidDisplayName { index });
        }
        if range.start_address >= range.end_address {
            return Err(FunctionAddressRangeValidationError::NonHalfOpenRange { index });
        }
        if let Some(end_address) = previous_end {
            if range.start_address < ranges[index - 1].start_address {
                return Err(FunctionAddressRangeValidationError::UnsortedRanges { index });
            }
            if range.start_address < end_address {
                return Err(FunctionAddressRangeValidationError::OverlappingRanges { index });
            }
        }
        previous_end = Some(range.end_address);
        if let Some(previous_name) = display_names.insert(&range.function_id, &range.display_name)
            && previous_name != range.display_name
        {
            return Err(
                FunctionAddressRangeValidationError::ConflictingDisplayName {
                    function_id: range.function_id.clone(),
                },
            );
        }
    }
    Ok(())
}

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
