//! Statistical PC-hit histograms and coarse heatmap contracts.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    DurationNs, EndpointFingerprintScheme, FirmwareBindingEvidenceSchemaVersion,
    HeatmapSchemaVersion, PcHitHistogramSchemaVersion, Sha256Digest, is_portable_session_id,
};

/// Maximum number of disjoint address buckets in one PC-hit histogram.
pub const MAX_PC_HIT_BUCKETS: usize = 16_384;
/// Maximum number of rendered cells in one coarse heatmap.
pub const MAX_HEATMAP_CELLS: usize = 16_384;

/// The TRACE32 sampling method that produced a histogram.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PcSamplingMethod {
    /// Runtime PC snooping without stopping the target.
    Realtime,
    /// Periodically stopping and restarting the target to read its PC.
    StopAndGo {
        /// Retained runtime percentage configured before sampling started.
        #[schemars(range(min = 0.0, max = 100.0))]
        configured_retained_runtime_percent: f64,
        /// Retained runtime percentage observed after sampling stopped.
        #[schemars(range(min = 0.0, max = 100.0))]
        observed_retained_runtime_percent: f64,
    },
}

/// A target execution-state observation taken at a capture boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetExecutionState {
    /// Whether TRACE32 reported target power as available.
    pub powered: bool,
    /// Whether TRACE32 reported that the target was running.
    pub running: bool,
    /// Whether TRACE32 reported that the target was halted.
    pub halted: bool,
}

impl TargetExecutionState {
    fn validate(self, boundary: &'static str) -> Result<(), PcHitHistogramValidationError> {
        if self.running && self.halted {
            return Err(PcHitHistogramValidationError::InconsistentTargetState { boundary });
        }
        if !self.powered && (self.running || self.halted) {
            return Err(PcHitHistogramValidationError::UnpoweredTargetState { boundary });
        }
        Ok(())
    }
}

/// The confidence of the firmware identity bound to a capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FirmwareBindingStatus {
    /// The loaded executable and capture target were verified to match.
    Verified,
    /// An immutable capture request asserted the deployed executable, but the target image was
    /// not compared.
    DeploymentAsserted,
    /// No target-side identity proof was available.
    Unverified,
    /// Target-side identity proof disagreed with the executable.
    Mismatch,
}

/// Firmware identity evidence recorded with a histogram.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FirmwareBinding {
    /// Confidence/status of the executable association.
    pub status: FirmwareBindingStatus,
    /// Digest of the executable used for address and symbol attribution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elf_sha256: Option<Sha256Digest>,
    /// Evidence proving how the firmware binding was established.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<FirmwareBindingProof>,
}

/// Evidence type used to establish a firmware binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FirmwareBindingProof {
    /// A deployment artifact bound the executable digest to the target image.
    DigestBoundDeployment {
        /// SHA-256 digest of the immutable deployment evidence artifact.
        evidence_artifact_sha256: Sha256Digest,
    },
    /// An immutable capture request asserted the deployed executable digest without comparing
    /// the target image.
    PrecommittedElfAssertion {
        /// SHA-256 digest of the immutable assertion evidence artifact.
        evidence_artifact_sha256: Sha256Digest,
    },
    /// A target-image comparison established or rejected the binding.
    TargetImageComparison {
        /// SHA-256 digest of the immutable target-comparison evidence artifact.
        evidence_artifact_sha256: Sha256Digest,
    },
}

/// The evidence mechanism used to associate an executable with a capture target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FirmwareBindingProofKind {
    /// A deployment record bound the executable digest to the target image.
    DigestBoundDeployment,
    /// An immutable capture request asserted the deployed executable digest without comparing
    /// the target image.
    PrecommittedElfAssertion,
    /// A target-image comparison established or rejected the binding.
    TargetImageComparison,
}

/// The outcome recorded by firmware-binding evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FirmwareBindingEvidenceResult {
    /// The target image matched the executable.
    Verified,
    /// An immutable capture request asserted the executable digest without comparing the target
    /// image.
    Asserted,
    /// The target image did not match the executable.
    Mismatch,
}

/// Immutable artifact whose bytes are referenced by [`FirmwareBindingProof`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FirmwareBindingEvidence {
    /// The firmware-binding evidence schema version.
    pub schema: FirmwareBindingEvidenceSchemaVersion,
    /// Portable capture session identifier.
    #[schemars(length(min = 1, max = 64))]
    pub session_id: String,
    /// SHA-256 fingerprint for the exclusively leased TRACE32 endpoint.
    pub endpoint_fingerprint: Sha256Digest,
    /// Fixed algorithm used for [`Self::endpoint_fingerprint`].
    pub endpoint_fingerprint_scheme: EndpointFingerprintScheme,
    /// Digest of the executable named by this evidence.
    pub elf_sha256: Sha256Digest,
    /// Evidence mechanism used for the binding.
    pub proof_kind: FirmwareBindingProofKind,
    /// Binding result established by the artifact.
    pub result: FirmwareBindingEvidenceResult,
}

impl FirmwareBindingEvidence {
    /// Validates portable identity and proof/result compatibility.
    pub fn validate(&self) -> Result<(), FirmwareBindingEvidenceValidationError> {
        if !is_portable_session_id(&self.session_id) {
            return Err(FirmwareBindingEvidenceValidationError::InvalidSessionId);
        }
        match (self.proof_kind, self.result) {
            (
                FirmwareBindingProofKind::PrecommittedElfAssertion,
                FirmwareBindingEvidenceResult::Asserted,
            )
            | (
                FirmwareBindingProofKind::DigestBoundDeployment,
                FirmwareBindingEvidenceResult::Verified,
            )
            | (
                FirmwareBindingProofKind::TargetImageComparison,
                FirmwareBindingEvidenceResult::Verified | FirmwareBindingEvidenceResult::Mismatch,
            ) => Ok(()),
            (_, FirmwareBindingEvidenceResult::Asserted) => {
                Err(FirmwareBindingEvidenceValidationError::AssertedRequiresPrecommittedAssertion)
            }
            (
                FirmwareBindingProofKind::PrecommittedElfAssertion,
                FirmwareBindingEvidenceResult::Verified,
            ) => Err(FirmwareBindingEvidenceValidationError::VerifiedRejectsPrecommittedAssertion),
            (_, FirmwareBindingEvidenceResult::Mismatch) => {
                Err(FirmwareBindingEvidenceValidationError::MismatchRequiresTargetComparison)
            }
        }
    }
}

/// One half-open address interval and its PC-hit count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PcHitBucket {
    /// Inclusive start address.
    pub start_address: u64,
    /// Exclusive end address.
    pub end_address: u64,
    /// Samples whose PC lies in this interval.
    pub hits: u64,
}

/// The fixed origin of optional runtime code labels reported by TRACE32.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DebuggerSymbolizationSource {
    /// TRACE32 resolved the observed address through its currently loaded symbol table.
    Trace32SymbolTable,
}

/// The fixed trust boundary for optional runtime code labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DebuggerSymbolizationTrust {
    /// The label is reported by TRACE32 and does not prove firmware identity.
    DebuggerReported,
}

/// One optional TRACE32 symbol-table label for a sampled histogram bucket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebuggerHotspotLocation {
    /// Inclusive start address of the parent sampled bucket.
    pub bucket_start_address: u64,
    /// Exclusive end address of the parent sampled bucket.
    pub bucket_end_address: u64,
    /// Exact hit count of the parent sampled bucket.
    pub hits: u64,
    /// Inclusive start of the refined dominant PC interval.
    pub dominant_start_address: u64,
    /// Exclusive end of the refined dominant PC interval.
    pub dominant_end_address: u64,
    /// Hits observed in the refined dominant PC interval.
    pub dominant_hits: u64,
    /// Optional function name reported by TRACE32.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_name: Option<String>,
    /// Optional source-file basename reported by TRACE32.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,
    /// Optional one-based source line reported by TRACE32.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_line: Option<u32>,
}

/// Optional, bounded runtime code labels obtained from TRACE32 during capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebuggerSymbolization {
    /// Symbol source; fixed to TRACE32's loaded symbol table.
    pub source: DebuggerSymbolizationSource,
    /// Trust boundary; labels do not upgrade firmware binding confidence.
    pub trust: DebuggerSymbolizationTrust,
    /// Width in bytes used for the dominant-address refinement.
    pub refinement_granularity_bytes: u64,
    /// At most ten sorted locations for the hottest sampled buckets.
    #[schemars(length(max = 10))]
    pub locations: Vec<DebuggerHotspotLocation>,
}

/// A bounded PC-hit histogram obtained from TRACE32 PERF sampling.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PcHitHistogram {
    /// The PC-hit histogram schema version.
    pub schema: PcHitHistogramSchemaVersion,
    /// Portable capture session identifier.
    #[schemars(length(min = 1, max = 64))]
    pub session_id: String,
    /// SHA-256 fingerprint for the exclusively leased TRACE32 endpoint.
    pub endpoint_fingerprint: Sha256Digest,
    /// Fixed algorithm used for [`Self::endpoint_fingerprint`].
    pub endpoint_fingerprint_scheme: EndpointFingerprintScheme,
    /// TRACE32 software/build identity observed during capture.
    #[schemars(length(min = 1, max = 256))]
    pub trace32: String,
    /// CPU identity reported by TRACE32.
    #[schemars(length(min = 1, max = 256))]
    pub cpu: String,
    /// Address-space identity used for every bucket.
    #[schemars(length(min = 1, max = 256))]
    pub address_space: String,
    /// Core that supplied the sampled program counters.
    pub core_id: u32,
    /// Sampling method actually reported by TRACE32.
    pub method: PcSamplingMethod,
    /// Whether sampling disturbed target execution.
    pub intrusive: bool,
    /// Requested capture duration measured on the host.
    #[schemars(range(min = 1))]
    pub requested_duration_ns: DurationNs,
    /// Observed host duration from arming PERF to stopping it.
    #[schemars(range(min = 1))]
    pub observed_duration_ns: DurationNs,
    /// Last observed sampling-rate snapshot in hertz; this is not an average.
    pub last_sample_rate_hz: u64,
    /// TRACE32 PC-snoop failures observed during this capture.
    pub snoop_failures: u64,
    /// Target state immediately before configuring PERF.
    pub target_state_before: TargetExecutionState,
    /// Target state immediately after stopping PERF.
    pub target_state_after: TargetExecutionState,
    /// Firmware identity evidence for symbol attribution.
    pub firmware: FirmwareBinding,
    /// Whether cleanup completed before the successful histogram was emitted.
    pub cleanup_complete: bool,
    /// Total hits within the declared address scope.
    pub in_scope_hits: u64,
    /// Sorted, pairwise disjoint half-open address buckets.
    #[schemars(length(min = 1, max = 16_384))]
    pub buckets: Vec<PcHitBucket>,
    /// Optional code labels reported by TRACE32's loaded symbol table.
    ///
    /// These labels are debugger-reported only and never upgrade [`Self::firmware`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debugger_symbolization: Option<DebuggerSymbolization>,
}

impl PcHitHistogram {
    /// Validates capture provenance and exact histogram accounting.
    pub fn validate(&self) -> Result<(), PcHitHistogramValidationError> {
        if !is_portable_session_id(&self.session_id) {
            return Err(PcHitHistogramValidationError::InvalidSessionId);
        }
        for (field, value) in [
            ("trace32", self.trace32.as_str()),
            ("cpu", self.cpu.as_str()),
            ("address_space", self.address_space.as_str()),
        ] {
            validate_text(field, value)?;
        }
        if self.intrusive != matches!(self.method, PcSamplingMethod::StopAndGo { .. }) {
            return Err(PcHitHistogramValidationError::IntrusiveMethodMismatch);
        }
        if self.requested_duration_ns == 0 || self.observed_duration_ns == 0 {
            return Err(PcHitHistogramValidationError::ZeroDuration);
        }
        if let PcSamplingMethod::StopAndGo {
            configured_retained_runtime_percent,
            observed_retained_runtime_percent,
        } = self.method
            && (!valid_percent(configured_retained_runtime_percent)
                || !valid_percent(observed_retained_runtime_percent))
        {
            return Err(PcHitHistogramValidationError::InvalidRetainedRuntimePercent);
        }
        self.target_state_before.validate("before")?;
        self.target_state_after.validate("after")?;
        match (
            &self.firmware.status,
            &self.firmware.elf_sha256,
            &self.firmware.proof,
        ) {
            (
                FirmwareBindingStatus::Verified,
                Some(_),
                Some(
                    FirmwareBindingProof::DigestBoundDeployment { .. }
                    | FirmwareBindingProof::TargetImageComparison { .. },
                ),
            ) => {}
            (
                FirmwareBindingStatus::DeploymentAsserted,
                Some(_),
                Some(FirmwareBindingProof::PrecommittedElfAssertion { .. }),
            ) => {}
            (
                FirmwareBindingStatus::Mismatch,
                Some(_),
                Some(FirmwareBindingProof::TargetImageComparison { .. }),
            ) => {}
            (FirmwareBindingStatus::Unverified, _, None) => {}
            (FirmwareBindingStatus::Unverified, _, Some(_)) => {
                return Err(PcHitHistogramValidationError::UnexpectedFirmwareProof);
            }
            (FirmwareBindingStatus::Mismatch, Some(_), _) => {
                return Err(PcHitHistogramValidationError::MismatchRequiresTargetComparison);
            }
            _ => return Err(PcHitHistogramValidationError::InvalidFirmwareBinding),
        }
        if !self.cleanup_complete {
            return Err(PcHitHistogramValidationError::CleanupIncomplete);
        }
        if self.buckets.is_empty() {
            return Err(PcHitHistogramValidationError::EmptyBuckets);
        }
        if self.buckets.len() > MAX_PC_HIT_BUCKETS {
            return Err(PcHitHistogramValidationError::TooManyBuckets {
                limit: MAX_PC_HIT_BUCKETS,
                actual: self.buckets.len(),
            });
        }
        let mut previous_end = None;
        let mut total = 0_u64;
        for bucket in &self.buckets {
            if bucket.start_address >= bucket.end_address {
                return Err(PcHitHistogramValidationError::NonHalfOpenBucket {
                    start_address: bucket.start_address,
                    end_address: bucket.end_address,
                });
            }
            if let Some(end_address) = previous_end
                && bucket.start_address < end_address
            {
                return Err(
                    PcHitHistogramValidationError::UnsortedOrOverlappingBuckets {
                        previous_end: end_address,
                        start_address: bucket.start_address,
                    },
                );
            }
            previous_end = Some(bucket.end_address);
            total = total
                .checked_add(bucket.hits)
                .ok_or(PcHitHistogramValidationError::HitCountOverflow)?;
        }
        if total != self.in_scope_hits {
            return Err(PcHitHistogramValidationError::InScopeHitMismatch {
                expected: total,
                actual: self.in_scope_hits,
            });
        }
        if let Some(symbolization) = &self.debugger_symbolization {
            validate_debugger_symbolization(symbolization, &self.buckets)?;
        }
        Ok(())
    }
}

fn validate_debugger_symbolization(
    symbolization: &DebuggerSymbolization,
    buckets: &[PcHitBucket],
) -> Result<(), PcHitHistogramValidationError> {
    if symbolization.source != DebuggerSymbolizationSource::Trace32SymbolTable {
        return Err(PcHitHistogramValidationError::InvalidDebuggerSymbolizationSource);
    }
    if symbolization.trust != DebuggerSymbolizationTrust::DebuggerReported {
        return Err(PcHitHistogramValidationError::InvalidDebuggerSymbolizationTrust);
    }
    if symbolization.refinement_granularity_bytes != 4 {
        return Err(PcHitHistogramValidationError::InvalidRefinementGranularity);
    }
    if symbolization.locations.len() > 10 {
        return Err(PcHitHistogramValidationError::TooManyDebuggerLocations {
            actual: symbolization.locations.len(),
        });
    }
    let mut previous = None;
    let mut parent_buckets = BTreeSet::new();
    for location in &symbolization.locations {
        if !parent_buckets.insert((location.bucket_start_address, location.bucket_end_address)) {
            return Err(PcHitHistogramValidationError::DuplicateDebuggerLocationBucket);
        }
        let bucket = buckets
            .iter()
            .find(|bucket| {
                bucket.start_address == location.bucket_start_address
                    && bucket.end_address == location.bucket_end_address
            })
            .ok_or(PcHitHistogramValidationError::DebuggerLocationMissingBucket)?;
        if bucket.hits != location.hits {
            return Err(PcHitHistogramValidationError::DebuggerLocationHitMismatch);
        }
        if location.dominant_start_address >= location.dominant_end_address
            || location.dominant_start_address < bucket.start_address
            || location.dominant_end_address > bucket.end_address
            || location.dominant_end_address - location.dominant_start_address
                > symbolization.refinement_granularity_bytes
            || location.dominant_hits == 0
            || location.dominant_hits > location.hits
        {
            return Err(PcHitHistogramValidationError::InvalidDebuggerLocationRange);
        }
        if let Some(function_name) = &location.function_name
            && (!valid_key_text(function_name, 256) || function_name.contains(['/', '\\']))
        {
            return Err(PcHitHistogramValidationError::InvalidDebuggerLocationText {
                field: "function_name",
            });
        }
        match (&location.source_file, location.source_line) {
            (Some(source_file), Some(source_line))
                if valid_key_text(source_file, 256)
                    && !source_file.contains(['/', '\\'])
                    && source_line > 0 => {}
            (Some(_), Some(_)) => {
                return Err(PcHitHistogramValidationError::InvalidDebuggerLocationText {
                    field: "source_file",
                });
            }
            (None, Some(_)) => {
                return Err(PcHitHistogramValidationError::InvalidDebuggerLocationText {
                    field: "source_line",
                });
            }
            (Some(_), None) => {
                return Err(PcHitHistogramValidationError::InvalidDebuggerLocationText {
                    field: "source_line",
                });
            }
            (None, None) => {}
        }
        if location.function_name.is_none() && location.source_file.is_none() {
            return Err(PcHitHistogramValidationError::MissingDebuggerLocationLabel);
        }
        let order = (
            std::cmp::Reverse(location.hits),
            location.bucket_start_address,
        );
        if previous.is_some_and(|previous| previous > order) {
            return Err(PcHitHistogramValidationError::UnsortedDebuggerLocations);
        }
        previous = Some(order);
    }
    Ok(())
}

fn valid_percent(value: f64) -> bool {
    value.is_finite() && (0.0..=100.0).contains(&value)
}

/// The one allowed evidence quality for a coarse sampling heatmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HeatmapQuality {
    /// Cells are statistical estimates from PC samples.
    Statistical,
}

/// The single projection granularity represented by all cells in a heatmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HeatmapProjectionKind {
    /// Half-open sampled address ranges.
    AddressRange,
    /// Executable functions.
    Function,
    /// Source-file lines.
    SourceLine,
}

/// Default minimum in-scope hits needed for a quantitative heatmap.
pub const DEFAULT_MIN_IN_SCOPE_HITS: u64 = 100;
/// Default minimum observed capture duration for a quantitative heatmap.
pub const DEFAULT_MIN_OBSERVED_DURATION_NS: DurationNs = 100_000_000;
/// Default minimum retained runtime for intrusive Stop-and-Go sampling.
pub const DEFAULT_MIN_STOP_AND_GO_RETAINED_RUNTIME_PERCENT: f64 = 90.0;
/// Default maximum TRACE32 PC-snoop failures for a quantitative heatmap.
pub const DEFAULT_MAX_SNOOP_FAILURES: u64 = 0;

/// Quantitative admission thresholds persisted with a heatmap projection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuantitativePolicy {
    /// Minimum in-scope PC hits needed for analysis.
    #[schemars(range(min = 1))]
    pub min_in_scope_hits: u64,
    /// Minimum observed capture duration needed for analysis.
    #[schemars(range(min = 1))]
    pub min_observed_duration_ns: DurationNs,
    /// Minimum retained runtime accepted for Stop-and-Go sampling.
    #[schemars(range(min = 0.0, max = 100.0))]
    pub min_stop_and_go_retained_runtime_percent: f64,
    /// Maximum allowed TRACE32 PC-snoop failures.
    pub max_snoop_failures: u64,
}

impl Default for QuantitativePolicy {
    fn default() -> Self {
        Self {
            min_in_scope_hits: DEFAULT_MIN_IN_SCOPE_HITS,
            min_observed_duration_ns: DEFAULT_MIN_OBSERVED_DURATION_NS,
            min_stop_and_go_retained_runtime_percent:
                DEFAULT_MIN_STOP_AND_GO_RETAINED_RUNTIME_PERCENT,
            max_snoop_failures: DEFAULT_MAX_SNOOP_FAILURES,
        }
    }
}

impl QuantitativePolicy {
    /// Validates threshold ranges before applying the policy to a histogram.
    pub fn validate(&self) -> Result<(), QuantitativePolicyValidationError> {
        if self.min_in_scope_hits == 0 {
            return Err(QuantitativePolicyValidationError::ZeroMinimumInScopeHits);
        }
        if self.min_observed_duration_ns == 0 {
            return Err(QuantitativePolicyValidationError::ZeroMinimumObservedDuration);
        }
        if !valid_percent(self.min_stop_and_go_retained_runtime_percent) {
            return Err(QuantitativePolicyValidationError::InvalidMinimumRetainedRuntime);
        }
        Ok(())
    }
}

/// A strictly typed heatmap-cell identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HeatmapCellKey {
    /// One half-open sampled program-counter interval.
    AddressRange {
        /// Inclusive interval start.
        start_address: u64,
        /// Exclusive interval end.
        end_address: u64,
    },
    /// One executable function.
    Function {
        /// Stable function identity from the bound executable.
        #[schemars(length(min = 1, max = 256))]
        function_id: String,
    },
    /// One source line from the bound executable's debug information.
    SourceLine {
        /// Source path as recorded by debug information.
        #[schemars(length(min = 1, max = 4_096))]
        source_path: String,
        /// One-based source line number.
        #[schemars(range(min = 1))]
        line: u32,
    },
}

/// A coarse heatmap cell with a statistical PC-hit count.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HeatmapCell {
    /// Typed identity for the cell.
    pub key: HeatmapCellKey,
    /// Human-readable cell label; it is not part of the stable cell identity.
    #[schemars(length(min = 1, max = 256))]
    pub display_name: String,
    /// Attributed PC hits represented by this cell.
    pub hits: u64,
    /// Optional TRACE32-reported label for this exact address bucket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debugger_location: Option<DebuggerHotspotLocation>,
}

/// Out-of-scope hit accounting when TRACE32 can or cannot provide it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum OutOfScopeHits {
    /// TRACE32 reported a count outside the declared address scope.
    Known {
        /// Count outside the declared scope.
        hits: u64,
    },
    /// TRACE32 did not provide a reliable count outside the declared scope.
    Unknown,
}

/// A bounded, statistical heatmap projected from a PC-hit histogram.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Heatmap {
    /// The heatmap schema version.
    pub schema: HeatmapSchemaVersion,
    /// Session that produced the source histogram.
    #[schemars(length(min = 1, max = 64))]
    pub session_id: String,
    /// Digest of the exact PC-hit histogram used for this projection.
    pub histogram_sha256: Sha256Digest,
    /// The fixed evidence quality of all heatmap cells.
    pub quality: HeatmapQuality,
    /// Projection granularity shared by every cell.
    pub projection_kind: HeatmapProjectionKind,
    /// Admission thresholds required before this projection is quantitative.
    pub quantitative_policy: QuantitativePolicy,
    /// Number of in-scope hits used as every derived cell-share denominator.
    #[schemars(range(min = 1))]
    pub denominator_hits: u64,
    /// Hits assigned to typed cells.
    pub attributed_hits: u64,
    /// In-scope hits not assigned to a typed cell.
    pub unattributed_hits: u64,
    /// Whether out-of-scope hit accounting is known.
    pub out_of_scope_hits: OutOfScopeHits,
    /// Unique typed cells, bounded for portable rendering.
    #[schemars(length(max = 16_384))]
    pub cells: Vec<HeatmapCell>,
}

impl Heatmap {
    /// Validates exact accounting, typed keys, and projection consistency.
    pub fn validate(&self) -> Result<(), HeatmapValidationError> {
        if !is_portable_session_id(&self.session_id) {
            return Err(HeatmapValidationError::InvalidSessionId);
        }
        self.quantitative_policy
            .validate()
            .map_err(HeatmapValidationError::InvalidQuantitativePolicy)?;
        if self.cells.len() > MAX_HEATMAP_CELLS {
            return Err(HeatmapValidationError::TooManyCells {
                limit: MAX_HEATMAP_CELLS,
                actual: self.cells.len(),
            });
        }
        let mut keys = BTreeSet::new();
        let mut total = 0_u64;
        for cell in &self.cells {
            validate_heatmap_key(&cell.key)?;
            if !valid_key_text(&cell.display_name, 256) {
                return Err(HeatmapValidationError::InvalidDisplayName);
            }
            if heatmap_key_projection_kind(&cell.key) != self.projection_kind {
                return Err(HeatmapValidationError::MixedProjectionKinds);
            }
            if cell.debugger_location.is_some()
                && self.projection_kind != HeatmapProjectionKind::AddressRange
            {
                return Err(HeatmapValidationError::DebuggerLocationRequiresAddressProjection);
            }
            if !keys.insert(cell.key.clone()) {
                return Err(HeatmapValidationError::DuplicateCellKey);
            }
            total = total
                .checked_add(cell.hits)
                .ok_or(HeatmapValidationError::HitCountOverflow)?;
        }
        if total != self.attributed_hits {
            return Err(HeatmapValidationError::AttributedHitMismatch {
                expected: total,
                actual: self.attributed_hits,
            });
        }
        let accounted = self
            .attributed_hits
            .checked_add(self.unattributed_hits)
            .ok_or(HeatmapValidationError::HitCountOverflow)?;
        if accounted != self.denominator_hits {
            return Err(HeatmapValidationError::DenominatorMismatch {
                expected: accounted,
                actual: self.denominator_hits,
            });
        }
        Ok(())
    }

    /// Validates this projection against the exact source histogram and digest.
    pub fn validate_against(
        &self,
        histogram: &PcHitHistogram,
        observed_histogram_sha256: Sha256Digest,
    ) -> Result<(), HeatmapAgainstHistogramValidationError> {
        self.validate()?;
        histogram.validate()?;
        if self.histogram_sha256 != observed_histogram_sha256 {
            return Err(HeatmapAgainstHistogramValidationError::HistogramDigestMismatch);
        }
        if self.session_id != histogram.session_id {
            return Err(HeatmapAgainstHistogramValidationError::SessionMismatch);
        }
        if self.denominator_hits != histogram.in_scope_hits {
            return Err(HeatmapAgainstHistogramValidationError::DenominatorMismatch);
        }
        let policy = &self.quantitative_policy;
        if histogram.last_sample_rate_hz == 0 {
            return Err(HeatmapAgainstHistogramValidationError::ZeroSampleRate);
        }
        validate_quantitative_target_state(histogram.target_state_before, "before")?;
        validate_quantitative_target_state(histogram.target_state_after, "after")?;
        if histogram.in_scope_hits < policy.min_in_scope_hits {
            return Err(HeatmapAgainstHistogramValidationError::InsufficientInScopeHits);
        }
        if histogram.observed_duration_ns < policy.min_observed_duration_ns {
            return Err(HeatmapAgainstHistogramValidationError::InsufficientObservedDuration);
        }
        if histogram.snoop_failures > policy.max_snoop_failures {
            return Err(HeatmapAgainstHistogramValidationError::TooManySnoopFailures);
        }
        if let PcSamplingMethod::StopAndGo {
            observed_retained_runtime_percent,
            ..
        } = histogram.method
            && observed_retained_runtime_percent < policy.min_stop_and_go_retained_runtime_percent
        {
            return Err(HeatmapAgainstHistogramValidationError::InsufficientRetainedRuntime);
        }
        if matches!(
            self.projection_kind,
            HeatmapProjectionKind::Function | HeatmapProjectionKind::SourceLine
        ) && !matches!(
            histogram.firmware.status,
            FirmwareBindingStatus::Verified | FirmwareBindingStatus::DeploymentAsserted
        ) {
            return Err(HeatmapAgainstHistogramValidationError::AttributedFirmwareBindingRequired);
        }
        if matches!(
            self.projection_kind,
            HeatmapProjectionKind::Function | HeatmapProjectionKind::SourceLine
        ) && histogram.firmware.proof.is_none()
        {
            return Err(HeatmapAgainstHistogramValidationError::FirmwareProofRequired);
        }
        if self.projection_kind == HeatmapProjectionKind::AddressRange {
            if self.cells.len() != histogram.buckets.len() {
                return Err(HeatmapAgainstHistogramValidationError::AddressCoverageMismatch);
            }
            for (cell, bucket) in self.cells.iter().zip(&histogram.buckets) {
                let HeatmapCellKey::AddressRange {
                    start_address,
                    end_address,
                } = cell.key
                else {
                    return Err(HeatmapAgainstHistogramValidationError::AddressCoverageMismatch);
                };
                if start_address != bucket.start_address
                    || end_address != bucket.end_address
                    || cell.hits != bucket.hits
                {
                    return Err(HeatmapAgainstHistogramValidationError::AddressCoverageMismatch);
                }
                let expected_location =
                    histogram
                        .debugger_symbolization
                        .as_ref()
                        .and_then(|symbolization| {
                            symbolization.locations.iter().find(|location| {
                                location.bucket_start_address == bucket.start_address
                                    && location.bucket_end_address == bucket.end_address
                            })
                        });
                if cell.debugger_location.as_ref() != expected_location {
                    return Err(HeatmapAgainstHistogramValidationError::DebuggerLocationMismatch);
                }
            }
        }
        Ok(())
    }
}

fn validate_quantitative_target_state(
    state: TargetExecutionState,
    boundary: &'static str,
) -> Result<(), HeatmapAgainstHistogramValidationError> {
    if !state.powered || !state.running || state.halted {
        return Err(HeatmapAgainstHistogramValidationError::TargetNotRunning { boundary });
    }
    Ok(())
}

fn validate_text(field: &'static str, value: &str) -> Result<(), PcHitHistogramValidationError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(PcHitHistogramValidationError::InvalidText { field });
    }
    Ok(())
}

fn validate_heatmap_key(key: &HeatmapCellKey) -> Result<(), HeatmapValidationError> {
    match key {
        HeatmapCellKey::AddressRange {
            start_address,
            end_address,
        } if start_address < end_address => Ok(()),
        HeatmapCellKey::Function { function_id } if valid_key_text(function_id, 256) => Ok(()),
        HeatmapCellKey::SourceLine { source_path, line }
            if valid_key_text(source_path, 4_096) && *line > 0 =>
        {
            Ok(())
        }
        HeatmapCellKey::AddressRange { .. } | HeatmapCellKey::Function { .. } => {
            Err(HeatmapValidationError::InvalidCellKey)
        }
        HeatmapCellKey::SourceLine { .. } => Err(HeatmapValidationError::InvalidCellKey),
    }
}

fn heatmap_key_projection_kind(key: &HeatmapCellKey) -> HeatmapProjectionKind {
    match key {
        HeatmapCellKey::AddressRange { .. } => HeatmapProjectionKind::AddressRange,
        HeatmapCellKey::Function { .. } => HeatmapProjectionKind::Function,
        HeatmapCellKey::SourceLine { .. } => HeatmapProjectionKind::SourceLine,
    }
}

fn valid_key_text(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
}

/// Semantic invariant violations in a PC-hit histogram.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum PcHitHistogramValidationError {
    /// Session identifiers must use the shared portable syntax.
    #[error("session_id must use the portable Session-ID syntax")]
    InvalidSessionId,
    /// A capture identity field was empty, too long, or contained a control character.
    #[error("invalid {field}")]
    InvalidText {
        /// Name of the rejected field.
        field: &'static str,
    },
    /// A sampling method disagreed with its declared disturbance property.
    #[error("intrusive must be true exactly for stop-and-go sampling")]
    IntrusiveMethodMismatch,
    /// A histogram must represent a nonzero capture duration.
    #[error("duration_ns must be nonzero")]
    ZeroDuration,
    /// Retained runtime must be finite and expressed as a percentage.
    #[error("Stop-and-Go retained runtime percentages must be finite and in 0..=100")]
    InvalidRetainedRuntimePercent,
    /// A boundary target state claimed both running and halted.
    #[error("target state at {boundary} cannot be both running and halted")]
    InconsistentTargetState {
        /// Capture boundary at which the invalid state was observed.
        boundary: &'static str,
    },
    /// An unpowered target cannot also be running or halted.
    #[error("target state at {boundary} cannot be active when unpowered")]
    UnpoweredTargetState {
        /// Capture boundary at which the invalid state was observed.
        boundary: &'static str,
    },
    /// A firmware binding did not have the proof and digest required by its status.
    #[error("firmware binding has an invalid digest/proof combination")]
    InvalidFirmwareBinding,
    /// A mismatch must use evidence from a target-image comparison.
    #[error("mismatched firmware binding requires target_image_comparison evidence")]
    MismatchRequiresTargetComparison,
    /// Unverified firmware may not claim proof.
    #[error("unverified firmware binding must not include proof")]
    UnexpectedFirmwareProof,
    /// Successful histogram publication requires confirmed cleanup.
    #[error("cleanup_complete must be true for a histogram")]
    CleanupIncomplete,
    /// The bounded histogram contains too many buckets.
    #[error("histogram has {actual} buckets; maximum is {limit}")]
    TooManyBuckets {
        /// Contract limit.
        limit: usize,
        /// Observed count.
        actual: usize,
    },
    /// A histogram must retain its complete, nonempty bucket partition.
    #[error("histogram buckets must be nonempty")]
    EmptyBuckets,
    /// A bucket was not a nonempty half-open interval.
    #[error("bucket {start_address:#x}..{end_address:#x} is not half-open and nonempty")]
    NonHalfOpenBucket {
        /// Declared inclusive start.
        start_address: u64,
        /// Declared exclusive end.
        end_address: u64,
    },
    /// Buckets were not sorted or overlapped.
    #[error("bucket starts at {start_address:#x} before previous end {previous_end:#x}")]
    UnsortedOrOverlappingBuckets {
        /// Exclusive end of the preceding bucket.
        previous_end: u64,
        /// Inclusive start of the current bucket.
        start_address: u64,
    },
    /// Adding bucket hits overflowed `u64`.
    #[error("bucket hit count overflow")]
    HitCountOverflow,
    /// Declared in-scope hits did not equal the bucket-hit sum.
    #[error("in_scope_hits is {actual}, expected bucket sum {expected}")]
    InScopeHitMismatch {
        /// Sum of the bucket hits.
        expected: u64,
        /// Declared in-scope hit count.
        actual: u64,
    },
    /// The debugger symbolization source was not the fixed TRACE32 symbol table.
    #[error("debugger symbolization source must be trace32_symbol_table")]
    InvalidDebuggerSymbolizationSource,
    /// The debugger symbolization trust boundary was not debugger-reported.
    #[error("debugger symbolization trust must be debugger_reported")]
    InvalidDebuggerSymbolizationTrust,
    /// Dominant addresses must use the fixed four-byte refinement granularity.
    #[error("debugger symbolization refinement_granularity_bytes must be 4")]
    InvalidRefinementGranularity,
    /// More than ten debugger hotspots were provided.
    #[error("debugger symbolization has {actual} locations; maximum is 10")]
    TooManyDebuggerLocations {
        /// Observed location count.
        actual: usize,
    },
    /// A debugger location did not name one exact sampled bucket.
    #[error("debugger location does not correspond to a histogram bucket")]
    DebuggerLocationMissingBucket,
    /// A debugger location's parent-bucket hit count differed from the histogram.
    #[error("debugger location hits differ from its histogram bucket")]
    DebuggerLocationHitMismatch,
    /// More than one debugger location named the same parent bucket.
    #[error("debugger locations must have unique parent buckets")]
    DuplicateDebuggerLocationBucket,
    /// A debugger location had an invalid dominant address interval or hit count.
    #[error("debugger location dominant interval or hit count is invalid")]
    InvalidDebuggerLocationRange,
    /// A debugger label was absent or malformed.
    #[error("debugger location {field} is invalid")]
    InvalidDebuggerLocationText {
        /// Rejected field.
        field: &'static str,
    },
    /// A debugger location did not contain a function or source location label.
    #[error("debugger location must include function_name or source_file and source_line")]
    MissingDebuggerLocationLabel,
    /// Debugger locations were not sorted by descending hits then ascending address.
    #[error("debugger locations must sort by descending hits then ascending address")]
    UnsortedDebuggerLocations,
}

/// Semantic invariant violations in a coarse heatmap.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum HeatmapValidationError {
    /// Session identifiers must use the shared portable syntax.
    #[error("session_id must use the portable Session-ID syntax")]
    InvalidSessionId,
    /// The embedded quantitative policy was invalid.
    #[error("invalid quantitative policy: {0}")]
    InvalidQuantitativePolicy(#[from] QuantitativePolicyValidationError),
    /// The bounded heatmap contains too many cells.
    #[error("heatmap has {actual} cells; maximum is {limit}")]
    TooManyCells {
        /// Contract limit.
        limit: usize,
        /// Observed count.
        actual: usize,
    },
    /// A typed cell key was malformed.
    #[error("heatmap cell key is malformed")]
    InvalidCellKey,
    /// A display label was empty, oversized, or contained a control character.
    #[error("heatmap cell display_name is invalid")]
    InvalidDisplayName,
    /// Typed cell keys must be unique.
    #[error("heatmap contains a duplicate cell key")]
    DuplicateCellKey,
    /// At least one cell did not match the declared projection kind.
    #[error("heatmap cells must all match projection_kind")]
    MixedProjectionKinds,
    /// Debugger-reported labels are valid only on address-range cells.
    #[error("debugger_location requires an address-range heatmap")]
    DebuggerLocationRequiresAddressProjection,
    /// Adding cell hit counts overflowed `u64`.
    #[error("heatmap hit count overflow")]
    HitCountOverflow,
    /// Declared attributed hits did not equal the cell-hit sum.
    #[error("attributed_hits is {actual}, expected cell sum {expected}")]
    AttributedHitMismatch {
        /// Sum of cell hits.
        expected: u64,
        /// Declared attributed hit count.
        actual: u64,
    },
    /// The denominator did not equal attributed plus unattributed hits.
    #[error("denominator_hits is {actual}, expected accounted hits {expected}")]
    DenominatorMismatch {
        /// Sum of attributed and unattributed hits.
        expected: u64,
        /// Declared denominator hit count.
        actual: u64,
    },
}

/// Semantic invariant violations in quantitative heatmap policy thresholds.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum QuantitativePolicyValidationError {
    /// The hit threshold must be nonzero.
    #[error("min_in_scope_hits must be nonzero")]
    ZeroMinimumInScopeHits,
    /// The duration threshold must be nonzero.
    #[error("min_observed_duration_ns must be nonzero")]
    ZeroMinimumObservedDuration,
    /// The Stop-and-Go retained-runtime threshold must be finite and bounded.
    #[error("min_stop_and_go_retained_runtime_percent must be finite and in 0..=100")]
    InvalidMinimumRetainedRuntime,
}

/// Semantic invariant violations in firmware-binding evidence documents.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FirmwareBindingEvidenceValidationError {
    /// Session identifiers must use the shared portable syntax.
    #[error("session_id must use the portable Session-ID syntax")]
    InvalidSessionId,
    /// A mismatch can only be established by target-image comparison evidence.
    #[error("mismatched binding evidence requires target_image_comparison")]
    MismatchRequiresTargetComparison,
    /// An asserted binding can only be established by a precommitted ELF assertion.
    #[error("asserted binding evidence requires precommitted_elf_assertion")]
    AssertedRequiresPrecommittedAssertion,
    /// Precommitted ELF assertions cannot claim target-image verification.
    #[error("verified binding evidence must not use precommitted_elf_assertion")]
    VerifiedRejectsPrecommittedAssertion,
}

/// Violations found while binding a heatmap to one source histogram.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum HeatmapAgainstHistogramValidationError {
    /// The heatmap's own invariants were invalid.
    #[error("invalid heatmap: {0}")]
    Heatmap(#[from] HeatmapValidationError),
    /// The source histogram's invariants were invalid.
    #[error("invalid source histogram: {0}")]
    Histogram(#[from] PcHitHistogramValidationError),
    /// The declared histogram digest was not the observed source digest.
    #[error("heatmap histogram_sha256 does not match the observed histogram digest")]
    HistogramDigestMismatch,
    /// The heatmap and histogram belonged to different sessions.
    #[error("heatmap and histogram session_id differ")]
    SessionMismatch,
    /// The heatmap denominator did not equal the histogram's in-scope hit count.
    #[error("heatmap denominator_hits does not match histogram in_scope_hits")]
    DenominatorMismatch,
    /// An address cell's debugger label did not exactly match its histogram location.
    #[error("address cell debugger_location does not exactly match histogram symbolization")]
    DebuggerLocationMismatch,
    /// The histogram had no usable final sampling-rate snapshot.
    #[error("histogram last_sample_rate_hz must be nonzero for quantitative analysis")]
    ZeroSampleRate,
    /// The target was not powered, running, and non-halted at a capture boundary.
    #[error("target must be powered and running, not halted, at {boundary}")]
    TargetNotRunning {
        /// Capture boundary at which the target state was observed.
        boundary: &'static str,
    },
    /// The histogram did not meet the policy hit threshold.
    #[error("histogram in_scope_hits is below the quantitative policy minimum")]
    InsufficientInScopeHits,
    /// The histogram did not meet the policy duration threshold.
    #[error("histogram observed_duration_ns is below the quantitative policy minimum")]
    InsufficientObservedDuration,
    /// TRACE32 reported more PC-snoop failures than policy permits.
    #[error("histogram snoop_failures exceeds the quantitative policy maximum")]
    TooManySnoopFailures,
    /// Stop-and-Go retained runtime did not meet policy.
    #[error("Stop-and-Go retained runtime is below the quantitative policy minimum")]
    InsufficientRetainedRuntime,
    /// Symbol-based projections require a verified or deployment-asserted firmware binding.
    #[error(
        "function and source-line heatmaps require verified or deployment-asserted firmware binding"
    )]
    AttributedFirmwareBindingRequired,
    /// Symbol-based projections require firmware-binding proof.
    #[error("function and source-line heatmaps require firmware-binding proof")]
    FirmwareProofRequired,
    /// Address-range cells did not exactly cover the source buckets.
    #[error("address-range heatmap cells do not exactly cover source buckets")]
    AddressCoverageMismatch,
}
