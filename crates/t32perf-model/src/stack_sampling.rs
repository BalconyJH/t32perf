//! Intrusive TRACE32 break-and-frame-walk stack sampling contracts.
//!
//! These artifacts record host-observed halt cycles. They do not establish CPU
//! time, call counts, exact target halt time, or a complete unwind.

use std::collections::BTreeSet;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use thiserror::Error;

use crate::{
    ArtifactPath, DebuggerSymbolizationSource, DebuggerSymbolizationTrust, DurationNs,
    EndpointFingerprintScheme, FirmwareBinding, FirmwareBindingProof, FirmwareBindingStatus,
    FoldedStackProfileSchemaVersion, SamplingAddressSpace, Sha256Digest,
    StackCaptureAttemptSchemaVersion, StackCaptureReceiptSchemaVersion,
    StackCaptureRequestSchemaVersion, StackDriverEventSchemaVersion, StackSamplesSchemaVersion,
    TargetExecutionState, is_portable_session_id,
};

/// Maximum accepted stack samples in one intrusive capture.
pub const MAX_STACK_SAMPLES: usize = 512;
/// Maximum accepted stack frames in one sample.
pub const MAX_STACK_FRAMES: usize = 64;
/// Maximum frames walked by the bounded intrusive capture implementation.
pub const MAX_STACK_CAPTURE_FRAMES: usize = 8;
/// Maximum event count for a successful bounded stack capture.
pub const MAX_STACK_DRIVER_EVENTS: usize = MAX_STACK_SAMPLES * 4 + 6;
const MAX_LABEL_BYTES: usize = 256;

/// Exact acknowledgement required before an intrusive capture may be requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackCaptureAcknowledgement;

impl Serialize for StackCaptureAcknowledgement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bool(true)
    }
}
impl<'de> Deserialize<'de> for StackCaptureAcknowledgement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if bool::deserialize(deserializer)? {
            Ok(Self)
        } else {
            Err(D::Error::custom("acknowledge_intrusive must be true"))
        }
    }
}
impl JsonSchema for StackCaptureAcknowledgement {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("StackCaptureAcknowledgement")
    }
    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({"type":"boolean", "const":true})
    }
}

/// A bounded, explicitly intrusive stack-sampling request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StackCaptureRequest {
    /// Schema version.
    pub schema: StackCaptureRequestSchemaVersion,
    /// Explicit acknowledgement that the target will be stopped and restarted.
    pub acknowledge_intrusive: StackCaptureAcknowledgement,
    /// Requested interval between halt cycles in milliseconds.
    #[schemars(range(min = 10, max = 1_000))]
    pub sample_period_ms: u32,
    /// Requested host capture duration in milliseconds.
    #[schemars(range(min = 100, max = 60_000))]
    pub duration_ms: u32,
    /// Maximum halt cycles permitted in this capture.
    #[schemars(range(min = 1, max = 512))]
    pub max_samples: u32,
    /// Maximum frames retained from one frame walk.
    #[schemars(range(min = 1, max = 8))]
    pub max_frames: u32,
    /// Core to halt and inspect. Version 1 supports only the current single core.
    #[schemars(range(min = 0, max = 0))]
    pub core_id: u32,
    /// Program address space used for every observed frame.
    pub address_space: SamplingAddressSpace,
    /// Optional assertion for the deployed ELF used by debugger labels.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_sha256_digest"
    )]
    #[schemars(schema_with = "optional_sha256_digest_schema")]
    pub deployed_firmware_elf_sha256: Option<Sha256Digest>,
}

fn deserialize_optional_sha256_digest<'de, D>(
    deserializer: D,
) -> Result<Option<Sha256Digest>, D::Error>
where
    D: Deserializer<'de>,
{
    Sha256Digest::deserialize(deserializer).map(Some)
}
fn optional_sha256_digest_schema(generator: &mut SchemaGenerator) -> Schema {
    Sha256Digest::json_schema(generator)
}

impl StackCaptureRequest {
    /// Validates the closed bounded request.
    pub fn validate(&self) -> Result<(), StackCaptureRequestValidationError> {
        if !(10..=1_000).contains(&self.sample_period_ms) {
            return Err(StackCaptureRequestValidationError::InvalidSamplePeriod);
        }
        if !(100..=60_000).contains(&self.duration_ms) {
            return Err(StackCaptureRequestValidationError::InvalidDuration);
        }
        if !(1..=MAX_STACK_SAMPLES as u32).contains(&self.max_samples) {
            return Err(StackCaptureRequestValidationError::InvalidMaxSamples);
        }
        if !(1..=MAX_STACK_CAPTURE_FRAMES as u32).contains(&self.max_frames) {
            return Err(StackCaptureRequestValidationError::InvalidMaxFrames);
        }
        if self.core_id != 0 {
            return Err(StackCaptureRequestValidationError::UnsupportedCore);
        }
        Ok(())
    }
}

/// Durable proof that one Host Session operation has spent its intrusive capture authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StackCaptureAttempt {
    /// Schema version.
    pub schema: StackCaptureAttemptSchemaVersion,
    /// Session whose operation was consumed.
    pub session_id: String,
    /// Exact Host Session operation identifier.
    #[schemars(regex(pattern = r"^[0-9a-f]{32}$"))]
    pub operation_id: String,
    /// SHA-256 of the exact immutable Session request bytes.
    pub request_sha256: Sha256Digest,
    /// Pinned TRACE32 endpoint observed before consumption.
    pub endpoint_fingerprint: Sha256Digest,
    /// Bounded host timestamp recorded before the first Break intent.
    #[schemars(length(min = 1, max = 64))]
    pub created_at: String,
}

impl StackCaptureAttempt {
    /// Validates the closed one-use marker.
    pub fn validate(&self) -> Result<(), StackCaptureAttemptValidationError> {
        if !is_portable_session_id(&self.session_id) {
            return Err(StackCaptureAttemptValidationError::InvalidSessionId);
        }
        if !is_lowercase_hex(&self.operation_id, 32) {
            return Err(StackCaptureAttemptValidationError::InvalidOperationId);
        }
        if !valid_label(&self.created_at) || self.created_at.len() > 64 {
            return Err(StackCaptureAttemptValidationError::InvalidCreatedAt);
        }
        Ok(())
    }
}

/// Fixed stack collection mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StackSamplingMethod {
    /// TRACE32 Break, B::Frame, and Go cycle.
    BreakFrameWalk,
}
/// Fixed order in which TRACE32 frame walks are recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StackFrameOrder {
    /// The leaf PC is first and each subsequent frame is its caller.
    LeafToRoot,
}
/// Reason why one recorded frame walk ended.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum StackSampleTermination {
    /// TRACE32 reached an outer boundary which is not verified as a complete unwind.
    TerminalUnverified,
    /// The caller-imposed maximum frame depth was reached.
    MaxFrames,
    /// TRACE32 could not read a program counter for the next frame.
    PcReadFailed,
    /// A repeated frame identity was detected during the walk.
    FrameCycle,
    /// The fixed per-cycle halt budget expired before another caller was observed.
    HaltDeadline,
}

/// One debugger-reported frame in a leaf-to-root sample.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StackSampleFrame {
    /// Zero-based position in the leaf-to-root walk.
    pub depth: u32,
    /// Program counter reported by TRACE32.
    pub pc: u64,
    /// Optional function label reported by TRACE32's loaded symbols.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_name: Option<String>,
    /// Optional source-file basename reported by TRACE32.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,
    /// Optional one-based source line reported by TRACE32.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_line: Option<u32>,
}

/// One intrusive halt cycle and the frames read while the target was stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StackSample {
    /// Strictly increasing one-based sample index.
    #[schemars(range(min = 1, max = 512))]
    pub sample_index: u32,
    /// Host-observed elapsed time from Break invocation through the matching Go return.
    /// This is not a measurement of exact target stopped duration.
    #[schemars(range(min = 1))]
    pub halt_cycle_duration_ns: DurationNs,
    /// Why this bounded frame walk ended; it does not prove unwind completeness.
    pub termination: StackSampleTermination,
    /// One or more leaf-to-root frames.
    #[schemars(length(min = 1, max = 8))]
    pub frames: Vec<StackSampleFrame>,
}

/// Raw samples from intrusive Break-and-frame-walk collection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StackSamples {
    /// Schema version.
    pub schema: StackSamplesSchemaVersion,
    /// Session owning the capture.
    pub session_id: String,
    /// Fingerprint of the exclusively leased TRACE32 endpoint.
    pub endpoint_fingerprint: Sha256Digest,
    /// Fixed endpoint-fingerprint algorithm.
    pub endpoint_fingerprint_scheme: EndpointFingerprintScheme,
    /// TRACE32 build identity observed during capture.
    pub trace32: String,
    /// CPU identity reported by TRACE32.
    pub cpu: String,
    /// Core that was halted and inspected.
    pub core_id: u32,
    /// Program address space used for all PCs.
    pub address_space: SamplingAddressSpace,
    /// Fixed collection mechanism.
    pub method: StackSamplingMethod,
    /// Always true: each sample stops and restarts the target.
    pub intrusive: bool,
    /// Fixed storage order for every sample.
    pub frame_order: StackFrameOrder,
    /// Requested capture duration in milliseconds.
    #[schemars(range(min = 1))]
    pub requested_duration_ms: u32,
    /// Host-observed capture duration in milliseconds.
    #[schemars(range(min = 1))]
    pub observed_duration_ms: u32,
    /// Requested interval between halt cycles in milliseconds.
    #[schemars(range(min = 10, max = 1_000))]
    pub requested_sample_period_ms: u32,
    /// Requested sample bound.
    #[schemars(range(min = 1, max = 512))]
    pub max_samples: u32,
    /// Requested depth bound.
    #[schemars(range(min = 1, max = 8))]
    pub max_frames: u32,
    /// Number of halt cycles attempted.
    pub attempted_samples: u32,
    /// Number of samples retained below.
    pub collected_samples: u32,
    /// Sum of host-observed Break-to-Go cycle durations. This is not target CPU time.
    pub total_halt_cycle_duration_ns: DurationNs,
    /// Target state immediately before the first halt cycle.
    pub target_state_before: TargetExecutionState,
    /// Target state after cleanup and the final restart.
    pub target_state_after: TargetExecutionState,
    /// Firmware identity evidence; labels remain debugger-reported regardless of this status.
    pub firmware: FirmwareBinding,
    /// Whether cleanup and final restart completed before emission.
    pub cleanup_complete: bool,
    /// Fixed origin of optional labels in frames.
    pub debugger_symbolization_source: DebuggerSymbolizationSource,
    /// Fixed trust boundary of optional labels in frames.
    pub debugger_symbolization_trust: DebuggerSymbolizationTrust,
    /// Strictly indexed bounded samples.
    #[schemars(length(max = 512))]
    pub samples: Vec<StackSample>,
}

impl StackSamples {
    /// Validates provenance, boundary state, bounded frame walks, and exact accounting.
    pub fn validate(&self) -> Result<(), StackSamplesValidationError> {
        if !is_portable_session_id(&self.session_id) {
            return Err(StackSamplesValidationError::InvalidSessionId);
        }
        for value in [&self.trace32, &self.cpu] {
            if !valid_label(value) {
                return Err(StackSamplesValidationError::InvalidIdentityText);
            }
        }
        if self.method != StackSamplingMethod::BreakFrameWalk
            || !self.intrusive
            || self.frame_order != StackFrameOrder::LeafToRoot
        {
            return Err(StackSamplesValidationError::InvalidCollectionMethod);
        }
        if self.requested_duration_ms == 0 || self.observed_duration_ms == 0 {
            return Err(StackSamplesValidationError::ZeroDuration);
        }
        if !(10..=1_000).contains(&self.requested_sample_period_ms) {
            return Err(StackSamplesValidationError::InvalidSamplePeriod);
        }
        if !(1..=MAX_STACK_SAMPLES as u32).contains(&self.max_samples) {
            return Err(StackSamplesValidationError::InvalidMaxSamples);
        }
        if !(1..=MAX_STACK_CAPTURE_FRAMES as u32).contains(&self.max_frames) {
            return Err(StackSamplesValidationError::InvalidMaxFrames);
        }
        if self.core_id != 0 {
            return Err(StackSamplesValidationError::UnsupportedCore);
        }
        if self.collected_samples != self.samples.len() as u32
            || self.collected_samples > self.max_samples
            || self.attempted_samples > self.max_samples
            || self.attempted_samples < self.collected_samples
        {
            return Err(StackSamplesValidationError::InvalidSampleAccounting);
        }
        if self.samples.is_empty() {
            return Err(StackSamplesValidationError::EmptySamples);
        }
        validate_running_boundary(self.target_state_before, "before")?;
        validate_running_boundary(self.target_state_after, "after")?;
        validate_firmware(&self.firmware)?;
        if !self.cleanup_complete {
            return Err(StackSamplesValidationError::CleanupIncomplete);
        }
        if self.debugger_symbolization_source != DebuggerSymbolizationSource::Trace32SymbolTable
            || self.debugger_symbolization_trust != DebuggerSymbolizationTrust::DebuggerReported
        {
            return Err(StackSamplesValidationError::InvalidDebuggerTrust);
        }
        let mut total = 0_u64;
        for (position, sample) in self.samples.iter().enumerate() {
            if sample.sample_index != position as u32 + 1 {
                return Err(StackSamplesValidationError::SampleIndexNotStrictlyIncreasing);
            }
            if sample.halt_cycle_duration_ns == 0 {
                return Err(StackSamplesValidationError::ZeroHaltCycleDuration);
            }
            if sample.frames.is_empty() || sample.frames.len() > self.max_frames as usize {
                return Err(StackSamplesValidationError::InvalidFrameCount);
            }
            if sample.termination == StackSampleTermination::MaxFrames
                && sample.frames.len() != self.max_frames as usize
            {
                return Err(StackSamplesValidationError::MaxFramesTerminationMismatch);
            }
            for (depth, frame) in sample.frames.iter().enumerate() {
                validate_frame(frame, depth as u32)?;
            }
            total = total
                .checked_add(sample.halt_cycle_duration_ns)
                .ok_or(StackSamplesValidationError::HaltCycleDurationOverflow)?;
        }
        if total != self.total_halt_cycle_duration_ns {
            return Err(StackSamplesValidationError::HaltCycleDurationMismatch {
                expected: total,
                actual: self.total_halt_cycle_duration_ns,
            });
        }
        Ok(())
    }
}

fn validate_frame(
    frame: &StackSampleFrame,
    expected_depth: u32,
) -> Result<(), StackSamplesValidationError> {
    if frame.depth != expected_depth {
        return Err(StackSamplesValidationError::InvalidFrameDepth);
    }
    if let Some(name) = &frame.function_name
        && !valid_label(name)
    {
        return Err(StackSamplesValidationError::InvalidFrameFunction);
    }
    match (&frame.source_file, frame.source_line) {
        (Some(file), Some(line))
            if line > 0 && valid_label(file) && !file.contains(['/', '\\']) =>
        {
            Ok(())
        }
        (None, None) => Ok(()),
        (Some(_), Some(_)) => Err(StackSamplesValidationError::InvalidFrameSource),
        (Some(_), None) | (None, Some(_)) => {
            Err(StackSamplesValidationError::IncompleteFrameSource)
        }
    }
}
fn valid_label(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_LABEL_BYTES && !value.chars().any(char::is_control)
}
fn validate_running_boundary(
    state: TargetExecutionState,
    boundary: &'static str,
) -> Result<(), StackSamplesValidationError> {
    if !state.powered {
        return Err(StackSamplesValidationError::TargetNotPowered { boundary });
    }
    if !state.running {
        return Err(StackSamplesValidationError::TargetNotRunning { boundary });
    }
    if state.halted {
        return Err(StackSamplesValidationError::TargetHalted { boundary });
    }
    Ok(())
}
fn validate_firmware(firmware: &FirmwareBinding) -> Result<(), StackSamplesValidationError> {
    match (&firmware.status, &firmware.elf_sha256, &firmware.proof) {
        (
            FirmwareBindingStatus::Verified,
            Some(_),
            Some(
                FirmwareBindingProof::DigestBoundDeployment { .. }
                | FirmwareBindingProof::TargetImageComparison { .. },
            ),
        )
        | (
            FirmwareBindingStatus::DeploymentAsserted,
            Some(_),
            Some(FirmwareBindingProof::PrecommittedElfAssertion { .. }),
        )
        | (
            FirmwareBindingStatus::Mismatch,
            Some(_),
            Some(FirmwareBindingProof::TargetImageComparison { .. }),
        )
        | (FirmwareBindingStatus::Unverified, _, None) => Ok(()),
        _ => Err(StackSamplesValidationError::InvalidFirmwareBinding),
    }
}

/// Fixed quality of folded paths built from intrusive samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FoldedStackProfileQuality {
    /// Statistical samples which required target halt cycles.
    IntrusiveStatistical,
}
/// Fixed order used in a folded path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FoldedStackFrameOrder {
    /// Frames begin at the outermost observed boundary and end at the leaf.
    RootToLeaf,
}
/// One root-to-leaf frame in a folded path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoldedStackFrame {
    /// Program counter reported by TRACE32.
    pub pc: u64,
    /// Optional function label reported by TRACE32.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_name: Option<String>,
    /// Optional source-file basename reported by TRACE32.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,
    /// Optional one-based source line reported by TRACE32.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_line: Option<u32>,
}
/// One exact observed root-to-leaf path and its sample count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoldedStackPath {
    /// The unverified outer-boundary reason of the original leaf-to-root walk.
    pub outer_boundary: StackSampleTermination,
    /// Root-to-leaf frames; no absent parent frame is fabricated.
    #[schemars(length(min = 1, max = 64))]
    pub frames: Vec<FoldedStackFrame>,
    /// Number of raw samples with exactly this path and termination.
    #[schemars(range(min = 1))]
    pub samples: u32,
}
/// Deterministic aggregation of raw stack samples for flame-graph rendering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoldedStackProfile {
    /// Schema version.
    pub schema: FoldedStackProfileSchemaVersion,
    /// Session of the bound raw artifact.
    pub session_id: String,
    /// SHA-256 of the exact [`StackSamples`] bytes used to build this profile.
    pub raw_samples_sha256: Sha256Digest,
    /// Fixed intrusive statistical quality.
    pub quality: FoldedStackProfileQuality,
    /// Fixed collection mechanism of the source artifact.
    pub method: StackSamplingMethod,
    /// Fixed order of all retained paths.
    pub frame_order: FoldedStackFrameOrder,
    /// Attempted raw halt cycles; not CPU time or a call count.
    pub attempted_samples: u32,
    /// Collected raw samples; not CPU time or a call count.
    pub collected_samples: u32,
    /// Sum of path sample counts; not CPU time, a call count, or a duration.
    pub included_samples: u32,
    /// Collected samples whose outer boundary is terminal_unverified.
    pub terminal_unverified_samples: u32,
    /// Collected samples truncated by max_frames, pc_read_failed, frame_cycle, or halt_deadline.
    pub truncated_samples: u32,
    /// Unique deterministically sorted observed paths.
    #[schemars(length(max = 512))]
    pub paths: Vec<FoldedStackPath>,
}

impl FoldedStackProfile {
    /// Validates raw-digest binding, exact counts, path uniqueness, and deterministic order.
    pub fn validate(&self) -> Result<(), FoldedStackProfileValidationError> {
        if !is_portable_session_id(&self.session_id) {
            return Err(FoldedStackProfileValidationError::InvalidSessionId);
        }
        if self.quality != FoldedStackProfileQuality::IntrusiveStatistical
            || self.method != StackSamplingMethod::BreakFrameWalk
            || self.frame_order != FoldedStackFrameOrder::RootToLeaf
        {
            return Err(FoldedStackProfileValidationError::InvalidProfileKind);
        }
        if self.paths.len() > MAX_STACK_SAMPLES {
            return Err(FoldedStackProfileValidationError::TooManyPaths);
        }
        if self.attempted_samples < self.collected_samples {
            return Err(FoldedStackProfileValidationError::InvalidSampleAccounting);
        }
        let mut included = 0_u32;
        let mut terminal = 0_u32;
        let mut truncated = 0_u32;
        let mut previous = None;
        let mut seen = BTreeSet::new();
        for path in &self.paths {
            if path.frames.is_empty() || path.frames.len() > MAX_STACK_FRAMES || path.samples == 0 {
                return Err(FoldedStackProfileValidationError::InvalidPath);
            }
            for frame in &path.frames {
                validate_folded_frame(frame)?;
            }
            let key = (path.outer_boundary, path.frames.clone());
            if !seen.insert(key.clone()) {
                return Err(FoldedStackProfileValidationError::DuplicatePath);
            }
            if previous.as_ref().is_some_and(|previous| previous > &key) {
                return Err(FoldedStackProfileValidationError::UnsortedPaths);
            }
            previous = Some(key);
            included = included
                .checked_add(path.samples)
                .ok_or(FoldedStackProfileValidationError::CountOverflow)?;
            match path.outer_boundary {
                StackSampleTermination::TerminalUnverified => {
                    terminal = terminal
                        .checked_add(path.samples)
                        .ok_or(FoldedStackProfileValidationError::CountOverflow)?
                }
                _ => {
                    truncated = truncated
                        .checked_add(path.samples)
                        .ok_or(FoldedStackProfileValidationError::CountOverflow)?
                }
            }
        }
        if included != self.included_samples
            || included != self.collected_samples
            || terminal != self.terminal_unverified_samples
            || truncated != self.truncated_samples
        {
            return Err(FoldedStackProfileValidationError::InvalidCounts);
        }
        Ok(())
    }
}
fn validate_folded_frame(
    frame: &FoldedStackFrame,
) -> Result<(), FoldedStackProfileValidationError> {
    validate_frame(
        &StackSampleFrame {
            depth: 0,
            pc: frame.pc,
            function_name: frame.function_name.clone(),
            source_file: frame.source_file.clone(),
            source_line: frame.source_line,
        },
        0,
    )
    .map_err(|_| FoldedStackProfileValidationError::InvalidPath)
}

/// Rejection of a durable one-use stack capture marker.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StackCaptureAttemptValidationError {
    /// Session identifier is not portable.
    #[error("session_id is invalid")]
    InvalidSessionId,
    /// Host operation identifier is malformed.
    #[error("operation_id must be 32 lowercase hexadecimal characters")]
    InvalidOperationId,
    /// Timestamp is empty, too long, or contains control characters.
    #[error("created_at is invalid")]
    InvalidCreatedAt,
}

/// Rejection of a stack capture request.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StackCaptureRequestValidationError {
    /// Period outside the bounded request range.
    #[error("sample_period_ms must be in 10..=1000")]
    InvalidSamplePeriod,
    /// Duration outside the bounded request range.
    #[error("duration_ms must be in 100..=60000")]
    InvalidDuration,
    /// Sample bound outside the contract.
    #[error("max_samples must be in 1..=512")]
    InvalidMaxSamples,
    /// Frame bound outside the contract.
    #[error("max_frames must be in 1..=8")]
    InvalidMaxFrames,
    /// Version 1 cannot select or verify another TRACE32 core.
    #[error("core_id must be 0 for stack capture v1")]
    UnsupportedCore,
}
/// Rejection of a raw intrusive stack-sampling artifact.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StackSamplesValidationError {
    /// Session identifier is not portable.
    #[error("session_id is invalid")]
    InvalidSessionId,
    /// TRACE32 or CPU identity is invalid.
    #[error("TRACE32 or CPU identity text is invalid")]
    InvalidIdentityText,
    /// Fixed collection attributes disagree.
    #[error("collection method, intrusiveness, or frame order is invalid")]
    InvalidCollectionMethod,
    /// Capture duration was zero.
    #[error("requested and observed durations must be positive")]
    ZeroDuration,
    /// Requested period is invalid.
    #[error("requested sample period is invalid")]
    InvalidSamplePeriod,
    /// Sample bound is invalid.
    #[error("max_samples is invalid")]
    InvalidMaxSamples,
    /// Depth bound is invalid.
    #[error("max_frames is invalid")]
    InvalidMaxFrames,
    /// Version 1 cannot attest samples from another TRACE32 core.
    #[error("core_id must be 0 for stack samples v1")]
    UnsupportedCore,
    /// Attempted and collected values disagree.
    #[error("attempted/collected sample accounting is invalid")]
    InvalidSampleAccounting,
    /// A successful raw artifact retained no samples.
    #[error("raw stack samples must not be empty")]
    EmptySamples,
    /// Target lacked power at a boundary.
    #[error("target was not powered at {boundary}")]
    TargetNotPowered {
        /// Boundary name.
        boundary: &'static str,
    },
    /// Target was not running at a boundary.
    #[error("target was not running at {boundary}")]
    TargetNotRunning {
        /// Boundary name.
        boundary: &'static str,
    },
    /// Target was halted at a boundary.
    #[error("target was halted at {boundary}")]
    TargetHalted {
        /// Boundary name.
        boundary: &'static str,
    },
    /// Firmware evidence is malformed.
    #[error("firmware binding is invalid")]
    InvalidFirmwareBinding,
    /// Required cleanup did not complete.
    #[error("cleanup is incomplete")]
    CleanupIncomplete,
    /// Label source or trust is not fixed TRACE32/debugger_reported.
    #[error("debugger symbolization trust is invalid")]
    InvalidDebuggerTrust,
    /// Sample indexes are not contiguous.
    #[error("sample indices are not strictly increasing from one")]
    SampleIndexNotStrictlyIncreasing,
    /// A halt cycle duration was zero.
    #[error("halt-cycle duration must be positive")]
    ZeroHaltCycleDuration,
    /// Frame count was outside the bound.
    #[error("sample frame count is invalid")]
    InvalidFrameCount,
    /// A max-frames termination did not retain exactly the configured maximum.
    #[error("max_frames termination must retain exactly max_frames frames")]
    MaxFramesTerminationMismatch,
    /// Frame depth disagreed with its position.
    #[error("frame depth does not match leaf-to-root position")]
    InvalidFrameDepth,
    /// Function label was malformed.
    #[error("frame function label is invalid")]
    InvalidFrameFunction,
    /// Source label was malformed.
    #[error("frame source label is invalid")]
    InvalidFrameSource,
    /// Source file and line were not both present.
    #[error("frame source file and line must occur together")]
    IncompleteFrameSource,
    /// Summing halt cycles overflowed.
    #[error("halt-cycle duration sum overflowed")]
    HaltCycleDurationOverflow,
    /// Stored and calculated cycle sums differ.
    #[error("total halt-cycle duration mismatch; expected {expected}, actual {actual}")]
    HaltCycleDurationMismatch {
        /// Calculated sum.
        expected: u64,
        /// Stored total.
        actual: u64,
    },
}
/// Rejection of a folded stack profile.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FoldedStackProfileValidationError {
    /// Session identifier is invalid.
    #[error("session_id is invalid")]
    InvalidSessionId,
    /// Fixed profile attributes disagree.
    #[error("profile quality, method, or frame order is invalid")]
    InvalidProfileKind,
    /// Path count exceeds the contract.
    #[error("path count exceeds 512")]
    TooManyPaths,
    /// Attempted and collected counts disagree.
    #[error("attempted/collected sample accounting is invalid")]
    InvalidSampleAccounting,
    /// A path has an invalid frame vector or count.
    #[error("path is invalid")]
    InvalidPath,
    /// A complete observed path was repeated.
    #[error("duplicate observed path")]
    DuplicatePath,
    /// Paths are not in deterministic key order.
    #[error("paths are not deterministically sorted")]
    UnsortedPaths,
    /// Summing counts overflowed.
    #[error("count overflow")]
    CountOverflow,
    /// Stored aggregate counts are not exact.
    #[error("profile counts do not exactly account for its paths")]
    InvalidCounts,
}

/// Exact JSON `true` used for irreversible stack-capture state assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackDriverTrue;

impl Serialize for StackDriverTrue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bool(true)
    }
}

impl<'de> Deserialize<'de> for StackDriverTrue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if bool::deserialize(deserializer)? {
            Ok(Self)
        } else {
            Err(D::Error::custom("value must be true"))
        }
    }
}

impl JsonSchema for StackDriverTrue {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("StackDriverTrue")
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({"type": "boolean", "const": true})
    }
}

/// Fixed sidecar identity allowed to emit stack-driver events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum StackDriverOwner {
    /// Current intrusive stack-sampling MCP sidecar contract.
    #[serde(rename = "lauterbach-stack-sampling-mcp/v1")]
    LauterbachStackSamplingMcpV1,
}

/// Tagged details of one durable intrusive stack-driver event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "event",
    content = "details",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum StackDriverEventDetails {
    /// Intent to perform the bounded intrusive capture.
    CaptureIntent {
        /// The target was initially running before the first mutation.
        initial_running: StackDriverTrue,
        /// Requested capture duration in milliseconds.
        #[schemars(range(min = 100, max = 60_000))]
        duration_ms: u32,
        /// Requested halt-cycle period in milliseconds.
        #[schemars(range(min = 10, max = 1_000))]
        sample_period_ms: u32,
        /// Maximum permitted samples.
        #[schemars(range(min = 1, max = 512))]
        max_samples: u32,
        /// Maximum frames in one walk.
        #[schemars(range(min = 1, max = 8))]
        max_frames: u32,
    },
    /// Intent to halt for one sample.
    BreakIntent {
        /// One-based sample index.
        #[schemars(range(min = 1, max = 512))]
        sample_index: u32,
    },
    /// The requested halt was observed.
    BreakObserved {
        /// One-based sample index.
        #[schemars(range(min = 1, max = 512))]
        sample_index: u32,
    },
    /// Intent to restart after one sample.
    GoIntent {
        /// One-based sample index.
        #[schemars(range(min = 1, max = 512))]
        sample_index: u32,
    },
    /// The requested restart was observed.
    GoObserved {
        /// One-based sample index.
        #[schemars(range(min = 1, max = 512))]
        sample_index: u32,
    },
    /// Capture result counts were observed before cleanup.
    CaptureObserved {
        /// Number of attempted halt cycles.
        attempted_samples: u32,
        /// Number of retained stack samples.
        collected_samples: u32,
    },
    /// Intent to clean up the temporary target state.
    CleanupIntent {
        /// Present only as exact true for recovery cleanup.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recovery: Option<StackDriverTrue>,
    },
    /// Cleanup completed successfully.
    CleanupObserved {},
    /// Cleanup failed with a bounded durable diagnostic.
    CleanupFailed {
        /// Present only as exact true for recovery cleanup.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recovery: Option<StackDriverTrue>,
        /// Bounded diagnostic suitable for durable journals.
        #[schemars(length(min = 1, max = 1_024))]
        error: String,
    },
    /// Recovery state was observed after a failed transaction.
    RecoveryObserved {
        /// Recovery is explicitly asserted.
        recovery: StackDriverTrue,
        /// Target is explicitly asserted running after recovery.
        running: StackDriverTrue,
    },
    /// Intent to export the final raw stack artifact.
    ExportIntent {},
    /// Final raw stack artifact binding was exported.
    ExportObserved {
        /// Canonical path relative to the Session artifact directory.
        relative_path: ArtifactPath,
        /// SHA-256 of exact exported bytes.
        sha256: Sha256Digest,
        /// Nonzero exported byte size.
        #[schemars(range(min = 1))]
        size_bytes: u64,
    },
}

/// Name of a stack-driver event, independent of its detail payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StackDriverEventName {
    /// Capture intent.
    CaptureIntent,
    /// Break intent.
    BreakIntent,
    /// Break observed.
    BreakObserved,
    /// Go intent.
    GoIntent,
    /// Go observed.
    GoObserved,
    /// Capture observed.
    CaptureObserved,
    /// Cleanup intent.
    CleanupIntent,
    /// Cleanup observed.
    CleanupObserved,
    /// Cleanup failed.
    CleanupFailed,
    /// Recovery observed.
    RecoveryObserved,
    /// Export intent.
    ExportIntent,
    /// Export observed.
    ExportObserved,
}

/// One append-only event emitted by the intrusive stack-sampling sidecar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StackDriverEvent {
    /// Schema version.
    pub schema: StackDriverEventSchemaVersion,
    /// Canonical lowercase UUID v4 transaction identity.
    #[schemars(regex(
        pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    ))]
    pub transaction_id: String,
    /// Fingerprint of the exclusively leased TRACE32 endpoint.
    pub endpoint_fingerprint: Sha256Digest,
    /// Fixed endpoint fingerprint algorithm.
    pub endpoint_fingerprint_scheme: EndpointFingerprintScheme,
    /// Fixed stack sidecar identity.
    pub owner: StackDriverOwner,
    /// Strictly positive append-only sequence.
    #[schemars(range(min = 1, max = 2054))]
    pub sequence: u64,
    /// Bounded observed timestamp string.
    #[schemars(length(min = 1, max = 64))]
    pub observed_at: String,
    /// Tagged event name and payload.
    #[serde(flatten)]
    pub details: StackDriverEventDetails,
}

impl StackDriverEvent {
    /// Returns the event name represented by the tagged details.
    #[must_use]
    pub fn event_name(&self) -> StackDriverEventName {
        match self.details {
            StackDriverEventDetails::CaptureIntent { .. } => StackDriverEventName::CaptureIntent,
            StackDriverEventDetails::BreakIntent { .. } => StackDriverEventName::BreakIntent,
            StackDriverEventDetails::BreakObserved { .. } => StackDriverEventName::BreakObserved,
            StackDriverEventDetails::GoIntent { .. } => StackDriverEventName::GoIntent,
            StackDriverEventDetails::GoObserved { .. } => StackDriverEventName::GoObserved,
            StackDriverEventDetails::CaptureObserved { .. } => {
                StackDriverEventName::CaptureObserved
            }
            StackDriverEventDetails::CleanupIntent { .. } => StackDriverEventName::CleanupIntent,
            StackDriverEventDetails::CleanupObserved { .. } => {
                StackDriverEventName::CleanupObserved
            }
            StackDriverEventDetails::CleanupFailed { .. } => StackDriverEventName::CleanupFailed,
            StackDriverEventDetails::RecoveryObserved { .. } => {
                StackDriverEventName::RecoveryObserved
            }
            StackDriverEventDetails::ExportIntent { .. } => StackDriverEventName::ExportIntent,
            StackDriverEventDetails::ExportObserved { .. } => StackDriverEventName::ExportObserved,
        }
    }

    /// Validates the event's closed local constraints.
    pub fn validate(&self) -> Result<(), StackDriverEventValidationError> {
        if !crate::is_canonical_uuid_v4(&self.transaction_id) {
            return Err(StackDriverEventValidationError::InvalidTransactionId);
        }
        if self.sequence == 0 || self.sequence > MAX_STACK_DRIVER_EVENTS as u64 {
            return Err(StackDriverEventValidationError::InvalidSequence);
        }
        if !valid_label(&self.observed_at) || self.observed_at.len() > 64 {
            return Err(StackDriverEventValidationError::InvalidObservedAt);
        }
        match &self.details {
            StackDriverEventDetails::CaptureIntent {
                duration_ms,
                sample_period_ms,
                max_samples,
                max_frames,
                ..
            } if !(100..=60_000).contains(duration_ms)
                || !(10..=1_000).contains(sample_period_ms)
                || !(1..=MAX_STACK_SAMPLES as u32).contains(max_samples)
                || !(1..=MAX_STACK_CAPTURE_FRAMES as u32).contains(max_frames) =>
            {
                Err(StackDriverEventValidationError::InvalidCaptureIntent)
            }
            StackDriverEventDetails::CaptureObserved {
                attempted_samples,
                collected_samples,
            } if *attempted_samples < *collected_samples
                || *attempted_samples > MAX_STACK_SAMPLES as u32 =>
            {
                Err(StackDriverEventValidationError::InvalidCaptureCounts)
            }
            StackDriverEventDetails::CleanupFailed { error, .. }
                if !valid_label(error) || error.len() > 1_024 =>
            {
                Err(StackDriverEventValidationError::InvalidCleanupError)
            }
            StackDriverEventDetails::ExportObserved { size_bytes: 0, .. } => {
                Err(StackDriverEventValidationError::ZeroExportSize)
            }
            _ => Ok(()),
        }
    }
}

/// Successful export binding recovered from a validated event sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackSuccessfulExportBinding {
    /// Exported artifact path.
    pub relative_path: ArtifactPath,
    /// Exported artifact digest.
    pub sha256: Sha256Digest,
    /// Exported artifact size.
    pub size_bytes: u64,
    /// Exact number of validated journal events.
    pub event_count: u64,
    /// Number of successfully completed sample cycles.
    pub successful_sample_count: u32,
    /// Number of Break/Go cycles attempted according to capture_observed.
    pub attempted_sample_count: u32,
    /// Authorized host capture duration from the first journal event.
    pub duration_ms: u32,
    /// Authorized interval between halt cycles from the first journal event.
    pub sample_period_ms: u32,
    /// Authorized halt-cycle bound from the first journal event.
    pub max_samples: u32,
    /// Authorized frame-depth bound from the first journal event.
    pub max_frames: u32,
}

/// Validates a complete successful stack-driver journal and returns its export binding.
///
/// Recovery and failed-cleanup journals are valid driver histories but cannot be
/// exported as successful captures, so this function rejects them.
pub fn validate_successful_stack_event_sequence(
    events: &[StackDriverEvent],
) -> Result<StackSuccessfulExportBinding, StackDriverSequenceValidationError> {
    let first = events
        .first()
        .ok_or(StackDriverSequenceValidationError::Empty)?;
    let transaction_id = &first.transaction_id;
    let endpoint = (
        &first.endpoint_fingerprint,
        first.endpoint_fingerprint_scheme,
    );
    for (expected_sequence, event) in (1_u64..).zip(events) {
        event
            .validate()
            .map_err(StackDriverSequenceValidationError::Event)?;
        if event.sequence != expected_sequence {
            return Err(StackDriverSequenceValidationError::SequenceGap);
        }
        if &event.transaction_id != transaction_id
            || (
                &event.endpoint_fingerprint,
                event.endpoint_fingerprint_scheme,
            ) != endpoint
        {
            return Err(StackDriverSequenceValidationError::MixedTransaction);
        }
    }
    let StackDriverEventDetails::CaptureIntent {
        duration_ms,
        sample_period_ms,
        max_samples,
        max_frames,
        ..
    } = first.details
    else {
        return Err(StackDriverSequenceValidationError::MissingCaptureIntent);
    };
    let mut cursor = 1_usize;
    let mut completed = 0_u32;
    while cursor < events.len()
        && matches!(
            events[cursor].details,
            StackDriverEventDetails::BreakIntent { .. }
        )
    {
        let sample_index = completed + 1;
        for expected in [
            StackDriverEventName::BreakIntent,
            StackDriverEventName::BreakObserved,
            StackDriverEventName::GoIntent,
            StackDriverEventName::GoObserved,
        ] {
            let event = events
                .get(cursor)
                .ok_or(StackDriverSequenceValidationError::IncompleteSampleCycle)?;
            if event.event_name() != expected
                || sample_index_of(&event.details) != Some(sample_index)
            {
                return Err(StackDriverSequenceValidationError::SampleCycleMismatch);
            }
            cursor += 1;
        }
        completed += 1;
    }
    let capture = events
        .get(cursor)
        .ok_or(StackDriverSequenceValidationError::MissingCaptureObserved)?;
    let StackDriverEventDetails::CaptureObserved {
        attempted_samples,
        collected_samples,
    } = capture.details
    else {
        return Err(StackDriverSequenceValidationError::MissingCaptureObserved);
    };
    if attempted_samples != completed
        || collected_samples > attempted_samples
        || attempted_samples > max_samples
    {
        return Err(StackDriverSequenceValidationError::CaptureCountsMismatch);
    }
    cursor += 1;
    let cleanup_intent = events
        .get(cursor)
        .ok_or(StackDriverSequenceValidationError::MissingSuccessfulCleanup)?;
    if !matches!(
        cleanup_intent.details,
        StackDriverEventDetails::CleanupIntent { recovery: None }
    ) {
        return Err(StackDriverSequenceValidationError::MissingSuccessfulCleanup);
    }
    cursor += 1;
    if !matches!(
        events.get(cursor).map(|event| &event.details),
        Some(StackDriverEventDetails::CleanupObserved { .. })
    ) {
        return Err(StackDriverSequenceValidationError::MissingSuccessfulCleanup);
    }
    cursor += 1;
    if !matches!(
        events.get(cursor).map(|event| &event.details),
        Some(StackDriverEventDetails::ExportIntent { .. })
    ) {
        return Err(StackDriverSequenceValidationError::MissingExport);
    }
    cursor += 1;
    let export = events
        .get(cursor)
        .ok_or(StackDriverSequenceValidationError::MissingExport)?;
    let StackDriverEventDetails::ExportObserved {
        relative_path,
        sha256,
        size_bytes,
    } = &export.details
    else {
        return Err(StackDriverSequenceValidationError::MissingExport);
    };
    cursor += 1;
    if cursor != events.len() {
        return Err(StackDriverSequenceValidationError::TrailingEvents);
    }
    Ok(StackSuccessfulExportBinding {
        relative_path: relative_path.clone(),
        sha256: sha256.clone(),
        size_bytes: *size_bytes,
        event_count: events.len() as u64,
        successful_sample_count: collected_samples,
        attempted_sample_count: attempted_samples,
        duration_ms,
        sample_period_ms,
        max_samples,
        max_frames,
    })
}

fn sample_index_of(details: &StackDriverEventDetails) -> Option<u32> {
    match details {
        StackDriverEventDetails::BreakIntent { sample_index }
        | StackDriverEventDetails::BreakObserved { sample_index }
        | StackDriverEventDetails::GoIntent { sample_index }
        | StackDriverEventDetails::GoObserved { sample_index } => Some(*sample_index),
        _ => None,
    }
}

/// Host-derived receipt binding a successful raw stack artifact to exact driver-journal bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StackCaptureReceipt {
    /// Schema version.
    pub schema: StackCaptureReceiptSchemaVersion,
    /// Portable Session identifier.
    pub session_id: String,
    /// Host Session operation id as 32 lowercase hexadecimal characters.
    #[schemars(regex(pattern = r"^[0-9a-f]{32}$"))]
    pub session_operation_id: String,
    /// SHA-256 of the exact session-owned request bytes.
    pub session_request_sha256: Sha256Digest,
    /// Completed transaction id.
    pub transaction_id: String,
    /// TRACE32 endpoint fingerprint.
    pub endpoint_fingerprint: Sha256Digest,
    /// Fixed endpoint fingerprint algorithm.
    pub endpoint_fingerprint_scheme: EndpointFingerprintScheme,
    /// SHA-256 of accepted raw stack-samples bytes.
    pub stack_samples_sha256: Sha256Digest,
    /// Nonzero raw artifact size.
    #[schemars(range(min = 1))]
    pub stack_samples_size_bytes: u64,
    /// Exact journal event count used for the journal chain.
    #[schemars(range(min = 1, max = 2054))]
    pub journal_event_count: u64,
    /// SHA-256 chain calculated by the Host over exact event bytes.
    pub journal_chain_sha256: Sha256Digest,
    /// Retained raw sample count from the successful capture.
    #[schemars(range(min = 1, max = 512))]
    pub successful_sample_count: u32,
}

impl StackCaptureReceipt {
    /// Validates receipt identity and bounded host-computed evidence claims.
    pub fn validate(&self) -> Result<(), StackCaptureReceiptValidationError> {
        if !is_portable_session_id(&self.session_id) {
            return Err(StackCaptureReceiptValidationError::InvalidSessionId);
        }
        if !is_lowercase_hex(&self.session_operation_id, 32) {
            return Err(StackCaptureReceiptValidationError::InvalidSessionOperationId);
        }
        if !crate::is_canonical_uuid_v4(&self.transaction_id) {
            return Err(StackCaptureReceiptValidationError::InvalidTransactionId);
        }
        if self.stack_samples_size_bytes == 0 {
            return Err(StackCaptureReceiptValidationError::ZeroStackSamplesSize);
        }
        if self.journal_event_count == 0
            || self.journal_event_count > MAX_STACK_DRIVER_EVENTS as u64
        {
            return Err(StackCaptureReceiptValidationError::InvalidJournalEventCount);
        }
        if self.successful_sample_count == 0
            || self.successful_sample_count > MAX_STACK_SAMPLES as u32
        {
            return Err(StackCaptureReceiptValidationError::InvalidSuccessfulSampleCount);
        }
        Ok(())
    }
}

fn is_lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Rejection of one stack-driver event.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StackDriverEventValidationError {
    /// Transaction id is not canonical lowercase UUID v4.
    #[error("transaction_id is invalid")]
    InvalidTransactionId,
    /// Sequence was outside the bounded append-only range.
    #[error("sequence is invalid")]
    InvalidSequence,
    /// Observed timestamp text was invalid.
    #[error("observed_at is invalid")]
    InvalidObservedAt,
    /// Capture intent bounds were invalid.
    #[error("capture intent bounds are invalid")]
    InvalidCaptureIntent,
    /// Capture observed counts were invalid.
    #[error("capture observed counts are invalid")]
    InvalidCaptureCounts,
    /// Cleanup diagnostic was invalid.
    #[error("cleanup failure error is invalid")]
    InvalidCleanupError,
    /// Export size was zero.
    #[error("export size is zero")]
    ZeroExportSize,
}

/// Rejection of a complete successful stack-driver sequence.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StackDriverSequenceValidationError {
    /// Event slice was empty.
    #[error("event sequence is empty")]
    Empty,
    /// A locally invalid event occurred.
    #[error("invalid event: {0}")]
    Event(#[from] StackDriverEventValidationError),
    /// Sequence was not contiguous from one.
    #[error("event sequence has a gap")]
    SequenceGap,
    /// Events mixed endpoint or transaction identities.
    #[error("event sequence mixes transaction identities")]
    MixedTransaction,
    /// Capture intent was not first.
    #[error("capture intent must be first")]
    MissingCaptureIntent,
    /// A four-event sample cycle was incomplete.
    #[error("sample cycle is incomplete")]
    IncompleteSampleCycle,
    /// A sample cycle had wrong event order or index.
    #[error("sample cycle order or index is invalid")]
    SampleCycleMismatch,
    /// Capture observed was missing or misplaced.
    #[error("capture observed is missing or misplaced")]
    MissingCaptureObserved,
    /// Capture observed counts disagreed with completed cycles.
    #[error("capture observed counts mismatch completed cycles")]
    CaptureCountsMismatch,
    /// Successful non-recovery cleanup was missing.
    #[error("successful cleanup is missing")]
    MissingSuccessfulCleanup,
    /// Export intent or observation was missing.
    #[error("successful export is missing")]
    MissingExport,
    /// Extra events followed a successful export.
    #[error("unexpected trailing event")]
    TrailingEvents,
}

/// Rejection of a stack capture receipt.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StackCaptureReceiptValidationError {
    /// Session id is invalid.
    #[error("session_id is invalid")]
    InvalidSessionId,
    /// Session operation id is invalid.
    #[error("session_operation_id is invalid")]
    InvalidSessionOperationId,
    /// Transaction id is invalid.
    #[error("transaction_id is invalid")]
    InvalidTransactionId,
    /// Raw artifact size was zero.
    #[error("stack_samples_size_bytes must be positive")]
    ZeroStackSamplesSize,
    /// Journal event count was outside the bounded range.
    #[error("journal_event_count is invalid")]
    InvalidJournalEventCount,
    /// Successful sample count was outside the bounded range.
    #[error("successful_sample_count is invalid")]
    InvalidSuccessfulSampleCount,
}
