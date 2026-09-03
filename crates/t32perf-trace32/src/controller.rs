//! Versioned file handoff contracts for the trusted t32mcp controller.

use std::collections::{BTreeMap, BTreeSet};

use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use t32perf_model::{
    Artifact, ArtifactPath, Sha256Digest, is_portable_artifact_id, is_portable_session_id,
    strict_json,
};
use thiserror::Error;

use crate::{
    PerfOperation, PerfScriptResponse, T32MCP_ABORT_TOOL, T32MCP_COLLECT_TOOL, T32MCP_EXECUTE_TOOL,
    T32PERF_SKILL_NAME, TargetAdapterCaptureKind, TargetAdapterControllerProtocol,
    TargetAdapterCustomEventCollectorContract,
};

/// Schema identifier for immutable controller execution requests.
pub const CONTROLLER_REQUEST_SCHEMA: &str = "t32perf.controller-request/v1";
/// Schema identifier for immutable multi-output controller execution requests.
pub const CONTROLLER_REQUEST_V2_SCHEMA: &str = "t32perf.controller-request/v2";
/// Schema identifier for immutable, validated controller responses.
pub const CONTROLLER_RESPONSE_SCHEMA: &str = "t32perf.controller-response/v1";
/// Schema identifier for immutable, validated multi-output controller responses.
pub const CONTROLLER_RESPONSE_V2_SCHEMA: &str = "t32perf.controller-response/v2";
/// Schema identifier for fail-closed controller abort requests.
pub const CONTROLLER_ABORT_REQUEST_SCHEMA: &str = "t32perf.controller-abort-request/v1";
/// Schema identifier for explicit unbound abort acknowledgements.
pub const CONTROLLER_ABORT_RECEIPT_SCHEMA: &str = "t32perf.controller-abort-receipt/v1";
/// Schema identifier for append-only host-driver journal events.
pub const CONTROLLER_DRIVER_EVENT_SCHEMA: &str = "t32perf.controller-driver-event/v1";
/// Schema identifier for capability-discovery evidence.
pub const CONTROLLER_CAPABILITIES_EVIDENCE_SCHEMA: &str =
    "t32perf.controller-capabilities-evidence/v1";
/// Schema identifier for capability evidence bound to the observed initial target state.
pub const CONTROLLER_CAPABILITIES_EVIDENCE_V2_SCHEMA: &str =
    "t32perf.controller-capabilities-evidence/v2";
/// Schema identifier for target-configuration evidence.
pub const CONTROLLER_CONFIGURE_EVIDENCE_SCHEMA: &str = "t32perf.controller-configure-evidence/v1";
/// Schema identifier for capture-start evidence.
pub const CONTROLLER_START_EVIDENCE_SCHEMA: &str = "t32perf.controller-start-evidence/v1";
/// Schema identifier for armed capture with external workload ownership.
pub const CONTROLLER_START_EVIDENCE_V2_SCHEMA: &str = "t32perf.controller-start-evidence/v2";
/// Schema identifier for capture-stop evidence.
pub const CONTROLLER_STOP_EVIDENCE_SCHEMA: &str = "t32perf.controller-stop-evidence/v1";
/// Schema identifier for stopped statistical-sampling evidence.
pub const CONTROLLER_STOP_EVIDENCE_V2_SCHEMA: &str = "t32perf.controller-stop-evidence/v2";
/// Schema identifier for hardware-health evidence.
pub const CONTROLLER_HEALTH_EVIDENCE_SCHEMA: &str = "t32perf.controller-health-evidence/v1";
/// Schema identifier for signal-scoped sampling health evidence.
pub const CONTROLLER_HEALTH_EVIDENCE_V2_SCHEMA: &str = "t32perf.controller-health-evidence/v2";
/// Schema identifier for stop-bound program-flow health evidence.
pub const CONTROLLER_HEALTH_EVIDENCE_V3_SCHEMA: &str = "t32perf.controller-health-evidence/v3";
/// Schema identifier for target-cleanup evidence.
pub const CONTROLLER_CLEANUP_EVIDENCE_SCHEMA: &str = "t32perf.controller-cleanup-evidence/v1";
/// Schema identifier for signal-scoped SNOOPer cleanup evidence.
pub const CONTROLLER_CLEANUP_EVIDENCE_V2_SCHEMA: &str = "t32perf.controller-cleanup-evidence/v2";
/// Domain separator for controller binding digests.
pub const CONTROLLER_BINDING_DOMAIN: &str = "t32perf.controller-binding/v1";
/// Independent upper bound for one controller request document.
pub const MAX_CONTROLLER_REQUEST_BYTES: u64 = 64 * 1024;
/// Independent upper bound for one collected t32mcp response wrapper.
pub const MAX_CONTROLLER_MCP_RESPONSE_BYTES: u64 = 64 * 1024;
/// Independent upper bound for one structured controller response document.
pub const MAX_CONTROLLER_RESPONSE_BYTES: u64 = 64 * 1024;
/// Independent upper bound for one host-driver journal event.
pub const MAX_CONTROLLER_DRIVER_EVENT_BYTES: u64 = 64 * 1024;
/// Independent upper bound for one target-control evidence document.
pub const MAX_CONTROLLER_EVIDENCE_BYTES: u64 = 1024 * 1024;
/// Maximum number of output slots in one V2 controller transaction.
pub const MAX_CONTROLLER_OUTPUT_SLOTS: usize = 5;
/// Hard safety bound for one V2 output artifact reservation.
pub const MAX_CONTROLLER_OUTPUT_ARTIFACT_BYTES: u64 = 1_u64 << 40;

const MAX_CONTROLLER_TEXT_BYTES: usize = 4 * 1024;

/// Supported controller request schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ControllerRequestSchemaVersion {
    /// Version 1.
    #[serde(rename = "t32perf.controller-request/v1")]
    V1,
}

/// Supported multi-output controller request schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ControllerRequestV2SchemaVersion {
    /// Version 2.
    #[serde(rename = "t32perf.controller-request/v2")]
    V2,
}

/// Supported controller response schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ControllerResponseSchemaVersion {
    /// Version 1.
    #[serde(rename = "t32perf.controller-response/v1")]
    V1,
}

/// Supported multi-output controller response schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ControllerResponseV2SchemaVersion {
    /// Version 2.
    #[serde(rename = "t32perf.controller-response/v2")]
    V2,
}

/// Supported controller abort-request schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ControllerAbortRequestSchemaVersion {
    /// Version 1.
    #[serde(rename = "t32perf.controller-abort-request/v1")]
    V1,
}

/// Supported controller abort-receipt schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ControllerAbortReceiptSchemaVersion {
    /// Version 1.
    #[serde(rename = "t32perf.controller-abort-receipt/v1")]
    V1,
}

/// Supported host-driver journal-event schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ControllerDriverEventSchemaVersion {
    /// Version 1.
    #[serde(rename = "t32perf.controller-driver-event/v1")]
    V1,
}

macro_rules! fixed_evidence_marker {
    ($name:ident, $wire:literal, $description:literal) => {
        #[doc = $description]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
        pub enum $name {
            /// The only supported version or operation marker.
            #[serde(rename = $wire)]
            V1,
        }
    };
}

fixed_evidence_marker!(
    ControllerCapabilitiesEvidenceSchemaVersion,
    "t32perf.controller-capabilities-evidence/v1",
    "Supported capability-evidence schema version."
);
fixed_evidence_marker!(
    ControllerCapabilitiesEvidenceV2SchemaVersion,
    "t32perf.controller-capabilities-evidence/v2",
    "Supported initial-state-bound capability-evidence schema version."
);
fixed_evidence_marker!(
    ControllerStartEvidenceV2SchemaVersion,
    "t32perf.controller-start-evidence/v2",
    "Supported externally-owned workload start-evidence schema version."
);
fixed_evidence_marker!(
    ControllerStopEvidenceV2SchemaVersion,
    "t32perf.controller-stop-evidence/v2",
    "Supported statistical-sampling stop-evidence schema version."
);
fixed_evidence_marker!(
    ControllerHealthEvidenceV2SchemaVersion,
    "t32perf.controller-health-evidence/v2",
    "Supported signal-scoped sampling-health evidence schema version."
);
fixed_evidence_marker!(
    ControllerProgramFlowHealthEvidenceSchemaVersion,
    "t32perf.controller-health-evidence/v3",
    "Supported stop-bound program-flow health evidence schema version."
);
fixed_evidence_marker!(
    ControllerConfigureEvidenceSchemaVersion,
    "t32perf.controller-configure-evidence/v1",
    "Supported configuration-evidence schema version."
);
fixed_evidence_marker!(
    ControllerStartEvidenceSchemaVersion,
    "t32perf.controller-start-evidence/v1",
    "Supported start-evidence schema version."
);
fixed_evidence_marker!(
    ControllerStopEvidenceSchemaVersion,
    "t32perf.controller-stop-evidence/v1",
    "Supported stop-evidence schema version."
);
fixed_evidence_marker!(
    ControllerHealthEvidenceSchemaVersion,
    "t32perf.controller-health-evidence/v1",
    "Supported health-evidence schema version."
);
fixed_evidence_marker!(
    ControllerCleanupEvidenceSchemaVersion,
    "t32perf.controller-cleanup-evidence/v1",
    "Supported cleanup-evidence schema version."
);
fixed_evidence_marker!(
    ControllerCleanupEvidenceV2SchemaVersion,
    "t32perf.controller-cleanup-evidence/v2",
    "Supported signal-scoped SNOOPer cleanup-evidence schema version."
);
fixed_evidence_marker!(
    ControllerCapabilitiesOperation,
    "perf_get_capabilities",
    "Fixed capability-discovery operation marker."
);
fixed_evidence_marker!(
    ControllerConfigureOperation,
    "perf_configure",
    "Fixed configuration operation marker."
);
fixed_evidence_marker!(
    ControllerStartOperation,
    "perf_start",
    "Fixed capture-start operation marker."
);
fixed_evidence_marker!(
    ControllerStopOperation,
    "perf_stop",
    "Fixed capture-stop operation marker."
);
fixed_evidence_marker!(
    ControllerHealthOperation,
    "perf_get_health",
    "Fixed hardware-health operation marker."
);
fixed_evidence_marker!(
    ControllerCleanupOperation,
    "perf_cleanup",
    "Fixed target-cleanup operation marker."
);

/// Target execution state observed by a verified adapter.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ControllerTargetState {
    /// The target was running.
    Running,
    /// The target was halted.
    Halted,
}

/// Hardware-health facts that a capability adapter can export reliably.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ControllerHealthSignal {
    /// Trace-buffer or transport overflow.
    TraceOverflow,
    /// Trace flow error.
    FlowError,
    /// Explicit trace gap.
    TraceGap,
    /// Truncated raw export.
    Truncation,
    /// Unexplained timestamp discontinuity.
    TimestampDiscontinuity,
    /// ELF and executing firmware identity mismatch.
    ElfMismatch,
    /// Program-flow closure or equivalent completeness check.
    ProgramFlowClosure,
    /// Sampling stopped because its bounded Stack buffer became full.
    SamplingBufferFull,
    /// SNOOPer stopped before the request for a reason the adapter cannot classify.
    SamplingUnexpectedStop,
}

/// Canonical closed health-signal order required by TASKEVENTS program flow.
pub const PROGRAM_FLOW_HEALTH_SIGNALS: [ControllerHealthSignal; 7] = [
    ControllerHealthSignal::TraceOverflow,
    ControllerHealthSignal::FlowError,
    ControllerHealthSignal::TraceGap,
    ControllerHealthSignal::Truncation,
    ControllerHealthSignal::TimestampDiscontinuity,
    ControllerHealthSignal::ElfMismatch,
    ControllerHealthSignal::ProgramFlowClosure,
];

/// Sampling acquisition method verified by a target adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ControllerSamplingMethod {
    /// Runtime PC access without periodic target stop.
    RealTime,
}

/// Sampling object verified by a target adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ControllerSamplingObject {
    /// Program-counter sampling.
    ProgramCounter,
}

/// Bounded sampling-buffer mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ControllerSamplingBufferMode {
    /// Stop sampling when the fixed buffer becomes full.
    Stack,
}

/// Sampling trace state observed after the explicit stop command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ControllerSamplingState {
    /// The SNOOPer is off and its records are readable/exportable.
    Off,
}

/// SNOOPer state captured immediately before explicit `SNOOPer.OFF`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ControllerSamplingPreStopState {
    /// Sampling was still armed when stop was requested.
    Arm,
    /// Sampling had stopped before the request, requiring reason classification.
    Break,
}

/// Exact SNOOPer facts for a stopped statistical capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerSamplingHealthEvidence {
    /// Actual acquisition method queried after configuration.
    pub method: ControllerSamplingMethod,
    /// Actual sampling object.
    pub object: ControllerSamplingObject,
    /// Actual bounded recording mode.
    pub buffer_mode: ControllerSamplingBufferMode,
    /// State observed after explicit `SNOOPer.OFF`.
    pub state: ControllerSamplingState,
    /// State captured immediately before explicit `SNOOPer.OFF`.
    pub pre_stop_state: ControllerSamplingPreStopState,
    /// Configured requested interval. TRACE32 does not guarantee this rate.
    #[schemars(range(min = 1))]
    pub requested_rate_ns: u64,
    /// Fixed configured capacity in records.
    #[schemars(range(min = 1))]
    pub capacity_records: u64,
    /// Records retained after stop.
    pub recorded_records: u64,
    /// Whether Stack capacity was reached and sampling stopped early.
    pub buffer_full: bool,
    /// Whether SNOOPer stopped early without reaching Stack capacity.
    pub unexpected_stop: bool,
}

/// Versioned evidence produced by a successful capability operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerCapabilitiesEvidence {
    /// Versioned document family.
    pub schema: ControllerCapabilitiesEvidenceSchemaVersion,
    /// Fixed operation marker.
    pub operation: ControllerCapabilitiesOperation,
    /// Exact controller binding echoed by the adapter.
    pub binding_sha256: Sha256Digest,
    /// Exact TRACE32 release label.
    pub trace32_release: String,
    /// Exact nonzero TRACE32 build number.
    #[schemars(range(min = 1))]
    pub trace32_build: u64,
    /// Exact architecture-package identity.
    pub architecture_package: String,
    /// Stable target identity.
    pub target_identifier: String,
    /// Stable probe identity.
    pub probe_identifier: String,
    /// Exact license features required by this adapter.
    #[schemars(length(min = 1, max = 128))]
    pub license_features: Vec<String>,
    /// Exact target-to-probe trace routing and pin identities.
    #[schemars(length(min = 1, max = 64))]
    pub trace_routing: Vec<String>,
    /// Explicit supported capture-mode identifiers.
    #[schemars(length(min = 1, max = 64))]
    pub capture_modes: Vec<String>,
    /// Explicit supported sink identifiers.
    #[schemars(length(min = 1, max = 64))]
    pub trace_sinks: Vec<String>,
    /// Cores covered by the adapter.
    #[schemars(length(min = 1, max = 256))]
    pub covered_cores: Vec<u32>,
    /// Whether the adapter verified timestamp support.
    pub timestamp_supported: bool,
    /// Exact RTOS-awareness adapter identity, absent when unsupported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtos_awareness: Option<String>,
    /// Hardware-health facts supported by this exact adapter/build.
    #[schemars(length(min = 1, max = 16))]
    pub health_signals: Vec<ControllerHealthSignal>,
}

/// Versioned capability evidence bound to the target state observed before configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerCapabilitiesEvidenceV2 {
    /// Versioned document family.
    pub schema: ControllerCapabilitiesEvidenceV2SchemaVersion,
    /// Fixed operation marker.
    pub operation: ControllerCapabilitiesOperation,
    /// Exact controller binding echoed by the adapter.
    pub binding_sha256: Sha256Digest,
    /// Exact TRACE32 release label.
    pub trace32_release: String,
    /// Exact nonzero TRACE32 build number.
    #[schemars(range(min = 1))]
    pub trace32_build: u64,
    /// Exact architecture-package identity.
    pub architecture_package: String,
    /// Stable target identity.
    pub target_identifier: String,
    /// Stable probe identity.
    pub probe_identifier: String,
    /// Exact license features required by this adapter.
    #[schemars(length(min = 1, max = 128))]
    pub license_features: Vec<String>,
    /// Exact target-to-probe trace routing and pin identities.
    #[schemars(length(min = 1, max = 64))]
    pub trace_routing: Vec<String>,
    /// Explicit supported capture-mode identifiers.
    #[schemars(length(min = 1, max = 64))]
    pub capture_modes: Vec<String>,
    /// Explicit supported sink identifiers.
    #[schemars(length(min = 1, max = 64))]
    pub trace_sinks: Vec<String>,
    /// Cores covered by the adapter.
    #[schemars(length(min = 1, max = 256))]
    pub covered_cores: Vec<u32>,
    /// Whether the adapter verified timestamp support.
    pub timestamp_supported: bool,
    /// Exact RTOS-awareness adapter identity, absent when unsupported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtos_awareness: Option<String>,
    /// Hardware-health facts supported by this exact adapter/build.
    #[schemars(length(min = 1, max = 16))]
    pub health_signals: Vec<ControllerHealthSignal>,
    /// Target state observed before this configuration transaction.
    pub initial_target_state: ControllerTargetState,
}

/// Versioned evidence produced by a successful configuration operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerConfigureEvidence {
    /// Versioned document family.
    pub schema: ControllerConfigureEvidenceSchemaVersion,
    /// Fixed operation marker.
    pub operation: ControllerConfigureOperation,
    /// Exact controller binding echoed by the adapter.
    pub binding_sha256: Sha256Digest,
    /// Semantic digest of the authoritative capture configuration.
    pub configuration_sha256: Sha256Digest,
    /// Exact selected capture mode.
    pub capture_mode: String,
    /// Exact selected trace sink.
    pub trace_sink: String,
    /// Whether timestamps were configured.
    pub timestamp_enabled: bool,
    /// Whether the fixed filter configuration was applied and verified.
    pub filters_verified: bool,
    /// Whether the fixed trigger configuration was applied and verified.
    pub trigger_verified: bool,
    /// Target state observed before configuration.
    pub initial_target_state: ControllerTargetState,
    /// Exact fixed workload identity selected by the authoritative configuration.
    pub workload_identity: String,
    /// Cores configured for capture.
    #[schemars(length(min = 1, max = 256))]
    pub covered_cores: Vec<u32>,
}

/// Versioned evidence produced by a successful capture-start operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerStartEvidence {
    /// Versioned document family.
    pub schema: ControllerStartEvidenceSchemaVersion,
    /// Fixed operation marker.
    pub operation: ControllerStartOperation,
    /// Exact controller binding echoed by the adapter.
    pub binding_sha256: Sha256Digest,
    /// Target state observed when start was requested.
    pub initial_target_state: ControllerTargetState,
    /// Must be true only after capture start was verified.
    pub capture_started: bool,
    /// Must be true only when workload execution ownership is explicit.
    pub workload_owned: bool,
    /// Exact fixed workload identity owned by the adapter.
    pub workload_identity: String,
}

/// Owner responsible for executing the fixed workload after capture is armed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ControllerWorkloadOwner {
    /// The target-specific controller invoked by the host façade.
    TargetSpecificController,
}

/// Start evidence for a capture armed before external workload execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerStartEvidenceV2 {
    /// Versioned document family.
    pub schema: ControllerStartEvidenceV2SchemaVersion,
    /// Fixed operation marker.
    pub operation: ControllerStartOperation,
    /// Exact controller binding echoed by the adapter.
    pub binding_sha256: Sha256Digest,
    /// Target state observed when capture was armed.
    pub initial_target_state: ControllerTargetState,
    /// Must be true only after the selected capture family was armed.
    pub capture_armed: bool,
    /// Explicit external workload owner.
    pub workload_owner: ControllerWorkloadOwner,
    /// Exact fixed workload identity.
    pub workload_identity: String,
}

/// Versioned evidence produced by a successful capture-stop operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerStopEvidence {
    /// Versioned document family.
    pub schema: ControllerStopEvidenceSchemaVersion,
    /// Fixed operation marker.
    pub operation: ControllerStopOperation,
    /// Exact controller binding echoed by the adapter.
    pub binding_sha256: Sha256Digest,
    /// Must be true only after capture stop was verified.
    pub capture_stopped: bool,
    /// Must be true only after the fixed workload reached its defined end condition.
    pub workload_completed: bool,
    /// Exact fixed workload identity that reached its end condition.
    pub workload_identity: String,
    /// Target state observed after the capture was stopped.
    pub target_state_after_stop: ControllerTargetState,
}

/// Versioned stop evidence for a SNOOPer statistical capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerStopEvidenceV2 {
    /// Versioned document family.
    pub schema: ControllerStopEvidenceV2SchemaVersion,
    /// Fixed operation marker.
    pub operation: ControllerStopOperation,
    /// Exact controller binding echoed by the adapter.
    pub binding_sha256: Sha256Digest,
    /// Must be true only after explicit `SNOOPer.OFF` was verified.
    pub capture_stopped: bool,
    /// Exact fixed workload/window identity.
    pub workload_identity: String,
    /// Target state after stop; the adapter never changes execution state itself.
    pub target_state_after_stop: ControllerTargetState,
    /// SNOOPer state captured before the OFF command.
    pub pre_stop_state: ControllerSamplingPreStopState,
    /// Fixed Stack capacity in records.
    #[schemars(range(min = 1))]
    pub capacity_records: u64,
    /// Records observed before OFF.
    pub recorded_records: u64,
    /// Whether SNOOPer.ZERO was set to the first retained record after OFF.
    pub time_origin_zeroed_to_first_record: bool,
}

/// Versioned evidence produced by a successful hardware-health operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerHealthEvidence {
    /// Versioned document family.
    pub schema: ControllerHealthEvidenceSchemaVersion,
    /// Fixed operation marker.
    pub operation: ControllerHealthOperation,
    /// Exact controller binding echoed by the adapter.
    pub binding_sha256: Sha256Digest,
    /// Must remain true while health is collected for an exportable capture.
    pub capture_stopped: bool,
    /// Whether overflow was observed.
    pub trace_overflow: bool,
    /// Whether a flow error was observed.
    pub flow_error: bool,
    /// Whether a trace gap was observed.
    pub trace_gap: bool,
    /// Whether the raw capture or export was truncated.
    pub truncated: bool,
    /// Whether an unexplained timestamp discontinuity was observed.
    pub timestamp_discontinuity: bool,
    /// Whether the executing firmware matched the declared ELF.
    pub elf_matches_firmware: bool,
    /// Whether the adapter's program-flow completeness check passed.
    pub program_flow_closed: bool,
}

/// Signal-scoped hardware health for statistical sampling adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerHealthEvidenceV2 {
    /// Versioned document family.
    pub schema: ControllerHealthEvidenceV2SchemaVersion,
    /// Fixed operation marker.
    pub operation: ControllerHealthOperation,
    /// Exact controller binding echoed by the adapter.
    pub binding_sha256: Sha256Digest,
    /// Must remain true while health is collected for an exportable capture.
    pub capture_stopped: bool,
    /// Exact supported-signal set. Unsupported facts have no boolean placeholder.
    #[schemars(length(min = 1, max = 16))]
    pub supported_signals: Vec<ControllerHealthSignal>,
    /// Exact immutable stop-evidence digest from which pre-stop facts came.
    pub stop_evidence_sha256: Sha256Digest,
    /// Exact stopped SNOOPer facts.
    pub sampling: ControllerSamplingHealthEvidence,
    /// Firmware comparison when the adapter has a trusted sparse image measurement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elf_matches_firmware: Option<bool>,
}

/// Stop-bound, signal-scoped health for complete TASKEVENTS program flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerProgramFlowHealthEvidence {
    /// Versioned document family.
    pub schema: ControllerProgramFlowHealthEvidenceSchemaVersion,
    /// Fixed operation marker.
    pub operation: ControllerHealthOperation,
    /// Exact controller binding echoed by the adapter.
    pub binding_sha256: Sha256Digest,
    /// Must remain true while health is collected for an exportable capture.
    pub capture_stopped: bool,
    /// Exact closed program-flow signal set.
    #[schemars(length(min = 7, max = 7))]
    pub supported_signals: Vec<ControllerHealthSignal>,
    /// Exact immutable Stop evidence artifact digest.
    pub stop_evidence_sha256: Sha256Digest,
    /// Whether trace-buffer or transport overflow was observed.
    pub trace_overflow: bool,
    /// Whether the TRACE32 decoder reported a flow error.
    pub flow_error: bool,
    /// Whether an explicit trace gap was observed.
    pub trace_gap: bool,
    /// Whether the raw capture or export was truncated.
    pub truncated: bool,
    /// Whether an unexplained timestamp discontinuity was observed.
    pub timestamp_discontinuity: bool,
    /// Whether the executing firmware matched the declared ELF.
    pub elf_matches_firmware: bool,
    /// Whether the adapter's program-flow completeness check passed.
    pub program_flow_closed: bool,
}

/// Versioned evidence produced by a successful target-cleanup operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerCleanupEvidence {
    /// Versioned document family.
    pub schema: ControllerCleanupEvidenceSchemaVersion,
    /// Fixed operation marker.
    pub operation: ControllerCleanupOperation,
    /// Exact controller binding echoed by the adapter.
    pub binding_sha256: Sha256Digest,
    /// Must be true only after adapter-owned capture state was restored.
    pub adapter_state_restored: bool,
    /// Must be true only after the adapter restored its target-state contract.
    pub target_state_restored: bool,
    /// Must always be false; cleanup never deletes Session files.
    pub files_deleted: bool,
}

/// Exact canonical SNOOPer baseline after cleanup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerSamplingCleanupEvidence {
    /// Restored sampling method.
    pub method: ControllerSamplingMethod,
    /// Restored sample object.
    pub object: ControllerSamplingObject,
    /// Restored buffer mode.
    pub buffer_mode: ControllerSamplingBufferMode,
    /// SNOOPer must be OFF.
    pub state: ControllerSamplingState,
    /// Fixed requested interval.
    #[schemars(range(min = 1))]
    pub requested_rate_ns: u64,
    /// Canonical restored Stack capacity in records.
    #[schemars(range(min = 1))]
    pub capacity_records: u64,
    /// AutoArm must be disabled.
    pub auto_arm: bool,
    /// AutoInit must be disabled.
    pub auto_init: bool,
    /// Adapter-owned ZERO origin was reset successfully.
    pub zero_reset: bool,
}

/// Signal-scoped cleanup evidence for the SNOOPer sampling profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerCleanupEvidenceV2 {
    /// Versioned document family.
    pub schema: ControllerCleanupEvidenceV2SchemaVersion,
    /// Fixed operation marker.
    pub operation: ControllerCleanupOperation,
    /// Exact controller binding echoed by the adapter.
    pub binding_sha256: Sha256Digest,
    /// Configure-time target state that cleanup preserved.
    pub initial_target_state: ControllerTargetState,
    /// Adapter-owned state was restored.
    pub adapter_state_restored: bool,
    /// Target execution state still equals the configure-time state.
    pub target_state_restored: bool,
    /// Exact canonical sampling baseline.
    pub sampling: ControllerSamplingCleanupEvidence,
    /// Cleanup never deletes Session files.
    pub files_deleted: bool,
}

/// A strict operation-specific target-control evidence document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerEvidence {
    /// Capability evidence.
    Capabilities(ControllerCapabilitiesEvidence),
    /// Capability evidence bound to the observed initial target state.
    CapabilitiesV2(ControllerCapabilitiesEvidenceV2),
    /// Configuration evidence.
    Configure(ControllerConfigureEvidence),
    /// Capture-start evidence.
    Start(ControllerStartEvidence),
    /// Armed capture with external workload ownership.
    StartV2(ControllerStartEvidenceV2),
    /// Capture-stop evidence.
    Stop(ControllerStopEvidence),
    /// Statistical-sampling stop evidence.
    StopV2(ControllerStopEvidenceV2),
    /// Hardware-health evidence.
    Health(ControllerHealthEvidence),
    /// Signal-scoped sampling health evidence.
    HealthV2(ControllerHealthEvidenceV2),
    /// Stop-bound signal-scoped program-flow health evidence.
    HealthV3(ControllerProgramFlowHealthEvidence),
    /// Target-cleanup evidence.
    Cleanup(ControllerCleanupEvidence),
    /// Signal-scoped SNOOPer cleanup evidence.
    CleanupV2(ControllerCleanupEvidenceV2),
}

impl ControllerEvidence {
    /// Validates operation-specific semantics and the exact transaction binding.
    pub fn validate_for(
        &self,
        operation: PerfOperation,
        binding_sha256: &Sha256Digest,
    ) -> Result<(), ControllerContractError> {
        let (actual_operation, actual_binding) = match self {
            Self::Capabilities(evidence) => {
                validate_capabilities_evidence(evidence)?;
                (PerfOperation::GetCapabilities, &evidence.binding_sha256)
            }
            Self::CapabilitiesV2(evidence) => {
                validate_capabilities_evidence_v2(evidence)?;
                (PerfOperation::GetCapabilities, &evidence.binding_sha256)
            }
            Self::Configure(evidence) => {
                validate_configure_evidence(evidence)?;
                (PerfOperation::Configure, &evidence.binding_sha256)
            }
            Self::Start(evidence) => {
                validate_text("workload_identity", &evidence.workload_identity)?;
                if !evidence.capture_started || !evidence.workload_owned {
                    return Err(ControllerContractError::InvalidEvidence {
                        message: "start evidence must verify capture start and workload ownership"
                            .to_owned(),
                    });
                }
                (PerfOperation::Start, &evidence.binding_sha256)
            }
            Self::StartV2(evidence) => {
                validate_text("workload_identity", &evidence.workload_identity)?;
                if !evidence.capture_armed {
                    return Err(ControllerContractError::InvalidEvidence {
                        message: "start evidence must prove the selected capture was armed"
                            .to_owned(),
                    });
                }
                (PerfOperation::Start, &evidence.binding_sha256)
            }
            Self::Stop(evidence) => {
                validate_text("workload_identity", &evidence.workload_identity)?;
                if !evidence.capture_stopped || !evidence.workload_completed {
                    return Err(ControllerContractError::InvalidEvidence {
                        message: "stop evidence must verify workload completion and capture stop"
                            .to_owned(),
                    });
                }
                (PerfOperation::Stop, &evidence.binding_sha256)
            }
            Self::StopV2(evidence) => {
                validate_text("workload_identity", &evidence.workload_identity)?;
                if !evidence.capture_stopped
                    || evidence.capacity_records == 0
                    || evidence.recorded_records == 0
                    || evidence.recorded_records > evidence.capacity_records
                    || !evidence.time_origin_zeroed_to_first_record
                {
                    return Err(ControllerContractError::InvalidEvidence {
                        message: "sampling stop evidence has an invalid transition or record count"
                            .to_owned(),
                    });
                }
                (PerfOperation::Stop, &evidence.binding_sha256)
            }
            Self::Health(evidence) => {
                if !evidence.capture_stopped {
                    return Err(ControllerContractError::InvalidEvidence {
                        message: "health evidence requires a stopped capture".to_owned(),
                    });
                }
                (PerfOperation::GetHealth, &evidence.binding_sha256)
            }
            Self::HealthV2(evidence) => {
                validate_sampling_health_evidence(evidence)?;
                (PerfOperation::GetHealth, &evidence.binding_sha256)
            }
            Self::HealthV3(evidence) => {
                validate_program_flow_health_evidence(evidence)?;
                (PerfOperation::GetHealth, &evidence.binding_sha256)
            }
            Self::Cleanup(evidence) => {
                if !evidence.adapter_state_restored
                    || !evidence.target_state_restored
                    || evidence.files_deleted
                {
                    return Err(ControllerContractError::InvalidEvidence {
                        message:
                            "cleanup evidence must restore adapter state without deleting files"
                                .to_owned(),
                    });
                }
                (PerfOperation::Cleanup, &evidence.binding_sha256)
            }
            Self::CleanupV2(evidence) => {
                let sampling = &evidence.sampling;
                if !evidence.adapter_state_restored
                    || !evidence.target_state_restored
                    || evidence.files_deleted
                    || sampling.method != ControllerSamplingMethod::RealTime
                    || sampling.object != ControllerSamplingObject::ProgramCounter
                    || sampling.buffer_mode != ControllerSamplingBufferMode::Stack
                    || sampling.state != ControllerSamplingState::Off
                    || sampling.requested_rate_ns != 1_000_000
                    || sampling.capacity_records != 65_536
                    || sampling.auto_arm
                    || sampling.auto_init
                    || !sampling.zero_reset
                {
                    return Err(ControllerContractError::InvalidEvidence {
                        message: "sampling cleanup evidence does not prove the canonical baseline"
                            .to_owned(),
                    });
                }
                (PerfOperation::Cleanup, &evidence.binding_sha256)
            }
        };
        if actual_operation != operation {
            return Err(ControllerContractError::InvalidEvidence {
                message: format!(
                    "evidence operation `{}` does not match `{}`",
                    actual_operation.as_str(),
                    operation.as_str()
                ),
            });
        }
        if actual_binding != binding_sha256 {
            return Err(ControllerContractError::EvidenceBindingMismatch);
        }
        Ok(())
    }
}

/// Typed Stop/Health completion evidence selected by the adapter capture family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerCaptureCompletionEvidence {
    /// Statistical sampling requires the signal-scoped V2 evidence pair.
    Sampling {
        /// Accepted bounded sampling stop evidence.
        stop: ControllerStopEvidenceV2,
        /// Accepted signal-scoped sampling health evidence.
        health: ControllerHealthEvidenceV2,
    },
    /// TASKEVENTS program flow requires the program-flow V1 evidence pair.
    ProgramFlowTaskEvents {
        /// Accepted complete program-flow stop evidence.
        stop: ControllerStopEvidence,
        /// Accepted exact program-flow health evidence.
        health: ControllerProgramFlowHealthEvidence,
    },
}

impl ControllerCaptureCompletionEvidence {
    /// Constructs the exact evidence family required by a typed capture contract.
    pub fn from_evidence(
        capture_kind: &TargetAdapterCaptureKind,
        stop: &ControllerEvidence,
        stop_artifact_sha256: &Sha256Digest,
        health: &ControllerEvidence,
    ) -> Result<Self, ControllerContractError> {
        match (capture_kind, stop, health) {
            (
                TargetAdapterCaptureKind::Sampling { .. },
                ControllerEvidence::StopV2(stop),
                ControllerEvidence::HealthV2(health),
            ) if &health.stop_evidence_sha256 == stop_artifact_sha256 => Ok(Self::Sampling {
                stop: stop.clone(),
                health: health.clone(),
            }),
            (
                TargetAdapterCaptureKind::ProgramFlowTaskEvents { .. },
                ControllerEvidence::Stop(stop),
                ControllerEvidence::HealthV3(health),
            ) if &health.stop_evidence_sha256 == stop_artifact_sha256 => {
                Ok(Self::ProgramFlowTaskEvents {
                    stop: stop.clone(),
                    health: health.clone(),
                })
            }
            (
                TargetAdapterCaptureKind::Sampling { .. },
                ControllerEvidence::StopV2(_),
                ControllerEvidence::HealthV2(_),
            )
            | (
                TargetAdapterCaptureKind::ProgramFlowTaskEvents { .. },
                ControllerEvidence::Stop(_),
                ControllerEvidence::HealthV3(_),
            ) => Err(ControllerContractError::InvalidEvidence {
                message: "health evidence is not bound to the accepted Stop artifact digest"
                    .to_owned(),
            }),
            (TargetAdapterCaptureKind::Sampling { .. }, _, _) => {
                Err(ControllerContractError::InvalidEvidence {
                    message: "sampling completion requires StopV2 and HealthV2 evidence".to_owned(),
                })
            }
            (TargetAdapterCaptureKind::ProgramFlowTaskEvents { .. }, _, _) => {
                Err(ControllerContractError::InvalidEvidence {
                    message: "TASKEVENTS program-flow completion requires Stop and Health evidence"
                        .to_owned(),
                })
            }
        }
    }
}

/// Strictly decodes the evidence document required by one target-control operation.
pub fn parse_controller_evidence(
    operation: PerfOperation,
    bytes: &[u8],
) -> Result<ControllerEvidence, ControllerContractError> {
    let invalid_json = |error: serde_json::Error| ControllerContractError::InvalidEvidence {
        message: error.to_string(),
    };
    match operation {
        PerfOperation::GetCapabilities => strict_json::from_slice(bytes)
            .map(ControllerEvidence::Capabilities)
            .or_else(|_| strict_json::from_slice(bytes).map(ControllerEvidence::CapabilitiesV2))
            .map_err(invalid_json),
        PerfOperation::Configure => strict_json::from_slice(bytes)
            .map(ControllerEvidence::Configure)
            .map_err(invalid_json),
        PerfOperation::Start => strict_json::from_slice(bytes)
            .map(ControllerEvidence::Start)
            .or_else(|_| strict_json::from_slice(bytes).map(ControllerEvidence::StartV2))
            .map_err(invalid_json),
        PerfOperation::Stop => strict_json::from_slice(bytes)
            .map(ControllerEvidence::Stop)
            .or_else(|_| strict_json::from_slice(bytes).map(ControllerEvidence::StopV2))
            .map_err(invalid_json),
        PerfOperation::GetHealth => strict_json::from_slice(bytes)
            .map(ControllerEvidence::Health)
            .or_else(|_| strict_json::from_slice(bytes).map(ControllerEvidence::HealthV2))
            .or_else(|_| strict_json::from_slice(bytes).map(ControllerEvidence::HealthV3))
            .map_err(invalid_json),
        PerfOperation::Cleanup => strict_json::from_slice(bytes)
            .map(ControllerEvidence::Cleanup)
            .or_else(|_| strict_json::from_slice(bytes).map(ControllerEvidence::CleanupV2))
            .map_err(invalid_json),
        PerfOperation::Export | PerfOperation::GetHotspots => {
            Err(ControllerContractError::InvalidEvidence {
                message: format!(
                    "operation `{}` does not produce target-control evidence",
                    operation.as_str()
                ),
            })
        }
    }
}

/// One of the three tools exposed by the official t32mcp server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum T32mcpTool {
    /// Start one fixed PRACTICE skill script.
    #[serde(rename = "execute_practice_skill")]
    ExecutePracticeSkill,
    /// Poll or collect the response from the active script.
    #[serde(rename = "collect_practice_skill_response")]
    CollectPracticeSkillResponse,
    /// Abort the globally active PRACTICE script.
    #[serde(rename = "abort_practice_skill")]
    AbortPracticeSkill,
}

impl T32mcpTool {
    /// Returns the exact official tool name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExecutePracticeSkill => T32MCP_EXECUTE_TOOL,
            Self::CollectPracticeSkillResponse => T32MCP_COLLECT_TOOL,
            Self::AbortPracticeSkill => T32MCP_ABORT_TOOL,
        }
    }
}

/// Arguments accepted by official `execute_practice_skill`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutePracticeSkillArguments {
    /// Fixed logical skill name.
    pub skill_name: String,
    /// Fixed repository-owned PRACTICE script name.
    pub script_name: String,
    /// Bounded scalar arguments serialized by t32mcp as `key=value` parameters.
    pub script_args: BTreeMap<String, String>,
}

/// Exact invocation of official `execute_practice_skill`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutePracticeSkillCall {
    /// Exact official tool name.
    pub tool: T32mcpTool,
    /// Typed tool arguments.
    pub arguments: ExecutePracticeSkillArguments,
}

/// Empty arguments for official collect and abort tools.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoArguments {}

/// Exact invocation of an official t32mcp tool with no arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoArgumentsToolCall {
    /// Exact official tool name.
    pub tool: T32mcpTool,
    /// Required empty object.
    pub arguments: NoArguments,
}

/// The complete MCP handoff for one transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerMcpHandoff {
    /// Starts the fixed PRACTICE script.
    pub execute: ExecutePracticeSkillCall,
    /// Polls only when execute reports `<NOT FINISHED>`.
    pub collect: NoArgumentsToolCall,
    /// Fail-safe abort call. It has no execution ownership in upstream t32mcp.
    pub abort: NoArgumentsToolCall,
}

/// Fields cryptographically bound into every controller transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerBinding {
    /// Session receiving the transaction artifacts.
    pub session_id: String,
    /// Immutable operation identifier from Session state.
    pub session_operation_id: String,
    /// Digest of the immutable Session request.
    pub session_request_sha256: Sha256Digest,
    /// Unique transaction identifier.
    pub transaction_id: String,
    /// Independent replay-prevention nonce.
    pub nonce: String,
    /// Digest of every preceding binding field with a versioned domain separator.
    pub binding_sha256: Sha256Digest,
}

impl ControllerBinding {
    /// Validates identifier syntax and the binding digest.
    pub fn validate(&self) -> Result<(), ControllerContractError> {
        if !is_portable_session_id(&self.session_id) {
            return Err(ControllerContractError::InvalidSessionId {
                value: self.session_id.clone(),
            });
        }
        validate_hex_identifier("session_operation_id", &self.session_operation_id)?;
        validate_hex_identifier("transaction_id", &self.transaction_id)?;
        validate_hex_identifier("nonce", &self.nonce)?;
        let expected = compute_controller_binding_sha256(
            &self.session_id,
            &self.session_operation_id,
            &self.session_request_sha256,
            &self.transaction_id,
            &self.nonce,
        );
        if self.binding_sha256 != expected {
            return Err(ControllerContractError::BindingDigestMismatch {
                expected: expected.to_string(),
                actual: self.binding_sha256.to_string(),
            });
        }
        Ok(())
    }
}

/// File reserved by the controller for a successful TRACE32 export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerOutputReservation {
    /// Semantic role of the reserved output.
    pub role: ControllerOutputRole,
    /// Path below `capture/staging` that TRACE32 may create once.
    pub staged_relative_path: ArtifactPath,
    /// Exact absolute path passed to the fixed export script.
    pub script_output_path: String,
    /// Artifact identifier used when accepting the completed export.
    pub artifact_id: String,
    /// Immutable destination below the Session.
    pub destination_relative_path: ArtifactPath,
    /// Artifact kind.
    pub kind: String,
    /// Artifact media type.
    pub media_type: String,
    /// Internal controller producer identity.
    pub producer: String,
    /// Independent bound applied before the exported file becomes durable.
    pub max_bytes: u64,
}

/// Semantic role of a Controller-owned script output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ControllerOutputRole {
    /// Potentially large raw trace export.
    TraceExport,
    /// Bounded machine-readable target-control evidence.
    MachineEvidence,
}

/// Closed semantic role of one V2 controller output slot.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ControllerOutputRoleV2 {
    /// Potentially large raw trace export.
    TraceExport,
    /// Target custom-event stream exported independently from program flow.
    CustomEvents,
    /// Runtime counter stream.
    Counters,
    /// Resource counter or resource-report stream.
    ResourceCounters,
    /// Bounded machine-readable target-control evidence.
    MachineEvidence,
}

impl ControllerOutputRoleV2 {
    /// Returns the one fixed V2 script argument key owned by this role.
    #[must_use]
    pub const fn script_argument(self) -> &'static str {
        match self {
            Self::TraceExport => "trace_export_output",
            Self::CustomEvents => "custom_events_output",
            Self::Counters => "counters_output",
            Self::ResourceCounters => "resource_counters_output",
            Self::MachineEvidence => "machine_evidence_output",
        }
    }
}

/// One closed V2 output slot with the complete reservation envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerOutputReservationV2 {
    /// Semantic output role.
    pub role: ControllerOutputRoleV2,
    /// Path below Session staging that the fixed script may create once.
    pub staged_relative_path: ArtifactPath,
    /// Exact PRACTICE-safe path passed under the role's fixed argument key.
    pub script_output_path: String,
    /// Artifact identifier used when the slot is accepted.
    pub artifact_id: String,
    /// Immutable destination below the Session.
    pub destination_relative_path: ArtifactPath,
    /// Artifact kind.
    pub kind: String,
    /// Artifact media type.
    pub media_type: String,
    /// Internal controller producer identity.
    pub producer: String,
    /// Independent bounded size limit.
    #[schemars(range(min = 1, max = MAX_CONTROLLER_OUTPUT_ARTIFACT_BYTES))]
    pub max_bytes: u64,
}

/// Exact admitted adapter implementation bound into every controller request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerTargetAdapterBinding {
    /// Stable compiled adapter identity selected by the trusted host.
    pub adapter_id: String,
    /// Exact adapter implementation version.
    pub adapter_version: String,
    /// Canonical TRACE32 release selected from capabilities.
    pub trace32_release: String,
    /// Exact TRACE32 build selected from capabilities.
    pub trace32_build: u64,
    /// Exact architecture package selected from capabilities.
    pub architecture_package: String,
    /// Exact target identity selected from capabilities.
    pub target_identifier: String,
    /// Exact probe identity selected from capabilities.
    pub probe_identifier: String,
    /// Digest of the complete selected profile document.
    pub profile_sha256: Sha256Digest,
    /// Deployment-verified expected digest of the canonical release bundle.
    ///
    /// Upstream t32mcp does not runtime-attest the installed skill bytes.
    pub implementation_sha256: Sha256Digest,
    /// Deployment-owned fixed scenario; public callers cannot relabel it.
    pub scenario: crate::TargetAdapterScenario,
    /// Exact typed capture-family contract selected by deployment.
    pub capture_kind: TargetAdapterCaptureKind,
    /// Explicit Controller request/response protocol copied from the selected profile.
    #[serde(
        default,
        skip_serializing_if = "TargetAdapterControllerProtocol::is_v1"
    )]
    pub controller_protocol: TargetAdapterControllerProtocol,
    /// Exact custom-event collector contract copied from the selected profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_event_collector: Option<TargetAdapterCustomEventCollectorContract>,
    /// Verified qualification receipt digest, absent for evidence-only candidates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualification_sha256: Option<Sha256Digest>,
}

impl ControllerTargetAdapterBinding {
    fn validate(&self) -> Result<(), ControllerContractError> {
        validate_text("adapter_id", &self.adapter_id)?;
        validate_text("adapter_version", &self.adapter_version)?;
        validate_text("trace32_release", &self.trace32_release)?;
        validate_text("architecture_package", &self.architecture_package)?;
        validate_text("target_identifier", &self.target_identifier)?;
        validate_text("probe_identifier", &self.probe_identifier)?;
        if self.trace32_build == 0
            || self
                .capture_kind
                .sampling_capacity_records()
                .is_some_and(|capacity| capacity == 0)
        {
            return Err(ControllerContractError::InvalidScriptArguments);
        }
        if let TargetAdapterCaptureKind::ProgramFlowTaskEvents {
            export_profile_id,
            rtos_awareness,
            timestamp_clock_id,
            orti_artifact_id,
            task_marker_artifact_id,
        } = &self.capture_kind
        {
            validate_text("export_profile_id", export_profile_id)?;
            validate_text("rtos_awareness", rtos_awareness)?;
            validate_text("timestamp_clock_id", timestamp_clock_id)?;
            validate_text("orti_artifact_id", orti_artifact_id)?;
            validate_text("task_marker_artifact_id", task_marker_artifact_id)?;
            if orti_artifact_id == task_marker_artifact_id {
                return Err(ControllerContractError::InvalidScriptArguments);
            }
        }
        match (
            self.controller_protocol,
            self.custom_event_collector.as_ref(),
        ) {
            (TargetAdapterControllerProtocol::V1, None) => {}
            (TargetAdapterControllerProtocol::V1, Some(_)) => {
                return Err(ControllerContractError::InvalidScriptArguments);
            }
            (TargetAdapterControllerProtocol::V2CustomEventsExport, None) => {
                return Err(ControllerContractError::InvalidScriptArguments);
            }
            (TargetAdapterControllerProtocol::V2CustomEventsExport, Some(collector)) => {
                collector
                    .validate()
                    .map_err(|_| ControllerContractError::InvalidScriptArguments)?;
                let TargetAdapterCaptureKind::ProgramFlowTaskEvents {
                    timestamp_clock_id, ..
                } = &self.capture_kind
                else {
                    return Err(ControllerContractError::InvalidScriptArguments);
                };
                if collector.clock.clock_id != *timestamp_clock_id {
                    return Err(ControllerContractError::InvalidScriptArguments);
                }
            }
        }
        match (&self.capture_kind, self.scenario) {
            (
                TargetAdapterCaptureKind::Sampling { .. },
                crate::TargetAdapterScenario::TraceOverflow
                | crate::TargetAdapterScenario::FlowError,
            )
            | (
                TargetAdapterCaptureKind::ProgramFlowTaskEvents { .. },
                crate::TargetAdapterScenario::SamplingBufferFull
                | crate::TargetAdapterScenario::SamplingUnexpectedStop,
            ) => return Err(ControllerContractError::InvalidScriptArguments),
            _ => {}
        }
        Ok(())
    }

    /// Returns the closed root-CMM scenario argument for an operation.
    ///
    /// The deployment scenario remains bound to every request. Root CMM scripts
    /// only accept the stage-local vocabulary: buffer-full changes Configure,
    /// CMM abort changes Start, and every other deployment scenario uses the
    /// normal script path for those stages.
    #[must_use]
    pub const fn script_scenario_for(&self, operation: PerfOperation) -> Option<&'static str> {
        match operation {
            PerfOperation::Configure => Some(match self.scenario {
                crate::TargetAdapterScenario::SamplingBufferFull => "sampling_buffer_full",
                crate::TargetAdapterScenario::TraceOverflow => "trace_overflow",
                crate::TargetAdapterScenario::FlowError => "flow_error",
                _ => "normal",
            }),
            PerfOperation::Start => Some(
                if matches!(self.scenario, crate::TargetAdapterScenario::CmmAbort) {
                    "cmm_abort"
                } else {
                    "normal"
                },
            ),
            _ => None,
        }
    }
}

/// Exact registered firmware image and host-derived sparse S3 measurement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerFirmwareImageBinding {
    /// Immutable source ELF artifact registered in the Session.
    pub source_elf_artifact: Artifact,
    /// Immutable canonical sparse S3 artifact derived by the trusted host.
    pub measurement_artifact: Artifact,
    /// Exact absolute measurement path passed to fixed PRACTICE scripts.
    pub script_input_path: String,
}

impl ControllerFirmwareImageBinding {
    fn validate(&self) -> Result<(), ControllerContractError> {
        if self.source_elf_artifact.id != "firmware-elf"
            || self.source_elf_artifact.kind != "firmware_elf"
            || self.source_elf_artifact.media_type != "application/x-elf"
            || self.measurement_artifact.id != "trace32-firmware-s3"
            || self.measurement_artifact.kind != "trace32_firmware_measurement"
            || self.measurement_artifact.media_type != "application/vnd.motorola-s-record"
            || self.measurement_artifact.producer != "t32perf-controller-firmware-image/v1"
            || self.measurement_artifact.input_artifact_ids != [self.source_elf_artifact.id.clone()]
            || self.measurement_artifact.size_bytes == 0
        {
            return Err(ControllerContractError::InvalidFirmwareImageBinding);
        }
        validate_practice_path("firmware_s3", &self.script_input_path)
    }
}

/// A closed deployment-owned fault action for one controller request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ControllerFaultAction {
    /// Disconnect the TRACE32 endpoint at the fixed stop boundary.
    Trace32DisconnectAtStop,
    /// Disconnect the deployment driver at the fixed export boundary.
    DriverDisconnectAtExport,
    /// Invoke the official t32mcp abort flow at the fixed start boundary.
    CmmAbortAtStart,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// Immutable request prepared before invoking t32mcp.
pub struct ControllerRequest {
    /// Versioned document family.
    pub schema: ControllerRequestSchemaVersion,
    /// Cryptographic transaction binding.
    pub binding: ControllerBinding,
    /// Fixed skill operation.
    pub operation: PerfOperation,
    /// Digest of the operation-specific adapter catalog used for selection.
    /// Endpoint-only operations bind all compiled candidates; target operations
    /// bind the exact Session admission catalog.
    pub adapter_catalog_sha256: Sha256Digest,
    /// Exact admitted target adapter selected after capabilities evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_adapter: Option<ControllerTargetAdapterBinding>,
    /// Closed deployment fault action, present only at its fixed operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fault_action: Option<ControllerFaultAction>,
    /// Exact source firmware and trusted sparse-S3 measurement used by target checks.
    pub firmware_image: ControllerFirmwareImageBinding,
    /// Exact official MCP calls available to the trusted controller.
    pub mcp: ControllerMcpHandoff,
    /// Controller-owned staging path where the final collected wrapper is written.
    pub response_staging_path: ArtifactPath,
    /// Independent bound for the final collected wrapper.
    pub max_response_bytes: u64,
    /// Export reservation, present only for the fixed export script.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<ControllerOutputReservation>,
}

impl ControllerRequest {
    /// Whether this request is a failure-only injection boundary.
    /// A final script response means the deployment driver missed the action.
    #[must_use]
    pub const fn requires_interruption(&self) -> bool {
        self.fault_action.is_some()
    }

    /// Validates the complete request without consulting the filesystem.
    pub fn validate(&self) -> Result<(), ControllerContractError> {
        self.binding.validate()?;
        match (&self.target_adapter, self.operation) {
            (None, PerfOperation::GetCapabilities | PerfOperation::GetHotspots) => {}
            (Some(binding), operation)
                if !matches!(
                    operation,
                    PerfOperation::GetCapabilities | PerfOperation::GetHotspots
                ) =>
            {
                binding.validate()?;
                if binding.controller_protocol != TargetAdapterControllerProtocol::V1 {
                    return Err(ControllerContractError::InvalidScriptArguments);
                }
            }
            _ => return Err(ControllerContractError::InvalidScriptArguments),
        }
        let expected_fault_action =
            match self.target_adapter.as_ref().map(|binding| binding.scenario) {
                Some(crate::TargetAdapterScenario::Trace32Disconnect)
                    if self.operation == PerfOperation::Stop =>
                {
                    Some(ControllerFaultAction::Trace32DisconnectAtStop)
                }
                Some(crate::TargetAdapterScenario::DriverDisconnect)
                    if self.operation == PerfOperation::Export =>
                {
                    Some(ControllerFaultAction::DriverDisconnectAtExport)
                }
                Some(crate::TargetAdapterScenario::CmmAbort)
                    if self.operation == PerfOperation::Start =>
                {
                    Some(ControllerFaultAction::CmmAbortAtStart)
                }
                _ => None,
            };
        if self.fault_action != expected_fault_action {
            return Err(ControllerContractError::InvalidScriptArguments);
        }
        self.firmware_image.validate()?;
        if self.max_response_bytes == 0
            || self.max_response_bytes > MAX_CONTROLLER_MCP_RESPONSE_BYTES
        {
            return Err(ControllerContractError::InvalidResponseLimit {
                actual: self.max_response_bytes,
                maximum: MAX_CONTROLLER_MCP_RESPONSE_BYTES,
            });
        }
        if self.mcp.execute.tool != T32mcpTool::ExecutePracticeSkill
            || self.mcp.collect.tool != T32mcpTool::CollectPracticeSkillResponse
            || self.mcp.abort.tool != T32mcpTool::AbortPracticeSkill
        {
            return Err(ControllerContractError::InvalidToolSequence);
        }
        let arguments = &self.mcp.execute.arguments;
        if arguments.skill_name != T32PERF_SKILL_NAME
            || arguments.script_name != self.operation.script_name()
        {
            return Err(ControllerContractError::InvalidScriptAddress);
        }
        validate_text("response_staging_path", self.response_staging_path.as_str())?;
        let binding = self.binding.binding_sha256.to_string();
        match (&self.output, self.operation) {
            (None, PerfOperation::GetHotspots) => {
                let expected = BTreeMap::from([("binding_sha256".to_owned(), binding)]);
                if arguments.script_args != expected {
                    return Err(ControllerContractError::InvalidScriptArguments);
                }
            }
            (Some(output), PerfOperation::Export) => {
                validate_output(output)?;
                if output.role != ControllerOutputRole::TraceExport {
                    return Err(ControllerContractError::InvalidOutputReservation {
                        message: "perf_export requires a trace_export reservation".to_owned(),
                    });
                }
                let mode = arguments
                    .script_args
                    .get("mode")
                    .ok_or(ControllerContractError::InvalidScriptArguments)?;
                if !matches!(mode.as_str(), "raw_ascii" | "task_events_elf_orti_verified") {
                    return Err(ControllerContractError::InvalidScriptArguments);
                }
                let adapter = self
                    .target_adapter
                    .as_ref()
                    .ok_or(ControllerContractError::InvalidScriptArguments)?;
                let expected_mode = match &adapter.capture_kind {
                    TargetAdapterCaptureKind::Sampling { .. } => "raw_ascii",
                    TargetAdapterCaptureKind::ProgramFlowTaskEvents { .. } => {
                        "task_events_elf_orti_verified"
                    }
                };
                if mode != expected_mode {
                    return Err(ControllerContractError::InvalidScriptArguments);
                }
                let expected = BTreeMap::from([
                    ("binding_sha256".to_owned(), binding),
                    ("mode".to_owned(), mode.clone()),
                    ("output".to_owned(), output.script_output_path.clone()),
                ]);
                if arguments.script_args != expected {
                    return Err(ControllerContractError::InvalidScriptArguments);
                }
            }
            (Some(output), PerfOperation::GetHealth) => {
                validate_output(output)?;
                if output.role != ControllerOutputRole::MachineEvidence
                    || output.max_bytes > MAX_CONTROLLER_EVIDENCE_BYTES
                {
                    return Err(ControllerContractError::InvalidOutputReservation {
                        message:
                            "target-control operation requires bounded machine_evidence output"
                                .to_owned(),
                    });
                }
                let mut expected = BTreeMap::from([
                    ("binding_sha256".to_owned(), binding),
                    (
                        "evidence_output".to_owned(),
                        output.script_output_path.clone(),
                    ),
                    (
                        "firmware_s3".to_owned(),
                        self.firmware_image.script_input_path.clone(),
                    ),
                ]);
                let adapter = self
                    .target_adapter
                    .as_ref()
                    .ok_or(ControllerContractError::InvalidScriptArguments)?;
                let stop_sha256 = arguments
                    .script_args
                    .get("stop_evidence_sha256")
                    .ok_or(ControllerContractError::InvalidScriptArguments)?;
                Sha256Digest::new(stop_sha256.clone())
                    .map_err(|_| ControllerContractError::InvalidScriptArguments)?;
                expected.insert("stop_evidence_sha256".to_owned(), stop_sha256.clone());
                if matches!(
                    &adapter.capture_kind,
                    TargetAdapterCaptureKind::Sampling { .. }
                ) {
                    let pre_stop_state = arguments
                        .script_args
                        .get("pre_stop_state")
                        .ok_or(ControllerContractError::InvalidScriptArguments)?;
                    if !matches!(pre_stop_state.as_str(), "arm" | "break") {
                        return Err(ControllerContractError::InvalidScriptArguments);
                    }
                    expected.insert("pre_stop_state".to_owned(), pre_stop_state.clone());
                    for field in ["recorded_records", "capacity_records"] {
                        let value = arguments
                            .script_args
                            .get(field)
                            .ok_or(ControllerContractError::InvalidScriptArguments)?;
                        if value.parse::<u64>().is_err() {
                            return Err(ControllerContractError::InvalidScriptArguments);
                        }
                        expected.insert(field.to_owned(), value.clone());
                    }
                }
                if arguments.script_args != expected {
                    return Err(ControllerContractError::InvalidScriptArguments);
                }
            }
            (Some(output), PerfOperation::Cleanup) => {
                validate_output(output)?;
                if output.role != ControllerOutputRole::MachineEvidence
                    || output.max_bytes > MAX_CONTROLLER_EVIDENCE_BYTES
                {
                    return Err(ControllerContractError::InvalidOutputReservation {
                        message:
                            "target-control operation requires bounded machine_evidence output"
                                .to_owned(),
                    });
                }
                let initial_target_state = arguments
                    .script_args
                    .get("initial_target_state")
                    .ok_or(ControllerContractError::InvalidScriptArguments)?;
                if !matches!(initial_target_state.as_str(), "running" | "halted") {
                    return Err(ControllerContractError::InvalidScriptArguments);
                }
                let expected = BTreeMap::from([
                    ("binding_sha256".to_owned(), binding),
                    (
                        "evidence_output".to_owned(),
                        output.script_output_path.clone(),
                    ),
                    (
                        "initial_target_state".to_owned(),
                        initial_target_state.clone(),
                    ),
                ]);
                if arguments.script_args != expected {
                    return Err(ControllerContractError::InvalidScriptArguments);
                }
            }
            (Some(output), PerfOperation::Configure) => {
                validate_output(output)?;
                if output.role != ControllerOutputRole::MachineEvidence
                    || output.max_bytes > MAX_CONTROLLER_EVIDENCE_BYTES
                {
                    return Err(ControllerContractError::InvalidOutputReservation {
                        message:
                            "target-control operation requires bounded machine_evidence output"
                                .to_owned(),
                    });
                }
                let initial_target_state = arguments
                    .script_args
                    .get("initial_target_state")
                    .ok_or(ControllerContractError::InvalidScriptArguments)?;
                if !matches!(initial_target_state.as_str(), "running" | "halted") {
                    return Err(ControllerContractError::InvalidScriptArguments);
                }
                let scenario = self
                    .target_adapter
                    .as_ref()
                    .and_then(|binding| binding.script_scenario_for(self.operation))
                    .ok_or(ControllerContractError::InvalidScriptArguments)?;
                if arguments
                    .script_args
                    .get("scenario")
                    .is_none_or(|actual| actual != scenario)
                {
                    return Err(ControllerContractError::InvalidScriptArguments);
                }
                let expected = BTreeMap::from([
                    ("binding_sha256".to_owned(), binding),
                    (
                        "evidence_output".to_owned(),
                        output.script_output_path.clone(),
                    ),
                    (
                        "initial_target_state".to_owned(),
                        initial_target_state.clone(),
                    ),
                    ("scenario".to_owned(), scenario.to_owned()),
                    (
                        "firmware_s3".to_owned(),
                        self.firmware_image.script_input_path.clone(),
                    ),
                ]);
                if arguments.script_args != expected {
                    return Err(ControllerContractError::InvalidScriptArguments);
                }
            }
            (Some(output), PerfOperation::Start) => {
                validate_output(output)?;
                if output.role != ControllerOutputRole::MachineEvidence
                    || output.max_bytes > MAX_CONTROLLER_EVIDENCE_BYTES
                {
                    return Err(ControllerContractError::InvalidOutputReservation {
                        message:
                            "target-control operation requires bounded machine_evidence output"
                                .to_owned(),
                    });
                }
                let adapter = self
                    .target_adapter
                    .as_ref()
                    .ok_or(ControllerContractError::InvalidScriptArguments)?;
                let scenario = adapter
                    .script_scenario_for(self.operation)
                    .ok_or(ControllerContractError::InvalidScriptArguments)?;
                let initial_target_state = arguments
                    .script_args
                    .get("initial_target_state")
                    .ok_or(ControllerContractError::InvalidScriptArguments)?;
                if !matches!(initial_target_state.as_str(), "running" | "halted") {
                    return Err(ControllerContractError::InvalidScriptArguments);
                }
                if arguments
                    .script_args
                    .get("scenario")
                    .is_none_or(|actual| actual != scenario)
                {
                    return Err(ControllerContractError::InvalidScriptArguments);
                }
                let mut expected = BTreeMap::from([
                    ("binding_sha256".to_owned(), binding),
                    (
                        "evidence_output".to_owned(),
                        output.script_output_path.clone(),
                    ),
                    (
                        "initial_target_state".to_owned(),
                        initial_target_state.clone(),
                    ),
                    ("scenario".to_owned(), scenario.to_owned()),
                ]);
                if let Some(capacity_records) = adapter.capture_kind.sampling_capacity_records() {
                    expected.insert("capacity_records".to_owned(), capacity_records.to_string());
                }
                if arguments.script_args != expected {
                    return Err(ControllerContractError::InvalidScriptArguments);
                }
            }
            (Some(output), PerfOperation::Stop) => {
                validate_output(output)?;
                if output.role != ControllerOutputRole::MachineEvidence
                    || output.max_bytes > MAX_CONTROLLER_EVIDENCE_BYTES
                {
                    return Err(ControllerContractError::InvalidOutputReservation {
                        message:
                            "target-control operation requires bounded machine_evidence output"
                                .to_owned(),
                    });
                }
                let adapter = self
                    .target_adapter
                    .as_ref()
                    .ok_or(ControllerContractError::InvalidScriptArguments)?;
                let mut expected = BTreeMap::from([
                    ("binding_sha256".to_owned(), binding),
                    (
                        "evidence_output".to_owned(),
                        output.script_output_path.clone(),
                    ),
                ]);
                if let Some(capacity_records) = adapter.capture_kind.sampling_capacity_records() {
                    expected.insert("capacity_records".to_owned(), capacity_records.to_string());
                }
                if arguments.script_args != expected {
                    return Err(ControllerContractError::InvalidScriptArguments);
                }
            }
            (Some(_), PerfOperation::GetHotspots) => {
                return Err(ControllerContractError::UnexpectedOutputReservation);
            }
            (Some(output), _) => {
                validate_output(output)?;
                if output.role != ControllerOutputRole::MachineEvidence
                    || output.max_bytes > MAX_CONTROLLER_EVIDENCE_BYTES
                {
                    return Err(ControllerContractError::InvalidOutputReservation {
                        message:
                            "target-control operation requires bounded machine_evidence output"
                                .to_owned(),
                    });
                }
                let expected = BTreeMap::from([
                    ("binding_sha256".to_owned(), binding),
                    (
                        "evidence_output".to_owned(),
                        output.script_output_path.clone(),
                    ),
                ]);
                if arguments.script_args != expected {
                    return Err(ControllerContractError::InvalidScriptArguments);
                }
            }
            (None, PerfOperation::Export) => {
                return Err(ControllerContractError::MissingExportReservation);
            }
            (None, _) => {
                return Err(ControllerContractError::MissingEvidenceReservation);
            }
        }
        Ok(())
    }
}

/// Immutable multi-output request prepared before invoking a V2 fixed script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerRequestV2 {
    /// Versioned document family.
    pub schema: ControllerRequestV2SchemaVersion,
    /// Cryptographic transaction binding.
    pub binding: ControllerBinding,
    /// Fixed skill operation.
    pub operation: PerfOperation,
    /// Digest of the operation-specific adapter catalog used for selection.
    /// Endpoint-only operations bind all compiled candidates; target operations
    /// bind the exact Session admission catalog.
    pub adapter_catalog_sha256: Sha256Digest,
    /// Exact admitted target adapter selected after capabilities evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_adapter: Option<ControllerTargetAdapterBinding>,
    /// Closed deployment fault action, present only at its fixed operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fault_action: Option<ControllerFaultAction>,
    /// Exact source firmware and trusted sparse-S3 measurement used by target checks.
    pub firmware_image: ControllerFirmwareImageBinding,
    /// Exact official MCP calls available to the trusted controller.
    pub mcp: ControllerMcpHandoff,
    /// Controller-owned staging path where the final collected wrapper is written.
    pub response_staging_path: ArtifactPath,
    /// Independent bound for the final collected wrapper.
    pub max_response_bytes: u64,
    /// Legacy V1 reservation field; V2 requires this to remain absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<ControllerOutputReservation>,
    /// Closed, deterministically ordered V2 output slots.
    #[schemars(length(min = 1, max = MAX_CONTROLLER_OUTPUT_SLOTS))]
    pub outputs: Vec<ControllerOutputReservationV2>,
}

impl ControllerRequestV2 {
    /// Whether this request is a failure-only injection boundary.
    #[must_use]
    pub const fn requires_interruption(&self) -> bool {
        self.fault_action.is_some()
    }

    /// Validates the complete V2 request without consulting the filesystem.
    pub fn validate(&self) -> Result<(), ControllerContractError> {
        self.binding.validate()?;
        match (&self.target_adapter, self.operation) {
            (Some(binding), operation) if operation.v2_script_name().is_some() => {
                binding.validate()?;
                if binding.controller_protocol
                    != TargetAdapterControllerProtocol::V2CustomEventsExport
                {
                    return Err(ControllerContractError::InvalidScriptArguments);
                }
            }
            _ => return Err(ControllerContractError::InvalidScriptArguments),
        }
        let expected_fault_action =
            match self.target_adapter.as_ref().map(|binding| binding.scenario) {
                Some(crate::TargetAdapterScenario::Trace32Disconnect)
                    if self.operation == PerfOperation::Stop =>
                {
                    Some(ControllerFaultAction::Trace32DisconnectAtStop)
                }
                Some(crate::TargetAdapterScenario::DriverDisconnect)
                    if self.operation == PerfOperation::Export =>
                {
                    Some(ControllerFaultAction::DriverDisconnectAtExport)
                }
                Some(crate::TargetAdapterScenario::CmmAbort)
                    if self.operation == PerfOperation::Start =>
                {
                    Some(ControllerFaultAction::CmmAbortAtStart)
                }
                _ => None,
            };
        if self.fault_action != expected_fault_action || self.output.is_some() {
            return Err(ControllerContractError::InvalidScriptArguments);
        }
        self.firmware_image.validate()?;
        if self.max_response_bytes == 0
            || self.max_response_bytes > MAX_CONTROLLER_MCP_RESPONSE_BYTES
        {
            return Err(ControllerContractError::InvalidResponseLimit {
                actual: self.max_response_bytes,
                maximum: MAX_CONTROLLER_MCP_RESPONSE_BYTES,
            });
        }
        if self.mcp.execute.tool != T32mcpTool::ExecutePracticeSkill
            || self.mcp.collect.tool != T32mcpTool::CollectPracticeSkillResponse
            || self.mcp.abort.tool != T32mcpTool::AbortPracticeSkill
        {
            return Err(ControllerContractError::InvalidToolSequence);
        }
        let arguments = &self.mcp.execute.arguments;
        if arguments.skill_name != T32PERF_SKILL_NAME
            || Some(arguments.script_name.as_str()) != self.operation.v2_script_name()
        {
            return Err(ControllerContractError::InvalidScriptAddress);
        }
        validate_text("response_staging_path", self.response_staging_path.as_str())?;
        validate_v2_output_set(self.operation, &self.outputs)?;
        if self.operation == PerfOperation::Export {
            let collector = self
                .required_target_adapter()?
                .custom_event_collector
                .as_ref()
                .ok_or(ControllerContractError::InvalidScriptArguments)?;
            if self.outputs.len() != 2
                || self.outputs[0].role != ControllerOutputRoleV2::TraceExport
                || self.outputs[1].role != ControllerOutputRoleV2::CustomEvents
                || self.outputs[1].max_bytes != collector.max_output_bytes
            {
                return Err(ControllerContractError::InvalidMultiOutputContract {
                    message: "Controller V2 custom-event export requires exact TraceExport and CustomEvents slots"
                        .to_owned(),
                });
            }
        }

        let mut expected = self.expected_non_output_script_args()?;
        for output in &self.outputs {
            if expected
                .insert(
                    output.role.script_argument().to_owned(),
                    output.script_output_path.clone(),
                )
                .is_some()
            {
                return Err(ControllerContractError::InvalidScriptArguments);
            }
        }
        if arguments.script_args != expected {
            return Err(ControllerContractError::InvalidScriptArguments);
        }
        Ok(())
    }

    fn expected_non_output_script_args(
        &self,
    ) -> Result<BTreeMap<String, String>, ControllerContractError> {
        let arguments = &self.mcp.execute.arguments.script_args;
        let mut expected = BTreeMap::from([(
            "binding_sha256".to_owned(),
            self.binding.binding_sha256.to_string(),
        )]);
        match self.operation {
            PerfOperation::GetCapabilities => {}
            PerfOperation::Configure => {
                let initial = required_target_state_argument(arguments)?;
                let scenario = self.required_script_scenario()?;
                expected.insert("initial_target_state".to_owned(), initial);
                expected.insert("scenario".to_owned(), scenario.to_owned());
                expected.insert(
                    "firmware_s3".to_owned(),
                    self.firmware_image.script_input_path.clone(),
                );
            }
            PerfOperation::Start => {
                let initial = required_target_state_argument(arguments)?;
                let adapter = self.required_target_adapter()?;
                let scenario = adapter
                    .script_scenario_for(self.operation)
                    .ok_or(ControllerContractError::InvalidScriptArguments)?;
                expected.insert("initial_target_state".to_owned(), initial);
                expected.insert("scenario".to_owned(), scenario.to_owned());
                if let Some(capacity) = adapter.capture_kind.sampling_capacity_records() {
                    expected.insert("capacity_records".to_owned(), capacity.to_string());
                }
            }
            PerfOperation::Stop => {
                let adapter = self.required_target_adapter()?;
                if let Some(capacity) = adapter.capture_kind.sampling_capacity_records() {
                    expected.insert("capacity_records".to_owned(), capacity.to_string());
                }
            }
            PerfOperation::GetHealth => {
                let adapter = self.required_target_adapter()?;
                let stop_sha256 = arguments
                    .get("stop_evidence_sha256")
                    .ok_or(ControllerContractError::InvalidScriptArguments)?;
                Sha256Digest::new(stop_sha256.clone())
                    .map_err(|_| ControllerContractError::InvalidScriptArguments)?;
                expected.insert("stop_evidence_sha256".to_owned(), stop_sha256.clone());
                expected.insert(
                    "firmware_s3".to_owned(),
                    self.firmware_image.script_input_path.clone(),
                );
                if adapter.capture_kind.is_sampling() {
                    let pre_stop_state = arguments
                        .get("pre_stop_state")
                        .filter(|value| matches!(value.as_str(), "arm" | "break"))
                        .ok_or(ControllerContractError::InvalidScriptArguments)?;
                    expected.insert("pre_stop_state".to_owned(), pre_stop_state.clone());
                    for field in ["recorded_records", "capacity_records"] {
                        let value = arguments
                            .get(field)
                            .filter(|value| value.parse::<u64>().is_ok())
                            .ok_or(ControllerContractError::InvalidScriptArguments)?;
                        expected.insert(field.to_owned(), value.clone());
                    }
                }
            }
            PerfOperation::Export => {
                let adapter = self.required_target_adapter()?;
                let mode = arguments
                    .get("mode")
                    .ok_or(ControllerContractError::InvalidScriptArguments)?;
                let expected_mode = match &adapter.capture_kind {
                    TargetAdapterCaptureKind::Sampling { .. } => "raw_ascii",
                    TargetAdapterCaptureKind::ProgramFlowTaskEvents { .. } => {
                        "task_events_elf_orti_verified"
                    }
                };
                if mode != expected_mode {
                    return Err(ControllerContractError::InvalidScriptArguments);
                }
                expected.insert("mode".to_owned(), mode.clone());
            }
            PerfOperation::Cleanup => {
                expected.insert(
                    "initial_target_state".to_owned(),
                    required_target_state_argument(arguments)?,
                );
            }
            PerfOperation::GetHotspots => {
                return Err(ControllerContractError::InvalidMultiOutputContract {
                    message: "perf_get_hotspots has no fixed-script V2 output contract".to_owned(),
                });
            }
        }
        Ok(expected)
    }

    fn required_target_adapter(
        &self,
    ) -> Result<&ControllerTargetAdapterBinding, ControllerContractError> {
        self.target_adapter
            .as_ref()
            .ok_or(ControllerContractError::InvalidScriptArguments)
    }

    fn required_script_scenario(&self) -> Result<&'static str, ControllerContractError> {
        self.required_target_adapter()?
            .script_scenario_for(self.operation)
            .ok_or(ControllerContractError::InvalidScriptArguments)
    }
}

/// Host-validated response bound to an immutable controller request artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerResponse {
    /// Versioned document family.
    pub schema: ControllerResponseSchemaVersion,
    /// Binding copied from and verified against the immutable request.
    pub binding: ControllerBinding,
    /// Artifact identifier of the immutable controller request.
    pub request_artifact_id: String,
    /// Digest of the exact immutable controller request bytes.
    pub request_artifact_sha256: Sha256Digest,
    /// Parsed fixed-script response.
    pub script_response: ControllerScriptResponse,
    /// Immutable raw t32mcp wrapper artifact.
    pub raw_response_artifact: Artifact,
    /// Immutable exported trace artifact, only after an `OK` export.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_artifact: Option<Artifact>,
}

/// Host-validated multi-output response bound to an immutable V2 request artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerResponseV2 {
    /// Versioned document family.
    pub schema: ControllerResponseV2SchemaVersion,
    /// Binding copied from and verified against the immutable request.
    pub binding: ControllerBinding,
    /// Artifact identifier of the immutable controller request.
    pub request_artifact_id: String,
    /// Digest of the exact immutable controller request bytes.
    pub request_artifact_sha256: Sha256Digest,
    /// Parsed fixed-script response.
    pub script_response: ControllerScriptResponse,
    /// Immutable raw t32mcp wrapper artifact.
    pub raw_response_artifact: Artifact,
    /// Legacy V1 artifact field; V2 requires this to remain absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_artifact: Option<Artifact>,
    /// Accepted output artifacts in exact request-slot order.
    #[schemars(length(max = MAX_CONTROLLER_OUTPUT_SLOTS))]
    pub output_artifacts: Vec<Artifact>,
}

impl ControllerResponseV2 {
    /// Validates all-or-nothing output acceptance against one immutable V2 request.
    pub fn validate_for(
        &self,
        request: &ControllerRequestV2,
        request_artifact: &Artifact,
    ) -> Result<(), ControllerContractError> {
        request.validate()?;
        if request.requires_interruption() {
            return Err(ControllerContractError::InvalidMultiOutputResponse {
                message: "failure-only V2 request cannot have an accepted final response"
                    .to_owned(),
            });
        }
        request_artifact.validate().map_err(|_| {
            ControllerContractError::InvalidMultiOutputResponse {
                message: "request artifact envelope is invalid".to_owned(),
            }
        })?;
        if self.output_artifact.is_some()
            || self.binding != request.binding
            || self.request_artifact_id != request_artifact.id
            || self.request_artifact_sha256 != request_artifact.sha256
            || self.script_response.operation != request.operation
        {
            return Err(ControllerContractError::InvalidMultiOutputResponse {
                message: "response is not bound to the exact V2 request".to_owned(),
            });
        }
        self.raw_response_artifact.validate().map_err(|_| {
            ControllerContractError::InvalidMultiOutputResponse {
                message: "raw response artifact envelope is invalid".to_owned(),
            }
        })?;
        if self.raw_response_artifact.input_artifact_ids != [request_artifact.id.clone()]
            || request
                .outputs
                .iter()
                .any(|slot| slot.artifact_id == self.raw_response_artifact.id)
        {
            return Err(ControllerContractError::InvalidMultiOutputResponse {
                message: "raw response artifact provenance or identity is invalid".to_owned(),
            });
        }
        if self.script_response.status == crate::PerfStatus::Ok {
            if self.output_artifacts.len() != request.outputs.len() {
                return Err(ControllerContractError::InvalidMultiOutputResponse {
                    message: "successful V2 response must accept every reserved output slot"
                        .to_owned(),
                });
            }
            for (artifact, reservation) in self.output_artifacts.iter().zip(&request.outputs) {
                validate_v2_response_artifact(artifact, reservation, request_artifact)?;
            }
        } else if !self.output_artifacts.is_empty() {
            return Err(ControllerContractError::InvalidMultiOutputResponse {
                message: "non-successful V2 response cannot accept any output slot".to_owned(),
            });
        }
        Ok(())
    }
}

/// Serializable subset of the strict fixed-script frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerScriptResponse {
    /// Fixed script operation.
    pub operation: PerfOperation,
    /// Fixed script status string.
    pub status: crate::PerfStatus,
    /// Stable operation result code.
    pub code: String,
    /// Cleanup evidence when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files_deleted: Option<bool>,
}

impl From<&PerfScriptResponse> for ControllerScriptResponse {
    fn from(response: &PerfScriptResponse) -> Self {
        Self {
            operation: response.operation,
            status: response.status,
            code: response.code.clone(),
            files_deleted: response.files_deleted,
        }
    }
}

/// Immutable request to invoke upstream's ownership-free abort tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerAbortRequest {
    /// Versioned document family.
    pub schema: ControllerAbortRequestSchemaVersion,
    /// Binding copied from the transaction being abandoned.
    pub binding: ControllerBinding,
    /// Artifact identifier of the immutable controller request.
    pub request_artifact_id: String,
    /// Digest of the exact immutable controller request bytes.
    pub request_artifact_sha256: Sha256Digest,
    /// Exact official abort call. Upstream exposes no execution ownership token.
    pub mcp: NoArgumentsToolCall,
    /// Stable fail-closed reason selected by the host controller.
    pub reason: ControllerAbortReason,
}

/// Explicit trusted-controller acknowledgement of upstream's unbound abort result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerAbortReceipt {
    /// Versioned document family.
    pub schema: ControllerAbortReceiptSchemaVersion,
    /// Binding copied from the abandoned transaction.
    pub binding: ControllerBinding,
    /// Artifact identifier of the immutable controller request.
    pub request_artifact_id: String,
    /// Digest of the exact immutable controller request bytes.
    pub request_artifact_sha256: Sha256Digest,
    /// Artifact identifier of the abort plan shown to the trusted caller.
    pub abort_request_artifact_id: String,
    /// Digest of the exact abort plan bytes.
    pub abort_request_artifact_sha256: Sha256Digest,
    /// Honest acknowledgement class; upstream exposes no ownership token.
    pub acknowledgement: ControllerAbortAcknowledgement,
}

/// Trust semantics of a confirmed upstream abort.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ControllerAbortAcknowledgement {
    /// The trusted single-tenant caller observed a successful unit result from
    /// `abort_practice_skill`; the result itself is not transaction-bound.
    UnboundSingleTenantToolSuccess,
}

/// Bounded reasons for abandoning an external execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ControllerAbortReason {
    /// The external script exceeded its deployment deadline.
    Timeout,
    /// The MCP transport failed before a final response was available.
    TransportFailure,
    /// An operator explicitly abandoned the transaction.
    OperatorRequest,
}

/// Stable append-only event names emitted by the trusted host driver.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ControllerDriverEventKind {
    /// The immutable request is durably selected for upstream dispatch.
    DispatchIntent,
    /// The immutable fault action is durably selected for execution.
    FaultIntent,
    /// The selected one-shot fault action returned successfully.
    FaultTriggered,
    /// The host is about to invoke the ownership-free upstream abort tool.
    AbortAttempt,
    /// The host observed a successful return from the upstream abort tool.
    AbortSuccessObserved,
    /// The accepted Start workload is durably selected for execution.
    WorkloadIntent,
    /// The accepted Start workload hook returned successfully.
    WorkloadComplete,
}

impl ControllerDriverEventKind {
    /// Returns the stable file and artifact identifier suffix.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DispatchIntent => "dispatch-intent",
            Self::FaultIntent => "fault-intent",
            Self::FaultTriggered => "fault-triggered",
            Self::AbortAttempt => "abort-attempt",
            Self::AbortSuccessObserved => "abort-success-observed",
            Self::WorkloadIntent => "workload-intent",
            Self::WorkloadComplete => "workload-complete",
        }
    }
}

/// One deterministic append-only host-driver journal marker.
///
/// The marker is evidence of host intent or observation only. It never
/// replaces an accepted controller response or confirmed abort receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerDriverEvent {
    /// Versioned document family.
    pub schema: ControllerDriverEventSchemaVersion,
    /// Stable event name used in the deterministic artifact identity.
    pub event: ControllerDriverEventKind,
    /// Complete immutable controller transaction binding.
    pub binding: ControllerBinding,
    /// Artifact identifier of the immutable controller request.
    pub request_artifact_id: String,
    /// Digest of the exact immutable controller request bytes.
    pub request_artifact_sha256: Sha256Digest,
    /// Fixed controller operation selected by the immutable request.
    pub operation: PerfOperation,
    /// Fault action selected by the immutable request, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fault_action: Option<ControllerFaultAction>,
    /// Abort reason copied from the immutable abort plan for abort events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abort_reason: Option<ControllerAbortReason>,
    /// Abort-plan artifact identifier for abort events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abort_request_artifact_id: Option<String>,
    /// Digest of the exact abort-plan bytes for abort events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abort_request_artifact_sha256: Option<Sha256Digest>,
    /// Accepted initial target state for workload events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_target_state: Option<ControllerTargetState>,
    /// Accepted external workload identity for workload events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_identity: Option<String>,
    /// Immutable performance-run deployment binding artifact referenced by a
    /// workload event.  The bound document carries the full deployment,
    /// workload executable, and signer identities without exposing commands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub performance_run_deployment_binding_artifact_id: Option<String>,
    /// Digest of the immutable deployment-binding artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub performance_run_deployment_binding_artifact_sha256: Option<Sha256Digest>,
    /// Digest covering the complete performance-run deployment block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub performance_run_deployment_sha256: Option<Sha256Digest>,
    /// Digest of the executable that owns workload side effects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_executable_sha256: Option<Sha256Digest>,
}

impl ControllerDriverEvent {
    /// Validates the event against its immutable request and optional abort plan.
    pub fn validate_for(
        &self,
        request: &ControllerRequest,
        request_artifact: &Artifact,
        abort_plan: Option<(&ControllerAbortRequest, &Artifact)>,
    ) -> Result<(), ControllerContractError> {
        self.validate_for_request(
            &request.binding,
            request.operation,
            request.fault_action,
            request_artifact,
            abort_plan,
        )
    }

    /// Validates the event against its immutable V2 request and optional abort plan.
    pub fn validate_for_v2(
        &self,
        request: &ControllerRequestV2,
        request_artifact: &Artifact,
        abort_plan: Option<(&ControllerAbortRequest, &Artifact)>,
    ) -> Result<(), ControllerContractError> {
        self.validate_for_request(
            &request.binding,
            request.operation,
            request.fault_action,
            request_artifact,
            abort_plan,
        )
    }

    fn validate_for_request(
        &self,
        request_binding: &ControllerBinding,
        request_operation: PerfOperation,
        request_fault_action: Option<ControllerFaultAction>,
        request_artifact: &Artifact,
        abort_plan: Option<(&ControllerAbortRequest, &Artifact)>,
    ) -> Result<(), ControllerContractError> {
        self.binding.validate()?;
        if self.binding != *request_binding
            || self.request_artifact_id != request_artifact.id
            || self.request_artifact_sha256 != request_artifact.sha256
            || self.operation != request_operation
            || self.fault_action != request_fault_action
        {
            return Err(ControllerContractError::InvalidDriverEventBinding);
        }
        let has_abort_claim = self.abort_reason.is_some()
            || self.abort_request_artifact_id.is_some()
            || self.abort_request_artifact_sha256.is_some();
        let has_workload_claim = self.initial_target_state.is_some()
            || self.workload_identity.is_some()
            || self
                .performance_run_deployment_binding_artifact_id
                .is_some()
            || self
                .performance_run_deployment_binding_artifact_sha256
                .is_some()
            || self.performance_run_deployment_sha256.is_some()
            || self.workload_executable_sha256.is_some();
        let has_deployment_claim = self
            .performance_run_deployment_binding_artifact_id
            .is_some()
            || self
                .performance_run_deployment_binding_artifact_sha256
                .is_some()
            || self.performance_run_deployment_sha256.is_some()
            || self.workload_executable_sha256.is_some();
        match self.event {
            ControllerDriverEventKind::DispatchIntent => {
                if has_abort_claim || has_workload_claim || has_deployment_claim {
                    return Err(ControllerContractError::InvalidDriverEventContext);
                }
            }
            ControllerDriverEventKind::FaultIntent => {
                if self.fault_action.is_none()
                    || has_abort_claim
                    || has_workload_claim
                    || has_deployment_claim
                {
                    return Err(ControllerContractError::InvalidDriverEventContext);
                }
            }
            ControllerDriverEventKind::FaultTriggered => {
                let Some((abort, abort_artifact)) = abort_plan else {
                    return Err(ControllerContractError::InvalidDriverEventContext);
                };
                if self.fault_action.is_none()
                    || has_workload_claim
                    || has_deployment_claim
                    || self.abort_reason != Some(abort.reason)
                    || self.abort_request_artifact_id.as_deref() != Some(abort_artifact.id.as_str())
                    || self.abort_request_artifact_sha256.as_ref() != Some(&abort_artifact.sha256)
                    || abort.binding != *request_binding
                    || abort.request_artifact_id != request_artifact.id
                    || abort.request_artifact_sha256 != request_artifact.sha256
                    || abort.mcp.tool != T32mcpTool::AbortPracticeSkill
                {
                    return Err(ControllerContractError::InvalidDriverEventContext);
                }
            }
            ControllerDriverEventKind::AbortAttempt
            | ControllerDriverEventKind::AbortSuccessObserved => {
                let Some((abort, abort_artifact)) = abort_plan else {
                    return Err(ControllerContractError::InvalidDriverEventContext);
                };
                if has_workload_claim
                    || has_deployment_claim
                    || self.abort_reason != Some(abort.reason)
                    || self.abort_request_artifact_id.as_deref() != Some(abort_artifact.id.as_str())
                    || self.abort_request_artifact_sha256.as_ref() != Some(&abort_artifact.sha256)
                    || abort.binding != *request_binding
                    || abort.request_artifact_id != request_artifact.id
                    || abort.request_artifact_sha256 != request_artifact.sha256
                    || abort.mcp.tool != T32mcpTool::AbortPracticeSkill
                {
                    return Err(ControllerContractError::InvalidDriverEventContext);
                }
            }
            ControllerDriverEventKind::WorkloadIntent
            | ControllerDriverEventKind::WorkloadComplete => {
                if has_abort_claim
                    || self.operation != PerfOperation::Start
                    || self.initial_target_state.is_none()
                    || self.workload_identity.as_deref().is_none_or(|identity| {
                        validate_text("workload_identity", identity).is_err()
                    })
                    || self
                        .performance_run_deployment_binding_artifact_id
                        .as_deref()
                        .is_some_and(|id| {
                            validate_text("performance_run_deployment_binding_artifact_id", id)
                                .is_err()
                        })
                    || has_deployment_claim
                        && (self
                            .performance_run_deployment_binding_artifact_id
                            .is_none()
                            || self
                                .performance_run_deployment_binding_artifact_sha256
                                .is_none()
                            || self.performance_run_deployment_sha256.is_none()
                            || self.workload_executable_sha256.is_none())
                {
                    return Err(ControllerContractError::InvalidDriverEventContext);
                }
            }
        }
        Ok(())
    }
}

/// A controller contract validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ControllerContractError {
    /// Session identifier is not portable.
    #[error("invalid controller Session id `{value}`")]
    InvalidSessionId {
        /// Rejected value.
        value: String,
    },
    /// A fixed-size lowercase hexadecimal identifier is invalid.
    #[error("controller field `{field}` must be exactly 32 lowercase hexadecimal characters")]
    InvalidHexIdentifier {
        /// Rejected field.
        field: &'static str,
    },
    /// Binding digest does not match its fields.
    #[error("controller binding digest mismatch: expected {expected}, found {actual}")]
    BindingDigestMismatch {
        /// Computed digest.
        expected: String,
        /// Declared digest.
        actual: String,
    },
    /// Response limit is absent or exceeds the protocol bound.
    #[error("controller response limit {actual} is invalid; maximum is {maximum}")]
    InvalidResponseLimit {
        /// Rejected limit.
        actual: u64,
        /// Protocol maximum.
        maximum: u64,
    },
    /// MCP calls do not name the exact official tools.
    #[error("controller MCP handoff does not use the exact execute/collect/abort tool sequence")]
    InvalidToolSequence,
    /// Skill or script is not the fixed repository-owned address.
    #[error("controller request does not address the fixed trace32-perf script")]
    InvalidScriptAddress,
    /// Script arguments differ from the operation contract.
    #[error("controller script arguments do not match the fixed operation contract")]
    InvalidScriptArguments,
    /// Firmware ELF/S3 provenance or PRACTICE handoff path is invalid.
    #[error("controller firmware image binding is invalid")]
    InvalidFirmwareImageBinding,
    /// Export operation lacks its output reservation.
    #[error("controller export request is missing its output reservation")]
    MissingExportReservation,
    /// A target-control operation lacks its evidence reservation.
    #[error("controller target-control request is missing its machine-evidence reservation")]
    MissingEvidenceReservation,
    /// Host-only hotspot handoff contains an output reservation.
    #[error("controller host-processing request contains an unexpected script output")]
    UnexpectedOutputReservation,
    /// A bounded controller text field is invalid.
    #[error("controller field `{field}` is empty, oversized, or contains control characters")]
    InvalidText {
        /// Rejected field.
        field: &'static str,
    },
    /// Output reservation metadata is invalid.
    #[error("controller output reservation is invalid: {message}")]
    InvalidOutputReservation {
        /// Validation detail.
        message: String,
    },
    /// V2 output slots violate their closed roles, bounds, uniqueness, or order.
    #[error("controller V2 output contract is invalid: {message}")]
    InvalidMultiOutputContract {
        /// Validation detail.
        message: String,
    },
    /// A V2 response is partial, mixed-version, reordered, or envelope-inconsistent.
    #[error("controller V2 response is invalid: {message}")]
    InvalidMultiOutputResponse {
        /// Validation detail.
        message: String,
    },
    /// Operation-specific evidence is malformed or semantically incomplete.
    #[error("controller target-control evidence is invalid: {message}")]
    InvalidEvidence {
        /// Validation detail.
        message: String,
    },
    /// Evidence does not echo the exact immutable transaction binding.
    #[error("controller target-control evidence binding does not match its request")]
    EvidenceBindingMismatch,
    /// Driver journal marker does not bind the immutable request.
    #[error("controller driver event is not bound to its immutable request")]
    InvalidDriverEventBinding,
    /// Driver journal marker fields do not match its closed event class.
    #[error("controller driver event context is invalid")]
    InvalidDriverEventContext,
}

/// Computes the digest echoed by fixed PRACTICE scripts.
#[must_use]
pub fn compute_controller_binding_sha256(
    session_id: &str,
    session_operation_id: &str,
    session_request_sha256: &Sha256Digest,
    transaction_id: &str,
    nonce: &str,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    for field in [
        CONTROLLER_BINDING_DOMAIN,
        session_id,
        session_operation_id,
        session_request_sha256.as_str(),
        transaction_id,
        nonce,
    ] {
        let bytes = field.as_bytes();
        hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(bytes);
    }
    Sha256Digest::new(hex_encode(&hasher.finalize())).expect("SHA-256 output is valid")
}

/// Generates the controller JSON Schemas owned by this crate.
#[must_use]
pub fn controller_schema_documents() -> BTreeMap<&'static str, Value> {
    BTreeMap::from([
        (
            "controller-abort-request.schema.json",
            schema_document::<ControllerAbortRequest>(CONTROLLER_ABORT_REQUEST_SCHEMA),
        ),
        (
            "controller-abort-receipt.schema.json",
            schema_document::<ControllerAbortReceipt>(CONTROLLER_ABORT_RECEIPT_SCHEMA),
        ),
        (
            "controller-driver-event.schema.json",
            schema_document::<ControllerDriverEvent>(CONTROLLER_DRIVER_EVENT_SCHEMA),
        ),
        (
            "controller-request.schema.json",
            schema_document::<ControllerRequest>(CONTROLLER_REQUEST_SCHEMA),
        ),
        (
            "controller-request-v2.schema.json",
            schema_document::<ControllerRequestV2>(CONTROLLER_REQUEST_V2_SCHEMA),
        ),
        (
            "controller-response.schema.json",
            schema_document::<ControllerResponse>(CONTROLLER_RESPONSE_SCHEMA),
        ),
        (
            "controller-response-v2.schema.json",
            schema_document::<ControllerResponseV2>(CONTROLLER_RESPONSE_V2_SCHEMA),
        ),
        (
            "controller-capabilities-evidence.schema.json",
            schema_document::<ControllerCapabilitiesEvidence>(
                CONTROLLER_CAPABILITIES_EVIDENCE_SCHEMA,
            ),
        ),
        (
            "controller-capabilities-evidence-v2.schema.json",
            schema_document::<ControllerCapabilitiesEvidenceV2>(
                CONTROLLER_CAPABILITIES_EVIDENCE_V2_SCHEMA,
            ),
        ),
        (
            "controller-configure-evidence.schema.json",
            schema_document::<ControllerConfigureEvidence>(CONTROLLER_CONFIGURE_EVIDENCE_SCHEMA),
        ),
        (
            "controller-start-evidence.schema.json",
            schema_document::<ControllerStartEvidence>(CONTROLLER_START_EVIDENCE_SCHEMA),
        ),
        (
            "controller-start-evidence-v2.schema.json",
            schema_document::<ControllerStartEvidenceV2>(CONTROLLER_START_EVIDENCE_V2_SCHEMA),
        ),
        (
            "controller-stop-evidence.schema.json",
            schema_document::<ControllerStopEvidence>(CONTROLLER_STOP_EVIDENCE_SCHEMA),
        ),
        (
            "controller-stop-evidence-v2.schema.json",
            schema_document::<ControllerStopEvidenceV2>(CONTROLLER_STOP_EVIDENCE_V2_SCHEMA),
        ),
        (
            "controller-health-evidence.schema.json",
            schema_document::<ControllerHealthEvidence>(CONTROLLER_HEALTH_EVIDENCE_SCHEMA),
        ),
        (
            "controller-health-evidence-v2.schema.json",
            schema_document::<ControllerHealthEvidenceV2>(CONTROLLER_HEALTH_EVIDENCE_V2_SCHEMA),
        ),
        (
            "controller-health-evidence-v3.schema.json",
            schema_document::<ControllerProgramFlowHealthEvidence>(
                CONTROLLER_HEALTH_EVIDENCE_V3_SCHEMA,
            ),
        ),
        (
            "controller-cleanup-evidence.schema.json",
            schema_document::<ControllerCleanupEvidence>(CONTROLLER_CLEANUP_EVIDENCE_SCHEMA),
        ),
        (
            "controller-cleanup-evidence-v2.schema.json",
            schema_document::<ControllerCleanupEvidenceV2>(CONTROLLER_CLEANUP_EVIDENCE_V2_SCHEMA),
        ),
    ])
}

struct CapabilitiesEvidenceFields<'a> {
    trace32_release: &'a str,
    trace32_build: u64,
    architecture_package: &'a str,
    target_identifier: &'a str,
    probe_identifier: &'a str,
    capture_modes: &'a [String],
    trace_sinks: &'a [String],
    license_features: &'a [String],
    trace_routing: &'a [String],
    rtos_awareness: Option<&'a str>,
    covered_cores: &'a [u32],
    health_signals: &'a [ControllerHealthSignal],
}

fn validate_capabilities_evidence(
    evidence: &ControllerCapabilitiesEvidence,
) -> Result<(), ControllerContractError> {
    validate_capabilities_fields(CapabilitiesEvidenceFields {
        trace32_release: &evidence.trace32_release,
        trace32_build: evidence.trace32_build,
        architecture_package: &evidence.architecture_package,
        target_identifier: &evidence.target_identifier,
        probe_identifier: &evidence.probe_identifier,
        capture_modes: &evidence.capture_modes,
        trace_sinks: &evidence.trace_sinks,
        license_features: &evidence.license_features,
        trace_routing: &evidence.trace_routing,
        rtos_awareness: evidence.rtos_awareness.as_deref(),
        covered_cores: &evidence.covered_cores,
        health_signals: &evidence.health_signals,
    })
}

fn validate_capabilities_fields(
    fields: CapabilitiesEvidenceFields<'_>,
) -> Result<(), ControllerContractError> {
    for (field, value) in [
        ("trace32_release", fields.trace32_release),
        ("architecture_package", fields.architecture_package),
        ("target_identifier", fields.target_identifier),
        ("probe_identifier", fields.probe_identifier),
    ] {
        validate_text(field, value)?;
    }
    if fields.trace32_build == 0 {
        return Err(ControllerContractError::InvalidEvidence {
            message: "TRACE32 build must be nonzero".to_owned(),
        });
    }
    validate_unique_text_values("capture_modes", fields.capture_modes, 64)?;
    validate_unique_text_values("trace_sinks", fields.trace_sinks, 64)?;
    validate_unique_text_values("license_features", fields.license_features, 128)?;
    validate_unique_text_values("trace_routing", fields.trace_routing, 64)?;
    if let Some(rtos_awareness) = fields.rtos_awareness {
        validate_text("rtos_awareness", rtos_awareness)?;
    }
    validate_unique_cores(fields.covered_cores)?;
    if fields.health_signals.is_empty() || fields.health_signals.len() > 16 {
        return Err(ControllerContractError::InvalidEvidence {
            message: "health_signals must contain 1..=16 entries".to_owned(),
        });
    }
    let unique = fields
        .health_signals
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    if unique.len() != fields.health_signals.len() {
        return Err(ControllerContractError::InvalidEvidence {
            message: "health_signals contains duplicate entries".to_owned(),
        });
    }
    Ok(())
}

fn validate_capabilities_evidence_v2(
    evidence: &ControllerCapabilitiesEvidenceV2,
) -> Result<(), ControllerContractError> {
    validate_capabilities_fields(CapabilitiesEvidenceFields {
        trace32_release: &evidence.trace32_release,
        trace32_build: evidence.trace32_build,
        architecture_package: &evidence.architecture_package,
        target_identifier: &evidence.target_identifier,
        probe_identifier: &evidence.probe_identifier,
        capture_modes: &evidence.capture_modes,
        trace_sinks: &evidence.trace_sinks,
        license_features: &evidence.license_features,
        trace_routing: &evidence.trace_routing,
        rtos_awareness: evidence.rtos_awareness.as_deref(),
        covered_cores: &evidence.covered_cores,
        health_signals: &evidence.health_signals,
    })
}

fn validate_configure_evidence(
    evidence: &ControllerConfigureEvidence,
) -> Result<(), ControllerContractError> {
    validate_text("capture_mode", &evidence.capture_mode)?;
    validate_text("trace_sink", &evidence.trace_sink)?;
    validate_text("workload_identity", &evidence.workload_identity)?;
    validate_unique_cores(&evidence.covered_cores)?;
    if !evidence.filters_verified || !evidence.trigger_verified {
        return Err(ControllerContractError::InvalidEvidence {
            message: "configuration evidence must verify filters and trigger".to_owned(),
        });
    }
    Ok(())
}

fn validate_sampling_health_evidence(
    evidence: &ControllerHealthEvidenceV2,
) -> Result<(), ControllerContractError> {
    if !evidence.capture_stopped {
        return Err(ControllerContractError::InvalidEvidence {
            message: "sampling health evidence requires a stopped capture".to_owned(),
        });
    }
    let supported = evidence
        .supported_signals
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if supported.len() != evidence.supported_signals.len()
        || !supported.contains(&ControllerHealthSignal::SamplingBufferFull)
        || !supported.contains(&ControllerHealthSignal::SamplingUnexpectedStop)
        || (evidence.elf_matches_firmware.is_some()
            != supported.contains(&ControllerHealthSignal::ElfMismatch))
        || !(supported.len() == 2 || supported.len() == 3)
        || supported.iter().any(|signal| {
            matches!(
                signal,
                ControllerHealthSignal::TraceOverflow
                    | ControllerHealthSignal::FlowError
                    | ControllerHealthSignal::TraceGap
                    | ControllerHealthSignal::Truncation
                    | ControllerHealthSignal::TimestampDiscontinuity
                    | ControllerHealthSignal::ProgramFlowClosure
            )
        })
    {
        return Err(ControllerContractError::InvalidEvidence {
            message: "sampling health supported_signals are incomplete or claim flow-decoder facts"
                .to_owned(),
        });
    }
    let sampling = &evidence.sampling;
    if sampling.requested_rate_ns == 0
        || sampling.capacity_records == 0
        || sampling.recorded_records > sampling.capacity_records
        || sampling.recorded_records == 0
        || (sampling.buffer_full && sampling.recorded_records != sampling.capacity_records)
        || (sampling.unexpected_stop && sampling.recorded_records == sampling.capacity_records)
        || (sampling.buffer_full && sampling.unexpected_stop)
    {
        return Err(ControllerContractError::InvalidEvidence {
            message: "sampling health counters are inconsistent".to_owned(),
        });
    }
    Ok(())
}

fn validate_unique_text_values(
    field: &'static str,
    values: &[String],
    maximum: usize,
) -> Result<(), ControllerContractError> {
    if values.is_empty() || values.len() > maximum {
        return Err(ControllerContractError::InvalidEvidence {
            message: format!("{field} must contain 1..={maximum} entries"),
        });
    }
    let mut unique = std::collections::BTreeSet::new();
    for value in values {
        validate_text(field, value)?;
        if !unique.insert(value) {
            return Err(ControllerContractError::InvalidEvidence {
                message: format!("{field} contains duplicate `{value}`"),
            });
        }
    }
    Ok(())
}

fn validate_program_flow_health_evidence(
    evidence: &ControllerProgramFlowHealthEvidence,
) -> Result<(), ControllerContractError> {
    if !evidence.capture_stopped || evidence.supported_signals != PROGRAM_FLOW_HEALTH_SIGNALS {
        return Err(ControllerContractError::InvalidEvidence {
            message:
                "program-flow health requires a stopped capture and the exact closed signal set"
                    .to_owned(),
        });
    }
    Ok(())
}

fn validate_unique_cores(cores: &[u32]) -> Result<(), ControllerContractError> {
    if cores.is_empty() || cores.len() > 256 {
        return Err(ControllerContractError::InvalidEvidence {
            message: "covered_cores must contain 1..=256 entries".to_owned(),
        });
    }
    let unique = cores
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    if unique.len() != cores.len() {
        return Err(ControllerContractError::InvalidEvidence {
            message: "covered_cores contains duplicate entries".to_owned(),
        });
    }
    Ok(())
}

fn validate_hex_identifier(
    field: &'static str,
    value: &str,
) -> Result<(), ControllerContractError> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ControllerContractError::InvalidHexIdentifier { field });
    }
    Ok(())
}

fn validate_text(field: &'static str, value: &str) -> Result<(), ControllerContractError> {
    if value.is_empty()
        || value.len() > MAX_CONTROLLER_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ControllerContractError::InvalidText { field });
    }
    Ok(())
}

fn validate_output(output: &ControllerOutputReservation) -> Result<(), ControllerContractError> {
    for (field, value) in [
        ("script_output_path", output.script_output_path.as_str()),
        ("kind", output.kind.as_str()),
        ("media_type", output.media_type.as_str()),
        ("producer", output.producer.as_str()),
    ] {
        validate_text(field, value)?;
    }
    if !is_portable_artifact_id(&output.artifact_id) {
        return Err(ControllerContractError::InvalidOutputReservation {
            message: "artifact id is not portable".to_owned(),
        });
    }
    if output.max_bytes == 0 {
        return Err(ControllerContractError::InvalidOutputReservation {
            message: "max_bytes must be nonzero".to_owned(),
        });
    }
    if !output.media_type.contains('/') {
        return Err(ControllerContractError::InvalidOutputReservation {
            message: "media type must contain `/`".to_owned(),
        });
    }
    validate_practice_path("script_output_path", &output.script_output_path).map_err(|_| {
        ControllerContractError::InvalidOutputReservation {
            message: "script output path contains a forbidden PRACTICE argument character"
                .to_owned(),
        }
    })?;
    Ok(())
}

fn required_target_state_argument(
    arguments: &BTreeMap<String, String>,
) -> Result<String, ControllerContractError> {
    arguments
        .get("initial_target_state")
        .filter(|value| matches!(value.as_str(), "running" | "halted"))
        .cloned()
        .ok_or(ControllerContractError::InvalidScriptArguments)
}

fn validate_v2_output_set(
    operation: PerfOperation,
    outputs: &[ControllerOutputReservationV2],
) -> Result<(), ControllerContractError> {
    if outputs.is_empty() || outputs.len() > MAX_CONTROLLER_OUTPUT_SLOTS {
        return Err(ControllerContractError::InvalidMultiOutputContract {
            message: format!("output slot count must be 1..={MAX_CONTROLLER_OUTPUT_SLOTS}"),
        });
    }
    let mut roles = BTreeSet::new();
    let mut artifact_ids = BTreeSet::new();
    let mut staged_paths = BTreeSet::new();
    let mut destination_paths = BTreeSet::new();
    let mut script_paths = BTreeSet::new();
    let mut previous_role = None;
    for output in outputs {
        validate_output_v2(output)?;
        if previous_role.is_some_and(|previous| previous >= output.role) {
            return Err(ControllerContractError::InvalidMultiOutputContract {
                message: "output slots are not in canonical role order".to_owned(),
            });
        }
        previous_role = Some(output.role);
        if !roles.insert(output.role)
            || !artifact_ids.insert(output.artifact_id.as_str())
            || !staged_paths.insert(output.staged_relative_path.as_str())
            || !destination_paths.insert(output.destination_relative_path.as_str())
            || !script_paths.insert(output.script_output_path.as_str())
        {
            return Err(ControllerContractError::InvalidMultiOutputContract {
                message: "output roles, IDs, and paths must be unique".to_owned(),
            });
        }
    }
    match operation {
        PerfOperation::Export
            if outputs.first().map(|output| output.role)
                == Some(ControllerOutputRoleV2::TraceExport)
                && outputs.iter().all(|output| {
                    matches!(
                        output.role,
                        ControllerOutputRoleV2::TraceExport
                            | ControllerOutputRoleV2::CustomEvents
                            | ControllerOutputRoleV2::Counters
                            | ControllerOutputRoleV2::ResourceCounters
                    )
                }) =>
        {
            Ok(())
        }
        PerfOperation::GetCapabilities
        | PerfOperation::Configure
        | PerfOperation::Start
        | PerfOperation::Stop
        | PerfOperation::GetHealth
        | PerfOperation::Cleanup
            if outputs.len() == 1 && outputs[0].role == ControllerOutputRoleV2::MachineEvidence =>
        {
            Ok(())
        }
        _ => Err(ControllerContractError::InvalidMultiOutputContract {
            message: "output roles are not allowed for the fixed operation".to_owned(),
        }),
    }
}

fn validate_output_v2(
    output: &ControllerOutputReservationV2,
) -> Result<(), ControllerContractError> {
    for (field, value) in [
        ("staged_relative_path", output.staged_relative_path.as_str()),
        (
            "destination_relative_path",
            output.destination_relative_path.as_str(),
        ),
        ("script_output_path", output.script_output_path.as_str()),
        ("kind", output.kind.as_str()),
        ("media_type", output.media_type.as_str()),
        ("producer", output.producer.as_str()),
    ] {
        validate_text(field, value)?;
    }
    if !is_portable_artifact_id(&output.artifact_id) {
        return Err(ControllerContractError::InvalidMultiOutputContract {
            message: "artifact id is not portable".to_owned(),
        });
    }
    if output.max_bytes == 0 || output.max_bytes > MAX_CONTROLLER_OUTPUT_ARTIFACT_BYTES {
        return Err(ControllerContractError::InvalidMultiOutputContract {
            message: format!("max_bytes must be 1..={MAX_CONTROLLER_OUTPUT_ARTIFACT_BYTES}"),
        });
    }
    if output.role == ControllerOutputRoleV2::MachineEvidence
        && output.max_bytes > MAX_CONTROLLER_EVIDENCE_BYTES
    {
        return Err(ControllerContractError::InvalidMultiOutputContract {
            message: "machine_evidence exceeds the evidence byte bound".to_owned(),
        });
    }
    if !output.media_type.contains('/') {
        return Err(ControllerContractError::InvalidMultiOutputContract {
            message: "media type must contain `/`".to_owned(),
        });
    }
    validate_practice_path("script_output_path", &output.script_output_path).map_err(|_| {
        ControllerContractError::InvalidMultiOutputContract {
            message: "script output path contains a forbidden PRACTICE argument character"
                .to_owned(),
        }
    })?;
    if output.script_output_path.contains('\\')
        || output.script_output_path.contains("//")
        || output
            .script_output_path
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
    {
        return Err(ControllerContractError::InvalidMultiOutputContract {
            message: "script output path is not in portable forward-slash form".to_owned(),
        });
    }
    Ok(())
}

fn validate_v2_response_artifact(
    artifact: &Artifact,
    reservation: &ControllerOutputReservationV2,
    request_artifact: &Artifact,
) -> Result<(), ControllerContractError> {
    artifact
        .validate()
        .map_err(|_| ControllerContractError::InvalidMultiOutputResponse {
            message: "output artifact envelope is invalid".to_owned(),
        })?;
    if artifact.id != reservation.artifact_id
        || artifact.kind != reservation.kind
        || artifact.relative_path != reservation.destination_relative_path
        || artifact.media_type != reservation.media_type
        || artifact.producer != reservation.producer
        || artifact.size_bytes > reservation.max_bytes
        || artifact.input_artifact_ids != [request_artifact.id.clone()]
    {
        return Err(ControllerContractError::InvalidMultiOutputResponse {
            message: format!(
                "artifact `{}` does not match its ordered request slot",
                artifact.id
            ),
        });
    }
    Ok(())
}

fn validate_practice_path(field: &'static str, value: &str) -> Result<(), ControllerContractError> {
    validate_text(field, value)?;
    let forbidden = ['=', '"', '\'', ';', '&'];
    if value
        .chars()
        .any(|character| forbidden.contains(&character))
    {
        return Err(ControllerContractError::InvalidFirmwareImageBinding);
    }
    Ok(())
}

fn schema_document<T: JsonSchema>(id: &'static str) -> Value {
    let mut schema =
        serde_json::to_value(schema_for!(T)).expect("schema serialization is infallible");
    schema
        .as_object_mut()
        .expect("root schemas are objects")
        .insert("$id".to_owned(), Value::String(id.to_owned()));
    schema
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
