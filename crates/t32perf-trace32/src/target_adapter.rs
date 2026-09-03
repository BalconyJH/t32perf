//! Build-gated target-adapter profiles and deterministic capture transitions.
//!
//! This module deliberately contains no free-form PRACTICE command strings.
//! A production adapter is compiled code selected by an exact, qualified
//! profile. The profile is an auditable compatibility and behavior contract;
//! it is not an instruction language supplied by a caller.

use std::collections::{BTreeMap, BTreeSet};

use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use t32perf_model::{
    AdapterInfo, CaptureCapabilities, CaptureConfigDocument, CaptureConfigSchemaVersion,
    CaptureDurationConfig, CaptureRtosAwarenessConfig, CaptureSinkConfig, CaptureTimestampConfig,
    CaptureTriggerConfig, InitialTargetState, MetricSupportEntry, MetricSupportLevel, Properties,
    Sha256Digest, is_portable_artifact_id, strict_json,
};
use thiserror::Error;

use crate::{
    ControllerCapabilitiesEvidence, ControllerCapabilitiesEvidenceV2, ControllerEvidence,
    ControllerHealthSignal, ControllerTargetState, PROGRAM_FLOW_HEALTH_SIGNALS, PerfOperation,
    PerfScriptResponse, PerfStatus,
};

/// Schema identifier for a deployment-owned target-adapter profile.
pub const TARGET_ADAPTER_PROFILE_SCHEMA: &str = "t32perf.target-adapter-profile/v1";
/// Schema identifier for recovery evidence after an interrupted target operation.
pub const TARGET_ADAPTER_RECOVERY_EVIDENCE_SCHEMA: &str =
    "t32perf.target-adapter-recovery-evidence/v1";
/// Schema identifier for a verified target-adapter qualification receipt.
pub const TARGET_ADAPTER_QUALIFICATION_RECEIPT_SCHEMA: &str =
    "t32perf.target-adapter-qualification-receipt/v1";
/// Maximum admitted frequency for one custom-event source clock.
pub const MAX_CUSTOM_EVENT_CLOCK_FREQUENCY_HZ: u64 = 1_000_000_000_000;
/// Maximum immutable raw custom-event output admitted by a collector contract.
pub const MAX_CUSTOM_EVENT_COLLECTOR_OUTPUT_BYTES: u64 = 1_u64 << 40;
/// Schema identifier for a deployment-owned target-adapter scenario selection.
pub const TARGET_ADAPTER_SCENARIO_SELECTION_SCHEMA: &str = "t32perf.target-adapter-scenario/v1";
/// Canonical digest of the checked TC234L root dispatch and adapter bundle.
///
/// The bundle manifest test recomputes this value from sorted path/digest
/// entries and fails whenever any executed script or fixed manifest drifts.
pub const TC234L_SNOOPER_BUILD190766_IMPLEMENTATION_SHA256: &str =
    "a366536ad33ce118eff8a79ebe12367e67bdc02c41f5f8e4457d54b83b6a30e4";
/// SHA-256 of the canonical sparse S3 representation of the fixed deployment ELF.
pub const TC234L_SNOOPER_BUILD190766_S3_SHA256: &str =
    "26753910bfc091b113dbed562ebbf989f810504810d81260db4a7067e524e347";
/// Exact byte size of the canonical sparse S3 representation.
pub const TC234L_SNOOPER_BUILD190766_S3_SIZE_BYTES: u64 = 148_955;

/// One compiled, deployment-selectable target-adapter bundle.
///
/// The directory is relative to the TRACE32 skill package root and identifies
/// the sole adapter subtree permitted to provide adapter-private bundle
/// members.  The candidate deliberately has no qualification receipt: that
/// evidence is deployment-owned and is admitted separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetAdapterBundleDescriptor {
    /// Portable directory relative to the TRACE32 skill package root.
    pub bundle_relative_directory: &'static str,
    /// Exact software candidate represented by this bundle.
    pub candidate_profile: TargetAdapterProfile,
}

impl TargetAdapterBundleDescriptor {
    /// Validates the closed compiled-bundle descriptor contract.
    pub fn validate(&self) -> Result<(), TargetAdapterError> {
        validate_bundle_relative_directory(self.bundle_relative_directory)?;
        self.candidate_profile.validate()?;
        if self.candidate_profile.qualification_sha256.is_some() {
            return Err(TargetAdapterError::InvalidProfile {
                message: "compiled bundle candidate must not contain qualification evidence"
                    .to_owned(),
            });
        }
        Ok(())
    }

    /// Verifies that an admitted profile differs from this candidate only by
    /// its deployment-owned qualification receipt digest.
    pub fn validate_admitted_profile(
        &self,
        admitted: &TargetAdapterProfile,
    ) -> Result<(), TargetAdapterError> {
        let mut expected = self.candidate_profile.clone();
        expected.qualification_sha256 = admitted.qualification_sha256.clone();
        if *admitted != expected {
            return Err(TargetAdapterError::InvalidProfile {
                message:
                    "admitted target-adapter profile does not match its compiled bundle candidate"
                        .to_owned(),
            });
        }
        Ok(())
    }

    /// Verifies an exact controller binding against this descriptor and the
    /// already-admitted profile selected for the Session.
    pub fn validate_controller_binding(
        &self,
        admitted: &TargetAdapterProfile,
        binding: &crate::ControllerTargetAdapterBinding,
    ) -> Result<(), TargetAdapterError> {
        self.validate_admitted_profile(admitted)?;
        let capture_kind = admitted
            .scenario(binding.scenario)
            .ok_or_else(|| TargetAdapterError::InvalidProfile {
                message: "controller binding selects an unsupported adapter scenario".to_owned(),
            })?
            .capture
            .capture_kind
            .clone();
        let profile_sha256 = admitted.digest()?;
        if binding.adapter_id != admitted.adapter_id
            || binding.adapter_version != admitted.adapter_version
            || binding.trace32_release != admitted.build_gate.trace32_release
            || binding.trace32_build != admitted.build_gate.minimum_build
            || binding.architecture_package != admitted.build_gate.architecture_package
            || binding.target_identifier != admitted.target_identifier
            || binding.probe_identifier != admitted.probe_identifier
            || binding.profile_sha256 != profile_sha256
            || binding.implementation_sha256 != self.candidate_profile.implementation_sha256
            || binding.capture_kind != capture_kind
            || binding.controller_protocol != admitted.controller_protocol
            || binding.custom_event_collector != admitted.custom_event_collector
            || binding.qualification_sha256 != admitted.qualification_sha256
        {
            return Err(TargetAdapterError::InvalidProfile {
                message:
                    "controller target-adapter binding does not match the selected compiled bundle"
                        .to_owned(),
            });
        }
        Ok(())
    }
}

/// Returns the closed catalog of production target-adapter bundles compiled
/// into this binary.
///
/// A deployment must select exactly one descriptor by its expected release
/// bundle digest.  This catalog intentionally contains only TC234L until a
/// distinct production adapter has independent deployment evidence.
#[must_use]
pub fn compiled_target_adapter_bundle_catalog() -> Vec<TargetAdapterBundleDescriptor> {
    vec![TargetAdapterBundleDescriptor {
        bundle_relative_directory: "scripts/adapters/tc234l-build190766",
        candidate_profile: tc234l_build190766_candidate_profile(),
    }]
}

const MAX_PROFILE_TEXT_BYTES: usize = 4 * 1024;
const MAX_QUALIFICATION_RECEIPT_BYTES: usize = 64 * 1024;

/// Supported target-adapter profile schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum TargetAdapterProfileSchemaVersion {
    /// Version 1.
    #[serde(rename = "t32perf.target-adapter-profile/v1")]
    V1,
}

/// Supported target-adapter recovery-evidence schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum TargetAdapterRecoveryEvidenceSchemaVersion {
    /// Version 1.
    #[serde(rename = "t32perf.target-adapter-recovery-evidence/v1")]
    V1,
}

/// Supported target-adapter qualification-receipt schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum TargetAdapterQualificationReceiptSchemaVersion {
    /// Version 1.
    #[serde(rename = "t32perf.target-adapter-qualification-receipt/v1")]
    V1,
}

/// Supported target-adapter scenario-selection schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum TargetAdapterScenarioSelectionSchemaVersion {
    /// Version 1.
    #[serde(rename = "t32perf.target-adapter-scenario/v1")]
    V1,
}

/// Deployment qualification bound to exact implementation and HIL evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetAdapterQualificationReceipt {
    /// Versioned receipt family.
    pub schema: TargetAdapterQualificationReceiptSchemaVersion,
    /// Stable adapter identity.
    pub adapter_id: String,
    /// Exact adapter version.
    pub adapter_version: String,
    /// Profile identity with the receipt digest field cleared to avoid a cycle.
    pub candidate_profile_sha256: Sha256Digest,
    /// Deployment-verified expected release-bundle manifest digest.
    ///
    /// Upstream t32mcp does not runtime-attest the installed skill bytes.
    pub implementation_sha256: Sha256Digest,
    /// Canonical TRACE32 release.
    pub trace32_release: String,
    /// Exact TRACE32 build.
    pub trace32_build: u64,
    /// Exact architecture package.
    pub architecture_package: String,
    /// Exact target identity.
    pub target_identifier: String,
    /// Exact probe identity.
    pub probe_identifier: String,
    /// Exact firmware ELF artifact SHA-256.
    pub firmware_elf_sha256: Sha256Digest,
    /// Exact official t32mcp implementation version qualified by HIL.
    pub t32mcp_version: String,
    /// Immutable HIL verification receipt digest.
    pub hil_verification_receipt_sha256: Sha256Digest,
}

/// A fixed target-adapter execution scenario.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TargetAdapterScenario {
    /// Normal capture without injected faults.
    Normal,
    /// Deliberately force trace-buffer or transport overflow.
    TraceOverflow,
    /// Deliberately force a TRACE32 flow error.
    FlowError,
    /// Use a fixed small SNOOPer Stack buffer and let it stop at capacity.
    SamplingBufferFull,
    /// Observe an unclassified early SNOOPer stop.
    SamplingUnexpectedStop,
    /// Disconnect TRACE32 during a fixed operation.
    Trace32Disconnect,
    /// Disconnect the deployment driver during a fixed operation.
    DriverDisconnect,
    /// Abort the active CMM transaction through the fixed t32mcp abort flow.
    CmmAbort,
}

impl TargetAdapterScenario {
    /// Returns the exact deployment-intent spelling used by controller requests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::TraceOverflow => "trace_overflow",
            Self::FlowError => "flow_error",
            Self::SamplingBufferFull => "sampling_buffer_full",
            Self::SamplingUnexpectedStop => "sampling_unexpected_stop",
            Self::Trace32Disconnect => "trace32_disconnect",
            Self::DriverDisconnect => "driver_disconnect",
            Self::CmmAbort => "cmm_abort",
        }
    }

    /// Parses one closed deployment-owned scenario identifier.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        [
            Self::Normal,
            Self::TraceOverflow,
            Self::FlowError,
            Self::SamplingBufferFull,
            Self::SamplingUnexpectedStop,
            Self::Trace32Disconnect,
            Self::DriverDisconnect,
            Self::CmmAbort,
        ]
        .into_iter()
        .find(|scenario| scenario.as_str() == value)
    }
}

/// Immutable deployment-owned selection of one compiled adapter scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetAdapterScenarioSelection {
    /// Versioned selection document family.
    pub schema: TargetAdapterScenarioSelectionSchemaVersion,
    /// Closed compiled scenario identifier.
    pub scenario: TargetAdapterScenario,
    /// Whether this candidate-only selection is restricted to evidence capture.
    pub evidence_only: bool,
}

impl TargetAdapterScenarioSelection {
    /// Validates that this selection is admitted by the reconstructed Session policy.
    pub fn validate_for_allowed(
        &self,
        allowed: &[TargetAdapterScenario],
    ) -> Result<(), TargetAdapterError> {
        if !allowed.contains(&self.scenario) {
            return Err(TargetAdapterError::InvalidScenarioSelection {
                message: "deployment-selected scenario is not admitted for this Session".to_owned(),
            });
        }
        Ok(())
    }
}

/// The operation at which an interruption scenario is injected.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TargetAdapterFaultPoint {
    /// During fixed target configuration.
    Configure,
    /// During capture start or workload launch.
    Start,
    /// During workload completion or capture stop.
    Stop,
    /// During build-gated health collection.
    Health,
    /// During fixed trace export.
    Export,
}

impl TargetAdapterFaultPoint {
    fn operation(self) -> PerfOperation {
        match self {
            Self::Configure => PerfOperation::Configure,
            Self::Start => PerfOperation::Start,
            Self::Stop => PerfOperation::Stop,
            Self::Health => PerfOperation::GetHealth,
            Self::Export => PerfOperation::Export,
        }
    }
}

/// Fixed behavior for one adapter scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetAdapterScenarioContract {
    /// Scenario selected by trusted deployment code.
    pub scenario: TargetAdapterScenario,
    /// Interruption point for disconnect and abort scenarios.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fault_point: Option<TargetAdapterFaultPoint>,
    /// Complete fixed capture contract for this scenario.
    pub capture: TargetAdapterCaptureContract,
}

/// Exact TRACE32/build/architecture compatibility gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetAdapterBuildGate {
    /// Exact TRACE32 release label.
    pub trace32_release: String,
    /// Inclusive nonzero minimum build.
    #[schemars(range(min = 1))]
    pub minimum_build: u64,
    /// Inclusive nonzero maximum build.
    #[schemars(range(min = 1))]
    pub maximum_build: u64,
    /// Exact architecture-package identity.
    pub architecture_package: String,
}

/// Closed Controller request/response protocol selected by one adapter profile.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TargetAdapterControllerProtocol {
    /// Single-output Controller request/response protocol.
    #[default]
    V1,
    /// Multi-output Controller V2 with one trace export and one custom-event export.
    V2CustomEventsExport,
}

impl TargetAdapterControllerProtocol {
    /// Whether this is the legacy single-output Controller protocol.
    #[must_use]
    pub const fn is_v1(&self) -> bool {
        matches!(self, Self::V1)
    }
}

/// Closed raw custom-event wire representation emitted by an adapter collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TargetAdapterCustomEventWireProtocol {
    /// T32Perf C SDK wire format version 1.
    CWireV1,
}

/// Closed merge-order policy for combining custom events with program flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TargetAdapterCustomEventMergeOrder {
    /// Reject equal-timestamp records whose cross-source order is not authoritative.
    RejectAmbiguousTies,
}

/// Exact shared clock domain used by one custom-event collector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetAdapterCustomEventClockContract {
    /// Stable clock-domain identity shared with the program-flow export.
    pub clock_id: String,
    /// Integer raw-tick frequency.
    #[schemars(range(min = 1, max = MAX_CUSTOM_EVENT_CLOCK_FREQUENCY_HZ))]
    pub frequency_hz: u64,
    /// Raw timestamp modulus used for bounded wrap expansion.
    #[schemars(range(min = 2))]
    pub timestamp_modulus: u64,
    /// Maximum accepted forward step between adjacent raw records.
    #[schemars(range(min = 1))]
    pub max_forward_ticks: u64,
    /// Exact raw timestamp assigned to the session origin.
    pub origin_ticks: u64,
    /// Session-relative nanoseconds assigned to `origin_ticks`.
    pub origin_ns: i64,
}

/// Adapter-owned custom-event collection and normalization contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetAdapterCustomEventCollectorContract {
    /// Exact target-side wire representation.
    pub wire_protocol: TargetAdapterCustomEventWireProtocol,
    /// Stable normalized source identity.
    pub source_id: String,
    /// Core affinity assigned to emitted custom events.
    pub core_id: u32,
    /// Exact clock-domain conversion and origin.
    pub clock: TargetAdapterCustomEventClockContract,
    /// Versioned target-to-host transport identity.
    pub transport: String,
    /// Fixed immutable deployment mapping artifact identity.
    pub mapping_artifact_id: String,
    /// Fixed immutable instrumentation-overhead evidence identity.
    pub instrumentation_overhead_artifact_id: String,
    /// Independent bound for the raw custom-event output slot.
    #[schemars(range(min = 1, max = MAX_CUSTOM_EVENT_COLLECTOR_OUTPUT_BYTES))]
    pub max_output_bytes: u64,
    /// Exact cross-source ordering policy.
    pub merge_order: TargetAdapterCustomEventMergeOrder,
}

impl TargetAdapterCustomEventCollectorContract {
    pub(crate) fn validate(&self) -> Result<(), TargetAdapterError> {
        for (field, value) in [
            ("custom_event_collector.source_id", self.source_id.as_str()),
            (
                "custom_event_collector.clock.clock_id",
                self.clock.clock_id.as_str(),
            ),
            ("custom_event_collector.transport", self.transport.as_str()),
        ] {
            validate_text(field, value)?;
        }
        if !is_portable_artifact_id(&self.source_id) {
            return Err(TargetAdapterError::InvalidProfile {
                message: "custom-event source_id is not portable".to_owned(),
            });
        }
        for (field, artifact_id) in [
            (
                "custom_event_collector.mapping_artifact_id",
                self.mapping_artifact_id.as_str(),
            ),
            (
                "custom_event_collector.instrumentation_overhead_artifact_id",
                self.instrumentation_overhead_artifact_id.as_str(),
            ),
        ] {
            validate_text(field, artifact_id)?;
            if !is_portable_artifact_id(artifact_id) {
                return Err(TargetAdapterError::InvalidProfile {
                    message: format!("{field} is not a portable artifact ID"),
                });
            }
        }
        if self.mapping_artifact_id == self.instrumentation_overhead_artifact_id {
            return Err(TargetAdapterError::InvalidProfile {
                message: "custom-event mapping and overhead artifact IDs must be distinct"
                    .to_owned(),
            });
        }
        if self.clock.frequency_hz == 0
            || self.clock.frequency_hz > MAX_CUSTOM_EVENT_CLOCK_FREQUENCY_HZ
            || self.clock.timestamp_modulus < 2
            || self.clock.max_forward_ticks == 0
            || self.clock.max_forward_ticks >= self.clock.timestamp_modulus
            || self.clock.origin_ticks >= self.clock.timestamp_modulus
        {
            return Err(TargetAdapterError::InvalidProfile {
                message:
                    "custom-event clock frequency, modulus, forward bound, or origin is invalid"
                        .to_owned(),
            });
        }
        if self.clock.origin_ns != 0 {
            return Err(TargetAdapterError::InvalidProfile {
                message: "custom-event clock must use the TASKEVENTS 0ns session origin".to_owned(),
            });
        }
        if self.max_output_bytes == 0
            || self.max_output_bytes > MAX_CUSTOM_EVENT_COLLECTOR_OUTPUT_BYTES
        {
            return Err(TargetAdapterError::InvalidProfile {
                message: format!(
                    "custom-event output bound must be 1..={MAX_CUSTOM_EVENT_COLLECTOR_OUTPUT_BYTES}"
                ),
            });
        }
        Ok(())
    }
}

/// Capture-family-specific contract without cross-family placeholder fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TargetAdapterCaptureKind {
    /// Bounded statistical sampling where Stack capacity is measured in records.
    Sampling {
        /// Exact SNOOPer Stack capacity in records.
        #[schemars(range(min = 1))]
        capacity_records: u64,
    },
    /// Complete program-flow capture exported through the strict TASKEVENTS profile.
    ProgramFlowTaskEvents {
        /// Exact deployment-owned TASKEVENTS mapping/export profile identifier.
        export_profile_id: String,
        /// Exact RTOS-awareness package identity verified by the adapter.
        rtos_awareness: String,
        /// Exact timestamp clock identity used by the TASKEVENTS export.
        timestamp_clock_id: String,
        /// Immutable ORTI metadata artifact identifier.
        orti_artifact_id: String,
        /// Immutable task/ISR/runnable marker metadata artifact identifier.
        task_marker_artifact_id: String,
    },
}

impl TargetAdapterCaptureKind {
    /// Returns the bounded sampling capacity, or `None` for program flow.
    #[must_use]
    pub const fn sampling_capacity_records(&self) -> Option<u64> {
        match self {
            Self::Sampling { capacity_records } => Some(*capacity_records),
            Self::ProgramFlowTaskEvents { .. } => None,
        }
    }

    /// Returns whether this contract is statistical sampling.
    #[must_use]
    pub const fn is_sampling(&self) -> bool {
        matches!(self, Self::Sampling { .. })
    }

    /// Returns whether this contract is TASKEVENTS program flow.
    #[must_use]
    pub const fn is_program_flow_task_events(&self) -> bool {
        matches!(self, Self::ProgramFlowTaskEvents { .. })
    }
}

/// Fixed capture configuration enforced by compiled adapter code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetAdapterCaptureContract {
    /// Semantic configuration SHA-256 for every supported initial state.
    pub configuration_sha256_by_initial_state: BTreeMap<ControllerTargetState, Sha256Digest>,
    /// Exact capture mode.
    pub capture_mode: String,
    /// Exact trace sink.
    pub trace_sink: String,
    /// Explicit capture-family contract.
    pub capture_kind: TargetAdapterCaptureKind,
    /// Whether timestamps are required.
    pub timestamp_enabled: bool,
    /// Fixed workload identity.
    pub workload_identity: String,
    /// Exact covered cores.
    #[schemars(length(min = 1, max = 256))]
    pub covered_cores: Vec<u32>,
    /// Initial target states with explicitly implemented semantics.
    #[schemars(length(min = 1, max = 2))]
    pub supported_initial_states: Vec<ControllerTargetState>,
}

impl<'de> Deserialize<'de> for TargetAdapterCaptureContract {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Tagged {
            configuration_sha256_by_initial_state: BTreeMap<ControllerTargetState, Sha256Digest>,
            capture_mode: String,
            trace_sink: String,
            capture_kind: TargetAdapterCaptureKind,
            timestamp_enabled: bool,
            workload_identity: String,
            covered_cores: Vec<u32>,
            supported_initial_states: Vec<ControllerTargetState>,
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct LegacySampling {
            configuration_sha256_by_initial_state: BTreeMap<ControllerTargetState, Sha256Digest>,
            capture_mode: String,
            trace_sink: String,
            capacity_records: u64,
            timestamp_enabled: bool,
            workload_identity: String,
            covered_cores: Vec<u32>,
            supported_initial_states: Vec<ControllerTargetState>,
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Tagged(Tagged),
            LegacySampling(LegacySampling),
        }

        Ok(match Wire::deserialize(deserializer)? {
            Wire::Tagged(value) => Self {
                configuration_sha256_by_initial_state: value.configuration_sha256_by_initial_state,
                capture_mode: value.capture_mode,
                trace_sink: value.trace_sink,
                capture_kind: value.capture_kind,
                timestamp_enabled: value.timestamp_enabled,
                workload_identity: value.workload_identity,
                covered_cores: value.covered_cores,
                supported_initial_states: value.supported_initial_states,
            },
            Wire::LegacySampling(value) => Self {
                configuration_sha256_by_initial_state: value.configuration_sha256_by_initial_state,
                capture_mode: value.capture_mode,
                trace_sink: value.trace_sink,
                capture_kind: TargetAdapterCaptureKind::Sampling {
                    capacity_records: value.capacity_records,
                },
                timestamp_enabled: value.timestamp_enabled,
                workload_identity: value.workload_identity,
                covered_cores: value.covered_cores,
                supported_initial_states: value.supported_initial_states,
            },
        })
    }
}

/// A qualified target-adapter profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetAdapterProfile {
    /// Versioned document family.
    pub schema: TargetAdapterProfileSchemaVersion,
    /// Stable compiled adapter identifier.
    pub adapter_id: String,
    /// Exact compiled adapter version.
    pub adapter_version: String,
    /// Deployment-verified expected SHA-256 of the release bundle manifest.
    ///
    /// This is not runtime attestation of the skill bytes resolved by t32mcp.
    pub implementation_sha256: Sha256Digest,
    /// SHA-256 of the immutable qualification receipt admitted by deployment.
    ///
    /// A missing value denotes a software-complete candidate that cannot be
    /// registered for production selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualification_sha256: Option<Sha256Digest>,
    /// Exact TRACE32 compatibility gate.
    pub build_gate: TargetAdapterBuildGate,
    /// Exact target identity.
    pub target_identifier: String,
    /// Exact probe identity expected by this deployment profile.
    pub probe_identifier: String,
    /// Exact license features required by compiled adapter code.
    #[schemars(length(min = 1, max = 128))]
    pub license_features: Vec<String>,
    /// Exact target-to-probe routing identities.
    #[schemars(length(min = 1, max = 64))]
    pub trace_routing: Vec<String>,
    /// Exact firmware ELF artifact SHA-256 qualified for this adapter profile.
    pub firmware_elf_sha256: Sha256Digest,
    /// Health facts this exact build adapter can obtain without inference.
    #[schemars(length(min = 1, max = 16))]
    pub health_signals: Vec<ControllerHealthSignal>,
    /// Observation-family capability ceiling for this adapter.
    pub capabilities: CaptureCapabilities,
    /// Explicit Controller request/response protocol; never inferred from evidence versions.
    #[serde(
        default,
        skip_serializing_if = "TargetAdapterControllerProtocol::is_v1"
    )]
    pub controller_protocol: TargetAdapterControllerProtocol,
    /// Exact custom-event collector contract, absent for adapters without custom-event support.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_event_collector: Option<TargetAdapterCustomEventCollectorContract>,
    /// Scenarios implemented by compiled adapter code.
    #[schemars(length(min = 1, max = 16))]
    pub scenarios: Vec<TargetAdapterScenarioContract>,
}

impl TargetAdapterProfile {
    /// Validates the profile as a closed, qualified selection contract.
    pub fn validate(&self) -> Result<(), TargetAdapterError> {
        for (field, value) in [
            ("adapter_id", self.adapter_id.as_str()),
            ("adapter_version", self.adapter_version.as_str()),
            ("trace32_release", self.build_gate.trace32_release.as_str()),
            (
                "architecture_package",
                self.build_gate.architecture_package.as_str(),
            ),
            ("target_identifier", self.target_identifier.as_str()),
            ("probe_identifier", self.probe_identifier.as_str()),
        ] {
            validate_text(field, value)?;
        }
        if self.build_gate.minimum_build == 0
            || self.build_gate.minimum_build > self.build_gate.maximum_build
        {
            return Err(TargetAdapterError::InvalidProfile {
                message: "build gate has a zero or reversed build range".to_owned(),
            });
        }
        validate_unique_text("license_features", &self.license_features, 128)?;
        validate_unique_text("trace_routing", &self.trace_routing, 64)?;
        validate_unique("health_signals", &self.health_signals, 16)?;
        self.capabilities
            .validate()
            .map_err(|error| TargetAdapterError::InvalidProfile {
                message: format!("capability ceiling is invalid: {error}"),
            })?;
        let scenarios = self
            .scenarios
            .iter()
            .map(|contract| contract.scenario)
            .collect::<Vec<_>>();
        validate_unique("scenarios", &scenarios, 16)?;
        if !scenarios.contains(&TargetAdapterScenario::Normal) {
            return Err(TargetAdapterError::InvalidProfile {
                message: "normal scenario is missing".to_owned(),
            });
        }
        let normal_capture = &self
            .scenario(TargetAdapterScenario::Normal)
            .expect("normal scenario presence checked")
            .capture;
        for contract in &self.scenarios {
            validate_capture_contract(&contract.capture)?;
            if contract.capture.capture_kind.is_sampling()
                != normal_capture.capture_kind.is_sampling()
            {
                return Err(TargetAdapterError::InvalidProfile {
                    message:
                        "one adapter profile cannot mix sampling and program-flow capture kinds"
                            .to_owned(),
                });
            }
            if normal_capture.capture_kind.is_program_flow_task_events()
                && contract.capture.capture_kind != normal_capture.capture_kind
            {
                return Err(TargetAdapterError::InvalidProfile {
                    message: "program-flow scenarios must use one exact TASKEVENTS export, clock, and metadata profile"
                        .to_owned(),
                });
            }
            let interrupted = matches!(
                contract.scenario,
                TargetAdapterScenario::Trace32Disconnect
                    | TargetAdapterScenario::DriverDisconnect
                    | TargetAdapterScenario::CmmAbort
            );
            if interrupted != contract.fault_point.is_some() {
                return Err(TargetAdapterError::InvalidProfile {
                    message: format!(
                        "scenario `{:?}` has an invalid fault-point contract",
                        contract.scenario
                    ),
                });
            }
        }
        if normal_capture.capture_kind.is_sampling()
            && scenarios.iter().any(|scenario| {
                matches!(
                    scenario,
                    TargetAdapterScenario::TraceOverflow | TargetAdapterScenario::FlowError
                )
            })
        {
            return Err(TargetAdapterError::InvalidProfile {
                message: "sampling profiles cannot declare program-flow fault scenarios".to_owned(),
            });
        }
        if normal_capture.capture_kind.is_program_flow_task_events() {
            if scenarios.iter().any(|scenario| {
                matches!(
                    scenario,
                    TargetAdapterScenario::SamplingBufferFull
                        | TargetAdapterScenario::SamplingUnexpectedStop
                )
            }) {
                return Err(TargetAdapterError::InvalidProfile {
                    message: "program-flow profiles cannot declare sampling fault scenarios"
                        .to_owned(),
                });
            }
            if self.health_signals != PROGRAM_FLOW_HEALTH_SIGNALS {
                return Err(TargetAdapterError::InvalidProfile {
                    message: "TASKEVENTS program flow requires the exact closed health-signal set"
                        .to_owned(),
                });
            }
            for (family, support) in [
                ("function_events", self.capabilities.function_events.support),
                (
                    "context_switches",
                    self.capabilities.context_switches.support,
                ),
                (
                    "interrupt_events",
                    self.capabilities.interrupt_events.support,
                ),
            ] {
                if support != MetricSupportLevel::Exact {
                    return Err(TargetAdapterError::InvalidProfile {
                        message: format!(
                            "TASKEVENTS program flow requires exact `{family}` capability"
                        ),
                    });
                }
            }
        }
        match (
            self.controller_protocol,
            self.custom_event_collector.as_ref(),
            self.capabilities.custom_events.support,
        ) {
            (TargetAdapterControllerProtocol::V1, None, MetricSupportLevel::Unavailable) => {}
            (
                TargetAdapterControllerProtocol::V2CustomEventsExport,
                Some(collector),
                MetricSupportLevel::Exact,
            ) => {
                collector.validate()?;
                if !normal_capture.capture_kind.is_program_flow_task_events() {
                    return Err(TargetAdapterError::InvalidProfile {
                        message:
                            "Controller V2 custom-event export requires TASKEVENTS program flow"
                                .to_owned(),
                    });
                }
                if self.capabilities.counters.support != MetricSupportLevel::Exact {
                    return Err(TargetAdapterError::InvalidProfile {
                        message: "Controller V2 C-wire custom-event export requires exact counter capability within the shared custom-event stream"
                            .to_owned(),
                    });
                }
                for scenario in &self.scenarios {
                    let TargetAdapterCaptureKind::ProgramFlowTaskEvents {
                        timestamp_clock_id, ..
                    } = &scenario.capture.capture_kind
                    else {
                        return Err(TargetAdapterError::InvalidProfile {
                            message: "Controller V2 custom-event export requires program-flow capture in every scenario"
                                .to_owned(),
                        });
                    };
                    if collector.clock.clock_id != *timestamp_clock_id {
                        return Err(TargetAdapterError::InvalidProfile {
                            message: "custom events and TASKEVENTS must use one exact shared timestamp clock"
                                .to_owned(),
                        });
                    }
                    if !scenario.capture.covered_cores.contains(&collector.core_id) {
                        return Err(TargetAdapterError::InvalidProfile {
                            message: "custom-event collector core is not covered by every adapter scenario"
                                .to_owned(),
                        });
                    }
                }
            }
            (TargetAdapterControllerProtocol::V1, Some(_), _) => {
                return Err(TargetAdapterError::InvalidProfile {
                    message: "Controller V1 forbids a custom-event collector contract".to_owned(),
                });
            }
            (TargetAdapterControllerProtocol::V1, None, _) => {
                return Err(TargetAdapterError::InvalidProfile {
                    message:
                        "Controller V1 requires custom_events capability to remain unavailable"
                            .to_owned(),
                });
            }
            (TargetAdapterControllerProtocol::V2CustomEventsExport, None, _) => {
                return Err(TargetAdapterError::InvalidProfile {
                    message:
                        "Controller V2 custom-event export requires an explicit collector contract"
                            .to_owned(),
                });
            }
            (TargetAdapterControllerProtocol::V2CustomEventsExport, Some(_), _) => {
                return Err(TargetAdapterError::InvalidProfile {
                    message:
                        "Controller V2 custom-event export requires exact custom_events capability"
                            .to_owned(),
                });
            }
        }
        for (scenario, signal) in [
            (
                TargetAdapterScenario::TraceOverflow,
                ControllerHealthSignal::TraceOverflow,
            ),
            (
                TargetAdapterScenario::FlowError,
                ControllerHealthSignal::FlowError,
            ),
            (
                TargetAdapterScenario::SamplingBufferFull,
                ControllerHealthSignal::SamplingBufferFull,
            ),
            (
                TargetAdapterScenario::SamplingUnexpectedStop,
                ControllerHealthSignal::SamplingUnexpectedStop,
            ),
        ] {
            if scenarios.contains(&scenario) && !self.health_signals.contains(&signal) {
                return Err(TargetAdapterError::InvalidProfile {
                    message: format!("scenario `{scenario:?}` requires health signal `{signal:?}`"),
                });
            }
        }
        Ok(())
    }

    /// Returns the canonical profile digest used by recovery evidence.
    pub fn digest(&self) -> Result<Sha256Digest, TargetAdapterError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).expect("profile serialization is infallible");
        Ok(Sha256Digest::new(hex_encode(&Sha256::digest(bytes)))
            .expect("SHA-256 digest syntax is valid"))
    }

    /// Returns the non-circular candidate profile identity used by qualification receipts.
    pub fn qualification_identity_digest(&self) -> Result<Sha256Digest, TargetAdapterError> {
        let mut candidate = self.clone();
        candidate.qualification_sha256 = None;
        candidate.digest()
    }

    /// Returns whether the profile declares a qualification receipt digest.
    ///
    /// This is not proof of qualification. Production selection additionally
    /// verifies the actual strict receipt bytes through the registry.
    #[must_use]
    pub const fn has_qualification_claim(&self) -> bool {
        self.qualification_sha256.is_some()
    }

    /// Returns the exact capture contract registered for a deployment scenario.
    #[must_use]
    pub fn scenario(
        &self,
        scenario: TargetAdapterScenario,
    ) -> Option<&TargetAdapterScenarioContract> {
        self.scenarios
            .iter()
            .find(|contract| contract.scenario == scenario)
    }
}

impl TargetAdapterQualificationReceipt {
    /// Strictly validates this receipt against an exact profile and its bytes.
    pub fn validate_for(
        &self,
        profile: &TargetAdapterProfile,
        receipt_bytes: &[u8],
    ) -> Result<(), TargetAdapterError> {
        if receipt_bytes.is_empty() || receipt_bytes.len() > MAX_QUALIFICATION_RECEIPT_BYTES {
            return Err(TargetAdapterError::InvalidQualificationReceipt {
                message: "qualification receipt size is outside the fixed bound".to_owned(),
            });
        }
        for (field, value) in [
            ("adapter_id", self.adapter_id.as_str()),
            ("adapter_version", self.adapter_version.as_str()),
            ("trace32_release", self.trace32_release.as_str()),
            ("architecture_package", self.architecture_package.as_str()),
            ("target_identifier", self.target_identifier.as_str()),
            ("probe_identifier", self.probe_identifier.as_str()),
            ("t32mcp_version", self.t32mcp_version.as_str()),
        ] {
            validate_text(field, value)?;
        }
        let declared = profile.qualification_sha256.as_ref().ok_or_else(|| {
            TargetAdapterError::InvalidQualificationReceipt {
                message: "profile has no qualification receipt claim".to_owned(),
            }
        })?;
        let actual = Sha256Digest::new(hex_encode(&Sha256::digest(receipt_bytes)))
            .expect("SHA-256 digest syntax is valid");
        if declared != &actual
            || self.adapter_id != profile.adapter_id
            || self.adapter_version != profile.adapter_version
            || self.candidate_profile_sha256 != profile.qualification_identity_digest()?
            || self.implementation_sha256 != profile.implementation_sha256
            || self.trace32_release != profile.build_gate.trace32_release
            || self.trace32_build != profile.build_gate.minimum_build
            || profile.build_gate.minimum_build != profile.build_gate.maximum_build
            || self.architecture_package != profile.build_gate.architecture_package
            || self.target_identifier != profile.target_identifier
            || self.probe_identifier != profile.probe_identifier
            || self.firmware_elf_sha256 != profile.firmware_elf_sha256
            || self.t32mcp_version != "0.2.2"
        {
            return Err(TargetAdapterError::InvalidQualificationReceipt {
                message: "qualification receipt does not match the exact profile/runtime bundle"
                    .to_owned(),
            });
        }
        Ok(())
    }
}

fn validate_capture_contract(
    capture: &TargetAdapterCaptureContract,
) -> Result<(), TargetAdapterError> {
    for (field, value) in [
        ("capture_mode", capture.capture_mode.as_str()),
        ("trace_sink", capture.trace_sink.as_str()),
        ("workload_identity", capture.workload_identity.as_str()),
    ] {
        validate_text(field, value)?;
    }
    validate_unique("covered_cores", &capture.covered_cores, 256)?;
    validate_unique(
        "supported_initial_states",
        &capture.supported_initial_states,
        2,
    )?;
    if !capture.timestamp_enabled {
        return Err(TargetAdapterError::InvalidProfile {
            message: "performance adapter must use verified timestamps".to_owned(),
        });
    }
    match &capture.capture_kind {
        TargetAdapterCaptureKind::Sampling { capacity_records } => {
            if *capacity_records == 0 {
                return Err(TargetAdapterError::InvalidProfile {
                    message: "sampling capture capacity must be nonzero".to_owned(),
                });
            }
        }
        TargetAdapterCaptureKind::ProgramFlowTaskEvents {
            export_profile_id,
            rtos_awareness,
            timestamp_clock_id,
            orti_artifact_id,
            task_marker_artifact_id,
        } => {
            validate_text("export_profile_id", export_profile_id)?;
            validate_text("rtos_awareness", rtos_awareness)?;
            validate_text("timestamp_clock_id", timestamp_clock_id)?;
            validate_text("orti_artifact_id", orti_artifact_id)?;
            validate_text("task_marker_artifact_id", task_marker_artifact_id)?;
            if orti_artifact_id == task_marker_artifact_id {
                return Err(TargetAdapterError::InvalidProfile {
                    message: "TASKEVENTS ORTI and marker artifacts must be distinct".to_owned(),
                });
            }
            if capture.covered_cores.len() != 1 {
                return Err(TargetAdapterError::InvalidProfile {
                    message: "TASKEVENTS program flow requires exactly one covered core".to_owned(),
                });
            }
        }
    }
    let states = capture
        .supported_initial_states
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let digest_states = capture
        .configuration_sha256_by_initial_state
        .keys()
        .copied()
        .collect::<BTreeSet<_>>();
    if states != digest_states {
        return Err(TargetAdapterError::InvalidProfile {
            message: "configuration digests do not exactly cover supported initial states"
                .to_owned(),
        });
    }
    Ok(())
}

/// Exact deployment-owned profile discriminator applied after runtime matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetAdapterSelectionDiscriminator {
    /// Exact stable adapter identity.
    pub adapter_id: String,
    /// Digest of the complete admitted profile document.
    pub profile_sha256: Sha256Digest,
}

impl TargetAdapterSelectionDiscriminator {
    /// Validates the exact persisted adapter/profile hint.
    pub fn validate(&self) -> Result<(), TargetAdapterError> {
        validate_text("selection.adapter_id", &self.adapter_id)
    }
}

/// Exact runtime identity used to select a compiled target adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetAdapterSelection {
    /// Exact TRACE32 release label.
    pub trace32_release: String,
    /// Exact nonzero TRACE32 build.
    pub trace32_build: u64,
    /// Exact architecture-package identity.
    pub architecture_package: String,
    /// Exact target identity.
    pub target_identifier: String,
    /// Exact probe identity.
    pub probe_identifier: String,
    /// Optional exact deployment-owned adapter/profile discriminator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discriminator: Option<TargetAdapterSelectionDiscriminator>,
}

impl TargetAdapterSelection {
    /// Validates runtime identity and the optional deployment-owned discriminator.
    pub fn validate(&self) -> Result<(), TargetAdapterError> {
        for (field, value) in [
            ("selection.trace32_release", self.trace32_release.as_str()),
            (
                "selection.architecture_package",
                self.architecture_package.as_str(),
            ),
            (
                "selection.target_identifier",
                self.target_identifier.as_str(),
            ),
            ("selection.probe_identifier", self.probe_identifier.as_str()),
        ] {
            validate_text(field, value)?;
        }
        if self.trace32_build == 0 {
            return Err(TargetAdapterError::InvalidSelection {
                message: "TRACE32 build must be nonzero".to_owned(),
            });
        }
        if let Some(discriminator) = &self.discriminator {
            discriminator.validate()?;
        }
        Ok(())
    }
}

fn profile_matches(
    profile: &TargetAdapterProfile,
    selection: &TargetAdapterSelection,
) -> Result<bool, TargetAdapterError> {
    let runtime_matches = profile.build_gate.trace32_release == selection.trace32_release
        && (profile.build_gate.minimum_build..=profile.build_gate.maximum_build)
            .contains(&selection.trace32_build)
        && profile.build_gate.architecture_package == selection.architecture_package
        && profile.target_identifier == selection.target_identifier
        && profile.probe_identifier == selection.probe_identifier;
    if !runtime_matches {
        return Ok(false);
    }
    let Some(discriminator) = &selection.discriminator else {
        return Ok(true);
    };
    Ok(profile.adapter_id == discriminator.adapter_id
        && profile.digest()? == discriminator.profile_sha256)
}

/// Registry of deployment-qualified, compiled target adapters.
#[derive(Debug, Default)]
pub struct TargetAdapterRegistry {
    profiles: BTreeMap<String, RegisteredTargetAdapter>,
}

/// A registry entry retaining the verified receipt claim used for selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredTargetAdapter {
    /// Exact qualified profile.
    pub profile: TargetAdapterProfile,
    /// Parsed receipt whose exact bytes matched the profile claim.
    pub qualification_receipt: TargetAdapterQualificationReceipt,
}

/// Admission catalog containing explicit evidence-only candidates and verified profiles.
#[derive(Debug, Default)]
pub struct TargetAdapterAdmissionCatalog {
    adapters: BTreeMap<String, AdmittedTargetAdapter>,
}

/// One exact catalog entry with an optional verified production receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedTargetAdapter {
    /// Exact executable profile.
    pub profile: TargetAdapterProfile,
    /// Parsed verified receipt for production entries; absent for candidates.
    pub qualification_receipt: Option<TargetAdapterQualificationReceipt>,
}

impl TargetAdapterAdmissionCatalog {
    /// Creates an empty fail-closed catalog.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Admits a profile only for evidence collection, never production trust.
    pub fn admit_candidate(
        &mut self,
        profile: TargetAdapterProfile,
    ) -> Result<(), TargetAdapterError> {
        profile.validate()?;
        if profile.has_qualification_claim() {
            return Err(TargetAdapterError::InvalidProfile {
                message: "candidate admission cannot carry an unverified qualification claim"
                    .to_owned(),
            });
        }
        self.insert(AdmittedTargetAdapter {
            profile,
            qualification_receipt: None,
        })
    }

    /// Admits a production profile after verifying the actual receipt bytes.
    pub fn admit_qualified(
        &mut self,
        profile: TargetAdapterProfile,
        receipt_bytes: &[u8],
    ) -> Result<(), TargetAdapterError> {
        profile.validate()?;
        let receipt = parse_target_adapter_qualification_receipt(receipt_bytes)?;
        receipt.validate_for(&profile, receipt_bytes)?;
        self.insert(AdmittedTargetAdapter {
            profile,
            qualification_receipt: Some(receipt),
        })
    }

    /// Selects exactly one admitted profile from runtime identity evidence.
    pub fn select(
        &self,
        selection: &TargetAdapterSelection,
    ) -> Result<&AdmittedTargetAdapter, TargetAdapterError> {
        selection.validate()?;
        let mut matches = Vec::new();
        for adapter in self.adapters.values() {
            if profile_matches(&adapter.profile, selection)? {
                matches.push(adapter);
            }
        }
        match matches.as_slice() {
            [adapter] => Ok(*adapter),
            [] => Err(TargetAdapterError::NoMatchingAdapter),
            _ => Err(TargetAdapterError::AmbiguousAdapter {
                adapter_ids: matches
                    .iter()
                    .map(|adapter| adapter.profile.adapter_id.clone())
                    .collect(),
            }),
        }
    }

    /// Returns one exact admission by stable adapter ID.
    pub fn get(&self, adapter_id: &str) -> Option<&AdmittedTargetAdapter> {
        self.adapters.get(adapter_id)
    }

    /// Returns a deterministic digest of all admitted profile and receipt claims.
    pub fn digest(&self) -> Result<Sha256Digest, TargetAdapterError> {
        let claims = self
            .adapters
            .values()
            .map(|adapter| {
                serde_json::json!({
                    "profile": adapter.profile,
                    "qualification_receipt": adapter.qualification_receipt,
                })
            })
            .collect::<Vec<_>>();
        let bytes = serde_json::to_vec(&claims).expect("catalog serialization is infallible");
        Ok(Sha256Digest::new(hex_encode(&Sha256::digest(bytes)))
            .expect("SHA-256 digest syntax is valid"))
    }

    fn insert(&mut self, adapter: AdmittedTargetAdapter) -> Result<(), TargetAdapterError> {
        let adapter_id = adapter.profile.adapter_id.clone();
        if self.adapters.insert(adapter_id.clone(), adapter).is_some() {
            return Err(TargetAdapterError::DuplicateAdapter { adapter_id });
        }
        Ok(())
    }
}

impl TargetAdapterRegistry {
    /// Creates an empty fail-closed registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one profile only after verifying the actual qualification receipt bytes.
    pub fn register(
        &mut self,
        profile: TargetAdapterProfile,
        qualification_receipt_bytes: &[u8],
    ) -> Result<(), TargetAdapterError> {
        profile.validate()?;
        if !profile.has_qualification_claim() {
            return Err(TargetAdapterError::UnqualifiedAdapter {
                adapter_id: profile.adapter_id,
            });
        }
        let receipt = parse_target_adapter_qualification_receipt(qualification_receipt_bytes)?;
        receipt.validate_for(&profile, qualification_receipt_bytes)?;
        if self.profiles.contains_key(&profile.adapter_id) {
            return Err(TargetAdapterError::DuplicateAdapter {
                adapter_id: profile.adapter_id,
            });
        }
        self.profiles.insert(
            profile.adapter_id.clone(),
            RegisteredTargetAdapter {
                profile,
                qualification_receipt: receipt,
            },
        );
        Ok(())
    }

    /// Selects exactly one profile matching all runtime identities.
    pub fn select(
        &self,
        selection: &TargetAdapterSelection,
    ) -> Result<&RegisteredTargetAdapter, TargetAdapterError> {
        selection.validate()?;
        let mut matches = Vec::new();
        for registered in self.profiles.values() {
            if profile_matches(&registered.profile, selection)? {
                matches.push(registered);
            }
        }
        match matches.as_slice() {
            [profile] => Ok(*profile),
            [] => Err(TargetAdapterError::NoMatchingAdapter),
            _ => Err(TargetAdapterError::AmbiguousAdapter {
                adapter_ids: matches
                    .iter()
                    .map(|registered| registered.profile.adapter_id.clone())
                    .collect(),
            }),
        }
    }
}

/// Returns the exact software candidate for the discovered TC234L deployment.
///
/// The checked facts are TRACE32 `R.2026.02.000190766`, TriCore package,
/// `TC234L`, core 0, JTAG at 30 MHz, DUALPORT enabled, and the deployment ELF
/// digest. The target is a production device and the configured Power Debug
/// PRO is used only for runtime PC access; this profile makes no MCDS/on-chip
/// or DAP-streaming claim. The profile intentionally has no qualification receipt and
/// cannot be registered until runtime capability and HIL evidence exists.
#[must_use]
pub fn tc234l_build190766_candidate_profile() -> TargetAdapterProfile {
    tc234l_snooper_build190766_profile(None)
}

/// Returns the executable SNOOPer PC sampling profile for this deployment.
///
/// A qualification digest is supplied only after deployment HIL. The profile
/// is nevertheless complete and can be executed for evidence collection.
#[must_use]
pub fn tc234l_snooper_build190766_profile(
    qualification_sha256: Option<Sha256Digest>,
) -> TargetAdapterProfile {
    let unavailable = |reason: &str| MetricSupportEntry::unavailable(reason);
    let normal_running = tc234l_snooper_capture_config_for_profile_scenario(
        "profile-normal-running",
        ControllerTargetState::Running,
        65_536,
        TargetAdapterScenario::Normal,
    );
    let normal_halted = tc234l_snooper_capture_config_for_profile_scenario(
        "profile-normal-halted",
        ControllerTargetState::Halted,
        65_536,
        TargetAdapterScenario::Normal,
    );
    let normal_capture = TargetAdapterCaptureContract {
        configuration_sha256_by_initial_state: BTreeMap::from([
            (
                ControllerTargetState::Running,
                capture_config_digest(&normal_running),
            ),
            (
                ControllerTargetState::Halted,
                capture_config_digest(&normal_halted),
            ),
        ]),
        capture_mode: "snooper-pc-realtime-stack".to_owned(),
        trace_sink: "host_snooper_buffer".to_owned(),
        capture_kind: TargetAdapterCaptureKind::Sampling {
            capacity_records: 65_536,
        },
        timestamp_enabled: true,
        workload_identity: "external-owner-sampling-window/v1".to_owned(),
        covered_cores: vec![0],
        supported_initial_states: vec![
            ControllerTargetState::Running,
            ControllerTargetState::Halted,
        ],
    };
    let mut buffer_full_capture = normal_capture.clone();
    buffer_full_capture.capture_kind = TargetAdapterCaptureKind::Sampling {
        capacity_records: 32,
    };
    buffer_full_capture.configuration_sha256_by_initial_state = BTreeMap::from([
        (
            ControllerTargetState::Running,
            capture_config_digest(&tc234l_snooper_capture_config_for_profile_scenario(
                "profile-overflow-running",
                ControllerTargetState::Running,
                32,
                TargetAdapterScenario::SamplingBufferFull,
            )),
        ),
        (
            ControllerTargetState::Halted,
            capture_config_digest(&tc234l_snooper_capture_config_for_profile_scenario(
                "profile-overflow-halted",
                ControllerTargetState::Halted,
                32,
                TargetAdapterScenario::SamplingBufferFull,
            )),
        ),
    ]);
    TargetAdapterProfile {
        schema: TargetAdapterProfileSchemaVersion::V1,
        adapter_id: "tricore-tc234l-snooper-pc-r2026.02-b190766-v1".to_owned(),
        adapter_version: "1.0.0".to_owned(),
        implementation_sha256: Sha256Digest::new(
            TC234L_SNOOPER_BUILD190766_IMPLEMENTATION_SHA256.to_owned(),
        )
        .expect("checked implementation digest syntax"),
        qualification_sha256,
        build_gate: TargetAdapterBuildGate {
            trace32_release: "2026.02".to_owned(),
            minimum_build: 190_766,
            maximum_build: 190_766,
            architecture_package: "tricore".to_owned(),
        },
        target_identifier: "infineon-tc234l-core0".to_owned(),
        probe_identifier: "powerdebug-pro:E17090031792:C23090376246".to_owned(),
        license_features: vec!["TriCore".to_owned()],
        trace_routing: vec!["runtime-pc-access-via-debug-port".to_owned()],
        firmware_elf_sha256: Sha256Digest::new(
            "7daae3ae027ab270c30de38530f83458a682d3e13c45deb69217048d8f449798".to_owned(),
        )
        .expect("checked ELF digest syntax"),
        health_signals: vec![
            ControllerHealthSignal::SamplingBufferFull,
            ControllerHealthSignal::SamplingUnexpectedStop,
            ControllerHealthSignal::ElfMismatch,
        ],
        capabilities: CaptureCapabilities {
            function_events: unavailable("pc_sampling_has_no_function_boundaries"),
            context_switches: unavailable("pc_sampling_has_no_context_switch_events"),
            interrupt_events: unavailable("pc_sampling_has_no_interrupt_events"),
            samples: MetricSupportEntry {
                support: MetricSupportLevel::Statistical,
                reasons: vec!["snooper_rate_is_not_guaranteed".to_owned()],
            },
            custom_events: unavailable("pc_sampling_has_no_custom_events"),
            counters: unavailable("pc_sampling_has_no_resource_counters"),
        },
        controller_protocol: TargetAdapterControllerProtocol::V1,
        custom_event_collector: None,
        scenarios: vec![
            TargetAdapterScenarioContract {
                scenario: TargetAdapterScenario::Normal,
                fault_point: None,
                capture: normal_capture.clone(),
            },
            TargetAdapterScenarioContract {
                scenario: TargetAdapterScenario::SamplingBufferFull,
                fault_point: None,
                capture: buffer_full_capture,
            },
            TargetAdapterScenarioContract {
                scenario: TargetAdapterScenario::Trace32Disconnect,
                fault_point: Some(TargetAdapterFaultPoint::Stop),
                capture: normal_capture.clone(),
            },
            TargetAdapterScenarioContract {
                scenario: TargetAdapterScenario::DriverDisconnect,
                fault_point: Some(TargetAdapterFaultPoint::Export),
                capture: normal_capture.clone(),
            },
            TargetAdapterScenarioContract {
                scenario: TargetAdapterScenario::CmmAbort,
                fault_point: Some(TargetAdapterFaultPoint::Start),
                capture: normal_capture,
            },
        ],
    }
}

/// Builds the authoritative capture config for the fixed TC234L SNOOPer profile.
#[must_use]
pub fn tc234l_snooper_capture_config(
    session_id: impl Into<String>,
    initial_target_state: ControllerTargetState,
    capacity_records: u64,
) -> CaptureConfigDocument {
    let scenario = if capacity_records == 32 {
        TargetAdapterScenario::SamplingBufferFull
    } else {
        TargetAdapterScenario::Normal
    };
    tc234l_snooper_capture_config_for_profile_scenario(
        session_id,
        initial_target_state,
        capacity_records,
        scenario,
    )
}

/// Builds the authoritative capture config for one closed adapter scenario.
#[must_use]
pub fn tc234l_snooper_capture_config_for_scenario(
    session_id: impl Into<String>,
    initial_target_state: ControllerTargetState,
    scenario: TargetAdapterScenario,
) -> CaptureConfigDocument {
    let capacity_records = if scenario == TargetAdapterScenario::SamplingBufferFull {
        32
    } else {
        65_536
    };
    tc234l_snooper_capture_config_for_profile_scenario(
        session_id,
        initial_target_state,
        capacity_records,
        scenario,
    )
}

fn tc234l_snooper_capture_config_for_profile_scenario(
    session_id: impl Into<String>,
    initial_target_state: ControllerTargetState,
    capacity_records: u64,
    scenario: TargetAdapterScenario,
) -> CaptureConfigDocument {
    CaptureConfigDocument {
        schema: CaptureConfigSchemaVersion,
        session_id: session_id.into(),
        provider: "trace32".to_owned(),
        adapter: AdapterInfo {
            id: "tricore-tc234l-snooper-pc-r2026.02-b190766-v1".to_owned(),
            version: "1.0.0".to_owned(),
        },
        mode: "snooper-pc-realtime-stack".to_owned(),
        covered_cores: vec![0],
        sink: CaptureSinkConfig {
            kind: "host_snooper_buffer".to_owned(),
            id: "snooper".to_owned(),
            capacity_bytes: None,
            stream_destination_identity: None,
        },
        timestamp: CaptureTimestampConfig {
            enabled: true,
            clock_id: Some("snooper_host_time".to_owned()),
        },
        filters: Vec::new(),
        trigger: CaptureTriggerConfig {
            kind: "external_owner_completion/v1".to_owned(),
            pre_trigger_ns: None,
            post_trigger_ns: None,
            condition_identity: Some("workload_complete_acknowledgement".to_owned()),
        },
        duration: CaptureDurationConfig {
            duration_ns: None,
            observation_limit: Some(capacity_records),
        },
        workload_identity: "external-owner-sampling-window/v1".to_owned(),
        initial_target_state: match initial_target_state {
            ControllerTargetState::Running => InitialTargetState::Running,
            ControllerTargetState::Halted => InitialTargetState::Halted,
        },
        rtos_awareness: CaptureRtosAwarenessConfig {
            kind: "none".to_owned(),
            metadata_artifact_ids: Vec::new(),
        },
        instrumentation: None,
        adapter_parameters: Properties::from([
            ("snooper.object".to_owned(), serde_json::json!("pc")),
            ("snooper.method".to_owned(), serde_json::json!("realtime")),
            ("snooper.buffer_mode".to_owned(), serde_json::json!("stack")),
            (
                "snooper.capacity_records".to_owned(),
                serde_json::json!(capacity_records),
            ),
            (
                "snooper.requested_rate_ns".to_owned(),
                serde_json::json!(1_000_000_u64),
            ),
            ("snooper.errorstop".to_owned(), serde_json::json!(true)),
            ("snooper.jitter".to_owned(), serde_json::json!(false)),
            ("snooper.autoarm".to_owned(), serde_json::json!(false)),
            ("snooper.autoinit".to_owned(), serde_json::json!(false)),
            (
                "snooper.time_origin".to_owned(),
                serde_json::json!("first_record_zero"),
            ),
            (
                "firmware.elf_sha256".to_owned(),
                serde_json::json!(
                    "7daae3ae027ab270c30de38530f83458a682d3e13c45deb69217048d8f449798"
                ),
            ),
            (
                "firmware.elf_artifact_id".to_owned(),
                serde_json::json!("firmware-elf"),
            ),
            (
                "firmware.measurement.method".to_owned(),
                serde_json::json!("tricore_sparse_s3_pt_load_paddr/v1"),
            ),
            (
                "firmware.measurement_artifact_id".to_owned(),
                serde_json::json!("trace32-firmware-s3"),
            ),
            (
                "firmware.measurement_sha256".to_owned(),
                serde_json::json!(TC234L_SNOOPER_BUILD190766_S3_SHA256),
            ),
            (
                "firmware.measurement_size_bytes".to_owned(),
                serde_json::json!(TC234L_SNOOPER_BUILD190766_S3_SIZE_BYTES),
            ),
            (
                "target_adapter.scenario".to_owned(),
                serde_json::json!(scenario.as_str()),
            ),
            (
                "export.profile".to_owned(),
                serde_json::json!("t32perf.trace32-ascii-profile/tc234l-build190766-v1"),
            ),
        ]),
    }
}

fn capture_config_digest(config: &CaptureConfigDocument) -> Sha256Digest {
    config.validate().expect("fixed capture config is valid");
    let bytes = config
        .configuration_identity_bytes()
        .expect("fixed capture config serialization is infallible");
    Sha256Digest::new(hex_encode(&Sha256::digest(bytes))).expect("SHA-256 digest syntax is valid")
}

/// Deterministic phase derived from accepted operation evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetAdapterPhase {
    /// No target operation has completed.
    New,
    /// Exact runtime capabilities match the selected profile.
    CapabilitiesVerified,
    /// Fixed capture configuration was verified.
    Configured,
    /// Capture and workload are active.
    Capturing,
    /// Capture stopped at the fixed workload termination point.
    Stopped,
    /// Build-gated hardware health was collected.
    HealthVerified,
    /// Raw capture was exported to Controller-owned staging.
    Exported,
    /// Adapter-owned state and original target state were restored.
    Cleaned,
    /// The active operation failed and external recovery evidence is required.
    RecoveryRequired,
    /// Recovery succeeded; the failed Session remains terminal and cannot resume.
    RecoveredTerminal,
}

/// Failure category requiring recovery before another Session uses the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TargetAdapterFailureKind {
    /// TRACE32 connection was lost.
    Trace32Disconnect,
    /// Deployment driver connection was lost.
    DriverDisconnect,
    /// The fixed CMM transaction was aborted.
    CmmAbort,
    /// A fixed operation returned another fail-closed error.
    OperationFailure,
}

/// Strict recovery evidence written by the trusted target Controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetAdapterRecoveryEvidence {
    /// Versioned document family.
    pub schema: TargetAdapterRecoveryEvidenceSchemaVersion,
    /// Stable candidate qualification-identity digest. This deliberately
    /// excludes a qualification receipt digest, avoiding a circular HIL /
    /// receipt / recovery-evidence dependency.
    pub profile_sha256: Sha256Digest,
    /// Controller binding of the failed operation.
    pub binding_sha256: Sha256Digest,
    /// Operation that failed.
    pub failed_operation: PerfOperation,
    /// Closed failure category.
    pub failure_kind: TargetAdapterFailureKind,
    /// Target state captured before adapter-owned mutation.
    pub initial_target_state: ControllerTargetState,
    /// Target state observed after recovery.
    pub restored_target_state: ControllerTargetState,
    /// Whether every adapter-owned capture mutation was restored.
    pub adapter_state_restored: bool,
    /// Exact canonical SNOOPer baseline facts for sampling adapters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampling: Option<TargetAdapterSamplingRecoveryEvidence>,
    /// Whether the upstream unbound abort was explicitly acknowledged when required.
    pub upstream_abort_confirmed: bool,
    /// Immutable host abort-receipt digest when an unbound CMM abort was acknowledged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_abort_receipt_sha256: Option<Sha256Digest>,
    /// Recovery must never delete Session files.
    pub files_deleted: bool,
    /// Recovery never resumes the failed Session.
    pub new_session_required: bool,
}

impl TargetAdapterRecoveryEvidence {
    /// Validates the canonical representation of the upstream abort receipt.
    pub fn validate(&self) -> Result<(), TargetAdapterError> {
        if self.upstream_abort_confirmed != self.upstream_abort_receipt_sha256.is_some() {
            return Err(TargetAdapterError::InvalidRecoveryEvidence);
        }
        Ok(())
    }
}

/// Canonical SNOOPer state verified during target-adapter recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetAdapterSamplingRecoveryEvidence {
    /// Restored acquisition method.
    pub method: crate::ControllerSamplingMethod,
    /// Restored sample object.
    pub object: crate::ControllerSamplingObject,
    /// Restored buffer mode.
    pub buffer_mode: crate::ControllerSamplingBufferMode,
    /// SNOOPer must be OFF after recovery.
    pub state: crate::ControllerSamplingState,
    /// Fixed requested interval from the profile.
    pub requested_rate_ns: u64,
    /// Canonical restored Stack capacity in records.
    pub capacity_records: u64,
    /// AutoArm canonical baseline.
    pub auto_arm: bool,
    /// AutoInit canonical baseline.
    pub auto_init: bool,
    /// Whether the adapter-owned ZERO origin was reset.
    pub zero_reset: bool,
}

/// State machine enforcing the fixed seven-operation sequence and recovery.
#[derive(Debug)]
pub struct TargetAdapterRun<'a> {
    profile: &'a TargetAdapterProfile,
    scenario: TargetAdapterScenario,
    phase: TargetAdapterPhase,
    initial_target_state: Option<ControllerTargetState>,
    capabilities_initial_target_state: Option<ControllerTargetState>,
    failed_operation: Option<PerfOperation>,
    failure_kind: Option<TargetAdapterFailureKind>,
    failed_binding: Option<Sha256Digest>,
    sampling_stop: Option<(crate::ControllerSamplingPreStopState, u64, u64)>,
    program_flow_stop_evidence_sha256: Option<Sha256Digest>,
}

struct RuntimeCapabilities<'a> {
    trace32_release: &'a str,
    trace32_build: u64,
    architecture_package: &'a str,
    target_identifier: &'a str,
    probe_identifier: &'a str,
    license_features: &'a [String],
    trace_routing: &'a [String],
    capture_modes: &'a [String],
    trace_sinks: &'a [String],
    covered_cores: &'a [u32],
    timestamp_supported: bool,
    rtos_awareness: Option<&'a str>,
    health_signals: &'a [ControllerHealthSignal],
}

impl<'a> TargetAdapterRun<'a> {
    /// Starts a run selected by trusted deployment code.
    pub fn new(
        profile: &'a TargetAdapterProfile,
        scenario: TargetAdapterScenario,
    ) -> Result<Self, TargetAdapterError> {
        profile.validate()?;
        if profile.scenario(scenario).is_none() {
            return Err(TargetAdapterError::UnsupportedScenario { scenario });
        }
        Ok(Self {
            profile,
            scenario,
            phase: TargetAdapterPhase::New,
            initial_target_state: None,
            capabilities_initial_target_state: None,
            failed_operation: None,
            failure_kind: None,
            failed_binding: None,
            sampling_stop: None,
            program_flow_stop_evidence_sha256: None,
        })
    }

    /// Returns the phase derived from accepted evidence.
    #[must_use]
    pub const fn phase(&self) -> TargetAdapterPhase {
        self.phase
    }

    /// Accepts and cross-checks one target-control evidence document.
    pub fn accept_evidence(
        &mut self,
        evidence: &ControllerEvidence,
    ) -> Result<(), TargetAdapterError> {
        self.accept_evidence_inner(evidence, None)
    }

    /// Accepts evidence together with its immutable artifact digest.
    ///
    /// TASKEVENTS Stop evidence must use this entry point so subsequent V3
    /// health can bind the exact accepted Stop artifact.
    pub fn accept_evidence_artifact(
        &mut self,
        evidence: &ControllerEvidence,
        artifact_sha256: &Sha256Digest,
    ) -> Result<(), TargetAdapterError> {
        self.accept_evidence_inner(evidence, Some(artifact_sha256))
    }

    fn accept_evidence_inner(
        &mut self,
        evidence: &ControllerEvidence,
        artifact_sha256: Option<&Sha256Digest>,
    ) -> Result<(), TargetAdapterError> {
        match (self.phase, evidence) {
            (TargetAdapterPhase::New, ControllerEvidence::Capabilities(value)) => {
                if self.is_sampling() {
                    return Err(TargetAdapterError::EvidenceMismatch {
                        message: "sampling profile requires capabilities evidence v2".to_owned(),
                    });
                }
                self.verify_capabilities(value)?;
                self.phase = TargetAdapterPhase::CapabilitiesVerified;
            }
            (TargetAdapterPhase::New, ControllerEvidence::CapabilitiesV2(value)) => {
                self.verify_capabilities_v2(value)?;
                self.capabilities_initial_target_state = Some(value.initial_target_state);
                self.phase = TargetAdapterPhase::CapabilitiesVerified;
            }
            (TargetAdapterPhase::CapabilitiesVerified, ControllerEvidence::Configure(value)) => {
                self.verify_configure(value)?;
                if self.capabilities_initial_target_state.is_some()
                    && self.capabilities_initial_target_state != Some(value.initial_target_state)
                {
                    return Err(TargetAdapterError::EvidenceMismatch {
                        message:
                            "configure evidence initial state differs from capabilities evidence v2"
                                .to_owned(),
                    });
                }
                self.initial_target_state = Some(value.initial_target_state);
                self.phase = TargetAdapterPhase::Configured;
            }
            (TargetAdapterPhase::Configured, ControllerEvidence::Start(value)) => {
                if self.is_sampling() {
                    return Err(TargetAdapterError::EvidenceMismatch {
                        message: "sampling profile requires start evidence v2".to_owned(),
                    });
                }
                let initial = self
                    .initial_target_state
                    .expect("configured state has initial state");
                if value.initial_target_state != initial
                    || value.workload_identity != self.capture().workload_identity
                    || !value.capture_started
                    || !value.workload_owned
                {
                    return Err(TargetAdapterError::EvidenceMismatch {
                        message: "start evidence does not match fixed state/workload contract"
                            .to_owned(),
                    });
                }
                self.phase = TargetAdapterPhase::Capturing;
            }
            (TargetAdapterPhase::Configured, ControllerEvidence::StartV2(value)) => {
                let initial = self
                    .initial_target_state
                    .expect("configured state has initial state");
                if value.initial_target_state != initial
                    || value.workload_identity != self.capture().workload_identity
                    || !value.capture_armed
                {
                    return Err(TargetAdapterError::EvidenceMismatch {
                        message:
                            "sampling start evidence does not match fixed owner/window contract"
                                .to_owned(),
                    });
                }
                self.phase = TargetAdapterPhase::Capturing;
            }
            (TargetAdapterPhase::Capturing, ControllerEvidence::Stop(value)) => {
                if self.is_sampling() {
                    return Err(TargetAdapterError::EvidenceMismatch {
                        message: "sampling profile requires stop evidence v2".to_owned(),
                    });
                }
                let initial = self
                    .initial_target_state
                    .expect("configured state has initial state");
                if value.workload_identity != self.capture().workload_identity
                    || !value.capture_stopped
                    || !value.workload_completed
                    || value.target_state_after_stop != initial
                {
                    return Err(TargetAdapterError::EvidenceMismatch {
                        message: "stop evidence does not prove fixed workload completion"
                            .to_owned(),
                    });
                }
                self.program_flow_stop_evidence_sha256 = Some(
                    artifact_sha256
                        .ok_or_else(|| TargetAdapterError::EvidenceMismatch {
                            message:
                                "program-flow Stop evidence requires its immutable artifact digest"
                                    .to_owned(),
                        })?
                        .clone(),
                );
                self.phase = TargetAdapterPhase::Stopped;
            }
            (TargetAdapterPhase::Capturing, ControllerEvidence::StopV2(value)) => {
                if !self.is_sampling() {
                    return Err(TargetAdapterError::EvidenceMismatch {
                        message: "program-flow profile requires stop evidence v1".to_owned(),
                    });
                }
                let initial = self
                    .initial_target_state
                    .expect("configured state has initial state");
                let expected_capacity_records = self
                    .capture()
                    .capture_kind
                    .sampling_capacity_records()
                    .expect("sampling profile has sampling capacity");
                if value.workload_identity != self.capture().workload_identity
                    || !value.capture_stopped
                    || value.target_state_after_stop != initial
                    || value.capacity_records == 0
                    || value.capacity_records != expected_capacity_records
                    || value.recorded_records == 0
                    || value.recorded_records > value.capacity_records
                    || !value.time_origin_zeroed_to_first_record
                {
                    return Err(TargetAdapterError::EvidenceMismatch {
                        message: "sampling stop evidence violates state or bounded-record contract"
                            .to_owned(),
                    });
                }
                self.sampling_stop = Some((
                    value.pre_stop_state,
                    value.recorded_records,
                    value.capacity_records,
                ));
                self.phase = TargetAdapterPhase::Stopped;
            }
            (TargetAdapterPhase::Stopped, ControllerEvidence::Health(_)) => {
                return Err(TargetAdapterError::EvidenceMismatch {
                    message: if self.is_sampling() {
                        "sampling profile requires signal-scoped health evidence v2"
                    } else {
                        "TASKEVENTS program flow requires stop-bound health evidence v3"
                    }
                    .to_owned(),
                });
            }
            (TargetAdapterPhase::Stopped, ControllerEvidence::HealthV3(value)) => {
                if self.is_sampling() {
                    return Err(TargetAdapterError::EvidenceMismatch {
                        message: "sampling profile cannot accept program-flow health evidence v3"
                            .to_owned(),
                    });
                }
                if !value.capture_stopped
                    || value.supported_signals != self.profile.health_signals
                    || self.program_flow_stop_evidence_sha256.as_ref()
                        != Some(&value.stop_evidence_sha256)
                {
                    return Err(TargetAdapterError::EvidenceMismatch {
                        message:
                            "program-flow health requires a stopped capture and the selected signal set"
                                .to_owned(),
                    });
                }
                let healthy = !value.trace_overflow
                    && !value.flow_error
                    && !value.trace_gap
                    && !value.truncated
                    && !value.timestamp_discontinuity
                    && value.elf_matches_firmware
                    && value.program_flow_closed;
                let exact_overflow = value.trace_overflow
                    && !value.flow_error
                    && !value.trace_gap
                    && !value.truncated
                    && !value.timestamp_discontinuity
                    && value.elf_matches_firmware
                    && !value.program_flow_closed;
                let exact_flow_error = value.flow_error
                    && !value.trace_overflow
                    && !value.trace_gap
                    && !value.truncated
                    && !value.timestamp_discontinuity
                    && value.elf_matches_firmware
                    && !value.program_flow_closed;
                let valid = match self.scenario {
                    TargetAdapterScenario::TraceOverflow => exact_overflow,
                    TargetAdapterScenario::FlowError => exact_flow_error,
                    _ => healthy,
                };
                if !valid {
                    return Err(TargetAdapterError::EvidenceMismatch {
                        message: match self.scenario {
                            TargetAdapterScenario::TraceOverflow => {
                                "overflow scenario did not produce the exact invalid overflow health set"
                            }
                            TargetAdapterScenario::FlowError => {
                                "flow-error scenario did not produce the exact invalid flow-error health set"
                            }
                            _ => "program-flow scenario contains adverse health facts",
                        }
                        .to_owned(),
                    });
                }
                self.phase = TargetAdapterPhase::HealthVerified;
            }
            (TargetAdapterPhase::Stopped, ControllerEvidence::HealthV2(value)) => {
                if !self.is_sampling() {
                    return Err(TargetAdapterError::EvidenceMismatch {
                        message: "program-flow profile requires health evidence v3".to_owned(),
                    });
                }
                let (pre_stop_state, recorded_records, capacity_records) = self
                    .sampling_stop
                    .ok_or_else(|| TargetAdapterError::EvidenceMismatch {
                        message: "sampling health has no accepted sampling stop evidence"
                            .to_owned(),
                    })?;
                let sampling = &value.sampling;
                let expected_buffer_full = pre_stop_state
                    == crate::ControllerSamplingPreStopState::Break
                    && recorded_records == capacity_records;
                let expected_unexpected_stop = pre_stop_state
                    == crate::ControllerSamplingPreStopState::Break
                    && recorded_records < capacity_records;
                if !value.capture_stopped
                    || value.supported_signals != self.profile.health_signals
                    || sampling.pre_stop_state != pre_stop_state
                    || sampling.recorded_records != recorded_records
                    || sampling.capacity_records != capacity_records
                    || sampling.buffer_full != expected_buffer_full
                    || sampling.unexpected_stop != expected_unexpected_stop
                    || sampling.state != crate::ControllerSamplingState::Off
                    || sampling.method != crate::ControllerSamplingMethod::RealTime
                    || sampling.object != crate::ControllerSamplingObject::ProgramCounter
                    || sampling.buffer_mode != crate::ControllerSamplingBufferMode::Stack
                    || sampling.requested_rate_ns != 1_000_000
                {
                    return Err(TargetAdapterError::EvidenceMismatch {
                        message: "sampling health does not match immutable pre-stop facts"
                            .to_owned(),
                    });
                }
                self.verify_sampling_firmware_match(value.elf_matches_firmware)?;
                match self.scenario {
                    TargetAdapterScenario::Normal
                        if expected_buffer_full
                            || expected_unexpected_stop
                            || value.elf_matches_firmware == Some(false) =>
                    {
                        return Err(TargetAdapterError::EvidenceMismatch {
                            message: "normal sampling scenario contains adverse health facts"
                                .to_owned(),
                        });
                    }
                    TargetAdapterScenario::SamplingBufferFull
                        if !expected_buffer_full
                            || expected_unexpected_stop
                            || value.elf_matches_firmware == Some(false) =>
                    {
                        return Err(TargetAdapterError::EvidenceMismatch {
                            message: "sampling-buffer-full scenario did not stop at exact capacity"
                                .to_owned(),
                        });
                    }
                    TargetAdapterScenario::SamplingUnexpectedStop
                        if !expected_unexpected_stop
                            || expected_buffer_full
                            || value.elf_matches_firmware == Some(false) =>
                    {
                        return Err(TargetAdapterError::EvidenceMismatch {
                            message: "unexpected-stop scenario did not stop before capacity"
                                .to_owned(),
                        });
                    }
                    TargetAdapterScenario::TraceOverflow | TargetAdapterScenario::FlowError => {
                        return Err(TargetAdapterError::EvidenceMismatch {
                            message: "sampling profile cannot claim flow-decoder fault scenarios"
                                .to_owned(),
                        });
                    }
                    _ => {}
                }
                self.phase = TargetAdapterPhase::HealthVerified;
            }
            (TargetAdapterPhase::Exported, ControllerEvidence::Cleanup(value)) => {
                if self.is_sampling() {
                    return Err(TargetAdapterError::EvidenceMismatch {
                        message: "sampling profile requires cleanup evidence v2".to_owned(),
                    });
                }
                if !value.adapter_state_restored
                    || !value.target_state_restored
                    || value.files_deleted
                {
                    return Err(TargetAdapterError::EvidenceMismatch {
                        message: "cleanup did not restore adapter and target state".to_owned(),
                    });
                }
                self.phase = TargetAdapterPhase::Cleaned;
            }
            (TargetAdapterPhase::Exported, ControllerEvidence::CleanupV2(value)) => {
                if !self.is_sampling() {
                    return Err(TargetAdapterError::EvidenceMismatch {
                        message: "program-flow profile requires cleanup evidence v1".to_owned(),
                    });
                }
                let initial = self
                    .initial_target_state
                    .expect("configured state has initial state");
                let sampling = &value.sampling;
                if value.initial_target_state != initial
                    || !value.adapter_state_restored
                    || !value.target_state_restored
                    || value.files_deleted
                    || sampling.method != crate::ControllerSamplingMethod::RealTime
                    || sampling.object != crate::ControllerSamplingObject::ProgramCounter
                    || sampling.buffer_mode != crate::ControllerSamplingBufferMode::Stack
                    || sampling.state != crate::ControllerSamplingState::Off
                    || sampling.requested_rate_ns != 1_000_000
                    || sampling.auto_arm
                    || sampling.auto_init
                    || !sampling.zero_reset
                {
                    return Err(TargetAdapterError::EvidenceMismatch {
                        message: "sampling cleanup did not prove the canonical baseline and initial target state"
                            .to_owned(),
                    });
                }
                self.phase = TargetAdapterPhase::Cleaned;
            }
            _ => {
                return Err(TargetAdapterError::UnexpectedEvidence { phase: self.phase });
            }
        }
        Ok(())
    }

    /// Accepts a successful fixed export response after health collection.
    pub fn accept_export(
        &mut self,
        response: &PerfScriptResponse,
    ) -> Result<(), TargetAdapterError> {
        let expected_code = match &self.capture().capture_kind {
            TargetAdapterCaptureKind::Sampling { .. } => "raw_ascii_exported",
            TargetAdapterCaptureKind::ProgramFlowTaskEvents { .. } => "task_events_exported",
        };
        if self.phase != TargetAdapterPhase::HealthVerified
            || response.operation != PerfOperation::Export
            || response.status != PerfStatus::Ok
            || response.code != expected_code
        {
            return Err(TargetAdapterError::InvalidExport);
        }
        self.phase = TargetAdapterPhase::Exported;
        Ok(())
    }

    /// Records a fail-closed operation interruption.
    pub fn record_failure(
        &mut self,
        operation: PerfOperation,
        binding_sha256: Sha256Digest,
        failure_kind: TargetAdapterFailureKind,
        observed_initial_target_state: ControllerTargetState,
    ) -> Result<(), TargetAdapterError> {
        let expected = expected_operation(self.phase)
            .ok_or(TargetAdapterError::FailureNotAllowed { phase: self.phase })?;
        if operation != expected {
            return Err(TargetAdapterError::WrongFailedOperation {
                expected,
                actual: operation,
            });
        }
        let Some(contract) = self.profile.scenario(self.scenario) else {
            return Err(TargetAdapterError::FaultContractMismatch);
        };
        let (Some(point), Some(expected_kind)) =
            (contract.fault_point, self.scenario.failure_kind())
        else {
            return Err(TargetAdapterError::FaultContractMismatch);
        };
        if point.operation() != operation || failure_kind != expected_kind {
            return Err(TargetAdapterError::FaultContractMismatch);
        }
        if !self
            .capture()
            .supported_initial_states
            .contains(&observed_initial_target_state)
            || self
                .initial_target_state
                .is_some_and(|initial| initial != observed_initial_target_state)
        {
            return Err(TargetAdapterError::FaultContractMismatch);
        }
        self.initial_target_state = Some(observed_initial_target_state);
        self.failed_operation = Some(operation);
        self.failure_kind = Some(failure_kind);
        self.failed_binding = Some(binding_sha256);
        self.phase = TargetAdapterPhase::RecoveryRequired;
        Ok(())
    }

    /// Records a non-injected operation failure for the normal scenario.
    ///
    /// This explicit path does not relabel the failure as a deployment fault
    /// injection. It still requires exact phase/initial-state binding and the
    /// same terminal recovery proof before another Session may use the target.
    pub fn record_operation_failure(
        &mut self,
        operation: PerfOperation,
        binding_sha256: Sha256Digest,
        observed_initial_target_state: ControllerTargetState,
    ) -> Result<(), TargetAdapterError> {
        if self.scenario != TargetAdapterScenario::Normal {
            return Err(TargetAdapterError::FaultContractMismatch);
        }
        let expected = expected_operation(self.phase)
            .ok_or(TargetAdapterError::FailureNotAllowed { phase: self.phase })?;
        if operation != expected {
            return Err(TargetAdapterError::WrongFailedOperation {
                expected,
                actual: operation,
            });
        }
        if !self
            .capture()
            .supported_initial_states
            .contains(&observed_initial_target_state)
            || self
                .initial_target_state
                .is_some_and(|initial| initial != observed_initial_target_state)
        {
            return Err(TargetAdapterError::FaultContractMismatch);
        }
        self.initial_target_state = Some(observed_initial_target_state);
        self.failed_operation = Some(operation);
        self.failure_kind = Some(TargetAdapterFailureKind::OperationFailure);
        self.failed_binding = Some(binding_sha256);
        self.phase = TargetAdapterPhase::RecoveryRequired;
        Ok(())
    }

    /// Accepts recovery evidence and permanently closes the failed Session.
    pub fn accept_recovery(
        &mut self,
        evidence: &TargetAdapterRecoveryEvidence,
    ) -> Result<(), TargetAdapterError> {
        evidence.validate()?;
        if self.phase != TargetAdapterPhase::RecoveryRequired {
            return Err(TargetAdapterError::RecoveryNotExpected);
        }
        let expected_initial = self
            .initial_target_state
            .ok_or(TargetAdapterError::InitialStateUnknown)?;
        let expected_kind = self.failure_kind.expect("failure phase has kind");
        if evidence.profile_sha256 != self.profile.qualification_identity_digest()?
            || Some(evidence.failed_operation) != self.failed_operation
            || evidence.failure_kind != expected_kind
            || evidence.initial_target_state != expected_initial
            || evidence.restored_target_state != expected_initial
            || !evidence.adapter_state_restored
            || evidence.files_deleted
            || !evidence.new_session_required
            || self.failed_binding.as_ref() != Some(&evidence.binding_sha256)
            || !evidence.upstream_abort_confirmed
            || evidence.upstream_abort_receipt_sha256.is_none()
        {
            return Err(TargetAdapterError::InvalidRecoveryEvidence);
        }
        match (&evidence.sampling, self.is_sampling()) {
            (None, false) => {}
            (Some(sampling), true)
                if sampling.method == crate::ControllerSamplingMethod::RealTime
                    && sampling.object == crate::ControllerSamplingObject::ProgramCounter
                    && sampling.buffer_mode == crate::ControllerSamplingBufferMode::Stack
                    && sampling.state == crate::ControllerSamplingState::Off
                    && sampling.requested_rate_ns == 1_000_000
                    && self.capture().capture_kind.sampling_capacity_records()
                        == Some(sampling.capacity_records)
                    && !sampling.auto_arm
                    && !sampling.auto_init
                    && sampling.zero_reset => {}
            _ => return Err(TargetAdapterError::InvalidRecoveryEvidence),
        }
        self.phase = TargetAdapterPhase::RecoveredTerminal;
        Ok(())
    }

    fn verify_capabilities(
        &self,
        evidence: &ControllerCapabilitiesEvidence,
    ) -> Result<(), TargetAdapterError> {
        self.verify_capabilities_fields(RuntimeCapabilities {
            trace32_release: &evidence.trace32_release,
            trace32_build: evidence.trace32_build,
            architecture_package: &evidence.architecture_package,
            target_identifier: &evidence.target_identifier,
            probe_identifier: &evidence.probe_identifier,
            license_features: &evidence.license_features,
            trace_routing: &evidence.trace_routing,
            capture_modes: &evidence.capture_modes,
            trace_sinks: &evidence.trace_sinks,
            covered_cores: &evidence.covered_cores,
            timestamp_supported: evidence.timestamp_supported,
            rtos_awareness: evidence.rtos_awareness.as_deref(),
            health_signals: &evidence.health_signals,
        })
    }

    fn verify_capabilities_v2(
        &self,
        evidence: &ControllerCapabilitiesEvidenceV2,
    ) -> Result<(), TargetAdapterError> {
        if !self
            .capture()
            .supported_initial_states
            .contains(&evidence.initial_target_state)
        {
            return Err(TargetAdapterError::EvidenceMismatch {
                message: "capabilities evidence v2 initial state is not supported".to_owned(),
            });
        }
        self.verify_capabilities_fields(RuntimeCapabilities {
            trace32_release: &evidence.trace32_release,
            trace32_build: evidence.trace32_build,
            architecture_package: &evidence.architecture_package,
            target_identifier: &evidence.target_identifier,
            probe_identifier: &evidence.probe_identifier,
            license_features: &evidence.license_features,
            trace_routing: &evidence.trace_routing,
            capture_modes: &evidence.capture_modes,
            trace_sinks: &evidence.trace_sinks,
            covered_cores: &evidence.covered_cores,
            timestamp_supported: evidence.timestamp_supported,
            rtos_awareness: evidence.rtos_awareness.as_deref(),
            health_signals: &evidence.health_signals,
        })
    }

    fn verify_capabilities_fields(
        &self,
        capabilities: RuntimeCapabilities<'_>,
    ) -> Result<(), TargetAdapterError> {
        let rtos_awareness_matches = match &self.capture().capture_kind {
            TargetAdapterCaptureKind::Sampling { .. } => capabilities.rtos_awareness.is_none(),
            TargetAdapterCaptureKind::ProgramFlowTaskEvents { rtos_awareness, .. } => {
                capabilities.rtos_awareness == Some(rtos_awareness.as_str())
            }
        };
        if capabilities.trace32_release != self.profile.build_gate.trace32_release
            || !(self.profile.build_gate.minimum_build..=self.profile.build_gate.maximum_build)
                .contains(&capabilities.trace32_build)
            || capabilities.architecture_package != self.profile.build_gate.architecture_package
            || capabilities.target_identifier != self.profile.target_identifier
            || capabilities.probe_identifier != self.profile.probe_identifier
            || capabilities.license_features != self.profile.license_features
            || capabilities.trace_routing != self.profile.trace_routing
            || capabilities.capture_modes != [self.capture().capture_mode.clone()]
            || capabilities.trace_sinks != [self.capture().trace_sink.clone()]
            || capabilities.covered_cores != self.capture().covered_cores
            || capabilities.timestamp_supported != self.capture().timestamp_enabled
            || !rtos_awareness_matches
            || capabilities.health_signals != self.profile.health_signals
        {
            return Err(TargetAdapterError::EvidenceMismatch {
                message: "capabilities evidence does not match selected profile".to_owned(),
            });
        }
        Ok(())
    }

    fn verify_configure(
        &self,
        evidence: &crate::ControllerConfigureEvidence,
    ) -> Result<(), TargetAdapterError> {
        let capture = self.capture();
        if capture
            .configuration_sha256_by_initial_state
            .get(&evidence.initial_target_state)
            != Some(&evidence.configuration_sha256)
            || evidence.capture_mode != capture.capture_mode
            || evidence.trace_sink != capture.trace_sink
            || evidence.timestamp_enabled != capture.timestamp_enabled
            || !evidence.filters_verified
            || !evidence.trigger_verified
            || evidence.workload_identity != capture.workload_identity
            || evidence.covered_cores != capture.covered_cores
            || !capture
                .supported_initial_states
                .contains(&evidence.initial_target_state)
        {
            return Err(TargetAdapterError::EvidenceMismatch {
                message: "configure evidence does not match fixed capture contract".to_owned(),
            });
        }
        Ok(())
    }

    fn capture(&self) -> &TargetAdapterCaptureContract {
        &self
            .profile
            .scenario(self.scenario)
            .expect("run scenario was validated")
            .capture
    }

    fn is_sampling(&self) -> bool {
        self.capture().capture_kind.is_sampling()
    }

    fn verify_sampling_firmware_match(
        &self,
        elf_matches_firmware: Option<bool>,
    ) -> Result<(), TargetAdapterError> {
        let supports_firmware_match = self
            .profile
            .health_signals
            .contains(&ControllerHealthSignal::ElfMismatch);
        match (supports_firmware_match, elf_matches_firmware) {
            (true, Some(true)) | (false, None) => Ok(()),
            (true, Some(false)) => Err(TargetAdapterError::EvidenceMismatch {
                message: "sampling health reports a firmware mismatch".to_owned(),
            }),
            (true, None) => Err(TargetAdapterError::EvidenceMismatch {
                message: "sampling health omits required firmware-match evidence".to_owned(),
            }),
            (false, Some(_)) => Err(TargetAdapterError::EvidenceMismatch {
                message: "sampling health claims unsupported firmware-match evidence".to_owned(),
            }),
        }
    }
}

impl TargetAdapterScenario {
    fn failure_kind(self) -> Option<TargetAdapterFailureKind> {
        match self {
            Self::Trace32Disconnect => Some(TargetAdapterFailureKind::Trace32Disconnect),
            Self::DriverDisconnect => Some(TargetAdapterFailureKind::DriverDisconnect),
            Self::CmmAbort => Some(TargetAdapterFailureKind::CmmAbort),
            Self::Normal
            | Self::TraceOverflow
            | Self::FlowError
            | Self::SamplingBufferFull
            | Self::SamplingUnexpectedStop => None,
        }
    }
}

/// Strictly decodes one deployment target-adapter profile.
pub fn parse_target_adapter_profile(
    bytes: &[u8],
) -> Result<TargetAdapterProfile, TargetAdapterError> {
    let profile: TargetAdapterProfile =
        strict_json::from_slice(bytes).map_err(|error| TargetAdapterError::InvalidProfile {
            message: error.to_string(),
        })?;
    profile.validate()?;
    Ok(profile)
}

/// Strictly decodes one deployment qualification receipt.
pub fn parse_target_adapter_qualification_receipt(
    bytes: &[u8],
) -> Result<TargetAdapterQualificationReceipt, TargetAdapterError> {
    if bytes.is_empty() || bytes.len() > MAX_QUALIFICATION_RECEIPT_BYTES {
        return Err(TargetAdapterError::InvalidQualificationReceipt {
            message: "qualification receipt size is outside the fixed bound".to_owned(),
        });
    }
    strict_json::from_slice(bytes).map_err(|error| {
        TargetAdapterError::InvalidQualificationReceipt {
            message: error.to_string(),
        }
    })
}

/// Strictly decodes one deployment scenario-selection document.
pub fn parse_target_adapter_scenario_selection(
    bytes: &[u8],
) -> Result<TargetAdapterScenarioSelection, TargetAdapterError> {
    strict_json::from_slice(bytes).map_err(|error| TargetAdapterError::InvalidScenarioSelection {
        message: error.to_string(),
    })
}

/// Returns checked JSON Schemas for target-adapter deployment artifacts.
#[must_use]
pub fn target_adapter_schema_documents() -> BTreeMap<&'static str, Value> {
    BTreeMap::from([
        (
            "target-adapter-profile.schema.json",
            schema_document::<TargetAdapterProfile>(TARGET_ADAPTER_PROFILE_SCHEMA),
        ),
        (
            "target-adapter-recovery-evidence.schema.json",
            schema_document::<TargetAdapterRecoveryEvidence>(
                TARGET_ADAPTER_RECOVERY_EVIDENCE_SCHEMA,
            ),
        ),
        (
            "target-adapter-qualification-receipt.schema.json",
            schema_document::<TargetAdapterQualificationReceipt>(
                TARGET_ADAPTER_QUALIFICATION_RECEIPT_SCHEMA,
            ),
        ),
        (
            "target-adapter-scenario.schema.json",
            schema_document::<TargetAdapterScenarioSelection>(
                TARGET_ADAPTER_SCENARIO_SELECTION_SCHEMA,
            ),
        ),
    ])
}

fn expected_operation(phase: TargetAdapterPhase) -> Option<PerfOperation> {
    match phase {
        TargetAdapterPhase::New => Some(PerfOperation::GetCapabilities),
        TargetAdapterPhase::CapabilitiesVerified => Some(PerfOperation::Configure),
        TargetAdapterPhase::Configured => Some(PerfOperation::Start),
        TargetAdapterPhase::Capturing => Some(PerfOperation::Stop),
        TargetAdapterPhase::Stopped => Some(PerfOperation::GetHealth),
        TargetAdapterPhase::HealthVerified => Some(PerfOperation::Export),
        TargetAdapterPhase::Exported => Some(PerfOperation::Cleanup),
        TargetAdapterPhase::Cleaned
        | TargetAdapterPhase::RecoveryRequired
        | TargetAdapterPhase::RecoveredTerminal => None,
    }
}

fn validate_text(field: &'static str, value: &str) -> Result<(), TargetAdapterError> {
    if value.is_empty()
        || value.len() > MAX_PROFILE_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(TargetAdapterError::InvalidText { field });
    }
    Ok(())
}

fn validate_bundle_relative_directory(value: &str) -> Result<(), TargetAdapterError> {
    let Some(leaf) = value.strip_prefix("scripts/adapters/") else {
        return Err(TargetAdapterError::InvalidProfile {
            message: "compiled bundle directory must be below `scripts/adapters`".to_owned(),
        });
    };
    if value.len() > MAX_PROFILE_TEXT_BYTES
        || !value.is_ascii()
        || leaf.is_empty()
        || leaf.contains('/')
        || leaf.contains('\\')
        || leaf.contains(':')
        || !is_portable_artifact_id(leaf)
    {
        return Err(TargetAdapterError::InvalidProfile {
            message: "compiled bundle directory is not a portable relative path".to_owned(),
        });
    }
    Ok(())
}

fn validate_unique_text(
    field: &'static str,
    values: &[String],
    maximum: usize,
) -> Result<(), TargetAdapterError> {
    for value in values {
        validate_text(field, value)?;
    }
    validate_unique(field, values, maximum)
}

fn validate_unique<T: Ord + std::fmt::Debug>(
    field: &'static str,
    values: &[T],
    maximum: usize,
) -> Result<(), TargetAdapterError> {
    if values.is_empty() || values.len() > maximum {
        return Err(TargetAdapterError::InvalidProfile {
            message: format!("{field} must contain 1..={maximum} entries"),
        });
    }
    let unique = values.iter().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err(TargetAdapterError::InvalidProfile {
            message: format!("{field} contains duplicate entries"),
        });
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

/// Target-adapter selection, evidence, or transition failure.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TargetAdapterError {
    /// A deployment scenario-selection document is invalid for its Session admission.
    #[error("target-adapter scenario selection is invalid: {message}")]
    InvalidScenarioSelection {
        /// Concrete invalidity.
        message: String,
    },
    /// A profile field is empty, too large, or contains control characters.
    #[error("target-adapter profile field `{field}` is invalid")]
    InvalidText {
        /// Invalid field.
        field: &'static str,
    },
    /// A profile violates its closed semantic contract.
    #[error("target-adapter profile is invalid: {message}")]
    InvalidProfile {
        /// Stable validation detail.
        message: String,
    },
    /// Qualification receipt bytes or claims do not match the profile.
    #[error("target-adapter qualification receipt is invalid: {message}")]
    InvalidQualificationReceipt {
        /// Stable validation detail.
        message: String,
    },
    /// A duplicate adapter ID was registered.
    #[error("target adapter `{adapter_id}` is already registered")]
    DuplicateAdapter {
        /// Duplicate identifier.
        adapter_id: String,
    },
    /// Runtime selection is malformed.
    #[error("target-adapter selection is invalid: {message}")]
    InvalidSelection {
        /// Stable validation detail.
        message: String,
    },
    /// No exact qualified profile matched the runtime identity.
    #[error(
        "UNSUPPORTED_NEEDS_TRACE32: no qualified target adapter matches the exact runtime identity"
    )]
    NoMatchingAdapter,
    /// More than one qualified profile matched the runtime identity.
    #[error("target-adapter selection is ambiguous: {adapter_ids:?}")]
    AmbiguousAdapter {
        /// Matching IDs.
        adapter_ids: Vec<String>,
    },
    /// A candidate lacks deployment qualification evidence.
    #[error("UNSUPPORTED_NEEDS_TRACE32: target adapter `{adapter_id}` is not qualified")]
    UnqualifiedAdapter {
        /// Candidate adapter identifier.
        adapter_id: String,
    },
    /// The selected profile does not implement a scenario.
    #[error("target adapter does not implement scenario `{scenario:?}`")]
    UnsupportedScenario {
        /// Unsupported fixed scenario.
        scenario: TargetAdapterScenario,
    },
    /// Evidence was submitted outside the required phase.
    #[error("target-control evidence is unexpected in phase `{phase:?}`")]
    UnexpectedEvidence {
        /// Current phase.
        phase: TargetAdapterPhase,
    },
    /// Evidence did not match the fixed profile.
    #[error("target-control evidence mismatch: {message}")]
    EvidenceMismatch {
        /// Stable mismatch detail.
        message: String,
    },
    /// Export response was not the expected successful fixed export.
    #[error("fixed export response is invalid or out of sequence")]
    InvalidExport,
    /// A failure cannot be recorded from the current phase.
    #[error("target-operation failure is not allowed in phase `{phase:?}`")]
    FailureNotAllowed {
        /// Current phase.
        phase: TargetAdapterPhase,
    },
    /// A failure was attached to the wrong operation.
    #[error("failed operation mismatch: expected `{expected:?}`, got `{actual:?}`")]
    WrongFailedOperation {
        /// Expected operation.
        expected: PerfOperation,
        /// Actual operation.
        actual: PerfOperation,
    },
    /// A fixed fault scenario did not fail at its declared point and kind.
    #[error("failure does not match the selected fixed fault-injection contract")]
    FaultContractMismatch,
    /// Recovery evidence arrived without a recorded failure.
    #[error("target recovery evidence is not expected")]
    RecoveryNotExpected,
    /// Configuration did not establish the original target state before failure.
    #[error("target recovery cannot be verified because the original state is unknown")]
    InitialStateUnknown,
    /// Recovery evidence did not prove complete restoration and terminal replacement.
    #[error("target recovery evidence is invalid")]
    InvalidRecoveryEvidence,
}
