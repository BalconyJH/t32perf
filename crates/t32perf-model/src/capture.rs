//! Trusted capture receipts produced by capture adapters and Session controllers.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AdapterInfo, CaptureAttestationSchemaVersion, CaptureConfigSchemaVersion,
    CaptureReceiptSchemaVersion, CaptureTrustPolicySchemaVersion, ClockInfo, FirmwareInfo,
    HealthObservation, InstrumentationOverheadEvidenceSchemaVersion, MetricSupportEntry,
    MetricSupportLevel, Properties, Sha256Digest, TargetInfo, Trace32Info, is_portable_artifact_id,
    portable_name_key,
};

const MAX_CAPTURE_CONFIG_FILTERS: usize = 256;
const MAX_CAPTURE_CONFIG_CORES: usize = 1_024;
const MAX_CAPTURE_CONFIG_METADATA_ARTIFACTS: usize = 256;
const MAX_CAPTURE_CONFIG_TEXT_BYTES: usize = 4_096;
const MAX_CAPTURE_CONFIG_PROPERTY_ENTRIES: usize = 1_024;
const MAX_CAPTURE_CONFIG_PROPERTY_ARRAY_ITEMS: usize = 4_096;
const MAX_CAPTURE_CONFIG_PROPERTY_DEPTH: usize = 16;
const MAX_CAPTURE_TRUST_CONSTRAINT_VALUES: usize = 256;

/// Exact immutable claim for the capture configuration used to produce observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureConfigArtifactClaim {
    /// Registered capture-configuration artifact identifier.
    pub artifact_id: String,
    /// SHA-256 of the exact registered configuration bytes.
    pub sha256: Sha256Digest,
    /// SHA-256 of the canonical configuration with its owning Session identity removed.
    pub configuration_sha256: Sha256Digest,
}

/// Exact immutable claim for controller-validated hardware-health evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerHealthArtifactClaim {
    /// Registered controller health-evidence artifact identifier.
    pub artifact_id: String,
    /// SHA-256 of the exact registered evidence bytes.
    pub sha256: Sha256Digest,
}

impl ControllerHealthArtifactClaim {
    /// Validates the portable artifact identity.
    pub fn validate(&self) -> Result<(), CaptureConfigValidationError> {
        if !is_portable_artifact_id(&self.artifact_id) {
            return Err(CaptureConfigValidationError::InvalidArtifactId {
                field: "controller_health.artifact_id".to_owned(),
                artifact_id: self.artifact_id.clone(),
            });
        }
        Ok(())
    }
}

impl CaptureConfigArtifactClaim {
    /// Validates the portable artifact identity.
    pub fn validate(&self) -> Result<(), CaptureConfigValidationError> {
        if !is_portable_artifact_id(&self.artifact_id) {
            return Err(CaptureConfigValidationError::InvalidArtifactId {
                field: "capture_config.artifact_id".to_owned(),
                artifact_id: self.artifact_id.clone(),
            });
        }
        Ok(())
    }
}

/// Target execution state at the instant capture configuration became authoritative.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InitialTargetState {
    /// The target was running.
    Running,
    /// The target was halted.
    Halted,
    /// The adapter could not establish the target state.
    Unknown,
}

/// Trace sink configured by the capture adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureSinkConfig {
    /// Adapter-defined, versioned sink kind.
    pub kind: String,
    /// Stable sink identity within the adapter deployment.
    pub id: String,
    /// Configured sink capacity when the sink is bounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub capacity_bytes: Option<u64>,
    /// Stable destination identity for streaming sinks; never contains credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_destination_identity: Option<String>,
}

/// Timestamp configuration applied by the capture adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureTimestampConfig {
    /// Whether captured records carry timestamps.
    pub enabled: bool,
    /// Clock-domain identifier used by those timestamps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_id: Option<String>,
}

/// One explicit adapter filter applied to the capture source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureFilterConfig {
    /// Adapter-defined, versioned filter kind.
    pub kind: String,
    /// Stable subject or rule identity.
    pub identity: String,
    /// Whether this filter was enabled for the capture.
    pub enabled: bool,
    /// Bounded authoritative adapter parameters for this filter.
    #[serde(default, skip_serializing_if = "Properties::is_empty")]
    pub parameters: Properties,
}

/// Trigger configuration applied by the capture adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureTriggerConfig {
    /// Adapter-defined, versioned trigger kind.
    pub kind: String,
    /// Requested pre-trigger capture duration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_trigger_ns: Option<u64>,
    /// Requested post-trigger capture duration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_trigger_ns: Option<u64>,
    /// Stable identity of an adapter-owned trigger condition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition_identity: Option<String>,
}

/// Capture duration or record-count limits requested from the adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureDurationConfig {
    /// Requested capture-duration limit in nanoseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub duration_ns: Option<u64>,
    /// Requested observation-count limit when capture is count bounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub observation_limit: Option<u64>,
}

/// RTOS-awareness configuration and its immutable metadata dependencies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureRtosAwarenessConfig {
    /// Adapter-defined RTOS-awareness kind, such as `none` or a versioned decoder identity.
    pub kind: String,
    /// Immutable Session artifacts used as RTOS metadata.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 256))]
    pub metadata_artifact_ids: Vec<String>,
}

/// Target instrumentation method and independently measured incremental cost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureInstrumentationConfig {
    /// Versioned target-side API or marker method, such as `t32perf-c-wire/v1`.
    pub method: String,
    /// Versioned transport identity, such as `shared-memory-ring-buffer/v1`.
    pub transport: String,
    /// Controlled measurement used to quantify incremental instrumentation cost.
    pub overhead: CaptureInstrumentationOverhead,
}

/// One controlled measurement of target-side instrumentation overhead.
///
/// The incremental cost is `instrumented_duration_ns - baseline_duration_ns`.
/// Keeping both source durations and the emitted-event count avoids a rounded
/// floating-point average in the authoritative contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureInstrumentationOverhead {
    /// Versioned benchmark or calibration procedure.
    pub measurement_method: String,
    /// Duration of the uninstrumented reference workload.
    pub baseline_duration_ns: u64,
    /// Duration of the same workload with instrumentation enabled.
    pub instrumented_duration_ns: u64,
    /// Number of target events emitted during the instrumented workload.
    #[schemars(range(min = 1))]
    pub emitted_event_count: u64,
    /// Immutable artifact containing raw measurement evidence.
    pub evidence_artifact_id: String,
}

/// Immutable deployment evidence for one controlled instrumentation-overhead measurement.
///
/// The document deliberately omits its own artifact identifier. The Session
/// catalog supplies that identity, and the authoritative capture config binds
/// it when converting this evidence into [`CaptureInstrumentationConfig`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InstrumentationOverheadEvidenceDocument {
    /// Versioned evidence family.
    pub schema: InstrumentationOverheadEvidenceSchemaVersion,
    /// Exact target-side instrumentation API or marker method.
    #[schemars(length(min = 1, max = 4096))]
    pub instrumentation_method: String,
    /// Exact adapter-owned transport used by the measured event stream.
    #[schemars(length(min = 1, max = 4096))]
    pub transport: String,
    /// Versioned benchmark or calibration procedure.
    #[schemars(length(min = 1, max = 4096))]
    pub measurement_method: String,
    /// Duration of the uninstrumented reference workload.
    pub baseline_duration_ns: u64,
    /// Duration of the same workload with instrumentation enabled.
    pub instrumented_duration_ns: u64,
    /// Number of target events emitted during the instrumented workload.
    #[schemars(range(min = 1))]
    pub emitted_event_count: u64,
}

impl InstrumentationOverheadEvidenceDocument {
    /// Validates the measured identities and checked duration relationship.
    pub fn validate(&self) -> Result<(), CaptureConfigValidationError> {
        validate_capture_config_text(
            "instrumentation_evidence.instrumentation_method",
            &self.instrumentation_method,
        )?;
        validate_capture_config_text("instrumentation_evidence.transport", &self.transport)?;
        validate_capture_config_text(
            "instrumentation_evidence.measurement_method",
            &self.measurement_method,
        )?;
        if self.emitted_event_count == 0 {
            return Err(CaptureConfigValidationError::ZeroInstrumentationEventCount);
        }
        if self.instrumented_duration_ns < self.baseline_duration_ns {
            return Err(CaptureConfigValidationError::NegativeInstrumentationOverhead);
        }
        Ok(())
    }

    /// Binds this immutable measurement to its Session artifact identity.
    pub fn capture_config(
        &self,
        evidence_artifact_id: String,
    ) -> Result<CaptureInstrumentationConfig, CaptureConfigValidationError> {
        self.validate()?;
        let config = CaptureInstrumentationConfig {
            method: self.instrumentation_method.clone(),
            transport: self.transport.clone(),
            overhead: CaptureInstrumentationOverhead {
                measurement_method: self.measurement_method.clone(),
                baseline_duration_ns: self.baseline_duration_ns,
                instrumented_duration_ns: self.instrumented_duration_ns,
                emitted_event_count: self.emitted_event_count,
                evidence_artifact_id,
            },
        };
        config.validate()?;
        Ok(config)
    }
}

impl CaptureInstrumentationConfig {
    /// Validates method identities, measured durations, and evidence ownership.
    pub fn validate(&self) -> Result<(), CaptureConfigValidationError> {
        validate_capture_config_text("instrumentation.method", &self.method)?;
        validate_capture_config_text("instrumentation.transport", &self.transport)?;
        validate_capture_config_text(
            "instrumentation.overhead.measurement_method",
            &self.overhead.measurement_method,
        )?;
        if self.overhead.emitted_event_count == 0 {
            return Err(CaptureConfigValidationError::ZeroInstrumentationEventCount);
        }
        if self.overhead.total_overhead_ns().is_none() {
            return Err(CaptureConfigValidationError::NegativeInstrumentationOverhead);
        }
        if !is_portable_artifact_id(&self.overhead.evidence_artifact_id) {
            return Err(CaptureConfigValidationError::InvalidArtifactId {
                field: "instrumentation.overhead.evidence_artifact_id".to_owned(),
                artifact_id: self.overhead.evidence_artifact_id.clone(),
            });
        }
        Ok(())
    }
}

impl CaptureInstrumentationOverhead {
    /// Returns the checked total incremental overhead in nanoseconds.
    #[must_use]
    pub fn total_overhead_ns(&self) -> Option<u64> {
        self.instrumented_duration_ns
            .checked_sub(self.baseline_duration_ns)
    }
}

/// Authoritative, language-neutral capture configuration recorded before normalization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureConfigDocument {
    /// The capture-config schema version.
    pub schema: CaptureConfigSchemaVersion,
    /// Session that owns this configuration and its resulting artifacts.
    pub session_id: String,
    /// Capture provider responsible for applying the configuration.
    pub provider: String,
    /// Versioned adapter responsible for applying the configuration.
    pub adapter: AdapterInfo,
    /// Adapter-defined capture mode.
    pub mode: String,
    /// Cores selected for capture.
    #[schemars(length(min = 1, max = 1024))]
    pub covered_cores: Vec<u32>,
    /// Configured capture sink.
    pub sink: CaptureSinkConfig,
    /// Configured timestamp source.
    pub timestamp: CaptureTimestampConfig,
    /// Explicit bounded filters applied by the adapter.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 256))]
    pub filters: Vec<CaptureFilterConfig>,
    /// Trigger configuration.
    pub trigger: CaptureTriggerConfig,
    /// Duration or record-count limits.
    pub duration: CaptureDurationConfig,
    /// Stable workload identity executed during capture.
    pub workload_identity: String,
    /// Initial target execution state observed by the adapter.
    pub initial_target_state: InitialTargetState,
    /// RTOS-awareness configuration.
    pub rtos_awareness: CaptureRtosAwarenessConfig,
    /// Target custom-event instrumentation and measured overhead, when used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instrumentation: Option<CaptureInstrumentationConfig>,
    /// Bounded authoritative parameters not represented by the common contract.
    #[serde(default, skip_serializing_if = "Properties::is_empty")]
    pub adapter_parameters: Properties,
}

impl CaptureConfigDocument {
    /// Returns deterministic bytes for cross-Session configuration identity.
    ///
    /// The owning `session_id` is replaced by the empty sentinel. Runtime
    /// result claims in the reserved `result.` adapter-parameter namespace are
    /// excluded, because they identify one accepted execution rather than the
    /// configuration shared by equivalent Sessions. Every other authoritative
    /// field remains covered, including provider, adapter, mode, core
    /// coverage, sink, timestamps, filters, trigger, workload, RTOS
    /// awareness, instrumentation evidence, and non-result adapter parameters.
    pub fn configuration_identity_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut identity = self.clone();
        identity.session_id.clear();
        identity
            .adapter_parameters
            .retain(|key, _| !key.starts_with("result."));
        serde_json::to_vec(&identity)
    }

    /// Validates identities, bounds, cross-field timestamp rules, and metadata references.
    pub fn validate(&self) -> Result<(), CaptureConfigValidationError> {
        for (field, value) in [
            ("session_id", self.session_id.as_str()),
            ("provider", self.provider.as_str()),
            ("adapter.id", self.adapter.id.as_str()),
            ("adapter.version", self.adapter.version.as_str()),
            ("mode", self.mode.as_str()),
            ("sink.kind", self.sink.kind.as_str()),
            ("sink.id", self.sink.id.as_str()),
            ("trigger.kind", self.trigger.kind.as_str()),
            ("workload_identity", self.workload_identity.as_str()),
            ("rtos_awareness.kind", self.rtos_awareness.kind.as_str()),
        ] {
            validate_capture_config_text(field, value)?;
        }
        validate_optional_capture_config_text(
            "sink.stream_destination_identity",
            self.sink.stream_destination_identity.as_deref(),
        )?;
        validate_optional_capture_config_text(
            "trigger.condition_identity",
            self.trigger.condition_identity.as_deref(),
        )?;
        if self.sink.capacity_bytes == Some(0) {
            return Err(CaptureConfigValidationError::ZeroSinkCapacity);
        }
        if self.duration.duration_ns.is_none() && self.duration.observation_limit.is_none() {
            return Err(CaptureConfigValidationError::MissingDurationLimit);
        }
        if self.duration.duration_ns == Some(0) {
            return Err(CaptureConfigValidationError::ZeroDurationBound {
                field: "duration.duration_ns",
            });
        }
        if self.duration.observation_limit == Some(0) {
            return Err(CaptureConfigValidationError::ZeroDurationBound {
                field: "duration.observation_limit",
            });
        }
        if self.covered_cores.is_empty() || self.covered_cores.len() > MAX_CAPTURE_CONFIG_CORES {
            return Err(CaptureConfigValidationError::InvalidCoreCount {
                actual: self.covered_cores.len(),
                limit: MAX_CAPTURE_CONFIG_CORES,
            });
        }
        let mut cores = BTreeSet::new();
        for core_id in &self.covered_cores {
            if !cores.insert(*core_id) {
                return Err(CaptureConfigValidationError::DuplicateCore { core_id: *core_id });
            }
        }
        if !self.covered_cores.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(CaptureConfigValidationError::NonCanonicalCoreOrder);
        }
        match (self.timestamp.enabled, self.timestamp.clock_id.as_deref()) {
            (true, Some(clock_id)) => validate_capture_config_text("timestamp.clock_id", clock_id)?,
            (true, None) => return Err(CaptureConfigValidationError::TimestampClockMissing),
            (false, Some(_)) => return Err(CaptureConfigValidationError::TimestampClockUnexpected),
            (false, None) => {}
        }
        if self.filters.len() > MAX_CAPTURE_CONFIG_FILTERS {
            return Err(CaptureConfigValidationError::TooManyFilters {
                actual: self.filters.len(),
                limit: MAX_CAPTURE_CONFIG_FILTERS,
            });
        }
        let mut filters = BTreeSet::new();
        for (index, filter) in self.filters.iter().enumerate() {
            validate_capture_config_text(&format!("filters[{index}].kind"), &filter.kind)?;
            validate_capture_config_text(&format!("filters[{index}].identity"), &filter.identity)?;
            if !filters.insert((filter.kind.as_str(), filter.identity.as_str())) {
                return Err(CaptureConfigValidationError::DuplicateFilter {
                    kind: filter.kind.clone(),
                    identity: filter.identity.clone(),
                });
            }
            validate_capture_config_properties(
                &format!("filters[{index}].parameters"),
                &filter.parameters,
            )?;
        }
        if self.rtos_awareness.metadata_artifact_ids.len() > MAX_CAPTURE_CONFIG_METADATA_ARTIFACTS {
            return Err(CaptureConfigValidationError::TooManyMetadataArtifacts {
                actual: self.rtos_awareness.metadata_artifact_ids.len(),
                limit: MAX_CAPTURE_CONFIG_METADATA_ARTIFACTS,
            });
        }
        let mut metadata = BTreeSet::new();
        for artifact_id in &self.rtos_awareness.metadata_artifact_ids {
            if !is_portable_artifact_id(artifact_id) {
                return Err(CaptureConfigValidationError::InvalidArtifactId {
                    field: "rtos_awareness.metadata_artifact_ids".to_owned(),
                    artifact_id: artifact_id.clone(),
                });
            }
            if !metadata.insert(portable_name_key(artifact_id)) {
                return Err(CaptureConfigValidationError::DuplicateMetadataArtifact {
                    artifact_id: artifact_id.clone(),
                });
            }
        }
        if let Some(instrumentation) = &self.instrumentation {
            instrumentation.validate()?;
            let evidence_artifact_id = &instrumentation.overhead.evidence_artifact_id;
            if !metadata.insert(portable_name_key(evidence_artifact_id)) {
                return Err(CaptureConfigValidationError::DuplicateMetadataArtifact {
                    artifact_id: evidence_artifact_id.clone(),
                });
            }
        }
        validate_capture_config_properties("adapter_parameters", &self.adapter_parameters)
    }

    /// Returns the exact ordered provenance inputs required by this config.
    #[must_use]
    pub fn input_artifact_ids(&self) -> Vec<&str> {
        self.rtos_awareness
            .metadata_artifact_ids
            .iter()
            .map(String::as_str)
            .chain(
                self.instrumentation
                    .iter()
                    .map(|instrumentation| instrumentation.overhead.evidence_artifact_id.as_str()),
            )
            .collect()
    }
}

fn validate_capture_config_text(
    field: &str,
    value: &str,
) -> Result<(), CaptureConfigValidationError> {
    if value.trim().is_empty()
        || value.len() > MAX_CAPTURE_CONFIG_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(CaptureConfigValidationError::InvalidText {
            field: field.to_owned(),
        });
    }
    Ok(())
}

fn validate_optional_capture_config_text(
    field: &str,
    value: Option<&str>,
) -> Result<(), CaptureConfigValidationError> {
    if let Some(value) = value {
        validate_capture_config_text(field, value)?;
    }
    Ok(())
}

fn validate_capture_config_properties(
    field: &str,
    properties: &Properties,
) -> Result<(), CaptureConfigValidationError> {
    let mut count = 0_usize;
    validate_capture_config_object(field, properties, 0, &mut count)
}

fn validate_capture_config_object(
    field: &str,
    properties: &Properties,
    depth: usize,
    count: &mut usize,
) -> Result<(), CaptureConfigValidationError> {
    if depth > MAX_CAPTURE_CONFIG_PROPERTY_DEPTH {
        return Err(CaptureConfigValidationError::InvalidProperties {
            field: field.to_owned(),
            reason: "nesting is too deep",
        });
    }
    *count = count.saturating_add(properties.len());
    if *count > MAX_CAPTURE_CONFIG_PROPERTY_ENTRIES {
        return Err(CaptureConfigValidationError::InvalidProperties {
            field: field.to_owned(),
            reason: "contains too many entries",
        });
    }
    for (key, value) in properties {
        if key.trim().is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
            return Err(CaptureConfigValidationError::InvalidProperties {
                field: field.to_owned(),
                reason: "contains an invalid key",
            });
        }
        validate_capture_config_value(field, value, depth + 1, count)?;
    }
    Ok(())
}

fn validate_capture_config_value(
    field: &str,
    value: &serde_json::Value,
    depth: usize,
    count: &mut usize,
) -> Result<(), CaptureConfigValidationError> {
    if depth > MAX_CAPTURE_CONFIG_PROPERTY_DEPTH {
        return Err(CaptureConfigValidationError::InvalidProperties {
            field: field.to_owned(),
            reason: "nesting is too deep",
        });
    }
    match value {
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
        serde_json::Value::String(value) => {
            if value.len() > MAX_CAPTURE_CONFIG_TEXT_BYTES || value.chars().any(char::is_control) {
                return Err(CaptureConfigValidationError::InvalidProperties {
                    field: field.to_owned(),
                    reason: "contains an invalid string",
                });
            }
        }
        serde_json::Value::Array(values) => {
            if values.len() > MAX_CAPTURE_CONFIG_PROPERTY_ARRAY_ITEMS {
                return Err(CaptureConfigValidationError::InvalidProperties {
                    field: field.to_owned(),
                    reason: "contains an oversized array",
                });
            }
            *count = count.saturating_add(values.len());
            if *count > MAX_CAPTURE_CONFIG_PROPERTY_ENTRIES {
                return Err(CaptureConfigValidationError::InvalidProperties {
                    field: field.to_owned(),
                    reason: "contains too many entries",
                });
            }
            for value in values {
                validate_capture_config_value(field, value, depth + 1, count)?;
            }
        }
        serde_json::Value::Object(values) => {
            let properties = values
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Properties>();
            validate_capture_config_object(field, &properties, depth, count)?;
        }
    }
    Ok(())
}

/// A semantic invariant violation in a capture configuration or claim.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CaptureConfigValidationError {
    /// A required string is empty, oversized, or contains control characters.
    #[error("capture config field `{field}` contains invalid text")]
    InvalidText {
        /// Invalid field path.
        field: String,
    },
    /// A referenced artifact identifier is not portable.
    #[error("capture config field `{field}` contains invalid artifact id `{artifact_id}`")]
    InvalidArtifactId {
        /// Invalid field path.
        field: String,
        /// Rejected artifact ID.
        artifact_id: String,
    },
    /// Covered cores are absent or exceed the bounded contract.
    #[error("capture config has {actual} covered cores; expected 1..={limit}")]
    InvalidCoreCount {
        /// Observed core count.
        actual: usize,
        /// Maximum core count.
        limit: usize,
    },
    /// A covered core is repeated.
    #[error("capture config contains duplicate core id {core_id}")]
    DuplicateCore {
        /// Repeated core ID.
        core_id: u32,
    },
    /// Covered cores are not serialized in ascending order.
    #[error("capture config covered cores are not in canonical ascending order")]
    NonCanonicalCoreOrder,
    /// Timestamping is enabled without a clock identity.
    #[error("capture config enables timestamps without a clock id")]
    TimestampClockMissing,
    /// Timestamping is disabled but still names a clock.
    #[error("capture config disables timestamps but declares a clock id")]
    TimestampClockUnexpected,
    /// A bounded sink declares no usable capacity.
    #[error("capture config declares a zero-byte sink capacity")]
    ZeroSinkCapacity,
    /// Neither a time nor observation-count capture bound is recorded.
    #[error("capture config omits both duration and observation-count limits")]
    MissingDurationLimit,
    /// A present duration or count bound is zero.
    #[error("capture config bound `{field}` must be greater than zero")]
    ZeroDurationBound {
        /// Invalid bound field.
        field: &'static str,
    },
    /// The filter list exceeds the bounded contract.
    #[error("capture config has {actual} filters; maximum is {limit}")]
    TooManyFilters {
        /// Observed filter count.
        actual: usize,
        /// Maximum filter count.
        limit: usize,
    },
    /// One filter identity is repeated for the same kind.
    #[error("capture config repeats filter `{kind}` / `{identity}`")]
    DuplicateFilter {
        /// Filter kind.
        kind: String,
        /// Filter identity.
        identity: String,
    },
    /// RTOS metadata references exceed the bounded contract.
    #[error("capture config has {actual} RTOS metadata artifacts; maximum is {limit}")]
    TooManyMetadataArtifacts {
        /// Observed metadata reference count.
        actual: usize,
        /// Maximum metadata reference count.
        limit: usize,
    },
    /// One RTOS metadata artifact is repeated.
    #[error("capture config repeats RTOS metadata artifact `{artifact_id}`")]
    DuplicateMetadataArtifact {
        /// Repeated artifact ID.
        artifact_id: String,
    },
    /// An instrumentation measurement claims zero emitted target events.
    #[error("capture instrumentation overhead requires at least one emitted event")]
    ZeroInstrumentationEventCount,
    /// The instrumented workload duration is less than its baseline duration.
    #[error("capture instrumentation duration is less than its baseline")]
    NegativeInstrumentationOverhead,
    /// Bounded extension properties are malformed.
    #[error("capture config properties `{field}` are invalid: {reason}")]
    InvalidProperties {
        /// Invalid property field path.
        field: String,
        /// Stable reason.
        reason: &'static str,
    },
}

/// Signed statement that binds trusted capture facts to one immutable observation artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureAttestationPayload {
    /// The capture-attestation schema version.
    pub schema: CaptureAttestationSchemaVersion,
    /// Trust-policy key used to sign this statement.
    pub key_id: String,
    /// Unique Session operation identifier preventing cross-Session replay.
    pub nonce: String,
    /// Adapter-provided capture facts covered by the signature.
    pub receipt: CaptureReceipt,
    /// Observation artifact identifier covered by the signature.
    pub observation_artifact_id: String,
    /// Digest of the exact normalized observation bytes.
    pub observation_sha256: Sha256Digest,
    /// Exact immutable capture-configuration artifact covered by the signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_config: Option<CaptureConfigArtifactClaim>,
    /// Exact controller-validated hardware-health evidence covered by the signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_health: Option<ControllerHealthArtifactClaim>,
}

impl CaptureAttestationPayload {
    /// Returns deterministic compact JSON bytes used for Ed25519 signing and verification.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Validates fields that do not require Session state or a trust policy.
    pub fn validate(&self) -> Result<(), CaptureAttestationValidationError> {
        for (field, value) in [
            ("key_id", self.key_id.as_str()),
            ("nonce", self.nonce.as_str()),
            (
                "observation_artifact_id",
                self.observation_artifact_id.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(CaptureAttestationValidationError::EmptyField {
                    field: field.to_owned(),
                });
            }
        }
        self.receipt
            .validate()
            .map_err(CaptureAttestationValidationError::InvalidReceipt)?;
        if let Some(claim) = &self.capture_config {
            claim
                .validate()
                .map_err(CaptureAttestationValidationError::InvalidCaptureConfig)?;
        }
        if self.capture_config != self.receipt.capture_config {
            return Err(CaptureAttestationValidationError::CaptureConfigClaimMismatch);
        }
        if let Some(claim) = &self.controller_health {
            claim
                .validate()
                .map_err(CaptureAttestationValidationError::InvalidControllerHealth)?;
        }
        if self.controller_health != self.receipt.controller_health {
            return Err(CaptureAttestationValidationError::ControllerHealthClaimMismatch);
        }
        Ok(())
    }
}

/// Ed25519-signed capture attestation supplied by an external trusted adapter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureAttestation {
    /// Signed payload.
    pub payload: CaptureAttestationPayload,
    /// Lowercase hexadecimal 64-byte Ed25519 signature.
    pub signature_ed25519: String,
}

impl CaptureAttestation {
    /// Validates payload semantics and signature encoding.
    pub fn validate(&self) -> Result<(), CaptureAttestationValidationError> {
        self.payload.validate()?;
        if !is_lower_hex(&self.signature_ed25519, 128) {
            return Err(CaptureAttestationValidationError::InvalidSignatureEncoding);
        }
        Ok(())
    }
}

/// Deployment-owned allowlist of external capture signing keys.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureTrustPolicy {
    /// The capture-trust-policy schema version.
    pub schema: CaptureTrustPolicySchemaVersion,
    /// Stable deployment policy identity retained in Session provenance.
    pub policy_id: String,
    /// Trusted adapter signing keys and their maximum claims.
    pub keys: Vec<CaptureTrustKey>,
}

impl CaptureTrustPolicy {
    /// Validates key uniqueness, encodings, and claim ceilings.
    pub fn validate(&self) -> Result<(), CaptureTrustPolicyValidationError> {
        if self.policy_id.trim().is_empty() {
            return Err(CaptureTrustPolicyValidationError::EmptyField {
                field: "policy_id".to_owned(),
            });
        }
        if self.keys.is_empty() {
            return Err(CaptureTrustPolicyValidationError::NoKeys);
        }
        let mut key_ids = BTreeSet::new();
        for key in &self.keys {
            key.validate()?;
            if !key_ids.insert(key.key_id.as_str()) {
                return Err(CaptureTrustPolicyValidationError::DuplicateKeyId {
                    key_id: key.key_id.clone(),
                });
            }
        }
        Ok(())
    }

    /// Returns the trusted key with the requested identifier.
    #[must_use]
    pub fn key(&self, key_id: &str) -> Option<&CaptureTrustKey> {
        self.keys.iter().find(|key| key.key_id == key_id)
    }
}

/// One trusted external adapter key and the strongest claims it may make.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureTrustKey {
    /// Stable key identifier referenced by attestations.
    pub key_id: String,
    /// Lowercase hexadecimal 32-byte Ed25519 public key.
    pub public_key_ed25519: String,
    /// Durable artifact producer assigned by the host after verification.
    pub producer: String,
    /// Capture provider this key may attest, such as `trace32`.
    pub provider: String,
    /// Exact adapter identity bound to the key.
    pub adapter: AdapterInfo,
    /// Capture modes this key may attest.
    pub allowed_modes: Vec<String>,
    /// Exact target identity bound to this trusted adapter deployment.
    pub target: TargetInfo,
    /// Exact TRACE32 installation and probe identity when required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace32: Option<Trace32Info>,
    /// Exact clock domains the deployment may claim.
    pub clocks: Vec<ClockInfo>,
    /// Cores this deployment is permitted to claim as covered.
    pub allowed_cores: Vec<u32>,
    /// Exact firmware ELF SHA-256 digests this deployment is permitted to attest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 256))]
    pub allowed_firmware_elf_sha256: Vec<Sha256Digest>,
    /// Strongest evidence level this key may claim for each observation family.
    pub capability_ceiling: CaptureCapabilities,
    /// Optional deployment restrictions for signed capture configurations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_constraints: Option<CaptureConfigConstraints>,
}

impl CaptureTrustKey {
    fn validate(&self) -> Result<(), CaptureTrustPolicyValidationError> {
        for (field, value) in [
            ("key_id", self.key_id.as_str()),
            ("producer", self.producer.as_str()),
            ("provider", self.provider.as_str()),
            ("adapter.id", self.adapter.id.as_str()),
            ("adapter.version", self.adapter.version.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(CaptureTrustPolicyValidationError::EmptyField {
                    field: field.to_owned(),
                });
            }
        }
        if !is_lower_hex(&self.public_key_ed25519, 64) {
            return Err(
                CaptureTrustPolicyValidationError::InvalidPublicKeyEncoding {
                    key_id: self.key_id.clone(),
                },
            );
        }
        validate_unique_nonempty(&self.allowed_modes, "allowed_modes", &self.key_id)?;
        if self.allowed_modes.is_empty() {
            return Err(CaptureTrustPolicyValidationError::NoAllowedModes {
                key_id: self.key_id.clone(),
            });
        }
        if self
            .target
            .architecture
            .as_deref()
            .is_none_or(str::is_empty)
            || self.target.device.as_deref().is_none_or(str::is_empty)
            || self.target.core_count.is_none_or(|count| count == 0)
            || (self.provider == "trace32"
                && self.target.board.as_deref().is_none_or(str::is_empty))
        {
            return Err(CaptureTrustPolicyValidationError::IncompleteTarget {
                key_id: self.key_id.clone(),
            });
        }
        if self.provider == "trace32"
            && self.trace32.as_ref().is_none_or(|trace32| {
                trace32.build.as_deref().is_none_or(str::is_empty)
                    || trace32.probe.as_deref().is_none_or(str::is_empty)
                    || trace32
                        .architecture_package
                        .as_deref()
                        .is_none_or(str::is_empty)
            })
        {
            return Err(CaptureTrustPolicyValidationError::IncompleteTrace32 {
                key_id: self.key_id.clone(),
            });
        }
        let clock_ids = self
            .clocks
            .iter()
            .map(|clock| clock.id.as_str())
            .collect::<BTreeSet<_>>();
        if self.clocks.is_empty()
            || clock_ids.len() != self.clocks.len()
            || self.clocks.iter().any(|clock| {
                clock.id.trim().is_empty()
                    || clock.frequency_hz.is_none_or(|hz| hz == 0)
                    || clock.source.as_deref().is_none_or(str::is_empty)
            })
        {
            return Err(CaptureTrustPolicyValidationError::IncompleteClocks {
                key_id: self.key_id.clone(),
            });
        }
        let cores = self.allowed_cores.iter().copied().collect::<BTreeSet<_>>();
        let core_count = self.target.core_count.unwrap_or_default();
        if cores.is_empty()
            || cores.len() != self.allowed_cores.len()
            || cores.iter().any(|core| *core >= core_count)
        {
            return Err(CaptureTrustPolicyValidationError::InvalidAllowedCores {
                key_id: self.key_id.clone(),
            });
        }
        let firmware_digests = self
            .allowed_firmware_elf_sha256
            .iter()
            .collect::<BTreeSet<_>>();
        if firmware_digests.len() != self.allowed_firmware_elf_sha256.len()
            || self.allowed_firmware_elf_sha256.len() > MAX_CAPTURE_TRUST_CONSTRAINT_VALUES
            || (self.provider == "trace32" && self.allowed_firmware_elf_sha256.is_empty())
        {
            return Err(
                CaptureTrustPolicyValidationError::InvalidFirmwareElfAllowlist {
                    key_id: self.key_id.clone(),
                },
            );
        }
        self.capability_ceiling.validate().map_err(|error| {
            CaptureTrustPolicyValidationError::InvalidCapabilityCeiling {
                key_id: self.key_id.clone(),
                message: error.to_string(),
            }
        })?;
        if let Some(constraints) = &self.config_constraints {
            constraints.validate(&self.key_id)?;
        }
        Ok(())
    }
}

/// Optional semantic and digest restrictions placed on capture configs signed by one key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureConfigConstraints {
    /// Allowed sink kinds; empty permits any signed sink kind.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 256))]
    pub allowed_sink_kinds: Vec<String>,
    /// Allowed stable sink identities; empty permits any signed sink identity.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 256))]
    pub allowed_sink_ids: Vec<String>,
    /// Allowed initial target states; empty permits any signed state.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 3))]
    pub allowed_initial_target_states: Vec<InitialTargetState>,
    /// Allowed RTOS-awareness kinds; empty permits any signed kind.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 256))]
    pub allowed_rtos_awareness_kinds: Vec<String>,
    /// Maximum sink capacity the key may attest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_sink_capacity_bytes: Option<u64>,
    /// Required timestamp-enabled value when constrained.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_timestamp_enabled: Option<bool>,
    /// Exact cross-Session configuration digests this key may attest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 256))]
    pub allowed_config_sha256: Vec<Sha256Digest>,
}

impl CaptureConfigConstraints {
    fn validate(&self, key_id: &str) -> Result<(), CaptureTrustPolicyValidationError> {
        validate_unique_nonempty(
            &self.allowed_sink_kinds,
            "config_constraints.allowed_sink_kinds",
            key_id,
        )?;
        validate_unique_nonempty(
            &self.allowed_sink_ids,
            "config_constraints.allowed_sink_ids",
            key_id,
        )?;
        validate_unique_nonempty(
            &self.allowed_rtos_awareness_kinds,
            "config_constraints.allowed_rtos_awareness_kinds",
            key_id,
        )?;
        if self
            .allowed_initial_target_states
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            != self.allowed_initial_target_states.len()
        {
            return Err(
                CaptureTrustPolicyValidationError::InvalidConfigConstraints {
                    key_id: key_id.to_owned(),
                    message: "initial target states are duplicated".to_owned(),
                },
            );
        }
        if self
            .allowed_config_sha256
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != self.allowed_config_sha256.len()
        {
            return Err(
                CaptureTrustPolicyValidationError::InvalidConfigConstraints {
                    key_id: key_id.to_owned(),
                    message: "capture-config digests are duplicated".to_owned(),
                },
            );
        }
        if self.allowed_initial_target_states.len() > 3
            || self.allowed_config_sha256.len() > MAX_CAPTURE_TRUST_CONSTRAINT_VALUES
            || self.max_sink_capacity_bytes == Some(0)
        {
            return Err(
                CaptureTrustPolicyValidationError::InvalidConfigConstraints {
                    key_id: key_id.to_owned(),
                    message: "constraint allowlist exceeds its bounded contract".to_owned(),
                },
            );
        }
        Ok(())
    }
}

fn validate_unique_nonempty(
    values: &[String],
    field: &'static str,
    key_id: &str,
) -> Result<(), CaptureTrustPolicyValidationError> {
    let mut unique = BTreeSet::new();
    if values.len() > MAX_CAPTURE_TRUST_CONSTRAINT_VALUES
        || values
            .iter()
            .any(|value| value.trim().is_empty() || !unique.insert(value.as_str()))
    {
        return Err(CaptureTrustPolicyValidationError::InvalidStringSet {
            key_id: key_id.to_owned(),
            field,
        });
    }
    Ok(())
}

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A malformed capture attestation before cryptographic verification.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CaptureAttestationValidationError {
    /// A required payload field is empty.
    #[error("capture attestation field `{field}` is empty")]
    EmptyField {
        /// Empty field path.
        field: String,
    },
    /// The embedded capture receipt is invalid.
    #[error("capture attestation receipt is invalid: {0}")]
    InvalidReceipt(CaptureReceiptValidationError),
    /// The capture-config artifact claim is invalid.
    #[error("capture attestation config claim is invalid: {0}")]
    InvalidCaptureConfig(CaptureConfigValidationError),
    /// The separately signed config claim differs from the embedded receipt claim.
    #[error("capture attestation config claim does not match its receipt")]
    CaptureConfigClaimMismatch,
    /// The controller-health artifact claim is invalid.
    #[error("capture attestation controller-health claim is invalid: {0}")]
    InvalidControllerHealth(CaptureConfigValidationError),
    /// The separately signed health claim differs from the embedded receipt claim.
    #[error("capture attestation controller-health claim does not match its receipt")]
    ControllerHealthClaimMismatch,
    /// The signature is not 64 lowercase hexadecimal bytes.
    #[error("capture attestation signature is not 64 lowercase hexadecimal bytes")]
    InvalidSignatureEncoding,
}

/// A malformed deployment capture-trust policy.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CaptureTrustPolicyValidationError {
    /// A required policy field is empty.
    #[error("capture trust policy field `{field}` is empty")]
    EmptyField {
        /// Empty field path.
        field: String,
    },
    /// A policy contains no trusted keys.
    #[error("capture trust policy contains no keys")]
    NoKeys,
    /// A key identifier is duplicated.
    #[error("capture trust policy contains duplicate key id `{key_id}`")]
    DuplicateKeyId {
        /// Duplicated key identifier.
        key_id: String,
    },
    /// A public key is not 32 lowercase hexadecimal bytes.
    #[error("capture trust key `{key_id}` has invalid Ed25519 public-key encoding")]
    InvalidPublicKeyEncoding {
        /// Invalid key identifier.
        key_id: String,
    },
    /// A trusted key permits no capture modes.
    #[error("capture trust key `{key_id}` permits no capture modes")]
    NoAllowedModes {
        /// Invalid key identifier.
        key_id: String,
    },
    /// A string allowlist is empty or duplicated.
    #[error("capture trust key `{key_id}` has invalid `{field}` values")]
    InvalidStringSet {
        /// Invalid key identifier.
        key_id: String,
        /// Invalid allowlist field.
        field: &'static str,
    },
    /// A trusted target identity is incomplete.
    #[error("capture trust key `{key_id}` has incomplete target identity")]
    IncompleteTarget {
        /// Invalid key identifier.
        key_id: String,
    },
    /// A TRACE32 trust key omits its build or architecture package.
    #[error("capture trust key `{key_id}` has incomplete TRACE32 identity")]
    IncompleteTrace32 {
        /// Invalid key identifier.
        key_id: String,
    },
    /// Trusted clock domains are absent or lack frequencies.
    #[error("capture trust key `{key_id}` has incomplete clock identity")]
    IncompleteClocks {
        /// Invalid key identifier.
        key_id: String,
    },
    /// Allowed cores are empty or duplicated.
    #[error("capture trust key `{key_id}` has invalid allowed cores")]
    InvalidAllowedCores {
        /// Invalid key identifier.
        key_id: String,
    },
    /// The firmware ELF allowlist is duplicated, oversized, or absent for TRACE32.
    #[error("capture trust key `{key_id}` has an invalid firmware ELF SHA-256 allowlist")]
    InvalidFirmwareElfAllowlist {
        /// Invalid key identifier.
        key_id: String,
    },
    /// The key's capability ceiling is semantically invalid.
    #[error("capture trust key `{key_id}` has invalid capability ceiling: {message}")]
    InvalidCapabilityCeiling {
        /// Invalid key identifier.
        key_id: String,
        /// Validation failure.
        message: String,
    },
    /// Optional capture-config constraints are malformed.
    #[error("capture trust key `{key_id}` has invalid capture-config constraints: {message}")]
    InvalidConfigConstraints {
        /// Invalid key identifier.
        key_id: String,
        /// Constraint validation failure.
        message: String,
    },
}

/// Evidence support for the observation families a capture can provide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CaptureCapabilities {
    /// Complete function enter/exit evidence.
    pub function_events: MetricSupportEntry,
    /// RTOS or scheduler context-switch evidence.
    pub context_switches: MetricSupportEntry,
    /// Interrupt enter/exit evidence.
    pub interrupt_events: MetricSupportEntry,
    /// Statistical program-counter samples.
    pub samples: MetricSupportEntry,
    /// Target-provided custom instant and span events.
    pub custom_events: MetricSupportEntry,
    /// Numeric resource and application counters.
    pub counters: MetricSupportEntry,
}

impl CaptureCapabilities {
    /// Creates a receipt in which no observation family has trusted evidence.
    #[must_use]
    pub fn unavailable(reason: impl Into<String>) -> Self {
        let entry = MetricSupportEntry {
            support: MetricSupportLevel::Unavailable,
            reasons: vec![reason.into()],
        };
        Self {
            function_events: entry.clone(),
            context_switches: entry.clone(),
            interrupt_events: entry.clone(),
            samples: entry.clone(),
            custom_events: entry.clone(),
            counters: entry,
        }
    }

    /// Validates that unavailable families explain their missing evidence.
    pub fn validate(&self) -> Result<(), CaptureReceiptValidationError> {
        for (family, entry) in [
            ("function_events", &self.function_events),
            ("context_switches", &self.context_switches),
            ("interrupt_events", &self.interrupt_events),
            ("samples", &self.samples),
            ("custom_events", &self.custom_events),
            ("counters", &self.counters),
        ] {
            if entry.support != MetricSupportLevel::Exact && entry.reasons.is_empty() {
                return Err(CaptureReceiptValidationError::NonExactWithoutReason {
                    family: family.to_owned(),
                    support: entry.support,
                });
            }
            let mut reasons = BTreeSet::new();
            for reason in &entry.reasons {
                if reason.trim().is_empty() {
                    return Err(CaptureReceiptValidationError::EmptyCapabilityReason {
                        family: family.to_owned(),
                    });
                }
                if !reasons.insert(reason) {
                    return Err(CaptureReceiptValidationError::DuplicateCapabilityReason {
                        family: family.to_owned(),
                        reason: reason.clone(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Immutable controller-produced evidence describing one completed capture.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CaptureReceipt {
    /// The capture-receipt schema version.
    pub schema: CaptureReceiptSchemaVersion,
    /// Session that owns this receipt and its artifacts.
    pub session_id: String,
    /// Capture provider, such as `synthetic` or `trace32`.
    pub provider: String,
    /// Capture mode, such as `etm`, `sampling`, or `instrumentation`.
    pub mode: String,
    /// Versioned adapter that produced the receipt.
    pub adapter: AdapterInfo,
    /// Target identity when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetInfo>,
    /// TRACE32 installation and probe evidence when TRACE32 was used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace32: Option<Trace32Info>,
    /// Firmware identity bound to the capture.
    pub firmware: FirmwareInfo,
    /// Clock domains required to interpret timestamps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clocks: Vec<ClockInfo>,
    /// Cores for which the receipt claims coverage.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub covered_cores: Vec<u32>,
    /// Evidence support for each observation family.
    pub capabilities: CaptureCapabilities,
    /// Raw capture- and parser-health facts supplied to host policy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub health_observations: Vec<HealthObservation>,
    /// Digest of the immutable Session request.
    pub request_sha256: Sha256Digest,
    /// Exact immutable configuration that governed this capture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_config: Option<CaptureConfigArtifactClaim>,
    /// Exact controller-validated hardware-health evidence covered by an external attestation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_health: Option<ControllerHealthArtifactClaim>,
    /// Adapter-specific, non-authoritative capture evidence.
    #[serde(default, skip_serializing_if = "Properties::is_empty")]
    pub properties: Properties,
}

impl CaptureReceipt {
    /// Validates identity, capability, clock, core, and health intervals.
    pub fn validate(&self) -> Result<(), CaptureReceiptValidationError> {
        for (field, value) in [
            ("session_id", self.session_id.as_str()),
            ("provider", self.provider.as_str()),
            ("mode", self.mode.as_str()),
            ("adapter.id", self.adapter.id.as_str()),
            ("adapter.version", self.adapter.version.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(CaptureReceiptValidationError::EmptyField {
                    field: field.to_owned(),
                });
            }
        }
        self.capabilities.validate()?;
        if let Some(claim) = &self.capture_config {
            claim
                .validate()
                .map_err(CaptureReceiptValidationError::InvalidCaptureConfig)?;
        }
        if let Some(claim) = &self.controller_health {
            claim
                .validate()
                .map_err(CaptureReceiptValidationError::InvalidControllerHealth)?;
        }

        let mut clocks = BTreeSet::new();
        for clock in &self.clocks {
            if clock.id.trim().is_empty() || !clocks.insert(clock.id.as_str()) {
                return Err(CaptureReceiptValidationError::InvalidClockId {
                    clock_id: clock.id.clone(),
                });
            }
            if clock.frequency_hz == Some(0) {
                return Err(CaptureReceiptValidationError::ZeroClockFrequency {
                    clock_id: clock.id.clone(),
                });
            }
            validate_optional_field("clock.source", clock.source.as_deref())?;
        }
        if let Some(target) = &self.target {
            validate_optional_field("target.architecture", target.architecture.as_deref())?;
            validate_optional_field("target.device", target.device.as_deref())?;
            validate_optional_field("target.board", target.board.as_deref())?;
            if target.core_count == Some(0) {
                return Err(CaptureReceiptValidationError::ZeroTargetCoreCount);
            }
        }
        if let Some(trace32) = &self.trace32 {
            validate_optional_field("trace32.build", trace32.build.as_deref())?;
            validate_optional_field("trace32.probe", trace32.probe.as_deref())?;
            validate_optional_field(
                "trace32.architecture_package",
                trace32.architecture_package.as_deref(),
            )?;
        }
        validate_optional_field("firmware.elf_path", self.firmware.elf_path.as_deref())?;
        validate_optional_field("firmware.build_id", self.firmware.build_id.as_deref())?;
        if self.provider == "trace32" && self.firmware.elf_sha256.is_none() {
            return Err(CaptureReceiptValidationError::MissingTrace32FirmwareElfSha256);
        }
        let mut cores = BTreeSet::new();
        for core in &self.covered_cores {
            if !cores.insert(*core) {
                return Err(CaptureReceiptValidationError::DuplicateCore { core_id: *core });
            }
        }
        for (index, observation) in self.health_observations.iter().enumerate() {
            if observation.code.trim().is_empty() {
                return Err(CaptureReceiptValidationError::EmptyField {
                    field: format!("health_observations[{index}].code"),
                });
            }
            if observation.source.trim().is_empty() {
                return Err(CaptureReceiptValidationError::EmptyField {
                    field: format!("health_observations[{index}].source"),
                });
            }
            validate_optional_field(
                &format!("health_observations[{index}].artifact_id"),
                observation.artifact_id.as_deref(),
            )?;
            if let (Some(start), Some(end)) = (observation.start_ns, observation.end_ns)
                && end < start
            {
                return Err(CaptureReceiptValidationError::InvalidHealthInterval {
                    code: observation.code.clone(),
                });
            }
        }
        Ok(())
    }
}

fn validate_optional_field(
    field: &str,
    value: Option<&str>,
) -> Result<(), CaptureReceiptValidationError> {
    if value.is_some_and(|value| value.trim().is_empty()) {
        return Err(CaptureReceiptValidationError::EmptyField {
            field: field.to_owned(),
        });
    }
    Ok(())
}

/// A semantic invariant violation in a capture receipt.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CaptureReceiptValidationError {
    /// A required identity field is empty.
    #[error("capture receipt field `{field}` is empty")]
    EmptyField {
        /// Empty field name.
        field: String,
    },
    /// A TRACE32 receipt omitted its required immutable firmware ELF digest.
    #[error("TRACE32 capture receipt omits firmware.elf_sha256")]
    MissingTrace32FirmwareElfSha256,
    /// A non-exact observation family does not explain its support level.
    #[error("capture capability `{family}` is {support:?} without a reason")]
    NonExactWithoutReason {
        /// Observation family.
        family: String,
        /// Declared support level.
        support: MetricSupportLevel,
    },
    /// A capability reason is empty.
    #[error("capture capability `{family}` contains an empty reason")]
    EmptyCapabilityReason {
        /// Observation family.
        family: String,
    },
    /// A capability reason is duplicated.
    #[error("capture capability `{family}` repeats reason `{reason}`")]
    DuplicateCapabilityReason {
        /// Observation family.
        family: String,
        /// Duplicated reason.
        reason: String,
    },
    /// A clock ID is empty or duplicated.
    #[error("capture receipt has invalid or duplicate clock id `{clock_id}`")]
    InvalidClockId {
        /// Invalid clock ID.
        clock_id: String,
    },
    /// A declared clock frequency is zero.
    #[error("capture clock `{clock_id}` has zero frequency")]
    ZeroClockFrequency {
        /// Invalid clock ID.
        clock_id: String,
    },
    /// A target declares zero processor cores.
    #[error("capture target has zero cores")]
    ZeroTargetCoreCount,
    /// One core appears more than once.
    #[error("capture receipt contains duplicate core id {core_id}")]
    DuplicateCore {
        /// Duplicated core ID.
        core_id: u32,
    },
    /// A health observation ends before it begins.
    #[error("capture health observation `{code}` has an invalid interval")]
    InvalidHealthInterval {
        /// Observation code.
        code: String,
    },
    /// The capture-config artifact claim is malformed.
    #[error("capture receipt config claim is invalid: {0}")]
    InvalidCaptureConfig(CaptureConfigValidationError),
    /// The controller-health artifact claim is malformed.
    #[error("capture receipt controller-health claim is invalid: {0}")]
    InvalidControllerHealth(CaptureConfigValidationError),
}
