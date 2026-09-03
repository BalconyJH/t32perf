//! Deployment-owned configuration contract for the real t32mcp driver.
//!
//! This module deliberately defines only bounded data and validation. Process
//! execution, environment handling, and filesystem resolution belong to the
//! deployment driver.

use std::{collections::BTreeSet, fmt};

use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use t32perf_model::{Sha256Digest, is_portable_artifact_id, strict_json};
use thiserror::Error;

/// Schema identifier for the deployment-owned t32mcp driver configuration.
pub const T32MCP_DRIVER_CONFIG_SCHEMA: &str = "t32perf.t32mcp-driver-config/v1";
/// The only official t32mcp version currently admitted by this driver contract.
pub const EXPECTED_T32MCP_DRIVER_VERSION: &str = "0.2.2";
/// Maximum encoded size of one t32mcp driver configuration document.
pub const MAX_T32MCP_DRIVER_CONFIG_BYTES: usize = 64 * 1024;
/// Absolute deployment ceiling for one requested performance-run workload.
pub const MAX_PERFORMANCE_RUN_DURATION_NS: u64 = 1_800_000_000_000;

const MAX_DRIVER_TEXT_BYTES: usize = 4 * 1024;
const MAX_DRIVER_ARGUMENTS: usize = 16;
const MIN_POLL_INTERVAL_MS: u64 = 10;
const MAX_POLL_INTERVAL_MS: u64 = 10_000;
const MIN_COMMAND_TIMEOUT_MS: u64 = 100;
const MAX_COMMAND_TIMEOUT_MS: u64 = 3_600_000;
const MAX_STDERR_BYTES: u64 = 1024 * 1024;

/// Supported t32mcp driver configuration schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum T32mcpDriverConfigSchemaVersion {
    /// Version 1.
    #[serde(rename = "t32perf.t32mcp-driver-config/v1")]
    V1,
}

/// Semantic role under which a deployment command is validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverCommandRole {
    /// Execute the fixed workload between the accepted start and stop phases.
    Workload,
    /// Disconnect TRACE32 at the fixed stop boundary.
    Trace32DisconnectAtStop,
    /// Ask the deployment-owned signer to write one capture attestation file.
    AttestationSigner,
}

impl DriverCommandRole {
    /// Returns the stable configuration-field spelling for this role.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Workload => "workload",
            Self::Trace32DisconnectAtStop => "trace32_disconnect_at_stop",
            Self::AttestationSigner => "attestation_signer",
        }
    }

    fn allows(self, placeholder: DriverCommandPlaceholder) -> bool {
        match self {
            Self::Workload => matches!(
                placeholder,
                DriverCommandPlaceholder::ArtifactRoot
                    | DriverCommandPlaceholder::SessionId
                    | DriverCommandPlaceholder::TransactionId
                    | DriverCommandPlaceholder::BindingSha256
                    | DriverCommandPlaceholder::InitialTargetState
                    | DriverCommandPlaceholder::WorkloadIdentity
                    | DriverCommandPlaceholder::DurationNs
            ),
            Self::Trace32DisconnectAtStop => matches!(
                placeholder,
                DriverCommandPlaceholder::ArtifactRoot
                    | DriverCommandPlaceholder::SessionId
                    | DriverCommandPlaceholder::TransactionId
                    | DriverCommandPlaceholder::BindingSha256
            ),
            Self::AttestationSigner => matches!(
                placeholder,
                DriverCommandPlaceholder::ArtifactRoot
                    | DriverCommandPlaceholder::SessionId
                    | DriverCommandPlaceholder::SigningRequestPath
                    | DriverCommandPlaceholder::SigningRequestSha256
                    | DriverCommandPlaceholder::AttestationOutputPath
                    | DriverCommandPlaceholder::PolicyId
                    | DriverCommandPlaceholder::KeyId
            ),
        }
    }

    fn required(self) -> &'static [DriverCommandPlaceholder] {
        match self {
            Self::Workload => &[
                DriverCommandPlaceholder::InitialTargetState,
                DriverCommandPlaceholder::WorkloadIdentity,
            ],
            Self::Trace32DisconnectAtStop => &[
                DriverCommandPlaceholder::TransactionId,
                DriverCommandPlaceholder::BindingSha256,
            ],
            Self::AttestationSigner => &[
                DriverCommandPlaceholder::SessionId,
                DriverCommandPlaceholder::SigningRequestPath,
                DriverCommandPlaceholder::SigningRequestSha256,
                DriverCommandPlaceholder::AttestationOutputPath,
                DriverCommandPlaceholder::PolicyId,
                DriverCommandPlaceholder::KeyId,
            ],
        }
    }
}

impl fmt::Display for DriverCommandRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A closed placeholder that may appear once in one command argument vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DriverCommandPlaceholder {
    /// Absolute artifact-root path supplied by the driver.
    ArtifactRoot,
    /// Portable Session identifier.
    SessionId,
    /// Immutable controller transaction identifier.
    TransactionId,
    /// Immutable controller binding digest.
    BindingSha256,
    /// Target state observed before the capture transaction.
    InitialTargetState,
    /// Fixed workload identity selected by the admitted adapter.
    WorkloadIdentity,
    /// Exact requested performance-run workload duration in nanoseconds.
    DurationNs,
    /// Absolute path of the immutable signing-request document.
    SigningRequestPath,
    /// Exact digest of the immutable signing-request document.
    SigningRequestSha256,
    /// Controller-reserved absolute path where the signer must write the attestation.
    AttestationOutputPath,
    /// Exact deployment trust-policy identity.
    PolicyId,
    /// Exact deployment signing-key identity.
    KeyId,
}

impl DriverCommandPlaceholder {
    /// Every placeholder admitted by this contract.
    pub const ALL: [Self; 12] = [
        Self::ArtifactRoot,
        Self::SessionId,
        Self::TransactionId,
        Self::BindingSha256,
        Self::InitialTargetState,
        Self::WorkloadIdentity,
        Self::DurationNs,
        Self::SigningRequestPath,
        Self::SigningRequestSha256,
        Self::AttestationOutputPath,
        Self::PolicyId,
        Self::KeyId,
    ];

    /// Returns the placeholder name without braces.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ArtifactRoot => "artifact_root",
            Self::SessionId => "session_id",
            Self::TransactionId => "transaction_id",
            Self::BindingSha256 => "binding_sha256",
            Self::InitialTargetState => "initial_target_state",
            Self::WorkloadIdentity => "workload_identity",
            Self::DurationNs => "duration_ns",
            Self::SigningRequestPath => "signing_request_path",
            Self::SigningRequestSha256 => "signing_request_sha256",
            Self::AttestationOutputPath => "attestation_output_path",
            Self::PolicyId => "policy_id",
            Self::KeyId => "key_id",
        }
    }

    /// Parses one exact placeholder name without braces.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|placeholder| placeholder.as_str() == value)
    }
}

/// One direct executable invocation with a closed, non-shell argument template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DriverCommand {
    /// Executable passed directly to the operating-system process API.
    #[schemars(length(min = 1, max = 4096))]
    pub executable: String,
    /// Exact executable digest from an administrator-verified deployment artifact.
    pub expected_executable_sha256: Sha256Digest,
    /// Separate argv entries; no command line or shell parsing is permitted.
    #[schemars(length(max = 16))]
    pub arguments: Vec<String>,
    /// Independent wall-clock timeout for this invocation.
    #[schemars(range(min = 100, max = 3600000))]
    pub timeout_ms: u64,
}

impl DriverCommand {
    /// Validates bounds, shell-free templates, and role-specific placeholders.
    pub fn validate(&self, role: DriverCommandRole) -> Result<(), T32mcpDriverConfigError> {
        validate_text("executable", &self.executable)
            .map_err(|message| command_error(role, message))?;
        if self.arguments.len() > MAX_DRIVER_ARGUMENTS {
            return Err(command_error(
                role,
                format!("arguments contains more than {MAX_DRIVER_ARGUMENTS} entries"),
            ));
        }
        validate_range(
            "timeout_ms",
            self.timeout_ms,
            MIN_COMMAND_TIMEOUT_MS,
            MAX_COMMAND_TIMEOUT_MS,
        )
        .map_err(|message| command_error(role, message))?;

        let mut placeholders = BTreeSet::new();
        for argument in &self.arguments {
            validate_argument(argument).map_err(|message| command_error(role, message))?;
            for placeholder in
                placeholders_in(argument).map_err(|message| command_error(role, message))?
            {
                if !role.allows(placeholder) {
                    return Err(command_error(
                        role,
                        format!(
                            "placeholder `{{{}}}` is not allowed for this role",
                            placeholder.as_str()
                        ),
                    ));
                }
                if !placeholders.insert(placeholder) {
                    return Err(command_error(
                        role,
                        format!(
                            "placeholder `{{{}}}` occurs more than once",
                            placeholder.as_str()
                        ),
                    ));
                }
            }
        }
        for required in role.required() {
            if !placeholders.contains(required) {
                return Err(command_error(
                    role,
                    format!(
                        "required placeholder `{{{}}}` is missing",
                        required.as_str()
                    ),
                ));
            }
        }
        Ok(())
    }

    fn contains_placeholder(&self, expected: DriverCommandPlaceholder) -> bool {
        self.arguments.iter().any(|argument| {
            placeholders_in(argument).is_ok_and(|placeholders| placeholders.contains(&expected))
        })
    }
}

/// Closed set of external fault-injection hooks.
///
/// CMM abort is intentionally absent because it must use the official t32mcp
/// abort operation rather than an arbitrary deployment command.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DriverFaultActions {
    /// Optional command that disconnects TRACE32 at the accepted stop boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace32_disconnect_at_stop: Option<DriverCommand>,
}

/// Deployment-owned immutable firmware input used by the one-request performance workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DriverFirmwareDeployment {
    /// Absolute plain-file path of the approved firmware ELF.
    #[schemars(length(min = 1, max = 4096))]
    pub path: String,
    /// Exact digest of the approved firmware ELF.
    pub sha256: Sha256Digest,
}

/// One immutable deployment-owned input file admitted by exact digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DriverQualificationInput {
    /// Absolute plain-file path of the approved input.
    #[schemars(length(min = 1, max = 4096))]
    pub path: String,
    /// Exact digest of the approved input bytes.
    pub sha256: Sha256Digest,
}

/// One immutable build resource admitted solely by its path and exact digest.
///
/// Resource identity, artifact kind, and media type are deliberately not
/// configurable at the deployment boundary. The consuming `perf_run` stage
/// assigns those closed semantics from the field that carries this input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DriverPerformanceRunResourceInput {
    /// Absolute plain-file path of the approved build resource.
    #[schemars(length(min = 1, max = 4096))]
    pub path: String,
    /// Exact digest of the approved build resource bytes.
    pub sha256: Sha256Digest,
}

/// All required inputs for a qualified TRACE32 TASKEVENTS program-flow capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DriverPerformanceRunProgramFlowResources {
    /// Approved OSEK/ORTI awareness input.
    pub orti: DriverPerformanceRunResourceInput,
    /// Approved task marker input emitted by the workload build.
    pub task_markers: DriverPerformanceRunResourceInput,
    /// Approved TASKEVENTS mapping template materialized after capture binding.
    pub task_events_mapping_template: DriverPerformanceRunResourceInput,
}

/// All required inputs for a qualified custom-event capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DriverPerformanceRunCustomEventResources {
    /// Approved C SDK wire context/counter mapping.
    pub c_wire_mapping: DriverPerformanceRunResourceInput,
    /// Approved instrumentation overhead evidence.
    pub instrumentation_overhead: DriverPerformanceRunResourceInput,
}

/// Optional immutable build resources provisioned by a performance deployment.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DriverPerformanceRunResources {
    /// Optional linker map for static RAM analysis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linker_map: Option<DriverPerformanceRunResourceInput>,
    /// Optional compiler stack-usage report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack_usage: Option<DriverPerformanceRunResourceInput>,
    /// Optional static-RAM parser configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_ram_config: Option<DriverPerformanceRunResourceInput>,
    /// Optional all-or-nothing program-flow resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program_flow: Option<DriverPerformanceRunProgramFlowResources>,
    /// Optional all-or-nothing custom-event resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_events: Option<DriverPerformanceRunCustomEventResources>,
}

/// Deployment-owned target-adapter qualification inputs for `perf_run` provisioning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DriverPerformanceRunQualificationDeployment {
    /// Exact qualification trust-policy identity selected from the artifact-root deployment.
    #[schemars(length(min = 1, max = 4096))]
    pub policy_id: String,
    /// Approved target-adapter qualification receipt.
    pub qualification_receipt: DriverQualificationInput,
    /// Approved HIL verification receipt bound by the qualification receipt.
    pub hil_receipt: DriverQualificationInput,
    /// Optional approved recovery evidence required by a recovery HIL receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_evidence: Option<DriverQualificationInput>,
}

/// Deployment-owned capture-attestation signer and trust-root selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DriverAttestationDeployment {
    /// Absolute plain-file path of the approved capture trust policy.
    #[schemars(length(min = 1, max = 4096))]
    pub policy_path: String,
    /// Exact digest of the approved capture trust policy bytes.
    pub policy_sha256: Sha256Digest,
    /// Exact policy identity expected inside the strict policy document.
    #[schemars(length(min = 1, max = 4096))]
    pub policy_id: String,
    /// Exact signing-key identity that must exist in the policy.
    #[schemars(length(min = 1, max = 4096))]
    pub key_id: String,
    /// Direct-argv signer invocation. Attestation bytes are written only to its output path.
    pub signer_command: DriverCommand,
    /// Required signer protocol guarantee for safe exact-request retry.
    pub idempotent_by_signing_request_sha256: bool,
}

/// Optional deployment inputs required by the one-request performance workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DriverPerformanceRunDeployment {
    /// Maximum caller-requested workload duration admitted by this deployment.
    #[schemars(range(min = 1_u64, max = 1_800_000_000_000_u64))]
    pub max_duration_ns: u64,
    /// Approved firmware source copied into each new performance Session.
    pub firmware: DriverFirmwareDeployment,
    /// Deployment-owned workload that consumes the exact requested duration.
    pub workload_command: DriverCommand,
    /// Approved qualification inputs provisioned into every performance Session.
    pub qualification: DriverPerformanceRunQualificationDeployment,
    /// Approved trust policy and external signer.
    pub attestation: DriverAttestationDeployment,
    /// Closed optional build resources provisioned with this deployment.
    #[serde(default)]
    pub resources: DriverPerformanceRunResources,
}

impl DriverPerformanceRunDeployment {
    fn validate(&self) -> Result<(), T32mcpDriverConfigError> {
        validate_range(
            "performance_run.max_duration_ns",
            self.max_duration_ns,
            1,
            MAX_PERFORMANCE_RUN_DURATION_NS,
        )
        .map_err(config_error)?;
        validate_text("performance_run.firmware.path", &self.firmware.path)
            .map_err(config_error)?;
        validate_text(
            "performance_run.qualification.policy_id",
            &self.qualification.policy_id,
        )
        .map_err(config_error)?;
        if !is_portable_artifact_id(&self.qualification.policy_id) {
            return Err(config_error(
                "performance_run.qualification.policy_id must be a portable artifact ID",
            ));
        }
        for (field, input) in [
            (
                "performance_run.qualification.qualification_receipt.path",
                &self.qualification.qualification_receipt,
            ),
            (
                "performance_run.qualification.hil_receipt.path",
                &self.qualification.hil_receipt,
            ),
        ] {
            validate_text(field, &input.path).map_err(config_error)?;
        }
        if let Some(recovery) = &self.qualification.recovery_evidence {
            validate_text(
                "performance_run.qualification.recovery_evidence.path",
                &recovery.path,
            )
            .map_err(config_error)?;
        }
        validate_text(
            "performance_run.attestation.policy_path",
            &self.attestation.policy_path,
        )
        .map_err(config_error)?;
        validate_text(
            "performance_run.attestation.policy_id",
            &self.attestation.policy_id,
        )
        .map_err(config_error)?;
        validate_text(
            "performance_run.attestation.key_id",
            &self.attestation.key_id,
        )
        .map_err(config_error)?;
        if !self.attestation.idempotent_by_signing_request_sha256 {
            return Err(config_error(
                "performance_run.attestation.idempotent_by_signing_request_sha256 must be true",
            ));
        }
        for (field, input) in [
            (
                "performance_run.resources.linker_map.path",
                self.resources.linker_map.as_ref(),
            ),
            (
                "performance_run.resources.stack_usage.path",
                self.resources.stack_usage.as_ref(),
            ),
            (
                "performance_run.resources.static_ram_config.path",
                self.resources.static_ram_config.as_ref(),
            ),
        ] {
            if let Some(input) = input {
                validate_text(field, &input.path).map_err(config_error)?;
            }
        }
        if let Some(program_flow) = &self.resources.program_flow {
            for (field, input) in [
                (
                    "performance_run.resources.program_flow.orti.path",
                    &program_flow.orti,
                ),
                (
                    "performance_run.resources.program_flow.task_markers.path",
                    &program_flow.task_markers,
                ),
                (
                    "performance_run.resources.program_flow.task_events_mapping_template.path",
                    &program_flow.task_events_mapping_template,
                ),
            ] {
                validate_text(field, &input.path).map_err(config_error)?;
            }
        }
        if let Some(custom_events) = &self.resources.custom_events {
            for (field, input) in [
                (
                    "performance_run.resources.custom_events.c_wire_mapping.path",
                    &custom_events.c_wire_mapping,
                ),
                (
                    "performance_run.resources.custom_events.instrumentation_overhead.path",
                    &custom_events.instrumentation_overhead,
                ),
            ] {
                validate_text(field, &input.path).map_err(config_error)?;
            }
        }
        self.workload_command
            .validate(DriverCommandRole::Workload)?;
        if !self
            .workload_command
            .contains_placeholder(DriverCommandPlaceholder::DurationNs)
        {
            return Err(command_error(
                DriverCommandRole::Workload,
                "performance_run.workload_command must contain the required `{duration_ns}` placeholder"
                    .to_owned(),
            ));
        }
        let maximum_duration_ms = self.max_duration_ns.div_ceil(1_000_000);
        if maximum_duration_ms >= self.workload_command.timeout_ms {
            return Err(command_error(
                DriverCommandRole::Workload,
                format!(
                    "performance_run.workload_command timeout_ms `{}` must be strictly greater than max_duration_ns rounded up to `{maximum_duration_ms}` ms",
                    self.workload_command.timeout_ms
                ),
            ));
        }
        self.attestation
            .signer_command
            .validate(DriverCommandRole::AttestationSigner)
    }
}

/// Complete deployment-owned configuration for one real t32mcp endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct T32mcpDriverConfig {
    /// Versioned configuration family.
    pub schema: T32mcpDriverConfigSchemaVersion,
    /// Official t32mcp executable passed directly to the process API.
    #[schemars(length(min = 1, max = 4096))]
    pub executable: String,
    /// Exact official t32mcp executable digest from an administrator-verified release.
    pub expected_executable_sha256: Sha256Digest,
    /// Read-only root containing the installed fixed PRACTICE skills.
    #[schemars(length(min = 1, max = 4096))]
    pub skills_root: String,
    /// Nonzero TCP port for the single-tenant TRACE32 endpoint.
    #[schemars(range(min = 1))]
    pub trace32_port: u16,
    /// Exact upstream implementation version admitted by this release.
    #[schemars(regex(pattern = r"^0\.2\.2$"))]
    pub expected_t32mcp_version: String,
    /// Exact digest of the verified fixed t32mcp skill/adapter bundle.
    pub expected_bundle_sha256: Sha256Digest,
    /// Interval between bounded collection polls.
    #[schemars(range(min = 10, max = 10000))]
    pub poll_interval_ms: u64,
    /// Default wall-clock deadline for one official MCP operation.
    #[schemars(range(min = 100, max = 3600000))]
    pub operation_timeout_ms: u64,
    /// Maximum stderr bytes retained from one child process.
    #[schemars(range(min = 1, max = 1048576))]
    pub max_stderr_bytes: u64,
    /// Optional external owner for the fixed workload window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload: Option<DriverCommand>,
    /// Closed external fault-injection hooks.
    pub fault_actions: DriverFaultActions,
    /// Optional deployment inputs for the one-request performance workflow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub performance_run: Option<DriverPerformanceRunDeployment>,
}

impl T32mcpDriverConfig {
    /// Validates the complete configuration without accessing the filesystem.
    pub fn validate(&self) -> Result<(), T32mcpDriverConfigError> {
        validate_text("executable", &self.executable).map_err(config_error)?;
        validate_text("skills_root", &self.skills_root).map_err(config_error)?;
        if self.trace32_port == 0 {
            return Err(config_error("trace32_port must be nonzero"));
        }
        if self.expected_t32mcp_version != EXPECTED_T32MCP_DRIVER_VERSION {
            return Err(config_error(format!(
                "expected_t32mcp_version must be exactly `{EXPECTED_T32MCP_DRIVER_VERSION}`"
            )));
        }
        validate_range(
            "poll_interval_ms",
            self.poll_interval_ms,
            MIN_POLL_INTERVAL_MS,
            MAX_POLL_INTERVAL_MS,
        )
        .map_err(config_error)?;
        validate_range(
            "operation_timeout_ms",
            self.operation_timeout_ms,
            MIN_COMMAND_TIMEOUT_MS,
            MAX_COMMAND_TIMEOUT_MS,
        )
        .map_err(config_error)?;
        validate_range(
            "max_stderr_bytes",
            self.max_stderr_bytes,
            1,
            MAX_STDERR_BYTES,
        )
        .map_err(config_error)?;
        if let Some(command) = &self.workload {
            command.validate(DriverCommandRole::Workload)?;
            if command.contains_placeholder(DriverCommandPlaceholder::DurationNs) {
                return Err(command_error(
                    DriverCommandRole::Workload,
                    "top-level workload cannot contain `{duration_ns}`; it is reserved for performance_run.workload_command"
                        .to_owned(),
                ));
            }
        }
        if let Some(command) = &self.fault_actions.trace32_disconnect_at_stop {
            command.validate(DriverCommandRole::Trace32DisconnectAtStop)?;
        }
        if let Some(performance_run) = &self.performance_run {
            performance_run.validate()?;
        }
        Ok(())
    }
}

/// Strict parsing or semantic validation failure for a driver configuration.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum T32mcpDriverConfigError {
    /// The encoded document is empty, oversized, duplicate-keyed, or malformed.
    #[error("t32mcp driver configuration is invalid JSON: {message}")]
    InvalidDocument {
        /// Stable parsing detail.
        message: String,
    },
    /// A top-level configuration field violates its closed contract.
    #[error("t32mcp driver configuration is invalid: {message}")]
    InvalidConfig {
        /// Stable validation detail.
        message: String,
    },
    /// A workload or fault command violates its role-specific contract.
    #[error("t32mcp driver command `{role}` is invalid: {message}")]
    InvalidCommand {
        /// Command role being validated.
        role: DriverCommandRole,
        /// Stable validation detail.
        message: String,
    },
}

/// Strictly decodes and validates one bounded t32mcp driver configuration.
pub fn parse_t32mcp_driver_config(
    bytes: &[u8],
) -> Result<T32mcpDriverConfig, T32mcpDriverConfigError> {
    if bytes.is_empty() || bytes.len() > MAX_T32MCP_DRIVER_CONFIG_BYTES {
        return Err(T32mcpDriverConfigError::InvalidDocument {
            message: format!(
                "document size must be within 1..={MAX_T32MCP_DRIVER_CONFIG_BYTES} bytes"
            ),
        });
    }
    let config = strict_json::from_slice::<T32mcpDriverConfig>(bytes).map_err(|error| {
        T32mcpDriverConfigError::InvalidDocument {
            message: error.to_string(),
        }
    })?;
    config.validate()?;
    Ok(config)
}

/// Returns generated JSON Schema documents for driver deployment contracts.
#[must_use]
pub fn driver_schema_documents() -> std::collections::BTreeMap<&'static str, Value> {
    std::collections::BTreeMap::from([(
        "t32mcp-driver-config.schema.json",
        schema_document::<T32mcpDriverConfig>(T32MCP_DRIVER_CONFIG_SCHEMA),
    )])
}

fn placeholders_in(argument: &str) -> Result<Vec<DriverCommandPlaceholder>, String> {
    let mut placeholders = Vec::new();
    let mut offset = 0;
    while let Some(relative) = argument[offset..].find(|character| ['{', '}'].contains(&character))
    {
        let start = offset + relative;
        if argument.as_bytes()[start] == b'}' {
            return Err("argument contains an unmatched closing brace".to_owned());
        }
        let name_start = start + 1;
        let Some(relative_end) = argument[name_start..].find('}') else {
            return Err("argument contains an unmatched opening brace".to_owned());
        };
        let end = name_start + relative_end;
        let name = &argument[name_start..end];
        if name.contains('{') {
            return Err("argument contains nested placeholder braces".to_owned());
        }
        let placeholder = DriverCommandPlaceholder::parse(name)
            .ok_or_else(|| format!("unknown placeholder `{{{name}}}`"))?;
        placeholders.push(placeholder);
        offset = end + 1;
    }
    Ok(placeholders)
}

fn validate_argument(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_DRIVER_TEXT_BYTES {
        return Err(format!(
            "argument is empty or longer than {MAX_DRIVER_TEXT_BYTES} bytes"
        ));
    }
    if value.chars().any(char::is_control) {
        return Err("argument contains a control character".to_owned());
    }
    const SHELL_METACHARACTERS: [char; 17] = [
        '&', '|', ';', '<', '>', '`', '$', '"', '\'', '^', '%', '!', '(', ')', '*', '?', '~',
    ];
    if let Some(character) = value
        .chars()
        .find(|character| SHELL_METACHARACTERS.contains(character))
    {
        return Err(format!(
            "argument contains forbidden shell metacharacter `{character}`"
        ));
    }
    Ok(())
}

fn validate_text(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_DRIVER_TEXT_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(format!(
            "{field} is empty, longer than {MAX_DRIVER_TEXT_BYTES} bytes, noncanonical, or contains a control character"
        ))
    } else {
        Ok(())
    }
}

fn validate_range(field: &str, value: u64, minimum: u64, maximum: u64) -> Result<(), String> {
    if (minimum..=maximum).contains(&value) {
        Ok(())
    } else {
        Err(format!("{field} must be within {minimum}..={maximum}"))
    }
}

fn command_error(role: DriverCommandRole, message: String) -> T32mcpDriverConfigError {
    T32mcpDriverConfigError::InvalidCommand { role, message }
}

fn config_error(message: impl Into<String>) -> T32mcpDriverConfigError {
    T32mcpDriverConfigError::InvalidConfig {
        message: message.into(),
    }
}

fn schema_document<T: JsonSchema>(id: &'static str) -> Value {
    let mut schema =
        serde_json::to_value(schema_for!(T)).expect("schema serialization is infallible");
    let root = schema.as_object_mut().expect("root schemas are objects");
    root.insert("$id".to_owned(), Value::String(id.to_owned()));
    root.get_mut("properties")
        .and_then(Value::as_object_mut)
        .and_then(|properties| properties.get_mut("expected_t32mcp_version"))
        .and_then(Value::as_object_mut)
        .expect("driver version schema is an object")
        .insert(
            "const".to_owned(),
            Value::String(EXPECTED_T32MCP_DRIVER_VERSION.to_owned()),
        );
    let argument_items = root
        .get_mut("$defs")
        .and_then(Value::as_object_mut)
        .and_then(|definitions| definitions.get_mut("DriverCommand"))
        .and_then(Value::as_object_mut)
        .and_then(|command| command.get_mut("properties"))
        .and_then(Value::as_object_mut)
        .and_then(|properties| properties.get_mut("arguments"))
        .and_then(Value::as_object_mut)
        .and_then(|arguments| arguments.get_mut("items"))
        .and_then(Value::as_object_mut)
        .expect("driver argument item schema is an object");
    argument_items.insert("minLength".to_owned(), Value::from(1));
    argument_items.insert(
        "maxLength".to_owned(),
        Value::from(u64::try_from(MAX_DRIVER_TEXT_BYTES).expect("fixed bound fits u64")),
    );
    root.get_mut("$defs")
        .and_then(Value::as_object_mut)
        .and_then(|definitions| definitions.get_mut("DriverAttestationDeployment"))
        .and_then(Value::as_object_mut)
        .and_then(|attestation| attestation.get_mut("properties"))
        .and_then(Value::as_object_mut)
        .and_then(|properties| properties.get_mut("idempotent_by_signing_request_sha256"))
        .and_then(Value::as_object_mut)
        .expect("signer idempotency schema is an object")
        .insert("const".to_owned(), Value::Bool(true));
    schema
}
