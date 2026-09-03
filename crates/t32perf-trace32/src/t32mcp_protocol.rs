//! Strict host-side parser for framed t32mcp PRACTICE responses.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use t32perf_model::strict_json;
use thiserror::Error;

/// Fixed logical skill name passed to t32mcp.
pub const T32PERF_SKILL_NAME: &str = "trace32-perf";
/// Response protocol identifier.
pub const T32PERF_PROTOCOL: &str = "t32perf/1";
/// Beginning marker for one response payload.
pub const T32PERF_RESULT_BEGIN: &str = "T32PERF_RESULT_BEGIN";
/// Ending marker for one response payload.
pub const T32PERF_RESULT_END: &str = "T32PERF_RESULT_END";
/// Exact official t32mcp tool used to start a fixed skill script.
pub const T32MCP_EXECUTE_TOOL: &str = "execute_practice_skill";
/// Exact official t32mcp tool used to poll or collect a script response.
pub const T32MCP_COLLECT_TOOL: &str = "collect_practice_skill_response";
/// Exact official t32mcp tool used to abort the globally active script.
pub const T32MCP_ABORT_TOOL: &str = "abort_practice_skill";

/// Fixed script filename for capability discovery.
pub const PERF_GET_CAPABILITIES_SCRIPT: &str = "perf_get_capabilities.cmm";
/// Fixed script filename for capture configuration.
pub const PERF_CONFIGURE_SCRIPT: &str = "perf_configure.cmm";
/// Fixed script filename for capture start.
pub const PERF_START_SCRIPT: &str = "perf_start.cmm";
/// Fixed script filename for capture stop.
pub const PERF_STOP_SCRIPT: &str = "perf_stop.cmm";
/// Fixed script filename for health retrieval.
pub const PERF_GET_HEALTH_SCRIPT: &str = "perf_get_health.cmm";
/// Fixed script filename for trace export.
pub const PERF_EXPORT_SCRIPT: &str = "perf_export.cmm";
/// Fixed script filename for hotspot retrieval.
pub const PERF_GET_HOTSPOTS_SCRIPT: &str = "perf_get_hotspots.cmm";
/// Fixed script filename for capture cleanup.
pub const PERF_CLEANUP_SCRIPT: &str = "perf_cleanup.cmm";
/// V2 adapter-owned script filename for capture configuration.
pub const PERF_CONFIGURE_V2_SCRIPT: &str = "perf_configure_v2.cmm";
/// V2 adapter-owned script filename for capture start.
pub const PERF_START_V2_SCRIPT: &str = "perf_start_v2.cmm";
/// V2 adapter-owned script filename for capture stop.
pub const PERF_STOP_V2_SCRIPT: &str = "perf_stop_v2.cmm";
/// V2 adapter-owned script filename for health retrieval.
pub const PERF_GET_HEALTH_V2_SCRIPT: &str = "perf_get_health_v2.cmm";
/// V2 adapter-owned script filename for multi-output export.
pub const PERF_EXPORT_V2_SCRIPT: &str = "perf_export_v2.cmm";
/// V2 adapter-owned script filename for capture cleanup.
pub const PERF_CLEANUP_V2_SCRIPT: &str = "perf_cleanup_v2.cmm";

/// A fixed script operation exposed by the TRACE32 performance skill.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub enum PerfOperation {
    /// Capability discovery.
    #[serde(rename = "perf_get_capabilities")]
    GetCapabilities,
    /// Target-specific configuration.
    #[serde(rename = "perf_configure")]
    Configure,
    /// Capture start.
    #[serde(rename = "perf_start")]
    Start,
    /// Capture stop.
    #[serde(rename = "perf_stop")]
    Stop,
    /// Health retrieval.
    #[serde(rename = "perf_get_health")]
    GetHealth,
    /// Artifact export.
    #[serde(rename = "perf_export")]
    Export,
    /// Hotspot retrieval.
    #[serde(rename = "perf_get_hotspots")]
    GetHotspots,
    /// Capture-state cleanup.
    #[serde(rename = "perf_cleanup")]
    Cleanup,
}

impl PerfOperation {
    /// Every supported operation in script-name order.
    pub const ALL: [Self; 8] = [
        Self::GetCapabilities,
        Self::Configure,
        Self::Start,
        Self::Stop,
        Self::GetHealth,
        Self::Export,
        Self::GetHotspots,
        Self::Cleanup,
    ];

    /// Returns the exact operation string in framed JSON.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetCapabilities => "perf_get_capabilities",
            Self::Configure => "perf_configure",
            Self::Start => "perf_start",
            Self::Stop => "perf_stop",
            Self::GetHealth => "perf_get_health",
            Self::Export => "perf_export",
            Self::GetHotspots => "perf_get_hotspots",
            Self::Cleanup => "perf_cleanup",
        }
    }

    /// Returns the exact fixed script filename.
    #[must_use]
    pub const fn script_name(self) -> &'static str {
        match self {
            Self::GetCapabilities => PERF_GET_CAPABILITIES_SCRIPT,
            Self::Configure => PERF_CONFIGURE_SCRIPT,
            Self::Start => PERF_START_SCRIPT,
            Self::Stop => PERF_STOP_SCRIPT,
            Self::GetHealth => PERF_GET_HEALTH_SCRIPT,
            Self::Export => PERF_EXPORT_SCRIPT,
            Self::GetHotspots => PERF_GET_HOTSPOTS_SCRIPT,
            Self::Cleanup => PERF_CLEANUP_SCRIPT,
        }
    }

    /// Returns the exact adapter-owned Controller V2 script filename.
    ///
    /// Capability and hotspot operations are intentionally V1-only and return
    /// `None`; a V2 request must therefore name one of the six target stages.
    #[must_use]
    pub const fn v2_script_name(self) -> Option<&'static str> {
        match self {
            Self::Configure => Some(PERF_CONFIGURE_V2_SCRIPT),
            Self::Start => Some(PERF_START_V2_SCRIPT),
            Self::Stop => Some(PERF_STOP_V2_SCRIPT),
            Self::GetHealth => Some(PERF_GET_HEALTH_V2_SCRIPT),
            Self::Export => Some(PERF_EXPORT_V2_SCRIPT),
            Self::Cleanup => Some(PERF_CLEANUP_V2_SCRIPT),
            Self::GetCapabilities | Self::GetHotspots => None,
        }
    }

    /// Parses an exact framed operation name.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|operation| operation.as_str() == value)
    }
}

/// Typed status returned by a fixed PRACTICE script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum PerfStatus {
    /// The requested script operation completed.
    #[serde(rename = "OK")]
    Ok,
    /// Script arguments were rejected.
    #[serde(rename = "INVALID_ARGUMENT")]
    InvalidArgument,
    /// Real TRACE32, target, build, mapping, or adapter evidence is required.
    #[serde(rename = "UNSUPPORTED_NEEDS_TRACE32")]
    UnsupportedNeedsTrace32,
    /// A host parser or analysis stage must continue the operation.
    #[serde(rename = "HOST_PROCESSING_REQUIRED")]
    HostProcessingRequired,
}

impl PerfStatus {
    /// Returns the exact status string in framed JSON.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::UnsupportedNeedsTrace32 => "UNSUPPORTED_NEEDS_TRACE32",
            Self::HostProcessingRequired => "HOST_PROCESSING_REQUIRED",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        [
            Self::Ok,
            Self::InvalidArgument,
            Self::UnsupportedNeedsTrace32,
            Self::HostProcessingRequired,
        ]
        .into_iter()
        .find(|status| status.as_str() == value)
    }
}

/// Validated result payload returned by one fixed script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerfScriptResponse {
    /// Fixed protocol version.
    pub protocol: &'static str,
    /// Typed fixed operation.
    pub operation: PerfOperation,
    /// Typed operation status.
    pub status: PerfStatus,
    /// Stable snake-case result code.
    pub code: String,
    /// Transaction binding digest echoed by the fixed script.
    pub binding_sha256: String,
    /// Cleanup evidence, present only in cleanup responses.
    pub files_deleted: Option<bool>,
}

/// Maximum size configuration for one framed payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerfFrameLimits {
    /// Maximum UTF-8 bytes in the single JSON payload line.
    pub max_payload_bytes: usize,
}

impl Default for PerfFrameLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: 2048,
        }
    }
}

/// Strict t32mcp wrapper or T32Perf frame failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PerfFrameError {
    /// Payload size limit is zero.
    #[error("frame payload limit must be nonzero")]
    InvalidLimit,
    /// t32mcp reports that the PRACTICE script is still running.
    #[error("t32mcp PRACTICE response is not finished")]
    NotFinished,
    /// The wrapper does not contain its required content marker.
    #[error("missing t32mcp <CONTENT> marker")]
    MissingContentMarker,
    /// The wrapper contains multiple content markers.
    #[error("duplicate t32mcp <CONTENT> marker")]
    DuplicateContentMarker,
    /// The wrapper or content contains output outside the exact protocol frame.
    #[error("protocol contamination at line {line}: `{text}`")]
    ProtocolContamination {
        /// One-based wrapper line.
        line: usize,
        /// Unexpected text.
        text: String,
    },
    /// The beginning marker is absent.
    #[error("missing T32PERF_RESULT_BEGIN marker")]
    MissingBeginMarker,
    /// The ending marker is absent.
    #[error("missing T32PERF_RESULT_END marker")]
    MissingEndMarker,
    /// The beginning marker appears more than once.
    #[error("duplicate T32PERF_RESULT_BEGIN marker")]
    DuplicateBeginMarker,
    /// The ending marker appears more than once.
    #[error("duplicate T32PERF_RESULT_END marker")]
    DuplicateEndMarker,
    /// Marker order or payload line count is invalid.
    #[error("frame contains {actual} payload lines; expected exactly one")]
    PayloadLineCount {
        /// Actual number of lines between markers.
        actual: usize,
    },
    /// The JSON line exceeds its configured bound.
    #[error("frame payload size {actual} exceeds {limit}")]
    PayloadTooLarge {
        /// Configured maximum.
        limit: usize,
        /// Actual payload bytes.
        actual: usize,
    },
    /// The payload is not a valid JSON object.
    #[error("invalid frame JSON: {message}")]
    InvalidJson {
        /// JSON error text.
        message: String,
    },
    /// The payload contains an unknown field.
    #[error("unknown frame field `{field}`")]
    UnknownField {
        /// Rejected field name.
        field: String,
    },
    /// The protocol value is absent or incompatible.
    #[error("unsupported frame protocol `{actual}`")]
    InvalidProtocol {
        /// Rejected protocol text.
        actual: String,
    },
    /// The operation is not one of the eight fixed scripts.
    #[error("unknown frame operation `{operation}`")]
    UnknownOperation {
        /// Rejected operation text.
        operation: String,
    },
    /// The status is not part of protocol v1.
    #[error("unknown frame status `{status}`")]
    UnknownStatus {
        /// Rejected status text.
        status: String,
    },
    /// The result code is empty or not ASCII snake_case.
    #[error("invalid frame code `{code}`")]
    InvalidCode {
        /// Rejected code.
        code: String,
    },
    /// The operation does not define the supplied result code.
    #[error("unknown code `{code}` for operation `{operation}`")]
    UnknownCode {
        /// Typed operation.
        operation: &'static str,
        /// Rejected code.
        code: String,
    },
    /// A known result code was paired with the wrong status.
    #[error("code `{code}` requires status `{expected}`, not `{actual}`")]
    CodeStatusMismatch {
        /// Result code.
        code: String,
        /// Required status.
        expected: &'static str,
        /// Rejected status.
        actual: &'static str,
    },
    /// Cleanup reported file deletion, which is forbidden by the protocol.
    #[error("cleanup response reports deleted files")]
    CleanupDeletedFiles,
    /// Binding is absent or is not one lowercase SHA-256 digest.
    #[error("invalid controller binding digest `{binding}`")]
    InvalidBinding {
        /// Rejected binding text.
        binding: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPerfPayload {
    protocol: String,
    operation: String,
    status: String,
    code: String,
    binding_sha256: String,
    files_deleted: Option<bool>,
    expected_initial_target_state: Option<String>,
    observed_target_state: Option<String>,
}

/// Parses one completed t32mcp wrapper and validates its exact response frame.
pub fn parse_t32mcp_perf_response(
    wrapper: &str,
    limits: PerfFrameLimits,
) -> Result<PerfScriptResponse, PerfFrameError> {
    if limits.max_payload_bytes == 0 {
        return Err(PerfFrameError::InvalidLimit);
    }
    let lines = wrapper.lines().collect::<Vec<_>>();
    if is_valid_not_finished_wrapper(&lines) {
        return Err(PerfFrameError::NotFinished);
    }
    let content_indices = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| (*line == "<CONTENT>").then_some(index))
        .collect::<Vec<_>>();
    let content_index = match content_indices.as_slice() {
        [] => return Err(PerfFrameError::MissingContentMarker),
        [index] => *index,
        _ => return Err(PerfFrameError::DuplicateContentMarker),
    };
    if content_index != 1 || lines.first() != Some(&"<FINISHED>") {
        let (index, text) = lines
            .iter()
            .enumerate()
            .find(|(index, _)| *index != content_index)
            .map(|(index, text)| (index + 1, (*text).to_owned()))
            .unwrap_or((1, String::new()));
        return Err(PerfFrameError::ProtocolContamination { line: index, text });
    }
    let content = &lines[content_index + 1..];
    validate_markers(content)?;
    let payload = content[1];
    if payload.len() > limits.max_payload_bytes {
        return Err(PerfFrameError::PayloadTooLarge {
            limit: limits.max_payload_bytes,
            actual: payload.len(),
        });
    }
    parse_payload(payload)
}

fn is_valid_not_finished_wrapper(lines: &[&str]) -> bool {
    lines.first() == Some(&"<NOT FINISHED>")
        && lines.get(1) == Some(&"<CONTENT>")
        && lines.iter().filter(|line| **line == "<CONTENT>").count() == 1
        && lines
            .iter()
            .skip(1)
            .all(|line| !matches!(*line, "<NOT FINISHED>" | "<FINISHED>"))
}

fn validate_markers(content: &[&str]) -> Result<(), PerfFrameError> {
    let begin_count = content
        .iter()
        .filter(|line| **line == T32PERF_RESULT_BEGIN)
        .count();
    let end_count = content
        .iter()
        .filter(|line| **line == T32PERF_RESULT_END)
        .count();
    match begin_count {
        0 => return Err(PerfFrameError::MissingBeginMarker),
        1 => {}
        _ => return Err(PerfFrameError::DuplicateBeginMarker),
    }
    match end_count {
        0 => return Err(PerfFrameError::MissingEndMarker),
        1 => {}
        _ => return Err(PerfFrameError::DuplicateEndMarker),
    }
    let begin = content
        .iter()
        .position(|line| *line == T32PERF_RESULT_BEGIN)
        .expect("count checked");
    let end = content
        .iter()
        .position(|line| *line == T32PERF_RESULT_END)
        .expect("count checked");
    if begin != 0 {
        return Err(PerfFrameError::ProtocolContamination {
            line: 3,
            text: content[0].to_owned(),
        });
    }
    if end <= begin {
        return Err(PerfFrameError::PayloadLineCount { actual: 0 });
    }
    let payload_lines = end - begin - 1;
    if payload_lines != 1 {
        return Err(PerfFrameError::PayloadLineCount {
            actual: payload_lines,
        });
    }
    if end + 1 != content.len() {
        let line = end + 4;
        return Err(PerfFrameError::ProtocolContamination {
            line,
            text: content[end + 1].to_owned(),
        });
    }
    Ok(())
}

fn parse_payload(payload: &str) -> Result<PerfScriptResponse, PerfFrameError> {
    let raw = strict_json::from_str::<RawPerfPayload>(payload).map_err(map_payload_error)?;
    if raw.protocol != T32PERF_PROTOCOL {
        return Err(PerfFrameError::InvalidProtocol {
            actual: raw.protocol,
        });
    }
    let operation =
        PerfOperation::parse(&raw.operation).ok_or_else(|| PerfFrameError::UnknownOperation {
            operation: raw.operation.clone(),
        })?;
    let status = PerfStatus::parse(&raw.status).ok_or_else(|| PerfFrameError::UnknownStatus {
        status: raw.status.clone(),
    })?;
    let code = raw.code;
    if !is_snake_case_code(&code) {
        return Err(PerfFrameError::InvalidCode { code });
    }
    let expected_status =
        status_for_code(operation, &code).ok_or_else(|| PerfFrameError::UnknownCode {
            operation: operation.as_str(),
            code: code.clone(),
        })?;
    if status != expected_status {
        return Err(PerfFrameError::CodeStatusMismatch {
            code,
            expected: expected_status.as_str(),
            actual: status.as_str(),
        });
    }
    let expected_initial_target_state = raw.expected_initial_target_state;
    let observed_target_state = raw.observed_target_state;
    if code == "initial_target_state_drift" {
        let expected = expected_initial_target_state.as_deref().ok_or_else(|| {
            PerfFrameError::InvalidJson {
                message: "initial target-state drift response omitted the expected state"
                    .to_owned(),
            }
        })?;
        let observed =
            observed_target_state
                .as_deref()
                .ok_or_else(|| PerfFrameError::InvalidJson {
                    message: "initial target-state drift response omitted the observed state"
                        .to_owned(),
                })?;
        if !matches!(expected, "running" | "halted")
            || !matches!(observed, "running" | "halted" | "unavailable")
            || expected == observed
        {
            return Err(PerfFrameError::InvalidJson {
                message: "initial target-state drift response contains inconsistent states"
                    .to_owned(),
            });
        }
    } else if expected_initial_target_state.is_some() {
        return Err(PerfFrameError::UnknownField {
            field: "expected_initial_target_state".to_owned(),
        });
    } else if observed_target_state.is_some() {
        return Err(PerfFrameError::UnknownField {
            field: "observed_target_state".to_owned(),
        });
    }
    let files_deleted = raw.files_deleted;
    if files_deleted == Some(true) {
        return Err(PerfFrameError::CleanupDeletedFiles);
    }
    if files_deleted.is_some() && operation != PerfOperation::Cleanup {
        return Err(PerfFrameError::UnknownField {
            field: "files_deleted".to_owned(),
        });
    }
    if operation == PerfOperation::Cleanup
        && code != "invalid_arguments"
        && files_deleted != Some(false)
    {
        return Err(PerfFrameError::InvalidJson {
            message: "target cleanup response must declare files_deleted=false".to_owned(),
        });
    }
    let binding_sha256 = raw.binding_sha256;
    if binding_sha256.len() != 64
        || !binding_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PerfFrameError::InvalidBinding {
            binding: binding_sha256,
        });
    }
    Ok(PerfScriptResponse {
        protocol: T32PERF_PROTOCOL,
        operation,
        status,
        code,
        binding_sha256,
        files_deleted,
    })
}

fn map_payload_error(error: serde_json::Error) -> PerfFrameError {
    let message = error.to_string();
    if let Some(rest) = message.strip_prefix("unknown field `")
        && let Some((field, _)) = rest.split_once('`')
    {
        return PerfFrameError::UnknownField {
            field: field.to_owned(),
        };
    }
    PerfFrameError::InvalidJson { message }
}

fn is_snake_case_code(code: &str) -> bool {
    !code.is_empty()
        && !code.starts_with('_')
        && !code.ends_with('_')
        && !code.contains("__")
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn status_for_code(operation: PerfOperation, code: &str) -> Option<PerfStatus> {
    use PerfOperation as Operation;
    use PerfStatus as Status;

    if code == "invalid_arguments" {
        return Some(Status::InvalidArgument);
    }
    match (operation, code) {
        (Operation::Configure | Operation::Start, "initial_target_state_drift") => {
            Some(Status::InvalidArgument)
        }
        (Operation::GetCapabilities, "hardware_adapter_required")
        | (Operation::Configure, "target_configuration_required")
        | (Operation::Start, "target_start_required")
        | (Operation::Stop, "target_stop_required")
        | (Operation::GetHealth, "verified_health_adapter_required")
        | (Operation::Cleanup, "target_cleanup_required")
        | (Operation::Export, "raw_ascii_export_failed")
        | (Operation::Export, "task_events_export_failed") => Some(Status::UnsupportedNeedsTrace32),
        (Operation::GetHotspots, "raw_trace_analysis_required") => {
            Some(Status::HostProcessingRequired)
        }
        (Operation::GetCapabilities, "capabilities_exported")
        | (Operation::Configure, "configured")
        | (Operation::Start, "started")
        | (Operation::Stop, "stopped")
        | (Operation::GetHealth, "health_exported")
        | (Operation::Cleanup, "cleanup_completed") => Some(Status::Ok),
        (Operation::Export, "raw_ascii_exported") | (Operation::Export, "task_events_exported") => {
            Some(Status::Ok)
        }
        (Operation::Export, "unsupported_export_mode") => Some(Status::InvalidArgument),
        _ => None,
    }
}
