use std::{
    collections::BTreeSet,
    fmt,
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read as _, Seek as _, SeekFrom, Write as _},
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(windows)]
use std::io;

#[cfg(unix)]
use nix::{
    errno::Errno,
    sys::{
        signal::{Signal, killpg},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::Pid,
};
use process_wrap::tokio::{ChildWrapper, CommandWrap, KillOnDrop};
#[cfg(windows)]
use process_wrap::tokio::{CommandWrapper, JobObject};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use t32perf_model::{ArtifactPath, CaptureAttestation, Sha256Digest, strict_json};
use t32perf_session::{ArtifactRoot, SessionId, verify_opened_plain_file_identity};
use t32perf_trace32::{
    ControllerTargetState, DriverCommand, DriverCommandPlaceholder, DriverCommandRole,
};
#[cfg(windows)]
use tokio::process::Command;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _},
    time::{Instant, sleep_until},
};

use crate::attestation::ATTESTATION_SIGNING_REQUEST_PATH;

use super::config::{
    LoadedDriverConfig, performance_run_deployment_sha256, read_bounded_plain_file,
    require_performance_run_config, revalidate_loaded_driver_config,
    revalidate_receipt_bound_driver_config, verify_absolute_plain_directory,
    verify_plain_executable_sha256, verify_plain_file_sha256,
};

const MAX_STDERR_SUMMARY_CHARS: usize = 4 * 1024;
const MAX_ATTESTATION_SIGNING_REQUEST_BYTES: u64 = 1024 * 1024;
const MAX_CAPTURE_ATTESTATION_BYTES: u64 = 1024 * 1024;
const MAX_ATTESTATION_RESERVATION_BYTES: u64 = 4 * 1024;
const ATTESTATION_RESERVATION_SCHEMA: &str = "t32perf.attestation-output-reservation/v1";
const CHILD_TERMINATION_GRACE: Duration = Duration::from_secs(1);
#[cfg(unix)]
const PROCESS_GROUP_POLL_INTERVAL: Duration = Duration::from_millis(10);
static PROCESS_STARTED_UNIX_NS: OnceLock<u64> = OnceLock::new();
static RESERVATION_NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);
static ACTIVE_ATTESTATION_RESERVATIONS: OnceLock<Mutex<BTreeSet<PathBuf>>> = OnceLock::new();

#[derive(Debug, Clone, Copy)]
pub(crate) struct WorkloadHookContext<'a> {
    pub(crate) session_id: &'a str,
    pub(crate) transaction_id: &'a str,
    pub(crate) binding_sha256: &'a Sha256Digest,
    pub(crate) initial_target_state: ControllerTargetState,
    pub(crate) workload_identity: &'a str,
    pub(crate) duration_ns: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FaultHookContext<'a> {
    pub(crate) artifact_root: &'a Path,
    pub(crate) session_id: &'a str,
    pub(crate) transaction_id: &'a str,
    pub(crate) binding_sha256: &'a Sha256Digest,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct AttestationSignerHookContext<'a> {
    pub(crate) session_id: &'a str,
    pub(crate) signing_request_sha256: &'a Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HookExecution {
    pub(crate) stderr_summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttestationSignerHookOutput {
    pub(crate) execution: HookExecution,
    pub(crate) path: PathBuf,
    pub(crate) size_bytes: u64,
    pub(crate) sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttestationSignerOutputPath {
    pub(crate) staged: ArtifactPath,
    pub(crate) absolute: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DriverHookError {
    Unsupported {
        role: DriverCommandRole,
    },
    InvalidCommand {
        role: DriverCommandRole,
        message: String,
    },
    InvalidContext {
        role: DriverCommandRole,
        message: String,
    },
    ExecutableRejected {
        role: DriverCommandRole,
        message: String,
    },
    DeploymentRejected {
        role: DriverCommandRole,
        message: String,
    },
    SpawnFailed {
        role: DriverCommandRole,
        message: String,
    },
    Timeout {
        role: DriverCommandRole,
        timeout_ms: u64,
    },
    UnexpectedStdout {
        role: DriverCommandRole,
    },
    StderrLimitExceeded {
        role: DriverCommandRole,
        limit_bytes: u64,
    },
    OutputReadFailed {
        role: DriverCommandRole,
        stream: &'static str,
        message: String,
    },
    ExitFailure {
        role: DriverCommandRole,
        code: Option<i32>,
        stderr_summary: Option<String>,
    },
    OutputRejected {
        role: DriverCommandRole,
        message: String,
    },
    TerminationFailed {
        role: DriverCommandRole,
        message: String,
    },
    #[cfg(unix)]
    ProcessGroupStateFailed {
        role: DriverCommandRole,
        message: String,
    },
}

impl DriverHookError {
    #[must_use]
    pub(crate) const fn is_unsupported(&self) -> bool {
        matches!(self, Self::Unsupported { .. })
    }
}

impl fmt::Display for DriverHookError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported { role } => {
                write!(formatter, "deployment hook `{role}` is unsupported")
            }
            Self::InvalidCommand { role, message } => {
                write!(formatter, "deployment hook `{role}` is invalid: {message}")
            }
            Self::InvalidContext { role, message } => {
                write!(
                    formatter,
                    "deployment hook `{role}` context is invalid: {message}"
                )
            }
            Self::ExecutableRejected { role, message } => {
                write!(
                    formatter,
                    "deployment hook `{role}` executable was rejected: {message}"
                )
            }
            Self::DeploymentRejected { role, message } => write!(
                formatter,
                "deployment hook `{role}` deployment was rejected: {message}"
            ),
            Self::SpawnFailed { role, message } => {
                write!(
                    formatter,
                    "deployment hook `{role}` could not be started: {message}"
                )
            }
            Self::Timeout { role, timeout_ms } => write!(
                formatter,
                "deployment hook `{role}` exceeded its {timeout_ms} ms timeout"
            ),
            Self::UnexpectedStdout { role } => write!(
                formatter,
                "deployment hook `{role}` wrote to stdout; hook stdout cannot be hardware evidence"
            ),
            Self::StderrLimitExceeded { role, limit_bytes } => write!(
                formatter,
                "deployment hook `{role}` exceeded its {limit_bytes}-byte stderr bound"
            ),
            Self::OutputReadFailed {
                role,
                stream,
                message,
            } => write!(
                formatter,
                "deployment hook `{role}` {stream} read failed: {message}"
            ),
            Self::ExitFailure {
                role,
                code,
                stderr_summary,
            } => {
                write!(
                    formatter,
                    "deployment hook `{role}` exited unsuccessfully with code {code:?}"
                )?;
                if let Some(summary) = stderr_summary {
                    write!(formatter, ": {summary}")?;
                }
                Ok(())
            }
            Self::OutputRejected { role, message } => write!(
                formatter,
                "deployment hook `{role}` output was rejected: {message}"
            ),
            Self::TerminationFailed { role, message } => write!(
                formatter,
                "deployment hook `{role}` process tree could not be terminated and reaped: {message}"
            ),
            #[cfg(unix)]
            Self::ProcessGroupStateFailed { role, message } => write!(
                formatter,
                "deployment hook `{role}` process group state could not be verified: {message}"
            ),
        }
    }
}

impl std::error::Error for DriverHookError {}

pub(crate) async fn run_workload_hook(
    root: &ArtifactRoot,
    initial: &LoadedDriverConfig,
    context: &WorkloadHookContext<'_>,
    deadline_cap_ms: u64,
) -> Result<HookExecution, DriverHookError> {
    let role = DriverCommandRole::Workload;
    if context.duration_ns == Some(0) {
        return Err(DriverHookError::InvalidContext {
            role,
            message: "duration_ns must be nonzero".to_owned(),
        });
    }
    let loaded = if context.duration_ns.is_some() {
        revalidate_receipt_bound_driver_config(root, initial)
    } else {
        revalidate_loaded_driver_config(root, initial)
    }
    .map_err(|error| DriverHookError::DeploymentRejected {
        role,
        message: error.to_string(),
    })?;
    let command = select_workload_command(&loaded, context.duration_ns)?;
    let duration_ns = context.duration_ns.map(|value| value.to_string());
    let values = HookValues {
        artifact_root: path_text(root.path(), role)?,
        session_id: context.session_id,
        transaction_id: Some(context.transaction_id),
        binding_sha256: Some(context.binding_sha256.as_str()),
        initial_target_state: Some(target_state_text(context.initial_target_state)),
        workload_identity: Some(context.workload_identity),
        duration_ns: duration_ns.as_deref(),
        signing_request_path: None,
        signing_request_sha256: None,
        attestation_output_path: None,
        policy_id: None,
        key_id: None,
    };
    run_hook_command(&loaded, command, role, &values, deadline_cap_ms).await
}

fn select_workload_command(
    loaded: &LoadedDriverConfig,
    duration_ns: Option<u64>,
) -> Result<&DriverCommand, DriverHookError> {
    let role = DriverCommandRole::Workload;
    match duration_ns {
        Some(_) => loaded
            .config
            .performance_run
            .as_ref()
            .map(|deployment| &deployment.workload_command)
            .ok_or(DriverHookError::Unsupported { role }),
        None => loaded
            .config
            .workload
            .as_ref()
            .ok_or(DriverHookError::Unsupported { role }),
    }
}

pub(crate) fn validate_workload_hook(
    loaded: &LoadedDriverConfig,
    duration_ns: Option<u64>,
) -> Result<(), DriverHookError> {
    let role = DriverCommandRole::Workload;
    if duration_ns == Some(0) {
        return Err(DriverHookError::InvalidContext {
            role,
            message: "duration_ns must be nonzero".to_owned(),
        });
    }
    select_workload_command(loaded, duration_ns)?
        .validate(role)
        .map_err(|error| DriverHookError::InvalidCommand {
            role,
            message: error.to_string(),
        })
}

pub(crate) async fn run_fault_hook(
    loaded: &LoadedDriverConfig,
    role: DriverCommandRole,
    context: &FaultHookContext<'_>,
    deadline_cap_ms: u64,
) -> Result<HookExecution, DriverHookError> {
    let command = match role {
        DriverCommandRole::Workload => {
            return Err(DriverHookError::InvalidCommand {
                role,
                message: "workload role must use run_workload_hook".to_owned(),
            });
        }
        DriverCommandRole::Trace32DisconnectAtStop => loaded
            .config
            .fault_actions
            .trace32_disconnect_at_stop
            .as_ref(),
        DriverCommandRole::AttestationSigner => {
            return Err(DriverHookError::InvalidCommand {
                role,
                message: "attestation signer role must use run_attestation_signer_hook".to_owned(),
            });
        }
    }
    .ok_or(DriverHookError::Unsupported { role })?;
    let values = HookValues {
        artifact_root: path_text(context.artifact_root, role)?,
        session_id: context.session_id,
        transaction_id: Some(context.transaction_id),
        binding_sha256: Some(context.binding_sha256.as_str()),
        initial_target_state: None,
        workload_identity: None,
        duration_ns: None,
        signing_request_path: None,
        signing_request_sha256: None,
        attestation_output_path: None,
        policy_id: None,
        key_id: None,
    };
    run_hook_command(loaded, command, role, &values, deadline_cap_ms).await
}

pub(crate) async fn run_attestation_signer_hook(
    root: &ArtifactRoot,
    initial: &LoadedDriverConfig,
    context: &AttestationSignerHookContext<'_>,
    deadline_cap_ms: u64,
) -> Result<AttestationSignerHookOutput, DriverHookError> {
    let role = DriverCommandRole::AttestationSigner;
    let loaded = revalidate_receipt_bound_driver_config(root, initial).map_err(|error| {
        DriverHookError::DeploymentRejected {
            role,
            message: error.to_string(),
        }
    })?;
    let performance_run = require_performance_run_config(&loaded)
        .map_err(|_| DriverHookError::Unsupported { role })?;
    let deployment_sha256 = performance_run_deployment_sha256(&loaded).map_err(|error| {
        DriverHookError::DeploymentRejected {
            role,
            message: error.to_string(),
        }
    })?;
    let paths = reserve_attestation_signer_paths(
        root,
        context,
        &deployment_sha256,
        &performance_run
            .attestation
            .signer_command
            .expected_executable_sha256,
    )?;
    verify_plain_file_sha256(
        &paths.signing_request,
        context.signing_request_sha256,
        MAX_ATTESTATION_SIGNING_REQUEST_BYTES,
        "attestation signing request",
    )
    .map_err(|error| DriverHookError::InvalidContext {
        role,
        message: error.to_string(),
    })?;
    let signing_request_path =
        path_text_for_role(&paths.signing_request, role, "signing_request_path")?;
    let attestation_output_path =
        path_text_for_role(&paths.output.path, role, "attestation_output_path")?;
    let values = HookValues {
        artifact_root: path_text(root.path(), role)?,
        session_id: context.session_id,
        transaction_id: None,
        binding_sha256: None,
        initial_target_state: None,
        workload_identity: None,
        duration_ns: None,
        signing_request_path: Some(signing_request_path),
        signing_request_sha256: Some(context.signing_request_sha256.as_str()),
        attestation_output_path: Some(attestation_output_path),
        policy_id: Some(&performance_run.attestation.policy_id),
        key_id: Some(&performance_run.attestation.key_id),
    };
    let execution = run_hook_command(
        &loaded,
        &performance_run.attestation.signer_command,
        role,
        &values,
        deadline_cap_ms,
    )
    .await?;
    let bytes = read_bounded_plain_file(
        &paths.output.path,
        MAX_CAPTURE_ATTESTATION_BYTES,
        "capture attestation signer output",
    )
    .map_err(|error| DriverHookError::OutputRejected {
        role,
        message: error.to_string(),
    })?;
    if bytes.is_empty() {
        return Err(DriverHookError::OutputRejected {
            role,
            message: "capture attestation signer output is empty".to_owned(),
        });
    }
    let attestation: CaptureAttestation =
        strict_json::from_slice(&bytes).map_err(|error| DriverHookError::OutputRejected {
            role,
            message: format!("capture attestation is not strict JSON: {error}"),
        })?;
    attestation
        .validate()
        .map_err(|error| DriverHookError::OutputRejected {
            role,
            message: format!("capture attestation is invalid: {error}"),
        })?;
    if attestation.payload.key_id != performance_run.attestation.key_id {
        return Err(DriverHookError::OutputRejected {
            role,
            message: format!(
                "capture attestation key_id `{}` does not match deployment key_id `{}`",
                attestation.payload.key_id, performance_run.attestation.key_id
            ),
        });
    }
    Ok(AttestationSignerHookOutput {
        execution,
        path: paths.output.path.clone(),
        size_bytes: u64::try_from(bytes.len()).expect("bounded attestation length fits u64"),
        sha256: digest(&bytes),
    })
}

async fn run_hook_command(
    loaded: &LoadedDriverConfig,
    command: &DriverCommand,
    role: DriverCommandRole,
    values: &HookValues<'_>,
    deadline_cap_ms: u64,
) -> Result<HookExecution, DriverHookError> {
    command
        .validate(role)
        .map_err(|error| DriverHookError::InvalidCommand {
            role,
            message: error.to_string(),
        })?;
    validate_context(role, values)?;
    let executable = Path::new(&command.executable);
    verify_plain_executable_sha256(
        executable,
        &command.expected_executable_sha256,
        &format!("`{role}` executable"),
    )
    .map_err(|error| DriverHookError::ExecutableRejected {
        role,
        message: error.to_string(),
    })?;
    let arguments = command
        .arguments
        .iter()
        .map(|argument| expand_argument(argument, role, values))
        .collect::<Result<Vec<_>, _>>()?;
    execute_process(
        executable,
        &arguments,
        role,
        command.timeout_ms.min(deadline_cap_ms),
        loaded.config.max_stderr_bytes,
    )
    .await
}

fn validate_context(
    role: DriverCommandRole,
    values: &HookValues<'_>,
) -> Result<(), DriverHookError> {
    for (field, value) in [
        ("artifact_root", values.artifact_root),
        ("session_id", values.session_id),
    ] {
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err(DriverHookError::InvalidContext {
                role,
                message: format!("{field} is empty or contains a control character"),
            });
        }
    }
    match role {
        DriverCommandRole::Workload => {
            require_context_value(role, "transaction_id", values.transaction_id)?;
            require_context_value(role, "binding_sha256", values.binding_sha256)?;
            require_context_value(role, "initial_target_state", values.initial_target_state)?;
            require_context_value(role, "workload_identity", values.workload_identity)?;
        }
        DriverCommandRole::Trace32DisconnectAtStop => {
            require_context_value(role, "transaction_id", values.transaction_id)?;
            require_context_value(role, "binding_sha256", values.binding_sha256)?;
        }
        DriverCommandRole::AttestationSigner => {
            require_context_value(role, "signing_request_path", values.signing_request_path)?;
            require_context_value(
                role,
                "signing_request_sha256",
                values.signing_request_sha256,
            )?;
            require_context_value(
                role,
                "attestation_output_path",
                values.attestation_output_path,
            )?;
            require_context_value(role, "policy_id", values.policy_id)?;
            require_context_value(role, "key_id", values.key_id)?;
        }
    }
    Ok(())
}

fn require_context_value(
    role: DriverCommandRole,
    field: &str,
    value: Option<&str>,
) -> Result<(), DriverHookError> {
    let Some(value) = value else {
        return Err(DriverHookError::InvalidContext {
            role,
            message: format!("{field} is missing"),
        });
    };
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(DriverHookError::InvalidContext {
            role,
            message: format!("{field} is empty or contains a control character"),
        });
    }
    Ok(())
}

struct HookValues<'a> {
    artifact_root: &'a str,
    session_id: &'a str,
    transaction_id: Option<&'a str>,
    binding_sha256: Option<&'a str>,
    initial_target_state: Option<&'a str>,
    workload_identity: Option<&'a str>,
    duration_ns: Option<&'a str>,
    signing_request_path: Option<&'a str>,
    signing_request_sha256: Option<&'a str>,
    attestation_output_path: Option<&'a str>,
    policy_id: Option<&'a str>,
    key_id: Option<&'a str>,
}

impl HookValues<'_> {
    fn get(&self, placeholder: DriverCommandPlaceholder) -> Option<&str> {
        match placeholder {
            DriverCommandPlaceholder::ArtifactRoot => Some(self.artifact_root),
            DriverCommandPlaceholder::SessionId => Some(self.session_id),
            DriverCommandPlaceholder::TransactionId => self.transaction_id,
            DriverCommandPlaceholder::BindingSha256 => self.binding_sha256,
            DriverCommandPlaceholder::InitialTargetState => self.initial_target_state,
            DriverCommandPlaceholder::WorkloadIdentity => self.workload_identity,
            DriverCommandPlaceholder::DurationNs => self.duration_ns,
            DriverCommandPlaceholder::SigningRequestPath => self.signing_request_path,
            DriverCommandPlaceholder::SigningRequestSha256 => self.signing_request_sha256,
            DriverCommandPlaceholder::AttestationOutputPath => self.attestation_output_path,
            DriverCommandPlaceholder::PolicyId => self.policy_id,
            DriverCommandPlaceholder::KeyId => self.key_id,
        }
    }
}

fn expand_argument(
    template: &str,
    role: DriverCommandRole,
    values: &HookValues<'_>,
) -> Result<String, DriverHookError> {
    let mut expanded = String::with_capacity(template.len());
    let mut offset = 0;
    while let Some(relative_start) = template[offset..].find('{') {
        let start = offset + relative_start;
        if template[offset..start].contains('}') {
            return Err(DriverHookError::InvalidCommand {
                role,
                message: "argument contains an unmatched closing brace".to_owned(),
            });
        }
        expanded.push_str(&template[offset..start]);
        let name_start = start + 1;
        let Some(relative_end) = template[name_start..].find('}') else {
            return Err(DriverHookError::InvalidCommand {
                role,
                message: "argument contains an unmatched opening brace".to_owned(),
            });
        };
        let end = name_start + relative_end;
        let name = &template[name_start..end];
        let placeholder = DriverCommandPlaceholder::parse(name).ok_or_else(|| {
            DriverHookError::InvalidCommand {
                role,
                message: format!("argument contains unknown placeholder `{{{name}}}`"),
            }
        })?;
        let value = values
            .get(placeholder)
            .ok_or_else(|| DriverHookError::InvalidContext {
                role,
                message: format!("placeholder `{{{name}}}` has no typed value"),
            })?;
        expanded.push_str(value);
        offset = end + 1;
    }
    if template[offset..].contains('}') {
        return Err(DriverHookError::InvalidCommand {
            role,
            message: "argument contains an unmatched closing brace".to_owned(),
        });
    }
    expanded.push_str(&template[offset..]);
    Ok(expanded)
}

async fn execute_process(
    executable: &Path,
    arguments: &[String],
    role: DriverCommandRole,
    timeout_ms: u64,
    max_stderr_bytes: u64,
) -> Result<HookExecution, DriverHookError> {
    let mut command = CommandWrap::with_new(executable, |command| {
        command
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        command.process_group(0);
    });
    command.wrap(KillOnDrop);
    #[cfg(windows)]
    {
        command.wrap(JobObject);
        command.wrap(NoWindowProcess);
    }
    let mut child = command
        .spawn()
        .map_err(|error| DriverHookError::SpawnFailed {
            role,
            message: error.to_string(),
        })?;
    #[cfg(unix)]
    // A zero process_group creates a dedicated group whose PGID is the spawned
    // leader PID. Retain it because the direct-child wait cannot observe a
    // descendant after that leader exits and the descendant is reparented.
    let process_group = Pid::from_raw(
        i32::try_from(
            child
                .id()
                .expect("spawned hook process has a process identifier"),
        )
        .expect("hook process identifier fits i32"),
    );
    #[cfg(unix)]
    let mut process_group_guard = ProcessGroupGuard::new(process_group);
    let stdout = child
        .stdout()
        .take()
        .expect("piped hook stdout is available");
    let stderr = child
        .stderr()
        .take()
        .expect("piped hook stderr is available");
    let mut stdout_task = tokio::spawn(require_empty_stdout(stdout));
    let mut stderr_task = tokio::spawn(read_bounded_stderr(stderr, max_stderr_bytes));
    #[cfg(unix)]
    let mut deadline = Instant::now() + Duration::from_millis(timeout_ms);
    #[cfg(not(unix))]
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut status = None;
    let mut stdout_complete = false;
    let mut stderr_bytes = None;
    #[cfg(windows)]
    let mut process_complete = false;
    let attempt = {
        let mut wait = child.wait();
        let result = 'process: loop {
            tokio::select! {
                biased;
                output = &mut stdout_task, if !stdout_complete => {
                    match output {
                        Ok(Ok(())) => stdout_complete = true,
                        Ok(Err(StreamReadError::UnexpectedStdout)) => {
                            break 'process Err(DriverHookError::UnexpectedStdout { role });
                        }
                        Ok(Err(StreamReadError::LimitExceeded)) => unreachable!("stdout has no byte limit"),
                        Ok(Err(StreamReadError::Io(message))) => {
                            break 'process Err(DriverHookError::OutputReadFailed {
                                role,
                                stream: "stdout",
                                message,
                            });
                        }
                        Err(error) => {
                            break 'process Err(DriverHookError::OutputReadFailed {
                                role,
                                stream: "stdout",
                                message: error.to_string(),
                            });
                        }
                    }
                }
                output = &mut stderr_task, if stderr_bytes.is_none() => {
                    match output {
                        Ok(Ok(bytes)) => stderr_bytes = Some(bytes),
                        Ok(Err(StreamReadError::LimitExceeded)) => {
                            break 'process Err(DriverHookError::StderrLimitExceeded {
                                role,
                                limit_bytes: max_stderr_bytes,
                            });
                        }
                        Ok(Err(StreamReadError::Io(message))) => {
                            break 'process Err(DriverHookError::OutputReadFailed {
                                role,
                                stream: "stderr",
                                message,
                            });
                        }
                        Ok(Err(StreamReadError::UnexpectedStdout)) => unreachable!("stderr accepts bounded output"),
                        Err(error) => {
                            break 'process Err(DriverHookError::OutputReadFailed {
                                role,
                                stream: "stderr",
                                message: error.to_string(),
                            });
                        }
                    }
                }
                process = &mut wait, if status.is_none() => {
                    match process {
                        Ok(exit_status) => {
                            #[cfg(unix)]
                            if !exit_status.success() {
                                deadline = deadline.min(Instant::now() + CHILD_TERMINATION_GRACE);
                                if let Err(error) = signal_unix_process_group(process_group) {
                                    break 'process Err(DriverHookError::TerminationFailed {
                                        role,
                                        message: format!(
                                            "after exit code {:?}: send SIGKILL to process group: {error}",
                                            exit_status.code()
                                        ),
                                    });
                                }
                            }
                            status = Some(exit_status);
                            #[cfg(windows)]
                            {
                                process_complete = true;
                            }
                        }
                        Err(error) => {
                            break 'process Err(DriverHookError::OutputReadFailed {
                                role,
                                stream: "process status",
                                message: error.to_string(),
                            });
                        }
                    }
                }
                _ = sleep_until(deadline) => {
                    if let Some(status) = status
                        && !status.success()
                    {
                        break 'process Err(exit_failure(
                            role,
                            status,
                            stderr_bytes.as_deref().unwrap_or_default(),
                        ));
                    }
                    break 'process Err(DriverHookError::Timeout { role, timeout_ms });
                }
            }
            if stdout_complete
                && let Some(status) = status
                && let Some(stderr) = stderr_bytes.take()
            {
                break 'process Ok((status, stderr));
            }
        };
        let result = match result {
            Ok((status, stderr)) => finish_process(role, status, stderr),
            Err(error) => Err(error),
        };
        #[cfg(unix)]
        match result {
            Ok(success) => {
                match wait_for_process_group_empty(process_group, deadline, role, timeout_ms).await
                {
                    Ok(()) => Ok(success),
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        }
        #[cfg(windows)]
        result
    };

    match attempt {
        Ok(execution) => {
            #[cfg(unix)]
            process_group_guard.disarm();
            Ok(execution)
        }
        Err(error) => {
            stdout_task.abort();
            stderr_task.abort();
            #[cfg(unix)]
            terminate_unix_process_group(&mut child, process_group)
                .await
                .map_err(|message| DriverHookError::TerminationFailed {
                    role,
                    message: format!("after `{error}`: {message}"),
                })?;
            #[cfg(windows)]
            if !process_complete {
                terminate_child_without_task(&mut child)
                    .await
                    .map_err(|message| DriverHookError::TerminationFailed {
                        role,
                        message: format!("after `{error}`: {message}"),
                    })?;
            }
            #[cfg(unix)]
            process_group_guard.disarm();
            Err(error)
        }
    }
}

fn finish_process(
    role: DriverCommandRole,
    status: ExitStatus,
    stderr: Vec<u8>,
) -> Result<HookExecution, DriverHookError> {
    if !status.success() {
        return Err(exit_failure(role, status, &stderr));
    }
    Ok(HookExecution {
        stderr_summary: stderr_summary(&stderr),
    })
}

fn exit_failure(role: DriverCommandRole, status: ExitStatus, stderr: &[u8]) -> DriverHookError {
    DriverHookError::ExitFailure {
        role,
        code: status.code(),
        stderr_summary: stderr_summary(stderr),
    }
}

async fn require_empty_stdout<R>(mut reader: R) -> Result<(), StreamReadError>
where
    R: AsyncRead + Unpin,
{
    let mut byte = [0_u8; 1];
    match reader.read(&mut byte).await {
        Ok(0) => Ok(()),
        Ok(_) => Err(StreamReadError::UnexpectedStdout),
        Err(error) => Err(StreamReadError::Io(error.to_string())),
    }
}

async fn read_bounded_stderr<R>(mut reader: R, maximum: u64) -> Result<Vec<u8>, StreamReadError>
where
    R: AsyncRead + Unpin,
{
    let capacity = usize::try_from(maximum.min(16 * 1024)).expect("bounded capacity fits usize");
    let mut bytes = Vec::with_capacity(capacity);
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .await
            .map_err(|error| StreamReadError::Io(error.to_string()))?;
        if count == 0 {
            return Ok(bytes);
        }
        let new_length = bytes
            .len()
            .checked_add(count)
            .ok_or(StreamReadError::LimitExceeded)?;
        if u64::try_from(new_length).expect("buffer length fits u64") > maximum {
            return Err(StreamReadError::LimitExceeded);
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
}

#[derive(Debug)]
enum StreamReadError {
    UnexpectedStdout,
    LimitExceeded,
    Io(String),
}

#[cfg(windows)]
async fn terminate_child_without_task(child: &mut Box<dyn ChildWrapper>) -> Result<(), String> {
    let kill = Box::into_pin(child.kill());
    match tokio::time::timeout(CHILD_TERMINATION_GRACE, kill).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err(format!(
            "kill-and-wait exceeded the {} ms cleanup deadline",
            CHILD_TERMINATION_GRACE.as_millis()
        )),
    }
}

#[cfg(unix)]
async fn wait_for_process_group_empty(
    process_group: Pid,
    deadline: Instant,
    role: DriverCommandRole,
    timeout_ms: u64,
) -> Result<(), DriverHookError> {
    loop {
        if Instant::now() >= deadline {
            return Err(DriverHookError::Timeout { role, timeout_ms });
        }
        match process_group_is_empty(process_group) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => {
                return Err(DriverHookError::ProcessGroupStateFailed {
                    role,
                    message: error.to_string(),
                });
            }
        }
        let now = Instant::now();
        sleep_until((now + PROCESS_GROUP_POLL_INTERVAL).min(deadline)).await;
    }
}

#[cfg(unix)]
async fn terminate_unix_process_group(
    child: &mut Box<dyn ChildWrapper>,
    process_group: Pid,
) -> Result<(), String> {
    let deadline = Instant::now() + CHILD_TERMINATION_GRACE;
    signal_unix_process_group(process_group)
        .map_err(|error| format!("send SIGKILL to process group: {error}"))?;
    let wait = child.wait();
    match tokio::time::timeout_at(deadline, wait).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => return Err(format!("wait for direct child: {error}")),
        Err(_) => {
            return Err(format!(
                "wait for direct child exceeded the {} ms cleanup deadline",
                CHILD_TERMINATION_GRACE.as_millis()
            ));
        }
    }
    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "process group remained alive after the {} ms cleanup deadline",
                CHILD_TERMINATION_GRACE.as_millis()
            ));
        }
        match process_group_is_empty(process_group) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => return Err(format!("inspect process group after SIGKILL: {error}")),
        }
        let now = Instant::now();
        sleep_until((now + PROCESS_GROUP_POLL_INTERVAL).min(deadline)).await;
    }
}

#[cfg(unix)]
fn signal_unix_process_group(process_group: Pid) -> Result<(), Errno> {
    match killpg(process_group, Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
#[derive(Debug)]
struct ProcessGroupGuard {
    process_group: Pid,
    armed: bool,
}

#[cfg(unix)]
impl ProcessGroupGuard {
    const fn new(process_group: Pid) -> Self {
        Self {
            process_group,
            armed: true,
        }
    }

    const fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(unix)]
impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = signal_unix_process_group(self.process_group);
        }
    }
}

#[cfg(unix)]
fn process_group_is_empty(process_group: Pid) -> Result<bool, Errno> {
    reap_exited_process_group_members(process_group)?;
    match killpg(process_group, None::<Signal>) {
        Ok(()) | Err(Errno::EPERM) => Ok(false),
        Err(Errno::ESRCH) => Ok(true),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn reap_exited_process_group_members(process_group: Pid) -> Result<(), Errno> {
    let members = Pid::from_raw(-process_group.as_raw());
    loop {
        match waitpid(members, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) | Err(Errno::ECHILD) => return Ok(()),
            Ok(_) => {}
            Err(error) => return Err(error),
        }
    }
}

#[cfg(windows)]
#[derive(Debug)]
struct NoWindowProcess;

#[cfg(windows)]
impl CommandWrapper for NoWindowProcess {
    fn pre_spawn(&mut self, command: &mut Command, _core: &CommandWrap) -> io::Result<()> {
        use std::os::windows::process::CommandExt as _;

        const CREATE_SUSPENDED: u32 = 0x0000_0004;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command
            .as_std_mut()
            .creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);
        Ok(())
    }
}

fn stderr_summary(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let mut summary = String::new();
    let mut character_count = 0_usize;
    for character in String::from_utf8_lossy(bytes).trim().chars() {
        for escaped in character.escape_default() {
            if character_count == MAX_STDERR_SUMMARY_CHARS {
                summary.push_str("...[truncated]");
                return Some(summary);
            }
            summary.push(escaped);
            character_count += 1;
        }
    }
    (!summary.is_empty()).then_some(summary)
}

fn path_text(path: &Path, role: DriverCommandRole) -> Result<&str, DriverHookError> {
    if !path.is_absolute() {
        return Err(DriverHookError::InvalidContext {
            role,
            message: format!("artifact_root `{}` must be absolute", path.display()),
        });
    }
    path.to_str()
        .ok_or_else(|| DriverHookError::InvalidContext {
            role,
            message: "artifact_root is not valid Unicode for argv expansion".to_owned(),
        })
}

fn path_text_for_role<'a>(
    path: &'a Path,
    role: DriverCommandRole,
    field: &str,
) -> Result<&'a str, DriverHookError> {
    path.to_str()
        .ok_or_else(|| DriverHookError::InvalidContext {
            role,
            message: format!("{field} is not valid Unicode for argv expansion"),
        })
}

struct AttestationSignerPaths {
    signing_request: PathBuf,
    output: ReservedAttestationOutput,
}

struct ReservedAttestationOutput {
    path: PathBuf,
    reservation_path: PathBuf,
    reservation: File,
    _active: ActiveAttestationReservation,
}

struct ActiveAttestationReservation {
    path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestationOutputReservationRecord {
    schema: String,
    session_id: String,
    signing_request_sha256: Sha256Digest,
    performance_run_deployment_sha256: Sha256Digest,
    signer_executable_sha256: Sha256Digest,
    owner_pid: u32,
    owner_started_unix_ns: u64,
    owner_nonce: Sha256Digest,
}

pub(crate) fn attestation_signer_output_path(
    root: &ArtifactRoot,
    session_id: &str,
    signing_request_sha256: &Sha256Digest,
) -> Result<AttestationSignerOutputPath, DriverHookError> {
    let role = DriverCommandRole::AttestationSigner;
    let session_id =
        SessionId::new(session_id).map_err(|error| DriverHookError::InvalidContext {
            role,
            message: format!("session_id is invalid: {error}"),
        })?;
    let staged = ArtifactPath::new(format!(
        "capture-attestation-{}.json",
        signing_request_sha256.as_str()
    ))
    .map_err(|error| DriverHookError::InvalidContext {
        role,
        message: format!("construct fixed attestation signer output path: {error}"),
    })?;
    let absolute = root
        .path()
        .join(session_id.as_str())
        .join("capture")
        .join("staging")
        .join(staged.as_str());
    Ok(AttestationSignerOutputPath { staged, absolute })
}

fn claim_attestation_output_reservation(
    path: &Path,
    session_id: &str,
    signing_request_sha256: &Sha256Digest,
    performance_run_deployment_sha256: &Sha256Digest,
    signer_executable_sha256: &Sha256Digest,
    role: DriverCommandRole,
) -> Result<File, DriverHookError> {
    let record = new_attestation_output_reservation_record(
        session_id,
        signing_request_sha256,
        performance_run_deployment_sha256,
        signer_executable_sha256,
    );
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("fixed reservation path has a Unicode filename");
    let temporary_path = path.with_file_name(format!(
        "{filename}.{}.unpublished",
        record.owner_nonce.as_str()
    ));
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&temporary_path)
        .map_err(|error| DriverHookError::InvalidContext {
            role,
            message: format!(
                "create unpublished attestation output reservation `{}`: {error}",
                temporary_path.display()
            ),
        })?;
    if let Err(error) = fs2::FileExt::try_lock_exclusive(&file) {
        if verify_opened_plain_file_identity(&temporary_path, &file).is_ok() {
            let _ = fs::remove_file(&temporary_path);
        }
        return Err(DriverHookError::InvalidContext {
            role,
            message: format!("lock unpublished attestation output reservation: {error}"),
        });
    }
    if let Err(error) =
        write_attestation_output_reservation(&temporary_path, &mut file, &record, role)
    {
        if verify_opened_plain_file_identity(&temporary_path, &file).is_ok() {
            let _ = fs::remove_file(&temporary_path);
        }
        let _ = fs2::FileExt::unlock(&file);
        return Err(error);
    }
    match fs::hard_link(&temporary_path, path) {
        Ok(()) => {
            verify_opened_plain_file_identity(path, &file).map_err(|error| {
                DriverHookError::InvalidContext {
                    role,
                    message: format!("verify published attestation output reservation: {error}"),
                }
            })?;
            fs::remove_file(&temporary_path).map_err(|error| DriverHookError::InvalidContext {
                role,
                message: format!("remove unpublished reservation link: {error}"),
            })?;
            Ok(file)
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temporary_path);
            let _ = fs2::FileExt::unlock(&file);
            drop(file);
            recover_stale_attestation_output_reservation(
                path,
                session_id,
                signing_request_sha256,
                performance_run_deployment_sha256,
                signer_executable_sha256,
                role,
            )
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary_path);
            let _ = fs2::FileExt::unlock(&file);
            Err(DriverHookError::InvalidContext {
                role,
                message: format!(
                    "atomically publish attestation output reservation `{}`: {error}",
                    path.display()
                ),
            })
        }
    }
}

fn recover_stale_attestation_output_reservation(
    path: &Path,
    session_id: &str,
    signing_request_sha256: &Sha256Digest,
    performance_run_deployment_sha256: &Sha256Digest,
    signer_executable_sha256: &Sha256Digest,
    role: DriverCommandRole,
) -> Result<File, DriverHookError> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| DriverHookError::InvalidContext {
            role,
            message: format!(
                "open existing attestation output reservation `{}`: {error}",
                path.display()
            ),
        })?;
    verify_opened_plain_file_identity(path, &file).map_err(|error| {
        DriverHookError::InvalidContext {
            role,
            message: format!("verify existing attestation output reservation: {error}"),
        }
    })?;
    let metadata = file
        .metadata()
        .map_err(|error| DriverHookError::InvalidContext {
            role,
            message: format!("inspect existing attestation output reservation: {error}"),
        })?;
    if metadata.len() == 0 || metadata.len() > MAX_ATTESTATION_RESERVATION_BYTES {
        return Err(DriverHookError::InvalidContext {
            role,
            message: "existing attestation output reservation is empty or oversized".to_owned(),
        });
    }
    match fs2::FileExt::try_lock_exclusive(&file) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::WouldBlock => {
            return Err(DriverHookError::InvalidContext {
                role,
                message: "attestation output is already reserved by a live signer invocation"
                    .to_owned(),
            });
        }
        Err(error) => {
            return Err(DriverHookError::InvalidContext {
                role,
                message: format!("test existing attestation output ownership: {error}"),
            });
        }
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).expect("bounded reservation length fits usize"),
    );
    file.seek(SeekFrom::Start(0))
        .and_then(|_| {
            (&mut file)
                .take(MAX_ATTESTATION_RESERVATION_BYTES.saturating_add(1))
                .read_to_end(&mut bytes)
        })
        .map_err(|error| DriverHookError::InvalidContext {
            role,
            message: format!("read existing attestation output reservation: {error}"),
        })?;
    verify_opened_plain_file_identity(path, &file).map_err(|error| {
        DriverHookError::InvalidContext {
            role,
            message: format!("reverify existing attestation output reservation: {error}"),
        }
    })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_ATTESTATION_RESERVATION_BYTES {
        return Err(DriverHookError::InvalidContext {
            role,
            message: "existing attestation output reservation exceeds its byte bound".to_owned(),
        });
    }
    let existing: AttestationOutputReservationRecord =
        strict_json::from_slice(&bytes).map_err(|error| DriverHookError::InvalidContext {
            role,
            message: format!("parse strict attestation output reservation: {error}"),
        })?;
    if serde_json::to_vec(&existing).expect("reservation serialization is infallible") != bytes {
        return Err(DriverHookError::InvalidContext {
            role,
            message: "existing attestation output reservation is not canonical JSON".to_owned(),
        });
    }
    if existing.schema != ATTESTATION_RESERVATION_SCHEMA
        || existing.session_id != session_id
        || existing.signing_request_sha256 != *signing_request_sha256
        || existing.performance_run_deployment_sha256 != *performance_run_deployment_sha256
        || existing.signer_executable_sha256 != *signer_executable_sha256
        || existing.owner_pid == 0
        || existing.owner_started_unix_ns == 0
    {
        return Err(DriverHookError::InvalidContext {
            role,
            message: "stale attestation output reservation is not exactly bound to this Session and signing request"
                .to_owned(),
        });
    }
    // The exclusive OS lock is the current ownership claim.  Keep the already
    // published, fully validated record byte-for-byte instead of truncating it
    // in place: a crash between truncate and rewrite would otherwise leave a
    // permanently ambiguous empty or partial reservation.
    Ok(file)
}

fn write_attestation_output_reservation(
    path: &Path,
    file: &mut File,
    record: &AttestationOutputReservationRecord,
    role: DriverCommandRole,
) -> Result<(), DriverHookError> {
    let bytes = serde_json::to_vec(record).expect("reservation serialization is infallible");
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_ATTESTATION_RESERVATION_BYTES {
        return Err(DriverHookError::InvalidContext {
            role,
            message: "attestation output reservation exceeds its byte bound".to_owned(),
        });
    }
    file.set_len(0)
        .and_then(|_| file.seek(SeekFrom::Start(0)).map(|_| ()))
        .and_then(|_| file.write_all(&bytes))
        .and_then(|_| file.sync_data())
        .map_err(|error| DriverHookError::InvalidContext {
            role,
            message: format!("persist attestation output reservation: {error}"),
        })?;
    verify_opened_plain_file_identity(path, file).map_err(|error| DriverHookError::InvalidContext {
        role,
        message: format!("reverify persisted attestation output reservation: {error}"),
    })
}

fn new_attestation_output_reservation_record(
    session_id: &str,
    signing_request_sha256: &Sha256Digest,
    performance_run_deployment_sha256: &Sha256Digest,
    signer_executable_sha256: &Sha256Digest,
) -> AttestationOutputReservationRecord {
    let owner_pid = std::process::id();
    let owner_started_unix_ns = *PROCESS_STARTED_UNIX_NS.get_or_init(|| {
        let nanoseconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        u64::try_from(nanoseconds).unwrap_or(u64::MAX).max(1)
    });
    let counter = RESERVATION_NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let owner_nonce =
        digest(format!("{owner_pid}:{owner_started_unix_ns}:{counter}:{session_id}").as_bytes());
    AttestationOutputReservationRecord {
        schema: ATTESTATION_RESERVATION_SCHEMA.to_owned(),
        session_id: session_id.to_owned(),
        signing_request_sha256: signing_request_sha256.clone(),
        performance_run_deployment_sha256: performance_run_deployment_sha256.clone(),
        signer_executable_sha256: signer_executable_sha256.clone(),
        owner_pid,
        owner_started_unix_ns,
        owner_nonce,
    }
}

impl Drop for ReservedAttestationOutput {
    fn drop(&mut self) {
        if verify_opened_plain_file_identity(&self.reservation_path, &self.reservation).is_ok() {
            let _ = fs::remove_file(&self.reservation_path);
        }
        let _ = fs2::FileExt::unlock(&self.reservation);
    }
}

impl ActiveAttestationReservation {
    fn claim(path: PathBuf, role: DriverCommandRole) -> Result<Self, DriverHookError> {
        let mut active = ACTIVE_ATTESTATION_RESERVATIONS
            .get_or_init(|| Mutex::new(BTreeSet::new()))
            .lock()
            .map_err(|_| DriverHookError::InvalidContext {
                role,
                message: "attestation reservation registry is poisoned".to_owned(),
            })?;
        if !active.insert(path.clone()) {
            return Err(DriverHookError::InvalidContext {
                role,
                message: "attestation output is already reserved by a live signer invocation"
                    .to_owned(),
            });
        }
        Ok(Self { path })
    }
}

impl Drop for ActiveAttestationReservation {
    fn drop(&mut self) {
        if let Ok(mut active) = ACTIVE_ATTESTATION_RESERVATIONS
            .get_or_init(|| Mutex::new(BTreeSet::new()))
            .lock()
        {
            active.remove(&self.path);
        }
    }
}

fn reserve_attestation_signer_paths(
    root: &ArtifactRoot,
    context: &AttestationSignerHookContext<'_>,
    performance_run_deployment_sha256: &Sha256Digest,
    signer_executable_sha256: &Sha256Digest,
) -> Result<AttestationSignerPaths, DriverHookError> {
    let role = DriverCommandRole::AttestationSigner;
    let session_id =
        SessionId::new(context.session_id).map_err(|error| DriverHookError::InvalidContext {
            role,
            message: format!("session_id is invalid: {error}"),
        })?;
    let session_root = root.path().join(session_id.as_str());
    let signing_request = session_root.join(ATTESTATION_SIGNING_REQUEST_PATH);
    let fixed_output =
        attestation_signer_output_path(root, context.session_id, context.signing_request_sha256)?;
    let staging_root = fixed_output
        .absolute
        .parent()
        .expect("fixed signer output has a staging parent")
        .to_path_buf();
    verify_absolute_plain_directory(&staging_root, "capture attestation staging directory")
        .map_err(|error| DriverHookError::InvalidContext {
            role,
            message: error.to_string(),
        })?;
    let output_path = fixed_output.absolute;
    ensure_output_path_missing(&output_path, role)?;
    let output_name = output_path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("fixed signer output has a Unicode filename");
    let reservation_path = staging_root.join(format!(".{output_name}.reserve"));
    let active = ActiveAttestationReservation::claim(reservation_path.clone(), role)?;
    let reservation = claim_attestation_output_reservation(
        &reservation_path,
        context.session_id,
        context.signing_request_sha256,
        performance_run_deployment_sha256,
        signer_executable_sha256,
        role,
    )?;
    let output = ReservedAttestationOutput {
        path: output_path,
        reservation_path,
        reservation,
        _active: active,
    };
    verify_opened_plain_file_identity(&output.reservation_path, &output.reservation).map_err(
        |error| DriverHookError::InvalidContext {
            role,
            message: format!("verify attestation output reservation: {error}"),
        },
    )?;
    ensure_output_path_missing(&output.path, role)?;
    Ok(AttestationSignerPaths {
        signing_request,
        output,
    })
}

fn ensure_output_path_missing(path: &Path, role: DriverCommandRole) -> Result<(), DriverHookError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(DriverHookError::InvalidContext {
            role,
            message: format!("inspect attestation_output_path: {error}"),
        }),
        Ok(_) => Err(DriverHookError::InvalidContext {
            role,
            message: "attestation_output_path already exists; signer output must be create-new"
                .to_owned(),
        }),
    }
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;

        write!(&mut encoded, "{byte:02x}").expect("write to String cannot fail");
    }
    Sha256Digest::new(encoded).expect("SHA-256 output is valid")
}

const fn target_state_text(state: ControllerTargetState) -> &'static str {
    match state {
        ControllerTargetState::Running => "running",
        ControllerTargetState::Halted => "halted",
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        io::{Read, Seek, SeekFrom},
        path::{Path, PathBuf},
        thread,
        time::Instant as StdInstant,
    };

    use t32perf_session::{ArtifactRoot, SessionId, SessionLimits};
    use t32perf_trace32::{
        DriverAttestationDeployment, DriverFaultActions, DriverFirmwareDeployment,
        DriverPerformanceRunDeployment, DriverPerformanceRunQualificationDeployment,
        DriverPerformanceRunResources, DriverQualificationInput, T32mcpDriverConfig,
        T32mcpDriverConfigSchemaVersion, TC234L_SNOOPER_BUILD190766_IMPLEMENTATION_SHA256,
    };
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn expands_only_closed_placeholders_without_rescanning_values() {
        let digest = Sha256Digest::new("a".repeat(64)).unwrap();
        let values = HookValues {
            artifact_root: "C:/artifacts/{session_id}",
            session_id: "session-1",
            transaction_id: Some("transaction-1"),
            binding_sha256: Some(digest.as_str()),
            initial_target_state: Some("halted"),
            workload_identity: Some("fixed-workload"),
            duration_ns: Some("500000000"),
            signing_request_path: None,
            signing_request_sha256: None,
            attestation_output_path: None,
            policy_id: None,
            key_id: None,
        };
        let expanded = expand_argument(
            "--root={artifact_root};--session={session_id};--state={initial_target_state};--duration={duration_ns}",
            DriverCommandRole::Workload,
            &values,
        )
        .unwrap();
        assert_eq!(
            expanded,
            "--root=C:/artifacts/{session_id};--session=session-1;--state=halted;--duration=500000000"
        );
        assert!(matches!(
            expand_argument("{not_allowed}", DriverCommandRole::Workload, &values),
            Err(DriverHookError::InvalidCommand { .. })
        ));
    }

    #[test]
    fn signer_expands_only_its_closed_typed_placeholders() {
        let digest = Sha256Digest::new("a".repeat(64)).unwrap();
        let values = HookValues {
            artifact_root: "C:/artifacts/{key_id}",
            session_id: "session-1",
            transaction_id: None,
            binding_sha256: None,
            initial_target_state: None,
            workload_identity: None,
            duration_ns: None,
            signing_request_path: Some("C:/artifacts/session-1/request.json"),
            signing_request_sha256: Some(digest.as_str()),
            attestation_output_path: Some("C:/artifacts/session-1/capture/staging/signed.json"),
            policy_id: Some("policy-1"),
            key_id: Some("key-1"),
        };
        let expanded = expand_argument(
            "--root={artifact_root};--request={signing_request_path};--key={key_id}",
            DriverCommandRole::AttestationSigner,
            &values,
        )
        .unwrap();
        assert_eq!(
            expanded,
            "--root=C:/artifacts/{key_id};--request=C:/artifacts/session-1/request.json;--key=key-1"
        );
        assert!(matches!(
            expand_argument(
                "{transaction_id}",
                DriverCommandRole::AttestationSigner,
                &values
            ),
            Err(DriverHookError::InvalidContext { .. })
        ));
    }

    #[test]
    fn signer_paths_are_fixed_session_bound_and_atomically_reserved() {
        let temp = TempDir::new().unwrap();
        let root = ArtifactRoot::open(
            temp.path(),
            SessionLimits {
                max_file_bytes: 16 * 1024 * 1024,
                max_session_bytes: 64 * 1024 * 1024,
            },
        )
        .unwrap();
        let session_id = SessionId::new("signer-session").unwrap();
        root.create_session_with_id(session_id, &serde_json::json!({}))
            .unwrap();
        let signing_request = root
            .path()
            .join("signer-session")
            .join(ATTESTATION_SIGNING_REQUEST_PATH);
        fs::write(&signing_request, b"request").unwrap();
        let digest = digest(b"request");
        let deployment_digest = Sha256Digest::new("d".repeat(64)).unwrap();
        let signer_digest = Sha256Digest::new("e".repeat(64)).unwrap();
        let context = AttestationSignerHookContext {
            session_id: "signer-session",
            signing_request_sha256: &digest,
        };
        let fixed_output = attestation_signer_output_path(
            &root,
            context.session_id,
            context.signing_request_sha256,
        )
        .unwrap();
        let reservation_filename = format!(
            ".{}.reserve",
            fixed_output.absolute.file_name().unwrap().to_string_lossy()
        );
        let interrupted = new_attestation_output_reservation_record(
            "signer-session",
            &digest,
            &deployment_digest,
            &signer_digest,
        );
        let unpublished = fixed_output.absolute.with_file_name(format!(
            "{reservation_filename}.{}.unpublished",
            interrupted.owner_nonce.as_str()
        ));
        fs::write(&unpublished, b"partial").unwrap();
        let reserved =
            reserve_attestation_signer_paths(&root, &context, &deployment_digest, &signer_digest)
                .unwrap();
        assert!(unpublished.exists());
        fs::remove_file(&unpublished).unwrap();
        assert_eq!(reserved.signing_request, signing_request);
        assert_eq!(
            fixed_output.staged.as_str(),
            format!("capture-attestation-{}.json", digest.as_str())
        );
        assert_eq!(
            fixed_output.absolute,
            root.path().join(format!(
                "signer-session/capture/staging/capture-attestation-{}.json",
                digest.as_str()
            ))
        );
        assert_eq!(reserved.output.path, fixed_output.absolute);
        assert!(matches!(
            reserve_attestation_signer_paths(
                &root,
                &context,
                &deployment_digest,
                &signer_digest,
            ),
            Err(DriverHookError::InvalidContext { message, .. })
                if message.contains("already reserved")
        ));

        let output = reserved.output.path.clone();
        drop(reserved);

        let output_name = output.file_name().unwrap().to_string_lossy();
        let reservation_path = output
            .parent()
            .unwrap()
            .join(format!(".{output_name}.reserve"));
        let stale = new_attestation_output_reservation_record(
            "signer-session",
            &digest,
            &deployment_digest,
            &signer_digest,
        );
        let stale_bytes = serde_json::to_vec(&stale).unwrap();
        fs::write(&reservation_path, &stale_bytes).unwrap();
        let mut recovered =
            reserve_attestation_signer_paths(&root, &context, &deployment_digest, &signer_digest)
                .unwrap();
        let mut recovered_bytes = Vec::new();
        recovered
            .output
            .reservation
            .seek(SeekFrom::Start(0))
            .unwrap();
        recovered
            .output
            .reservation
            .read_to_end(&mut recovered_bytes)
            .unwrap();
        assert_eq!(recovered_bytes, stale_bytes);
        drop(recovered);

        for malformed in [Vec::new(), b"{\"schema\":".to_vec()] {
            fs::write(&reservation_path, malformed).unwrap();
            assert!(matches!(
                reserve_attestation_signer_paths(
                    &root,
                    &context,
                    &deployment_digest,
                    &signer_digest,
                ),
                Err(DriverHookError::InvalidContext { .. })
            ));
            fs::remove_file(&reservation_path).unwrap();
        }

        let mut mismatched = new_attestation_output_reservation_record(
            "signer-session",
            &digest,
            &deployment_digest,
            &signer_digest,
        );
        mismatched.performance_run_deployment_sha256 = Sha256Digest::new("f".repeat(64)).unwrap();
        fs::write(&reservation_path, serde_json::to_vec(&mismatched).unwrap()).unwrap();
        assert!(matches!(
            reserve_attestation_signer_paths(
                &root,
                &context,
                &deployment_digest,
                &signer_digest,
            ),
            Err(DriverHookError::InvalidContext { message, .. })
                if message.contains("exactly bound")
        ));
        fs::remove_file(&reservation_path).unwrap();

        let linked_target = temp.path().join("foreign-reservation.json");
        fs::write(&linked_target, serde_json::to_vec(&stale).unwrap()).unwrap();
        if create_file_symlink(&linked_target, &reservation_path).is_ok() {
            assert!(matches!(
                reserve_attestation_signer_paths(
                    &root,
                    &context,
                    &deployment_digest,
                    &signer_digest,
                ),
                Err(DriverHookError::InvalidContext { .. })
            ));
            fs::remove_file(&reservation_path).unwrap();
        }

        fs::write(&output, b"already exists").unwrap();
        assert!(matches!(
            reserve_attestation_signer_paths(
                &root,
                &context,
                &deployment_digest,
                &signer_digest,
            ),
            Err(DriverHookError::InvalidContext { message, .. })
                if message.contains("create-new")
        ));
    }

    #[test]
    fn missing_hook_is_explicitly_unsupported() {
        let loaded = LoadedDriverConfig::for_test(PathBuf::from("unused"), config_without_hooks());
        let digest = Sha256Digest::new("a".repeat(64)).unwrap();
        let artifact_root = absolute_test_directory();
        let context = FaultHookContext {
            artifact_root: &artifact_root,
            session_id: "session-1",
            transaction_id: "transaction-1",
            binding_sha256: &digest,
        };
        let error = block_on(run_fault_hook(
            &loaded,
            DriverCommandRole::Trace32DisconnectAtStop,
            &context,
            1_000,
        ))
        .unwrap_err();
        assert!(error.is_unsupported());
    }

    #[test]
    fn duration_selects_only_the_performance_run_workload() {
        let mut loaded =
            LoadedDriverConfig::for_test(PathBuf::from("unused"), config_without_hooks());
        loaded.config.workload = Some(test_command("low-level-workload", vec![]));
        loaded.config.performance_run = Some(DriverPerformanceRunDeployment {
            max_duration_ns: 100_000_000,
            firmware: DriverFirmwareDeployment {
                path: "unused-firmware".to_owned(),
                sha256: Sha256Digest::new("1".repeat(64)).unwrap(),
            },
            workload_command: test_command("performance-run-workload", vec![]),
            qualification: DriverPerformanceRunQualificationDeployment {
                policy_id: "qualification-policy".to_owned(),
                qualification_receipt: test_qualification_input(),
                hil_receipt: test_qualification_input(),
                recovery_evidence: None,
            },
            attestation: DriverAttestationDeployment {
                policy_path: "unused-policy".to_owned(),
                policy_sha256: Sha256Digest::new("2".repeat(64)).unwrap(),
                policy_id: "policy".to_owned(),
                key_id: "key".to_owned(),
                signer_command: test_command("signer", vec![]),
                idempotent_by_signing_request_sha256: true,
            },
            resources: DriverPerformanceRunResources::default(),
        });

        assert_eq!(
            select_workload_command(&loaded, None).unwrap().executable,
            "low-level-workload"
        );
        assert_eq!(
            select_workload_command(&loaded, Some(500_000_000))
                .unwrap()
                .executable,
            "performance-run-workload"
        );
    }

    #[test]
    fn hook_executable_digest_is_rechecked_before_invocation() {
        let executable = std::env::current_exe().unwrap();
        let mut loaded =
            LoadedDriverConfig::for_test(PathBuf::from("unused"), config_without_hooks());
        loaded.config.workload = Some(DriverCommand {
            executable: executable.to_string_lossy().into_owned(),
            expected_executable_sha256: Sha256Digest::new("0".repeat(64)).unwrap(),
            arguments: vec![
                "{initial_target_state}".to_owned(),
                "{workload_identity}".to_owned(),
            ],
            timeout_ms: 100,
        });
        let digest = Sha256Digest::new("a".repeat(64)).unwrap();
        let artifact_root = absolute_test_directory();
        let artifact_root_text = artifact_root.to_string_lossy();
        let values = HookValues {
            artifact_root: &artifact_root_text,
            session_id: "session-1",
            transaction_id: Some("transaction-1"),
            binding_sha256: Some(digest.as_str()),
            initial_target_state: Some("running"),
            workload_identity: Some("fixed-workload"),
            duration_ns: None,
            signing_request_path: None,
            signing_request_sha256: None,
            attestation_output_path: None,
            policy_id: None,
            key_id: None,
        };
        let command = loaded.config.workload.as_ref().unwrap();
        assert!(matches!(
            block_on(run_hook_command(
                &loaded,
                command,
                DriverCommandRole::Workload,
                &values,
                1_000,
            )),
            Err(DriverHookError::ExecutableRejected { message, .. })
                if message.contains("has SHA-256")
        ));
    }

    #[test]
    fn process_requires_zero_exit_and_empty_stdout() {
        let (executable, arguments) = shell("exit 0", "exit /b 0");
        let success = block_on(execute_process(
            &executable,
            &arguments,
            DriverCommandRole::Workload,
            2_000,
            4_096,
        ))
        .unwrap();
        assert_eq!(success.stderr_summary, None);

        let (executable, arguments) = shell("printf unexpected", "echo unexpected");
        assert!(matches!(
            block_on(execute_process(
                &executable,
                &arguments,
                DriverCommandRole::Workload,
                2_000,
                4_096,
            )),
            Err(DriverHookError::UnexpectedStdout { .. })
        ));

        let (executable, arguments) =
            shell("printf boom >&2; exit 7", "echo boom 1>&2 & exit /b 7");
        let error = block_on(execute_process(
            &executable,
            &arguments,
            DriverCommandRole::Workload,
            2_000,
            4_096,
        ))
        .unwrap_err();
        assert!(matches!(
            error,
            DriverHookError::ExitFailure {
                stderr_summary: Some(summary),
                ..
            } if summary.contains("boom")
        ));
    }

    #[test]
    fn process_kills_timeout_and_stderr_overflow() {
        let (executable, arguments) = long_running_process();
        let started = StdInstant::now();
        assert!(matches!(
            block_on(execute_process(
                &executable,
                &arguments,
                DriverCommandRole::Workload,
                100,
                4_096,
            )),
            Err(DriverHookError::Timeout { .. })
        ));
        assert!(started.elapsed() < Duration::from_secs(2));

        let (executable, arguments) = shell(
            "i=0; while [ $i -lt 1000 ]; do printf 0123456789 >&2; i=$((i+1)); done",
            "for /L %i in (1,1,1000) do @echo 0123456789 1>&2",
        );
        assert!(matches!(
            block_on(execute_process(
                &executable,
                &arguments,
                DriverCommandRole::Workload,
                2_000,
                64,
            )),
            Err(DriverHookError::StderrLimitExceeded { .. })
        ));
    }

    #[test]
    fn process_total_deadline_cap_kills_nested_process_tree() {
        let temp = TempDir::new().unwrap();
        let marker = temp.path().join("descendant-was-not-killed");
        let (executable, arguments) = nested_marker_process(&marker);
        let configured_hook_timeout_ms = 2_000;
        let total_driver_deadline_cap_ms = 100;
        let started = StdInstant::now();
        assert!(matches!(
            block_on(execute_process(
                &executable,
                &arguments,
                DriverCommandRole::Workload,
                configured_hook_timeout_ms.min(total_driver_deadline_cap_ms),
                4_096,
            )),
            Err(DriverHookError::Timeout { .. })
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        thread::sleep(Duration::from_millis(1_200));
        assert!(
            !marker.exists(),
            "a descendant survived the hook process-tree termination"
        );
    }

    #[test]
    fn signer_timeout_kills_its_nested_process_tree() {
        let temp = TempDir::new().unwrap();
        let marker = temp.path().join("signer-descendant-survived");
        let (executable, arguments) = nested_marker_process(&marker);
        assert!(matches!(
            block_on(execute_process(
                &executable,
                &arguments,
                DriverCommandRole::AttestationSigner,
                100,
                4_096,
            )),
            Err(DriverHookError::Timeout { .. })
        ));
        thread::sleep(Duration::from_millis(1_200));
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn successful_hook_waits_for_descendants_that_close_standard_streams() {
        let temp = TempDir::new().unwrap();
        let marker = temp.path().join("detached-descendant-complete");
        let marker_text = marker.to_string_lossy();
        let script = format!(
            "(exec </dev/null >/dev/null 2>&1; sleep 0.4; printf complete > '{}') & exit 0",
            marker_text.replace('\'', "'\\''")
        );
        let started = StdInstant::now();
        block_on(execute_process(
            Path::new("/bin/sh"),
            &["-c".to_owned(), script],
            DriverCommandRole::AttestationSigner,
            2_000,
            4_096,
        ))
        .unwrap();
        assert!(started.elapsed() >= Duration::from_millis(300));
        assert!(marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn detached_descendant_that_outlives_deadline_is_killed() {
        let temp = TempDir::new().unwrap();
        let marker = temp.path().join("detached-descendant-survived");
        let marker_text = marker.to_string_lossy();
        let script = format!(
            "(exec </dev/null >/dev/null 2>&1; sleep 1; printf complete > '{}') & exit 0",
            marker_text.replace('\'', "'\\''")
        );
        assert!(matches!(
            block_on(execute_process(
                Path::new("/bin/sh"),
                &["-c".to_owned(), script],
                DriverCommandRole::AttestationSigner,
                100,
                4_096,
            )),
            Err(DriverHookError::Timeout { .. })
        ));
        thread::sleep(Duration::from_millis(1_200));
        assert!(
            !marker.exists(),
            "a detached descendant survived the hook process-group termination"
        );
    }

    #[cfg(unix)]
    #[test]
    fn nonzero_hook_kills_detached_descendant() {
        let temp = TempDir::new().unwrap();
        let marker = temp.path().join("failed-hook-descendant-survived");
        let marker_text = marker.to_string_lossy();
        let script = format!(
            "(exec </dev/null >/dev/null 2>&1; sleep 1; printf complete > '{}') & exit 7",
            marker_text.replace('\'', "'\\''")
        );
        assert!(matches!(
            block_on(execute_process(
                Path::new("/bin/sh"),
                &["-c".to_owned(), script],
                DriverCommandRole::AttestationSigner,
                2_000,
                4_096,
            )),
            Err(DriverHookError::ExitFailure { code: Some(7), .. })
        ));
        thread::sleep(Duration::from_millis(1_200));
        assert!(
            !marker.exists(),
            "a failed hook's detached descendant survived process-group termination"
        );
    }

    #[cfg(unix)]
    #[test]
    fn nonzero_hook_kills_descendant_that_holds_standard_streams() {
        let temp = TempDir::new().unwrap();
        let marker = temp.path().join("failed-hook-stream-descendant-survived");
        let marker_text = marker.to_string_lossy();
        let script = format!(
            "(sleep 1; printf complete > '{}') & printf boom >&2; exit 7",
            marker_text.replace('\'', "'\\''")
        );
        let error = block_on(execute_process(
            Path::new("/bin/sh"),
            &["-c".to_owned(), script],
            DriverCommandRole::AttestationSigner,
            2_000,
            4_096,
        ))
        .unwrap_err();
        assert!(matches!(
            error,
            DriverHookError::ExitFailure {
                code: Some(7),
                stderr_summary: Some(summary),
                ..
            } if summary.contains("boom")
        ));
        thread::sleep(Duration::from_millis(1_200));
        assert!(
            !marker.exists(),
            "a failed hook's stream-holding descendant survived process-group termination"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cancelling_hook_kills_its_process_group() {
        let temp = TempDir::new().unwrap();
        let started = temp.path().join("hook-started");
        let marker = temp.path().join("cancelled-hook-descendant-survived");
        let started_text = started.to_string_lossy();
        let marker_text = marker.to_string_lossy();
        let script = format!(
            "(exec </dev/null >/dev/null 2>&1; printf started > '{}'; sleep 1; printf complete > '{}') & sleep 10",
            started_text.replace('\'', "'\\''"),
            marker_text.replace('\'', "'\\''")
        );
        block_on(async {
            let task = tokio::spawn(async move {
                execute_process(
                    Path::new("/bin/sh"),
                    &["-c".to_owned(), script],
                    DriverCommandRole::AttestationSigner,
                    20_000,
                    4_096,
                )
                .await
            });
            let started_deadline = Instant::now() + Duration::from_secs(2);
            while !started.exists() {
                assert!(
                    Instant::now() < started_deadline,
                    "hook did not start before the test deadline"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            tokio::time::sleep(Duration::from_millis(1_200)).await;
        });
        assert!(
            !marker.exists(),
            "a cancelled hook's descendant survived process-group kill-on-drop"
        );
    }

    fn config_without_hooks() -> T32mcpDriverConfig {
        T32mcpDriverConfig {
            schema: T32mcpDriverConfigSchemaVersion::V1,
            executable: absolute_test_directory()
                .join("unused-t32mcp")
                .to_string_lossy()
                .into_owned(),
            expected_executable_sha256: Sha256Digest::new("0".repeat(64)).unwrap(),
            skills_root: absolute_test_directory().to_string_lossy().into_owned(),
            trace32_port: 20_000,
            expected_t32mcp_version: "0.2.2".to_owned(),
            expected_bundle_sha256: Sha256Digest::new(
                TC234L_SNOOPER_BUILD190766_IMPLEMENTATION_SHA256.to_owned(),
            )
            .unwrap(),
            poll_interval_ms: 100,
            operation_timeout_ms: 1_000,
            max_stderr_bytes: 4_096,
            workload: None,
            fault_actions: DriverFaultActions::default(),
            performance_run: None,
        }
    }

    fn test_command(executable: &str, arguments: Vec<String>) -> DriverCommand {
        DriverCommand {
            executable: executable.to_owned(),
            expected_executable_sha256: Sha256Digest::new("0".repeat(64)).unwrap(),
            arguments,
            timeout_ms: 100,
        }
    }

    fn test_qualification_input() -> DriverQualificationInput {
        DriverQualificationInput {
            path: "unused-qualification-input".to_owned(),
            sha256: Sha256Digest::new("3".repeat(64)).unwrap(),
        }
    }

    fn absolute_test_directory() -> PathBuf {
        std::env::current_dir().unwrap()
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    #[cfg(unix)]
    fn shell(unix_script: &str, _windows_script: &str) -> (PathBuf, Vec<String>) {
        (
            PathBuf::from("/bin/sh"),
            vec!["-c".to_owned(), unix_script.to_owned()],
        )
    }

    #[cfg(windows)]
    fn shell(_unix_script: &str, windows_script: &str) -> (PathBuf, Vec<String>) {
        let executable = std::env::var_os("ComSpec")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows\System32\cmd.exe"));
        (
            executable,
            vec![
                "/D".to_owned(),
                "/S".to_owned(),
                "/C".to_owned(),
                windows_script.to_owned(),
            ],
        )
    }

    #[cfg(unix)]
    fn long_running_process() -> (PathBuf, Vec<String>) {
        (PathBuf::from("/bin/sleep"), vec!["5".to_owned()])
    }

    #[cfg(windows)]
    fn long_running_process() -> (PathBuf, Vec<String>) {
        let system_root = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        (
            system_root.join(r"System32\WindowsPowerShell\v1.0\powershell.exe"),
            vec![
                "-NoLogo".to_owned(),
                "-NoProfile".to_owned(),
                "-NonInteractive".to_owned(),
                "-Command".to_owned(),
                "Start-Sleep -Seconds 5".to_owned(),
            ],
        )
    }

    #[cfg(unix)]
    fn nested_marker_process(marker: &Path) -> (PathBuf, Vec<String>) {
        let marker = marker.to_string_lossy().into_owned();
        (
            PathBuf::from("/bin/sh"),
            vec![
                "-c".to_owned(),
                "/bin/sh -c 'sleep 0.8; printf late > \"$1\"' nested \"$1\"; wait".to_owned(),
                "outer".to_owned(),
                marker,
            ],
        )
    }

    #[cfg(windows)]
    fn nested_marker_process(marker: &Path) -> (PathBuf, Vec<String>) {
        let executable = std::env::var_os("ComSpec")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows\System32\cmd.exe"));
        let marker = marker.to_string_lossy().replace('\'', "''");
        let script = format!(
            "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"Start-Sleep -Milliseconds 800; [System.IO.File]::WriteAllText('{marker}','late')\""
        );
        (
            executable,
            vec!["/D".to_owned(), "/S".to_owned(), "/C".to_owned(), script],
        )
    }

    #[cfg(unix)]
    fn create_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn create_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_file(target, link)
    }
}
