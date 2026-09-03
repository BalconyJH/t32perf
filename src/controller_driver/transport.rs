use std::{
    collections::BTreeSet,
    future::Future,
    io,
    path::Path,
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use anyhow::{Context as _, Result, bail, ensure};
#[cfg(windows)]
use process_wrap::tokio::JobObject;
#[cfg(unix)]
use process_wrap::tokio::ProcessGroup;
use process_wrap::tokio::{ChildWrapper, CommandWrap, KillOnDrop};
use rmcp::{
    RoleClient, ServiceExt as _,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, JsonObject,
        PaginatedRequestParams, ResultType,
    },
    service::{QuitReason, RunningService, RxJsonRpcMessage, TxJsonRpcMessage},
    transport::Transport,
};
use serde::Serialize;
use t32perf_trace32::{
    ExecutePracticeSkillCall, MAX_CONTROLLER_MCP_RESPONSE_BYTES, NoArgumentsToolCall, T32mcpTool,
};
use tokio::{
    io::{
        AsyncBufRead, AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWrite,
        AsyncWriteExt as _, BufReader,
    },
    process::{ChildStderr, ChildStdin, ChildStdout, Command},
    sync::Mutex as AsyncMutex,
    task::JoinHandle,
    time::{Instant, timeout, timeout_at},
};

const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const MCP_INITIALIZE_TIMEOUT: Duration = Duration::from_secs(10);
const MCP_TOOL_INVENTORY_TIMEOUT: Duration = Duration::from_secs(10);
const MCP_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const STDERR_JOIN_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_VERSION_STDOUT_BYTES: u64 = 256;
const MAX_MCP_JSON_LINE_BYTES: usize = 1024 * 1024;
const MAX_TOOL_INVENTORY_ENTRIES: usize = 128;
const MAX_TOOL_INVENTORY_PAGES: usize = 32;
const MAX_TOOL_NAME_BYTES: usize = 256;
const MAX_PAGINATION_CURSOR_BYTES: usize = 1024;
const HIDDEN_EXECUTE_PRACTICE_TOOL: &str = "execute_practice";
const CHILD_GRACEFUL_EXIT_TIMEOUT: Duration = Duration::from_secs(3);
const CHILD_FORCE_EXIT_TIMEOUT: Duration = Duration::from_secs(3);

type ClientService = RunningService<RoleClient, ()>;
type StderrTask = JoinHandle<std::io::Result<BoundedOutput>>;
type SharedChild = Arc<AsyncMutex<Option<Box<dyn ChildWrapper>>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ChildShutdownMode {
    Graceful = 0,
    Force = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildCloseOutcome {
    Graceful { success: bool, code: Option<i32> },
    Forced,
    AlreadyExitedBeforeForce { success: bool, code: Option<i32> },
    ForcedAfterGracefulTimeout,
    ProtocolFailureKilled,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForceExitOutcome {
    Killed,
    AlreadyExited { success: bool, code: Option<i32> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportFailure {
    StdoutFrameTooLarge,
    TruncatedStdoutFrame,
    InvalidStdoutJson,
    StdoutRead,
}

impl TransportFailure {
    const fn message(self) -> &'static str {
        match self {
            Self::StdoutFrameTooLarge => "t32mcp emitted an oversized MCP JSON frame",
            Self::TruncatedStdoutFrame => "t32mcp closed stdout with a truncated MCP JSON frame",
            Self::InvalidStdoutJson => "t32mcp emitted an invalid MCP JSON frame",
            Self::StdoutRead => "failed to read t32mcp MCP stdout",
        }
    }
}

#[derive(Clone)]
struct TransportControl {
    shutdown_mode: Arc<AtomicU8>,
    failure: Arc<Mutex<Option<TransportFailure>>>,
    close_outcome: Arc<Mutex<Option<ChildCloseOutcome>>>,
}

impl TransportControl {
    fn new() -> Self {
        Self {
            shutdown_mode: Arc::new(AtomicU8::new(ChildShutdownMode::Graceful as u8)),
            failure: Arc::new(Mutex::new(None)),
            close_outcome: Arc::new(Mutex::new(None)),
        }
    }

    fn force(&self) {
        self.shutdown_mode
            .store(ChildShutdownMode::Force as u8, Ordering::Release);
    }

    fn shutdown_mode(&self) -> ChildShutdownMode {
        if self.shutdown_mode.load(Ordering::Acquire) == ChildShutdownMode::Force as u8 {
            ChildShutdownMode::Force
        } else {
            ChildShutdownMode::Graceful
        }
    }

    fn record_failure(&self, failure: TransportFailure) {
        let mut slot = self
            .failure
            .lock()
            .expect("transport failure lock poisoned");
        slot.get_or_insert(failure);
    }

    fn failure(&self) -> Option<TransportFailure> {
        *self
            .failure
            .lock()
            .expect("transport failure lock poisoned")
    }

    fn record_close_outcome(&self, outcome: ChildCloseOutcome) {
        *self
            .close_outcome
            .lock()
            .expect("child close outcome lock poisoned") = Some(outcome);
    }

    fn close_outcome(&self) -> Option<ChildCloseOutcome> {
        *self
            .close_outcome
            .lock()
            .expect("child close outcome lock poisoned")
    }
}

struct BoundedChildTransport<R, W> {
    child: SharedChild,
    read: BufReader<R>,
    write: Arc<AsyncMutex<Option<W>>>,
    control: TransportControl,
}

/// Injectable MCP boundary used by the controller driver.
pub(crate) trait T32mcpTransport {
    fn execute<'a>(
        &'a self,
        call: &'a ExecutePracticeSkillCall,
    ) -> impl Future<Output = Result<String>> + 'a;

    fn collect<'a>(
        &'a self,
        call: &'a NoArgumentsToolCall,
    ) -> impl Future<Output = Result<String>> + 'a;

    fn abort<'a>(&'a self, call: &'a NoArgumentsToolCall) -> impl Future<Output = Result<()>> + 'a;

    fn shutdown(self) -> impl Future<Output = Result<String>>
    where
        Self: Sized;

    fn force_disconnect(self) -> impl Future<Output = Result<ForceDisconnectResult>>
    where
        Self: Sized;
}

/// The exact child tree has been killed and reaped.  Post-kill MCP service or
/// stderr cleanup diagnostics do not revoke that external side effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ForceDisconnectResult {
    pub(crate) cleanup_diagnostic: Option<String>,
}

/// Official t32mcp client over its standard-input/standard-output transport.
pub(crate) struct StdioT32mcpClient {
    service: ClientService,
    stderr_task: StderrTask,
    control: TransportControl,
    child: SharedChild,
}

#[derive(Debug)]
enum FrameReadError {
    TooLarge,
    Truncated,
    Io,
}

impl<R, W> Transport<RoleClient> for BoundedChildTransport<R, W>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    type Error = io::Error;

    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleClient>,
    ) -> impl Future<Output = std::result::Result<(), Self::Error>> + Send + 'static {
        let write = self.write.clone();
        async move {
            let mut bytes = serde_json::to_vec(&item)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "serialize MCP frame"))?;
            if bytes.len() >= MAX_MCP_JSON_LINE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "outbound MCP frame exceeds the fixed bound",
                ));
            }
            bytes.push(b'\n');
            let mut writer = write.lock().await;
            let writer = writer.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "t32mcp stdin is closed")
            })?;
            writer.write_all(&bytes).await?;
            writer.flush().await
        }
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleClient>> {
        loop {
            let frame = match read_bounded_frame(&mut self.read).await {
                Ok(Some(frame)) => frame,
                Ok(None) => return None,
                Err(error) => {
                    let failure = match error {
                        FrameReadError::TooLarge => TransportFailure::StdoutFrameTooLarge,
                        FrameReadError::Truncated => TransportFailure::TruncatedStdoutFrame,
                        FrameReadError::Io => TransportFailure::StdoutRead,
                    };
                    self.control.record_failure(failure);
                    return None;
                }
            };
            if frame.is_empty() {
                continue;
            }
            match serde_json::from_slice(&frame) {
                Ok(message) => return Some(message),
                Err(_) => {
                    self.control
                        .record_failure(TransportFailure::InvalidStdoutJson);
                    return None;
                }
            }
        }
    }

    async fn close(&mut self) -> std::result::Result<(), Self::Error> {
        let protocol_failure = self.control.failure().is_some();
        let mode = self.control.shutdown_mode();
        if mode == ChildShutdownMode::Graceful && !protocol_failure {
            self.write.lock().await.take();
        }
        let mut child = self.child.lock().await;
        let already_forced = mode == ChildShutdownMode::Force
            && self.control.close_outcome() == Some(ChildCloseOutcome::Forced);
        let outcome = if already_forced {
            child.take();
            ChildCloseOutcome::Forced
        } else {
            match child.take() {
                Some(mut child) => close_child(&mut child, mode, protocol_failure).await,
                None => ChildCloseOutcome::Failed,
            }
        };
        if mode == ChildShutdownMode::Force || protocol_failure {
            self.write.lock().await.take();
        }
        self.control.record_close_outcome(outcome);
        if outcome == ChildCloseOutcome::Failed {
            Err(io::Error::other("failed to terminate exact t32mcp child"))
        } else {
            Ok(())
        }
    }
}

fn spawn_mcp_transport(
    executable: &Path,
    skills_root: &Path,
    trace32_port: u16,
    deadline: Instant,
) -> io::Result<(
    BoundedChildTransport<ChildStdout, ChildStdin>,
    ChildStderr,
    TransportControl,
    SharedChild,
)> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "t32mcp MCP process spawn was not started because the absolute startup deadline elapsed",
        ));
    }
    let mut command = managed_command(executable, |command| {
        command
            .arg("--skills")
            .arg(skills_root)
            .arg("--port")
            .arg(trace32_port.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
    });
    let mut child = command.spawn()?;
    let stdin = child
        .stdin()
        .take()
        .ok_or_else(|| io::Error::other("t32mcp child stdin was unavailable"))?;
    let stdout = child
        .stdout()
        .take()
        .ok_or_else(|| io::Error::other("t32mcp child stdout was unavailable"))?;
    let stderr = child
        .stderr()
        .take()
        .ok_or_else(|| io::Error::other("t32mcp child stderr was unavailable"))?;
    let control = TransportControl::new();
    let child = Arc::new(AsyncMutex::new(Some(child)));
    let transport = BoundedChildTransport {
        child: child.clone(),
        read: BufReader::new(stdout),
        write: Arc::new(AsyncMutex::new(Some(stdin))),
        control: control.clone(),
    };
    Ok((transport, stderr, control, child))
}

fn managed_command(executable: &Path, configure: impl FnOnce(&mut Command)) -> CommandWrap {
    let mut command = CommandWrap::with_new(executable, configure);
    command.wrap(KillOnDrop);
    #[cfg(unix)]
    command.wrap(ProcessGroup::leader());
    #[cfg(windows)]
    command.wrap(JobObject);
    command
}

async fn read_bounded_frame<R>(
    reader: &mut R,
) -> std::result::Result<Option<Vec<u8>>, FrameReadError>
where
    R: AsyncBufRead + Unpin,
{
    let mut frame = Vec::with_capacity(8 * 1024);
    loop {
        let available = reader.fill_buf().await.map_err(|_| FrameReadError::Io)?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err(FrameReadError::Truncated)
            };
        }
        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            let payload = &available[..newline];
            if frame.len().saturating_add(payload.len()) > MAX_MCP_JSON_LINE_BYTES {
                return Err(FrameReadError::TooLarge);
            }
            frame.extend_from_slice(payload);
            reader.consume(newline + 1);
            if frame.last() == Some(&b'\r') {
                frame.pop();
            }
            return Ok(Some(frame));
        }
        if frame.len().saturating_add(available.len()) > MAX_MCP_JSON_LINE_BYTES {
            return Err(FrameReadError::TooLarge);
        }
        let consumed = available.len();
        frame.extend_from_slice(available);
        reader.consume(consumed);
    }
}

async fn close_child(
    child: &mut Box<dyn ChildWrapper>,
    mode: ChildShutdownMode,
    protocol_failure: bool,
) -> ChildCloseOutcome {
    if protocol_failure {
        return if force_child_exit(child).await.is_ok() {
            ChildCloseOutcome::ProtocolFailureKilled
        } else {
            ChildCloseOutcome::Failed
        };
    }
    match mode {
        ChildShutdownMode::Graceful => {
            match timeout(CHILD_GRACEFUL_EXIT_TIMEOUT, child.wait()).await {
                Ok(Ok(status)) => ChildCloseOutcome::Graceful {
                    success: status.success(),
                    code: status.code(),
                },
                Ok(Err(_)) => ChildCloseOutcome::Failed,
                Err(_) => {
                    if force_child_exit(child).await.is_ok() {
                        ChildCloseOutcome::ForcedAfterGracefulTimeout
                    } else {
                        ChildCloseOutcome::Failed
                    }
                }
            }
        }
        ChildShutdownMode::Force => match child.try_wait() {
            Ok(Some(status)) => ChildCloseOutcome::AlreadyExitedBeforeForce {
                success: status.success(),
                code: status.code(),
            },
            Ok(None) => match force_child_exit(child).await {
                Ok(ForceExitOutcome::Killed) => ChildCloseOutcome::Forced,
                Ok(ForceExitOutcome::AlreadyExited { success, code }) => {
                    ChildCloseOutcome::AlreadyExitedBeforeForce { success, code }
                }
                Err(_) => ChildCloseOutcome::Failed,
            },
            Err(_) => ChildCloseOutcome::Failed,
        },
    }
}

async fn force_shared_child(child: &SharedChild, control: &TransportControl) -> Result<()> {
    let mut child = child.lock().await;
    let outcome = match child.as_mut() {
        Some(child) => close_child(child, ChildShutdownMode::Force, false).await,
        None => ChildCloseOutcome::Failed,
    };
    control.record_close_outcome(outcome);
    match outcome {
        ChildCloseOutcome::Forced => Ok(()),
        ChildCloseOutcome::AlreadyExitedBeforeForce { success, code } => {
            bail!("t32mcp child exited before forced disconnect (success={success}, code={code:?})")
        }
        _ => bail!("failed to kill and wait for the exact t32mcp process tree"),
    }
}

async fn force_child_exit(child: &mut Box<dyn ChildWrapper>) -> io::Result<ForceExitOutcome> {
    if let Some(status) = child.try_wait()? {
        return Ok(ForceExitOutcome::AlreadyExited {
            success: status.success(),
            code: status.code(),
        });
    }
    if let Err(kill_error) = child.start_kill() {
        if let Some(status) = child.try_wait()? {
            return Ok(ForceExitOutcome::AlreadyExited {
                success: status.success(),
                code: status.code(),
            });
        }
        return Err(kill_error);
    }
    timeout(CHILD_FORCE_EXIT_TIMEOUT, child.wait())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "t32mcp child did not exit"))??;
    Ok(ForceExitOutcome::Killed)
}

impl StdioT32mcpClient {
    /// Verifies the executable, starts the server, and validates its MCP identity.
    pub(crate) async fn spawn(
        executable: &Path,
        skills_root: &Path,
        trace32_port: u16,
        expected_version: &str,
        max_stderr_bytes: u64,
    ) -> Result<Self> {
        Self::spawn_until(
            executable,
            skills_root,
            trace32_port,
            expected_version,
            max_stderr_bytes,
            Instant::now()
                + VERSION_PROBE_TIMEOUT
                + MCP_INITIALIZE_TIMEOUT
                + MCP_TOOL_INVENTORY_TIMEOUT,
        )
        .await
    }

    /// Starts a client under an absolute controller deadline.  Every owning
    /// startup stage handles its own timeout and reaps the child before
    /// returning, so callers never cancel/drop startup futures.
    pub(crate) async fn spawn_until(
        executable: &Path,
        skills_root: &Path,
        trace32_port: u16,
        expected_version: &str,
        max_stderr_bytes: u64,
        deadline: Instant,
    ) -> Result<Self> {
        ensure_startup_deadline(deadline, "t32mcp startup")?;
        validate_expected_version(expected_version)?;
        ensure!(trace32_port != 0, "TRACE32 API port must be nonzero");
        ensure!(
            max_stderr_bytes != 0,
            "t32mcp stderr retention bound must be nonzero"
        );
        verify_executable_version(executable, expected_version, max_stderr_bytes, deadline).await?;
        ensure_startup_deadline(deadline, "MCP process spawn")?;

        let (transport, stderr, control, child) =
            spawn_mcp_transport(executable, skills_root, trace32_port, deadline).with_context(
                || {
                    format!(
                        "failed to spawn t32mcp executable `{}`",
                        executable.display()
                    )
                },
            )?;
        let stderr_task = tokio::spawn(read_bounded(stderr, max_stderr_bytes));

        let initialize_deadline = deadline.min(Instant::now() + MCP_INITIALIZE_TIMEOUT);
        let service = match timeout_at(initialize_deadline, ().serve(transport)).await {
            Ok(Ok(service)) => service,
            Ok(Err(error)) => {
                let error = transport_or_service_error(
                    &control,
                    anyhow::Error::new(error).context("t32mcp MCP initialization failed"),
                );
                return Err(
                    cleanup_failed_initialization(stderr_task, &child, &control, error).await,
                );
            }
            Err(_) => {
                let error = transport_or_service_error(
                    &control,
                    anyhow::anyhow!(
                        "t32mcp MCP initialization exceeded its absolute startup deadline"
                    ),
                );
                return Err(
                    cleanup_failed_initialization(stderr_task, &child, &control, error).await,
                );
            }
        };

        if let Err(error) = validate_initialized_server(&service, expected_version) {
            return Err(cleanup_started_service(service, stderr_task, &control, error).await);
        }

        let inventory_deadline = deadline.min(Instant::now() + MCP_TOOL_INVENTORY_TIMEOUT);
        let tools = match timeout_at(inventory_deadline, list_all_tool_names(&service)).await {
            Ok(Ok(tools)) => tools,
            Ok(Err(error)) => {
                let error = transport_or_service_error(&control, error);
                return Err(cleanup_started_service(service, stderr_task, &control, error).await);
            }
            Err(_) => {
                let error =
                    anyhow::anyhow!("t32mcp tools/list exceeded its absolute startup deadline");
                return Err(cleanup_started_service(service, stderr_task, &control, error).await);
            }
        };
        if let Err(error) = validate_tool_inventory(tools.iter().map(String::as_str)) {
            return Err(cleanup_started_service(service, stderr_task, &control, error).await);
        }

        Ok(Self {
            service,
            stderr_task,
            control,
            child,
        })
    }

    /// Calls the official skill execution tool and returns its sole text block.
    pub(crate) async fn execute(&self, call: &ExecutePracticeSkillCall) -> Result<String> {
        ensure!(
            call.tool == T32mcpTool::ExecutePracticeSkill,
            "execute handoff names the wrong official t32mcp tool"
        );
        let arguments = serialize_arguments(&call.arguments)?;
        let result = self
            .call_once(T32mcpTool::ExecutePracticeSkill, arguments)
            .await?;
        extract_text_result(result, T32mcpTool::ExecutePracticeSkill.as_str())
    }

    /// Calls the official response collection tool and returns its sole text block.
    pub(crate) async fn collect(&self, call: &NoArgumentsToolCall) -> Result<String> {
        ensure!(
            call.tool == T32mcpTool::CollectPracticeSkillResponse,
            "collect handoff names the wrong official t32mcp tool"
        );
        let arguments = serialize_empty_arguments(&call.arguments)?;
        let result = self
            .call_once(T32mcpTool::CollectPracticeSkillResponse, arguments)
            .await?;
        extract_text_result(result, T32mcpTool::CollectPracticeSkillResponse.as_str())
    }

    /// Calls the official abort tool and accepts only an empty success result.
    pub(crate) async fn abort(&self, call: &NoArgumentsToolCall) -> Result<()> {
        ensure!(
            call.tool == T32mcpTool::AbortPracticeSkill,
            "abort handoff names the wrong official t32mcp tool"
        );
        let arguments = serialize_empty_arguments(&call.arguments)?;
        let result = self
            .call_once(T32mcpTool::AbortPracticeSkill, arguments)
            .await?;
        extract_empty_result(result, T32mcpTool::AbortPracticeSkill.as_str())
    }

    /// Closes the MCP service and child process, then returns bounded stderr.
    pub(crate) async fn shutdown(self) -> Result<String> {
        self.finish(ChildShutdownMode::Graceful).await
    }

    /// Kills the exact t32mcp process tree and waits for its termination.
    pub(crate) async fn force_disconnect(self) -> Result<ForceDisconnectResult> {
        self.finish_force().await
    }

    async fn finish_force(mut self) -> Result<ForceDisconnectResult> {
        self.control.force();
        // This is the authoritative exact-child kill-and-wait boundary.  If
        // it fails, no fault marker may be written.
        force_shared_child(&self.child, &self.control).await?;
        let close_error = close_outcome_error(
            self.service.close_with_timeout(MCP_SHUTDOWN_TIMEOUT).await,
            "forced disconnect",
            true,
        )
        .or_else(|| child_close_outcome_error(&self.control, ChildShutdownMode::Force));
        let stderr = finish_stderr_task(self.stderr_task).await;
        let cleanup_diagnostic = match (close_error, stderr) {
            (None, Ok(_)) => None,
            (Some(error), Ok(_)) => Some(error.to_string()),
            (None, Err(error)) => {
                Some(format!("failed to finish t32mcp stderr cleanup: {error:#}"))
            }
            (Some(close_error), Err(stderr_error)) => Some(format!(
                "{close_error:#}; additionally failed to finish t32mcp stderr cleanup: {stderr_error:#}"
            )),
        };
        Ok(ForceDisconnectResult { cleanup_diagnostic })
    }

    async fn finish(mut self, mode: ChildShutdownMode) -> Result<String> {
        let force_error = if mode == ChildShutdownMode::Force {
            self.control.force();
            force_shared_child(&self.child, &self.control).await.err()
        } else {
            None
        };
        let close_error = close_outcome_error(
            self.service.close_with_timeout(MCP_SHUTDOWN_TIMEOUT).await,
            if mode == ChildShutdownMode::Force {
                "forced disconnect"
            } else {
                "shutdown"
            },
            mode == ChildShutdownMode::Force,
        )
        .or(force_error)
        .or_else(|| child_close_outcome_error(&self.control, mode));
        let stderr = finish_stderr_task(self.stderr_task).await;
        match (close_error, stderr) {
            (None, Ok(stderr)) => Ok(stderr),
            (Some(error), Ok(_)) => Err(error),
            (None, Err(error)) => Err(error),
            (Some(close_error), Err(stderr_error)) => Err(close_error.context(format!(
                "additionally failed to finish t32mcp stderr cleanup: {stderr_error:#}"
            ))),
        }
    }

    async fn call_once(&self, tool: T32mcpTool, arguments: JsonObject) -> Result<CallToolResult> {
        let tool_name = tool.as_str();
        let response = match self
            .service
            .call_tool_once(
                CallToolRequestParams::new(tool_name.to_owned()).with_arguments(arguments),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => {
                return Err(transport_or_service_error(
                    &self.control,
                    anyhow::Error::new(error)
                        .context(format!("official t32mcp tool `{tool_name}` call failed")),
                ));
            }
        };
        match response {
            CallToolResponse::Complete(result) => Ok(result),
            CallToolResponse::InputRequired(_) => {
                bail!("official t32mcp tool `{tool_name}` requested unsupported interactive input")
            }
            CallToolResponse::Task(_) => {
                bail!("official t32mcp tool `{tool_name}` returned an unsupported task")
            }
            _ => bail!("official t32mcp tool `{tool_name}` returned an unsupported response"),
        }
    }
}

impl T32mcpTransport for StdioT32mcpClient {
    async fn execute(&self, call: &ExecutePracticeSkillCall) -> Result<String> {
        StdioT32mcpClient::execute(self, call).await
    }

    async fn collect(&self, call: &NoArgumentsToolCall) -> Result<String> {
        StdioT32mcpClient::collect(self, call).await
    }

    async fn abort(&self, call: &NoArgumentsToolCall) -> Result<()> {
        StdioT32mcpClient::abort(self, call).await
    }

    async fn shutdown(self) -> Result<String> {
        StdioT32mcpClient::shutdown(self).await
    }

    async fn force_disconnect(self) -> Result<ForceDisconnectResult> {
        StdioT32mcpClient::force_disconnect(self).await
    }
}

fn validate_expected_version(expected_version: &str) -> Result<()> {
    ensure!(
        !expected_version.is_empty(),
        "expected t32mcp version is empty"
    );
    ensure!(
        expected_version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+')),
        "expected t32mcp version contains unsupported characters"
    );
    let expected_stdout_bytes = b"t32mcp v".len() + expected_version.len();
    ensure!(
        u64::try_from(expected_stdout_bytes).unwrap_or(u64::MAX) <= MAX_VERSION_STDOUT_BYTES,
        "expected t32mcp version exceeds the version-output bound"
    );
    Ok(())
}

async fn verify_executable_version(
    executable: &Path,
    expected_version: &str,
    max_stderr_bytes: u64,
    absolute_deadline: Instant,
) -> Result<()> {
    ensure_startup_deadline(absolute_deadline, "--version process spawn")?;
    let mut command = managed_command(executable, |command| {
        command
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
    });
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to execute `{}` --version", executable.display()))?;
    let stdout = child
        .stdout()
        .take()
        .context("t32mcp --version did not expose piped stdout")?;
    let stderr = child
        .stderr()
        .take()
        .context("t32mcp --version did not expose piped stderr")?;
    let stdout_task = tokio::spawn(read_bounded(stdout, MAX_VERSION_STDOUT_BYTES));
    let stderr_task = tokio::spawn(read_bounded(stderr, max_stderr_bytes));
    let deadline = absolute_deadline.min(Instant::now() + VERSION_PROBE_TIMEOUT);

    let status = match timeout_at(deadline, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(error)) => {
            terminate_version_probe(&mut child, stdout_task, stderr_task).await;
            return Err(error).context("failed to wait for t32mcp --version");
        }
        Err(_) => {
            terminate_version_probe(&mut child, stdout_task, stderr_task).await;
            bail!("t32mcp --version exceeded {:?}", VERSION_PROBE_TIMEOUT);
        }
    };
    let (stdout, stderr) = finish_version_probe_readers(stdout_task, stderr_task, deadline).await?;

    ensure!(
        status.success(),
        "t32mcp --version exited unsuccessfully with status {status}"
    );
    ensure!(
        !stdout.truncated,
        "t32mcp --version stdout exceeded {MAX_VERSION_STDOUT_BYTES} bytes"
    );
    ensure!(
        stderr.observed_bytes == 0,
        "t32mcp --version wrote {} bytes to stderr",
        stderr.observed_bytes
    );
    validate_version_stdout(&stdout.bytes, expected_version)
}

fn ensure_startup_deadline(deadline: Instant, stage: &'static str) -> Result<()> {
    ensure!(
        Instant::now() < deadline,
        "t32mcp {stage} was not started because the absolute startup deadline elapsed"
    );
    Ok(())
}

fn validate_version_stdout(stdout: &[u8], expected_version: &str) -> Result<()> {
    let stdout = std::str::from_utf8(stdout).context("t32mcp --version stdout is not UTF-8")?;
    let stdout = stdout
        .strip_suffix("\r\n")
        .or_else(|| stdout.strip_suffix('\n'))
        .unwrap_or(stdout);
    ensure!(
        !stdout.contains(['\r', '\n']),
        "t32mcp --version stdout contains multiple lines"
    );
    ensure!(
        stdout == format!("t32mcp v{expected_version}"),
        "t32mcp --version stdout does not exactly match the expected version"
    );
    Ok(())
}

fn validate_initialized_server(service: &ClientService, expected_version: &str) -> Result<()> {
    let peer = service
        .peer_info()
        .context("t32mcp initialization did not retain server information")?;
    let implementation = peer
        .server_info
        .as_ref()
        .context("t32mcp initialization omitted serverInfo")?;
    ensure!(
        implementation.name == "t32mcp",
        "initialized MCP server name is not `t32mcp`"
    );
    ensure!(
        implementation.version == expected_version,
        "initialized t32mcp server version does not match the verified executable"
    );
    ensure!(
        peer.capabilities.tools.is_some(),
        "initialized t32mcp server did not advertise tools capability"
    );
    Ok(())
}

async fn list_all_tool_names(service: &ClientService) -> Result<Vec<String>> {
    let mut names = Vec::new();
    let mut cursor = None;
    let mut seen_cursors = BTreeSet::new();
    for _ in 0..MAX_TOOL_INVENTORY_PAGES {
        let result = service
            .list_tools(Some(PaginatedRequestParams::default().with_cursor(cursor)))
            .await
            .context("t32mcp tools/list failed")?;
        for tool in result.tools {
            ensure!(
                tool.name.len() <= MAX_TOOL_NAME_BYTES,
                "t32mcp tools/list returned an oversized tool name"
            );
            names.push(tool.name.into_owned());
        }
        ensure!(
            names.len() <= MAX_TOOL_INVENTORY_ENTRIES,
            "t32mcp tools/list exceeded {MAX_TOOL_INVENTORY_ENTRIES} entries"
        );
        cursor = result.next_cursor;
        let Some(next_cursor) = cursor.as_ref() else {
            return Ok(names);
        };
        ensure!(
            next_cursor.len() <= MAX_PAGINATION_CURSOR_BYTES,
            "t32mcp tools/list returned an oversized pagination cursor"
        );
        ensure!(
            seen_cursors.insert(next_cursor.clone()),
            "t32mcp tools/list repeated a pagination cursor"
        );
    }
    bail!("t32mcp tools/list exceeded {MAX_TOOL_INVENTORY_PAGES} pagination pages")
}

fn validate_tool_inventory<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let mut inventory = BTreeSet::new();
    for name in names {
        ensure!(
            inventory.insert(name),
            "t32mcp tools/list contains duplicate tool names"
        );
    }
    ensure!(
        !inventory.contains(HIDDEN_EXECUTE_PRACTICE_TOOL),
        "t32mcp exposed forbidden hidden tool `{HIDDEN_EXECUTE_PRACTICE_TOOL}`"
    );
    let required = [
        T32mcpTool::ExecutePracticeSkill.as_str(),
        T32mcpTool::CollectPracticeSkillResponse.as_str(),
        T32mcpTool::AbortPracticeSkill.as_str(),
    ];
    ensure!(
        inventory.len() == required.len(),
        "t32mcp tools/list exposed {} tools instead of exactly three official tools",
        inventory.len()
    );
    for required in required {
        ensure!(
            inventory.contains(required),
            "t32mcp tools/list omitted required official tool `{required}`"
        );
    }
    Ok(())
}

fn serialize_arguments(arguments: &impl Serialize) -> Result<JsonObject> {
    match serde_json::to_value(arguments).context("failed to serialize typed t32mcp arguments")? {
        serde_json::Value::Object(arguments) => Ok(arguments),
        _ => bail!("typed t32mcp arguments did not serialize as an object"),
    }
}

fn serialize_empty_arguments(arguments: &impl Serialize) -> Result<JsonObject> {
    let arguments = serialize_arguments(arguments)?;
    ensure!(
        arguments.is_empty(),
        "no-arguments t32mcp handoff serialized non-empty arguments"
    );
    Ok(arguments)
}

fn validate_common_result(result: &CallToolResult, tool_name: &str) -> Result<()> {
    ensure!(
        result
            .result_type
            .as_ref()
            .is_none_or(|result_type| result_type == &ResultType::COMPLETE),
        "official t32mcp tool `{tool_name}` returned a non-complete result type"
    );
    ensure!(
        result.is_error != Some(true),
        "official t32mcp tool `{tool_name}` returned an error result"
    );
    ensure!(
        result.structured_content.is_none(),
        "official t32mcp tool `{tool_name}` returned forbidden structured content"
    );
    Ok(())
}

fn extract_text_result(result: CallToolResult, tool_name: &str) -> Result<String> {
    validate_common_result(&result, tool_name)?;
    ensure!(
        result.content.len() == 1,
        "official t32mcp tool `{tool_name}` returned {} content blocks instead of exactly one",
        result.content.len()
    );
    let content = result
        .content
        .into_iter()
        .next()
        .context("validated t32mcp text result unexpectedly has no content")?;
    let ContentBlock::Text(text) = content else {
        bail!("official t32mcp tool `{tool_name}` returned non-text content");
    };
    ensure!(
        u64::try_from(text.text.len()).unwrap_or(u64::MAX) <= MAX_CONTROLLER_MCP_RESPONSE_BYTES,
        "official t32mcp tool `{tool_name}` text exceeded {MAX_CONTROLLER_MCP_RESPONSE_BYTES} bytes"
    );
    Ok(text.text)
}

fn extract_empty_result(result: CallToolResult, tool_name: &str) -> Result<()> {
    validate_common_result(&result, tool_name)?;
    match result.content.as_slice() {
        [] => Ok(()),
        [ContentBlock::Text(text)] if text.text.is_empty() => Ok(()),
        [ContentBlock::Text(text)] => bail!(
            "official t32mcp tool `{tool_name}` returned {} non-empty text bytes",
            text.text.len()
        ),
        [_] => bail!("official t32mcp tool `{tool_name}` returned non-text content"),
        content => bail!(
            "official t32mcp tool `{tool_name}` returned {} content blocks instead of at most one empty text block",
            content.len()
        ),
    }
}

#[derive(Debug)]
struct BoundedOutput {
    bytes: Vec<u8>,
    observed_bytes: u64,
    truncated: bool,
}

impl BoundedOutput {
    fn into_summary(self) -> String {
        let mut summary = String::from_utf8_lossy(&self.bytes).into_owned();
        if self.truncated {
            summary.push_str(&format!(
                "\n[stderr truncated after {} bytes; observed {} bytes]",
                self.bytes.len(),
                self.observed_bytes
            ));
        }
        summary
    }
}

async fn read_bounded<R>(mut reader: R, max_bytes: u64) -> std::io::Result<BoundedOutput>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    let mut observed_bytes = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        observed_bytes = observed_bytes.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        let stored = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let remaining = max_bytes.saturating_sub(stored);
        let take =
            usize::try_from(remaining.min(u64::try_from(read).unwrap_or(u64::MAX))).unwrap_or(read);
        bytes.extend_from_slice(&buffer[..take]);
    }
    Ok(BoundedOutput {
        bytes,
        observed_bytes,
        truncated: observed_bytes > max_bytes,
    })
}

fn bounded_task_result(
    result: std::result::Result<std::io::Result<BoundedOutput>, tokio::task::JoinError>,
    label: &str,
) -> Result<BoundedOutput> {
    result
        .with_context(|| format!("{label} reader task failed"))?
        .with_context(|| format!("failed to read {label}"))
}

async fn finish_version_probe_readers(
    mut stdout_task: StderrTask,
    mut stderr_task: StderrTask,
    deadline: Instant,
) -> Result<(BoundedOutput, BoundedOutput)> {
    let stdout = match timeout_at(deadline, &mut stdout_task).await {
        Ok(result) => match bounded_task_result(result, "t32mcp --version stdout") {
            Ok(output) => output,
            Err(error) => {
                abort_bounded_task(stderr_task).await;
                return Err(error);
            }
        },
        Err(_) => {
            abort_bounded_task(stdout_task).await;
            abort_bounded_task(stderr_task).await;
            bail!(
                "t32mcp --version output pipes did not close within {:?}",
                VERSION_PROBE_TIMEOUT
            );
        }
    };
    let stderr = match timeout_at(deadline, &mut stderr_task).await {
        Ok(result) => bounded_task_result(result, "t32mcp --version stderr")?,
        Err(_) => {
            abort_bounded_task(stderr_task).await;
            bail!(
                "t32mcp --version output pipes did not close within {:?}",
                VERSION_PROBE_TIMEOUT
            );
        }
    };
    Ok((stdout, stderr))
}

async fn terminate_version_probe(
    child: &mut Box<dyn ChildWrapper>,
    stdout_task: StderrTask,
    stderr_task: StderrTask,
) {
    let _ = timeout(STDERR_JOIN_TIMEOUT, force_child_exit(child)).await;
    abort_bounded_task(stdout_task).await;
    abort_bounded_task(stderr_task).await;
}

async fn abort_bounded_task(task: StderrTask) {
    task.abort();
    let _ = task.await;
}

async fn finish_stderr_task(mut task: StderrTask) -> Result<String> {
    let output = match timeout(STDERR_JOIN_TIMEOUT, &mut task).await {
        Ok(output) => output
            .context("t32mcp stderr reader task failed")?
            .context("failed to read t32mcp stderr")?,
        Err(_) => {
            task.abort();
            let _ = task.await;
            bail!(
                "t32mcp stderr did not close within {:?}",
                STDERR_JOIN_TIMEOUT
            );
        }
    };
    Ok(output.into_summary())
}

async fn cleanup_failed_initialization(
    stderr_task: StderrTask,
    child: &SharedChild,
    control: &TransportControl,
    error: anyhow::Error,
) -> anyhow::Error {
    let child_error = cleanup_startup_child(child, control).await.err();
    let stderr_error = finish_stderr_task(stderr_task).await.err();
    match (child_error, stderr_error) {
        (None, None) => error,
        (Some(child_error), None) => error.context(format!(
            "additionally failed to terminate t32mcp startup child: {child_error:#}"
        )),
        (None, Some(stderr_error)) => error.context(format!(
            "additionally failed to finish t32mcp stderr cleanup: {stderr_error:#}"
        )),
        (Some(child_error), Some(stderr_error)) => error.context(format!(
            "additionally failed to terminate t32mcp startup child ({child_error:#}) and finish stderr cleanup ({stderr_error:#})"
        )),
    }
}

async fn cleanup_startup_child(child: &SharedChild, control: &TransportControl) -> Result<()> {
    let mut child = child.lock().await;
    let outcome = match child.as_mut() {
        Some(child) => close_child(child, ChildShutdownMode::Force, false).await,
        None => ChildCloseOutcome::Failed,
    };
    control.record_close_outcome(outcome);
    ensure!(
        matches!(
            outcome,
            ChildCloseOutcome::Forced | ChildCloseOutcome::AlreadyExitedBeforeForce { .. }
        ),
        "failed to kill and wait for the t32mcp startup child"
    );
    Ok(())
}

async fn cleanup_started_service(
    mut service: ClientService,
    stderr_task: StderrTask,
    control: &TransportControl,
    error: anyhow::Error,
) -> anyhow::Error {
    let close_error = close_outcome_error(
        service.close_with_timeout(MCP_SHUTDOWN_TIMEOUT).await,
        "cleanup",
        false,
    )
    .or_else(|| child_close_outcome_error(control, ChildShutdownMode::Graceful));
    let stderr_error = finish_stderr_task(stderr_task).await.err();
    match (close_error, stderr_error) {
        (None, None) => error,
        (Some(close_error), None) => error.context(format!(
            "additionally failed to close t32mcp: {close_error:#}"
        )),
        (None, Some(stderr_error)) => error.context(format!(
            "additionally failed to finish t32mcp stderr cleanup: {stderr_error:#}"
        )),
        (Some(close_error), Some(stderr_error)) => error.context(format!(
            "additionally failed to close t32mcp ({close_error:#}) and finish stderr cleanup ({stderr_error:#})"
        )),
    }
}

fn transport_or_service_error(
    control: &TransportControl,
    service_error: anyhow::Error,
) -> anyhow::Error {
    control
        .failure()
        .map_or(service_error, |failure| anyhow::anyhow!(failure.message()))
}

fn child_close_outcome_error(
    control: &TransportControl,
    mode: ChildShutdownMode,
) -> Option<anyhow::Error> {
    if let Some(failure) = control.failure() {
        return Some(anyhow::anyhow!(failure.message()));
    }
    match (mode, control.close_outcome()) {
        (
            ChildShutdownMode::Graceful,
            Some(ChildCloseOutcome::Graceful {
                success: true,
                code: _,
            }),
        )
        | (ChildShutdownMode::Force, Some(ChildCloseOutcome::Forced)) => None,
        (
            ChildShutdownMode::Graceful,
            Some(ChildCloseOutcome::Graceful {
                success: false,
                code,
            }),
        ) => Some(anyhow::anyhow!(
            "t32mcp child exited unsuccessfully during graceful shutdown with code {code:?}"
        )),
        (ChildShutdownMode::Graceful, Some(ChildCloseOutcome::ForcedAfterGracefulTimeout)) => Some(
            anyhow::anyhow!("t32mcp child required forced termination during graceful shutdown"),
        ),
        (
            ChildShutdownMode::Force,
            Some(ChildCloseOutcome::AlreadyExitedBeforeForce { success, code }),
        ) => Some(anyhow::anyhow!(
            "t32mcp child exited before forced disconnect (success={success}, code={code:?})"
        )),
        (_, Some(ChildCloseOutcome::ProtocolFailureKilled)) => Some(anyhow::anyhow!(
            "t32mcp child was killed after an MCP transport failure"
        )),
        (_, Some(ChildCloseOutcome::Failed)) | (_, None) => Some(anyhow::anyhow!(
            "exact t32mcp child termination was not durably observed"
        )),
        (ChildShutdownMode::Graceful, Some(ChildCloseOutcome::Forced))
        | (ChildShutdownMode::Graceful, Some(ChildCloseOutcome::AlreadyExitedBeforeForce { .. }))
        | (ChildShutdownMode::Force, Some(ChildCloseOutcome::Graceful { .. }))
        | (ChildShutdownMode::Force, Some(ChildCloseOutcome::ForcedAfterGracefulTimeout)) => Some(
            anyhow::anyhow!("t32mcp child termination mode did not match the requested lifecycle"),
        ),
    }
}

fn close_outcome_error(
    outcome: Result<Option<QuitReason>, tokio::task::JoinError>,
    phase: &str,
    allow_closed: bool,
) -> Option<anyhow::Error> {
    match outcome {
        Ok(Some(QuitReason::Cancelled)) => None,
        Ok(Some(QuitReason::Closed)) if allow_closed => None,
        Ok(Some(QuitReason::Closed)) => Some(anyhow::anyhow!(
            "t32mcp MCP service closed unexpectedly before local {phase}"
        )),
        Ok(Some(QuitReason::JoinError(error))) => Some(anyhow::anyhow!(
            "t32mcp MCP service {phase} reported a task failure: {error}"
        )),
        Ok(Some(_)) => Some(anyhow::anyhow!(
            "t32mcp MCP service {phase} returned an unsupported quit reason"
        )),
        Ok(None) => Some(anyhow::anyhow!(
            "t32mcp MCP service {phase} exceeded {:?}",
            MCP_SHUTDOWN_TIMEOUT
        )),
        Err(error) => Some(anyhow::Error::new(error).context(format!(
            "failed to join the t32mcp MCP service during {phase}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        process::ExitStatus,
        sync::{Arc, Mutex},
    };

    use process_wrap::tokio::ChildWrapper;
    use rmcp::model::ContentBlock;
    use serde_json::json;

    use super::*;

    const REQUIRED_TOOLS: [&str; 3] = [
        "execute_practice_skill",
        "collect_practice_skill_response",
        "abort_practice_skill",
    ];

    #[derive(Debug, Default)]
    struct FakeChildState {
        killed: bool,
        waited: bool,
        exited: bool,
    }

    #[derive(Debug)]
    struct FakeChild {
        state: Arc<Mutex<FakeChildState>>,
    }

    impl ChildWrapper for FakeChild {
        fn inner(&self) -> &dyn ChildWrapper {
            self
        }

        fn inner_mut(&mut self) -> &mut dyn ChildWrapper {
            self
        }

        fn into_inner(self: Box<Self>) -> Box<dyn ChildWrapper> {
            self
        }

        fn start_kill(&mut self) -> io::Result<()> {
            let mut state = self.state.lock().expect("fake child lock");
            state.killed = true;
            state.exited = true;
            Ok(())
        }

        fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
            let state = self.state.lock().expect("fake child lock");
            Ok(state.exited.then(success_exit_status))
        }

        fn wait(&mut self) -> Pin<Box<dyn Future<Output = io::Result<ExitStatus>> + Send + '_>> {
            let state = self.state.clone();
            Box::pin(async move {
                let mut state = state.lock().expect("fake child lock");
                state.waited = true;
                state.exited = true;
                Ok(success_exit_status())
            })
        }
    }

    #[cfg(unix)]
    fn success_exit_status() -> ExitStatus {
        use std::os::unix::process::ExitStatusExt as _;

        ExitStatus::from_raw(0)
    }

    #[cfg(windows)]
    fn success_exit_status() -> ExitStatus {
        use std::os::windows::process::ExitStatusExt as _;

        ExitStatus::from_raw(0)
    }

    fn test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime")
    }

    #[test]
    fn version_stdout_accepts_exact_line_with_conventional_line_endings() {
        validate_version_stdout(b"t32mcp v0.2.2", "0.2.2").expect("no newline");
        validate_version_stdout(b"t32mcp v0.2.2\n", "0.2.2").expect("LF");
        validate_version_stdout(b"t32mcp v0.2.2\r\n", "0.2.2").expect("CRLF");
    }

    #[test]
    fn version_stdout_rejects_whitespace_extra_lines_and_wrong_versions() {
        for stdout in [
            b" t32mcp v0.2.2".as_slice(),
            b"t32mcp v0.2.2 \n".as_slice(),
            b"t32mcp v0.2.2\nextra\n".as_slice(),
            b"t32mcp v0.2.3\n".as_slice(),
        ] {
            assert!(validate_version_stdout(stdout, "0.2.2").is_err());
        }
    }

    #[test]
    fn tool_inventory_requires_each_official_tool_once() {
        validate_tool_inventory(REQUIRED_TOOLS).expect("official inventory");

        assert!(validate_tool_inventory(REQUIRED_TOOLS[..2].iter().copied()).is_err());
        assert!(
            validate_tool_inventory(REQUIRED_TOOLS.into_iter().chain([REQUIRED_TOOLS[0]])).is_err()
        );
        assert!(validate_tool_inventory(REQUIRED_TOOLS.into_iter().chain(["get_status"])).is_err());
    }

    #[test]
    fn tool_inventory_rejects_visible_hidden_execute_practice() {
        assert!(
            validate_tool_inventory(
                REQUIRED_TOOLS
                    .into_iter()
                    .chain([HIDDEN_EXECUTE_PRACTICE_TOOL])
            )
            .is_err()
        );
    }

    #[test]
    fn text_result_requires_one_bounded_unstructured_text_block() {
        let result = CallToolResult::success(vec![ContentBlock::text("ok")]);
        assert_eq!(
            result.is_error,
            Some(false),
            "rmcp's official success wrapper explicitly emits isError=false"
        );
        assert_eq!(
            extract_text_result(result, "execute_practice_skill").expect("text result"),
            "ok"
        );

        let mut result = CallToolResult::success(vec![ContentBlock::text("ok")]);
        result.is_error = Some(true);
        assert!(extract_text_result(result, "execute_practice_skill").is_err());

        let mut result = CallToolResult::success(vec![ContentBlock::text("ok")]);
        result.structured_content = Some(json!({"unexpected": true}));
        assert!(extract_text_result(result, "execute_practice_skill").is_err());

        let result = CallToolResult::success(vec![ContentBlock::image("AA==", "image/png")]);
        assert!(extract_text_result(result, "execute_practice_skill").is_err());

        let result = CallToolResult::success(vec![
            ContentBlock::text("first"),
            ContentBlock::text("second"),
        ]);
        assert!(extract_text_result(result, "execute_practice_skill").is_err());
    }

    #[test]
    fn text_result_rejects_oversized_text() {
        let text = "x"
            .repeat(usize::try_from(MAX_CONTROLLER_MCP_RESPONSE_BYTES).expect("small bound") + 1);
        let result = CallToolResult::success(vec![ContentBlock::text(text)]);
        assert!(extract_text_result(result, "collect_practice_skill_response").is_err());
    }

    #[test]
    fn abort_result_accepts_only_no_content_or_one_empty_text_block() {
        extract_empty_result(CallToolResult::success(Vec::new()), "abort_practice_skill")
            .expect("no content");
        extract_empty_result(
            CallToolResult::success(vec![ContentBlock::text("")]),
            "abort_practice_skill",
        )
        .expect("empty text");

        assert!(
            extract_empty_result(
                CallToolResult::success(vec![ContentBlock::text("unexpected")]),
                "abort_practice_skill"
            )
            .is_err()
        );
        assert!(
            extract_empty_result(
                CallToolResult::success(vec![ContentBlock::image("AA==", "image/png")]),
                "abort_practice_skill"
            )
            .is_err()
        );
    }

    #[test]
    fn raw_frame_reader_rejects_oversized_and_truncated_lines_before_json_decode() {
        test_runtime().block_on(async {
            let oversized = vec![b'x'; MAX_MCP_JSON_LINE_BYTES + 1];
            let mut oversized = BufReader::new(oversized.as_slice());
            assert!(matches!(
                read_bounded_frame(&mut oversized).await,
                Err(FrameReadError::TooLarge)
            ));

            let mut truncated = BufReader::new(b"{\"jsonrpc\":\"2.0\"}".as_slice());
            assert!(matches!(
                read_bounded_frame(&mut truncated).await,
                Err(FrameReadError::Truncated)
            ));
        });
    }

    #[test]
    fn version_pipe_join_uses_the_original_probe_deadline() {
        test_runtime().block_on(async {
            let (_stdout_writer, stdout_reader) = tokio::io::duplex(32);
            let (_stderr_writer, stderr_reader) = tokio::io::duplex(32);
            let stdout_task = tokio::spawn(read_bounded(stdout_reader, 16));
            let stderr_task = tokio::spawn(read_bounded(stderr_reader, 16));
            let started = Instant::now();
            let result = finish_version_probe_readers(
                stdout_task,
                stderr_task,
                Instant::now() + Duration::from_millis(20),
            )
            .await;
            assert!(result.is_err());
            assert!(started.elapsed() < Duration::from_secs(1));
        });
    }

    #[test]
    fn expired_before_version_rejects_without_starting_a_child() {
        test_runtime().block_on(async {
            let started = Instant::now();
            let error = verify_executable_version(
                Path::new("this-path-must-not-be-executed"),
                "0.2.2",
                16,
                Instant::now() - Duration::from_millis(1),
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains("--version process spawn"));
            assert!(started.elapsed() < Duration::from_secs(1));
        });
    }

    #[test]
    fn expired_after_version_before_mcp_rejects_without_starting_a_child() {
        let result = spawn_mcp_transport(
            Path::new("this-path-must-not-be-executed"),
            Path::new("."),
            20_000,
            Instant::now() - Duration::from_millis(1),
        );
        assert!(result.is_err());
        let error = result.err().expect("expired spawn is rejected");
        assert!(error.to_string().contains("MCP process spawn"));
    }

    #[test]
    fn closed_service_and_mismatched_child_lifecycles_are_rejected() {
        assert!(close_outcome_error(Ok(Some(QuitReason::Closed)), "shutdown", false).is_some());
        let control = TransportControl::new();
        control.record_close_outcome(ChildCloseOutcome::Forced);
        assert!(child_close_outcome_error(&control, ChildShutdownMode::Graceful).is_some());
        assert!(child_close_outcome_error(&control, ChildShutdownMode::Force).is_none());
    }

    #[test]
    fn force_close_kills_and_waits_the_exact_child() {
        test_runtime().block_on(async {
            let state = Arc::new(Mutex::new(FakeChildState::default()));
            let (_stdout_writer, stdout_reader) = tokio::io::duplex(32);
            let (stdin_writer, _stdin_reader) = tokio::io::duplex(32);
            let control = TransportControl::new();
            control.force();
            let mut transport = BoundedChildTransport {
                child: Arc::new(AsyncMutex::new(Some(Box::new(FakeChild {
                    state: state.clone(),
                })
                    as Box<dyn ChildWrapper>))),
                read: BufReader::new(stdout_reader),
                write: Arc::new(AsyncMutex::new(Some(stdin_writer))),
                control: control.clone(),
            };

            Transport::<RoleClient>::close(&mut transport)
                .await
                .expect("force close");
            let state = state.lock().expect("fake child lock");
            assert!(state.killed);
            assert!(state.waited);
            assert_eq!(control.close_outcome(), Some(ChildCloseOutcome::Forced));
        });
    }

    #[test]
    fn oversized_raw_mcp_frame_kills_the_child_before_deserialization() {
        test_runtime().block_on(async {
            use tokio::io::AsyncWriteExt as _;

            let state = Arc::new(Mutex::new(FakeChildState::default()));
            let (mut server_stdout, client_stdout) = tokio::io::duplex(16 * 1024);
            let (client_stdin, _server_stdin) = tokio::io::duplex(32);
            let control = TransportControl::new();
            let mut transport = BoundedChildTransport {
                child: Arc::new(AsyncMutex::new(Some(Box::new(FakeChild {
                    state: state.clone(),
                })
                    as Box<dyn ChildWrapper>))),
                read: BufReader::new(client_stdout),
                write: Arc::new(AsyncMutex::new(Some(client_stdin))),
                control: control.clone(),
            };
            let writer = tokio::spawn(async move {
                let oversized = vec![b'x'; MAX_MCP_JSON_LINE_BYTES + 1];
                let _ = server_stdout.write_all(&oversized).await;
            });

            assert!(
                Transport::<RoleClient>::receive(&mut transport)
                    .await
                    .is_none()
            );
            writer.abort();
            let _ = writer.await;
            assert_eq!(
                control.failure(),
                Some(TransportFailure::StdoutFrameTooLarge)
            );
            Transport::<RoleClient>::close(&mut transport)
                .await
                .expect("protocol-failure cleanup");
            assert!(state.lock().expect("fake child lock").killed);
            assert_eq!(
                control.close_outcome(),
                Some(ChildCloseOutcome::ProtocolFailureKilled)
            );
        });
    }

    #[test]
    fn bounded_transport_initializes_and_lists_tools_with_a_fake_stdio_server() {
        test_runtime().block_on(async {
            use tokio::io::AsyncBufReadExt as _;

            let state = Arc::new(Mutex::new(FakeChildState::default()));
            let (mut server_stdout, client_stdout) = tokio::io::duplex(16 * 1024);
            let (client_stdin, server_stdin) = tokio::io::duplex(16 * 1024);
            let control = TransportControl::new();
            let transport = BoundedChildTransport {
                child: Arc::new(AsyncMutex::new(Some(Box::new(FakeChild {
                    state: state.clone(),
                })
                    as Box<dyn ChildWrapper>))),
                read: BufReader::new(client_stdout),
                write: Arc::new(AsyncMutex::new(Some(client_stdin))),
                control: control.clone(),
            };
            let server_task = tokio::spawn(async move {
                let mut server_stdin = BufReader::new(server_stdin);
                let initialize = read_fake_request(&mut server_stdin).await;
                let initialize_id = initialize["id"].clone();
                let protocol_version = initialize["params"]["protocolVersion"].clone();
                write_fake_response(
                    &mut server_stdout,
                    json!({
                        "jsonrpc": "2.0",
                        "id": initialize_id,
                        "result": {
                            "protocolVersion": protocol_version,
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "t32mcp", "version": "0.2.2"}
                        }
                    }),
                )
                .await;

                let initialized = read_fake_request(&mut server_stdin).await;
                assert_eq!(initialized["method"], "notifications/initialized");
                let list = read_fake_request(&mut server_stdin).await;
                let list_id = list["id"].clone();
                let tools = REQUIRED_TOOLS
                    .into_iter()
                    .map(|name| {
                        json!({
                            "name": name,
                            "inputSchema": {"type": "object", "properties": {}}
                        })
                    })
                    .collect::<Vec<_>>();
                write_fake_response(
                    &mut server_stdout,
                    json!({
                        "jsonrpc": "2.0",
                        "id": list_id,
                        "result": {"tools": tools}
                    }),
                )
                .await;

                let mut remainder = String::new();
                while server_stdin
                    .read_line(&mut remainder)
                    .await
                    .expect("read until client close")
                    != 0
                {
                    remainder.clear();
                }
            });

            let mut service = ().serve(transport).await.expect("initialize fake server");
            validate_initialized_server(&service, "0.2.2").expect("server identity");
            let names = list_all_tool_names(&service).await.expect("list tools");
            validate_tool_inventory(names.iter().map(String::as_str)).expect("tool inventory");
            let reason = service
                .close_with_timeout(Duration::from_secs(1))
                .await
                .expect("join service")
                .expect("bounded close");
            assert!(matches!(reason, QuitReason::Cancelled));
            assert!(child_close_outcome_error(&control, ChildShutdownMode::Graceful).is_none());
            server_task.await.expect("fake server");
            let state = state.lock().expect("fake child lock");
            assert!(!state.killed);
            assert!(state.waited);
        });
    }

    async fn read_fake_request<R>(reader: &mut R) -> serde_json::Value
    where
        R: AsyncBufRead + Unpin,
    {
        use tokio::io::AsyncBufReadExt as _;

        let mut line = String::new();
        reader.read_line(&mut line).await.expect("read request");
        serde_json::from_str(&line).expect("request JSON")
    }

    async fn write_fake_response<W>(writer: &mut W, response: serde_json::Value)
    where
        W: AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt as _;

        let mut bytes = serde_json::to_vec(&response).expect("response JSON");
        bytes.push(b'\n');
        writer.write_all(&bytes).await.expect("write response");
        writer.flush().await.expect("flush response");
    }

    #[test]
    fn bounded_reader_drains_but_stores_only_the_requested_prefix() {
        test_runtime().block_on(async {
            let (mut writer, reader) = tokio::io::duplex(32);
            let writer_task = tokio::spawn(async move {
                use tokio::io::AsyncWriteExt as _;

                writer.write_all(b"abcdefgh").await.expect("write");
            });
            let output = read_bounded(reader, 3).await.expect("read");
            writer_task.await.expect("writer");

            assert_eq!(output.bytes, b"abc");
            assert_eq!(output.observed_bytes, 8);
            assert!(output.truncated);
        });
    }
}
