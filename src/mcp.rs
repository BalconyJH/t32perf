//! Bounded MCP adapter for the public T32Perf host facade.

use std::{
    future::Future,
    io,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use rmcp::{
    Json, RoleServer, ServerHandler, ServiceExt as _,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ErrorData, Implementation, ServerCapabilities, ServerInfo},
    service::{RequestContext, RxJsonRpcMessage, TxJsonRpcMessage},
    tool, tool_handler, tool_router,
    transport::Transport,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
use t32perf_model::{
    Artifact, PerfArtifactReference, PerfCapturePhase, PerfComparePayload, PerfControlPayload,
    PerfControlStatus, PerfConvertPayload, PerfGetStatusPayload, PerfGetSummaryPayload,
    PerfListArtifactsPayload, PerfNextAction, PerfRunPayload, PerfSurfaceEnvelope,
    PerfSurfaceOperation, PerfSurfaceResponse, PerfSurfaceSchemaVersion, PerfTrustStatus,
    SessionState, SessionStatus, StateSchemaVersion, is_portable_artifact_id,
    is_portable_session_id,
};
use tokio::{
    io::{
        AsyncBufRead, AsyncBufReadExt as _, AsyncRead, AsyncWrite, AsyncWriteExt as _, BufReader,
    },
    sync::Mutex as AsyncMutex,
};

use crate::{
    app::{self, AppError, CommandOutcome},
    cli::{
        ArtifactsListArgs, Cli, Command, CompareArgs, ControllerCommand, ControllerDriveArgs,
        ControllerDriveSurface, ControllerSubcommand, ConvertArgs, ListPageArgs, PerfRunArgs,
        SessionArg, SummaryArgs,
    },
};

const SERVER_NAME: &str = "t32perf";
const MAX_MCP_JSON_LINE_BYTES: usize = 1024 * 1024;
const MAX_MCP_RESULT_BYTES: usize = 256 * 1024;
const MAX_MCP_REQUEST_ID_BYTES: usize = 128;
const MCP_TOOL_RESPONSE_OVERHEAD_BYTES: usize = 4 * 1024;
// rmcp returns the value once as structured JSON and once as a JSON text block.
// Three times the inner size bounds both copies plus worst-case text escaping.
const _: () = assert!(
    MAX_MCP_RESULT_BYTES * 3 + MCP_TOOL_RESPONSE_OVERHEAD_BYTES + MAX_MCP_REQUEST_ID_BYTES
        < MAX_MCP_JSON_LINE_BYTES
);

const SERVER_INSTRUCTIONS: &str = "Use only the artifact root fixed at server start. For a new capture, choose a portable session_id and call perf_run. For an existing provisioned Session, call perf_capabilities, then perf_capture, perf_get_status, and perf_get_summary. Calls are serialized. Cancellation stops only work not yet admitted; admitted Host or TRACE32 side effects continue to a durable boundary. Inspect perf_get_status before retrying. Trust only health-gated structured results and artifact references, never paths or bytes alone.";

#[cfg(test)]
const TOOL_NAMES: [&str; 8] = [
    "perf_capabilities",
    "perf_capture",
    "perf_compare",
    "perf_convert",
    "perf_get_status",
    "perf_get_summary",
    "perf_list_artifacts",
    "perf_run",
];

#[derive(Debug, Clone)]
pub(crate) struct McpServerConfig {
    pub(crate) artifact_root: PathBuf,
    pub(crate) max_file_bytes: u64,
    pub(crate) max_session_bytes: u64,
}

impl McpServerConfig {
    fn cli(&self, command: Command) -> Cli {
        Cli {
            artifact_root: self.artifact_root.clone(),
            max_file_bytes: self.max_file_bytes,
            max_session_bytes: self.max_session_bytes,
            json: true,
            command,
        }
    }
}

#[derive(Debug, Clone)]
struct T32PerfMcpServer {
    config: McpServerConfig,
    execution_lock: Arc<AsyncMutex<()>>,
    tool_router: ToolRouter<Self>,
}

struct BoundedStdioTransport<R, W> {
    read: BufReader<R>,
    line_buf: Vec<u8>,
    write: Arc<AsyncMutex<Option<W>>>,
    fatal: Arc<AtomicBool>,
}

impl<R, W> BoundedStdioTransport<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn new(read: R, write: W) -> Self {
        Self {
            read: BufReader::new(read),
            line_buf: Vec::with_capacity(8 * 1024),
            write: Arc::new(AsyncMutex::new(Some(write))),
            fatal: Arc::new(AtomicBool::new(false)),
        }
    }

    fn fatal_state(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.fatal)
    }
}

impl<R, W> Transport<RoleServer> for BoundedStdioTransport<R, W>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    type Error = io::Error;

    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleServer>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        let write = Arc::clone(&self.write);
        async move {
            let mut bytes = serde_json::to_vec(&item)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            if bytes.len() > MAX_MCP_JSON_LINE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "outbound MCP frame exceeds the fixed bound",
                ));
            }
            bytes.push(b'\n');
            let mut writer = write.lock().await;
            let writer = writer
                .as_mut()
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "MCP stdout is closed"))?;
            writer.write_all(&bytes).await?;
            writer.flush().await
        }
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        loop {
            let frame = match read_bounded_frame(&mut self.read, &mut self.line_buf).await {
                Ok(Some(frame)) => frame,
                Ok(None) => return None,
                Err(error) => {
                    tracing::warn!(error = %error, "mcp_input_rejected");
                    self.fatal.store(true, Ordering::Release);
                    return None;
                }
            };
            if frame.is_empty() {
                continue;
            }
            let json = frame
                .strip_prefix(b"\xEF\xBB\xBF")
                .unwrap_or(frame.as_slice());
            if request_id_exceeds_bound(json) {
                tracing::warn!("mcp_input_rejected: request id exceeds fixed bound");
                self.fatal.store(true, Ordering::Release);
                return None;
            }
            match serde_json::from_slice(json) {
                Ok(message) => return Some(message),
                Err(error) => match error.classify() {
                    serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {
                        tracing::debug!(error = %error, "mcp_input_unparseable");
                    }
                    serde_json::error::Category::Data | serde_json::error::Category::Io => {
                        tracing::debug!(error = %error, "mcp_input_invalid_request");
                        if let Some(id) = request_id_from_well_formed_json(json) {
                            let response = TxJsonRpcMessage::<RoleServer>::error(
                                ErrorData::invalid_request("Invalid request", None),
                                Some(id),
                            );
                            if Self::write_raw(Arc::clone(&self.write), response)
                                .await
                                .is_err()
                            {
                                return None;
                            }
                        }
                    }
                },
            }
        }
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        self.write.lock().await.take();
        Ok(())
    }
}

impl<R, W> BoundedStdioTransport<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    async fn write_raw(
        write: Arc<AsyncMutex<Option<W>>>,
        item: TxJsonRpcMessage<RoleServer>,
    ) -> io::Result<()> {
        let mut bytes = serde_json::to_vec(&item)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if bytes.len() > MAX_MCP_JSON_LINE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "outbound MCP frame exceeds the fixed bound",
            ));
        }
        bytes.push(b'\n');
        let mut writer = write.lock().await;
        let writer = writer
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "MCP stdout is closed"))?;
        writer.write_all(&bytes).await?;
        writer.flush().await
    }
}

fn request_id_from_well_formed_json(json: &[u8]) -> Option<rmcp::model::RequestId> {
    let value: Value = serde_json::from_slice(json).ok()?;
    serde_json::from_value(value.get("id")?.clone()).ok()
}

fn request_id_exceeds_bound(json: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<Value>(json) else {
        return false;
    };
    let Some(id) = value.get("id") else {
        return false;
    };
    let Ok(id) = serde_json::from_value::<rmcp::model::RequestId>(id.clone()) else {
        return true;
    };
    serde_json::to_vec(&id).map_or(true, |encoded| encoded.len() > MAX_MCP_REQUEST_ID_BYTES)
}

async fn read_bounded_frame<R>(
    reader: &mut R,
    line_buf: &mut Vec<u8>,
) -> io::Result<Option<Vec<u8>>>
where
    R: AsyncBufRead + Unpin,
{
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if line_buf.is_empty() {
                Ok(None)
            } else {
                line_buf.clear();
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "MCP input closed with a truncated frame",
                ))
            };
        }
        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            let payload = &available[..newline];
            if line_buf.len().saturating_add(payload.len()) > MAX_MCP_JSON_LINE_BYTES {
                line_buf.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "inbound MCP frame exceeds the fixed bound",
                ));
            }
            line_buf.extend_from_slice(payload);
            reader.consume(newline + 1);
            if line_buf.last() == Some(&b'\r') {
                line_buf.pop();
            }
            return Ok(Some(std::mem::take(line_buf)));
        }
        if line_buf.len().saturating_add(available.len()) > MAX_MCP_JSON_LINE_BYTES {
            line_buf.clear();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "inbound MCP frame exceeds the fixed bound",
            ));
        }
        let consumed = available.len();
        line_buf.extend_from_slice(available);
        reader.consume(consumed);
    }
}

impl T32PerfMcpServer {
    fn new(config: McpServerConfig) -> Self {
        Self {
            config,
            execution_lock: Arc::new(AsyncMutex::new(())),
            tool_router: Self::tool_router(),
        }
    }

    async fn execute_action<C, F, Success>(
        &self,
        cancellation: C,
        action: F,
    ) -> Result<Json<McpToolResult<Success>>, Json<McpToolResult<Success>>>
    where
        C: Future<Output = ()> + Send,
        F: FnOnce(McpServerConfig) -> Result<Success, AppError> + Send + 'static,
        Success: Serialize + Send + 'static,
    {
        let config = self.config.clone();
        let execution_guard = tokio::select! {
            biased;
            _ = cancellation => return Err(Json(McpToolResult::Error(McpToolError::cancelled()))),
            guard = Arc::clone(&self.execution_lock).lock_owned() => guard,
        };
        match tokio::task::spawn_blocking(move || {
            let _guard = execution_guard;
            let result = match action(config) {
                Ok(success) => McpToolResult::Success(success),
                Err(error) => McpToolResult::Error(McpToolError::from(error)),
            };
            let encoded = serde_json::to_vec(&result).map_err(|error| {
                McpToolError::internal(
                    format!("failed to encode the typed MCP result: {error}"),
                    false,
                )
            })?;
            if encoded.len() > MAX_MCP_RESULT_BYTES {
                return Ok(McpToolResult::Error(McpToolError::result_too_large()));
            }
            Ok(result)
        })
        .await
        {
            Ok(Ok(result)) => match result {
                McpToolResult::Success(_) => Ok(Json(result)),
                McpToolResult::Error(_) => Err(Json(result)),
            },
            Ok(Err(error)) => Err(Json(McpToolResult::Error(error))),
            Err(error) => Err(Json(McpToolResult::Error(McpToolError::internal(
                format!("the MCP host worker failed: {error}"),
                false,
            )))),
        }
    }
}

#[tool_router]
impl T32PerfMcpServer {
    #[tool(
        name = "perf_capabilities",
        description = "Drive capability discovery for an existing provisioned T32Perf Session through the deployment-owned t32mcp child.",
        annotations(
            title = "Check TRACE32 performance capabilities",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn perf_capabilities(
        &self,
        Parameters(input): Parameters<SessionInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<McpToolResult<CapabilitiesEnvelope>>, Json<McpToolResult<CapabilitiesEnvelope>>>
    {
        validate_session_id(&input.session_id)
            .map_err(|error| Json(McpToolResult::Error(error)))?;
        self.execute_action(context.ct.cancelled_owned(), move |config| {
            execute_driven_surface(
                config,
                input.session_id,
                ControllerDriveSurface::Capabilities,
                None,
            )
            .and_then(project_capabilities)
        })
        .await
    }

    #[tool(
        name = "perf_capture",
        description = "Drive the normal TRACE32 capture chain for an existing provisioned Session, including the deployment-owned workload and cleanup.",
        annotations(
            title = "Capture TRACE32 performance data",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn perf_capture(
        &self,
        Parameters(input): Parameters<CaptureInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<McpToolResult<CaptureEnvelope>>, Json<McpToolResult<CaptureEnvelope>>> {
        validate_session_id(&input.session_id)
            .map_err(|error| Json(McpToolResult::Error(error)))?;
        self.execute_action(context.ct.cancelled_owned(), move |config| {
            execute_driven_surface(
                config,
                input.session_id,
                ControllerDriveSurface::Capture,
                Some(input.mode.as_str()),
            )
            .and_then(project_capture)
        })
        .await
    }

    #[tool(
        name = "perf_get_status",
        description = "Read one T32Perf Session's durable lifecycle, manifest, artifact count, and trust status.",
        annotations(
            title = "Get T32Perf Session status",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn perf_get_status(
        &self,
        Parameters(input): Parameters<SessionInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<McpToolResult<StatusEnvelope>>, Json<McpToolResult<StatusEnvelope>>> {
        validate_session_id(&input.session_id)
            .map_err(|error| Json(McpToolResult::Error(error)))?;
        self.execute_action(context.ct.cancelled_owned(), move |config| {
            execute_surface(
                config,
                Command::PerfGetStatus(SessionArg {
                    session: input.session_id,
                }),
                PerfSurfaceOperation::GetStatus,
            )
            .and_then(project_status)
        })
        .await
    }

    #[tool(
        name = "perf_get_summary",
        description = "Read a bounded, health-gated T32Perf summary; quantitative rows are present only when the Session is VALID.",
        annotations(
            title = "Get a health-gated performance summary",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn perf_get_summary(
        &self,
        Parameters(input): Parameters<SummaryInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<McpToolResult<SummaryEnvelope>>, Json<McpToolResult<SummaryEnvelope>>> {
        validate_session_id(&input.session_id)
            .map_err(|error| Json(McpToolResult::Error(error)))?;
        validate_top(input.top).map_err(|error| Json(McpToolResult::Error(error)))?;
        self.execute_action(context.ct.cancelled_owned(), move |config| {
            execute_surface(
                config,
                Command::PerfGetSummary(SummaryArgs {
                    session: input.session_id,
                    top: input.top,
                }),
                PerfSurfaceOperation::GetSummary,
            )
            .and_then(project_summary)
        })
        .await
    }

    #[tool(
        name = "perf_list_artifacts",
        description = "List a bounded page of immutable artifact metadata and provenance references without returning artifact contents.",
        annotations(
            title = "List T32Perf artifacts",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn perf_list_artifacts(
        &self,
        Parameters(input): Parameters<ListArtifactsInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<
        Json<McpToolResult<ListArtifactsEnvelope>>,
        Json<McpToolResult<ListArtifactsEnvelope>>,
    > {
        validate_session_id(&input.session_id)
            .map_err(|error| Json(McpToolResult::Error(error)))?;
        validate_list_limit(input.limit).map_err(|error| Json(McpToolResult::Error(error)))?;
        if let Some(after) = &input.after {
            validate_artifact_id(after).map_err(|error| Json(McpToolResult::Error(error)))?;
        }
        self.execute_action(context.ct.cancelled_owned(), move |config| {
            execute_surface(
                config,
                Command::PerfListArtifacts(ArtifactsListArgs {
                    session: input.session_id,
                    page: ListPageArgs {
                        limit: input.limit,
                        after: input.after,
                    },
                }),
                PerfSurfaceOperation::ListArtifacts,
            )
            .and_then(project_list_artifacts)
        })
        .await
    }

    #[tool(
        name = "perf_convert",
        description = "Create the supported immutable report for a processed T32Perf Session and return only its artifact reference.",
        annotations(
            title = "Convert a T32Perf report",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn perf_convert(
        &self,
        Parameters(input): Parameters<ConvertInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<McpToolResult<ConvertEnvelope>>, Json<McpToolResult<ConvertEnvelope>>> {
        validate_session_id(&input.session_id)
            .map_err(|error| Json(McpToolResult::Error(error)))?;
        self.execute_action(context.ct.cancelled_owned(), move |config| {
            execute_surface(
                config,
                Command::PerfConvert(ConvertArgs {
                    session: input.session_id,
                    format: input.format.as_str().to_owned(),
                }),
                PerfSurfaceOperation::Convert,
            )
            .and_then(project_convert)
        })
        .await
    }

    #[tool(
        name = "perf_compare",
        description = "Compare two completed T32Perf Sessions under a closed built-in policy and return a bounded verdict plus report reference.",
        annotations(
            title = "Compare T32Perf Sessions",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn perf_compare(
        &self,
        Parameters(input): Parameters<CompareInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<McpToolResult<CompareEnvelope>>, Json<McpToolResult<CompareEnvelope>>> {
        validate_session_id(&input.baseline_session_id)
            .map_err(|error| Json(McpToolResult::Error(error)))?;
        validate_session_id(&input.candidate_session_id)
            .map_err(|error| Json(McpToolResult::Error(error)))?;
        validate_top(input.top).map_err(|error| Json(McpToolResult::Error(error)))?;
        self.execute_action(context.ct.cancelled_owned(), move |config| {
            execute_surface(
                config,
                Command::PerfCompare(CompareArgs {
                    baseline: input.baseline_session_id,
                    candidate: input.candidate_session_id,
                    policy: input.policy.as_str().to_owned(),
                    allow_inconclusive: input.allow_inconclusive,
                    top: input.top,
                }),
                PerfSurfaceOperation::Compare,
            )
            .and_then(project_compare)
        })
        .await
    }

    #[tool(
        name = "perf_run",
        description = "Run the closed provision-to-report TRACE32 workflow for a new or resumable T32Perf Session using deployment-owned configuration.",
        annotations(
            title = "Run a complete TRACE32 performance session",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn perf_run(
        &self,
        Parameters(input): Parameters<RunInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<McpToolResult<RunEnvelope>>, Json<McpToolResult<RunEnvelope>>> {
        validate_duration(input.duration_ms).map_err(|error| Json(McpToolResult::Error(error)))?;
        validate_top(usize::from(input.top)).map_err(|error| Json(McpToolResult::Error(error)))?;
        validate_session_id(&input.session_id)
            .map_err(|error| Json(McpToolResult::Error(error)))?;
        self.execute_action(context.ct.cancelled_owned(), move |config| {
            execute_surface(
                config,
                Command::PerfRun(PerfRunArgs {
                    duration_ms: input.duration_ms,
                    id: Some(input.session_id),
                    top: input.top,
                }),
                PerfSurfaceOperation::Run,
            )
            .and_then(project_run)
        })
        .await
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for T32PerfMcpServer {
    fn get_info(&self) -> ServerInfo {
        let mut implementation = Implementation::new(SERVER_NAME, env!("CARGO_PKG_VERSION"));
        implementation.title = Some("T32Perf Host".to_owned());
        implementation.description =
            Some("Bounded, health-gated TRACE32 performance Session orchestration".to_owned());
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(implementation)
            .with_instructions(SERVER_INSTRUCTIONS)
    }
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct SessionInput {
    /// Existing T32Perf Session identifier.
    #[schemars(length(min = 1, max = 64))]
    session_id: String,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct CaptureInput {
    /// Existing, deployment-provisioned T32Perf Session identifier.
    #[schemars(length(min = 1, max = 64))]
    session_id: String,
    /// Export mode admitted by the selected target adapter.
    mode: CaptureMode,
}

#[derive(Debug, Clone, Copy, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum CaptureMode {
    RawAscii,
}

impl CaptureMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RawAscii => "raw_ascii",
        }
    }
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct SummaryInput {
    /// Completed or analyzed T32Perf Session identifier.
    #[schemars(length(min = 1, max = 64))]
    session_id: String,
    /// Maximum rows returned per supported metric family.
    #[serde(default = "default_top")]
    #[schemars(range(min = 1, max = 100))]
    top: usize,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ListArtifactsInput {
    /// T32Perf Session identifier.
    #[schemars(length(min = 1, max = 64))]
    session_id: String,
    /// Maximum artifact references in this page.
    #[serde(default = "default_artifact_limit")]
    #[schemars(range(min = 1, max = 100))]
    limit: usize,
    /// Exclusive artifact ID cursor returned by the previous page.
    #[serde(default)]
    after: Option<String>,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ConvertInput {
    /// Processed T32Perf Session identifier.
    #[schemars(length(min = 1, max = 64))]
    session_id: String,
    /// Supported report format.
    format: ReportFormat,
}

#[derive(Debug, Clone, Copy, Deserialize, rmcp::schemars::JsonSchema)]
enum ReportFormat {
    #[serde(rename = "perfetto-json")]
    PerfettoJson,
}

impl ReportFormat {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PerfettoJson => "perfetto-json",
        }
    }
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct CompareInput {
    /// Completed baseline Session.
    #[schemars(length(min = 1, max = 64))]
    baseline_session_id: String,
    /// Completed candidate Session.
    #[schemars(length(min = 1, max = 64))]
    candidate_session_id: String,
    /// Closed built-in comparison policy.
    #[serde(default)]
    policy: ComparisonPolicy,
    /// Accept an inconclusive verdict as a successful host exit status.
    #[serde(default)]
    allow_inconclusive: bool,
    /// Maximum rows retained in each bounded comparison projection.
    #[serde(default = "default_comparison_top")]
    #[schemars(range(min = 1, max = 100))]
    top: usize,
}

#[derive(Debug, Default, Clone, Copy, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum ComparisonPolicy {
    #[default]
    Default,
    Strict,
    Relaxed,
}

impl ComparisonPolicy {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Strict => "strict",
            Self::Relaxed => "relaxed",
        }
    }
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct RunInput {
    /// Requested target workload duration in milliseconds.
    #[schemars(range(min = 1, max = 1_800_000))]
    duration_ms: u64,
    /// Deterministic Session identifier required for safe resume after a lost response.
    #[schemars(length(min = 1, max = 64))]
    session_id: String,
    /// Maximum hotspot rows returned in the bounded summary.
    #[serde(default = "default_top_u8")]
    #[schemars(range(min = 1, max = 100))]
    top: u8,
}

#[derive(Debug, Clone, Serialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct McpToolError {
    code: String,
    message: String,
    details: McpEmptyDetails,
    exit_code: u8,
    retryable: bool,
}

impl McpToolError {
    fn invalid_argument(message: &'static str) -> Self {
        Self {
            code: "INVALID_ARGUMENT".to_owned(),
            message: message.to_owned(),
            details: McpEmptyDetails {},
            exit_code: 2,
            retryable: false,
        }
    }

    fn cancelled() -> Self {
        Self {
            code: "CANCELLED".to_owned(),
            message: "the request was cancelled before host work was admitted".to_owned(),
            details: McpEmptyDetails {},
            exit_code: 1,
            retryable: true,
        }
    }

    fn result_too_large() -> Self {
        Self {
            code: "MCP_RESULT_TOO_LARGE".to_owned(),
            message: "the bounded host result exceeds the MCP response limit; request a smaller top or artifact page".to_owned(),
            details: McpEmptyDetails {},
            exit_code: 1,
            retryable: true,
        }
    }

    fn internal(message: impl Into<String>, retryable: bool) -> Self {
        Self {
            code: "MCP_SERVER_INTERNAL".to_owned(),
            message: message.into(),
            details: McpEmptyDetails {},
            exit_code: 1,
            retryable,
        }
    }
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[serde(untagged)]
enum McpToolResult<Success> {
    Success(Success),
    Error(McpToolError),
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct McpSurfaceEnvelope<Operation, Payload> {
    schema: PerfSurfaceSchemaVersion,
    operation: Operation,
    payload: Payload,
}

macro_rules! operation_marker {
    ($name:ident, $variant:ident, $wire:literal) => {
        #[derive(Debug, Clone, Copy, Serialize, rmcp::schemars::JsonSchema)]
        enum $name {
            #[serde(rename = $wire)]
            $variant,
        }
    };
}

operation_marker!(CapabilitiesOperation, Capabilities, "perf_capabilities");
operation_marker!(CaptureOperation, Capture, "perf_capture");
operation_marker!(NextCaptureOperation, Capture, "perf_capture");
operation_marker!(
    CapabilitiesCompleteStatus,
    CapabilitiesComplete,
    "capabilities_complete"
);
operation_marker!(ControlCompleteStatus, ControlComplete, "control_complete");
operation_marker!(CaptureCompletePhase, CaptureComplete, "capture_complete");
operation_marker!(StatusOperation, GetStatus, "perf_get_status");
operation_marker!(SummaryOperation, GetSummary, "perf_get_summary");
operation_marker!(ListArtifactsOperation, ListArtifacts, "perf_list_artifacts");
operation_marker!(ConvertOperation, Convert, "perf_convert");
operation_marker!(CompareOperation, Compare, "perf_compare");
operation_marker!(RunOperation, Run, "perf_run");

type CapabilitiesEnvelope = McpSurfaceEnvelope<CapabilitiesOperation, McpCapabilitiesPayload>;
type CaptureEnvelope = McpSurfaceEnvelope<CaptureOperation, McpCapturePayload>;
type StatusEnvelope = McpSurfaceEnvelope<StatusOperation, McpGetStatusPayload>;
type SummaryEnvelope = McpSurfaceEnvelope<SummaryOperation, Box<PerfGetSummaryPayload>>;
type ListArtifactsEnvelope = McpSurfaceEnvelope<ListArtifactsOperation, PerfListArtifactsPayload>;
type ConvertEnvelope = McpSurfaceEnvelope<ConvertOperation, PerfConvertPayload>;
type CompareEnvelope = McpSurfaceEnvelope<CompareOperation, PerfComparePayload>;
type RunEnvelope = McpSurfaceEnvelope<RunOperation, PerfRunPayload>;

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct McpCapabilitiesPayload {
    session_id: String,
    state: SessionStatus,
    capture_phase: PerfCapturePhase,
    status: CapabilitiesCompleteStatus,
    #[schemars(length(max = 8))]
    completed_operations: Vec<t32perf_model::PerfControllerOperation>,
    #[schemars(length(max = 8))]
    capture_artifacts: Vec<Artifact>,
    next_action: McpCapabilitiesNextAction,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum McpCapabilitiesNextAction {
    Invoke { operation: NextCaptureOperation },
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct McpCapturePayload {
    session_id: String,
    state: SessionStatus,
    capture_phase: CaptureCompletePhase,
    status: ControlCompleteStatus,
    #[schemars(length(max = 8))]
    completed_operations: Vec<t32perf_model::PerfControllerOperation>,
    #[schemars(length(max = 8))]
    capture_artifacts: Vec<Artifact>,
    next_action: McpCaptureNextAction,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum McpCaptureNextAction {
    CaptureConfigReady {
        capture_config: PerfArtifactReference,
    },
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct McpGetStatusPayload {
    session_id: String,
    state: McpSessionState,
    manifest_committed: bool,
    artifact_count: u64,
    trust_status: PerfTrustStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    health_verdict: Option<t32perf_model::HealthVerdict>,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct McpSessionState {
    schema: StateSchemaVersion,
    created_at: String,
    #[serde(rename = "state")]
    status: SessionStatus,
    operation_id: String,
    revision: u64,
    updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<McpSessionError>,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct McpSessionError {
    code: String,
    message: &'static str,
    details: McpEmptyDetails,
}

#[derive(Debug, Clone, Copy, Default, Serialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct McpEmptyDetails {}

fn invalid_argument(message: &'static str) -> Result<(), McpToolError> {
    Err(McpToolError::invalid_argument(message))
}

fn validate_session_id(value: &str) -> Result<(), McpToolError> {
    if is_portable_session_id(value) {
        Ok(())
    } else {
        invalid_argument("session_id must be a portable Session identifier")
    }
}

fn validate_artifact_id(value: &str) -> Result<(), McpToolError> {
    if is_portable_artifact_id(value) {
        Ok(())
    } else {
        invalid_argument("after must be a portable artifact identifier")
    }
}

fn validate_top(value: usize) -> Result<(), McpToolError> {
    if (1..=100).contains(&value) {
        Ok(())
    } else {
        invalid_argument("top must be between 1 and 100")
    }
}

fn validate_list_limit(value: usize) -> Result<(), McpToolError> {
    if (1..=100).contains(&value) {
        Ok(())
    } else {
        invalid_argument("limit must be between 1 and 100")
    }
}

fn validate_duration(value: u64) -> Result<(), McpToolError> {
    if (1..=1_800_000).contains(&value) {
        Ok(())
    } else {
        invalid_argument("duration_ms must be between 1 and 1800000")
    }
}

impl From<AppError> for McpToolError {
    fn from(error: AppError) -> Self {
        let retryable = error.is_nonterminal_retryable();
        tracing::warn!(
            code = error.code,
            exit_code = error.exit_code,
            retryable,
            "mcp_host_action_failed"
        );
        Self {
            code: error.code.to_owned(),
            message: if retryable {
                "the host operation did not complete; inspect durable Session state before retrying"
                    .to_owned()
            } else {
                "the host operation was rejected; inspect durable Session state for safe follow-up"
                    .to_owned()
            },
            details: McpEmptyDetails {},
            exit_code: error.exit_code,
            retryable,
        }
    }
}

const fn default_top() -> usize {
    10
}

const fn default_top_u8() -> u8 {
    10
}

const fn default_comparison_top() -> usize {
    20
}

const fn default_artifact_limit() -> usize {
    50
}

fn project_capabilities(envelope: PerfSurfaceEnvelope) -> Result<CapabilitiesEnvelope, AppError> {
    let PerfSurfaceEnvelope { schema, response } = envelope;
    let PerfSurfaceResponse::Capabilities(control) = response else {
        return Err(AppError::operational(
            "controller drive did not return the required capabilities terminal state",
        ));
    };
    if control.status != PerfControlStatus::CapabilitiesComplete
        || control.completed_operations.len() > 8
        || control.capture_artifacts.len() > 8
        || !matches!(
            control.next_action,
            PerfNextAction::Invoke {
                operation: PerfSurfaceOperation::Capture,
                ..
            }
        )
    {
        return Err(AppError::operational(
            "controller drive did not return the required capabilities terminal state",
        ));
    }
    Ok(McpSurfaceEnvelope {
        schema,
        operation: CapabilitiesOperation::Capabilities,
        payload: McpCapabilitiesPayload {
            session_id: control.session_id,
            state: control.state,
            capture_phase: control.capture_phase,
            status: CapabilitiesCompleteStatus::CapabilitiesComplete,
            completed_operations: control.completed_operations,
            capture_artifacts: control.capture_artifacts,
            next_action: McpCapabilitiesNextAction::Invoke {
                operation: NextCaptureOperation::Capture,
            },
        },
    })
}

fn project_capture(envelope: PerfSurfaceEnvelope) -> Result<CaptureEnvelope, AppError> {
    let PerfSurfaceEnvelope { schema, response } = envelope;
    let PerfSurfaceResponse::Capture(control) = response else {
        return Err(AppError::operational(
            "controller drive did not return the required capture terminal state",
        ));
    };
    let PerfNextAction::CaptureConfigReady { capture_config } = control.next_action else {
        return Err(AppError::operational(
            "controller drive did not return the required capture terminal state",
        ));
    };
    if control.status != PerfControlStatus::ControlComplete
        || control.capture_phase != PerfCapturePhase::CaptureComplete
        || control.completed_operations.len() > 8
        || control.capture_artifacts.len() > 8
    {
        return Err(AppError::operational(
            "controller drive did not return the required capture terminal state",
        ));
    }
    Ok(McpSurfaceEnvelope {
        schema,
        operation: CaptureOperation::Capture,
        payload: McpCapturePayload {
            session_id: control.session_id,
            state: control.state,
            capture_phase: CaptureCompletePhase::CaptureComplete,
            status: ControlCompleteStatus::ControlComplete,
            completed_operations: control.completed_operations,
            capture_artifacts: control.capture_artifacts,
            next_action: McpCaptureNextAction::CaptureConfigReady { capture_config },
        },
    })
}

fn project_status(envelope: PerfSurfaceEnvelope) -> Result<StatusEnvelope, AppError> {
    let PerfSurfaceEnvelope { schema, response } = envelope;
    let PerfSurfaceResponse::GetStatus(payload) = response else {
        return Err(AppError::operational(
            "host operation did not return the required status response",
        ));
    };
    Ok(McpSurfaceEnvelope {
        schema,
        operation: StatusOperation::GetStatus,
        payload: project_status_payload(payload),
    })
}

fn project_status_payload(payload: PerfGetStatusPayload) -> McpGetStatusPayload {
    McpGetStatusPayload {
        session_id: payload.session_id,
        state: project_session_state(payload.state),
        manifest_committed: payload.manifest_committed,
        artifact_count: payload.artifact_count,
        trust_status: payload.trust_status,
        health_verdict: payload.health_verdict,
    }
}

fn project_session_state(state: SessionState) -> McpSessionState {
    McpSessionState {
        schema: state.schema,
        created_at: state.created_at,
        status: state.status,
        operation_id: state.operation_id,
        revision: state.revision,
        updated_at: state.updated_at,
        error: state.error.map(|error| McpSessionError {
            code: error.code,
            message: "session failed; inspect restricted local diagnostics",
            details: McpEmptyDetails {},
        }),
    }
}

macro_rules! project_simple_surface {
    ($name:ident, $operation:ident, $marker:ident, $variant:ident, $payload:ty, $error:literal) => {
        fn $name(
            envelope: PerfSurfaceEnvelope,
        ) -> Result<McpSurfaceEnvelope<$marker, $payload>, AppError> {
            let PerfSurfaceEnvelope { schema, response } = envelope;
            let PerfSurfaceResponse::$variant(payload) = response else {
                return Err(AppError::operational($error));
            };
            Ok(McpSurfaceEnvelope {
                schema,
                operation: $marker::$operation,
                payload,
            })
        }
    };
}

project_simple_surface!(
    project_summary,
    GetSummary,
    SummaryOperation,
    GetSummary,
    Box<PerfGetSummaryPayload>,
    "host operation did not return the required summary response"
);
project_simple_surface!(
    project_list_artifacts,
    ListArtifacts,
    ListArtifactsOperation,
    ListArtifacts,
    PerfListArtifactsPayload,
    "host operation did not return the required artifact-list response"
);
project_simple_surface!(
    project_convert,
    Convert,
    ConvertOperation,
    Convert,
    PerfConvertPayload,
    "host operation did not return the required conversion response"
);
project_simple_surface!(
    project_compare,
    Compare,
    CompareOperation,
    Compare,
    PerfComparePayload,
    "host operation did not return the required comparison response"
);
project_simple_surface!(
    project_run,
    Run,
    RunOperation,
    Run,
    PerfRunPayload,
    "host operation did not return the required run response"
);

fn execute_surface(
    config: McpServerConfig,
    command: Command,
    expected_operation: PerfSurfaceOperation,
) -> Result<PerfSurfaceEnvelope, AppError> {
    let outcome = app::execute(config.cli(command))?;
    decode_surface_outcome(outcome, expected_operation)
}

fn execute_driven_surface(
    config: McpServerConfig,
    session_id: String,
    surface: ControllerDriveSurface,
    mode: Option<&str>,
) -> Result<PerfSurfaceEnvelope, AppError> {
    let expected_operation = match surface {
        ControllerDriveSurface::Capabilities => PerfSurfaceOperation::Capabilities,
        ControllerDriveSurface::Capture => PerfSurfaceOperation::Capture,
    };
    let outcome = app::execute(config.cli(Command::Controller(ControllerCommand {
        command: ControllerSubcommand::Drive(ControllerDriveArgs {
            session: session_id,
            surface,
            mode: mode.map(str::to_owned),
        }),
    })))?;
    let control = outcome.result.get("control").cloned().ok_or_else(|| {
        AppError::operational("controller drive omitted its typed control result")
    })?;
    let control = serde_json::from_value::<PerfControlPayload>(control).map_err(|error| {
        AppError::operational(format!(
            "controller drive result violates the typed performance surface: {error}"
        ))
    })?;
    let response = match surface {
        ControllerDriveSurface::Capabilities => PerfSurfaceResponse::Capabilities(control),
        ControllerDriveSurface::Capture => PerfSurfaceResponse::Capture(control),
    };
    let envelope = PerfSurfaceEnvelope::new(response);
    if envelope.operation() != expected_operation {
        return Err(AppError::operational(
            "controller drive returned the wrong performance operation",
        ));
    }
    Ok(envelope)
}

fn decode_surface_outcome(
    outcome: CommandOutcome,
    expected_operation: PerfSurfaceOperation,
) -> Result<PerfSurfaceEnvelope, AppError> {
    let envelope =
        serde_json::from_value::<PerfSurfaceEnvelope>(outcome.result).map_err(|error| {
            AppError::operational(format!(
                "{} result violates the typed performance surface: {error}",
                expected_operation.as_str()
            ))
        })?;
    if envelope.operation() != expected_operation {
        return Err(AppError::operational(format!(
            "{} returned a mismatched performance operation",
            expected_operation.as_str()
        )));
    }
    Ok(envelope)
}

pub(crate) fn serve_stdio(config: McpServerConfig) -> Result<(), AppError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(AppError::operational)?
        .block_on(async move {
            let transport = BoundedStdioTransport::new(tokio::io::stdin(), tokio::io::stdout());
            let fatal_transport = transport.fatal_state();
            let service = T32PerfMcpServer::new(config)
                .serve(transport)
                .await
                .map_err(|error| {
                    AppError::operational(format!("failed to initialize MCP stdio: {error}"))
                })?;
            match service.waiting().await.map_err(AppError::operational)? {
                rmcp::service::QuitReason::Cancelled | rmcp::service::QuitReason::Closed
                    if fatal_transport.load(Ordering::Acquire) =>
                {
                    Err(AppError::operational(
                        "MCP stdio rejected an unsafe input frame",
                    ))
                }
                rmcp::service::QuitReason::Cancelled | rmcp::service::QuitReason::Closed => Ok(()),
                rmcp::service::QuitReason::JoinError(error) => Err(AppError::operational(format!(
                    "MCP stdio service task failed: {error}"
                ))),
                _ => Err(AppError::operational(
                    "MCP stdio service stopped for an unsupported reason",
                )),
            }
        })
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::cli::{CaptureArgs, DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_SESSION_BYTES};

    fn config(root: &TempDir) -> McpServerConfig {
        McpServerConfig {
            artifact_root: root.path().to_path_buf(),
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_session_bytes: DEFAULT_MAX_SESSION_BYTES,
        }
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
    }

    #[test]
    fn inventory_is_exact_typed_and_annotated() {
        let root = TempDir::new().unwrap();
        let server = T32PerfMcpServer::new(config(&root));
        let tools = server.tool_router.list_all();
        assert_eq!(
            tools
                .iter()
                .map(|tool| tool.name.as_ref())
                .collect::<Vec<_>>(),
            TOOL_NAMES
        );
        for tool in &tools {
            assert!(tool.output_schema.is_some(), "{} output schema", tool.name);
            let output_schema =
                serde_json::to_string(tool.output_schema.as_ref().unwrap()).unwrap();
            assert!(
                output_schema.contains("operation"),
                "{} success schema",
                tool.name
            );
            assert!(output_schema.contains("code"), "{} error schema", tool.name);
            assert!(
                output_schema.contains("message"),
                "{} error schema",
                tool.name
            );
            let expected_operation = tool.name.as_ref();
            assert!(
                output_schema.contains(expected_operation),
                "{} output schema must include only its success operation marker",
                tool.name
            );
            for operation in TOOL_NAMES {
                let allowed_nested_capability_action =
                    expected_operation == "perf_capabilities" && operation == "perf_capture";
                if operation != expected_operation && !allowed_nested_capability_action {
                    assert!(
                        !output_schema.contains(operation),
                        "{} output schema must not include {operation}",
                        tool.name
                    );
                }
            }
            for internal in [
                "execute_practice_skill",
                "collect_practice_skill_response",
                "run_workload",
                "response_handoff",
                "prepared",
                "pending",
            ] {
                assert!(
                    !output_schema.contains(internal),
                    "{} output schema must not expose {internal}",
                    tool.name
                );
            }
            assert_eq!(
                tool.input_schema.get("additionalProperties"),
                Some(&Value::Bool(false)),
                "{} must reject unknown input fields",
                tool.name
            );
            let annotations = tool
                .annotations
                .as_ref()
                .unwrap_or_else(|| panic!("{} annotations", tool.name));
            let read_only = matches!(
                tool.name.as_ref(),
                "perf_get_status" | "perf_get_summary" | "perf_list_artifacts"
            );
            let target_side_effect = matches!(
                tool.name.as_ref(),
                "perf_capabilities" | "perf_capture" | "perf_run"
            );
            let destructive = matches!(tool.name.as_ref(), "perf_capture" | "perf_run");
            assert_eq!(annotations.read_only_hint, Some(read_only), "{}", tool.name);
            assert_eq!(
                annotations.idempotent_hint,
                Some(read_only),
                "{}",
                tool.name
            );
            assert_eq!(
                annotations.open_world_hint,
                Some(target_side_effect),
                "{}",
                tool.name
            );
            assert_eq!(
                annotations.destructive_hint,
                Some(destructive),
                "{}",
                tool.name
            );
        }
        assert!(serde_json::to_vec(&tools).unwrap().len() < MAX_MCP_JSON_LINE_BYTES);
    }

    #[test]
    fn initialization_identifies_the_server_and_frontloads_safety_guidance() {
        let root = TempDir::new().unwrap();
        let info = T32PerfMcpServer::new(config(&root)).get_info();
        assert_eq!(info.server_info.name, SERVER_NAME);
        assert_eq!(info.server_info.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(info.instructions.as_deref(), Some(SERVER_INSTRUCTIONS));
        assert!(SERVER_INSTRUCTIONS.len() <= 512);
        assert!(SERVER_INSTRUCTIONS.contains("Cancellation stops only work not yet admitted"));
    }

    #[test]
    fn status_returns_structured_surface_and_host_errors_remain_tool_errors() {
        let root = TempDir::new().unwrap();
        app::execute(config(&root).cli(Command::Capture(CaptureArgs {
            provider: "synthetic".to_owned(),
            id: Some("mcp-status".to_owned()),
            events: 8,
        })))
        .expect("synthetic fixture");
        let server = T32PerfMcpServer::new(config(&root));
        runtime().block_on(async {
            let result = server
                .execute_action(std::future::pending(), move |config| {
                    execute_surface(
                        config,
                        Command::PerfGetStatus(SessionArg {
                            session: "mcp-status".to_owned(),
                        }),
                        PerfSurfaceOperation::GetStatus,
                    )
                    .and_then(project_status)
                })
                .await;
            let envelope = match result {
                Ok(Json(McpToolResult::Success(envelope))) => envelope,
                Err(_) => panic!("status should succeed"),
                Ok(Json(McpToolResult::Error(_))) => panic!("status must return a surface"),
            };
            assert!(matches!(envelope.operation, StatusOperation::GetStatus));

            let result = server
                .execute_action(std::future::pending(), move |config| {
                    execute_surface(
                        config,
                        Command::PerfGetStatus(SessionArg {
                            session: "missing".to_owned(),
                        }),
                        PerfSurfaceOperation::GetStatus,
                    )
                    .and_then(project_status)
                })
                .await;
            let error = match result {
                Err(Json(McpToolResult::Error(error))) => error,
                Ok(_) => panic!("missing Session should fail"),
                Err(Json(McpToolResult::Success(_))) => {
                    panic!("missing Session should return an error")
                }
            };
            assert_eq!(error.code, "OPERATIONAL_ERROR");
            assert!(!error.retryable);
        });
    }

    #[test]
    fn raw_stdio_frames_are_bounded_and_require_a_delimiter() {
        runtime().block_on(async {
            let exact = vec![b'x'; MAX_MCP_JSON_LINE_BYTES];
            let mut exact_line = exact.clone();
            exact_line.push(b'\n');
            let mut exact_reader = BufReader::new(exact_line.as_slice());
            let mut line_buf = Vec::new();
            assert_eq!(
                read_bounded_frame(&mut exact_reader, &mut line_buf)
                    .await
                    .expect("exact limit")
                    .expect("frame")
                    .len(),
                MAX_MCP_JSON_LINE_BYTES
            );

            let mut oversized = vec![b'x'; MAX_MCP_JSON_LINE_BYTES + 1];
            oversized.push(b'\n');
            let mut oversized_reader = BufReader::new(oversized.as_slice());
            let mut line_buf = Vec::new();
            assert_eq!(
                read_bounded_frame(&mut oversized_reader, &mut line_buf)
                    .await
                    .expect_err("oversized frame")
                    .kind(),
                io::ErrorKind::InvalidData
            );

            let mut truncated_reader = BufReader::new(b"{}".as_slice());
            let mut line_buf = Vec::new();
            assert_eq!(
                read_bounded_frame(&mut truncated_reader, &mut line_buf)
                    .await
                    .expect_err("truncated frame")
                    .kind(),
                io::ErrorKind::UnexpectedEof
            );
        });
    }

    #[test]
    fn malformed_frames_do_not_end_the_transport_and_invalid_requests_get_a_response() {
        runtime().block_on(async {
            let (mut input_writer, input_reader) = tokio::io::duplex(1024);
            let (output_writer, output_reader) = tokio::io::duplex(1024);
            let mut transport = BoundedStdioTransport::new(input_reader, output_writer);
            tokio::spawn(async move {
                input_writer.write_all(b"{not-json}\n").await.unwrap();
                input_writer
                    .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":3}\n")
                    .await
                    .unwrap();
                input_writer
                    .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"ping\"}\n")
                    .await
                    .unwrap();
            });
            assert!(
                transport.receive().await.is_some(),
                "valid frame must continue after rejection"
            );
            let mut output = BufReader::new(output_reader);
            let mut response = String::new();
            output.read_line(&mut response).await.unwrap();
            let response: Value = serde_json::from_str(&response).unwrap();
            assert_eq!(response.pointer("/error/code"), Some(&json!(-32600)));
            assert_eq!(response.get("id"), Some(&json!(7)));
        });
    }

    #[test]
    fn request_ids_have_a_fixed_pre_dispatch_bound() {
        runtime().block_on(async {
            let (mut valid_writer, valid_reader) = tokio::io::duplex(1024);
            let (valid_output, _) = tokio::io::duplex(1024);
            let mut valid = BoundedStdioTransport::new(valid_reader, valid_output);
            let max_id = "a".repeat(MAX_MCP_REQUEST_ID_BYTES - 2);
            valid_writer
                .write_all(
                    format!("{{\"jsonrpc\":\"2.0\",\"id\":\"{max_id}\",\"method\":\"ping\"}}\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
            assert!(valid.receive().await.is_some());
            assert!(!valid.fatal.load(Ordering::Acquire));

            let (mut oversized_writer, oversized_reader) = tokio::io::duplex(1024);
            let (oversized_output, _) = tokio::io::duplex(1024);
            let mut oversized = BoundedStdioTransport::new(oversized_reader, oversized_output);
            let oversized_id = "a".repeat(MAX_MCP_REQUEST_ID_BYTES - 1);
            oversized_writer
                .write_all(
                    format!(
                        "{{\"jsonrpc\":\"2.0\",\"id\":\"{oversized_id}\",\"method\":\"ping\"}}\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            assert!(oversized.receive().await.is_none());
            assert!(oversized.fatal.load(Ordering::Acquire));

            let (mut numeric_writer, numeric_reader) = tokio::io::duplex(1024);
            let (numeric_output, _) = tokio::io::duplex(1024);
            let mut numeric = BoundedStdioTransport::new(numeric_reader, numeric_output);
            let oversized_numeric_id = "9".repeat(MAX_MCP_REQUEST_ID_BYTES + 1);
            numeric_writer
                .write_all(
                    format!(
                        "{{\"jsonrpc\":\"2.0\",\"id\":{oversized_numeric_id},\"method\":\"ping\"}}\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            assert!(numeric.receive().await.is_none());
            assert!(numeric.fatal.load(Ordering::Acquire));
        });
    }

    #[test]
    fn runtime_input_boundaries_return_small_non_echoing_errors() {
        let invalid_session = "x".repeat(65);
        let invalid_artifact = "../artifact";
        for result in [
            validate_session_id(&invalid_session),
            validate_artifact_id(invalid_artifact),
            validate_top(0),
            validate_top(101),
            validate_list_limit(0),
            validate_list_limit(101),
            validate_duration(0),
            validate_duration(1_800_001),
        ] {
            let error = result.expect_err("invalid input");
            assert_eq!(error.code, "INVALID_ARGUMENT");
            assert!(!error.message.contains(&invalid_session));
            assert!(serde_json::to_vec(&error).unwrap().len() <= MAX_MCP_RESULT_BYTES);
        }
    }

    #[test]
    fn host_errors_do_not_echo_sensitive_diagnostics() {
        let error = McpToolError::from(AppError {
            code: "OPERATIONAL_ERROR",
            message: "hook failed at C:\\secret\\policy.toml with token=top-secret".to_owned(),
            details: json!({"path": "C:\\secret\\policy.toml", "token": "top-secret"}),
            exit_code: 1,
        });
        let encoded = serde_json::to_string(&error).unwrap();
        assert!(!encoded.contains("secret"));
        assert!(!encoded.contains("policy.toml"));
        assert_eq!(serde_json::to_value(error.details).unwrap(), json!({}));
    }

    #[test]
    fn error_details_schema_is_a_closed_empty_object() {
        let schema = serde_json::to_value(rmcp::schemars::schema_for!(McpEmptyDetails)).unwrap();
        assert_eq!(schema.get("type"), Some(&json!("object")));
        assert_eq!(schema.get("additionalProperties"), Some(&json!(false)));
        assert!(
            schema
                .get("properties")
                .is_none_or(|properties| properties == &json!({}))
        );
    }

    #[test]
    fn status_projection_redacts_persisted_failure_diagnostics() {
        let state = SessionState {
            schema: StateSchemaVersion,
            created_at: "2026-09-03T00:00:00Z".to_owned(),
            status: SessionStatus::Failed,
            operation_id: "capture".to_owned(),
            revision: 7,
            updated_at: "2026-09-03T00:01:00Z".to_owned(),
            error: Some(t32perf_model::SessionError {
                code: "TARGET_FAILURE".to_owned(),
                message: "secret token=top-secret at C:\\private\\trace.cmm".to_owned(),
                details: serde_json::from_value(json!({
                    "token": "top-secret",
                    "path": "C:\\private\\trace.cmm"
                }))
                .unwrap(),
            }),
        };
        let projected = project_session_state(state);
        let encoded = serde_json::to_string(&projected).unwrap();
        assert!(encoded.contains("TARGET_FAILURE"));
        assert!(encoded.contains("session failed; inspect restricted local diagnostics"));
        assert!(!encoded.contains("top-secret"));
        assert!(!encoded.contains("trace.cmm"));
        assert_eq!(
            serde_json::to_value(projected.error.unwrap().details).unwrap(),
            json!({})
        );
    }

    #[test]
    fn terminal_control_projections_remain_canonical_perf_surface_v1() {
        let artifact = Artifact {
            id: "capture-output".to_owned(),
            kind: "controller_evidence".to_owned(),
            relative_path: t32perf_model::ArtifactPath::new("capture/output.json").unwrap(),
            media_type: "application/json".to_owned(),
            size_bytes: 128,
            sha256: t32perf_model::Sha256Digest::new("a".repeat(64)).unwrap(),
            producer: "t32perf-controller".to_owned(),
            input_artifact_ids: vec!["capture-input".to_owned()],
        };
        let capabilities = project_capabilities(PerfSurfaceEnvelope::new(
            PerfSurfaceResponse::Capabilities(PerfControlPayload {
                session_id: "projection-session".to_owned(),
                state: SessionStatus::Created,
                capture_phase: PerfCapturePhase::ConfigureRequired,
                status: PerfControlStatus::CapabilitiesComplete,
                completed_operations: vec![t32perf_model::PerfControllerOperation::GetCapabilities],
                pending_operation: None,
                transaction_id: None,
                request_artifact: None,
                capture_artifacts: vec![artifact.clone()],
                next_action: PerfNextAction::Invoke {
                    operation: PerfSurfaceOperation::Capture,
                    required_controller_operation: Some(
                        t32perf_model::PerfControllerOperation::Configure,
                    ),
                },
            }),
        ))
        .unwrap();
        let canonical: PerfSurfaceEnvelope =
            serde_json::from_value(serde_json::to_value(capabilities).unwrap()).unwrap();
        let PerfSurfaceResponse::Capabilities(payload) = canonical.response else {
            panic!("capabilities projection changed operation")
        };
        assert_eq!(
            payload.capture_artifacts[0].input_artifact_ids,
            ["capture-input"]
        );

        let capture_config = PerfArtifactReference::from(&artifact);
        let capture = project_capture(PerfSurfaceEnvelope::new(PerfSurfaceResponse::Capture(
            PerfControlPayload {
                session_id: "projection-session".to_owned(),
                state: SessionStatus::Captured,
                capture_phase: PerfCapturePhase::CaptureComplete,
                status: PerfControlStatus::ControlComplete,
                completed_operations: vec![t32perf_model::PerfControllerOperation::Cleanup],
                pending_operation: None,
                transaction_id: None,
                request_artifact: None,
                capture_artifacts: vec![artifact],
                next_action: PerfNextAction::CaptureConfigReady { capture_config },
            },
        )))
        .unwrap();
        let canonical: PerfSurfaceEnvelope =
            serde_json::from_value(serde_json::to_value(capture).unwrap()).unwrap();
        assert_eq!(canonical.operation(), PerfSurfaceOperation::Capture);
    }

    #[test]
    fn cancellation_before_admission_does_not_execute_the_action() {
        let root = TempDir::new().unwrap();
        let server = T32PerfMcpServer::new(config(&root));
        runtime().block_on(async {
            let held = server.execution_lock.clone().lock_owned().await;
            let executed = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let action_executed = Arc::clone(&executed);
            let result = server
                .execute_action(std::future::ready(()), move |_| {
                    action_executed.store(true, std::sync::atomic::Ordering::SeqCst);
                    Err::<StatusEnvelope, _>(AppError::operational("must not execute"))
                })
                .await;
            drop(held);
            assert!(!executed.load(std::sync::atomic::Ordering::SeqCst));
            let Err(Json(McpToolResult::Error(error))) = result else {
                panic!("must cancel")
            };
            assert_eq!(error.code, "CANCELLED");
        });
    }

    #[test]
    fn cancelled_handler_keeps_serialization_until_host_work_finishes() {
        let root = TempDir::new().unwrap();
        let server = T32PerfMcpServer::new(config(&root));
        runtime().block_on(async {
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let running_server = server.clone();
            let running = tokio::spawn(async move {
                running_server
                    .execute_action(std::future::pending(), move |_| {
                        started_tx.send(()).expect("signal started");
                        release_rx.recv().expect("release host work");
                        Err::<StatusEnvelope, _>(AppError::operational(
                            "cancelled test action completed",
                        ))
                    })
                    .await
            });

            started_rx.await.expect("host work started");
            running.abort();
            let _ = running.await;
            assert!(server.execution_lock.try_lock().is_err());

            release_tx.send(()).expect("release host work");
            let result = server
                .execute_action(std::future::pending(), |_| {
                    Err::<StatusEnvelope, _>(AppError::operational("next action reached"))
                })
                .await;
            let error = match result {
                Err(Json(McpToolResult::Error(error))) => error,
                Ok(_) => panic!("test action should fail"),
                Err(Json(McpToolResult::Success(_))) => {
                    panic!("test action should return an error")
                }
            };
            assert_eq!(error.code, "OPERATIONAL_ERROR");
        });
    }
}
