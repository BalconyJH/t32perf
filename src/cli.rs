use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

pub(crate) const DEFAULT_MAX_FILE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub(crate) const DEFAULT_MAX_SESSION_BYTES: u64 = 256 * 1024 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "t32perf",
    version,
    about = "TRACE32 performance observation pipeline"
)]
pub struct Cli {
    #[arg(long, global = true, default_value = ".t32perf")]
    pub artifact_root: PathBuf,
    #[arg(
        long,
        global = true,
        alias = "file-limit",
        default_value_t = DEFAULT_MAX_FILE_BYTES
    )]
    pub max_file_bytes: u64,
    #[arg(
        long,
        global = true,
        alias = "session-limit",
        default_value_t = DEFAULT_MAX_SESSION_BYTES
    )]
    pub max_session_bytes: u64,
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(name = "perf_capabilities")]
    PerfCapabilities(PerfCapabilitiesArgs),
    #[command(name = "perf_capture")]
    PerfCapture(PerfCaptureArgs),
    #[command(name = "perf_get_status")]
    PerfGetStatus(SessionArg),
    #[command(name = "perf_get_summary")]
    PerfGetSummary(SummaryArgs),
    #[command(name = "perf_list_artifacts")]
    PerfListArtifacts(ArtifactsListArgs),
    #[command(name = "perf_convert")]
    PerfConvert(ConvertArgs),
    #[command(name = "perf_compare")]
    PerfCompare(CompareArgs),
    #[command(name = "perf_run")]
    PerfRun(PerfRunArgs),
    /// Serve the bounded T32Perf host facade over MCP stdio.
    Mcp,
    Sampling(SamplingCommand),
    Stack(StackCommand),
    Session(SessionCommand),
    Maintenance(MaintenanceCommand),
    Normalize(NormalizeArgs),
    Validate(ValidateArgs),
    Analyze(AnalyzeArgs),
    Summary(SummaryArgs),
    Convert(ConvertArgs),
    Compare(CompareArgs),
    Controller(ControllerCommand),
    Artifacts(ArtifactsCommand),
    Doctor,
    Fixture(FixtureCommand),
    Capture(CaptureArgs),
}

impl Command {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::PerfCapabilities(_) => "perf_capabilities",
            Self::PerfCapture(_) => "perf_capture",
            Self::PerfGetStatus(_) => "perf_get_status",
            Self::PerfGetSummary(_) => "perf_get_summary",
            Self::PerfListArtifacts(_) => "perf_list_artifacts",
            Self::PerfConvert(_) => "perf_convert",
            Self::PerfCompare(_) => "perf_compare",
            Self::PerfRun(_) => "perf_run",
            Self::Mcp => "mcp",
            Self::Sampling(_) => "sampling",
            Self::Stack(_) => "stack",
            Self::Session(_) => "session",
            Self::Maintenance(_) => "maintenance",
            Self::Normalize(_) => "normalize",
            Self::Validate(_) => "validate",
            Self::Analyze(_) => "analyze",
            Self::Summary(_) => "summary",
            Self::Convert(_) => "convert",
            Self::Compare(_) => "compare",
            Self::Controller(_) => "controller",
            Self::Artifacts(_) => "artifacts",
            Self::Doctor => "doctor",
            Self::Fixture(_) => "fixture",
            Self::Capture(_) => "capture",
        }
    }
}

/// Diagnostic-only coarse TRACE32 PERF histogram analysis.
#[derive(Debug, Args)]
pub struct SamplingCommand {
    #[command(subcommand)]
    pub command: SamplingSubcommand,
}

/// Intrusive TRACE32 break-and-frame-walk stack sampling.
#[derive(Debug, Args)]
pub struct StackCommand {
    #[command(subcommand)]
    pub command: StackSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum StackSubcommand {
    Prepare(StackPrepareArgs),
    Ingest(StackIngestArgs),
    Analyze(StackAnalyzeArgs),
    Summary(StackSummaryArgs),
    Render(StackRenderArgs),
}

#[derive(Debug, Args)]
pub struct StackPrepareArgs {
    pub session: String,
    #[arg(long, value_name = "JSON")]
    pub capture_request: String,
}

#[derive(Debug, Args)]
pub struct StackIngestArgs {
    pub session: String,
    #[arg(long, value_name = "RELATIVE_PATH")]
    pub staged: String,
}

#[derive(Debug, Args)]
pub struct StackAnalyzeArgs {
    pub session: String,
    #[arg(long)]
    pub stack_samples_artifact: String,
}

#[derive(Debug, Args)]
pub struct StackSummaryArgs {
    pub session: String,
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u8).range(1..=100))]
    pub top: u8,
}

#[derive(Debug, Args)]
pub struct StackRenderArgs {
    pub session: String,
    #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u8).range(1..=64))]
    pub max_depth: u8,
}

#[derive(Debug, Subcommand)]
pub enum SamplingSubcommand {
    Prepare(SamplingPrepareArgs),
    Ingest(SamplingIngestArgs),
    BindFirmware(SamplingBindFirmwareArgs),
    Analyze(SamplingAnalyzeArgs),
    Summary(SamplingSummaryArgs),
    Render(SamplingRenderArgs),
    Flame(SamplingFlameArgs),
}

/// Issues one immutable Host-side sampling capture capability.
#[derive(Debug, Args)]
pub struct SamplingPrepareArgs {
    pub session: String,
    /// Strict `t32perf.sampling-capture-request/v1` JSON document.
    #[arg(long, value_name = "JSON")]
    pub capture_request: String,
}

/// Host-side acceptance of one sampling-sidecar staging artifact.
#[derive(Debug, Args)]
pub struct SamplingIngestArgs {
    pub session: String,
    /// Sidecar-created path relative to the Session directory.
    #[arg(long, value_name = "RELATIVE_PATH")]
    pub staged: String,
}

/// Binds the immutable capture request's deployed firmware digest to a staged ELF.
#[derive(Debug, Args)]
pub struct SamplingBindFirmwareArgs {
    pub session: String,
    /// Plain ELF path relative to the Session staging directory.
    #[arg(long, value_name = "RELATIVE_PATH")]
    pub staged: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SamplingProjection {
    Address,
    Function,
}

impl SamplingProjection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Address => "address",
            Self::Function => "function",
        }
    }
}

#[derive(Debug, Args)]
pub struct SamplingAnalyzeArgs {
    pub session: String,
    #[arg(long)]
    pub histogram_artifact: String,
    #[arg(long, value_enum)]
    pub projection: SamplingProjection,
    #[arg(long)]
    pub elf_artifact: Option<String>,
    #[arg(long)]
    pub firmware_evidence_artifact: Option<String>,
}

#[derive(Debug, Args)]
pub struct SamplingSummaryArgs {
    pub session: String,
    #[arg(long, value_enum)]
    pub projection: SamplingProjection,
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u8).range(1..=100))]
    pub top: u8,
}

#[derive(Debug, Args)]
pub struct SamplingRenderArgs {
    pub session: String,
    #[arg(long, value_enum)]
    pub projection: SamplingProjection,
    #[arg(long, default_value_t = 25, value_parser = clap::value_parser!(u8).range(1..=100))]
    pub max_rows: u8,
}

#[derive(Debug, Args)]
pub struct SamplingFlameArgs {
    pub session: String,
    #[arg(long, value_enum)]
    pub projection: SamplingProjection,
    #[arg(long, default_value_t = 25, value_parser = clap::value_parser!(u8).range(1..=100))]
    pub max_frames: u8,
}

#[derive(Debug, Args)]
pub struct PerfCapabilitiesArgs {
    pub session: String,
}

#[derive(Debug, Args)]
pub struct PerfCaptureArgs {
    pub session: String,
    #[arg(
        long,
        help = "Acknowledge that the fixed workload completed after the accepted start phase, permitting preparation of stop"
    )]
    pub workload_complete: bool,
    #[arg(
        long,
        value_name = "EXPORT_MODE",
        help = "Required when the next durable capture phase is export: raw_ascii or task_events_elf_orti_verified"
    )]
    pub mode: Option<String>,
}

/// Closed one-shot performance-run request.
#[derive(Debug, Args)]
pub struct PerfRunArgs {
    /// Requested target capture duration in milliseconds.
    #[arg(long)]
    pub duration_ms: u64,
    /// Optional deterministic Session identity.
    #[arg(long)]
    pub id: Option<String>,
    /// Bounded hotspot count.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u8).range(1..=100))]
    pub top: u8,
}

#[derive(Debug, Args)]
pub struct ControllerCommand {
    #[command(subcommand)]
    pub command: ControllerSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ControllerSubcommand {
    ProvisionFirmware(ControllerProvisionFirmwareArgs),
    ProvisionQualification(ControllerProvisionQualificationArgs),
    SelectScenario(ControllerSelectScenarioArgs),
    Prepare(ControllerPrepareArgs),
    Accept(ControllerTransactionArgs),
    Abort(ControllerAbortArgs),
    ConfirmAbort(ControllerConfirmAbortArgs),
    Drive(ControllerDriveArgs),
    DriverPreflight,
    DriveTransaction(ControllerTransactionArgs),
    AbortUpstream(ControllerAbortArgs),
    Recover(ControllerRecoverCommand),
    Status(ControllerStatusArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ControllerDriveSurface {
    Capabilities,
    Capture,
}

impl ControllerDriveSurface {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Capabilities => "capabilities",
            Self::Capture => "capture",
        }
    }
}

#[derive(Debug, Args)]
pub struct ControllerDriveArgs {
    pub session: String,
    #[arg(long, value_enum)]
    pub surface: ControllerDriveSurface,
    #[arg(long, value_parser = ["raw_ascii"])]
    pub mode: Option<String>,
}

#[derive(Debug, Args)]
pub struct ControllerProvisionFirmwareArgs {
    pub session: String,
    #[arg(long, value_name = "REL")]
    pub staged: String,
}

#[derive(Debug, Args)]
pub struct ControllerProvisionQualificationArgs {
    pub session: String,
    #[arg(long)]
    pub policy_id: String,
    #[arg(long, value_name = "REL")]
    pub qualification_staged: String,
    #[arg(long, value_name = "REL")]
    pub hil_staged: String,
    #[arg(long, value_name = "REL")]
    pub recovery_staged: Option<String>,
}

#[derive(Debug, Args)]
pub struct ControllerSelectScenarioArgs {
    pub session: String,
    #[arg(long, value_name = "CLOSED")]
    pub scenario: String,
}

#[derive(Debug, Args)]
pub struct ControllerRecoverCommand {
    #[command(subcommand)]
    pub command: ControllerRecoverSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ControllerRecoverSubcommand {
    Prepare(ControllerRecoveryPrepareArgs),
    Accept(ControllerRecoveryAcceptArgs),
}

#[derive(Debug, Args)]
pub struct ControllerRecoveryPrepareArgs {
    pub session: String,
    pub transaction: String,
    #[arg(long, value_parser = ["endpoint", "target"])]
    pub scope: String,
}

#[derive(Debug, Args)]
pub struct ControllerRecoveryAcceptArgs {
    pub reservation: String,
}

#[derive(Debug, Args)]
pub struct ControllerPrepareArgs {
    pub session: String,
    #[arg(
        long,
        value_name = "PERF_OPERATION",
        help = "Exact fixed operation name, such as perf_export"
    )]
    pub operation: String,
    #[arg(
        long,
        value_name = "EXPORT_MODE",
        help = "Required only for perf_export: raw_ascii or task_events_elf_orti_verified"
    )]
    pub mode: Option<String>,
}

#[derive(Debug, Args)]
pub struct ControllerTransactionArgs {
    pub session: String,
    pub transaction: String,
}

#[derive(Debug, Args)]
pub struct ControllerAbortArgs {
    pub session: String,
    pub transaction: String,
    #[arg(
        long,
        value_name = "REASON",
        value_parser = ["timeout", "transport_failure", "operator_request"],
        help = "timeout, transport_failure, or operator_request"
    )]
    pub reason: String,
}

#[derive(Debug, Args)]
pub struct ControllerConfirmAbortArgs {
    pub session: String,
    pub transaction: String,
    #[arg(
        long,
        help = "Confirm that the trusted single-tenant caller observed abort_practice_skill return success despite upstream's lack of a transaction-bound acknowledgement"
    )]
    pub acknowledge_unbound_success: bool,
}

#[derive(Debug, Args)]
pub struct ControllerStatusArgs {
    pub session: String,
}

#[derive(Debug, Args)]
pub struct MaintenanceCommand {
    #[command(subcommand)]
    pub command: MaintenanceSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum MaintenanceSubcommand {
    Inspect(MaintenanceInspectArgs),
    Diagnostics(MaintenanceDiagnosticsArgs),
    Schema(MaintenanceSchemaArgs),
    Retention(RetentionCommand),
    Abandon(AbandonCommand),
}

#[derive(Debug, Args)]
pub struct MaintenanceInspectArgs {
    pub session: String,
    #[arg(long)]
    pub deep: bool,
}

#[derive(Debug, Args)]
pub struct MaintenanceDiagnosticsArgs {
    pub session: String,
}

#[derive(Debug, Args)]
pub struct MaintenanceSchemaArgs {
    pub session: Option<String>,
}

#[derive(Debug, Args)]
pub struct RetentionCommand {
    #[command(subcommand)]
    pub command: RetentionSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum RetentionSubcommand {
    Plan(RetentionPlanArgs),
    Apply(RetentionApplyArgs),
    Restore(RetentionRestoreArgs),
}

#[derive(Debug, Args)]
pub struct RetentionPlanArgs {
    #[arg(long = "session", required = true)]
    pub sessions: Vec<String>,
}

#[derive(Debug, Args)]
pub struct RetentionApplyArgs {
    pub plan: String,
    #[arg(long)]
    pub confirm: String,
}

#[derive(Debug, Args)]
pub struct RetentionRestoreArgs {
    pub plan: String,
    pub session: String,
    #[arg(long)]
    pub confirm: String,
}

#[derive(Debug, Args)]
pub struct AbandonCommand {
    #[command(subcommand)]
    pub command: AbandonSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum AbandonSubcommand {
    Plan(AbandonPlanArgs),
    Apply(AbandonApplyArgs),
    Restore(AbandonRestoreArgs),
}

#[derive(Debug, Args)]
pub struct AbandonPlanArgs {
    pub session: String,
}

#[derive(Debug, Args)]
pub struct AbandonApplyArgs {
    pub plan: String,
    #[arg(long)]
    pub confirm: String,
}

#[derive(Debug, Args)]
pub struct AbandonRestoreArgs {
    pub plan: String,
    #[arg(long)]
    pub confirm: String,
}

#[derive(Debug, Args)]
pub struct NormalizeArgs {
    pub session: String,
    #[arg(long)]
    pub input_artifact: Option<String>,
    #[arg(long)]
    pub config_artifact: String,
}

#[derive(Debug, Args)]
pub struct SummaryArgs {
    pub session: String,
    #[arg(long, default_value_t = 10)]
    pub top: usize,
}

#[derive(Debug, Args)]
pub struct AnalyzeArgs {
    pub session: String,
    /// Explicit static-RAM input flavor. No file-format detection is performed.
    #[arg(long)]
    pub static_ram_flavor: Option<String>,
    /// Backward-compatible name for `--static-ram-flavor`.
    #[arg(long)]
    pub linker_map_flavor: Option<String>,
    #[arg(long, default_value = "gcc-stack-usage-v1")]
    pub stack_usage_flavor: String,
}

#[derive(Debug, Args)]
pub struct SessionCommand {
    #[command(subcommand)]
    pub command: SessionSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum SessionSubcommand {
    Create(SessionCreateArgs),
    List(ListPageArgs),
    Status(SessionArg),
    Ingest(SessionIngestArgs),
    Attest(SessionAttestArgs),
}

#[derive(Debug, Args)]
pub struct SessionCreateArgs {
    #[arg(long)]
    pub id: Option<String>,
    #[arg(long, default_value = "{}")]
    pub request: String,
}

#[derive(Debug, Args)]
pub struct SessionArg {
    pub session: String,
}

#[derive(Debug, Args)]
pub struct SessionIngestArgs {
    pub session: String,
    #[arg(long)]
    pub staged: String,
    #[arg(long)]
    pub id: String,
    #[arg(long)]
    pub kind: String,
    #[arg(long)]
    pub destination: String,
    #[arg(long)]
    pub media_type: String,
    #[arg(long, default_value = "t32perf-cli")]
    pub producer: String,
    #[arg(long = "input-artifact")]
    pub input_artifact_ids: Vec<String>,
}

#[derive(Debug, Args)]
pub struct SessionAttestArgs {
    pub session: String,
    #[arg(long, value_name = "RELATIVE_PATH")]
    pub staged: String,
    #[arg(long, value_name = "FILE")]
    pub policy: PathBuf,
}

#[derive(Debug, Args)]
pub struct ValidateArgs {
    pub session: String,
    #[arg(long)]
    pub deep: bool,
}

#[derive(Debug, Args)]
pub struct ConvertArgs {
    pub session: String,
    #[arg(long)]
    pub format: String,
}

#[derive(Debug, Args)]
pub struct CompareArgs {
    pub baseline: String,
    pub candidate: String,
    #[arg(
        long,
        value_name = "NAME|JSON|FILE",
        help = "Comparison policy: default, strict, relaxed, inline JSON, or a bounded JSON file"
    )]
    pub policy: String,
    #[arg(
        long,
        help = "Return exit code 0 instead of 13 when the comparison verdict is inconclusive"
    )]
    pub allow_inconclusive: bool,
    #[arg(
        long,
        default_value_t = 20,
        value_parser = parse_comparison_top,
        help = "Maximum rows returned per comparison row family; the complete report is stored in the control plane"
    )]
    pub top: usize,
}

#[derive(Debug, Args)]
pub struct ArtifactsCommand {
    #[command(subcommand)]
    pub command: ArtifactsSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ArtifactsSubcommand {
    List(ArtifactsListArgs),
    Verify(ArtifactsVerifyArgs),
}

#[derive(Debug, Args)]
pub struct ListPageArgs {
    #[arg(
        long,
        default_value_t = 100,
        value_parser = parse_list_limit
    )]
    pub limit: usize,
    #[arg(long, value_name = "ID")]
    pub after: Option<String>,
}

#[derive(Debug, Args)]
pub struct ArtifactsListArgs {
    pub session: String,
    #[command(flatten)]
    pub page: ListPageArgs,
}

#[derive(Debug, Args)]
pub struct ArtifactsVerifyArgs {
    pub session: String,
    #[arg(long)]
    pub id: Option<String>,
    #[arg(long)]
    pub shallow: bool,
}

#[derive(Debug, Args)]
pub struct FixtureCommand {
    #[command(subcommand)]
    pub command: FixtureSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum FixtureSubcommand {
    Generate(GenerateArgs),
}

#[derive(Debug, Args)]
pub struct GenerateArgs {
    #[arg(long, alias = "session")]
    pub id: Option<String>,
    #[arg(
        long,
        default_value_t = 16,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub events: u64,
}

#[derive(Debug, Args)]
pub struct CaptureArgs {
    #[arg(long)]
    pub provider: String,
    #[arg(long, alias = "session")]
    pub id: Option<String>,
    #[arg(
        long,
        default_value_t = 16,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub events: u64,
}

fn parse_comparison_top(value: &str) -> Result<usize, String> {
    parse_bounded_usize(value, 100, "comparison --top")
}

fn parse_list_limit(value: &str) -> Result<usize, String> {
    parse_bounded_usize(value, 1000, "list --limit")
}

fn parse_bounded_usize(value: &str, maximum: usize, name: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("{name} must be an integer in 1..={maximum}"))?;
    if !(1..=maximum).contains(&parsed) {
        return Err(format!("{name} must be in 1..={maximum}"));
    }
    Ok(parsed)
}
