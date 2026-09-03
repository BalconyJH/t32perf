mod config;
mod fault_action;
mod hooks;
pub(crate) mod lease;
mod transport;
mod workload;

pub(crate) use config::{
    LoadedDriverConfig, load_driver_config, load_receipt_bound_driver_config,
    performance_run_deployment_sha256, read_verified_deployment_source,
    require_performance_run_config, revalidate_loaded_driver_config,
    revalidate_receipt_bound_driver_config,
};
pub(crate) use hooks::{
    AttestationSignerHookContext, attestation_signer_output_path, run_attestation_signer_hook,
};

use std::{collections::BTreeSet, future::Future, path::Path, time::Duration};

use serde_json::{Value, json};
use t32perf_model::{
    PerfCapturePhase, PerfControlPayload, PerfControlStatus, PerfControllerOperation, PerfMcpTool,
    PerfNextAction, PerfSurfaceOperation,
};
use t32perf_session::ArtifactRoot;
use t32perf_trace32::{
    ControllerFaultAction, ExecutePracticeSkillCall, MAX_CONTROLLER_MCP_RESPONSE_BYTES,
    PerfFrameError, PerfFrameLimits, PerfOperation, T32mcpTool, parse_t32mcp_perf_response,
};
use tokio::time::{Instant, sleep_until, timeout_at};

use crate::{
    app::{AppError, CommandOutcome, EXIT_OPERATIONAL, EXIT_SUCCESS},
    cli::ControllerDriveSurface,
    controller::{ControllerRequestEnvelope, DriverTransactionState, DriverWorkloadContext},
};

use self::{
    fault_action::{
        expected_cmm_abort_marker_envelope, external_hook_role, fault_injected_error_envelope,
        has_exact_cmm_abort_marker,
    },
    transport::{ForceDisconnectResult, StdioT32mcpClient, T32mcpTransport},
    workload::{ConfiguredHookRunner, DriverHookRunner, FaultInvocation, WorkloadInvocation},
};

const MAX_DRIVER_ITERATIONS: usize = 128;
const DRIVER_FRAME_PAYLOAD_BYTES: usize = 4 * 1024;
const MAX_PERFORMANCE_RUN_CAPTURE_TIMEOUT_MS: u64 = 7_200_000;

fn performance_run_capture_timeout_ms(
    operation_timeout_ms: u64,
    workload_timeout_ms: u64,
) -> Result<u64, AppError> {
    let total = operation_timeout_ms
        .checked_add(workload_timeout_ms)
        .ok_or_else(|| AppError::operational("performance-run capture timeout overflow"))?;
    if total > MAX_PERFORMANCE_RUN_CAPTURE_TIMEOUT_MS {
        return Err(AppError::operational(format!(
            "performance-run capture timeout `{total}` ms exceeds the compiled {MAX_PERFORMANCE_RUN_CAPTURE_TIMEOUT_MS} ms bound"
        )));
    }
    Ok(total)
}

fn ensure_performance_run_duration(
    duration_ns: u64,
    max_duration_ns: u64,
    workload_timeout_ms: u64,
) -> Result<(), AppError> {
    if duration_ns == 0 || duration_ns > max_duration_ns {
        return Err(AppError::operational(format!(
            "performance-run duration_ns `{duration_ns}` is outside deployment range 1..={max_duration_ns}"
        )));
    }
    let duration_ms = duration_ns.div_ceil(1_000_000);
    if duration_ms >= workload_timeout_ms {
        return Err(AppError::operational(format!(
            "performance-run workload timeout `{workload_timeout_ms}` ms does not exceed requested duration `{duration_ms}` ms"
        )));
    }
    Ok(())
}

/// Performs the closed, side-effect-free validation shared by the CLI gate
/// and the authoritative driver entry point.
pub(crate) fn preflight_drive(
    surface: ControllerDriveSurface,
    mode: Option<&str>,
) -> Result<(), AppError> {
    match (surface, mode) {
        (ControllerDriveSurface::Capabilities, None)
        | (ControllerDriveSurface::Capture, None | Some("raw_ascii")) => Ok(()),
        (ControllerDriveSurface::Capabilities, Some(_)) => Err(AppError::operational(
            "--mode is valid only with --surface capture",
        )),
        (ControllerDriveSurface::Capture, Some(mode)) => Err(AppError::operational(format!(
            "unsupported controller driver capture mode `{mode}`"
        ))),
    }
}

fn ensure_strict_performance_run_driver_admission(
    root: &ArtifactRoot,
    session_id: &str,
    loaded: &LoadedDriverConfig,
) -> Result<(), AppError> {
    let session = root
        .session(
            &t32perf_session::SessionId::new(session_id.to_owned())
                .map_err(AppError::operational)?,
        )
        .map_err(AppError::operational)?;
    let Some(request) = strict_performance_run_request(&session)? else {
        return Ok(());
    };
    ensure_performance_run_driver_admission(&session, &request, loaded)
}

/// Applies the strict performance-run deployment gate to a public controller
/// dispatch. The caller must already hold the root-wide driver execution lease.
pub(crate) fn require_strict_performance_run_dispatch_admission(
    root: &ArtifactRoot,
    session_id: &str,
) -> Result<(), AppError> {
    let session = root
        .session(
            &t32perf_session::SessionId::new(session_id.to_owned())
                .map_err(AppError::operational)?,
        )
        .map_err(AppError::operational)?;
    let Some(request) = strict_performance_run_request(&session)? else {
        return Ok(());
    };
    let loaded = load_driver_config(root).map_err(AppError::operational)?;
    ensure_performance_run_driver_admission(&session, &request, &loaded)
}

fn strict_performance_run_request(
    session: &t32perf_session::Session,
) -> Result<Option<t32perf_model::PerformanceRunRequest>, AppError> {
    let request_value = session.request().map_err(AppError::operational)?;
    if request_value
        .get("schema")
        .and_then(serde_json::Value::as_str)
        != Some(t32perf_model::PERFORMANCE_RUN_REQUEST_SCHEMA)
    {
        return Ok(None);
    }
    let request: t32perf_model::PerformanceRunRequest = serde_json::from_value(request_value)
        .map_err(|error| {
            AppError::operational(format!(
                "performance-run driver dispatch requires a strict immutable request: {error}"
            ))
        })?;
    request.validate().map_err(AppError::operational)?;
    Ok(Some(request))
}

fn ensure_performance_run_driver_admission(
    session: &t32perf_session::Session,
    request: &t32perf_model::PerformanceRunRequest,
    loaded: &LoadedDriverConfig,
) -> Result<(), AppError> {
    let deployment = require_performance_run_config(loaded).map_err(AppError::operational)?;
    ensure_performance_run_duration(
        request.duration_ns,
        deployment.max_duration_ns,
        deployment.workload_command.timeout_ms,
    )?;
    let artifacts = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    crate::target_adapter_provisioning::require_performance_run_deployment_binding(
        session, &artifacts, loaded,
    )?;
    crate::target_adapter_provisioning::require_performance_run_provisioning_receipt(
        session, &artifacts, loaded,
    )?;
    Ok(())
}

/// Rebinds every driver-owned operation to the one bundle selected by the
/// currently admitted Session profile.  A valid deployment bundle alone is
/// insufficient: it must be the bundle for this immutable controller binding.
fn validate_selected_bundle_admission(
    root: &ArtifactRoot,
    loaded: &LoadedDriverConfig,
    session_id: &str,
    request: &ControllerRequestEnvelope,
) -> Result<(), AppError> {
    let session = root
        .session(
            &t32perf_session::SessionId::new(session_id.to_owned())
                .map_err(AppError::operational)?,
        )
        .map_err(AppError::operational)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    match request.target_adapter() {
        Some(binding) => {
            let (admitted, _, _, _) =
                crate::controller_qualification::load_session_admission(&session, &artifacts)?;
            loaded
                .selected_bundle
                .validate_controller_binding(&admitted, binding)
                .map_err(AppError::operational)
        }
        None if matches!(
            request.operation(),
            PerfOperation::GetCapabilities | PerfOperation::GetHotspots
        ) =>
        {
            validate_endpoint_bundle_catalog(&loaded.selected_bundle.candidate_profile, request)
        }
        None => Err(AppError::operational(
            "controller request without a selected target adapter is limited to endpoint-only capabilities or hotspots operations",
        )),
    }
}

fn validate_endpoint_bundle_catalog(
    selected_profile: &t32perf_trace32::TargetAdapterProfile,
    request: &ControllerRequestEnvelope,
) -> Result<(), AppError> {
    if request.target_adapter().is_some()
        || !matches!(
            request.operation(),
            PerfOperation::GetCapabilities | PerfOperation::GetHotspots
        )
    {
        return Err(AppError::operational(
            "endpoint bundle-catalog admission received a target-bound operation",
        ));
    }
    let catalog = crate::controller_qualification::compiled_candidate_admission_catalog()?;
    let expected_catalog_sha256 = catalog.digest().map_err(AppError::operational)?;
    if request.adapter_catalog_sha256() != &expected_catalog_sha256 {
        return Err(AppError::operational(
            "endpoint controller request is not bound to the complete compiled target-adapter catalog",
        ));
    }
    let selected = catalog.get(&selected_profile.adapter_id).ok_or_else(|| {
        AppError::operational(
            "deployment-selected target-adapter bundle is absent from the endpoint catalog",
        )
    })?;
    if &selected.profile != selected_profile {
        return Err(AppError::operational(
            "deployment-selected target-adapter bundle does not match the endpoint catalog",
        ));
    }
    Ok(())
}

fn load_driver_config_for_session_dispatch(
    root: &ArtifactRoot,
    session_id: &str,
) -> Result<(LoadedDriverConfig, bool), AppError> {
    let session = root
        .session(
            &t32perf_session::SessionId::new(session_id.to_owned())
                .map_err(AppError::operational)?,
        )
        .map_err(AppError::operational)?;
    if strict_performance_run_request(&session)?.is_some() {
        let initial = load_receipt_bound_driver_config(root).map_err(AppError::operational)?;
        let loaded = revalidate_receipt_bound_driver_config(root, &initial)
            .map_err(AppError::operational)?;
        ensure_strict_performance_run_driver_admission(root, session_id, &loaded)?;
        Ok((loaded, true))
    } else {
        Ok((
            load_driver_config(root).map_err(AppError::operational)?,
            false,
        ))
    }
}

#[derive(Debug, Clone)]
struct DriverTransactionView {
    request: ControllerRequestEnvelope,
    response_staged: bool,
    response_accepted: bool,
    dispatch_intent_recorded: bool,
    fault_intent_recorded: bool,
    fault_triggered_recorded: bool,
    abort_planned: bool,
    abort_attempted: bool,
    abort_success_observed: bool,
    abort_confirmed: bool,
}

impl From<DriverTransactionState> for DriverTransactionView {
    fn from(state: DriverTransactionState) -> Self {
        Self {
            request: state.request,
            response_staged: state.response_staged,
            response_accepted: state.response_accepted,
            dispatch_intent_recorded: state.dispatch_intent_recorded,
            fault_intent_recorded: state.fault_intent_recorded,
            fault_triggered_recorded: state.fault_triggered_recorded,
            abort_planned: state.abort_planned,
            abort_attempted: state.abort_attempted,
            abort_success_observed: state.abort_success_observed,
            abort_confirmed: state.abort_confirmed,
        }
    }
}

trait DriverHost {
    fn revalidate_deployment(&self) -> Result<(), AppError>;

    fn revalidate_transaction(
        &self,
        session_id: &str,
        request: &ControllerRequestEnvelope,
    ) -> Result<(), AppError>;

    fn revalidate_workload_context(
        &self,
        session_id: &str,
        context: &DriverWorkloadContext,
    ) -> Result<(), AppError>;

    fn invoke_surface(
        &self,
        session_id: &str,
        surface: ControllerDriveSurface,
        mode: Option<&str>,
        workload_complete: bool,
    ) -> Result<PerfControlPayload, AppError>;

    fn transaction(
        &self,
        session_id: &str,
        transaction_id: &str,
    ) -> Result<DriverTransactionView, AppError>;

    fn stage_response(
        &self,
        session_id: &str,
        transaction_id: &str,
        bytes: &[u8],
    ) -> Result<(), AppError>;

    fn accept(&self, session_id: &str, transaction_id: &str) -> Result<CommandOutcome, AppError>;

    fn workload_context(&self, session_id: &str) -> Result<DriverWorkloadContext, AppError>;

    fn record_dispatch_intent(
        &self,
        session_id: &str,
        transaction_id: &str,
    ) -> Result<(), AppError>;

    fn record_fault_intent(&self, session_id: &str, transaction_id: &str) -> Result<(), AppError>;

    fn record_fault_triggered(
        &self,
        session_id: &str,
        transaction_id: &str,
    ) -> Result<(), AppError>;

    fn record_abort_attempt(&self, session_id: &str, transaction_id: &str) -> Result<(), AppError>;

    fn record_abort_success(&self, session_id: &str, transaction_id: &str) -> Result<(), AppError>;

    fn record_workload_intent(&self, session_id: &str) -> Result<(), AppError>;

    fn record_workload_complete(&self, session_id: &str) -> Result<(), AppError>;

    fn plan_abort(
        &self,
        session_id: &str,
        transaction_id: &str,
        reason: &str,
    ) -> Result<CommandOutcome, AppError>;

    fn confirm_abort(
        &self,
        session_id: &str,
        transaction_id: &str,
    ) -> Result<CommandOutcome, AppError>;
}

struct RootDriverHost<'a> {
    root: &'a ArtifactRoot,
    loaded: &'a LoadedDriverConfig,
    receipt_bound: bool,
}

impl DriverHost for RootDriverHost<'_> {
    fn revalidate_deployment(&self) -> Result<(), AppError> {
        revalidate_execution_config(self.root, self.loaded, self.receipt_bound)
            .map(|_| ())
            .map_err(AppError::operational)
    }

    fn revalidate_transaction(
        &self,
        session_id: &str,
        request: &ControllerRequestEnvelope,
    ) -> Result<(), AppError> {
        self.revalidate_deployment()?;
        validate_selected_bundle_admission(self.root, self.loaded, session_id, request)
    }

    fn revalidate_workload_context(
        &self,
        session_id: &str,
        context: &DriverWorkloadContext,
    ) -> Result<(), AppError> {
        let transaction = self.transaction(session_id, &context.start_transaction_id)?;
        if transaction.request.operation() != PerfOperation::Start
            || transaction.request.binding().binding_sha256 != context.start_binding_sha256
        {
            return Err(AppError::operational(
                "workload context no longer matches its immutable Start controller request",
            ));
        }
        self.revalidate_transaction(session_id, &transaction.request)
    }

    fn invoke_surface(
        &self,
        session_id: &str,
        surface: ControllerDriveSurface,
        mode: Option<&str>,
        workload_complete: bool,
    ) -> Result<PerfControlPayload, AppError> {
        let outcome = match surface {
            ControllerDriveSurface::Capabilities => {
                if mode.is_some() || workload_complete {
                    return Err(AppError::operational(
                        "capabilities façade cannot receive capture-only driver arguments",
                    ));
                }
                crate::controller::perf_capabilities(self.root, session_id)?
            }
            ControllerDriveSurface::Capture => {
                crate::controller::perf_capture(self.root, session_id, mode, workload_complete)?
            }
        };
        serde_json::from_value(outcome.result).map_err(|error| {
            AppError::operational(format!(
                "controller driver received an invalid typed façade payload: {error}"
            ))
        })
    }

    fn transaction(
        &self,
        session_id: &str,
        transaction_id: &str,
    ) -> Result<DriverTransactionView, AppError> {
        crate::controller::driver_transaction(self.root, session_id, transaction_id).map(Into::into)
    }

    fn stage_response(
        &self,
        session_id: &str,
        transaction_id: &str,
        bytes: &[u8],
    ) -> Result<(), AppError> {
        crate::controller::stage_driver_response(self.root, session_id, transaction_id, bytes)
    }

    fn accept(&self, session_id: &str, transaction_id: &str) -> Result<CommandOutcome, AppError> {
        crate::controller::accept(self.root, session_id, transaction_id)
    }

    fn workload_context(&self, session_id: &str) -> Result<DriverWorkloadContext, AppError> {
        crate::controller::driver_workload_context(self.root, session_id)
    }

    fn record_dispatch_intent(
        &self,
        session_id: &str,
        transaction_id: &str,
    ) -> Result<(), AppError> {
        crate::controller::record_driver_dispatch_intent(self.root, session_id, transaction_id)
    }

    fn record_fault_intent(&self, session_id: &str, transaction_id: &str) -> Result<(), AppError> {
        crate::controller::record_driver_fault_intent(self.root, session_id, transaction_id)
    }

    fn record_fault_triggered(
        &self,
        session_id: &str,
        transaction_id: &str,
    ) -> Result<(), AppError> {
        crate::controller::record_driver_fault_triggered(self.root, session_id, transaction_id)
    }

    fn record_abort_attempt(&self, session_id: &str, transaction_id: &str) -> Result<(), AppError> {
        crate::controller::record_driver_abort_attempt(self.root, session_id, transaction_id)
    }

    fn record_abort_success(&self, session_id: &str, transaction_id: &str) -> Result<(), AppError> {
        crate::controller::record_driver_abort_success(self.root, session_id, transaction_id)
    }

    fn record_workload_intent(&self, session_id: &str) -> Result<(), AppError> {
        crate::controller::record_driver_workload_intent(self.root, session_id)
    }

    fn record_workload_complete(&self, session_id: &str) -> Result<(), AppError> {
        crate::controller::record_driver_workload_complete(self.root, session_id)
    }

    fn plan_abort(
        &self,
        session_id: &str,
        transaction_id: &str,
        reason: &str,
    ) -> Result<CommandOutcome, AppError> {
        crate::controller::abort(self.root, session_id, transaction_id, reason)
    }

    fn confirm_abort(
        &self,
        session_id: &str,
        transaction_id: &str,
    ) -> Result<CommandOutcome, AppError> {
        crate::controller::confirm_driver_abort(self.root, session_id, transaction_id)
    }
}

fn revalidate_execution_config(
    root: &ArtifactRoot,
    initial: &LoadedDriverConfig,
    receipt_bound: bool,
) -> anyhow::Result<LoadedDriverConfig> {
    if receipt_bound {
        revalidate_receipt_bound_driver_config(root, initial)
    } else {
        revalidate_loaded_driver_config(root, initial)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolResponse {
    Pending,
    Final,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DriverAbortState {
    planned: bool,
    attempted: bool,
    success_observed: bool,
    confirmed: bool,
}

impl From<&DriverTransactionView> for DriverAbortState {
    fn from(transaction: &DriverTransactionView) -> Self {
        Self {
            planned: transaction.abort_planned,
            attempted: transaction.abort_attempted,
            success_observed: transaction.abort_success_observed,
            confirmed: transaction.abort_confirmed,
        }
    }
}

struct DriverBudget {
    deadline: Instant,
    iterations: usize,
}

impl DriverBudget {
    fn new(timeout_ms: u64) -> Self {
        Self {
            deadline: Instant::now() + Duration::from_millis(timeout_ms),
            iterations: 0,
        }
    }

    fn step(&mut self, activity: &'static str) -> Result<(), AppError> {
        self.iterations += 1;
        if self.iterations > MAX_DRIVER_ITERATIONS {
            return Err(driver_bound_error(activity, self.iterations));
        }
        if Instant::now() >= self.deadline {
            return Err(driver_timeout_error(activity));
        }
        Ok(())
    }

    async fn poll(&self, poll_interval_ms: u64, activity: &'static str) -> Result<(), AppError> {
        let wake = Instant::now() + Duration::from_millis(poll_interval_ms);
        sleep_until(wake.min(self.deadline)).await;
        if Instant::now() >= self.deadline {
            Err(driver_timeout_error(activity))
        } else {
            Ok(())
        }
    }

    async fn tool<T>(
        &self,
        activity: &'static str,
        future: impl Future<Output = anyhow::Result<T>>,
    ) -> Result<T, AppError> {
        match timeout_at(self.deadline, future).await {
            Ok(result) => result.map_err(|error| {
                AppError::operational(format!("controller driver {activity} failed: {error}"))
            }),
            Err(_) => Err(driver_timeout_error(activity)),
        }
    }

    fn remaining_timeout_ms(&self, activity: &'static str) -> Result<u64, AppError> {
        let now = Instant::now();
        if now >= self.deadline {
            return Err(driver_timeout_error(activity));
        }
        Ok(u64::try_from((self.deadline - now).as_millis())
            .unwrap_or(u64::MAX)
            .max(1))
    }

    fn require_remaining(&self, activity: &'static str) -> Result<(), AppError> {
        if Instant::now() >= self.deadline {
            Err(driver_timeout_error(activity))
        } else {
            Ok(())
        }
    }
}

pub(crate) fn driver_preflight(root: &ArtifactRoot) -> Result<CommandOutcome, AppError> {
    let _lease = lease::try_acquire(root)?;
    let loaded = load_driver_config(root).map_err(AppError::operational)?;
    let config_path = loaded.path.display().to_string();
    run_driver(async {
        let client = spawn_revalidated_client(root, &loaded, false).await?;
        T32mcpTransport::shutdown(client).await.map_err(|error| {
            AppError::operational(format!("t32mcp preflight shutdown failed: {error}"))
        })?;
        driver_success(
            "controller.driver-preflight",
            json!({
                "server": "t32mcp",
                "version": loaded.config.expected_t32mcp_version,
                "executable_sha256": loaded.config.expected_executable_sha256,
                "bundle_sha256": loaded.config.expected_bundle_sha256,
                "config": config_path,
                "tools_invoked": false,
            }),
        )
    })
}

pub(crate) fn drive(
    root: &ArtifactRoot,
    session_id: &str,
    surface: ControllerDriveSurface,
    mode: Option<&str>,
) -> Result<CommandOutcome, AppError> {
    preflight_drive(surface, mode)?;
    let _lease = lease::try_acquire(root)?;
    let (loaded, receipt_bound) = load_driver_config_for_session_dispatch(root, session_id)?;
    let host = RootDriverHost {
        root,
        loaded: &loaded,
        receipt_bound,
    };
    let hooks = ConfiguredHookRunner::new(root, &loaded);
    run_driver(async {
        let client = spawn_revalidated_client(root, &loaded, receipt_bound).await?;
        let result = drive_surface_core(
            &host,
            &client,
            &hooks,
            session_id,
            surface,
            mode,
            loaded.config.poll_interval_ms,
            loaded.config.operation_timeout_ms,
        )
        .await;
        finish_client(client, result).await
    })
}

/// Drives the target-sensitive performance control chain under one root-wide
/// lease and one revalidated MCP client, preventing another Session from
/// changing the selected target between capabilities and capture.
pub(crate) fn drive_performance_run_control(
    root: &ArtifactRoot,
    session_id: &str,
    duration_ns: u64,
    initial: &LoadedDriverConfig,
) -> Result<CommandOutcome, AppError> {
    if duration_ns == 0 {
        return Err(AppError::operational(
            "performance-run duration_ns must be nonzero",
        ));
    }
    let _lease = lease::try_acquire(root)?;
    let session = root
        .session(
            &t32perf_session::SessionId::new(session_id.to_owned())
                .map_err(AppError::operational)?,
        )
        .map_err(AppError::operational)?;
    let request: t32perf_model::PerformanceRunRequest = serde_json::from_value(
        session.request().map_err(AppError::operational)?,
    )
    .map_err(|_| {
        AppError::operational(
            "performance-run control requires a strict immutable perf_run request",
        )
    })?;
    request.validate().map_err(AppError::operational)?;
    if request.duration_ns != duration_ns {
        return Err(AppError::operational(
            "performance-run control duration does not match the immutable Session request",
        ));
    }
    let loaded =
        revalidate_receipt_bound_driver_config(root, initial).map_err(AppError::operational)?;
    let deployment = require_performance_run_config(&loaded).map_err(AppError::operational)?;
    ensure_performance_run_duration(
        duration_ns,
        deployment.max_duration_ns,
        deployment.workload_command.timeout_ms,
    )?;
    let capture_timeout_ms = performance_run_capture_timeout_ms(
        loaded.config.operation_timeout_ms,
        deployment.workload_command.timeout_ms,
    )?;
    let artifacts = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    crate::target_adapter_provisioning::require_performance_run_deployment_binding(
        &session, &artifacts, &loaded,
    )?;
    crate::target_adapter_provisioning::require_performance_run_provisioning_receipt(
        &session, &artifacts, &loaded,
    )?;
    let host = RootDriverHost {
        root,
        loaded: &loaded,
        receipt_bound: true,
    };
    let hooks = ConfiguredHookRunner::new(root, &loaded);
    run_driver(async {
        let client = spawn_revalidated_client(root, &loaded, true).await?;
        let result = async {
            drive_surface_core(
                &host,
                &client,
                &hooks,
                session_id,
                ControllerDriveSurface::Capabilities,
                None,
                loaded.config.poll_interval_ms,
                loaded.config.operation_timeout_ms,
            )
            .await?;
            let mode = crate::controller::selected_capture_export_mode(root, session_id)?;
            drive_surface_core(
                &host,
                &client,
                &hooks,
                session_id,
                ControllerDriveSurface::Capture,
                Some(mode),
                loaded.config.poll_interval_ms,
                capture_timeout_ms,
            )
            .await
        }
        .await;
        finish_client(client, result).await
    })
}

pub(crate) fn drive_transaction(
    root: &ArtifactRoot,
    session_id: &str,
    transaction_id: &str,
) -> Result<CommandOutcome, AppError> {
    crate::controller::preflight_transaction_id(transaction_id)?;
    let _lease = lease::try_acquire(root)?;
    let (loaded, receipt_bound) = load_driver_config_for_session_dispatch(root, session_id)?;
    let host = RootDriverHost {
        root,
        loaded: &loaded,
        receipt_bound,
    };
    let transaction = host.transaction(session_id, transaction_id)?;
    host.revalidate_transaction(session_id, &transaction.request)?;
    if transaction.response_accepted || transaction.response_staged {
        return host.accept(session_id, transaction_id).map(|accepted| {
            driver_transaction_outcome(
                session_id,
                transaction_id,
                transaction.request.operation(),
                accepted,
            )
        });
    }
    if requires_trace32_disconnect_hook(&transaction) {
        ensure_trace32_disconnect_hook_configured(&loaded)?;
    }
    let hooks = ConfiguredHookRunner::new(root, &loaded);
    run_driver(async {
        let client = spawn_revalidated_client(root, &loaded, receipt_bound).await?;
        match transaction.request.fault_action() {
            None => {
                let result = drive_normal_transaction(
                    &host,
                    &client,
                    session_id,
                    transaction_id,
                    &transaction.request,
                    loaded.config.poll_interval_ms,
                    loaded.config.operation_timeout_ms,
                )
                .await
                .map(|accepted| {
                    driver_transaction_outcome(
                        session_id,
                        transaction_id,
                        transaction.request.operation(),
                        accepted,
                    )
                });
                finish_client(client, result).await
            }
            Some(ControllerFaultAction::CmmAbortAtStart) => {
                let result = drive_cmm_abort_transaction(
                    &host,
                    &client,
                    session_id,
                    transaction_id,
                    &transaction.request,
                    loaded.config.poll_interval_ms,
                    loaded.config.operation_timeout_ms,
                )
                .await
                .map(|accepted| {
                    driver_transaction_outcome(
                        session_id,
                        transaction_id,
                        transaction.request.operation(),
                        accepted,
                    )
                });
                finish_client(client, result).await
            }
            Some(ControllerFaultAction::Trace32DisconnectAtStop) => {
                drive_trace32_disconnect_transaction(
                    &host,
                    client,
                    &hooks,
                    loaded.config.operation_timeout_ms,
                    root.path(),
                    session_id,
                    transaction_id,
                    &transaction.request,
                )
                .await
            }
            Some(ControllerFaultAction::DriverDisconnectAtExport) => {
                drive_driver_disconnect_transaction(
                    &host,
                    client,
                    loaded.config.operation_timeout_ms,
                    session_id,
                    transaction_id,
                    &transaction.request,
                    |deadline| {
                        spawn_revalidated_client_until(root, &loaded, receipt_bound, deadline)
                    },
                )
                .await
            }
        }
    })
}

pub(crate) fn abort_upstream(
    root: &ArtifactRoot,
    session_id: &str,
    transaction_id: &str,
    reason: &str,
) -> Result<CommandOutcome, AppError> {
    crate::controller::preflight_abort(transaction_id, reason)?;
    let _lease = lease::try_acquire(root)?;
    let (loaded, receipt_bound) = load_driver_config_for_session_dispatch(root, session_id)?;
    let host = RootDriverHost {
        root,
        loaded: &loaded,
        receipt_bound,
    };
    let transaction = host.transaction(session_id, transaction_id)?;
    host.revalidate_transaction(session_id, &transaction.request)?;
    if transaction.response_accepted {
        return Err(AppError::operational(
            "an accepted controller response cannot be aborted upstream",
        ));
    }
    let mut abort = DriverAbortState::from(&transaction);
    ensure_abort_planned(&host, &mut abort, session_id, transaction_id, reason)?;
    if abort.confirmed || abort.success_observed {
        let confirmation = host.confirm_abort(session_id, transaction_id)?;
        return abort_upstream_success(session_id, transaction_id, reason, confirmation);
    }
    if abort.attempted {
        return Err(driver_abort_ambiguous_error(
            session_id,
            transaction_id,
            "a durable abort attempt exists without a durable success observation",
        ));
    }
    run_driver(async {
        let client = spawn_revalidated_client(root, &loaded, receipt_bound).await?;
        let budget = DriverBudget::new(loaded.config.operation_timeout_ms);
        let confirmation = official_abort_and_confirm(
            &host,
            &client,
            &budget,
            session_id,
            transaction_id,
            &transaction.request,
            &mut abort,
        )
        .await;
        let confirmation = finish_client(client, confirmation).await?;
        abort_upstream_success(session_id, transaction_id, reason, confirmation)
    })
}

fn run_driver<T>(future: impl Future<Output = Result<T, AppError>>) -> Result<T, AppError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(AppError::operational)?
        .block_on(future)
}

async fn spawn_stdio_client(loaded: &LoadedDriverConfig) -> Result<StdioT32mcpClient, AppError> {
    StdioT32mcpClient::spawn(
        Path::new(&loaded.config.executable),
        Path::new(&loaded.config.skills_root),
        loaded.config.trace32_port,
        &loaded.config.expected_t32mcp_version,
        loaded.config.max_stderr_bytes,
    )
    .await
    .map_err(|error| AppError::operational(format!("t32mcp driver startup failed: {error}")))
}

async fn spawn_revalidated_client(
    root: &ArtifactRoot,
    initial: &LoadedDriverConfig,
    receipt_bound: bool,
) -> Result<StdioT32mcpClient, AppError> {
    let revalidated =
        revalidate_execution_config(root, initial, receipt_bound).map_err(AppError::operational)?;
    spawn_stdio_client(&revalidated).await
}

async fn spawn_revalidated_client_until(
    root: &ArtifactRoot,
    initial: &LoadedDriverConfig,
    receipt_bound: bool,
    deadline: Instant,
) -> Result<StdioT32mcpClient, AppError> {
    ensure_driver_startup_deadline(deadline, "deployment revalidation")?;
    let revalidated =
        revalidate_execution_config(root, initial, receipt_bound).map_err(AppError::operational)?;
    // Revalidation is bounded by the deployment reader.  Check again before
    // handing control to any child-owning transport startup stage.
    ensure_driver_startup_deadline(deadline, "t32mcp startup")?;
    StdioT32mcpClient::spawn_until(
        Path::new(&revalidated.config.executable),
        Path::new(&revalidated.config.skills_root),
        revalidated.config.trace32_port,
        &revalidated.config.expected_t32mcp_version,
        revalidated.config.max_stderr_bytes,
        deadline,
    )
    .await
    .map_err(|error| AppError::operational(format!("t32mcp driver startup failed: {error}")))
}

fn ensure_driver_startup_deadline(deadline: Instant, stage: &'static str) -> Result<(), AppError> {
    if Instant::now() >= deadline {
        Err(driver_timeout_error(stage))
    } else {
        Ok(())
    }
}

async fn finish_client<T, C>(client: C, result: Result<T, AppError>) -> Result<T, AppError>
where
    C: T32mcpTransport,
{
    let shutdown = T32mcpTransport::shutdown(client).await;
    match (result, shutdown) {
        (Ok(value), Ok(_)) => Ok(value),
        (Ok(_), Err(error)) => Err(driver_cleanup_error(None, &error.to_string())),
        (Err(error), Ok(_)) => Err(error),
        (Err(error), Err(cleanup)) => Err(driver_cleanup_error(Some(&error), &cleanup.to_string())),
    }
}

// Every path that still owns an MCP client must close it.  Keep this at the
// ownership boundary rather than relying on a future being dropped to close a
// child process.
macro_rules! cleanup_on_error {
    ($client:ident, $result:expr) => {
        match $result {
            Ok(value) => value,
            Err(error) => return finish_client($client, Err(error)).await,
        }
    };
}

#[allow(clippy::too_many_arguments)]
async fn drive_surface_core<H, T, K>(
    host: &H,
    transport: &T,
    hooks: &K,
    session_id: &str,
    requested_surface: ControllerDriveSurface,
    mode: Option<&str>,
    poll_interval_ms: u64,
    timeout_ms: u64,
) -> Result<CommandOutcome, AppError>
where
    H: DriverHost,
    T: T32mcpTransport,
    K: DriverHookRunner,
{
    let mut budget = DriverBudget::new(timeout_ms);
    let mut active_surface = requested_surface;
    let mut capture_phase = None;
    let mut workload_complete = false;
    let mut live_dispatches = BTreeSet::new();

    loop {
        budget.step("surface orchestration")?;
        let selected_mode = (active_surface == ControllerDriveSurface::Capture
            && capture_phase == Some(PerfCapturePhase::ExportRequired))
        .then_some(mode)
        .flatten();
        let payload =
            host.invoke_surface(session_id, active_surface, selected_mode, workload_complete)?;
        workload_complete = false;
        capture_phase = Some(payload.capture_phase);

        if payload.status == PerfControlStatus::CapabilitiesComplete {
            return driver_surface_success(
                session_id,
                requested_surface,
                payload,
                budget.iterations,
            );
        }

        match &payload.next_action {
            PerfNextAction::Execute {
                mcp,
                response_handoff,
            } => {
                let transaction_id = required_transaction_id(&payload)?;
                let transaction = host.transaction(session_id, transaction_id)?;
                ensure_surface_execute_matches(mcp, &transaction.request.mcp().execute)?;
                ensure_response_limit(response_handoff.max_bytes, &transaction.request)?;
                if transaction.request.fault_action().is_some() {
                    return Err(AppError::operational(
                        "public performance façade returned a forbidden fault-action request",
                    ));
                }
                if transaction.abort_planned
                    || transaction.abort_attempted
                    || transaction.abort_success_observed
                    || transaction.abort_confirmed
                {
                    return Err(recover_preexisting_abort(
                        host,
                        transport,
                        &budget,
                        session_id,
                        transaction_id,
                        &transaction,
                    )
                    .await);
                }
                if transaction.dispatch_intent_recorded {
                    return Err(recover_abandoned_dispatch(
                        host,
                        transport,
                        &budget,
                        session_id,
                        transaction_id,
                        &transaction,
                    )
                    .await);
                }
                host.revalidate_transaction(session_id, &transaction.request)?;
                host.record_dispatch_intent(session_id, transaction_id)?;
                live_dispatches.insert(transaction_id.to_owned());
                let response = budget
                    .tool(
                        "execute_practice_skill",
                        transport.execute(&transaction.request.mcp().execute),
                    )
                    .await?;
                if classify_tool_response(&response, transaction.request.max_response_bytes())?
                    == ToolResponse::Final
                {
                    host.stage_response(
                        session_id,
                        transaction_id,
                        bounded_response_bytes(
                            &response,
                            transaction.request.max_response_bytes(),
                        )?,
                    )?;
                }
            }
            PerfNextAction::Collect {
                mcp,
                response_handoff,
                abort_available,
            } => {
                if !abort_available || mcp.tool != PerfMcpTool::CollectPracticeSkillResponse {
                    return Err(AppError::operational(
                        "typed façade returned an invalid collect action",
                    ));
                }
                let transaction_id = required_transaction_id(&payload)?;
                let transaction = host.transaction(session_id, transaction_id)?;
                ensure_response_limit(response_handoff.max_bytes, &transaction.request)?;
                if !transaction.dispatch_intent_recorded
                    || !live_dispatches.contains(transaction_id)
                {
                    return Err(recover_abandoned_dispatch(
                        host,
                        transport,
                        &budget,
                        session_id,
                        transaction_id,
                        &transaction,
                    )
                    .await);
                }
                budget
                    .poll(poll_interval_ms, "collect_practice_skill_response")
                    .await?;
                host.revalidate_transaction(session_id, &transaction.request)?;
                let response = budget
                    .tool(
                        "collect_practice_skill_response",
                        transport.collect(&transaction.request.mcp().collect),
                    )
                    .await?;
                if classify_tool_response(&response, transaction.request.max_response_bytes())?
                    == ToolResponse::Final
                {
                    host.stage_response(
                        session_id,
                        transaction_id,
                        bounded_response_bytes(
                            &response,
                            transaction.request.max_response_bytes(),
                        )?,
                    )?;
                }
            }
            PerfNextAction::Invoke {
                operation,
                required_controller_operation: _,
            } => {
                active_surface = match operation {
                    PerfSurfaceOperation::Capabilities => ControllerDriveSurface::Capabilities,
                    PerfSurfaceOperation::Capture => ControllerDriveSurface::Capture,
                    _ => {
                        return Err(AppError::operational(
                            "controller driver received an out-of-scope façade invocation",
                        ));
                    }
                };
                if requested_surface == ControllerDriveSurface::Capabilities
                    && payload
                        .completed_operations
                        .contains(&PerfControllerOperation::GetCapabilities)
                {
                    // Render the dedicated capability terminal projection on
                    // the next iteration instead of broadening a capability-
                    // only request into capture.
                    active_surface = ControllerDriveSurface::Capabilities;
                }
            }
            PerfNextAction::RunWorkload { ownership, resume } => {
                if ownership != "target_specific_controller"
                    || resume.operation != PerfSurfaceOperation::Capture
                    || resume.arguments != ["--workload-complete"]
                {
                    return Err(AppError::operational(
                        "typed façade returned an invalid workload ownership or resume action",
                    ));
                }
                let context = host.workload_context(session_id)?;
                if context.complete_recorded {
                    active_surface = ControllerDriveSurface::Capture;
                    workload_complete = true;
                    continue;
                }
                if context.intent_recorded {
                    return Err(driver_workload_ambiguous_error(
                        session_id,
                        &context.start_transaction_id,
                    ));
                }
                host.revalidate_workload_context(session_id, &context)?;
                // A missing hook is a configuration error, not an externally
                // ambiguous workload attempt.  Validate it before recording
                // the one-shot intent.
                hooks.validate_workload(context.duration_ns)?;
                let hook_timeout_ms = budget.remaining_timeout_ms("workload hook")?;
                host.record_workload_intent(session_id)?;
                hooks
                    .run_workload(
                        WorkloadInvocation {
                            session_id,
                            transaction_id: &context.start_transaction_id,
                            initial_target_state: context.initial_target_state,
                            workload_identity: &context.workload_identity,
                            binding_sha256: &context.start_binding_sha256,
                            duration_ns: context.duration_ns,
                        },
                        hook_timeout_ms,
                    )
                    .await?;
                host.record_workload_complete(session_id)?;
                // The external hook has completed successfully.  Its durable
                // marker must win the race with the total deadline so a retry
                // resumes rather than treating the workload as ambiguous.
                budget.require_remaining("workload hook")?;
                active_surface = ControllerDriveSurface::Capture;
                workload_complete = true;
            }
            PerfNextAction::CaptureConfigReady { .. } => {
                if payload.status != PerfControlStatus::ControlComplete
                    || payload.capture_phase != PerfCapturePhase::CaptureComplete
                {
                    return Err(AppError::operational(
                        "typed façade returned capture_config_ready before control completion",
                    ));
                }
                return driver_surface_success(
                    session_id,
                    requested_surface,
                    payload,
                    budget.iterations,
                );
            }
        }
    }
}

async fn recover_abandoned_dispatch<H, T>(
    host: &H,
    transport: &T,
    budget: &DriverBudget,
    session_id: &str,
    transaction_id: &str,
    transaction: &DriverTransactionView,
) -> AppError
where
    H: DriverHost,
    T: T32mcpTransport,
{
    let mut abort = DriverAbortState::from(transaction);
    if let Err(error) = host.revalidate_transaction(session_id, &transaction.request) {
        return error;
    }
    if let Err(error) = ensure_abort_planned(
        host,
        &mut abort,
        session_id,
        transaction_id,
        "transport_failure",
    ) {
        return error;
    }
    if let Err(error) = official_abort_and_confirm(
        host,
        transport,
        budget,
        session_id,
        transaction_id,
        &transaction.request,
        &mut abort,
    )
    .await
    {
        return error;
    }
    driver_dispatch_recovery_error(session_id, transaction_id)
}

async fn recover_preexisting_abort<H, T>(
    host: &H,
    transport: &T,
    budget: &DriverBudget,
    session_id: &str,
    transaction_id: &str,
    transaction: &DriverTransactionView,
) -> AppError
where
    H: DriverHost,
    T: T32mcpTransport,
{
    let mut abort = DriverAbortState::from(transaction);
    if let Err(error) = host.revalidate_transaction(session_id, &transaction.request) {
        return error;
    }
    if let Err(error) = ensure_abort_planned(
        host,
        &mut abort,
        session_id,
        transaction_id,
        "transport_failure",
    ) {
        return error;
    }
    if let Err(error) = official_abort_and_confirm(
        host,
        transport,
        budget,
        session_id,
        transaction_id,
        &transaction.request,
        &mut abort,
    )
    .await
    {
        return error;
    }
    driver_preexisting_abort_recovery_error(session_id, transaction_id)
}

async fn drive_normal_transaction<H, T>(
    host: &H,
    transport: &T,
    session_id: &str,
    transaction_id: &str,
    request: &ControllerRequestEnvelope,
    poll_interval_ms: u64,
    timeout_ms: u64,
) -> Result<CommandOutcome, AppError>
where
    H: DriverHost,
    T: T32mcpTransport,
{
    let mut budget = DriverBudget::new(timeout_ms);
    budget.step("transaction execution")?;
    let transaction = host.transaction(session_id, transaction_id)?;
    if transaction.request != *request {
        return Err(AppError::operational(
            "controller driver transaction request changed after initial Host validation",
        ));
    }
    if transaction.abort_planned
        || transaction.abort_attempted
        || transaction.abort_success_observed
        || transaction.abort_confirmed
    {
        return Err(recover_preexisting_abort(
            host,
            transport,
            &budget,
            session_id,
            transaction_id,
            &transaction,
        )
        .await);
    }
    if transaction.dispatch_intent_recorded {
        return Err(recover_abandoned_dispatch(
            host,
            transport,
            &budget,
            session_id,
            transaction_id,
            &transaction,
        )
        .await);
    }
    host.revalidate_transaction(session_id, request)?;
    host.record_dispatch_intent(session_id, transaction_id)?;
    let mut response = budget
        .tool(
            "execute_practice_skill",
            transport.execute(&request.mcp().execute),
        )
        .await?;
    loop {
        budget.step("transaction collection")?;
        match classify_tool_response(&response, request.max_response_bytes())? {
            ToolResponse::Final => {
                host.stage_response(
                    session_id,
                    transaction_id,
                    bounded_response_bytes(&response, request.max_response_bytes())?,
                )?;
                return host.accept(session_id, transaction_id);
            }
            ToolResponse::Pending => {
                budget
                    .poll(poll_interval_ms, "collect_practice_skill_response")
                    .await?;
                host.revalidate_transaction(session_id, request)?;
                response = budget
                    .tool(
                        "collect_practice_skill_response",
                        transport.collect(&request.mcp().collect),
                    )
                    .await?;
            }
        }
    }
}

async fn drive_cmm_abort_transaction<H, T>(
    host: &H,
    transport: &T,
    session_id: &str,
    transaction_id: &str,
    request: &ControllerRequestEnvelope,
    poll_interval_ms: u64,
    timeout_ms: u64,
) -> Result<CommandOutcome, AppError>
where
    H: DriverHost,
    T: T32mcpTransport,
{
    let expected_marker = expected_cmm_abort_marker_envelope(request)?;
    let mut budget = DriverBudget::new(timeout_ms);
    budget.step("CMM abort execution")?;
    let transaction = host.transaction(session_id, transaction_id)?;
    if transaction.request != *request {
        return Err(AppError::operational(
            "controller driver CMM-abort request changed after initial Host validation",
        ));
    }
    if transaction.fault_intent_recorded {
        if transaction.abort_attempted
            || transaction.abort_success_observed
            || transaction.abort_confirmed
        {
            return Err(recover_preexisting_abort(
                host,
                transport,
                &budget,
                session_id,
                transaction_id,
                &transaction,
            )
            .await);
        }
        if !transaction.fault_triggered_recorded {
            return Err(driver_fault_ambiguous_error(
                session_id,
                transaction_id,
                request.fault_action(),
            ));
        }
        return Err(recover_preexisting_abort(
            host,
            transport,
            &budget,
            session_id,
            transaction_id,
            &transaction,
        )
        .await);
    }
    if transaction.abort_planned
        || transaction.abort_attempted
        || transaction.abort_success_observed
        || transaction.abort_confirmed
    {
        return Err(recover_preexisting_abort(
            host,
            transport,
            &budget,
            session_id,
            transaction_id,
            &transaction,
        )
        .await);
    }
    if transaction.dispatch_intent_recorded {
        return Err(recover_abandoned_dispatch(
            host,
            transport,
            &budget,
            session_id,
            transaction_id,
            &transaction,
        )
        .await);
    }
    host.revalidate_transaction(session_id, request)?;
    host.record_fault_intent(session_id, transaction_id)?;
    host.record_dispatch_intent(session_id, transaction_id)?;
    let mut response = budget
        .tool(
            "execute_practice_skill",
            transport.execute(&request.mcp().execute),
        )
        .await?;
    loop {
        budget.step("CMM abort marker collection")?;
        bounded_response_bytes(&response, request.max_response_bytes())?;
        if has_exact_cmm_abort_marker(&response, &expected_marker) {
            let mut abort = DriverAbortState::from(&transaction);
            ensure_abort_planned(
                host,
                &mut abort,
                session_id,
                transaction_id,
                "operator_request",
            )?;
            host.record_fault_triggered(session_id, transaction_id)?;
            official_abort_and_confirm(
                host,
                transport,
                &budget,
                session_id,
                transaction_id,
                request,
                &mut abort,
            )
            .await?;
            return Err(fault_injected_error_envelope(request));
        }
        match classify_tool_response(&response, request.max_response_bytes())? {
            ToolResponse::Final => {
                host.stage_response(session_id, transaction_id, response.as_bytes())?;
                return host.accept(session_id, transaction_id);
            }
            ToolResponse::Pending => {
                budget
                    .poll(poll_interval_ms, "CMM abort marker collection")
                    .await?;
                host.revalidate_transaction(session_id, request)?;
                response = budget
                    .tool(
                        "collect_practice_skill_response",
                        transport.collect(&request.mcp().collect),
                    )
                    .await?;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn drive_trace32_disconnect_transaction<H, K, T>(
    host: &H,
    client: T,
    hooks: &K,
    timeout_ms: u64,
    artifact_root: &Path,
    session_id: &str,
    transaction_id: &str,
    request: &ControllerRequestEnvelope,
) -> Result<CommandOutcome, AppError>
where
    H: DriverHost,
    K: DriverHookRunner,
    T: T32mcpTransport,
{
    let role = cleanup_on_error!(
        client,
        external_hook_role(ControllerFaultAction::Trace32DisconnectAtStop)
    );
    let mut budget = DriverBudget::new(timeout_ms);
    cleanup_on_error!(client, budget.step("disconnect fault hook"));
    let transaction = cleanup_on_error!(client, host.transaction(session_id, transaction_id));
    if transaction.request != *request {
        return finish_client(
            client,
            Err(AppError::operational(
                "controller driver TRACE32-disconnect request changed after initial Host validation",
            )),
        )
        .await;
    }
    if transaction.fault_intent_recorded {
        if transaction.abort_attempted
            || transaction.abort_success_observed
            || transaction.abort_confirmed
        {
            let error = recover_preexisting_abort(
                host,
                &client,
                &budget,
                session_id,
                transaction_id,
                &transaction,
            )
            .await;
            return finish_client(client, Err(error)).await;
        }
        if !transaction.fault_triggered_recorded {
            return finish_client(
                client,
                Err(driver_fault_ambiguous_error(
                    session_id,
                    transaction_id,
                    request.fault_action(),
                )),
            )
            .await;
        }
        let error = recover_preexisting_abort(
            host,
            &client,
            &budget,
            session_id,
            transaction_id,
            &transaction,
        )
        .await;
        return finish_client(client, Err(error)).await;
    }
    if transaction.abort_planned
        || transaction.abort_attempted
        || transaction.abort_success_observed
        || transaction.abort_confirmed
    {
        let error = recover_preexisting_abort(
            host,
            &client,
            &budget,
            session_id,
            transaction_id,
            &transaction,
        )
        .await;
        return finish_client(client, Err(error)).await;
    }
    let mut abort = DriverAbortState::from(&transaction);
    cleanup_on_error!(client, host.revalidate_transaction(session_id, request));
    cleanup_on_error!(client, host.record_fault_intent(session_id, transaction_id));
    cleanup_on_error!(
        client,
        ensure_abort_planned(
            host,
            &mut abort,
            session_id,
            transaction_id,
            "transport_failure",
        )
    );
    cleanup_on_error!(client, host.revalidate_transaction(session_id, request));
    if let Err(error) = arm_disconnect_fault(
        hooks,
        &budget,
        role,
        artifact_root,
        session_id,
        transaction_id,
        request,
    )
    .await
    {
        return finish_client(
            client,
            Err(driver_fault_side_effect_error(
                session_id,
                transaction_id,
                request.fault_action(),
                &error.message,
            )),
        )
        .await;
    };
    if let Err(error) = host.record_fault_triggered(session_id, transaction_id) {
        return finish_client(
            client,
            Err(driver_fault_side_effect_error(
                session_id,
                transaction_id,
                request.fault_action(),
                &format!(
                    "fault side effect completed but its durable marker failed: {}",
                    error.message
                ),
            )),
        )
        .await;
    }
    if let Err(error) = budget.require_remaining("disconnect fault hook") {
        return finish_client(client, Err(error)).await;
    }
    let result = official_abort_and_confirm(
        host,
        &client,
        &budget,
        session_id,
        transaction_id,
        request,
        &mut abort,
    )
    .await
    .and_then(|_| Err(fault_injected_error_envelope(request)));
    finish_client(client, result).await
}

async fn drive_driver_disconnect_transaction<H, T, F, Fut>(
    host: &H,
    client: T,
    timeout_ms: u64,
    session_id: &str,
    transaction_id: &str,
    request: &ControllerRequestEnvelope,
    replacement_factory: F,
) -> Result<CommandOutcome, AppError>
where
    H: DriverHost,
    T: T32mcpTransport,
    F: FnOnce(Instant) -> Fut,
    Fut: Future<Output = Result<T, AppError>>,
{
    let mut budget = DriverBudget::new(timeout_ms);
    cleanup_on_error!(client, budget.step("driver disconnect fault"));
    let transaction = cleanup_on_error!(client, host.transaction(session_id, transaction_id));
    if transaction.request != *request {
        return finish_client(
            client,
            Err(AppError::operational(
                "controller driver driver-disconnect request changed after initial Host validation",
            )),
        )
        .await;
    }

    if transaction.fault_intent_recorded {
        if transaction.abort_attempted
            || transaction.abort_success_observed
            || transaction.abort_confirmed
        {
            let error = recover_preexisting_abort(
                host,
                &client,
                &budget,
                session_id,
                transaction_id,
                &transaction,
            )
            .await;
            return finish_client(client, Err(error)).await;
        }
        if !transaction.fault_triggered_recorded {
            return finish_client(
                client,
                Err(driver_fault_ambiguous_error(
                    session_id,
                    transaction_id,
                    request.fault_action(),
                )),
            )
            .await;
        }
        let error = recover_preexisting_abort(
            host,
            &client,
            &budget,
            session_id,
            transaction_id,
            &transaction,
        )
        .await;
        return finish_client(client, Err(error)).await;
    }

    if transaction.abort_planned
        || transaction.abort_attempted
        || transaction.abort_success_observed
        || transaction.abort_confirmed
    {
        let error = recover_preexisting_abort(
            host,
            &client,
            &budget,
            session_id,
            transaction_id,
            &transaction,
        )
        .await;
        return finish_client(client, Err(error)).await;
    }

    if transaction.dispatch_intent_recorded {
        let error = recover_abandoned_dispatch(
            host,
            &client,
            &budget,
            session_id,
            transaction_id,
            &transaction,
        )
        .await;
        return finish_client(client, Err(error)).await;
    }

    cleanup_on_error!(client, host.revalidate_transaction(session_id, request));
    cleanup_on_error!(
        client,
        host.record_dispatch_intent(session_id, transaction_id)
    );
    let response = cleanup_on_error!(
        client,
        budget
            .tool(
                "execute_practice_skill",
                client.execute(&request.mcp().execute),
            )
            .await
    );
    if cleanup_on_error!(
        client,
        classify_tool_response(&response, request.max_response_bytes())
    ) == ToolResponse::Final
    {
        cleanup_on_error!(
            client,
            host.stage_response(
                session_id,
                transaction_id,
                cleanup_on_error!(
                    client,
                    bounded_response_bytes(&response, request.max_response_bytes())
                ),
            )
        );
        let accepted = host.accept(session_id, transaction_id);
        return finish_client(client, accepted).await;
    }

    cleanup_on_error!(client, host.revalidate_transaction(session_id, request));
    cleanup_on_error!(client, host.record_fault_intent(session_id, transaction_id));
    let mut abort = DriverAbortState::from(&transaction);
    cleanup_on_error!(
        client,
        ensure_abort_planned(
            host,
            &mut abort,
            session_id,
            transaction_id,
            "transport_failure",
        )
    );
    cleanup_on_error!(client, host.revalidate_transaction(session_id, request));
    let force_result = match arm_driver_disconnect_fault(client, &budget).await {
        Ok(result) => result,
        Err(error) => {
            return Err(driver_fault_side_effect_error(
                session_id,
                transaction_id,
                request.fault_action(),
                &error.message,
            ));
        }
    };
    if let Err(error) = host.record_fault_triggered(session_id, transaction_id) {
        return Err(driver_fault_side_effect_error(
            session_id,
            transaction_id,
            request.fault_action(),
            &format!(
                "fault side effect completed but its durable marker failed: {}",
                error.message
            ),
        ));
    }
    budget.require_remaining("force driver disconnect")?;
    if let Some(diagnostic) = force_result.cleanup_diagnostic {
        return Err(AppError::operational(format!(
            "t32mcp forced-disconnect exact child termination succeeded, but post-kill cleanup reported: {diagnostic}"
        )));
    }

    // The exact Export-owning child has now been consumed. Revalidate the
    // complete deployment and create exactly one replacement for the durable
    // abort plan. Journal state prevents a second abort tool invocation.
    // Startup owns a newly-created child and must be allowed to finish its
    // own bounded startup cleanup.  In particular, dropping it via
    // `timeout_at` could orphan that child.  If the total budget elapsed
    // meanwhile, explicitly shut the replacement down before returning.
    let replacement = replacement_factory(budget.deadline).await?;
    if let Err(error) = budget.require_remaining("replacement t32mcp startup") {
        return finish_client(replacement, Err(error)).await;
    }
    let result = official_abort_and_confirm(
        host,
        &replacement,
        &budget,
        session_id,
        transaction_id,
        request,
        &mut abort,
    )
    .await
    .and_then(|_| Err(fault_injected_error_envelope(request)));
    finish_client(replacement, result).await
}

async fn arm_driver_disconnect_fault<T>(
    transport: T,
    _budget: &DriverBudget,
) -> Result<ForceDisconnectResult, AppError>
where
    T: T32mcpTransport,
{
    // `force_disconnect` owns the client and performs the exact child-tree
    // kill and wait.  Do not cancel that cleanup future at the DriverBudget
    // deadline; report the elapsed deadline only after it has completed.
    transport.force_disconnect().await.map_err(|error| {
        AppError::operational(format!(
            "controller driver force driver disconnect failed: {error}"
        ))
    })
}

#[allow(clippy::too_many_arguments)]
async fn arm_disconnect_fault<K>(
    hooks: &K,
    budget: &DriverBudget,
    role: t32perf_trace32::DriverCommandRole,
    artifact_root: &Path,
    session_id: &str,
    transaction_id: &str,
    request: &ControllerRequestEnvelope,
) -> Result<(), AppError>
where
    K: DriverHookRunner,
{
    let hook_timeout_ms = budget.remaining_timeout_ms("disconnect fault hook")?;
    hooks
        .run_fault(
            role,
            FaultInvocation {
                artifact_root,
                session_id,
                transaction_id,
                binding_sha256: &request.binding().binding_sha256,
            },
            hook_timeout_ms,
        )
        .await?;
    Ok(())
}

fn ensure_abort_planned<H>(
    host: &H,
    state: &mut DriverAbortState,
    session_id: &str,
    transaction_id: &str,
    reason: &str,
) -> Result<(), AppError>
where
    H: DriverHost,
{
    // `plan_abort` is the Host's exact-idempotency and reason-consistency
    // gate.  Replaying it is required even when our snapshot says planned:
    // otherwise a caller could silently report a different reason.
    host.plan_abort(session_id, transaction_id, reason)?;
    state.planned = true;
    Ok(())
}

async fn official_abort_and_confirm<H, T>(
    host: &H,
    transport: &T,
    budget: &DriverBudget,
    session_id: &str,
    transaction_id: &str,
    request: &ControllerRequestEnvelope,
    state: &mut DriverAbortState,
) -> Result<CommandOutcome, AppError>
where
    H: DriverHost,
    T: T32mcpTransport,
{
    if state.confirmed || state.success_observed {
        let confirmation = host.confirm_abort(session_id, transaction_id)?;
        state.confirmed = true;
        return Ok(confirmation);
    }
    if state.attempted {
        return Err(driver_abort_ambiguous_error(
            session_id,
            transaction_id,
            "a durable abort attempt exists without a durable success observation",
        ));
    }
    if !state.planned {
        return Err(AppError::operational(
            "controller driver cannot invoke abort_practice_skill before a durable Host abort plan",
        ));
    }

    host.revalidate_transaction(session_id, request)?;
    host.record_abort_attempt(session_id, transaction_id)?;
    state.attempted = true;
    if let Err(error) = budget
        .tool(
            "abort_practice_skill",
            transport.abort(&request.mcp().abort),
        )
        .await
    {
        return Err(driver_abort_ambiguous_error(
            session_id,
            transaction_id,
            &error.message,
        ));
    }
    if let Err(error) = host.record_abort_success(session_id, transaction_id) {
        return Err(driver_abort_ambiguous_error(
            session_id,
            transaction_id,
            &format!(
                "abort succeeded but its durable success marker failed: {}",
                error.message
            ),
        ));
    }
    state.success_observed = true;
    let confirmation = host.confirm_abort(session_id, transaction_id)?;
    state.confirmed = true;
    Ok(confirmation)
}

fn required_transaction_id(payload: &PerfControlPayload) -> Result<&str, AppError> {
    payload.transaction_id.as_deref().ok_or_else(|| {
        AppError::operational("typed façade MCP action has no immutable transaction identity")
    })
}

fn ensure_trace32_disconnect_hook_configured(loaded: &LoadedDriverConfig) -> Result<(), AppError> {
    if loaded
        .config
        .fault_actions
        .trace32_disconnect_at_stop
        .is_some()
    {
        Ok(())
    } else {
        Err(AppError::unsupported(
            "controller_driver.fault_action",
            "the immutable fault request has no matching closed deployment hook; transaction remains pending",
        ))
    }
}

fn requires_trace32_disconnect_hook(transaction: &DriverTransactionView) -> bool {
    transaction.request.fault_action() == Some(ControllerFaultAction::Trace32DisconnectAtStop)
        && !transaction.fault_intent_recorded
        && !transaction.abort_planned
        && !transaction.abort_attempted
        && !transaction.abort_success_observed
        && !transaction.abort_confirmed
}

fn ensure_surface_execute_matches(
    actual: &t32perf_model::PerfExecuteCall,
    expected: &ExecutePracticeSkillCall,
) -> Result<(), AppError> {
    if actual.tool != PerfMcpTool::ExecutePracticeSkill
        || expected.tool != T32mcpTool::ExecutePracticeSkill
        || actual.arguments.skill_name != expected.arguments.skill_name
        || actual.arguments.script_name != expected.arguments.script_name
        || actual.arguments.script_args != expected.arguments.script_args
    {
        return Err(AppError::operational(
            "typed façade execute action differs from its immutable Controller request",
        ));
    }
    Ok(())
}

fn ensure_response_limit(actual: u64, request: &ControllerRequestEnvelope) -> Result<(), AppError> {
    if actual != request.max_response_bytes()
        || actual == 0
        || actual > MAX_CONTROLLER_MCP_RESPONSE_BYTES
    {
        Err(AppError::operational(
            "typed façade response handoff limit differs from its immutable Controller request",
        ))
    } else {
        Ok(())
    }
}

fn bounded_response_bytes(response: &str, maximum: u64) -> Result<&[u8], AppError> {
    let actual = u64::try_from(response.len()).unwrap_or(u64::MAX);
    if maximum == 0 || maximum > MAX_CONTROLLER_MCP_RESPONSE_BYTES || actual > maximum {
        return Err(AppError::operational(format!(
            "official t32mcp response is {actual} bytes; immutable maximum is {maximum}"
        )));
    }
    Ok(response.as_bytes())
}

fn classify_tool_response(response: &str, maximum: u64) -> Result<ToolResponse, AppError> {
    bounded_response_bytes(response, maximum)?;
    match parse_t32mcp_perf_response(
        response,
        PerfFrameLimits {
            max_payload_bytes: DRIVER_FRAME_PAYLOAD_BYTES,
        },
    ) {
        Ok(_) => Ok(ToolResponse::Final),
        Err(PerfFrameError::NotFinished) => Ok(ToolResponse::Pending),
        // A bounded non-pending wrapper belongs to the Host's immutable raw
        // response and strict accept path, even when malformed. The driver
        // must not discard or reinterpret that authoritative rejection input.
        Err(_) => Ok(ToolResponse::Final),
    }
}

fn driver_surface_success(
    session_id: &str,
    surface: ControllerDriveSurface,
    payload: PerfControlPayload,
    iterations: usize,
) -> Result<CommandOutcome, AppError> {
    driver_success(
        "controller.drive",
        json!({
            "session_id": session_id,
            "surface": surface.as_str(),
            "iterations": iterations,
            "control": payload,
        }),
    )
}

fn driver_transaction_outcome(
    session_id: &str,
    transaction_id: &str,
    operation: PerfOperation,
    accepted: CommandOutcome,
) -> CommandOutcome {
    CommandOutcome {
        command: "controller.drive-transaction",
        result: json!({
            "session_id": session_id,
            "transaction_id": transaction_id,
            "operation": operation,
            "accepted": accepted.result,
        }),
        exit_code: accepted.exit_code,
    }
}

fn abort_upstream_success(
    session_id: &str,
    transaction_id: &str,
    reason: &str,
    confirmation: CommandOutcome,
) -> Result<CommandOutcome, AppError> {
    driver_success(
        "controller.abort-upstream",
        json!({
            "session_id": session_id,
            "transaction_id": transaction_id,
            "reason": reason,
            "confirmation": confirmation.result,
        }),
    )
}

fn driver_success(command: &'static str, result: Value) -> Result<CommandOutcome, AppError> {
    Ok(CommandOutcome {
        command,
        result,
        exit_code: EXIT_SUCCESS,
    })
}

fn driver_bound_error(activity: &'static str, iterations: usize) -> AppError {
    AppError {
        code: "CONTROLLER_DRIVER_LOOP_LIMIT",
        message: format!(
            "controller driver exceeded its fixed {MAX_DRIVER_ITERATIONS}-iteration bound while {activity}"
        ),
        details: json!({
            "activity": activity,
            "iterations": iterations,
            "maximum_iterations": MAX_DRIVER_ITERATIONS,
        }),
        exit_code: EXIT_OPERATIONAL,
    }
}

fn driver_timeout_error(activity: &'static str) -> AppError {
    AppError {
        code: "CONTROLLER_DRIVER_TIMEOUT",
        message: format!(
            "controller driver exceeded its configured total timeout while {activity}"
        ),
        details: json!({"activity": activity}),
        exit_code: EXIT_OPERATIONAL,
    }
}

fn driver_abort_ambiguous_error(session_id: &str, transaction_id: &str, cause: &str) -> AppError {
    AppError {
        code: "CONTROLLER_DRIVER_ABORT_AMBIGUOUS",
        message: format!(
            "controller driver cannot safely retry abort_practice_skill for transaction `{transaction_id}`: {cause}"
        ),
        details: json!({
            "session_id": session_id,
            "transaction_id": transaction_id,
            "abort_retry_permitted": false,
            "cause": cause,
        }),
        exit_code: EXIT_OPERATIONAL,
    }
}

fn driver_dispatch_recovery_error(session_id: &str, transaction_id: &str) -> AppError {
    AppError {
        code: "CONTROLLER_DRIVER_DISPATCH_RECOVERED",
        message: format!(
            "controller driver found an abandoned dispatch intent for transaction `{transaction_id}`; it aborted and quarantined the transaction without re-executing or blindly collecting"
        ),
        details: json!({
            "session_id": session_id,
            "transaction_id": transaction_id,
            "execute_retried": false,
            "collect_attempted": false,
            "target_quarantined": true,
        }),
        exit_code: EXIT_OPERATIONAL,
    }
}

fn driver_preexisting_abort_recovery_error(session_id: &str, transaction_id: &str) -> AppError {
    AppError {
        code: "CONTROLLER_DRIVER_ABORT_RECOVERED",
        message: format!(
            "controller driver completed the durable pre-existing abort lifecycle for transaction `{transaction_id}` without dispatching controller work"
        ),
        details: json!({
            "session_id": session_id,
            "transaction_id": transaction_id,
            "execute_attempted": false,
            "collect_attempted": false,
            "target_quarantined": true,
        }),
        exit_code: EXIT_OPERATIONAL,
    }
}

fn driver_workload_ambiguous_error(session_id: &str, transaction_id: &str) -> AppError {
    AppError {
        code: "CONTROLLER_DRIVER_WORKLOAD_AMBIGUOUS",
        message: format!(
            "controller driver found a workload intent without durable completion for start transaction `{transaction_id}`; the hook will not be executed again"
        ),
        details: json!({
            "session_id": session_id,
            "transaction_id": transaction_id,
            "workload_retry_permitted": false,
        }),
        exit_code: EXIT_OPERATIONAL,
    }
}

fn driver_fault_ambiguous_error(
    session_id: &str,
    transaction_id: &str,
    fault_action: Option<ControllerFaultAction>,
) -> AppError {
    AppError {
        code: "CONTROLLER_DRIVER_FAULT_AMBIGUOUS",
        message: format!(
            "controller driver found a durable fault intent for transaction `{transaction_id}` without proof that the one-shot side effect completed; it will neither repeat the fault action nor invoke an unproven abort"
        ),
        details: json!({
            "session_id": session_id,
            "transaction_id": transaction_id,
            "fault_action": fault_action,
            "fault_retry_permitted": false,
            "abort_attempted": false,
            "target_quarantined": false,
        }),
        exit_code: EXIT_OPERATIONAL,
    }
}

fn driver_fault_side_effect_error(
    session_id: &str,
    transaction_id: &str,
    fault_action: Option<ControllerFaultAction>,
    cause: &str,
) -> AppError {
    AppError {
        code: "CONTROLLER_DRIVER_FAULT_SIDE_EFFECT_FAILED",
        message: format!(
            "controller driver one-shot fault side effect for transaction `{transaction_id}` failed and will not be repeated: {cause}"
        ),
        details: json!({
            "session_id": session_id,
            "transaction_id": transaction_id,
            "fault_action": fault_action,
            "fault_retry_permitted": false,
            "cause": cause,
            "abort_attempted": false,
            "target_quarantined": false,
        }),
        exit_code: EXIT_OPERATIONAL,
    }
}

fn driver_cleanup_error(primary: Option<&AppError>, cleanup: &str) -> AppError {
    AppError {
        code: "CONTROLLER_DRIVER_CLEANUP_FAILED",
        message: format!("t32mcp driver child cleanup failed: {cleanup}"),
        details: json!({
            "cleanup_error": cleanup,
            "primary_error": primary.map(|error| json!({
                "code": error.code,
                "message": error.message,
                "details": error.details,
            })),
            "durable_host_state_preserved": true,
        }),
        exit_code: EXIT_OPERATIONAL,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        collections::{BTreeMap, VecDeque},
        path::Path,
        rc::Rc,
    };

    use anyhow::{Result as AnyResult, anyhow};
    use t32perf_model::{
        Artifact, ArtifactPath, PerfArtifactReference, PerfCapturePhase, PerfControlPayload,
        PerfControlStatus, PerfNextAction, PerfResumeAction, PerfSurfaceOperation, SessionStatus,
        Sha256Digest,
    };
    use t32perf_trace32::{
        ControllerBinding, ControllerFaultAction, ControllerFirmwareImageBinding,
        ControllerMcpHandoff, ControllerRequest, ControllerRequestSchemaVersion,
        ControllerTargetState, DriverCommandRole, ExecutePracticeSkillArguments,
        ExecutePracticeSkillCall, NoArguments, NoArgumentsToolCall, PerfOperation,
        T32PERF_SKILL_NAME, T32mcpTool, compute_controller_binding_sha256,
    };

    use super::*;

    #[test]
    fn performance_run_capture_budget_is_checked_and_bounded() {
        assert_eq!(
            performance_run_capture_timeout_ms(300_000, 600_000).unwrap(),
            900_000
        );
        assert_eq!(
            performance_run_capture_timeout_ms(3_600_000, 3_600_000).unwrap(),
            MAX_PERFORMANCE_RUN_CAPTURE_TIMEOUT_MS
        );
        assert!(performance_run_capture_timeout_ms(u64::MAX, 1).is_err());
        assert!(
            performance_run_capture_timeout_ms(MAX_PERFORMANCE_RUN_CAPTURE_TIMEOUT_MS, 1).is_err()
        );
    }

    #[test]
    fn performance_run_duration_requires_exact_bound_and_workload_grace() {
        ensure_performance_run_duration(1_000_000, 1_000_000, 2).unwrap();
        assert!(ensure_performance_run_duration(1_000_001, 2_000_000, 2).is_err());
        assert!(ensure_performance_run_duration(1_000_001, 1_000_000, 3).is_err());
        assert!(ensure_performance_run_duration(0, 1_000_000, 2).is_err());
    }

    #[test]
    fn drive_preflight_is_closed_and_side_effect_free() {
        preflight_drive(ControllerDriveSurface::Capabilities, None).unwrap();
        preflight_drive(ControllerDriveSurface::Capture, None).unwrap();
        preflight_drive(ControllerDriveSurface::Capture, Some("raw_ascii")).unwrap();

        assert!(
            preflight_drive(ControllerDriveSurface::Capabilities, Some("raw_ascii"))
                .unwrap_err()
                .message
                .contains("valid only with --surface capture")
        );
        assert!(
            preflight_drive(ControllerDriveSurface::Capture, Some("untrusted"))
                .unwrap_err()
                .message
                .contains("unsupported controller driver capture mode")
        );
    }

    struct FakeTransport {
        execute: RefCell<VecDeque<AnyResult<String>>>,
        collect: RefCell<VecDeque<AnyResult<String>>>,
        execute_calls: Cell<usize>,
        collect_calls: Cell<usize>,
        abort_calls: Cell<usize>,
        abort_error: bool,
        shutdown_error: bool,
        force_disconnect_error: bool,
        force_disconnect_late_success: bool,
        force_disconnect_cleanup_diagnostic: Option<&'static str>,
        events: Rc<RefCell<Vec<&'static str>>>,
    }

    impl FakeTransport {
        fn new(execute: Vec<&str>, collect: Vec<&str>) -> Self {
            Self {
                execute: RefCell::new(
                    execute
                        .into_iter()
                        .map(|value| Ok(value.to_owned()))
                        .collect(),
                ),
                collect: RefCell::new(
                    collect
                        .into_iter()
                        .map(|value| Ok(value.to_owned()))
                        .collect(),
                ),
                execute_calls: Cell::new(0),
                collect_calls: Cell::new(0),
                abort_calls: Cell::new(0),
                abort_error: false,
                shutdown_error: false,
                force_disconnect_error: false,
                force_disconnect_late_success: false,
                force_disconnect_cleanup_diagnostic: None,
                events: Rc::new(RefCell::new(Vec::new())),
            }
        }

        fn with_events(events: Rc<RefCell<Vec<&'static str>>>) -> Self {
            Self {
                events,
                ..Self::new(Vec::new(), Vec::new())
            }
        }
    }

    impl T32mcpTransport for FakeTransport {
        async fn execute(&self, _call: &ExecutePracticeSkillCall) -> AnyResult<String> {
            self.execute_calls.set(self.execute_calls.get() + 1);
            self.events.borrow_mut().push("execute");
            self.execute
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| Err(anyhow!("unexpected execute")))
        }

        async fn collect(&self, _call: &NoArgumentsToolCall) -> AnyResult<String> {
            self.collect_calls.set(self.collect_calls.get() + 1);
            self.events.borrow_mut().push("collect");
            self.collect
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| Err(anyhow!("unexpected collect")))
        }

        async fn abort(&self, _call: &NoArgumentsToolCall) -> AnyResult<()> {
            self.abort_calls.set(self.abort_calls.get() + 1);
            self.events.borrow_mut().push("abort");
            if self.abort_error {
                Err(anyhow!("ambiguous abort transport failure"))
            } else {
                Ok(())
            }
        }

        async fn shutdown(self) -> AnyResult<String> {
            self.events.borrow_mut().push("shutdown");
            if self.shutdown_error {
                Err(anyhow!("bounded child cleanup failure"))
            } else {
                Ok(String::new())
            }
        }

        async fn force_disconnect(self) -> AnyResult<ForceDisconnectResult> {
            self.events.borrow_mut().push("force_disconnect");
            if self.force_disconnect_late_success {
                tokio::time::sleep(Duration::from_millis(75)).await;
            }
            if self.force_disconnect_error {
                Err(anyhow!("forced disconnect failed"))
            } else {
                Ok(ForceDisconnectResult {
                    cleanup_diagnostic: self.force_disconnect_cleanup_diagnostic.map(str::to_owned),
                })
            }
        }
    }

    struct FakeHost {
        transaction: RefCell<DriverTransactionView>,
        surfaces: RefCell<VecDeque<PerfControlPayload>>,
        fallback_surface: Option<PerfControlPayload>,
        surface_calls: RefCell<Vec<(ControllerDriveSurface, bool)>>,
        staged: RefCell<Vec<Vec<u8>>>,
        accepts: Cell<usize>,
        accept_error: Option<&'static str>,
        revalidate_error: bool,
        abort_reason: RefCell<Option<String>>,
        plans: Cell<usize>,
        confirms: Cell<usize>,
        revalidations: Cell<usize>,
        dispatches: Cell<usize>,
        fault_intents: Cell<usize>,
        fault_triggers: Cell<usize>,
        abort_attempts: Cell<usize>,
        abort_successes: Cell<usize>,
        workload_intents: Cell<usize>,
        workload_completes: Cell<usize>,
        events: Rc<RefCell<Vec<&'static str>>>,
        workload: RefCell<DriverWorkloadContext>,
    }

    impl FakeHost {
        fn new(request: ControllerRequestEnvelope) -> Self {
            Self {
                transaction: RefCell::new(DriverTransactionView {
                    request,
                    response_staged: false,
                    response_accepted: false,
                    dispatch_intent_recorded: false,
                    fault_intent_recorded: false,
                    fault_triggered_recorded: false,
                    abort_planned: false,
                    abort_attempted: false,
                    abort_success_observed: false,
                    abort_confirmed: false,
                }),
                surfaces: RefCell::new(VecDeque::new()),
                fallback_surface: None,
                surface_calls: RefCell::new(Vec::new()),
                staged: RefCell::new(Vec::new()),
                accepts: Cell::new(0),
                accept_error: None,
                revalidate_error: false,
                abort_reason: RefCell::new(None),
                plans: Cell::new(0),
                confirms: Cell::new(0),
                revalidations: Cell::new(0),
                dispatches: Cell::new(0),
                fault_intents: Cell::new(0),
                fault_triggers: Cell::new(0),
                abort_attempts: Cell::new(0),
                abort_successes: Cell::new(0),
                workload_intents: Cell::new(0),
                workload_completes: Cell::new(0),
                events: Rc::new(RefCell::new(Vec::new())),
                workload: RefCell::new(DriverWorkloadContext {
                    initial_target_state: ControllerTargetState::Halted,
                    workload_identity: "fixed-workload".to_owned(),
                    start_transaction_id: "3".repeat(32),
                    start_binding_sha256: Sha256Digest::new("a".repeat(64)).unwrap(),
                    duration_ns: None,
                    intent_recorded: false,
                    complete_recorded: false,
                }),
            }
        }

        fn outcome(command: &'static str) -> Result<CommandOutcome, AppError> {
            Ok(CommandOutcome {
                command,
                result: json!({"accepted": true}),
                exit_code: EXIT_SUCCESS,
            })
        }
    }

    impl DriverHost for FakeHost {
        fn revalidate_deployment(&self) -> Result<(), AppError> {
            self.revalidations.set(self.revalidations.get() + 1);
            self.events.borrow_mut().push("revalidate");
            if self.revalidate_error {
                Err(AppError::operational("deployment revalidation failed"))
            } else {
                Ok(())
            }
        }

        fn revalidate_transaction(
            &self,
            _session_id: &str,
            _request: &ControllerRequestEnvelope,
        ) -> Result<(), AppError> {
            self.revalidate_deployment()
        }

        fn revalidate_workload_context(
            &self,
            _session_id: &str,
            _context: &DriverWorkloadContext,
        ) -> Result<(), AppError> {
            self.revalidate_deployment()
        }

        fn invoke_surface(
            &self,
            _session_id: &str,
            surface: ControllerDriveSurface,
            _mode: Option<&str>,
            workload_complete: bool,
        ) -> Result<PerfControlPayload, AppError> {
            self.surface_calls
                .borrow_mut()
                .push((surface, workload_complete));
            self.surfaces
                .borrow_mut()
                .pop_front()
                .or_else(|| self.fallback_surface.clone())
                .ok_or_else(|| AppError::operational("unexpected façade invocation"))
        }

        fn transaction(
            &self,
            _session_id: &str,
            _transaction_id: &str,
        ) -> Result<DriverTransactionView, AppError> {
            Ok(self.transaction.borrow().clone())
        }

        fn stage_response(
            &self,
            _session_id: &str,
            _transaction_id: &str,
            bytes: &[u8],
        ) -> Result<(), AppError> {
            self.staged.borrow_mut().push(bytes.to_vec());
            Ok(())
        }

        fn accept(
            &self,
            _session_id: &str,
            _transaction_id: &str,
        ) -> Result<CommandOutcome, AppError> {
            self.accepts.set(self.accepts.get() + 1);
            if let Some(code) = self.accept_error {
                Err(AppError {
                    code,
                    message: "authoritative host rejection".to_owned(),
                    details: json!({}),
                    exit_code: EXIT_OPERATIONAL,
                })
            } else {
                Self::outcome("controller.accept")
            }
        }

        fn workload_context(&self, _session_id: &str) -> Result<DriverWorkloadContext, AppError> {
            Ok(self.workload.borrow().clone())
        }

        fn record_dispatch_intent(
            &self,
            _session_id: &str,
            _transaction_id: &str,
        ) -> Result<(), AppError> {
            self.dispatches.set(self.dispatches.get() + 1);
            self.transaction.borrow_mut().dispatch_intent_recorded = true;
            self.events.borrow_mut().push("dispatch_intent");
            Ok(())
        }

        fn record_fault_intent(
            &self,
            _session_id: &str,
            _transaction_id: &str,
        ) -> Result<(), AppError> {
            self.fault_intents.set(self.fault_intents.get() + 1);
            self.transaction.borrow_mut().fault_intent_recorded = true;
            self.events.borrow_mut().push("fault_intent");
            Ok(())
        }

        fn record_fault_triggered(
            &self,
            _session_id: &str,
            _transaction_id: &str,
        ) -> Result<(), AppError> {
            self.fault_triggers.set(self.fault_triggers.get() + 1);
            self.transaction.borrow_mut().fault_triggered_recorded = true;
            self.events.borrow_mut().push("fault_triggered");
            Ok(())
        }

        fn record_abort_attempt(
            &self,
            _session_id: &str,
            _transaction_id: &str,
        ) -> Result<(), AppError> {
            self.abort_attempts.set(self.abort_attempts.get() + 1);
            self.transaction.borrow_mut().abort_attempted = true;
            self.events.borrow_mut().push("abort_attempt");
            Ok(())
        }

        fn record_abort_success(
            &self,
            _session_id: &str,
            _transaction_id: &str,
        ) -> Result<(), AppError> {
            self.abort_successes.set(self.abort_successes.get() + 1);
            self.transaction.borrow_mut().abort_success_observed = true;
            self.events.borrow_mut().push("abort_success");
            Ok(())
        }

        fn record_workload_intent(&self, _session_id: &str) -> Result<(), AppError> {
            self.workload_intents.set(self.workload_intents.get() + 1);
            self.workload.borrow_mut().intent_recorded = true;
            self.events.borrow_mut().push("workload_intent");
            Ok(())
        }

        fn record_workload_complete(&self, _session_id: &str) -> Result<(), AppError> {
            self.workload_completes
                .set(self.workload_completes.get() + 1);
            self.workload.borrow_mut().complete_recorded = true;
            self.events.borrow_mut().push("workload_complete");
            Ok(())
        }

        fn plan_abort(
            &self,
            _session_id: &str,
            _transaction_id: &str,
            reason: &str,
        ) -> Result<CommandOutcome, AppError> {
            let mut recorded_reason = self.abort_reason.borrow_mut();
            if let Some(existing) = recorded_reason.as_deref()
                && existing != reason
            {
                return Err(AppError::operational(format!(
                    "abort reason mismatch: existing `{existing}`, requested `{reason}`"
                )));
            }
            *recorded_reason = Some(reason.to_owned());
            drop(recorded_reason);
            self.plans.set(self.plans.get() + 1);
            self.transaction.borrow_mut().abort_planned = true;
            self.events.borrow_mut().push("plan");
            Self::outcome("controller.abort")
        }

        fn confirm_abort(
            &self,
            _session_id: &str,
            _transaction_id: &str,
        ) -> Result<CommandOutcome, AppError> {
            self.confirms.set(self.confirms.get() + 1);
            self.transaction.borrow_mut().abort_confirmed = true;
            self.events.borrow_mut().push("confirm");
            Self::outcome("controller.confirm-abort")
        }
    }

    struct FakeHooks {
        workload_missing: bool,
        workload_hangs: bool,
        workload_late_success: bool,
        fault_error: bool,
        fault_late_success: bool,
        workload_calls: Cell<usize>,
        fault_calls: Cell<usize>,
        events: Rc<RefCell<Vec<&'static str>>>,
    }

    impl FakeHooks {
        fn healthy() -> Self {
            Self {
                workload_missing: false,
                workload_hangs: false,
                workload_late_success: false,
                fault_error: false,
                fault_late_success: false,
                workload_calls: Cell::new(0),
                fault_calls: Cell::new(0),
                events: Rc::new(RefCell::new(Vec::new())),
            }
        }
    }

    impl DriverHookRunner for FakeHooks {
        fn validate_workload(&self, _duration_ns: Option<u64>) -> Result<(), AppError> {
            if self.workload_missing {
                Err(AppError::unsupported(
                    "controller_driver.workload",
                    "missing workload hook",
                ))
            } else {
                Ok(())
            }
        }

        fn run_workload<'a>(
            &'a self,
            _invocation: WorkloadInvocation<'a>,
            timeout_ms: u64,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), AppError>> + 'a>> {
            Box::pin(async move {
                self.workload_calls.set(self.workload_calls.get() + 1);
                self.events.borrow_mut().push("workload_hook");
                if self.workload_hangs {
                    tokio::time::sleep(Duration::from_millis(timeout_ms)).await;
                    return Err(driver_timeout_error("workload hook"));
                }
                if self.workload_late_success {
                    tokio::time::sleep(Duration::from_millis(timeout_ms + 5)).await;
                }
                if self.workload_missing {
                    Err(AppError::unsupported(
                        "controller_driver.workload",
                        "missing workload hook",
                    ))
                } else {
                    Ok(())
                }
            })
        }

        fn run_fault<'a>(
            &'a self,
            _role: DriverCommandRole,
            _invocation: FaultInvocation<'a>,
            timeout_ms: u64,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), AppError>> + 'a>> {
            Box::pin(async move {
                self.fault_calls.set(self.fault_calls.get() + 1);
                self.events.borrow_mut().push("fault_hook");
                if self.fault_late_success {
                    tokio::time::sleep(Duration::from_millis(timeout_ms + 5)).await;
                }
                if self.fault_error {
                    Err(AppError::operational("one-shot fault hook failed"))
                } else {
                    Ok(())
                }
            })
        }
    }

    fn request(
        operation: PerfOperation,
        fault_action: Option<ControllerFaultAction>,
    ) -> ControllerRequestEnvelope {
        let session_request_sha256 = Sha256Digest::new("1".repeat(64)).unwrap();
        let session_operation_id = "2".repeat(32);
        let transaction_id = "3".repeat(32);
        let nonce = "4".repeat(32);
        let binding_sha256 = compute_controller_binding_sha256(
            "driver-test",
            &session_operation_id,
            &session_request_sha256,
            &transaction_id,
            &nonce,
        );
        let binding = ControllerBinding {
            session_id: "driver-test".to_owned(),
            session_operation_id,
            session_request_sha256,
            transaction_id: transaction_id.clone(),
            nonce,
            binding_sha256,
        };
        let mut script_args = BTreeMap::from([(
            "binding_sha256".to_owned(),
            binding.binding_sha256.to_string(),
        )]);
        if fault_action == Some(ControllerFaultAction::CmmAbortAtStart) {
            script_args.insert("initial_target_state".to_owned(), "halted".to_owned());
        }
        ControllerRequestEnvelope::V1(ControllerRequest {
            schema: ControllerRequestSchemaVersion::V1,
            binding,
            operation,
            adapter_catalog_sha256: Sha256Digest::new("7".repeat(64)).unwrap(),
            target_adapter: None,
            fault_action,
            firmware_image: ControllerFirmwareImageBinding {
                source_elf_artifact: artifact(
                    "firmware-elf",
                    "firmware_elf",
                    "capture/firmware.elf",
                    "application/x-elf",
                    "test-firmware",
                    "8",
                ),
                measurement_artifact: Artifact {
                    input_artifact_ids: vec!["firmware-elf".to_owned()],
                    ..artifact(
                        "trace32-firmware-s3",
                        "trace32_firmware_measurement",
                        "capture/trace32-firmware.s3",
                        "application/vnd.motorola-s-record",
                        "t32perf-controller-firmware-image/v1",
                        "9",
                    )
                },
                script_input_path: "E:/staging/firmware.s3".to_owned(),
            },
            mcp: ControllerMcpHandoff {
                execute: ExecutePracticeSkillCall {
                    tool: T32mcpTool::ExecutePracticeSkill,
                    arguments: ExecutePracticeSkillArguments {
                        skill_name: T32PERF_SKILL_NAME.to_owned(),
                        script_name: operation.script_name().to_owned(),
                        script_args,
                    },
                },
                collect: NoArgumentsToolCall {
                    tool: T32mcpTool::CollectPracticeSkillResponse,
                    arguments: NoArguments::default(),
                },
                abort: NoArgumentsToolCall {
                    tool: T32mcpTool::AbortPracticeSkill,
                    arguments: NoArguments::default(),
                },
            },
            response_staging_path: ArtifactPath::new(format!(
                "controller/{transaction_id}.mcp-response.txt"
            ))
            .unwrap(),
            max_response_bytes: MAX_CONTROLLER_MCP_RESPONSE_BYTES,
            output: None,
        })
    }

    #[test]
    fn endpoint_bundle_gate_requires_the_complete_candidate_catalog_digest() {
        let selected_profile = t32perf_trace32::compiled_target_adapter_bundle_catalog()
            .pop()
            .unwrap()
            .candidate_profile;
        let catalog_sha256 =
            crate::controller_qualification::compiled_candidate_admission_catalog()
                .unwrap()
                .digest()
                .unwrap();
        let mut endpoint = request(PerfOperation::GetCapabilities, None);
        if let ControllerRequestEnvelope::V1(endpoint_request) = &mut endpoint {
            endpoint_request.adapter_catalog_sha256 = catalog_sha256.clone();
        } else {
            unreachable!("test helper emits V1");
        }
        validate_endpoint_bundle_catalog(&selected_profile, &endpoint).unwrap();

        if let ControllerRequestEnvelope::V1(endpoint_request) = &mut endpoint {
            endpoint_request.adapter_catalog_sha256 = Sha256Digest::new("0".repeat(64)).unwrap();
        }
        assert!(validate_endpoint_bundle_catalog(&selected_profile, &endpoint).is_err());

        let mut target_operation = request(PerfOperation::Configure, None);
        if let ControllerRequestEnvelope::V1(target_request) = &mut target_operation {
            target_request.adapter_catalog_sha256 = catalog_sha256;
        } else {
            unreachable!("test helper emits V1");
        }
        assert!(validate_endpoint_bundle_catalog(&selected_profile, &target_operation).is_err());
    }

    fn artifact(
        id: &str,
        kind: &str,
        path: &str,
        media_type: &str,
        producer: &str,
        digest_character: &str,
    ) -> Artifact {
        Artifact {
            id: id.to_owned(),
            kind: kind.to_owned(),
            relative_path: ArtifactPath::new(path).unwrap(),
            media_type: media_type.to_owned(),
            size_bytes: 1,
            sha256: Sha256Digest::new(digest_character.repeat(64)).unwrap(),
            producer: producer.to_owned(),
            input_artifact_ids: Vec::new(),
        }
    }

    fn workload_payload() -> PerfControlPayload {
        PerfControlPayload {
            session_id: "driver-test".to_owned(),
            state: SessionStatus::Capturing,
            capture_phase: PerfCapturePhase::StopRequired,
            status: PerfControlStatus::WorkloadRequired,
            completed_operations: Vec::new(),
            pending_operation: None,
            transaction_id: None,
            request_artifact: None,
            capture_artifacts: Vec::new(),
            next_action: PerfNextAction::RunWorkload {
                ownership: "target_specific_controller".to_owned(),
                resume: PerfResumeAction {
                    operation: PerfSurfaceOperation::Capture,
                    arguments: vec!["--workload-complete".to_owned()],
                },
            },
        }
    }

    fn invoke_payload() -> PerfControlPayload {
        PerfControlPayload {
            session_id: "driver-test".to_owned(),
            state: SessionStatus::Capturing,
            capture_phase: PerfCapturePhase::ConfigureRequired,
            status: PerfControlStatus::OperationCompleted,
            completed_operations: Vec::new(),
            pending_operation: None,
            transaction_id: None,
            request_artifact: None,
            capture_artifacts: Vec::new(),
            next_action: PerfNextAction::Invoke {
                operation: PerfSurfaceOperation::Capture,
                required_controller_operation: None,
            },
        }
    }

    fn capture_ready_payload() -> PerfControlPayload {
        PerfControlPayload {
            session_id: "driver-test".to_owned(),
            state: SessionStatus::Capturing,
            capture_phase: PerfCapturePhase::CaptureComplete,
            status: PerfControlStatus::ControlComplete,
            completed_operations: Vec::new(),
            pending_operation: None,
            transaction_id: None,
            request_artifact: None,
            capture_artifacts: Vec::new(),
            next_action: PerfNextAction::CaptureConfigReady {
                capture_config: PerfArtifactReference {
                    id: "capture-config".to_owned(),
                    kind: "capture_config".to_owned(),
                    relative_path: ArtifactPath::new("capture/config.json").unwrap(),
                    media_type: "application/json".to_owned(),
                    size_bytes: 1,
                    sha256: Sha256Digest::new("b".repeat(64)).unwrap(),
                    producer: "driver-test".to_owned(),
                },
            },
        }
    }

    fn outcome_error(result: Result<CommandOutcome, AppError>) -> AppError {
        match result {
            Ok(outcome) => panic!("expected driver error, got `{}`", outcome.command),
            Err(error) => error,
        }
    }

    #[test]
    fn normal_transaction_executes_collects_stages_and_accepts() {
        let request = request(PerfOperation::GetHotspots, None);
        let host = FakeHost::new(request.clone());
        let transport = FakeTransport::new(
            vec!["<NOT FINISHED>\n<CONTENT>\n"],
            vec!["bounded-invalid-final-wrapper"],
        );
        let outcome = run_driver(drive_normal_transaction(
            &host,
            &transport,
            "driver-test",
            &"3".repeat(32),
            &request,
            1,
            1_000,
        ))
        .unwrap();
        assert_eq!(outcome.command, "controller.accept");
        assert_eq!(transport.execute_calls.get(), 1);
        assert_eq!(transport.collect_calls.get(), 1);
        assert_eq!(
            host.staged.borrow()[0],
            b"bounded-invalid-final-wrapper".to_vec()
        );
        assert_eq!(host.accepts.get(), 1);
        assert_eq!(host.dispatches.get(), 1);
        assert_eq!(host.revalidations.get(), 2);
    }

    #[test]
    fn valid_pending_wrapper_with_partial_content_allows_collection() {
        assert_eq!(
            classify_tool_response("<NOT FINISHED>\n<CONTENT>\npartial output\n", 1_024).unwrap(),
            ToolResponse::Pending
        );
        assert_eq!(
            classify_tool_response(
                "<NOT FINISHED>\n<CONTENT>\npartial output\n<FINISHED>\n",
                1_024,
            )
            .unwrap(),
            ToolResponse::Final
        );
    }

    #[test]
    fn abandoned_dispatch_is_aborted_without_execute_or_collect() {
        let request = request(PerfOperation::GetHotspots, None);
        let host = FakeHost::new(request.clone());
        host.transaction.borrow_mut().dispatch_intent_recorded = true;
        let transport = FakeTransport::new(Vec::new(), Vec::new());
        let error = outcome_error(run_driver(drive_normal_transaction(
            &host,
            &transport,
            "driver-test",
            &"3".repeat(32),
            &request,
            1,
            1_000,
        )));
        assert_eq!(error.code, "CONTROLLER_DRIVER_DISPATCH_RECOVERED");
        assert_eq!(transport.execute_calls.get(), 0);
        assert_eq!(transport.collect_calls.get(), 0);
        assert_eq!(transport.abort_calls.get(), 1);
        assert_eq!(host.plans.get(), 1);
        assert_eq!(host.abort_attempts.get(), 1);
        assert_eq!(host.abort_successes.get(), 1);
        assert_eq!(host.confirms.get(), 1);
    }

    #[test]
    fn abort_attempt_without_observed_success_is_never_retried() {
        let request = request(PerfOperation::Start, None);
        let host = FakeHost::new(request.clone());
        {
            let mut transaction = host.transaction.borrow_mut();
            transaction.abort_planned = true;
            transaction.abort_attempted = true;
        }
        let transport = FakeTransport::new(Vec::new(), Vec::new());
        let error = outcome_error(run_driver(drive_normal_transaction(
            &host,
            &transport,
            "driver-test",
            &"3".repeat(32),
            &request,
            1,
            1_000,
        )));
        assert_eq!(error.code, "CONTROLLER_DRIVER_ABORT_AMBIGUOUS");
        assert_eq!(transport.abort_calls.get(), 0);
        assert_eq!(transport.execute_calls.get(), 0);
        assert_eq!(host.abort_attempts.get(), 0);
        assert_eq!(host.confirms.get(), 0);
    }

    #[test]
    fn observed_abort_success_only_confirms_and_never_repeats_end() {
        let request = request(PerfOperation::Start, None);
        let host = FakeHost::new(request.clone());
        {
            let mut transaction = host.transaction.borrow_mut();
            transaction.abort_planned = true;
            transaction.abort_attempted = true;
            transaction.abort_success_observed = true;
        }
        let transport = FakeTransport::new(Vec::new(), Vec::new());
        let error = outcome_error(run_driver(drive_normal_transaction(
            &host,
            &transport,
            "driver-test",
            &"3".repeat(32),
            &request,
            1,
            1_000,
        )));
        assert_eq!(error.code, "CONTROLLER_DRIVER_ABORT_RECOVERED");
        assert_eq!(transport.abort_calls.get(), 0);
        assert_eq!(transport.execute_calls.get(), 0);
        assert_eq!(host.abort_attempts.get(), 0);
        assert_eq!(host.abort_successes.get(), 0);
        assert_eq!(host.confirms.get(), 1);
    }

    #[test]
    fn confirmed_abort_is_idempotent_without_another_upstream_abort() {
        let request = request(PerfOperation::Start, None);
        let host = FakeHost::new(request.clone());
        {
            let mut transaction = host.transaction.borrow_mut();
            transaction.abort_planned = true;
            transaction.abort_attempted = true;
            transaction.abort_success_observed = true;
            transaction.abort_confirmed = true;
        }
        let transport = FakeTransport::new(Vec::new(), Vec::new());
        let error = outcome_error(run_driver(drive_normal_transaction(
            &host,
            &transport,
            "driver-test",
            &"3".repeat(32),
            &request,
            1,
            1_000,
        )));
        assert_eq!(error.code, "CONTROLLER_DRIVER_ABORT_RECOVERED");
        assert_eq!(transport.abort_calls.get(), 0);
        assert_eq!(host.confirms.get(), 1);
    }

    #[test]
    fn missing_workload_hook_never_acknowledges_resume() {
        let request = request(PerfOperation::Start, None);
        let host = FakeHost::new(request);
        host.surfaces.borrow_mut().push_back(workload_payload());
        let transport = FakeTransport::new(Vec::new(), Vec::new());
        let hooks = FakeHooks {
            workload_missing: true,
            ..FakeHooks::healthy()
        };
        let error = outcome_error(run_driver(drive_surface_core(
            &host,
            &transport,
            &hooks,
            "driver-test",
            ControllerDriveSurface::Capture,
            Some("raw_ascii"),
            1,
            1_000,
        )));
        assert_eq!(error.code, "UNSUPPORTED");
        assert_eq!(
            host.surface_calls.borrow().as_slice(),
            [(ControllerDriveSurface::Capture, false)]
        );
        assert_eq!(hooks.workload_calls.get(), 0);
        assert_eq!(host.workload_intents.get(), 0);
    }

    #[test]
    fn workload_hook_is_bounded_by_the_driver_total_deadline() {
        let request = request(PerfOperation::Start, None);
        let host = FakeHost::new(request);
        host.surfaces.borrow_mut().push_back(workload_payload());
        let transport = FakeTransport::new(Vec::new(), Vec::new());
        let hooks = FakeHooks {
            workload_hangs: true,
            ..FakeHooks::healthy()
        };
        let error = outcome_error(run_driver(drive_surface_core(
            &host,
            &transport,
            &hooks,
            "driver-test",
            ControllerDriveSurface::Capture,
            None,
            1,
            100,
        )));
        assert_eq!(error.code, "CONTROLLER_DRIVER_TIMEOUT");
        assert_eq!(host.surface_calls.borrow().len(), 1);
    }

    #[test]
    fn completed_workload_is_marked_before_an_elapsed_total_deadline_is_reported() {
        let request = request(PerfOperation::Start, None);
        let host = FakeHost::new(request);
        host.surfaces.borrow_mut().push_back(workload_payload());
        let transport = FakeTransport::new(Vec::new(), Vec::new());
        let hooks = FakeHooks {
            workload_late_success: true,
            ..FakeHooks::healthy()
        };
        let error = outcome_error(run_driver(drive_surface_core(
            &host,
            &transport,
            &hooks,
            "driver-test",
            ControllerDriveSurface::Capture,
            None,
            1,
            50,
        )));
        assert_eq!(error.code, "CONTROLLER_DRIVER_TIMEOUT");
        assert_eq!(host.workload_intents.get(), 1);
        assert_eq!(host.workload_completes.get(), 1);
    }

    #[test]
    fn workload_intent_without_completion_is_ambiguous_and_not_rerun() {
        let request = request(PerfOperation::Start, None);
        let host = FakeHost::new(request);
        host.workload.borrow_mut().intent_recorded = true;
        host.surfaces.borrow_mut().push_back(workload_payload());
        let transport = FakeTransport::new(Vec::new(), Vec::new());
        let hooks = FakeHooks::healthy();
        let error = outcome_error(run_driver(drive_surface_core(
            &host,
            &transport,
            &hooks,
            "driver-test",
            ControllerDriveSurface::Capture,
            None,
            1,
            1_000,
        )));
        assert_eq!(error.code, "CONTROLLER_DRIVER_WORKLOAD_AMBIGUOUS");
        assert_eq!(hooks.workload_calls.get(), 0);
        assert_eq!(host.workload_intents.get(), 0);
        assert_eq!(host.workload_completes.get(), 0);
    }

    #[test]
    fn completed_workload_skips_hook_and_resumes_from_durable_state() {
        let request = request(PerfOperation::Start, None);
        let host = FakeHost::new(request);
        {
            let mut workload = host.workload.borrow_mut();
            workload.intent_recorded = true;
            workload.complete_recorded = true;
        }
        host.surfaces.borrow_mut().push_back(workload_payload());
        host.surfaces
            .borrow_mut()
            .push_back(capture_ready_payload());
        let transport = FakeTransport::new(Vec::new(), Vec::new());
        let hooks = FakeHooks::healthy();
        run_driver(drive_surface_core(
            &host,
            &transport,
            &hooks,
            "driver-test",
            ControllerDriveSurface::Capture,
            None,
            1,
            1_000,
        ))
        .unwrap();
        assert_eq!(hooks.workload_calls.get(), 0);
        assert_eq!(host.workload_completes.get(), 0);
        assert_eq!(
            host.surface_calls.borrow().as_slice(),
            [
                (ControllerDriveSurface::Capture, false),
                (ControllerDriveSurface::Capture, true)
            ]
        );
    }

    #[test]
    fn workload_intent_precedes_hook_and_completion_follows_success() {
        let request = request(PerfOperation::Start, None);
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut host = FakeHost::new(request);
        host.events = Rc::clone(&events);
        host.surfaces.borrow_mut().push_back(workload_payload());
        host.surfaces
            .borrow_mut()
            .push_back(capture_ready_payload());
        let transport = FakeTransport::new(Vec::new(), Vec::new());
        let hooks = FakeHooks {
            events: Rc::clone(&events),
            ..FakeHooks::healthy()
        };
        run_driver(drive_surface_core(
            &host,
            &transport,
            &hooks,
            "driver-test",
            ControllerDriveSurface::Capture,
            None,
            1,
            1_000,
        ))
        .unwrap();
        assert_eq!(
            events.borrow().as_slice(),
            [
                "revalidate",
                "workload_intent",
                "workload_hook",
                "workload_complete"
            ]
        );
        assert_eq!(host.workload_intents.get(), 1);
        assert_eq!(host.workload_completes.get(), 1);
    }

    #[test]
    fn exact_cmm_marker_plans_aborts_and_confirms_without_staging() {
        let request = request(
            PerfOperation::Start,
            Some(ControllerFaultAction::CmmAbortAtStart),
        );
        let host = FakeHost::new(request.clone());
        let marker = expected_cmm_abort_marker_envelope(&request).unwrap();
        let transport = FakeTransport::new(Vec::new(), Vec::new());
        transport
            .execute
            .borrow_mut()
            .push_back(Ok(format!("<NOT FINISHED>\n<CONTENT>\n{marker}\n")));
        let error = outcome_error(run_driver(drive_cmm_abort_transaction(
            &host,
            &transport,
            "driver-test",
            &"3".repeat(32),
            &request,
            1,
            1_000,
        )));
        assert_eq!(error.code, "CONTROLLER_FAULT_INJECTED");
        assert_eq!(host.plans.get(), 1);
        assert_eq!(host.fault_intents.get(), 1);
        assert_eq!(host.fault_triggers.get(), 1);
        assert_eq!(transport.abort_calls.get(), 1);
        assert_eq!(host.confirms.get(), 1);
        assert!(host.staged.borrow().is_empty());
        assert_eq!(host.accepts.get(), 0);
    }

    #[test]
    fn cmm_fault_intent_without_trigger_is_neither_reexecuted_nor_aborted() {
        let request = request(
            PerfOperation::Start,
            Some(ControllerFaultAction::CmmAbortAtStart),
        );
        let host = FakeHost::new(request.clone());
        {
            let mut transaction = host.transaction.borrow_mut();
            transaction.fault_intent_recorded = true;
            transaction.dispatch_intent_recorded = true;
            transaction.abort_planned = true;
        }
        let transport = FakeTransport::new(Vec::new(), Vec::new());
        let error = outcome_error(run_driver(drive_cmm_abort_transaction(
            &host,
            &transport,
            "driver-test",
            &"3".repeat(32),
            &request,
            1,
            1_000,
        )));
        assert_eq!(error.code, "CONTROLLER_DRIVER_FAULT_AMBIGUOUS");
        assert_eq!(transport.execute_calls.get(), 0);
        assert_eq!(transport.collect_calls.get(), 0);
        assert_eq!(transport.abort_calls.get(), 0);
        assert_eq!(host.abort_attempts.get(), 0);
        assert_eq!(host.confirms.get(), 0);
    }

    #[test]
    fn cmm_fault_trigger_recovery_only_runs_the_durable_abort_lifecycle() {
        let request = request(
            PerfOperation::Start,
            Some(ControllerFaultAction::CmmAbortAtStart),
        );
        let host = FakeHost::new(request.clone());
        {
            let mut transaction = host.transaction.borrow_mut();
            transaction.fault_intent_recorded = true;
            transaction.fault_triggered_recorded = true;
            transaction.dispatch_intent_recorded = true;
            transaction.abort_planned = true;
        }
        let transport = FakeTransport::new(Vec::new(), Vec::new());
        let error = outcome_error(run_driver(drive_cmm_abort_transaction(
            &host,
            &transport,
            "driver-test",
            &"3".repeat(32),
            &request,
            1,
            1_000,
        )));
        assert_eq!(error.code, "CONTROLLER_DRIVER_ABORT_RECOVERED");
        assert_eq!(transport.execute_calls.get(), 0);
        assert_eq!(transport.collect_calls.get(), 0);
        assert_eq!(transport.abort_calls.get(), 1);
        assert_eq!(host.abort_attempts.get(), 1);
        assert_eq!(host.abort_successes.get(), 1);
        assert_eq!(host.confirms.get(), 1);
    }

    #[test]
    fn fault_final_wrapper_is_staged_for_authoritative_host_rejection() {
        let request = request(
            PerfOperation::Start,
            Some(ControllerFaultAction::CmmAbortAtStart),
        );
        let mut host = FakeHost::new(request.clone());
        host.accept_error = Some("CONTROLLER_FAULT_ACTION_NOT_OBSERVED");
        let transport = FakeTransport::new(vec!["bounded-final-but-invalid"], Vec::new());
        let error = outcome_error(run_driver(drive_cmm_abort_transaction(
            &host,
            &transport,
            "driver-test",
            &"3".repeat(32),
            &request,
            1,
            1_000,
        )));
        assert_eq!(error.code, "CONTROLLER_FAULT_ACTION_NOT_OBSERVED");
        assert_eq!(host.staged.borrow().len(), 1);
        assert_eq!(host.accepts.get(), 1);
        assert_eq!(host.confirms.get(), 0);
    }

    #[test]
    fn disconnect_boundary_runs_only_the_one_shot_hook() {
        let request = request(
            PerfOperation::Stop,
            Some(ControllerFaultAction::Trace32DisconnectAtStop),
        );
        let hooks = FakeHooks::healthy();
        let budget = DriverBudget::new(1_000);
        run_driver(arm_disconnect_fault(
            &hooks,
            &budget,
            DriverCommandRole::Trace32DisconnectAtStop,
            Path::new("E:/artifacts"),
            "driver-test",
            &"3".repeat(32),
            &request,
        ))
        .unwrap();
        assert_eq!(hooks.fault_calls.get(), 1);
    }

    #[test]
    fn trace32_hook_configuration_is_required_only_for_a_fresh_fault() {
        let request = request(
            PerfOperation::Stop,
            Some(ControllerFaultAction::Trace32DisconnectAtStop),
        );
        let host = FakeHost::new(request);
        assert!(requires_trace32_disconnect_hook(&host.transaction.borrow()));
        host.transaction.borrow_mut().fault_intent_recorded = true;
        assert!(!requires_trace32_disconnect_hook(
            &host.transaction.borrow()
        ));
        {
            let mut transaction = host.transaction.borrow_mut();
            transaction.fault_intent_recorded = false;
            transaction.abort_success_observed = true;
        }
        assert!(!requires_trace32_disconnect_hook(
            &host.transaction.borrow()
        ));
    }

    #[test]
    fn trace32_observed_abort_confirms_without_fault_trigger_or_hook() {
        let request = request(
            PerfOperation::Stop,
            Some(ControllerFaultAction::Trace32DisconnectAtStop),
        );
        let host = FakeHost::new(request.clone());
        {
            let mut transaction = host.transaction.borrow_mut();
            transaction.fault_intent_recorded = true;
            transaction.abort_planned = true;
            transaction.abort_attempted = true;
            transaction.abort_success_observed = true;
        }
        let hooks = FakeHooks::healthy();
        let transport = FakeTransport::new(Vec::new(), Vec::new());
        let error = outcome_error(run_driver(drive_trace32_disconnect_transaction(
            &host,
            transport,
            &hooks,
            1_000,
            Path::new("E:/artifacts"),
            "driver-test",
            &"3".repeat(32),
            &request,
        )));
        assert_eq!(error.code, "CONTROLLER_DRIVER_ABORT_RECOVERED");
        assert_eq!(hooks.fault_calls.get(), 0);
        assert_eq!(host.confirms.get(), 1);
        assert_eq!(host.abort_attempts.get(), 0);
    }

    #[test]
    fn trace32_fault_intent_and_abort_plan_precede_hook_and_failure_is_not_replayed() {
        let request = request(
            PerfOperation::Stop,
            Some(ControllerFaultAction::Trace32DisconnectAtStop),
        );
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut host = FakeHost::new(request.clone());
        host.events = Rc::clone(&events);
        let hooks = FakeHooks {
            fault_error: true,
            events: Rc::clone(&events),
            ..FakeHooks::healthy()
        };
        let transport = FakeTransport::with_events(Rc::clone(&events));
        let error = outcome_error(run_driver(drive_trace32_disconnect_transaction(
            &host,
            transport,
            &hooks,
            1_000,
            Path::new("E:/artifacts"),
            "driver-test",
            &"3".repeat(32),
            &request,
        )));
        assert_eq!(error.code, "CONTROLLER_DRIVER_FAULT_SIDE_EFFECT_FAILED");
        let first_events = events.borrow().clone();
        let fault_intent = first_events
            .iter()
            .position(|event| *event == "fault_intent")
            .unwrap();
        let plan = first_events
            .iter()
            .position(|event| *event == "plan")
            .unwrap();
        let hook = first_events
            .iter()
            .position(|event| *event == "fault_hook")
            .unwrap();
        assert!(fault_intent < plan && plan < hook);
        assert_eq!(hooks.fault_calls.get(), 1);
        assert_eq!(host.fault_intents.get(), 1);
        assert_eq!(host.fault_triggers.get(), 0);
        assert_eq!(host.abort_attempts.get(), 0);
        assert_eq!(host.confirms.get(), 0);

        let retry_transport = FakeTransport::with_events(Rc::clone(&events));
        let retry = outcome_error(run_driver(drive_trace32_disconnect_transaction(
            &host,
            retry_transport,
            &hooks,
            1_000,
            Path::new("E:/artifacts"),
            "driver-test",
            &"3".repeat(32),
            &request,
        )));
        assert_eq!(retry.code, "CONTROLLER_DRIVER_FAULT_AMBIGUOUS");
        assert_eq!(hooks.fault_calls.get(), 1);
        assert_eq!(host.fault_intents.get(), 1);
        assert_eq!(host.confirms.get(), 0);
    }

    #[test]
    fn completed_trace32_disconnect_is_marked_before_deadline_failure() {
        let request = request(
            PerfOperation::Stop,
            Some(ControllerFaultAction::Trace32DisconnectAtStop),
        );
        let host = FakeHost::new(request.clone());
        let hooks = FakeHooks {
            fault_late_success: true,
            ..FakeHooks::healthy()
        };
        let transport = FakeTransport::new(Vec::new(), Vec::new());
        let error = outcome_error(run_driver(drive_trace32_disconnect_transaction(
            &host,
            transport,
            &hooks,
            50,
            Path::new("E:/artifacts"),
            "driver-test",
            &"3".repeat(32),
            &request,
        )));
        assert_eq!(error.code, "CONTROLLER_DRIVER_TIMEOUT");
        assert_eq!(host.fault_triggers.get(), 1);
        assert_eq!(host.abort_attempts.get(), 0);
    }

    #[test]
    fn trace32_abort_tool_failure_is_ambiguous_and_never_auto_retried() {
        let request = request(
            PerfOperation::Stop,
            Some(ControllerFaultAction::Trace32DisconnectAtStop),
        );
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut host = FakeHost::new(request.clone());
        host.events = Rc::clone(&events);
        let hooks = FakeHooks {
            events: Rc::clone(&events),
            ..FakeHooks::healthy()
        };
        let transport = FakeTransport {
            abort_error: true,
            events: Rc::clone(&events),
            ..FakeTransport::new(Vec::new(), Vec::new())
        };
        let error = outcome_error(run_driver(drive_trace32_disconnect_transaction(
            &host,
            transport,
            &hooks,
            1_000,
            Path::new("E:/artifacts"),
            "driver-test",
            &"3".repeat(32),
            &request,
        )));
        assert_eq!(error.code, "CONTROLLER_DRIVER_ABORT_AMBIGUOUS");
        assert_eq!(
            events
                .borrow()
                .iter()
                .filter(|event| **event == "abort")
                .count(),
            1
        );

        let retry_transport = FakeTransport::with_events(Rc::clone(&events));
        let retry = outcome_error(run_driver(drive_trace32_disconnect_transaction(
            &host,
            retry_transport,
            &hooks,
            1_000,
            Path::new("E:/artifacts"),
            "driver-test",
            &"3".repeat(32),
            &request,
        )));
        assert_eq!(retry.code, "CONTROLLER_DRIVER_ABORT_AMBIGUOUS");
        assert_eq!(
            events
                .borrow()
                .iter()
                .filter(|event| **event == "abort")
                .count(),
            1
        );
        assert_eq!(hooks.fault_calls.get(), 1);
    }

    #[test]
    fn shutdown_failure_after_abort_confirmation_is_explicit_cleanup_failure() {
        let request = request(
            PerfOperation::Stop,
            Some(ControllerFaultAction::Trace32DisconnectAtStop),
        );
        let host = FakeHost::new(request.clone());
        let hooks = FakeHooks::healthy();
        let transport = FakeTransport {
            shutdown_error: true,
            ..FakeTransport::new(Vec::new(), Vec::new())
        };
        let error = outcome_error(run_driver(drive_trace32_disconnect_transaction(
            &host,
            transport,
            &hooks,
            1_000,
            Path::new("E:/artifacts"),
            "driver-test",
            &"3".repeat(32),
            &request,
        )));
        assert_eq!(error.code, "CONTROLLER_DRIVER_CLEANUP_FAILED");
        assert_eq!(host.confirms.get(), 1);
        assert!(host.transaction.borrow().abort_confirmed);
    }

    #[test]
    fn driver_disconnect_consumes_the_exact_transport() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let transport = FakeTransport::with_events(Rc::clone(&events));
        run_driver(arm_driver_disconnect_fault(
            transport,
            &DriverBudget::new(1_000),
        ))
        .unwrap();
        assert_eq!(events.borrow().as_slice(), ["force_disconnect"]);
    }

    #[test]
    fn failed_exact_driver_disconnect_is_not_retried_by_the_boundary() {
        let transport = FakeTransport {
            force_disconnect_error: true,
            ..FakeTransport::new(Vec::new(), Vec::new())
        };
        let error = run_driver(arm_driver_disconnect_fault(
            transport,
            &DriverBudget::new(1_000),
        ))
        .unwrap_err();
        assert!(error.message.contains("forced disconnect failed"));
    }

    #[test]
    fn pre_force_driver_error_still_finishes_the_original_client() {
        let request = request(
            PerfOperation::Export,
            Some(ControllerFaultAction::DriverDisconnectAtExport),
        );
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut host = FakeHost::new(request.clone());
        host.events = Rc::clone(&events);
        host.revalidate_error = true;
        let transport = FakeTransport {
            events: Rc::clone(&events),
            ..FakeTransport::new(Vec::new(), Vec::new())
        };

        let error = outcome_error(run_driver(drive_driver_disconnect_transaction(
            &host,
            transport,
            1_000,
            "driver-test",
            &"3".repeat(32),
            &request,
            |_| async { Ok(FakeTransport::with_events(Rc::clone(&events))) },
        )));
        assert_eq!(error.code, "OPERATIONAL_ERROR");
        assert_eq!(events.borrow().as_slice(), ["revalidate", "shutdown"]);
    }

    #[test]
    fn driver_disconnect_executes_export_before_forcing_exact_child_then_uses_one_replacement() {
        let request = request(
            PerfOperation::Export,
            Some(ControllerFaultAction::DriverDisconnectAtExport),
        );
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut host = FakeHost::new(request.clone());
        host.events = Rc::clone(&events);
        let primary = FakeTransport {
            events: Rc::clone(&events),
            ..FakeTransport::new(
                vec!["<NOT FINISHED>\n<CONTENT>\npartial export output\n"],
                Vec::new(),
            )
        };
        let replacement = FakeTransport::with_events(Rc::clone(&events));
        let replacement_calls = Cell::new(0);
        let error = outcome_error(run_driver(drive_driver_disconnect_transaction(
            &host,
            primary,
            1_000,
            "driver-test",
            &"3".repeat(32),
            &request,
            |_| async {
                replacement_calls.set(replacement_calls.get() + 1);
                Ok(replacement)
            },
        )));
        assert_eq!(error.code, "CONTROLLER_FAULT_INJECTED");
        assert_eq!(replacement_calls.get(), 1);
        let events = events.borrow();
        let execute = events.iter().position(|event| *event == "execute").unwrap();
        let fault_intent = events
            .iter()
            .position(|event| *event == "fault_intent")
            .unwrap();
        let plan = events.iter().position(|event| *event == "plan").unwrap();
        let disconnect = events
            .iter()
            .position(|event| *event == "force_disconnect")
            .unwrap();
        let abort = events.iter().position(|event| *event == "abort").unwrap();
        assert!(execute < fault_intent);
        assert!(fault_intent < plan);
        assert!(plan < disconnect);
        assert!(disconnect < abort);
        assert_eq!(host.dispatches.get(), 1);
        assert_eq!(host.fault_intents.get(), 1);
        assert_eq!(host.fault_triggers.get(), 1);
        assert_eq!(host.abort_attempts.get(), 1);
        assert_eq!(host.abort_successes.get(), 1);
        assert_eq!(host.confirms.get(), 1);
    }

    #[test]
    fn exact_forced_disconnect_is_marked_before_deadline_failure() {
        let request = request(
            PerfOperation::Export,
            Some(ControllerFaultAction::DriverDisconnectAtExport),
        );
        let host = FakeHost::new(request.clone());
        let primary = FakeTransport {
            force_disconnect_late_success: true,
            ..FakeTransport::new(vec!["<NOT FINISHED>\n<CONTENT>\n"], Vec::new())
        };
        let error = outcome_error(run_driver(drive_driver_disconnect_transaction(
            &host,
            primary,
            25,
            "driver-test",
            &"3".repeat(32),
            &request,
            |_| async { Ok(FakeTransport::new(Vec::new(), Vec::new())) },
        )));
        assert_eq!(error.code, "CONTROLLER_DRIVER_TIMEOUT");
        assert_eq!(host.fault_triggers.get(), 1);
        assert_eq!(host.abort_attempts.get(), 0);
    }

    #[test]
    fn forced_disconnect_cleanup_diagnostic_marks_then_retries_only_abort() {
        let request = request(
            PerfOperation::Export,
            Some(ControllerFaultAction::DriverDisconnectAtExport),
        );
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut host = FakeHost::new(request.clone());
        host.events = Rc::clone(&events);
        let first = FakeTransport {
            force_disconnect_cleanup_diagnostic: Some("stderr collector timed out"),
            events: Rc::clone(&events),
            ..FakeTransport::new(vec!["<NOT FINISHED>\n<CONTENT>\n"], Vec::new())
        };
        let first_error = outcome_error(run_driver(drive_driver_disconnect_transaction(
            &host,
            first,
            1_000,
            "driver-test",
            &"3".repeat(32),
            &request,
            |_| async { Ok(FakeTransport::with_events(Rc::clone(&events))) },
        )));
        assert_eq!(first_error.code, "OPERATIONAL_ERROR");
        assert_eq!(host.fault_triggers.get(), 1);

        let retry = outcome_error(run_driver(drive_driver_disconnect_transaction(
            &host,
            FakeTransport::with_events(Rc::clone(&events)),
            1_000,
            "driver-test",
            &"3".repeat(32),
            &request,
            |_| async { Ok(FakeTransport::with_events(Rc::clone(&events))) },
        )));
        assert_eq!(retry.code, "CONTROLLER_DRIVER_ABORT_RECOVERED");
        assert_eq!(
            events
                .borrow()
                .iter()
                .filter(|event| **event == "force_disconnect")
                .count(),
            1
        );
        assert_eq!(host.abort_attempts.get(), 1);
    }

    #[test]
    fn replacement_factory_overrun_is_shutdown_without_abort() {
        let request = request(
            PerfOperation::Export,
            Some(ControllerFaultAction::DriverDisconnectAtExport),
        );
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut host = FakeHost::new(request.clone());
        host.events = Rc::clone(&events);
        let primary = FakeTransport {
            events: Rc::clone(&events),
            ..FakeTransport::new(vec!["<NOT FINISHED>\n<CONTENT>\n"], Vec::new())
        };
        let error = outcome_error(run_driver(drive_driver_disconnect_transaction(
            &host,
            primary,
            25,
            "driver-test",
            &"3".repeat(32),
            &request,
            |_| async {
                tokio::time::sleep(Duration::from_millis(75)).await;
                Ok(FakeTransport::with_events(Rc::clone(&events)))
            },
        )));
        assert_eq!(error.code, "CONTROLLER_DRIVER_TIMEOUT");
        assert!(events.borrow().contains(&"shutdown"));
        assert_eq!(host.abort_attempts.get(), 0);
    }

    #[test]
    fn driver_disconnect_final_response_is_staged_for_host_fault_miss_rejection() {
        let request = request(
            PerfOperation::Export,
            Some(ControllerFaultAction::DriverDisconnectAtExport),
        );
        let mut host = FakeHost::new(request.clone());
        host.accept_error = Some("CONTROLLER_FAULT_ACTION_NOT_OBSERVED");
        let primary = FakeTransport::new(vec!["bounded-final-response"], Vec::new());
        let replacement_calls = Cell::new(0);
        let error = outcome_error(run_driver(drive_driver_disconnect_transaction(
            &host,
            primary,
            1_000,
            "driver-test",
            &"3".repeat(32),
            &request,
            |_| async {
                replacement_calls.set(replacement_calls.get() + 1);
                Ok(FakeTransport::new(Vec::new(), Vec::new()))
            },
        )));
        assert_eq!(error.code, "CONTROLLER_FAULT_ACTION_NOT_OBSERVED");
        assert_eq!(host.staged.borrow().as_slice(), [b"bounded-final-response"]);
        assert_eq!(host.accepts.get(), 1);
        assert_eq!(host.fault_intents.get(), 0);
        assert_eq!(host.plans.get(), 0);
        assert_eq!(replacement_calls.get(), 0);
    }

    #[test]
    fn driver_disconnect_side_effect_failure_is_not_aborted_or_replayed() {
        let request = request(
            PerfOperation::Export,
            Some(ControllerFaultAction::DriverDisconnectAtExport),
        );
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut host = FakeHost::new(request.clone());
        host.events = Rc::clone(&events);
        let primary = FakeTransport {
            force_disconnect_error: true,
            events: Rc::clone(&events),
            ..FakeTransport::new(vec!["<NOT FINISHED>\n<CONTENT>\n"], Vec::new())
        };
        let replacement_calls = Cell::new(0);
        let error = outcome_error(run_driver(drive_driver_disconnect_transaction(
            &host,
            primary,
            1_000,
            "driver-test",
            &"3".repeat(32),
            &request,
            |_| async {
                replacement_calls.set(replacement_calls.get() + 1);
                Ok(FakeTransport::with_events(Rc::clone(&events)))
            },
        )));
        assert_eq!(error.code, "CONTROLLER_DRIVER_FAULT_SIDE_EFFECT_FAILED");
        assert_eq!(
            events
                .borrow()
                .iter()
                .filter(|event| **event == "force_disconnect")
                .count(),
            1
        );
        assert_eq!(replacement_calls.get(), 0);
        assert_eq!(host.fault_triggers.get(), 0);
        assert_eq!(host.abort_attempts.get(), 0);

        let retry = outcome_error(run_driver(drive_driver_disconnect_transaction(
            &host,
            FakeTransport::with_events(Rc::clone(&events)),
            1_000,
            "driver-test",
            &"3".repeat(32),
            &request,
            |_| async {
                replacement_calls.set(replacement_calls.get() + 1);
                Ok(FakeTransport::with_events(Rc::clone(&events)))
            },
        )));
        assert_eq!(retry.code, "CONTROLLER_DRIVER_FAULT_AMBIGUOUS");
        assert_eq!(
            events
                .borrow()
                .iter()
                .filter(|event| **event == "force_disconnect")
                .count(),
            1
        );
        assert_eq!(replacement_calls.get(), 0);
        assert_eq!(
            events
                .borrow()
                .iter()
                .filter(|event| **event == "abort")
                .count(),
            0
        );
    }

    #[test]
    fn abort_success_is_confirmed_immediately() {
        let request = request(PerfOperation::Start, None);
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut host = FakeHost::new(request.clone());
        host.events = Rc::clone(&events);
        let transport = FakeTransport::with_events(Rc::clone(&events));
        host.plan_abort("driver-test", &"3".repeat(32), "timeout")
            .unwrap();
        let mut abort = DriverAbortState {
            planned: true,
            attempted: false,
            success_observed: false,
            confirmed: false,
        };
        run_driver(official_abort_and_confirm(
            &host,
            &transport,
            &DriverBudget::new(1_000),
            "driver-test",
            &"3".repeat(32),
            &request,
            &mut abort,
        ))
        .unwrap();
        assert_eq!(
            events.borrow().as_slice(),
            [
                "plan",
                "revalidate",
                "abort_attempt",
                "abort",
                "abort_success",
                "confirm"
            ]
        );
    }

    #[test]
    fn abort_plan_replay_rejects_a_different_reason() {
        let request = request(PerfOperation::Start, None);
        let host = FakeHost::new(request);
        let mut state = DriverAbortState {
            planned: false,
            attempted: false,
            success_observed: false,
            confirmed: false,
        };
        ensure_abort_planned(&host, &mut state, "driver-test", &"3".repeat(32), "timeout").unwrap();
        let error = ensure_abort_planned(
            &host,
            &mut state,
            "driver-test",
            &"3".repeat(32),
            "operator_request",
        )
        .unwrap_err();
        assert_eq!(error.code, "OPERATIONAL_ERROR");
        assert_eq!(host.plans.get(), 1);
    }

    #[test]
    fn preexisting_abort_recovery_rechecks_its_exact_reason() {
        let request = request(PerfOperation::Start, None);
        let host = FakeHost::new(request);
        host.plan_abort("driver-test", &"3".repeat(32), "operator_request")
            .unwrap();
        let transaction = host.transaction("driver-test", &"3".repeat(32)).unwrap();
        let transport = FakeTransport::new(Vec::new(), Vec::new());
        let error = run_driver(async {
            Err::<(), _>(
                recover_preexisting_abort(
                    &host,
                    &transport,
                    &DriverBudget::new(1_000),
                    "driver-test",
                    &"3".repeat(32),
                    &transaction,
                )
                .await,
            )
        });
        let error = error.unwrap_err();
        assert_eq!(error.code, "OPERATIONAL_ERROR");
        assert_eq!(transport.abort_calls.get(), 0);
        assert_eq!(host.plans.get(), 1);
    }

    #[test]
    fn surface_loop_has_a_fixed_iteration_bound() {
        let request = request(PerfOperation::GetHotspots, None);
        let mut host = FakeHost::new(request);
        host.fallback_surface = Some(invoke_payload());
        let transport = FakeTransport::new(Vec::new(), Vec::new());
        let hooks = FakeHooks::healthy();
        let error = outcome_error(run_driver(drive_surface_core(
            &host,
            &transport,
            &hooks,
            "driver-test",
            ControllerDriveSurface::Capture,
            None,
            1,
            10_000,
        )));
        assert_eq!(error.code, "CONTROLLER_DRIVER_LOOP_LIMIT");
        assert_eq!(host.surface_calls.borrow().len(), MAX_DRIVER_ITERATIONS);
    }
}
