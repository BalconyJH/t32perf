//! Closed request construction and durable create-or-resume boundary for `perf_run`.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

use sha2::{Digest as _, Sha256};
use t32perf_model::{
    ArtifactPath, HealthReport, HealthVerdict, HotspotReport, PerfRunPayload, PerfRunSummary,
    PerfTrustStatus, PerformanceReportFormat, PerformanceRunPhase, PerformanceRunRequest,
    PerformanceRunRequestSchemaVersion, SessionError, SessionStatus, Sha256Digest,
};
use t32perf_session::{ArtifactRoot, Session, SessionId, verify_opened_plain_file_identity};

use crate::app::{AppError, CommandOutcome, EXIT_SUCCESS};
use crate::cli::{ControllerProvisionQualificationArgs, ControllerSelectScenarioArgs};

const PERF_RUN_CONTROL_DIRECTORY: &str = "perf-run";
static ACTIVE_SESSION_ID_EXECUTIONS: OnceLock<Mutex<BTreeSet<PathBuf>>> = OnceLock::new();

/// Per-Session identifier reservation used briefly by ordinary creation and
/// held for the complete lifecycle of strict performance-run orchestration.
pub(crate) struct SessionIdExecutionLease {
    file: File,
    lease_path: PathBuf,
}

/// Creates or resumes the immutable `perf_run` request boundary.
///
/// The subsequent provision/control/normalization/attestation stages are
/// deliberately driven only after this request has been durably bound to the
/// Session; callers cannot provide deployment paths, policies, or executables.
pub(crate) fn run(
    root: &ArtifactRoot,
    duration_ms: u64,
    requested_id: Option<&str>,
    top: u8,
) -> Result<CommandOutcome, AppError> {
    preflight_performance_run_request(duration_ms, requested_id, top)?;
    let request = validated_performance_run_request(duration_ms, top)?;
    let session_id = requested_id
        .map(|id| SessionId::new(id.to_owned()).map_err(AppError::operational))
        .transpose()?
        .unwrap_or_else(SessionId::generate);
    let _session_execution_lease = try_acquire_session_id_execution_lease(root, &session_id)?;
    let existing = existing_performance_run_session(root, &session_id, &request)?;
    let (deployment_bound, receipt_bound) = existing
        .as_ref()
        .map(|session| {
            session
                .registered_artifacts(true)
                .map(|artifacts| {
                    (
                        artifacts.iter().any(|artifact| {
                            artifact.id
                                == crate::target_adapter_provisioning::PERFORMANCE_RUN_DEPLOYMENT_BINDING_ID
                        }),
                        artifacts.iter().any(|artifact| {
                            artifact.id
                                == crate::target_adapter_provisioning::PERFORMANCE_RUN_PROVISIONING_RECEIPT_ID
                        }),
                    )
                })
                .map_err(AppError::operational)
        })
        .transpose()?
        .unwrap_or((false, false));
    let initial = crate::controller_driver::load_receipt_bound_driver_config(root)
        .map_err(AppError::operational)?;
    let deployment_mode = match (existing.is_some(), deployment_bound, receipt_bound) {
        (false, _, _) | (true, false, false) => DeploymentMode::Fresh,
        (true, true, false) => DeploymentMode::PartialResume,
        (true, _, true) => DeploymentMode::ReceiptBound,
    };
    let loaded = if deployment_mode == DeploymentMode::Fresh {
        crate::controller_driver::revalidate_loaded_driver_config(root, &initial)
            .map_err(AppError::operational)?
    } else {
        let loaded =
            crate::controller_driver::revalidate_receipt_bound_driver_config(root, &initial)
                .map_err(AppError::operational)?;
        if deployment_mode == DeploymentMode::ReceiptBound {
            let session = existing
                .as_ref()
                .expect("receipt-bound admission requires an existing Session");
            let artifacts = session
                .registered_artifacts(true)
                .map_err(AppError::operational)?;
            crate::target_adapter_provisioning::require_performance_run_provisioning_receipt(
                session, &artifacts, &loaded,
            )?;
        }
        loaded
    };
    let deployment = crate::controller_driver::require_performance_run_config(&loaded)
        .map_err(AppError::operational)?;
    ensure_duration_admitted(request.duration_ns, deployment.max_duration_ns)?;
    let orchestrator = ProductionOrchestrator {
        initial: &loaded,
        deployment_mode,
    };
    let outcome = run_with_session_id(
        root,
        request,
        session_id,
        deployment.max_duration_ns,
        &orchestrator,
    )?;
    let payload: PerfRunPayload =
        serde_json::from_value(outcome.result.clone()).map_err(AppError::operational)?;
    if payload.state != SessionStatus::Complete {
        return Err(AppError::operational(
            "perf_run production orchestration returned before the Session was complete",
        ));
    }
    let verdict = payload
        .health_verdict
        .ok_or_else(|| AppError::operational("complete perf_run payload lacks health verdict"))?;
    Ok(CommandOutcome {
        command: outcome.command,
        result: outcome.result,
        exit_code: crate::app::health_exit_code(verdict),
    })
}

fn preflight_performance_run_request(
    duration_ms: u64,
    requested_id: Option<&str>,
    top: u8,
) -> Result<(), AppError> {
    validated_performance_run_request(duration_ms, top)?;
    requested_id
        .map(|id| SessionId::new(id.to_owned()).map_err(AppError::operational))
        .transpose()?;
    Ok(())
}

fn validated_performance_run_request(
    duration_ms: u64,
    top: u8,
) -> Result<PerformanceRunRequest, AppError> {
    let duration_ns = duration_ms
        .checked_mul(1_000_000)
        .ok_or_else(|| AppError::operational("perf_run duration-ms overflows nanoseconds"))?;
    let request = PerformanceRunRequest {
        schema: PerformanceRunRequestSchemaVersion,
        duration_ns,
        top,
        report_format: PerformanceReportFormat::PerfettoJson,
    };
    request.validate().map_err(AppError::operational)?;
    Ok(request)
}

fn existing_performance_run_session(
    root: &ArtifactRoot,
    session_id: &SessionId,
    expected: &PerformanceRunRequest,
) -> Result<Option<Session>, AppError> {
    let session = match root.session(session_id) {
        Ok(session) => session,
        Err(t32perf_session::SessionStoreError::SessionNotFound { .. }) => return Ok(None),
        Err(error) => return Err(AppError::operational(error)),
    };
    let existing: PerformanceRunRequest =
        serde_json::from_value(session.request().map_err(AppError::operational)?).map_err(
            |_| AppError::operational("existing Session request is not a strict perf_run request"),
        )?;
    existing.validate().map_err(AppError::operational)?;
    if &existing != expected {
        return Err(AppError::operational(
            "perf_run request conflicts with the immutable request bound to this Session",
        ));
    }
    Ok(Some(session))
}

/// The durable orchestration boundary for a one-shot performance run.
///
/// The production implementation is deliberately the only implementation that
/// can reach deployment hooks, the MCP controller, or the external signer.
/// Keeping the state-machine seam here makes recovery tests entirely offline.
trait PerfRunOrchestrator {
    fn verify_deployment_binding(
        &self,
        _root: &ArtifactRoot,
        _session: &Session,
    ) -> Result<(), AppError> {
        Ok(())
    }

    fn provision_and_control(
        &self,
        root: &ArtifactRoot,
        session: &Session,
        duration_ns: u64,
    ) -> Result<bool, AppError>;

    /// Re-enters only the controller recovery path for an interrupted capture.
    /// Provisioning is already durable for a `capturing` Session and must not
    /// be replayed.
    fn control(
        &self,
        root: &ArtifactRoot,
        session: &Session,
        duration_ns: u64,
    ) -> Result<bool, AppError>;

    fn control_complete(&self, _root: &ArtifactRoot, _session: &Session) -> Result<bool, AppError> {
        Ok(true)
    }

    fn normalize(&self, root: &ArtifactRoot, session: &Session) -> Result<bool, AppError>;

    fn attest(&self, root: &ArtifactRoot, session: &Session) -> Result<bool, AppError>;

    fn analyze(&self, root: &ArtifactRoot, session: &Session) -> Result<bool, AppError>;

    fn convert(&self, root: &ArtifactRoot, session: &Session) -> Result<bool, AppError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeploymentMode {
    Fresh,
    PartialResume,
    ReceiptBound,
}

struct ProductionOrchestrator<'a> {
    initial: &'a crate::controller_driver::LoadedDriverConfig,
    deployment_mode: DeploymentMode,
}

impl ProductionOrchestrator<'_> {
    fn has_provisioning_receipt(&self, session: &Session) -> Result<bool, AppError> {
        Ok(session
            .registered_artifacts(true)
            .map_err(AppError::operational)?
            .iter()
            .any(|artifact| {
                artifact.id
                    == crate::target_adapter_provisioning::PERFORMANCE_RUN_PROVISIONING_RECEIPT_ID
            }))
    }

    fn revalidate_for_session(
        &self,
        root: &ArtifactRoot,
        session: &Session,
    ) -> Result<crate::controller_driver::LoadedDriverConfig, AppError> {
        if self.deployment_mode != DeploymentMode::Fresh
            || self.has_provisioning_receipt(session)?
        {
            crate::controller_driver::revalidate_receipt_bound_driver_config(root, self.initial)
                .map_err(AppError::operational)
        } else {
            crate::controller_driver::revalidate_loaded_driver_config(root, self.initial)
                .map_err(AppError::operational)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResumeBindingRequirement {
    None,
    Deployment,
    DeploymentAndWorkload,
}

const fn resume_binding_requirement(status: SessionStatus) -> ResumeBindingRequirement {
    match status {
        SessionStatus::Created | SessionStatus::Failed => ResumeBindingRequirement::None,
        SessionStatus::Capturing => ResumeBindingRequirement::Deployment,
        SessionStatus::Captured | SessionStatus::Processing | SessionStatus::Complete => {
            ResumeBindingRequirement::DeploymentAndWorkload
        }
    }
}

impl PerfRunOrchestrator for ProductionOrchestrator<'_> {
    fn verify_deployment_binding(
        &self,
        root: &ArtifactRoot,
        session: &Session,
    ) -> Result<(), AppError> {
        let state = session.read_state().map_err(AppError::operational)?;
        match resume_binding_requirement(state.status) {
            ResumeBindingRequirement::None => Ok(()),
            ResumeBindingRequirement::Deployment => {
                let _lease = crate::controller_driver::lease::try_acquire(root)?;
                let loaded = self.revalidate_for_session(root, session)?;
                verify_performance_run_deployment(session, &loaded)
            }
            ResumeBindingRequirement::DeploymentAndWorkload => {
                let _lease = crate::controller_driver::lease::try_acquire(root)?;
                let loaded = self.revalidate_for_session(root, session)?;
                verify_performance_run_deployment_and_workload(session, &loaded)
            }
        }
    }

    fn provision_and_control(
        &self,
        root: &ArtifactRoot,
        session: &Session,
        duration_ns: u64,
    ) -> Result<bool, AppError> {
        if self.deployment_mode == DeploymentMode::ReceiptBound
            || self.has_provisioning_receipt(session)?
        {
            let loaded = self.revalidate_for_session(root, session)?;
            verify_performance_run_deployment(session, &loaded)?;
        } else {
            provision(
                root,
                session.id().as_str(),
                self.initial,
                self.deployment_mode,
            )?;
        }
        self.control(root, session, duration_ns)
    }

    fn control(
        &self,
        root: &ArtifactRoot,
        session: &Session,
        duration_ns: u64,
    ) -> Result<bool, AppError> {
        crate::controller_driver::drive_performance_run_control(
            root,
            session.id().as_str(),
            duration_ns,
            self.initial,
        )?;
        Ok(false)
    }

    fn control_complete(&self, root: &ArtifactRoot, session: &Session) -> Result<bool, AppError> {
        Ok(
            crate::controller::controller_capture_progress(root, session.id().as_str())?.phase
                == crate::controller::ControllerCapturePhase::Complete,
        )
    }

    fn normalize(&self, root: &ArtifactRoot, session: &Session) -> Result<bool, AppError> {
        let loaded = self.revalidate_for_session(root, session)?;
        verify_performance_run_deployment_and_workload(session, &loaded)?;
        let normalize =
            crate::normalize::ensure_performance_run_normalize_config(root, session.id().as_str())?;
        let ensured = crate::normalize::ensure_normalized(
            root,
            session.id().as_str(),
            normalize.cli_input_artifact_id.as_deref(),
            &normalize.config_artifact.id,
        )?;
        Ok(ensured.resumed)
    }

    fn attest(&self, root: &ArtifactRoot, session: &Session) -> Result<bool, AppError> {
        attest(root, session.id().as_str(), self.initial)
    }

    fn analyze(&self, root: &ArtifactRoot, session: &Session) -> Result<bool, AppError> {
        let static_ram_flavor =
            crate::target_adapter_provisioning::performance_run_static_ram_flavor(root, session)?;
        let ensured = crate::pipeline::ensure_analyzed(
            root,
            session.id().as_str(),
            static_ram_flavor,
            "gcc-stack-usage-v1",
        )?;
        Ok(ensured.resumed)
    }

    fn convert(&self, root: &ArtifactRoot, session: &Session) -> Result<bool, AppError> {
        let ensured = crate::pipeline::ensure_converted(root, session.id().as_str())?;
        Ok(ensured.resumed)
    }
}

fn verify_performance_run_deployment(
    session: &Session,
    loaded: &crate::controller_driver::LoadedDriverConfig,
) -> Result<(), AppError> {
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

fn verify_performance_run_deployment_and_workload(
    session: &Session,
    loaded: &crate::controller_driver::LoadedDriverConfig,
) -> Result<(), AppError> {
    let artifacts = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    let binding = crate::target_adapter_provisioning::require_performance_run_deployment_binding(
        session, &artifacts, loaded,
    )?;
    crate::target_adapter_provisioning::require_performance_run_provisioning_receipt(
        session, &artifacts, loaded,
    )?;
    let Some((_artifact, document)) =
        crate::target_adapter_provisioning::workload_deployment_binding_claim(session, &artifacts)?
    else {
        return Err(AppError::operational(
            "performance-run deployment binding is absent",
        ));
    };
    crate::controller_journal::require_performance_run_workload_deployment_binding(
        session,
        &artifacts,
        &binding,
        &document.performance_run_deployment_sha256,
        &document.workload_executable_sha256,
    )
}

pub(crate) fn try_acquire_session_id_execution_lease(
    root: &ArtifactRoot,
    session_id: &SessionId,
) -> Result<SessionIdExecutionLease, AppError> {
    let directory = root
        .path()
        .join(".t32perf-control")
        .join(PERF_RUN_CONTROL_DIRECTORY);
    ensure_plain_orchestration_directory(
        directory
            .parent()
            .expect("Session execution control directory has a parent"),
    )?;
    ensure_plain_orchestration_directory(&directory)?;
    let lease_path = directory.join(format!("{}.lock", session_id.as_str()));
    let mut active = ACTIVE_SESSION_ID_EXECUTIONS
        .get_or_init(|| Mutex::new(BTreeSet::new()))
        .lock()
        .map_err(|_| AppError::operational("Session execution registry is poisoned"))?;
    if !active.insert(lease_path.clone()) {
        return Err(session_execution_busy(session_id.as_str()));
    }
    drop(active);

    let result = open_orchestration_lease(&lease_path, session_id.as_str()).map(|file| {
        SessionIdExecutionLease {
            file,
            lease_path: lease_path.clone(),
        }
    });
    if result.is_err() {
        release_orchestration_process_claim(&lease_path);
    }
    result
}

fn ensure_plain_orchestration_directory(path: &Path) -> Result<(), AppError> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(AppError::operational(error)),
    }
    let metadata = fs::symlink_metadata(path).map_err(AppError::operational)?;
    if !metadata.is_dir() || orchestration_path_is_link_like(&metadata) {
        return Err(AppError::operational(format!(
            "Session execution control directory `{}` is not a plain directory",
            path.display()
        )));
    }
    Ok(())
}

fn orchestration_path_is_link_like(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

fn open_orchestration_lease(path: &Path, session_id: &str) -> Result<File, AppError> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| {
            AppError::operational(format!(
                "open Session execution lease `{}`: {error}",
                path.display()
            ))
        })?;
    verify_orchestration_lease(path, &file)?;
    if let Err(error) = fs2::FileExt::try_lock_exclusive(&file) {
        return Err(if orchestration_lock_is_contended(&error) {
            session_execution_busy(session_id)
        } else {
            AppError::operational(format!(
                "lock Session execution lease `{}`: {error}",
                path.display()
            ))
        });
    }
    if let Err(error) = verify_orchestration_lease(path, &file) {
        let _ = fs2::FileExt::unlock(&file);
        return Err(error);
    }
    Ok(file)
}

fn orchestration_lock_is_contended(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(windows)]
    {
        const ERROR_LOCK_VIOLATION: i32 = 33;
        if error.raw_os_error() == Some(ERROR_LOCK_VIOLATION) {
            return true;
        }
    }
    false
}

fn verify_orchestration_lease(path: &Path, file: &File) -> Result<(), AppError> {
    verify_opened_plain_file_identity(path, file).map_err(|error| {
        AppError::operational(format!(
            "verify Session execution lease `{}`: {error}",
            path.display()
        ))
    })?;
    let metadata = file.metadata().map_err(|error| {
        AppError::operational(format!(
            "inspect Session execution lease `{}`: {error}",
            path.display()
        ))
    })?;
    if metadata.len() != 0 {
        return Err(AppError::operational(format!(
            "Session execution lease `{}` must remain empty",
            path.display()
        )));
    }
    Ok(())
}

fn session_execution_busy(session_id: &str) -> AppError {
    AppError {
        code: "SESSION_EXECUTION_BUSY",
        message: format!("Session `{session_id}` already has an active mutation or creation"),
        details: serde_json::json!({
            "session_id": session_id,
            "scope": "session_id",
        }),
        exit_code: crate::app::EXIT_OPERATIONAL,
    }
}

fn release_orchestration_process_claim(session_path: &Path) {
    if let Ok(mut active) = ACTIVE_SESSION_ID_EXECUTIONS
        .get_or_init(|| Mutex::new(BTreeSet::new()))
        .lock()
    {
        active.remove(session_path);
    }
}

impl Drop for SessionIdExecutionLease {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
        release_orchestration_process_claim(&self.lease_path);
    }
}

#[cfg(test)]
fn run_with<O: PerfRunOrchestrator>(
    root: &ArtifactRoot,
    duration_ms: u64,
    requested_id: Option<&str>,
    top: u8,
    orchestrator: &O,
) -> Result<CommandOutcome, AppError> {
    run_with_max_duration(
        root,
        duration_ms,
        requested_id,
        top,
        t32perf_trace32::MAX_PERFORMANCE_RUN_DURATION_NS,
        orchestrator,
    )
}

#[cfg(test)]
fn run_with_max_duration<O: PerfRunOrchestrator>(
    root: &ArtifactRoot,
    duration_ms: u64,
    requested_id: Option<&str>,
    top: u8,
    max_duration_ns: u64,
    orchestrator: &O,
) -> Result<CommandOutcome, AppError> {
    let request = validated_performance_run_request(duration_ms, top)?;
    let session_id = requested_id
        .map(|id| SessionId::new(id.to_owned()).map_err(AppError::operational))
        .transpose()?
        .unwrap_or_else(SessionId::generate);
    let _session_execution_lease = try_acquire_session_id_execution_lease(root, &session_id)?;
    run_with_session_id(root, request, session_id, max_duration_ns, orchestrator)
}

/// Drives an already-reserved Session identifier. Callers must hold its
/// [`SessionIdExecutionLease`] for this function's complete lifetime.
fn run_with_session_id<O: PerfRunOrchestrator>(
    root: &ArtifactRoot,
    request: PerformanceRunRequest,
    session_id: SessionId,
    max_duration_ns: u64,
    orchestrator: &O,
) -> Result<CommandOutcome, AppError> {
    request.validate().map_err(AppError::operational)?;
    ensure_duration_admitted(request.duration_ns, max_duration_ns)?;
    let request_value = serde_json::to_value(&request).map_err(AppError::operational)?;
    let (session, resumed) = match root.create_session_with_id(session_id.clone(), &request_value) {
        Ok(session) => (session, false),
        Err(t32perf_session::SessionStoreError::SessionExists { .. }) => {
            let session = root.session(&session_id).map_err(AppError::operational)?;
            let existing: PerformanceRunRequest = serde_json::from_value(
                session.request().map_err(AppError::operational)?,
            )
            .map_err(|_| {
                AppError::operational("existing Session request is not a strict perf_run request")
            })?;
            existing.validate().map_err(AppError::operational)?;
            if existing != request {
                return Err(AppError::operational(
                    "perf_run request conflicts with the immutable request bound to this Session",
                ));
            }
            (session, true)
        }
        Err(error) => return Err(AppError::operational(error)),
    };
    let state = session.read_state().map_err(AppError::operational)?;
    if state.status == SessionStatus::Failed {
        return Err(AppError::operational(
            "perf_run refuses a failed Session without invoking control or deployment side effects",
        ));
    }
    orchestrator.verify_deployment_binding(root, &session)?;
    let mut resumed_stage = false;
    match state.status {
        SessionStatus::Created => {
            resumed_stage |=
                orchestrator.provision_and_control(root, &session, request.duration_ns)?
        }
        SessionStatus::Capturing => {
            resumed_stage |= orchestrator.control(root, &session, request.duration_ns)?
        }
        SessionStatus::Captured => {
            if !orchestrator.control_complete(root, &session)? {
                resumed_stage |= orchestrator.control(root, &session, request.duration_ns)?;
            }
        }
        SessionStatus::Processing | SessionStatus::Complete => {}
        SessionStatus::Failed => unreachable!("checked before orchestration"),
    }

    // Each durable boundary is reread before dispatch.  This makes a rerun
    // resume only the missing idempotent stage, rather than replaying a
    // controller/signing side effect after a process crash.
    let after_control = session.read_state().map_err(AppError::operational)?.status;
    if after_control == SessionStatus::Captured {
        if !orchestrator.control_complete(root, &session)? {
            return Err(AppError {
                code: "DRIVER_RESUME_REQUIRED",
                message: "controller capture is still incomplete after a recovery drive".to_owned(),
                details: serde_json::json!({
                    "session_id": session.id().as_str(),
                    "required_action": "resume the strict perf_run controller driver",
                }),
                exit_code: crate::app::EXIT_OPERATIONAL,
            });
        }
        resumed_stage |= terminal_host_stage(
            &session,
            PerfRunTerminalStage::Normalize,
            orchestrator.normalize(root, &session),
        )?;
        resumed_stage |= terminal_host_stage(
            &session,
            PerfRunTerminalStage::Attest,
            orchestrator.attest(root, &session),
        )?;
        resumed_stage |= terminal_host_stage(
            &session,
            PerfRunTerminalStage::Analyze,
            orchestrator.analyze(root, &session),
        )?;
        if session.read_state().map_err(AppError::operational)?.status == SessionStatus::Processing
        {
            resumed_stage |= terminal_host_stage(
                &session,
                PerfRunTerminalStage::Convert,
                orchestrator.convert(root, &session),
            )?;
        }
    } else if after_control == SessionStatus::Processing {
        resumed_stage |= terminal_host_stage(
            &session,
            PerfRunTerminalStage::Analyze,
            orchestrator.analyze(root, &session),
        )?;
        resumed_stage |= terminal_host_stage(
            &session,
            PerfRunTerminalStage::Convert,
            orchestrator.convert(root, &session),
        )?;
    }
    let payload =
        payload_for_session(&session, resumed || resumed_stage, usize::from(request.top))?;
    payload.validate().map_err(AppError::operational)?;
    Ok(CommandOutcome {
        command: "perf_run",
        result: serde_json::to_value(payload).map_err(AppError::operational)?,
        exit_code: EXIT_SUCCESS,
    })
}

#[derive(Clone, Copy)]
enum PerfRunTerminalStage {
    Normalize,
    Attest,
    Analyze,
    Convert,
}

impl PerfRunTerminalStage {
    const fn name(self) -> &'static str {
        match self {
            Self::Normalize => "normalize",
            Self::Attest => "attest",
            Self::Analyze => "analyze",
            Self::Convert => "convert",
        }
    }

    const fn code(self) -> &'static str {
        match self {
            Self::Normalize => "PERF_RUN_NORMALIZE_FAILED",
            Self::Attest => "PERF_RUN_ATTEST_FAILED",
            Self::Analyze => "PERF_RUN_ANALYZE_FAILED",
            Self::Convert => "PERF_RUN_CONVERT_FAILED",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::Normalize => "perf_run normalize stage failed",
            Self::Attest => "perf_run attest stage failed",
            Self::Analyze => "perf_run analyze stage failed",
            Self::Convert => "perf_run convert stage failed",
        }
    }
}

fn terminal_host_stage<T>(
    session: &Session,
    stage: PerfRunTerminalStage,
    result: Result<T, AppError>,
) -> Result<T, AppError> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            if error.is_nonterminal_retryable() {
                return Err(error);
            }
            persist_terminal_stage_failure(session, stage, &error)?;
            Err(error)
        }
    }
}

fn persist_terminal_stage_failure(
    session: &Session,
    stage: PerfRunTerminalStage,
    error: &AppError,
) -> Result<(), AppError> {
    let lock = session
        .try_lock()
        .map_err(|state_error| AppError::state_persistence(stage.name(), error, state_error))?;
    let state = session
        .read_state()
        .map_err(|state_error| AppError::state_persistence(stage.name(), error, state_error))?;
    if state.status == SessionStatus::Failed {
        return Ok(());
    }
    session
        .transition(
            &lock,
            SessionStatus::Failed,
            Some(SessionError {
                code: stage.code().to_owned(),
                message: stage.message().to_owned(),
                details: BTreeMap::from([
                    ("stage".to_owned(), serde_json::json!(stage.name())),
                    (
                        "cause_exit_code".to_owned(),
                        serde_json::json!(error.exit_code),
                    ),
                    ("cause_message".to_owned(), serde_json::json!(error.message)),
                ]),
            }),
        )
        .map(|_| ())
        .map_err(|state_error| AppError::state_persistence(stage.name(), error, state_error))
}

fn ensure_duration_admitted(duration_ns: u64, max_duration_ns: u64) -> Result<(), AppError> {
    if max_duration_ns == 0 || max_duration_ns > t32perf_trace32::MAX_PERFORMANCE_RUN_DURATION_NS {
        return Err(AppError::operational(
            "performance-run deployment max_duration_ns is outside the compiled bound",
        ));
    }
    if duration_ns == 0 {
        return Err(AppError::operational(
            "performance-run duration_ns must be nonzero",
        ));
    }
    if duration_ns > max_duration_ns {
        return Err(AppError::operational(format!(
            "performance-run duration_ns `{duration_ns}` exceeds deployment max_duration_ns `{max_duration_ns}`"
        )));
    }
    Ok(())
}

fn payload_for_session(
    session: &t32perf_session::Session,
    resumed: bool,
    top: usize,
) -> Result<PerfRunPayload, AppError> {
    let state = session.read_state().map_err(AppError::operational)?;
    if state.status != SessionStatus::Complete {
        let phase = match state.status {
            SessionStatus::Created => PerformanceRunPhase::Provision,
            SessionStatus::Capturing => PerformanceRunPhase::Control,
            SessionStatus::Captured => PerformanceRunPhase::Normalize,
            SessionStatus::Processing => PerformanceRunPhase::Analyze,
            SessionStatus::Complete | SessionStatus::Failed => unreachable!(),
        };
        return Ok(PerfRunPayload {
            session_id: session.id().to_string(),
            phase,
            state: state.status,
            trust_status: PerfTrustStatus::NotEvaluated,
            health_verdict: None,
            summary: None,
            report_artifact: None,
            manifest_sha256: None,
            resumed,
        });
    }
    let artifacts = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    let health_artifact = artifacts
        .iter()
        .find(|a| a.id == "health")
        .ok_or_else(|| AppError::operational("completed perf_run lacks health artifact"))?;
    let report = artifacts
        .iter()
        .find(|a| a.id == "perfetto")
        .ok_or_else(|| AppError::operational("completed perf_run lacks Perfetto artifact"))?
        .clone();
    let health: HealthReport = serde_json::from_reader(
        session
            .open_artifact(health_artifact)
            .map_err(AppError::operational)?,
    )
    .map_err(AppError::operational)?;
    let trust = match health.verdict {
        HealthVerdict::Valid => PerfTrustStatus::Valid,
        HealthVerdict::Degraded => PerfTrustStatus::Degraded,
        HealthVerdict::Invalid => PerfTrustStatus::Invalid,
    };
    let summary = if health.verdict == HealthVerdict::Valid {
        let artifact = artifacts
            .iter()
            .find(|artifact| artifact.id == "hotspots")
            .ok_or_else(|| {
                AppError::operational("VALID completed perf_run lacks hotspots artifact")
            })?;
        let hotspots: HotspotReport = serde_json::from_reader(
            session
                .open_artifact(artifact)
                .map_err(AppError::operational)?,
        )
        .map_err(AppError::operational)?;
        hotspots.validate().map_err(AppError::operational)?;
        Some(hotspot_summary(&hotspots, top)?)
    } else {
        None
    };
    let _manifest = session
        .manifest()
        .map_err(AppError::operational)?
        .ok_or_else(|| AppError::operational("completed perf_run lacks manifest"))?;
    let manifest_sha256 = manifest_digest(&session.path().join("manifest.json"))?;
    let payload = PerfRunPayload {
        session_id: session.id().to_string(),
        phase: PerformanceRunPhase::Complete,
        state: state.status,
        trust_status: trust,
        health_verdict: Some(health.verdict),
        summary,
        report_artifact: Some(report),
        manifest_sha256: Some(manifest_sha256),
        resumed,
    };
    payload.validate().map_err(AppError::operational)?;
    Ok(payload)
}

fn hotspot_summary(hotspots: &HotspotReport, top: usize) -> Result<PerfRunSummary, AppError> {
    let total = hotspots
        .functions
        .len()
        .checked_add(hotspots.sampling.len())
        .ok_or_else(|| AppError::operational("hotspot count overflow"))?;
    let returned = total.min(top);
    Ok(PerfRunSummary {
        hotspots_returned: u8::try_from(returned)
            .map_err(|_| AppError::operational("bounded hotspot count overflow"))?,
        hotspots_total: u64::try_from(total)
            .map_err(|_| AppError::operational("hotspot count overflow"))?,
        truncated: returned < total,
    })
}

fn manifest_digest(path: &Path) -> Result<Sha256Digest, AppError> {
    let manifest_bytes = fs::read(path).map_err(AppError::operational)?;
    Sha256Digest::new(lower_hex(&Sha256::digest(manifest_bytes))).map_err(AppError::operational)
}

fn attest(
    root: &ArtifactRoot,
    session_id: &str,
    initial: &crate::controller_driver::LoadedDriverConfig,
) -> Result<bool, AppError> {
    let _lease = crate::controller_driver::lease::try_acquire(root)?;
    let loaded = crate::controller_driver::revalidate_receipt_bound_driver_config(root, initial)
        .map_err(AppError::operational)?;
    let deployment = crate::controller_driver::require_performance_run_config(&loaded)
        .map_err(AppError::operational)?;
    let deployment_sha = crate::controller_driver::performance_run_deployment_sha256(&loaded)
        .map_err(AppError::operational)?;
    let session = root
        .session(&SessionId::new(session_id.to_owned()).map_err(AppError::operational)?)
        .map_err(AppError::operational)?;
    let artifacts = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    crate::target_adapter_provisioning::require_performance_run_deployment_binding(
        &session, &artifacts, &loaded,
    )?;
    crate::target_adapter_provisioning::require_performance_run_provisioning_receipt(
        &session, &artifacts, &loaded,
    )?;
    let policy = crate::attestation::require_attestation_policy_snapshot(
        &session,
        &artifacts,
        &deployment.attestation.policy_sha256,
        &deployment.attestation.policy_id,
        &deployment.attestation.key_id,
    )
    .map_err(AppError::operational)?;
    session
        .verify_artifact(&policy, true)
        .map_err(AppError::operational)?;
    let lock = session.try_lock().map_err(AppError::from_session_store)?;
    let request = crate::attestation::build_attestation_signing_request(
        &session,
        &deployment.attestation.policy_id,
        &deployment.attestation.key_id,
    )
    .map_err(AppError::operational)?;
    let signing = crate::attestation::ensure_attestation_signing_request(
        &session,
        &lock,
        &request,
        &deployment.attestation.policy_sha256,
    )
    .map_err(AppError::operational)?;
    let intent = crate::attestation::record_signer_dispatch_intent(
        &session,
        &lock,
        &signing,
        &request,
        &deployment.attestation.policy_sha256,
        &deployment_sha,
        &deployment
            .attestation
            .signer_command
            .expected_executable_sha256,
    )
    .map_err(AppError::operational)?;
    let output =
        crate::controller_driver::attestation_signer_output_path(root, session_id, &signing.sha256)
            .map_err(AppError::operational)?;
    drop(lock);
    if !output.absolute.exists() {
        let context = crate::controller_driver::AttestationSignerHookContext {
            session_id,
            signing_request_sha256: &signing.sha256,
        };
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(AppError::operational)?
            .block_on(crate::controller_driver::run_attestation_signer_hook(
                root,
                &loaded,
                &context,
                loaded.config.operation_timeout_ms,
            ))
            .map_err(AppError::operational)?;
    }
    let lock = session.try_lock().map_err(AppError::from_session_store)?;
    let attested = crate::attestation::ensure_attested_from_staged(
        &session,
        &lock,
        &output.staged,
        &deployment.attestation.policy_sha256,
        &deployment_sha,
        &deployment
            .attestation
            .signer_command
            .expected_executable_sha256,
    )
    .map_err(|error| {
        if crate::attestation::is_signer_dispatch_ambiguous(&error) {
            AppError {
                code: "ATTESTATION_SIGNER_OUTPUT_PENDING",
                message: error.to_string(),
                details: serde_json::json!({
                    "session_id": session_id,
                    "required_action": "resume perf_run after the idempotent signer output is available",
                }),
                exit_code: crate::app::EXIT_OPERATIONAL,
            }
        } else {
            AppError::operational(error)
        }
    })?;
    if attested.verified.policy_id != deployment.attestation.policy_id
        || attested.verified.key_id != deployment.attestation.key_id
    {
        return Err(AppError::operational(
            "attestation receipt identity does not match the performance-run deployment",
        ));
    }
    Ok(intent.resumed || attested.resumed)
}

fn provision(
    root: &ArtifactRoot,
    session_id: &str,
    initial: &crate::controller_driver::LoadedDriverConfig,
    deployment_mode: DeploymentMode,
) -> Result<(), AppError> {
    let _lease = crate::controller_driver::lease::try_acquire(root)?;
    let session = root
        .session(&SessionId::new(session_id.to_owned()).map_err(AppError::operational)?)
        .map_err(AppError::operational)?;
    let artifacts = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    if artifacts.iter().any(|artifact| {
        artifact.id == crate::target_adapter_provisioning::PERFORMANCE_RUN_PROVISIONING_RECEIPT_ID
    }) {
        let loaded =
            crate::controller_driver::revalidate_receipt_bound_driver_config(root, initial)
                .map_err(AppError::operational)?;
        crate::target_adapter_provisioning::require_performance_run_provisioning_receipt(
            &session, &artifacts, &loaded,
        )?;
        return Ok(());
    }
    if artifacts.iter().any(|artifact| {
        artifact
            .id
            .starts_with(crate::controller::CONTROLLER_ARTIFACT_ID_PREFIX)
    }) {
        return Err(AppError::operational(
            "performance-run provisioning is incomplete after controller activity",
        ));
    }
    let loaded = if deployment_mode == DeploymentMode::Fresh {
        crate::controller_driver::revalidate_loaded_driver_config(root, initial)
    } else {
        crate::controller_driver::revalidate_receipt_bound_driver_config(root, initial)
    }
    .map_err(AppError::operational)?;
    let deployment = crate::controller_driver::require_performance_run_config(&loaded)
        .map_err(AppError::operational)?;
    let lock = session.try_lock().map_err(AppError::from_session_store)?;
    crate::target_adapter_provisioning::ensure_performance_run_deployment_binding(
        &session, &lock, &loaded,
    )?;
    if !artifacts
        .iter()
        .any(|artifact| artifact.id == crate::controller_qualification::FIRMWARE_ELF_ARTIFACT_ID)
    {
        stage_deployment_input(
            &session,
            &lock,
            "perf-run-firmware.elf",
            &deployment.firmware.path,
            &deployment.firmware.sha256,
        )?;
    }
    if !artifacts
        .iter()
        .any(|artifact| artifact.id == crate::controller::TARGET_ADAPTER_QUALIFICATION_ARTIFACT_ID)
    {
        stage_deployment_input(
            &session,
            &lock,
            "perf-run-qualification.json",
            &deployment.qualification.qualification_receipt.path,
            &deployment.qualification.qualification_receipt.sha256,
        )?;
    }
    if !artifacts.iter().any(|artifact| {
        artifact.id == crate::controller_qualification::HIL_VERIFICATION_ARTIFACT_ID
    }) {
        stage_deployment_input(
            &session,
            &lock,
            "perf-run-hil.json",
            &deployment.qualification.hil_receipt.path,
            &deployment.qualification.hil_receipt.sha256,
        )?;
    }
    if let Some(recovery) = &deployment.qualification.recovery_evidence
        && !artifacts.iter().any(|artifact| {
            artifact.id == crate::controller_qualification::HIL_RECOVERY_EVIDENCE_ARTIFACT_ID
        })
    {
        stage_deployment_input(
            &session,
            &lock,
            "perf-run-recovery.json",
            &recovery.path,
            &recovery.sha256,
        )?;
    }
    drop(lock);
    crate::controller_qualification::provision_firmware(
        root,
        session_id,
        &ArtifactPath::new("perf-run-firmware.elf").map_err(AppError::operational)?,
    )?;
    crate::controller_qualification::provision(
        root,
        ControllerProvisionQualificationArgs {
            session: session_id.to_owned(),
            policy_id: deployment.qualification.policy_id.clone(),
            qualification_staged: "perf-run-qualification.json".to_owned(),
            hil_staged: "perf-run-hil.json".to_owned(),
            recovery_staged: deployment
                .qualification
                .recovery_evidence
                .as_ref()
                .map(|_| "perf-run-recovery.json".to_owned()),
        },
    )?;
    crate::controller_qualification::select_scenario(
        root,
        ControllerSelectScenarioArgs {
            session: session_id.to_owned(),
            scenario: "normal".to_owned(),
        },
    )?;
    crate::target_adapter_provisioning::provision_performance_run_build_resources(
        root, &session, &loaded,
    )?;
    let lock = session.try_lock().map_err(AppError::from_session_store)?;
    crate::attestation::ensure_deployment_attestation_policy_snapshot(
        &session,
        &lock,
        Path::new(&deployment.attestation.policy_path),
        &deployment.attestation.policy_sha256,
        &deployment.attestation.policy_id,
        &deployment.attestation.key_id,
    )
    .map_err(AppError::operational)?;
    crate::target_adapter_provisioning::ensure_performance_run_provisioning_receipt(
        &session, &lock, &loaded,
    )?;
    Ok(())
}

fn stage_deployment_input(
    session: &t32perf_session::Session,
    lock: &t32perf_session::SessionLock,
    staged: &str,
    path: &str,
    expected: &Sha256Digest,
) -> Result<(), AppError> {
    const MAX: u64 = 256 * 1024 * 1024;
    let path = Path::new(path);
    let bytes = crate::controller_driver::read_verified_deployment_source(
        path,
        expected,
        MAX,
        "performance-run deployment input",
    )
    .map_err(AppError::operational)?;
    session
        .ensure_staged_exact(
            lock,
            &ArtifactPath::new(staged).map_err(AppError::operational)?,
            &bytes,
            MAX,
        )
        .map_err(AppError::operational)
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        collections::VecDeque,
        sync::mpsc::{self, Receiver, Sender},
        time::Duration,
    };

    use t32perf_model::{Quality, SamplingHotspot, SessionStatus};
    use t32perf_session::{ArtifactRoot, SessionLimits};
    use tempfile::TempDir;

    use super::*;

    /// Offline-only stage recorder.  It never delegates to production code,
    /// so tests cannot start t32mcp, a workload hook, or a signer.
    #[derive(Default)]
    struct OfflineOrchestrator {
        calls: RefCell<Vec<String>>,
        fail_stage: Option<&'static str>,
        fail_code: Option<&'static str>,
        control_completion: RefCell<VecDeque<bool>>,
    }

    impl OfflineOrchestrator {
        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }

        fn record(&self, name: &str) {
            self.calls.borrow_mut().push(name.to_owned());
        }

        fn failing(stage: &'static str) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                fail_stage: Some(stage),
                fail_code: Some("OPERATIONAL_ERROR"),
                control_completion: RefCell::new(VecDeque::new()),
            }
        }

        fn busy(stage: &'static str) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                fail_stage: Some(stage),
                fail_code: Some("CONTROLLER_DRIVER_BUSY"),
                control_completion: RefCell::new(VecDeque::new()),
            }
        }

        fn retryable(stage: &'static str, code: &'static str) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                fail_stage: Some(stage),
                fail_code: Some(code),
                control_completion: RefCell::new(VecDeque::new()),
            }
        }

        fn with_incomplete_controller_phase() -> Self {
            Self {
                control_completion: RefCell::new(VecDeque::from([false, true])),
                ..Self::default()
            }
        }

        fn fail_if_selected(&self, stage: &'static str) -> Result<(), AppError> {
            if self.fail_stage == Some(stage) {
                let message = format!("injected perf_run {stage} failure");
                if let Some(code) = self.fail_code.filter(|code| *code != "OPERATIONAL_ERROR") {
                    Err(AppError {
                        code,
                        message,
                        details: serde_json::json!({}),
                        exit_code: crate::app::EXIT_OPERATIONAL,
                    })
                } else {
                    Err(AppError::operational(message))
                }
            } else {
                Ok(())
            }
        }
    }

    impl PerfRunOrchestrator for OfflineOrchestrator {
        fn provision_and_control(
            &self,
            _root: &ArtifactRoot,
            session: &Session,
            duration_ns: u64,
        ) -> Result<bool, AppError> {
            self.record("provision");
            self.control(_root, session, duration_ns)
        }

        fn control(
            &self,
            _root: &ArtifactRoot,
            session: &Session,
            duration_ns: u64,
        ) -> Result<bool, AppError> {
            self.record(&format!("control:{duration_ns}"));
            self.fail_if_selected("control")?;
            let status = session.read_state().map_err(AppError::operational)?.status;
            if matches!(status, SessionStatus::Created | SessionStatus::Capturing) {
                let lock = session.try_lock().map_err(AppError::operational)?;
                if status == SessionStatus::Created {
                    session
                        .transition(&lock, SessionStatus::Capturing, None)
                        .map_err(AppError::operational)?;
                }
                session
                    .transition(&lock, SessionStatus::Captured, None)
                    .map_err(AppError::operational)?;
            }
            Ok(false)
        }

        fn control_complete(
            &self,
            _root: &ArtifactRoot,
            _session: &Session,
        ) -> Result<bool, AppError> {
            Ok(self
                .control_completion
                .borrow_mut()
                .pop_front()
                .unwrap_or(true))
        }

        fn normalize(&self, _root: &ArtifactRoot, _session: &Session) -> Result<bool, AppError> {
            self.record("normalize");
            self.fail_if_selected("normalize")?;
            Ok(false)
        }

        fn attest(&self, _root: &ArtifactRoot, _session: &Session) -> Result<bool, AppError> {
            self.record("attest");
            self.fail_if_selected("attest")?;
            Ok(false)
        }

        fn analyze(&self, _root: &ArtifactRoot, session: &Session) -> Result<bool, AppError> {
            self.record("analyze");
            self.fail_if_selected("analyze")?;
            if session.read_state().map_err(AppError::operational)?.status
                == SessionStatus::Captured
            {
                let lock = session.try_lock().map_err(AppError::operational)?;
                session
                    .transition(&lock, SessionStatus::Processing, None)
                    .map_err(AppError::operational)?;
            }
            Ok(false)
        }

        fn convert(&self, _root: &ArtifactRoot, _session: &Session) -> Result<bool, AppError> {
            self.record("convert");
            self.fail_if_selected("convert")?;
            Ok(false)
        }
    }

    struct BlockingOrchestrator {
        entered: Sender<()>,
        release: Receiver<()>,
    }

    impl PerfRunOrchestrator for BlockingOrchestrator {
        fn provision_and_control(
            &self,
            root: &ArtifactRoot,
            session: &Session,
            duration_ns: u64,
        ) -> Result<bool, AppError> {
            self.entered
                .send(())
                .map_err(|error| AppError::operational(error.to_string()))?;
            self.release
                .recv_timeout(Duration::from_secs(5))
                .map_err(|error| AppError::operational(error.to_string()))?;
            self.control(root, session, duration_ns)
        }

        fn control(
            &self,
            _root: &ArtifactRoot,
            session: &Session,
            _duration_ns: u64,
        ) -> Result<bool, AppError> {
            let lock = session.try_lock().map_err(AppError::operational)?;
            if session.read_state().map_err(AppError::operational)?.status == SessionStatus::Created
            {
                session
                    .transition(&lock, SessionStatus::Capturing, None)
                    .map_err(AppError::operational)?;
            }
            session
                .transition(&lock, SessionStatus::Captured, None)
                .map_err(AppError::operational)?;
            Ok(false)
        }

        fn normalize(&self, _root: &ArtifactRoot, _session: &Session) -> Result<bool, AppError> {
            Ok(false)
        }

        fn attest(&self, _root: &ArtifactRoot, _session: &Session) -> Result<bool, AppError> {
            Ok(false)
        }

        fn analyze(&self, _root: &ArtifactRoot, session: &Session) -> Result<bool, AppError> {
            let lock = session.try_lock().map_err(AppError::operational)?;
            session
                .transition(&lock, SessionStatus::Processing, None)
                .map_err(AppError::operational)?;
            Ok(false)
        }

        fn convert(&self, _root: &ArtifactRoot, _session: &Session) -> Result<bool, AppError> {
            Ok(false)
        }
    }

    struct NamespaceContendedOrchestrator {
        stage: &'static str,
        entered: Sender<()>,
        release: Receiver<()>,
    }

    impl NamespaceContendedOrchestrator {
        fn contend(&self, stage: &'static str, session: &Session) -> Result<(), AppError> {
            if self.stage != stage {
                return Ok(());
            }
            self.entered
                .send(())
                .map_err(|error| AppError::operational(error.to_string()))?;
            self.release
                .recv_timeout(Duration::from_secs(5))
                .map_err(|error| AppError::operational(error.to_string()))?;
            let _lock = session.try_lock().map_err(AppError::from_session_store)?;
            Ok(())
        }
    }

    impl PerfRunOrchestrator for NamespaceContendedOrchestrator {
        fn provision_and_control(
            &self,
            _root: &ArtifactRoot,
            _session: &Session,
            _duration_ns: u64,
        ) -> Result<bool, AppError> {
            unreachable!("namespace contention test starts from Captured")
        }

        fn control(
            &self,
            _root: &ArtifactRoot,
            _session: &Session,
            _duration_ns: u64,
        ) -> Result<bool, AppError> {
            unreachable!("namespace contention test has complete controller state")
        }

        fn normalize(&self, _root: &ArtifactRoot, session: &Session) -> Result<bool, AppError> {
            self.contend("normalize", session)?;
            Ok(false)
        }

        fn attest(&self, _root: &ArtifactRoot, session: &Session) -> Result<bool, AppError> {
            self.contend("attest", session)?;
            Ok(false)
        }

        fn analyze(&self, _root: &ArtifactRoot, _session: &Session) -> Result<bool, AppError> {
            Ok(false)
        }

        fn convert(&self, _root: &ArtifactRoot, _session: &Session) -> Result<bool, AppError> {
            Ok(false)
        }
    }

    fn root() -> (TempDir, ArtifactRoot) {
        let temp = TempDir::new().unwrap();
        let root = ArtifactRoot::open(temp.path(), SessionLimits::default()).unwrap();
        (temp, root)
    }

    #[test]
    fn strict_request_is_stable_for_exact_resume_identity() {
        let temp = TempDir::new().unwrap();
        let root = ArtifactRoot::open(temp.path(), SessionLimits::default()).unwrap();
        let request = PerformanceRunRequest {
            schema: PerformanceRunRequestSchemaVersion,
            duration_ns: 1_000_000,
            top: 10,
            report_format: PerformanceReportFormat::PerfettoJson,
        };
        let value = serde_json::to_value(&request).unwrap();
        root.create_session_with_id(SessionId::new("perf-run").unwrap(), &value)
            .unwrap();
        let session = root.session(&SessionId::new("perf-run").unwrap()).unwrap();
        let recovered: PerformanceRunRequest =
            serde_json::from_value(session.request().unwrap()).unwrap();
        assert_eq!(recovered, request);
    }

    #[test]
    fn offline_orchestration_passes_exact_duration_and_has_no_external_path() {
        let (_temp, root) = root();
        let fake = OfflineOrchestrator::default();

        let outcome = run_with(&root, 17, Some("offline-run"), 3, &fake).unwrap();
        let payload: PerfRunPayload = serde_json::from_value(outcome.result).unwrap();

        assert_eq!(
            fake.calls(),
            [
                "provision",
                "control:17000000",
                "normalize",
                "attest",
                "analyze",
                "convert"
            ]
        );
        assert_eq!(payload.phase, PerformanceRunPhase::Analyze);
        assert_eq!(payload.state, SessionStatus::Processing);
        payload.validate().unwrap();
    }

    #[test]
    fn duration_admission_rejects_before_session_or_orchestrator_calls() {
        let (_temp, root) = root();
        let fake = OfflineOrchestrator::default();

        let error = match run_with_max_duration(
            &root,
            2,
            Some("duration-too-large"),
            1,
            1_000_000,
            &fake,
        ) {
            Ok(_) => panic!("over-limit duration unexpectedly created a performance Session"),
            Err(error) => error,
        };

        assert!(error.message.contains("exceeds deployment max_duration_ns"));
        assert!(fake.calls().is_empty());
        assert!(!root.path().join("duration-too-large").exists());
    }

    #[test]
    fn request_preflight_precedes_deployment_loading_and_all_writes() {
        for (duration_ms, requested_id, top, expected) in [
            (0, Some("zero-duration"), 1, "nonzero"),
            (u64::MAX, Some("overflow-duration"), 1, "overflows"),
            (1, Some("invalid/id"), 1, "invalid session id"),
            (1, Some("invalid-top"), 0, "top"),
        ] {
            let (_temp, root) = root();
            let error = match run(&root, duration_ms, requested_id, top) {
                Ok(_) => panic!("invalid request unexpectedly reached deployment loading"),
                Err(error) => error,
            };
            assert!(
                error.message.contains(expected),
                "unexpected preflight error: {}",
                error.message
            );
            if let Some(session_id) = requested_id.filter(|id| !id.contains('/')) {
                assert!(!root.path().join(session_id).exists());
            }
            assert!(!root.path().join(".t32perf-control").exists());
        }
    }

    #[test]
    fn duration_admission_accepts_the_exact_deployment_boundary() {
        let (_temp, root) = root();
        let fake = OfflineOrchestrator::default();

        run_with_max_duration(&root, 1, Some("duration-boundary"), 1, 1_000_000, &fake).unwrap();

        assert!(fake.calls().contains(&"control:1000000".to_owned()));
    }

    #[test]
    fn normalize_and_attest_failures_are_terminal_and_stop_later_stages() {
        for (stage, expected_code, expected_calls) in [
            (
                "normalize",
                "PERF_RUN_NORMALIZE_FAILED",
                vec!["provision", "control:1000000", "normalize"],
            ),
            (
                "attest",
                "PERF_RUN_ATTEST_FAILED",
                vec!["provision", "control:1000000", "normalize", "attest"],
            ),
            (
                "analyze",
                "PERF_RUN_ANALYZE_FAILED",
                vec![
                    "provision",
                    "control:1000000",
                    "normalize",
                    "attest",
                    "analyze",
                ],
            ),
            (
                "convert",
                "PERF_RUN_CONVERT_FAILED",
                vec![
                    "provision",
                    "control:1000000",
                    "normalize",
                    "attest",
                    "analyze",
                    "convert",
                ],
            ),
        ] {
            let (_temp, root) = root();
            let fake = OfflineOrchestrator::failing(stage);
            let session_id = format!("{stage}-terminal-failure");

            assert!(
                run_with_max_duration(&root, 1, Some(&session_id), 1, 1_000_000, &fake,).is_err()
            );

            let session = root.session(&SessionId::new(session_id).unwrap()).unwrap();
            let state = session.read_state().unwrap();
            assert_eq!(state.status, SessionStatus::Failed);
            assert_eq!(state.error.as_ref().unwrap().code, expected_code);
            assert_eq!(fake.calls(), expected_calls);
        }
    }

    #[test]
    fn held_orchestration_lease_is_busy_without_stage_or_state_mutation() {
        let (_temp, root) = root();
        let request = PerformanceRunRequest {
            schema: PerformanceRunRequestSchemaVersion,
            duration_ns: 1_000_000,
            top: 1,
            report_format: PerformanceReportFormat::PerfettoJson,
        };
        let session = root
            .create_session_with_id(
                SessionId::new("held-orchestration-lease").unwrap(),
                &serde_json::to_value(&request).unwrap(),
            )
            .unwrap();
        let before = session.read_state().unwrap();
        let _lease = try_acquire_session_id_execution_lease(&root, session.id()).unwrap();
        let fake = OfflineOrchestrator::default();

        let error = match run_with_max_duration(
            &root,
            1,
            Some("held-orchestration-lease"),
            1,
            1_000_000,
            &fake,
        ) {
            Ok(_) => panic!("concurrent perf_run unexpectedly acquired the Session lease"),
            Err(error) => error,
        };

        assert_eq!(error.code, "SESSION_EXECUTION_BUSY");
        assert!(fake.calls().is_empty());
        assert_eq!(session.read_state().unwrap(), before);
    }

    #[test]
    fn maintenance_contention_is_busy_without_failing_the_active_perf_run() {
        let (_temp, root) = root();
        let worker_root = root.clone();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            run_with_max_duration(
                &worker_root,
                1,
                Some("maintenance-contention"),
                1,
                1_000_000,
                &BlockingOrchestrator {
                    entered: entered_tx,
                    release: release_rx,
                },
            )
        });
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("perf_run reached the controlled stage while holding its lease");

        let error = match crate::operations::abandon_plan(&root, "maintenance-contention") {
            Ok(_) => panic!("maintenance unexpectedly acquired the active perf_run Session"),
            Err(error) => error,
        };
        assert_eq!(error.code, "SESSION_EXECUTION_BUSY");

        release_tx.send(()).unwrap();
        let result = worker.join().expect("perf_run worker did not panic");
        assert!(result.is_ok(), "maintenance contention failed perf_run");
        let session = root
            .session(&SessionId::new("maintenance-contention").unwrap())
            .unwrap();
        assert_eq!(
            session.read_state().unwrap().status,
            SessionStatus::Processing
        );
    }

    #[test]
    fn controller_driver_busy_does_not_terminalize_normalize_or_attest() {
        for stage in ["normalize", "attest"] {
            let (_temp, root) = root();
            let fake = OfflineOrchestrator::busy(stage);
            let session_id = format!("{stage}-driver-busy");

            let error =
                match run_with_max_duration(&root, 1, Some(&session_id), 1, 1_000_000, &fake) {
                    Ok(_) => panic!("driver contention unexpectedly completed perf_run"),
                    Err(error) => error,
                };

            assert_eq!(error.code, "CONTROLLER_DRIVER_BUSY");
            let session = root.session(&SessionId::new(session_id).unwrap()).unwrap();
            assert_eq!(
                session.read_state().unwrap().status,
                SessionStatus::Captured
            );
            assert!(!fake.calls().contains(&"analyze".to_owned()));
            assert!(!fake.calls().contains(&"convert".to_owned()));
        }
    }

    #[test]
    fn controller_ownership_errors_remain_retryable_without_terminalization() {
        for (stage, code) in [
            ("normalize", "CONTROLLER_TRANSACTION_PENDING"),
            ("attest", "CONTROLLER_CAPTURE_LEASE_ACTIVE"),
        ] {
            let (_temp, root) = root();
            let fake = OfflineOrchestrator::retryable(stage, code);
            let session_id = format!("{stage}-controller-retryable");

            let error =
                match run_with_max_duration(&root, 1, Some(&session_id), 1, 1_000_000, &fake) {
                    Ok(_) => panic!("retryable controller ownership error unexpectedly completed"),
                    Err(error) => error,
                };

            assert_eq!(error.code, code);
            let session = root
                .session(&SessionId::new(session_id.clone()).unwrap())
                .unwrap();
            assert_eq!(
                session.read_state().unwrap().status,
                SessionStatus::Captured
            );

            let recovered = OfflineOrchestrator::default();
            run_with_max_duration(&root, 1, Some(&session_id), 1, 1_000_000, &recovered).unwrap();
            assert!(recovered.calls().contains(&"analyze".to_owned()));
        }
    }

    #[test]
    fn namespace_contention_during_normalize_or_attest_is_retryable() {
        for stage in ["normalize", "attest"] {
            let (_temp, root) = root();
            let session_id = format!("{stage}-namespace-contention");
            let request = PerformanceRunRequest {
                schema: PerformanceRunRequestSchemaVersion,
                duration_ns: 1_000_000,
                top: 1,
                report_format: PerformanceReportFormat::PerfettoJson,
            };
            let session = root
                .create_session_with_id(
                    SessionId::new(session_id.clone()).unwrap(),
                    &serde_json::to_value(&request).unwrap(),
                )
                .unwrap();
            let lock = session.try_lock().unwrap();
            session
                .transition(&lock, SessionStatus::Capturing, None)
                .unwrap();
            session
                .transition(&lock, SessionStatus::Captured, None)
                .unwrap();
            drop(lock);

            let worker_root = root.clone();
            let worker_session_id = session_id.clone();
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                run_with_max_duration(
                    &worker_root,
                    1,
                    Some(&worker_session_id),
                    1,
                    1_000_000,
                    &NamespaceContendedOrchestrator {
                        stage,
                        entered: entered_tx,
                        release: release_rx,
                    },
                )
            });
            entered_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("host stage reached the controlled contention point");
            let namespace = root.try_namespace_lock().unwrap();
            release_tx.send(()).unwrap();
            let error = match worker.join().expect("host-stage worker did not panic") {
                Ok(_) => panic!("namespace contention unexpectedly completed {stage}"),
                Err(error) => error,
            };

            assert_eq!(error.code, "ARTIFACT_ROOT_NAMESPACE_BUSY");
            assert_eq!(
                session.read_state().unwrap().status,
                SessionStatus::Captured
            );
            drop(namespace);

            let recovered = OfflineOrchestrator::default();
            run_with_max_duration(&root, 1, Some(&session_id), 1, 1_000_000, &recovered).unwrap();
            assert!(recovered.calls().contains(&"analyze".to_owned()));
        }
    }

    #[test]
    fn resume_from_processing_skips_control_normalize_and_attestation() {
        let (_temp, root) = root();
        let request = PerformanceRunRequest {
            schema: PerformanceRunRequestSchemaVersion,
            duration_ns: 5_000_000,
            top: 2,
            report_format: PerformanceReportFormat::PerfettoJson,
        };
        let session = root
            .create_session_with_id(
                SessionId::new("resume-processing").unwrap(),
                &serde_json::to_value(&request).unwrap(),
            )
            .unwrap();
        let lock = session.try_lock().unwrap();
        session
            .transition(&lock, SessionStatus::Capturing, None)
            .unwrap();
        session
            .transition(&lock, SessionStatus::Captured, None)
            .unwrap();
        session
            .transition(&lock, SessionStatus::Processing, None)
            .unwrap();
        drop(lock);
        let fake = OfflineOrchestrator::default();

        let outcome = run_with(&root, 5, Some("resume-processing"), 2, &fake).unwrap();
        let payload: PerfRunPayload = serde_json::from_value(outcome.result).unwrap();

        assert_eq!(fake.calls(), ["analyze", "convert"]);
        assert!(payload.resumed);
        assert_eq!(payload.phase, PerformanceRunPhase::Analyze);
        payload.validate().unwrap();
    }

    #[test]
    fn resume_from_captured_replays_only_idempotent_host_stages() {
        let (_temp, root) = root();
        let request = PerformanceRunRequest {
            schema: PerformanceRunRequestSchemaVersion,
            duration_ns: 5_000_000,
            top: 2,
            report_format: PerformanceReportFormat::PerfettoJson,
        };
        let session = root
            .create_session_with_id(
                SessionId::new("resume-captured").unwrap(),
                &serde_json::to_value(&request).unwrap(),
            )
            .unwrap();
        let lock = session.try_lock().unwrap();
        session
            .transition(&lock, SessionStatus::Capturing, None)
            .unwrap();
        session
            .transition(&lock, SessionStatus::Captured, None)
            .unwrap();
        drop(lock);
        let fake = OfflineOrchestrator::default();

        run_with(&root, 5, Some("resume-captured"), 2, &fake).unwrap();

        assert_eq!(fake.calls(), ["normalize", "attest", "analyze", "convert"]);
    }

    #[test]
    fn captured_state_reenters_control_until_the_controller_chain_is_complete() {
        for checkpoint in [
            "after-stop",
            "health-pending",
            "export-or-cleanup-pending",
            "capture-config-repair",
        ] {
            let (_temp, root) = root();
            let session_id = format!("captured-{checkpoint}");
            let request = PerformanceRunRequest {
                schema: PerformanceRunRequestSchemaVersion,
                duration_ns: 5_000_000,
                top: 2,
                report_format: PerformanceReportFormat::PerfettoJson,
            };
            let session = root
                .create_session_with_id(
                    SessionId::new(session_id.clone()).unwrap(),
                    &serde_json::to_value(&request).unwrap(),
                )
                .unwrap();
            let lock = session.try_lock().unwrap();
            session
                .transition(&lock, SessionStatus::Capturing, None)
                .unwrap();
            session
                .transition(&lock, SessionStatus::Captured, None)
                .unwrap();
            drop(lock);
            let fake = OfflineOrchestrator::with_incomplete_controller_phase();

            run_with(&root, 5, Some(&session_id), 2, &fake).unwrap();

            assert_eq!(
                fake.calls(),
                [
                    "control:5000000",
                    "normalize",
                    "attest",
                    "analyze",
                    "convert"
                ],
                "checkpoint {checkpoint} skipped controller recovery"
            );
        }
    }

    #[test]
    fn resume_from_capturing_reenters_control_without_provisioning() {
        let (_temp, root) = root();
        let request = PerformanceRunRequest {
            schema: PerformanceRunRequestSchemaVersion,
            duration_ns: 5_000_000,
            top: 2,
            report_format: PerformanceReportFormat::PerfettoJson,
        };
        let session = root
            .create_session_with_id(
                SessionId::new("resume-capturing").unwrap(),
                &serde_json::to_value(&request).unwrap(),
            )
            .unwrap();
        let lock = session.try_lock().unwrap();
        session
            .transition(&lock, SessionStatus::Capturing, None)
            .unwrap();
        drop(lock);
        let fake = OfflineOrchestrator::default();

        run_with(&root, 5, Some("resume-capturing"), 2, &fake).unwrap();

        assert_eq!(
            fake.calls(),
            [
                "control:5000000",
                "normalize",
                "attest",
                "analyze",
                "convert"
            ]
        );
    }

    #[test]
    fn resume_binding_gate_defers_workload_marker_validation_until_capture_completed() {
        assert_eq!(
            resume_binding_requirement(SessionStatus::Created),
            ResumeBindingRequirement::None
        );
        assert_eq!(
            resume_binding_requirement(SessionStatus::Capturing),
            ResumeBindingRequirement::Deployment
        );
        for status in [
            SessionStatus::Captured,
            SessionStatus::Processing,
            SessionStatus::Complete,
        ] {
            assert_eq!(
                resume_binding_requirement(status),
                ResumeBindingRequirement::DeploymentAndWorkload
            );
        }
    }

    #[test]
    fn complete_session_never_dispatches_another_stage() {
        let (_temp, root) = root();
        let request = PerformanceRunRequest {
            schema: PerformanceRunRequestSchemaVersion,
            duration_ns: 5_000_000,
            top: 2,
            report_format: PerformanceReportFormat::PerfettoJson,
        };
        let session = root
            .create_session_with_id(
                SessionId::new("resume-complete").unwrap(),
                &serde_json::to_value(&request).unwrap(),
            )
            .unwrap();
        let lock = session.try_lock().unwrap();
        session
            .transition(&lock, SessionStatus::Capturing, None)
            .unwrap();
        session
            .transition(&lock, SessionStatus::Captured, None)
            .unwrap();
        // A complete state without its immutable manifest is deliberately
        // invalid, but still proves orchestration does not replay a stage.
        let manifest = t32perf_model::Manifest {
            schema: t32perf_model::ManifestSchemaVersion,
            session_id: session.id().to_string(),
            created_at: session.read_state().unwrap().created_at,
            tool: t32perf_model::ToolInfo {
                name: "test".to_owned(),
                version: "1".to_owned(),
                commit: None,
            },
            capture: t32perf_model::CaptureInfo {
                provider: None,
                mode: "test".to_owned(),
                adapter: t32perf_model::AdapterInfo {
                    id: "test".to_owned(),
                    version: "1".to_owned(),
                },
                target: None,
                trace32: None,
                request_sha256: None,
                covered_cores: Vec::new(),
                capabilities: None,
                capture_config: None,
                instrumentation: None,
            },
            firmware: t32perf_model::FirmwareInfo {
                elf_path: None,
                elf_sha256: None,
                build_id: None,
            },
            clocks: Vec::new(),
            stages: Vec::new(),
            artifacts: Vec::new(),
        };
        session.finalize(&lock, &manifest).unwrap();
        drop(lock);
        let fake = OfflineOrchestrator::default();

        assert!(run_with(&root, 5, Some("resume-complete"), 2, &fake).is_err());
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn failed_session_performs_zero_orchestration_calls() {
        let (_temp, root) = root();
        let request = PerformanceRunRequest {
            schema: PerformanceRunRequestSchemaVersion,
            duration_ns: 1_000_000,
            top: 1,
            report_format: PerformanceReportFormat::PerfettoJson,
        };
        let session = root
            .create_session_with_id(
                SessionId::new("failed-run").unwrap(),
                &serde_json::to_value(&request).unwrap(),
            )
            .unwrap();
        let lock = session.try_lock().unwrap();
        session
            .transition(
                &lock,
                SessionStatus::Failed,
                Some(t32perf_model::SessionError {
                    code: "TEST_FAILURE".to_owned(),
                    message: "injected failure".to_owned(),
                    details: Default::default(),
                }),
            )
            .unwrap();
        drop(lock);
        let fake = OfflineOrchestrator::default();

        assert!(run_with(&root, 1, Some("failed-run"), 1, &fake).is_err());
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn resume_conflict_is_rejected_before_orchestration() {
        let (_temp, root) = root();
        let fake = OfflineOrchestrator::default();
        let request = PerformanceRunRequest {
            schema: PerformanceRunRequestSchemaVersion,
            duration_ns: 1_000_000,
            top: 1,
            report_format: PerformanceReportFormat::PerfettoJson,
        };
        root.create_session_with_id(
            SessionId::new("conflict-run").unwrap(),
            &serde_json::to_value(&request).unwrap(),
        )
        .unwrap();

        assert!(run_with(&root, 2, Some("conflict-run"), 1, &fake).is_err());
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn incomplete_payload_phases_remain_contract_legal() {
        let cases = [
            (PerformanceRunPhase::Provision, SessionStatus::Created),
            (PerformanceRunPhase::Control, SessionStatus::Capturing),
            (PerformanceRunPhase::Normalize, SessionStatus::Captured),
            (PerformanceRunPhase::Attest, SessionStatus::Captured),
            (PerformanceRunPhase::Analyze, SessionStatus::Processing),
            (PerformanceRunPhase::Convert, SessionStatus::Processing),
        ];
        for (phase, state) in cases {
            PerfRunPayload {
                session_id: "phase-test".to_owned(),
                phase,
                state,
                trust_status: PerfTrustStatus::NotEvaluated,
                health_verdict: None,
                summary: None,
                report_artifact: None,
                manifest_sha256: None,
                resumed: false,
            }
            .validate()
            .unwrap();
        }
    }

    #[test]
    fn complete_payload_contract_covers_each_health_projection() {
        let report = t32perf_model::Artifact {
            id: "perfetto".to_owned(),
            kind: "perfetto".to_owned(),
            relative_path: ArtifactPath::new("reports/perfetto.json").unwrap(),
            media_type: "application/json".to_owned(),
            size_bytes: 2,
            sha256: Sha256Digest::new("a".repeat(64)).unwrap(),
            producer: "test".to_owned(),
            input_artifact_ids: Vec::new(),
        };
        let digest = Sha256Digest::new("b".repeat(64)).unwrap();
        for (verdict, trust, summary) in [
            (
                HealthVerdict::Valid,
                PerfTrustStatus::Valid,
                Some(PerfRunSummary {
                    hotspots_returned: 2,
                    hotspots_total: 3,
                    truncated: true,
                }),
            ),
            (HealthVerdict::Degraded, PerfTrustStatus::Degraded, None),
            (HealthVerdict::Invalid, PerfTrustStatus::Invalid, None),
        ] {
            PerfRunPayload {
                session_id: "complete-test".to_owned(),
                phase: PerformanceRunPhase::Complete,
                state: SessionStatus::Complete,
                trust_status: trust,
                health_verdict: Some(verdict),
                summary,
                report_artifact: Some(report.clone()),
                manifest_sha256: Some(digest.clone()),
                resumed: false,
            }
            .validate()
            .unwrap();
        }
    }

    #[test]
    fn manifest_digest_is_the_exact_manifest_bytes_not_a_request_digest() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("manifest.json");
        let bytes = br#"{\"manifest\":true,\"request\":false}\n"#;
        fs::write(&path, bytes).unwrap();

        assert_eq!(
            manifest_digest(&path).unwrap(),
            Sha256Digest::new(lower_hex(&Sha256::digest(bytes))).unwrap()
        );
        assert_ne!(
            manifest_digest(&path).unwrap(),
            Sha256Digest::new(lower_hex(&Sha256::digest(br#"{\"request\":false}"#))).unwrap()
        );
    }

    #[test]
    fn hotspot_summary_reports_total_returned_and_truncation() {
        let mut hotspots = HotspotReport::new("summary-test", Quality::Statistical);
        hotspots.sampling = (0..3)
            .map(|address| SamplingHotspot {
                function_id: None,
                address: Some(address),
                context_id: None,
                sample_count: 1,
                estimated_share: 1.0 / 3.0,
                quality: Quality::Statistical,
            })
            .collect();

        assert_eq!(
            hotspot_summary(&hotspots, 2).unwrap(),
            PerfRunSummary {
                hotspots_returned: 2,
                hotspots_total: 3,
                truncated: true,
            }
        );
        assert_eq!(
            hotspot_summary(&hotspots, 9).unwrap(),
            PerfRunSummary {
                hotspots_returned: 3,
                hotspots_total: 3,
                truncated: false,
            }
        );
    }
}
