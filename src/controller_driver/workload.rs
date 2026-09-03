use std::{future::Future, path::Path, pin::Pin};

use t32perf_model::Sha256Digest;
use t32perf_session::ArtifactRoot;
use t32perf_trace32::{ControllerTargetState, DriverCommandRole};

use crate::app::AppError;

use super::{
    config::LoadedDriverConfig,
    hooks::{
        FaultHookContext, WorkloadHookContext, run_fault_hook, run_workload_hook,
        validate_workload_hook,
    },
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct WorkloadInvocation<'a> {
    pub(crate) session_id: &'a str,
    pub(crate) transaction_id: &'a str,
    pub(crate) initial_target_state: ControllerTargetState,
    pub(crate) workload_identity: &'a str,
    pub(crate) binding_sha256: &'a Sha256Digest,
    pub(crate) duration_ns: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FaultInvocation<'a> {
    pub(crate) artifact_root: &'a Path,
    pub(crate) session_id: &'a str,
    pub(crate) transaction_id: &'a str,
    pub(crate) binding_sha256: &'a Sha256Digest,
}

pub(crate) trait DriverHookRunner {
    /// Performs only configuration validation.  It deliberately happens before
    /// the Host records the non-replayable workload intent.
    fn validate_workload(&self, duration_ns: Option<u64>) -> Result<(), AppError>;

    fn run_workload<'a>(
        &'a self,
        invocation: WorkloadInvocation<'a>,
        timeout_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + 'a>>;

    fn run_fault<'a>(
        &'a self,
        role: DriverCommandRole,
        invocation: FaultInvocation<'a>,
        timeout_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + 'a>>;
}

pub(crate) struct ConfiguredHookRunner<'a> {
    root: &'a ArtifactRoot,
    loaded: &'a LoadedDriverConfig,
}

impl<'a> ConfiguredHookRunner<'a> {
    pub(crate) const fn new(root: &'a ArtifactRoot, loaded: &'a LoadedDriverConfig) -> Self {
        Self { root, loaded }
    }
}

impl DriverHookRunner for ConfiguredHookRunner<'_> {
    fn validate_workload(&self, duration_ns: Option<u64>) -> Result<(), AppError> {
        validate_workload_hook(self.loaded, duration_ns)
            .map_err(|error| hook_error("controller_driver.workload", error))
    }

    fn run_workload<'a>(
        &'a self,
        invocation: WorkloadInvocation<'a>,
        timeout_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + 'a>> {
        Box::pin(async move {
            run_workload_hook(
                self.root,
                self.loaded,
                &WorkloadHookContext {
                    session_id: invocation.session_id,
                    transaction_id: invocation.transaction_id,
                    binding_sha256: invocation.binding_sha256,
                    initial_target_state: invocation.initial_target_state,
                    workload_identity: invocation.workload_identity,
                    duration_ns: invocation.duration_ns,
                },
                timeout_ms,
            )
            .await
            .map(|_| ())
            .map_err(|error| hook_error("controller_driver.workload", error))
        })
    }

    fn run_fault<'a>(
        &'a self,
        role: DriverCommandRole,
        invocation: FaultInvocation<'a>,
        timeout_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + 'a>> {
        Box::pin(async move {
            run_fault_hook(
                self.loaded,
                role,
                &FaultHookContext {
                    artifact_root: invocation.artifact_root,
                    session_id: invocation.session_id,
                    transaction_id: invocation.transaction_id,
                    binding_sha256: invocation.binding_sha256,
                },
                timeout_ms,
            )
            .await
            .map(|_| ())
            .map_err(|error| hook_error("controller_driver.fault_action", error))
        })
    }
}

fn hook_error(feature: &'static str, error: super::hooks::DriverHookError) -> AppError {
    if error.is_unsupported() {
        AppError::unsupported(feature, error.to_string())
    } else {
        AppError::operational(error)
    }
}
