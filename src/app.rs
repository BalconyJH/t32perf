use std::{env, io::Read as _, path::PathBuf};

use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use t32perf_model::{
    AnalysisStageReceipt, AnalysisSummaryDocument, Artifact, ArtifactPath, HealthReport,
    HealthVerdict, HotspotReport, PERFORMANCE_RUN_REQUEST_SCHEMA, PerfComparePayload,
    PerfControlPayload, PerfConvertPayload, PerfGetStatusPayload, PerfGetSummaryPayload,
    PerfListArtifactsPayload, PerfSurfaceEnvelope, PerfSurfaceOperation, PerfSurfaceResponse,
    PerformanceRunRequest, SessionError, SessionState, SessionStatus, is_portable_artifact_id,
    portable_name_key, strict_json,
};
use t32perf_session::{
    ArtifactRoot, ArtifactSpec, IngestIntentClassification, IngestIntentInspection, Session,
    SessionId, SessionLimits, SessionLock, SessionStoreError,
};
use t32perf_trace32::{
    AdapterError, AdapterRegistry, AdapterRequest, CANONICAL_NDJSON_ADAPTER_ID,
    GNU_LD_MAP_V1_FLAVOR, TRACE_ASCII_ADAPTER_ID, TRACE_TASK_EVENTS_ADAPTER_ID,
};

use crate::{
    attestation::{
        ATTESTATION_SIGNER_DISPATCH_INTENT_ID, ATTESTATION_SIGNER_DISPATCH_INTENT_KIND,
        ATTESTATION_SIGNER_DISPATCH_INTENT_PATH, ATTESTATION_SIGNER_DISPATCH_INTENT_PRODUCER,
        ATTESTATION_SIGNING_REQUEST_ID, ATTESTATION_SIGNING_REQUEST_KIND,
        ATTESTATION_SIGNING_REQUEST_PATH, ATTESTATION_SIGNING_REQUEST_PRODUCER,
        CAPTURE_ATTESTATION_ID, CAPTURE_ATTESTATION_KIND, CAPTURE_ATTESTATION_PATH,
        CAPTURE_ATTESTATION_PRODUCER, CAPTURE_RECEIPT_PATH, CAPTURE_TRUST_POLICY_ID,
        CAPTURE_TRUST_POLICY_KIND, CAPTURE_TRUST_POLICY_PATH, CAPTURE_TRUST_POLICY_PRODUCER,
        attest_captured_session,
    },
    capture_config::{
        CAPTURE_CONFIG_ID, CAPTURE_CONFIG_KIND, CAPTURE_CONFIG_PATH,
        SYNTHETIC_CAPTURE_CONFIG_PRODUCER,
    },
    cli::{
        AbandonSubcommand, ArtifactsSubcommand, Cli, Command, ControllerRecoverSubcommand,
        ControllerSubcommand, FixtureSubcommand, MaintenanceSubcommand, RetentionSubcommand,
        SamplingSubcommand, SessionIngestArgs, SessionSubcommand, StackSubcommand,
    },
    fixture,
    pipeline::{
        ANALYSIS_REQUEST_ID, ANALYSIS_REQUEST_KIND, ANALYSIS_REQUEST_PATH,
        ANALYSIS_REQUEST_PRODUCER, open_derived, validate_health_document,
        validate_summary_document,
    },
    receipt::{
        ANALYSIS_STAGE_ID, ANALYSIS_STAGE_PRODUCER, SYNTHETIC_RECEIPT_PRODUCER,
        validate_analysis_stage_receipt,
    },
};

pub const EXIT_SUCCESS: u8 = 0;
pub const EXIT_DEGRADED: u8 = 10;
pub const EXIT_INVALID: u8 = 11;
pub const EXIT_REGRESSION: u8 = 12;
pub const EXIT_INCONCLUSIVE: u8 = 13;
pub const EXIT_UNSUPPORTED: u8 = 20;
pub const EXIT_OPERATIONAL: u8 = 1;

const MAX_INGEST_RECOVERY_INSPECTIONS: usize = 32;
const MAX_INGEST_RECOVERY_TEXT_CHARS: usize = 512;
const MAX_LISTED_ARTIFACT_INPUTS: usize = 16;
const MAX_APP_JSON_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

fn portable_eq(actual: &str, expected: &str) -> bool {
    portable_name_key(actual) == portable_name_key(expected)
}

fn portable_matches_any(actual: &str, expected: &[&str]) -> bool {
    expected.iter().any(|value| portable_eq(actual, value))
}

fn portable_starts_with(actual: &str, expected_prefix: &str) -> bool {
    portable_name_key(actual).starts_with(&portable_name_key(expected_prefix))
}

fn is_reserved_controller_claim(id: &str, kind: &str, path: &str, producer: &str) -> bool {
    portable_starts_with(id, crate::controller::CONTROLLER_ARTIFACT_ID_PREFIX)
        || portable_starts_with(
            id,
            crate::controller_journal::CONTROLLER_DRIVER_EVENT_ID_PREFIX,
        )
        || portable_matches_any(
            id,
            &[
                crate::controller::TARGET_ADAPTER_QUALIFICATION_ARTIFACT_ID,
                crate::controller_qualification::QUALIFICATION_POLICY_ARTIFACT_ID,
                crate::controller_qualification::HIL_VERIFICATION_ARTIFACT_ID,
                crate::controller_qualification::ADMISSION_SNAPSHOT_ARTIFACT_ID,
                crate::controller_qualification::HIL_RECOVERY_EVIDENCE_ARTIFACT_ID,
                crate::controller_qualification::FIRMWARE_ELF_ARTIFACT_ID,
                crate::controller::FIRMWARE_S3_ARTIFACT_ID,
                crate::controller::TARGET_ADAPTER_SCENARIO_ARTIFACT_ID,
                crate::target_adapter_provisioning::LINKER_MAP_ARTIFACT_ID,
                crate::target_adapter_provisioning::STACK_USAGE_ARTIFACT_ID,
                crate::target_adapter_provisioning::STATIC_RAM_CONFIG_ARTIFACT_ID,
                crate::target_adapter_provisioning::TASK_EVENTS_MAPPING_TEMPLATE_ARTIFACT_ID,
                crate::target_adapter_provisioning::PERFORMANCE_RUN_DEPLOYMENT_BINDING_ID,
            ],
        )
        || [
            crate::controller::CONTROLLER_REQUEST_KIND,
            crate::controller::CONTROLLER_RAW_RESPONSE_KIND,
            crate::controller::CONTROLLER_RESPONSE_KIND,
            crate::controller::CONTROLLER_ABORT_REQUEST_KIND,
            crate::controller::CONTROLLER_ABORT_RECEIPT_KIND,
            crate::controller::TARGET_ADAPTER_QUALIFICATION_KIND,
            crate::controller_qualification::QUALIFICATION_POLICY_KIND,
            crate::controller_qualification::HIL_VERIFICATION_KIND,
            crate::controller_qualification::ADMISSION_SNAPSHOT_KIND,
            crate::controller_qualification::HIL_RECOVERY_EVIDENCE_KIND,
            crate::controller::FIRMWARE_S3_ARTIFACT_KIND,
            crate::controller::TARGET_ADAPTER_SCENARIO_KIND,
            crate::controller_journal::CONTROLLER_DRIVER_EVENT_KIND,
            "trace32_orti",
            "trace32_task_markers",
            "trace32_task_events_mapping_template",
            crate::target_adapter_provisioning::PERFORMANCE_RUN_DEPLOYMENT_BINDING_KIND,
        ]
        .contains(&kind)
        || portable_starts_with(path, crate::controller::CONTROLLER_ARTIFACT_PATH_PREFIX)
        || portable_starts_with(
            path,
            crate::controller_journal::CONTROLLER_DRIVER_EVENT_PATH_PREFIX,
        )
        || portable_matches_any(
            path,
            &[
                crate::controller_qualification::QUALIFICATION_POLICY_PATH,
                crate::controller_qualification::HIL_VERIFICATION_PATH,
                crate::controller_qualification::HIL_RECOVERY_EVIDENCE_PATH,
                crate::controller_qualification::QUALIFICATION_PATH,
                crate::controller_qualification::ADMISSION_SNAPSHOT_PATH,
                crate::controller_qualification::FIRMWARE_ELF_ARTIFACT_PATH,
                crate::controller::FIRMWARE_S3_ARTIFACT_PATH,
                crate::controller::TARGET_ADAPTER_SCENARIO_PATH,
                "capture/deployment/build-resources/linker.map",
                "capture/deployment/build-resources/stack-usage.su",
                "capture/deployment/build-resources/static-ram-config.json",
                "capture/deployment/program-flow/orti.bin",
                "capture/deployment/program-flow/task-markers.bin",
                "capture/deployment/program-flow/task-events-mapping-template.json",
                crate::target_adapter_provisioning::PERFORMANCE_RUN_DEPLOYMENT_BINDING_PATH,
            ],
        )
        || [
            crate::controller::CONTROLLER_PRODUCER,
            crate::controller::TARGET_ADAPTER_QUALIFICATION_PRODUCER,
            crate::controller_qualification::DEPLOYMENT_PRODUCER,
            crate::controller_qualification::FIRMWARE_ELF_ARTIFACT_PRODUCER,
            crate::controller::FIRMWARE_S3_PRODUCER,
            crate::controller::TARGET_ADAPTER_SCENARIO_PRODUCER,
            crate::controller_journal::CONTROLLER_DRIVER_EVENT_PRODUCER,
            crate::target_adapter_provisioning::BUILD_RESOURCE_PRODUCER,
            crate::target_adapter_provisioning::PERFORMANCE_RUN_DEPLOYMENT_BINDING_PRODUCER,
        ]
        .contains(&producer)
}

fn is_controller_owned_artifact(artifact: &Artifact) -> bool {
    is_reserved_controller_claim(
        &artifact.id,
        &artifact.kind,
        artifact.relative_path.as_str(),
        &artifact.producer,
    )
}

fn is_reserved_analysis_request(id: &str, kind: &str, path: &str, producer: &str) -> bool {
    portable_matches_any(id, &[ANALYSIS_REQUEST_ID])
        || kind == ANALYSIS_REQUEST_KIND
        || portable_matches_any(path, &[ANALYSIS_REQUEST_PATH])
        || producer == ANALYSIS_REQUEST_PRODUCER
}

fn is_reserved_sampling_claim(id: &str, kind: &str, path: &str, producer: &str) -> bool {
    portable_starts_with(id, crate::sampling::ARTIFACT_ID_PREFIX)
        || [
            crate::sampling::HISTOGRAM_KIND,
            crate::sampling::CAPTURE_RECEIPT_KIND,
            crate::sampling::FIRMWARE_EVIDENCE_KIND,
            crate::sampling::HEATMAP_KIND,
            crate::sampling::FLAT_PROFILE_KIND,
        ]
        .contains(&kind)
        || portable_starts_with(path, crate::sampling::CAPTURE_ARTIFACT_PATH_PREFIX)
        || portable_starts_with(path, crate::sampling::ANALYSIS_ARTIFACT_PATH_PREFIX)
        || portable_starts_with(path, crate::sampling::REPORT_ARTIFACT_PATH_PREFIX)
        || [
            crate::sampling::SIDECAR_PRODUCER,
            crate::sampling::CAPTURE_RECEIPT_PRODUCER,
            crate::sampling::FIRMWARE_ELF_PRODUCER,
            crate::sampling::FIRMWARE_EVIDENCE_PRODUCER,
            crate::sampling::ANALYSIS_PRODUCER,
            crate::sampling::FLAT_PROFILE_PRODUCER,
        ]
        .contains(&producer)
}

fn is_reserved_stack_claim(id: &str, kind: &str, path: &str, producer: &str) -> bool {
    portable_starts_with(id, crate::stack::ARTIFACT_ID_PREFIX)
        || [
            crate::stack::RAW_KIND,
            crate::stack::CAPTURE_RECEIPT_KIND,
            crate::stack::PROFILE_KIND,
            crate::stack::FLAMEGRAPH_KIND,
        ]
        .contains(&kind)
        || portable_starts_with(path, crate::stack::CAPTURE_ARTIFACT_PATH_PREFIX)
        || portable_starts_with(path, crate::stack::ANALYSIS_ARTIFACT_PATH_PREFIX)
        || portable_starts_with(path, crate::stack::REPORT_ARTIFACT_PATH_PREFIX)
        || [
            crate::stack::SIDECAR_PRODUCER,
            crate::stack::CAPTURE_RECEIPT_PRODUCER,
            crate::stack::ANALYSIS_PRODUCER,
            crate::stack::FLAMEGRAPH_PRODUCER,
        ]
        .contains(&producer)
}

pub struct CommandOutcome {
    pub command: &'static str,
    pub result: Value,
    pub exit_code: u8,
}

#[derive(Debug)]
pub struct AppError {
    pub code: &'static str,
    pub message: String,
    pub details: Value,
    pub exit_code: u8,
}

impl AppError {
    pub(crate) fn from_session_store(error: SessionStoreError) -> Self {
        match error {
            SessionStoreError::SessionLocked { session_id } => Self {
                code: "SESSION_LOCK_BUSY",
                message: format!("Session `{session_id}` is locked by another operation"),
                details: json!({"session_id": session_id}),
                exit_code: EXIT_OPERATIONAL,
            },
            SessionStoreError::ArtifactRootNamespaceLocked { path } => Self {
                code: "ARTIFACT_ROOT_NAMESPACE_BUSY",
                message: format!(
                    "artifact-root Session namespace is locked: `{}`",
                    path.display()
                ),
                details: json!({"artifact_root": path}),
                exit_code: EXIT_OPERATIONAL,
            },
            error => Self::operational(error),
        }
    }

    pub(crate) fn is_transient_contention(&self) -> bool {
        matches!(
            self.code,
            "SESSION_LOCK_BUSY"
                | "ARTIFACT_ROOT_NAMESPACE_BUSY"
                | "SESSION_EXECUTION_BUSY"
                | "CONTROLLER_DRIVER_BUSY"
        )
    }

    pub(crate) fn is_nonterminal_retryable(&self) -> bool {
        self.is_transient_contention()
            || matches!(
                self.code,
                "CONTROLLER_TRANSACTION_PENDING"
                    | "CONTROLLER_CAPTURE_LEASE_ACTIVE"
                    | "CONTROLLER_ROOT_BUSY"
                    | "CONTROLLER_ROOT_OWNERSHIP_CONFLICT"
                    | "DRIVER_RESUME_REQUIRED"
                    | "ATTESTATION_SIGNER_OUTPUT_PENDING"
            )
    }

    pub fn operational(error: impl std::fmt::Display) -> Self {
        Self {
            code: "OPERATIONAL_ERROR",
            message: error.to_string(),
            details: json!({}),
            exit_code: EXIT_OPERATIONAL,
        }
    }

    pub(crate) fn unsupported(feature: &str, reason: impl Into<String>) -> Self {
        Self {
            code: "UNSUPPORTED",
            message: reason.into(),
            details: json!({"feature": feature}),
            exit_code: EXIT_UNSUPPORTED,
        }
    }

    pub(crate) fn state_persistence(
        stage: &str,
        original: &Self,
        persistence_error: impl std::fmt::Display,
    ) -> Self {
        Self {
            code: "STATE_PERSISTENCE_FAILED",
            message: format!(
                "stage `{stage}` failed and its durable failure state could not be persisted"
            ),
            details: json!({
                "stage": stage,
                "original_error": {
                    "code": original.code,
                    "message": original.message,
                    "details": original.details,
                    "exit_code": original.exit_code,
                },
                "persistence_error": persistence_error.to_string(),
            }),
            exit_code: EXIT_OPERATIONAL,
        }
    }
}

pub fn execute(cli: Cli) -> Result<CommandOutcome, AppError> {
    let root = ArtifactRoot::open(
        &cli.artifact_root,
        SessionLimits {
            max_file_bytes: cli.max_file_bytes,
            max_session_bytes: cli.max_session_bytes,
        },
    )
    .map_err(AppError::operational)?;

    match cli.command {
        Command::PerfCapabilities(arguments) => {
            with_managed_session_rejection(&root, &arguments.session, || {
                with_driver_execution_lease(&root, || {
                    crate::controller_driver::require_strict_performance_run_dispatch_admission(
                        &root,
                        &arguments.session,
                    )?;
                    perf_surface_outcome(
                        PerfSurfaceOperation::Capabilities,
                        crate::controller::perf_capabilities(&root, &arguments.session)?,
                    )
                })
            })
        }
        Command::PerfCapture(arguments) => {
            with_managed_session_rejection(&root, &arguments.session, || {
                with_driver_execution_lease(&root, || {
                    crate::controller_driver::require_strict_performance_run_dispatch_admission(
                        &root,
                        &arguments.session,
                    )?;
                    perf_surface_outcome(
                        PerfSurfaceOperation::Capture,
                        crate::controller::perf_capture(
                            &root,
                            &arguments.session,
                            arguments.mode.as_deref(),
                            arguments.workload_complete,
                        )?,
                    )
                })
            })
        }
        Command::PerfGetStatus(arguments) => perf_surface_outcome(
            PerfSurfaceOperation::GetStatus,
            session_status(&root, &arguments.session)?,
        ),
        Command::PerfGetSummary(arguments) => perf_surface_outcome(
            PerfSurfaceOperation::GetSummary,
            crate::summary::summary(&root, &arguments.session, arguments.top)?,
        ),
        Command::PerfListArtifacts(arguments) => perf_surface_outcome(
            PerfSurfaceOperation::ListArtifacts,
            artifacts_list(
                &root,
                &arguments.session,
                arguments.page.limit,
                arguments.page.after.as_deref(),
            )?,
        ),
        Command::PerfConvert(arguments) => {
            crate::pipeline::preflight_convert_format(&arguments.format)?;
            with_managed_session_rejection(&root, &arguments.session, || {
                perf_surface_outcome(
                    PerfSurfaceOperation::Convert,
                    convert_session(&root, &arguments.session, &arguments.format)?,
                )
            })
        }
        Command::PerfCompare(arguments) => {
            crate::pipeline::preflight_comparison_policy(&arguments.policy)?;
            perf_surface_outcome(
                PerfSurfaceOperation::Compare,
                crate::pipeline::compare(
                    &root,
                    &arguments.baseline,
                    &arguments.candidate,
                    &arguments.policy,
                    arguments.allow_inconclusive,
                    arguments.top,
                )?,
            )
        }
        Command::PerfRun(arguments) => perf_surface_outcome(
            PerfSurfaceOperation::Run,
            crate::perf_run::run(
                &root,
                arguments.duration_ms,
                arguments.id.as_deref(),
                arguments.top,
            )?,
        ),
        Command::Mcp => {
            crate::mcp::serve_stdio(crate::mcp::McpServerConfig {
                artifact_root: root.path().to_path_buf(),
                max_file_bytes: cli.max_file_bytes,
                max_session_bytes: cli.max_session_bytes,
            })?;
            success("mcp", json!({"transport": "stdio"}))
        }
        Command::Sampling(command) => match command.command {
            SamplingSubcommand::Prepare(arguments) => crate::sampling::prepare(&root, arguments),
            SamplingSubcommand::Ingest(arguments) => {
                let session_id = arguments.session.clone();
                with_managed_session_rejection(&root, &session_id, || {
                    with_driver_execution_lease(&root, || crate::sampling::ingest(&root, arguments))
                })
            }
            SamplingSubcommand::BindFirmware(arguments) => {
                let session_id = arguments.session.clone();
                with_managed_session_rejection(&root, &session_id, || {
                    crate::sampling::bind_firmware(&root, arguments)
                })
            }
            SamplingSubcommand::Analyze(arguments) => {
                let session_id = arguments.session.clone();
                with_managed_session_rejection(&root, &session_id, || {
                    crate::sampling::analyze(&root, arguments)
                })
            }
            SamplingSubcommand::Summary(arguments) => crate::sampling::summary(&root, arguments),
            SamplingSubcommand::Render(arguments) => {
                let session_id = arguments.session.clone();
                with_managed_session_rejection(&root, &session_id, || {
                    crate::sampling::render(&root, arguments)
                })
            }
            SamplingSubcommand::Flame(arguments) => {
                let session_id = arguments.session.clone();
                with_managed_session_rejection(&root, &session_id, || {
                    crate::sampling::render_flat_flame(&root, arguments)
                })
            }
        },
        Command::Stack(command) => match command.command {
            StackSubcommand::Prepare(arguments) => crate::stack::prepare(&root, arguments),
            StackSubcommand::Ingest(arguments) => {
                let session_id = arguments.session.clone();
                with_managed_session_rejection(&root, &session_id, || {
                    with_driver_execution_lease(&root, || crate::stack::ingest(&root, arguments))
                })
            }
            StackSubcommand::Analyze(arguments) => {
                let session_id = arguments.session.clone();
                with_managed_session_rejection(&root, &session_id, || {
                    crate::stack::analyze(&root, arguments)
                })
            }
            StackSubcommand::Summary(arguments) => crate::stack::summary(&root, arguments),
            StackSubcommand::Render(arguments) => {
                let session_id = arguments.session.clone();
                with_managed_session_rejection(&root, &session_id, || {
                    crate::stack::render(&root, arguments)
                })
            }
        },
        Command::Session(command) => execute_session(&root, command.command),
        Command::Maintenance(command) => match command.command {
            MaintenanceSubcommand::Inspect(arguments) => {
                crate::operations::inspect(&root, &arguments.session, arguments.deep)
            }
            MaintenanceSubcommand::Diagnostics(arguments) => {
                crate::operations::diagnostics(&root, &arguments.session)
            }
            MaintenanceSubcommand::Schema(arguments) => {
                crate::operations::schema_inventory(&root, arguments.session.as_deref())
            }
            MaintenanceSubcommand::Retention(command) => match command.command {
                RetentionSubcommand::Plan(arguments) => {
                    crate::operations::retention_plan(&root, &arguments.sessions)
                }
                RetentionSubcommand::Apply(arguments) => {
                    crate::operations::retention_apply(&root, &arguments.plan, &arguments.confirm)
                }
                RetentionSubcommand::Restore(arguments) => crate::operations::retention_restore(
                    &root,
                    &arguments.plan,
                    &arguments.session,
                    &arguments.confirm,
                ),
            },
            MaintenanceSubcommand::Abandon(command) => match command.command {
                AbandonSubcommand::Plan(arguments) => {
                    crate::operations::abandon_plan(&root, &arguments.session)
                }
                AbandonSubcommand::Apply(arguments) => {
                    crate::operations::abandon_apply(&root, &arguments.plan, &arguments.confirm)
                }
                AbandonSubcommand::Restore(arguments) => {
                    crate::operations::abandon_restore(&root, &arguments.plan, &arguments.confirm)
                }
            },
        },
        Command::Normalize(arguments) => {
            with_managed_session_rejection(&root, &arguments.session, || {
                crate::normalize::normalize(
                    &root,
                    &arguments.session,
                    arguments.input_artifact.as_deref(),
                    &arguments.config_artifact,
                )
            })
        }
        Command::Validate(arguments) => validate(&root, &arguments.session, arguments.deep),
        Command::Analyze(arguments) => {
            let static_ram_flavor = match (
                arguments.static_ram_flavor.as_deref(),
                arguments.linker_map_flavor.as_deref(),
            ) {
                (Some(current), Some(legacy)) if current != legacy => {
                    return Err(AppError::unsupported(
                        "analyze.static_ram_flavor",
                        format!(
                            "--static-ram-flavor `{current}` conflicts with --linker-map-flavor `{legacy}`"
                        ),
                    ));
                }
                (Some(current), _) => current,
                (None, Some(legacy)) => legacy,
                (None, None) => GNU_LD_MAP_V1_FLAVOR,
            };
            crate::pipeline::preflight_analysis_flavors(
                static_ram_flavor,
                &arguments.stack_usage_flavor,
            )?;
            with_managed_session_rejection(&root, &arguments.session, || {
                crate::pipeline::analyze(
                    &root,
                    &arguments.session,
                    static_ram_flavor,
                    &arguments.stack_usage_flavor,
                )
            })
        }
        Command::Summary(arguments) => {
            crate::summary::summary(&root, &arguments.session, arguments.top)
        }
        Command::Convert(arguments) => {
            crate::pipeline::preflight_convert_format(&arguments.format)?;
            with_managed_session_rejection(&root, &arguments.session, || {
                convert_session(&root, &arguments.session, &arguments.format)
            })
        }
        Command::Compare(arguments) => {
            crate::pipeline::preflight_comparison_policy(&arguments.policy)?;
            crate::pipeline::compare(
                &root,
                &arguments.baseline,
                &arguments.candidate,
                &arguments.policy,
                arguments.allow_inconclusive,
                arguments.top,
            )
        }
        Command::Controller(command) => match command.command {
            ControllerSubcommand::ProvisionFirmware(arguments) => {
                ArtifactPath::new(arguments.staged.clone()).map_err(AppError::operational)?;
                let session_id = arguments.session.clone();
                with_managed_session_rejection(&root, &session_id, || {
                    with_driver_execution_lease(&root, || {
                        crate::controller_driver::require_strict_performance_run_dispatch_admission(
                            &root,
                            &arguments.session,
                        )?;
                        crate::controller_qualification::provision_firmware_command(
                            &root, arguments,
                        )
                    })
                })
            }
            ControllerSubcommand::ProvisionQualification(arguments) => {
                if !is_portable_artifact_id(&arguments.policy_id) {
                    return Err(AppError::operational(
                        "qualification policy ID is not a portable artifact identifier",
                    ));
                }
                ArtifactPath::new(arguments.qualification_staged.clone())
                    .map_err(AppError::operational)?;
                ArtifactPath::new(arguments.hil_staged.clone()).map_err(AppError::operational)?;
                if let Some(recovery_staged) = &arguments.recovery_staged {
                    ArtifactPath::new(recovery_staged.clone()).map_err(AppError::operational)?;
                }
                let session_id = arguments.session.clone();
                with_managed_session_rejection(&root, &session_id, || {
                    with_driver_execution_lease(&root, || {
                        crate::controller_driver::require_strict_performance_run_dispatch_admission(
                            &root,
                            &arguments.session,
                        )?;
                        crate::controller_qualification::provision(&root, arguments)
                    })
                })
            }
            ControllerSubcommand::SelectScenario(arguments) => {
                t32perf_trace32::TargetAdapterScenario::parse(&arguments.scenario).ok_or_else(
                    || {
                        AppError::operational(
                            "target-adapter scenario is not in the closed deployment vocabulary",
                        )
                    },
                )?;
                let session_id = arguments.session.clone();
                with_managed_session_rejection(&root, &session_id, || {
                    with_driver_execution_lease(&root, || {
                        crate::controller_driver::require_strict_performance_run_dispatch_admission(
                            &root,
                            &arguments.session,
                        )?;
                        crate::controller_qualification::select_scenario(&root, arguments)
                    })
                })
            }
            ControllerSubcommand::Prepare(arguments) => {
                crate::controller::preflight_prepare(
                    &arguments.operation,
                    arguments.mode.as_deref(),
                )?;
                with_managed_session_rejection(&root, &arguments.session, || {
                    with_driver_execution_lease(&root, || {
                        crate::controller_driver::require_strict_performance_run_dispatch_admission(
                            &root,
                            &arguments.session,
                        )?;
                        crate::controller::prepare(
                            &root,
                            &arguments.session,
                            &arguments.operation,
                            arguments.mode.as_deref(),
                        )
                    })
                })
            }
            ControllerSubcommand::Accept(arguments) => {
                crate::controller::preflight_transaction_id(&arguments.transaction)?;
                with_managed_session_rejection(&root, &arguments.session, || {
                    with_driver_execution_lease(&root, || {
                        crate::controller_driver::require_strict_performance_run_dispatch_admission(
                            &root,
                            &arguments.session,
                        )?;
                        crate::controller::accept(&root, &arguments.session, &arguments.transaction)
                    })
                })
            }
            ControllerSubcommand::Abort(arguments) => {
                crate::controller::preflight_abort(&arguments.transaction, &arguments.reason)?;
                with_session_execution_lease(&root, &arguments.session, || {
                    with_driver_execution_lease(&root, || {
                        crate::controller::abort(
                            &root,
                            &arguments.session,
                            &arguments.transaction,
                            &arguments.reason,
                        )
                    })
                })
            }
            ControllerSubcommand::ConfirmAbort(arguments) => {
                crate::controller::preflight_confirm_abort(
                    &arguments.transaction,
                    arguments.acknowledge_unbound_success,
                )?;
                with_session_execution_lease(&root, &arguments.session, || {
                    with_driver_execution_lease(&root, || {
                        crate::controller::confirm_abort(
                            &root,
                            &arguments.session,
                            &arguments.transaction,
                            arguments.acknowledge_unbound_success,
                        )
                    })
                })
            }
            ControllerSubcommand::Drive(arguments) => {
                crate::controller_driver::preflight_drive(
                    arguments.surface,
                    arguments.mode.as_deref(),
                )?;
                with_session_execution_lease(&root, &arguments.session, || {
                    crate::controller_driver::drive(
                        &root,
                        &arguments.session,
                        arguments.surface,
                        arguments.mode.as_deref(),
                    )
                })
            }
            ControllerSubcommand::DriverPreflight => {
                crate::controller_driver::driver_preflight(&root)
            }
            ControllerSubcommand::DriveTransaction(arguments) => {
                crate::controller::preflight_transaction_id(&arguments.transaction)?;
                with_session_execution_lease(&root, &arguments.session, || {
                    crate::controller_driver::drive_transaction(
                        &root,
                        &arguments.session,
                        &arguments.transaction,
                    )
                })
            }
            ControllerSubcommand::AbortUpstream(arguments) => {
                crate::controller::preflight_abort(&arguments.transaction, &arguments.reason)?;
                with_session_execution_lease(&root, &arguments.session, || {
                    crate::controller_driver::abort_upstream(
                        &root,
                        &arguments.session,
                        &arguments.transaction,
                        &arguments.reason,
                    )
                })
            }
            ControllerSubcommand::Recover(command) => match command.command {
                ControllerRecoverSubcommand::Prepare(arguments) => {
                    crate::controller_recovery::preflight_prepare_recovery(
                        &arguments.session,
                        &arguments.transaction,
                    )?;
                    let scope = match arguments.scope.as_str() {
                        "endpoint" => crate::controller_recovery::RecoveryScopeArgument::Endpoint,
                        "target" => crate::controller_recovery::RecoveryScopeArgument::Target,
                        _ => unreachable!("clap validates controller recovery scope"),
                    };
                    with_session_execution_lease(&root, &arguments.session, || {
                        with_driver_execution_lease(&root, || {
                            crate::controller_recovery::prepare_recovery(
                                &root,
                                &arguments.session,
                                &arguments.transaction,
                                scope,
                            )
                        })
                    })
                }
                ControllerRecoverSubcommand::Accept(arguments) => {
                    crate::controller_recovery::preflight_accept_recovery(&arguments.reservation)?;
                    with_all_session_execution_leases(&root, || {
                        with_driver_execution_lease(&root, || {
                            crate::controller_recovery::accept_recovery(
                                &root,
                                &arguments.reservation,
                            )
                        })
                    })
                }
            },
            ControllerSubcommand::Status(arguments) => {
                let mut outcome = crate::controller::status(&root, &arguments.session)?;
                let session_quarantine =
                    crate::controller_recovery::quarantine_status(&root, &arguments.session)?;
                let root_quarantine = crate::controller_recovery::root_quarantine_status(&root)?;
                let object = outcome
                    .result
                    .as_object_mut()
                    .expect("controller status result is an object");
                object.insert("session_quarantine".to_owned(), session_quarantine);
                object.insert("root_quarantine".to_owned(), root_quarantine);
                Ok(outcome)
            }
        },
        Command::Artifacts(command) => match command.command {
            ArtifactsSubcommand::List(arguments) => artifacts_list(
                &root,
                &arguments.session,
                arguments.page.limit,
                arguments.page.after.as_deref(),
            ),
            ArtifactsSubcommand::Verify(arguments) => artifacts_verify(
                &root,
                &arguments.session,
                arguments.id.as_deref(),
                !arguments.shallow,
            ),
        },
        Command::Doctor => doctor(&root),
        Command::Fixture(command) => match command.command {
            FixtureSubcommand::Generate(arguments) => {
                capture_synthetic(&root, arguments.id, arguments.events, "fixture.generate")
            }
        },
        Command::Capture(arguments) => {
            if arguments.provider != "synthetic" {
                return Err(AppError::unsupported(
                    "capture.provider",
                    format!(
                        "capture provider `{}` is unavailable; TRACE32 capture remains controlled by the external t32mcp skill",
                        arguments.provider
                    ),
                ));
            }
            capture_synthetic(&root, arguments.id, arguments.events, "capture.synthetic")
        }
    }
}

fn with_driver_execution_lease(
    root: &ArtifactRoot,
    operation: impl FnOnce() -> Result<CommandOutcome, AppError>,
) -> Result<CommandOutcome, AppError> {
    let _lease = crate::controller_driver::lease::try_acquire(root)?;
    operation()
}

/// Holds the per-Session execution lease across an external mutation before
/// opening any Session or inspecting its immutable request.
fn with_session_execution_lease(
    root: &ArtifactRoot,
    session_id: &str,
    operation: impl FnOnce() -> Result<CommandOutcome, AppError>,
) -> Result<CommandOutcome, AppError> {
    with_session_execution_leases(root, &[session_id], false, operation)
}

fn with_managed_session_rejection(
    root: &ArtifactRoot,
    session_id: &str,
    operation: impl FnOnce() -> Result<CommandOutcome, AppError>,
) -> Result<CommandOutcome, AppError> {
    with_session_execution_leases(root, &[session_id], true, operation)
}

fn with_session_execution_leases(
    root: &ArtifactRoot,
    session_ids: &[&str],
    reject_managed: bool,
    operation: impl FnOnce() -> Result<CommandOutcome, AppError>,
) -> Result<CommandOutcome, AppError> {
    let mut session_ids = session_ids
        .iter()
        .map(|value| SessionId::new((*value).to_owned()).map_err(AppError::operational))
        .collect::<Result<Vec<_>, _>>()?;
    session_ids.sort();
    session_ids.dedup();

    let mut _leases = Vec::new();
    for session_id in &session_ids {
        _leases.push(crate::perf_run::try_acquire_session_id_execution_lease(
            root, session_id,
        )?);
    }
    for session_id in &session_ids {
        match root.session(session_id) {
            Ok(session) => {
                validate_strict_performance_run_claim(&session)?;
                if reject_managed && is_managed_performance_run_session(&session)? {
                    return Err(AppError {
                        code: "PERF_RUN_MANAGED_SESSION",
                        message: format!(
                            "Session `{}` is managed exclusively by perf_run; rerun perf_run to continue",
                            session.id()
                        ),
                        details: json!({"session_id": session.id().as_str()}),
                        exit_code: EXIT_OPERATIONAL,
                    });
                }
            }
            Err(SessionStoreError::SessionNotFound { .. }) => {}
            Err(error) => return Err(AppError::from_session_store(error)),
        }
    }
    operation()
}

/// Recovery acceptance names a reservation rather than a Session. Acquire
/// every existing Session execution lease before resolving that reservation.
fn with_all_session_execution_leases(
    root: &ArtifactRoot,
    operation: impl FnOnce() -> Result<CommandOutcome, AppError>,
) -> Result<CommandOutcome, AppError> {
    let session_ids = root.list_sessions().map_err(AppError::operational)?;
    let session_ids = session_ids
        .iter()
        .map(SessionId::as_str)
        .collect::<Vec<_>>();
    with_session_execution_leases(root, &session_ids, false, operation)
}

fn validate_strict_performance_run_claim(session: &Session) -> Result<(), AppError> {
    let request = session.request().map_err(AppError::from_session_store)?;
    if request.get("schema").and_then(Value::as_str) != Some(PERFORMANCE_RUN_REQUEST_SCHEMA) {
        return Ok(());
    }
    let request: PerformanceRunRequest = serde_json::from_value(request).map_err(|error| {
        AppError::operational(format!(
            "perf_run Session `{}` has an invalid immutable request: {error}",
            session.id()
        ))
    })?;
    request.validate().map_err(AppError::operational)
}

fn is_managed_performance_run_session(session: &Session) -> Result<bool, AppError> {
    Ok(session
        .request()
        .map_err(AppError::from_session_store)?
        .get("schema")
        .and_then(Value::as_str)
        == Some(PERFORMANCE_RUN_REQUEST_SCHEMA))
}

fn perf_surface_outcome(
    operation: PerfSurfaceOperation,
    outcome: CommandOutcome,
) -> Result<CommandOutcome, AppError> {
    let response = match operation {
        PerfSurfaceOperation::Run => PerfSurfaceResponse::Run(decode_surface_payload::<
            t32perf_model::PerfRunPayload,
        >(outcome.result, operation)?),
        PerfSurfaceOperation::Capabilities => PerfSurfaceResponse::Capabilities(
            decode_surface_payload::<PerfControlPayload>(outcome.result, operation)?,
        ),
        PerfSurfaceOperation::Capture => PerfSurfaceResponse::Capture(decode_surface_payload::<
            PerfControlPayload,
        >(
            outcome.result, operation
        )?),
        PerfSurfaceOperation::GetStatus => PerfSurfaceResponse::GetStatus(
            decode_surface_payload::<PerfGetStatusPayload>(outcome.result, operation)?,
        ),
        PerfSurfaceOperation::GetSummary => {
            PerfSurfaceResponse::GetSummary(Box::new(decode_surface_payload::<
                PerfGetSummaryPayload,
            >(
                summary_surface_projection(outcome.result)?,
                operation,
            )?))
        }
        PerfSurfaceOperation::ListArtifacts => PerfSurfaceResponse::ListArtifacts(
            decode_surface_payload::<PerfListArtifactsPayload>(outcome.result, operation)?,
        ),
        PerfSurfaceOperation::Convert => PerfSurfaceResponse::Convert(decode_surface_payload::<
            PerfConvertPayload,
        >(
            outcome.result, operation
        )?),
        PerfSurfaceOperation::Compare => {
            PerfSurfaceResponse::Compare(decode_surface_payload::<PerfComparePayload>(
                comparison_surface_projection(outcome.result)?,
                operation,
            )?)
        }
    };
    let envelope = PerfSurfaceEnvelope::new(response);
    Ok(CommandOutcome {
        command: operation.as_str(),
        result: serde_json::to_value(envelope).map_err(AppError::operational)?,
        exit_code: outcome.exit_code,
    })
}

fn decode_surface_payload<T: DeserializeOwned>(
    value: Value,
    operation: PerfSurfaceOperation,
) -> Result<T, AppError> {
    serde_json::from_value(value).map_err(|error| {
        AppError::operational(format!(
            "{} internal result violates its typed façade contract: {error}",
            operation.as_str()
        ))
    })
}

fn summary_surface_projection(mut value: Value) -> Result<Value, AppError> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| AppError::operational("summary produced a non-object result"))?;
    if let Some(quantitative) = object.get_mut("quantitative") {
        quantitative
            .as_object_mut()
            .ok_or_else(|| AppError::operational("summary quantitative result is not an object"))?
            .remove("resources");
    }
    Ok(value)
}

fn comparison_surface_projection(mut value: Value) -> Result<Value, AppError> {
    let report = value
        .as_object_mut()
        .and_then(|object| object.get_mut("report"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| AppError::operational("comparison produced no report projection"))?;
    for field in [
        "metrics",
        "metrics_returned_count",
        "metrics_truncated",
        "resource_metrics",
        "resource_metrics_returned_count",
        "resource_metrics_truncated",
        "static_ram_metrics",
        "static_ram_metrics_returned_count",
        "static_ram_metrics_truncated",
    ] {
        report.remove(field);
    }
    Ok(value)
}

fn convert_session(
    root: &ArtifactRoot,
    session_id: &str,
    format: &str,
) -> Result<CommandOutcome, AppError> {
    if format != "perfetto-json" {
        return Err(AppError::unsupported(
            "convert.format",
            format!("conversion format `{format}` is unsupported"),
        ));
    }
    crate::pipeline::convert(root, session_id)
}

fn session_status(root: &ArtifactRoot, session_id: &str) -> Result<CommandOutcome, AppError> {
    let session = open_session(root, session_id)?;
    let state = session.read_state().map_err(AppError::operational)?;
    let manifest = session.manifest().map_err(AppError::operational)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    let stage_artifact = find_artifact(&artifacts, ANALYSIS_STAGE_ID);
    let health_verdict = match stage_artifact {
        Some(stage_artifact) => {
            let stage = read_artifact_json::<AnalysisStageReceipt>(&session, stage_artifact)?;
            validate_analysis_stage_receipt(
                &stage,
                stage_artifact,
                &artifacts,
                session.id().as_str(),
            )?;
            let health_artifact = find_artifact(&artifacts, "health").ok_or_else(|| {
                AppError::operational(
                    "analysis stage completed without a registered health artifact",
                )
            })?;
            let health = read_artifact_json::<HealthReport>(&session, health_artifact)?;
            validate_health_document(&session, &health, &stage)?;
            let summary_artifact =
                find_artifact(&artifacts, "analysis-summary").ok_or_else(|| {
                    AppError::operational(
                        "analysis stage completed without a registered summary artifact",
                    )
                })?;
            let summary =
                read_artifact_json::<AnalysisSummaryDocument>(&session, summary_artifact)?;
            validate_summary_document(&session, summary_artifact, &summary, &stage, &artifacts)?;
            Some(health.verdict)
        }
        None => None,
    };
    let trust_status = match (state.status, health_verdict) {
        (SessionStatus::Failed, _) => json!("INCOMPLETE"),
        (SessionStatus::Processing | SessionStatus::Complete, None) => json!("INCOMPLETE"),
        (_, Some(verdict)) => json!(verdict),
        _ => json!("NOT_EVALUATED"),
    };
    success(
        "session.status",
        json!({
            "session_id": session.id().as_str(),
            "state": state,
            "manifest_committed": manifest.is_some(),
            "artifact_count": artifacts.len(),
            "trust_status": trust_status,
            "health_verdict": health_verdict,
        }),
    )
}

fn execute_session(
    root: &ArtifactRoot,
    command: SessionSubcommand,
) -> Result<CommandOutcome, AppError> {
    match command {
        SessionSubcommand::Ingest(arguments) => {
            preflight_external_ingest(&arguments)?;
            let session_id = arguments.session.clone();
            with_managed_session_rejection(root, &session_id, || {
                execute_session_unleased(root, SessionSubcommand::Ingest(arguments))
            })
        }
        SessionSubcommand::Attest(arguments) => {
            ArtifactPath::new(arguments.staged.clone()).map_err(AppError::operational)?;
            let session_id = arguments.session.clone();
            with_managed_session_rejection(root, &session_id, || {
                execute_session_unleased(root, SessionSubcommand::Attest(arguments))
            })
        }
        command => execute_session_unleased(root, command),
    }
}

fn execute_session_unleased(
    root: &ArtifactRoot,
    command: SessionSubcommand,
) -> Result<CommandOutcome, AppError> {
    match command {
        SessionSubcommand::Create(arguments) => {
            let request: Value =
                strict_json::from_str(&arguments.request).map_err(AppError::operational)?;
            if !request.is_object() {
                return Err(AppError::operational(
                    "session request must be a JSON object",
                ));
            }
            if request.get("schema").and_then(Value::as_str) == Some(PERFORMANCE_RUN_REQUEST_SCHEMA)
            {
                return Err(AppError::unsupported(
                    "session.create.request",
                    "performance-run Sessions are created only by perf_run",
                ));
            }
            let session_id = arguments
                .id
                .map(SessionId::new)
                .transpose()
                .map_err(AppError::operational)?
                .unwrap_or_else(SessionId::generate);
            let _lease =
                crate::perf_run::try_acquire_session_id_execution_lease(root, &session_id)?;
            let session = root
                .create_session_with_id(session_id, &request)
                .map_err(AppError::operational)?;
            let state = session.read_state().map_err(AppError::operational)?;
            success(
                "session.create",
                json!({
                    "session_id": session.id().as_str(),
                    "status": state.status,
                    "revision": state.revision,
                }),
            )
        }
        SessionSubcommand::List(arguments) => {
            let after = arguments
                .after
                .map(SessionId::new)
                .transpose()
                .map_err(AppError::operational)?;
            let sessions = root.list_sessions().map_err(AppError::operational)?;
            let total_count = sessions.len();
            let mut sessions = sessions
                .into_iter()
                .filter(|id| after.as_ref().is_none_or(|after| id > after))
                .take(arguments.limit.saturating_add(1))
                .map(|id| {
                    let session = root.session(&id).map_err(AppError::operational)?;
                    let state = session.read_state().map_err(AppError::operational)?;
                    let artifact_count = session
                        .registered_artifacts(false)
                        .map_err(AppError::operational)?
                        .len();
                    Ok(json!({
                        "session_id": id.as_str(),
                        "status": state.status,
                        "revision": state.revision,
                        "artifact_count": artifact_count,
                    }))
                })
                .collect::<Result<Vec<_>, AppError>>()?;
            let truncated = sessions.len() > arguments.limit;
            if truncated {
                sessions.truncate(arguments.limit);
            }
            let next_after = truncated
                .then(|| {
                    sessions
                        .last()
                        .and_then(|session| session["session_id"].as_str())
                        .map(str::to_owned)
                })
                .flatten();
            let returned_count = sessions.len();
            success(
                "session.list",
                json!({
                    "sessions": sessions,
                    "total_count": total_count,
                    "returned_count": returned_count,
                    "limit": arguments.limit,
                    "after": after.as_ref().map(SessionId::as_str),
                    "truncated": truncated,
                    "next_after": next_after,
                }),
            )
        }
        SessionSubcommand::Status(arguments) => session_status(root, &arguments.session),
        SessionSubcommand::Ingest(arguments) => {
            preflight_external_ingest(&arguments)?;
            let capture_config_fields = [
                portable_eq(&arguments.id, CAPTURE_CONFIG_ID),
                arguments.kind == CAPTURE_CONFIG_KIND,
                portable_eq(&arguments.destination, CAPTURE_CONFIG_PATH),
            ];
            if capture_config_fields.iter().any(|matches| *matches)
                && !capture_config_fields.iter().all(|matches| *matches)
            {
                return Err(AppError::operational(format!(
                    "capture config must use ID `{CAPTURE_CONFIG_ID}`, kind `{CAPTURE_CONFIG_KIND}`, and destination `{CAPTURE_CONFIG_PATH}` together"
                )));
            }
            let reserved_capture_provenance = portable_matches_any(
                &arguments.id,
                &[
                    ATTESTATION_SIGNING_REQUEST_ID,
                    ATTESTATION_SIGNER_DISPATCH_INTENT_ID,
                    CAPTURE_ATTESTATION_ID,
                    CAPTURE_TRUST_POLICY_ID,
                    crate::receipt::CAPTURE_RECEIPT_ID,
                ],
            ) || [
                ATTESTATION_SIGNING_REQUEST_KIND,
                ATTESTATION_SIGNER_DISPATCH_INTENT_KIND,
                CAPTURE_ATTESTATION_KIND,
                CAPTURE_TRUST_POLICY_KIND,
                "capture_receipt",
            ]
            .contains(&arguments.kind.as_str())
                || portable_matches_any(
                    &arguments.destination,
                    &[
                        ATTESTATION_SIGNING_REQUEST_PATH,
                        ATTESTATION_SIGNER_DISPATCH_INTENT_PATH,
                        CAPTURE_ATTESTATION_PATH,
                        CAPTURE_TRUST_POLICY_PATH,
                        CAPTURE_RECEIPT_PATH,
                    ],
                );
            if reserved_capture_provenance {
                return Err(AppError::operational(format!(
                    "artifact ID `{}`, kind `{}`, or destination `{}` is reserved for verified capture provenance",
                    arguments.id, arguments.kind, arguments.destination
                )));
            }
            let reserved_controller_artifact = is_reserved_controller_claim(
                &arguments.id,
                &arguments.kind,
                &arguments.destination,
                &arguments.producer,
            );
            if reserved_controller_artifact {
                return Err(AppError::operational(
                    "controller artifact identifiers, kinds, paths, and producer are reserved for the typed t32mcp transaction boundary",
                ));
            }
            if is_reserved_sampling_claim(
                &arguments.id,
                &arguments.kind,
                &arguments.destination,
                &arguments.producer,
            ) || is_reserved_stack_claim(
                &arguments.id,
                &arguments.kind,
                &arguments.destination,
                &arguments.producer,
            ) {
                return Err(AppError::operational(
                    "sampling artifact identifiers, kinds, paths, and producers are reserved for the typed sampling boundary",
                ));
            }
            let reserved_semantic_mapping = portable_matches_any(
                &arguments.id,
                &[
                    crate::normalize::TRACE32_SYMBOL_MAPPING_ARTIFACT_ID,
                    crate::normalize::TRACE32_TASK_EVENTS_MAPPING_ARTIFACT_ID,
                ],
            ) || [
                crate::normalize::TRACE32_SYMBOL_MAPPING_ARTIFACT_KIND,
                crate::normalize::TRACE32_TASK_EVENTS_MAPPING_ARTIFACT_KIND,
                crate::normalize::C_WIRE_COUNTER_MAPPING_ARTIFACT_KIND,
            ]
            .contains(&arguments.kind.as_str())
                || portable_matches_any(
                    &arguments.destination,
                    &[
                        crate::normalize::TRACE32_SYMBOL_MAPPING_ARTIFACT_PATH,
                        crate::normalize::TRACE32_TASK_EVENTS_MAPPING_ARTIFACT_PATH,
                    ],
                )
                || [
                    crate::normalize::TRACE32_TASK_EVENTS_MAPPING_PRODUCER,
                    crate::normalize::C_WIRE_COUNTER_MAPPING_PRODUCER,
                ]
                .contains(&arguments.producer.as_str());
            if reserved_semantic_mapping {
                return Err(AppError::operational(
                    "semantic mapping artifact identifiers, kinds, paths, and producers are reserved for trusted host derivation or deployment qualification",
                ));
            }
            let reserved_analysis_request = is_reserved_analysis_request(
                &arguments.id,
                &arguments.kind,
                &arguments.destination,
                &arguments.producer,
            );
            if reserved_analysis_request {
                return Err(AppError::operational(
                    "analysis request identifiers, kinds, paths, and producers are reserved for the immutable Host analysis binding",
                ));
            }
            if [
                SYNTHETIC_RECEIPT_PRODUCER,
                ANALYSIS_STAGE_PRODUCER,
                "t32perf-static-ram",
                "t32perf-stack-usage",
                "t32perf-perfetto",
                ANALYSIS_REQUEST_PRODUCER,
                "t32perf-normalize/v1",
                SYNTHETIC_CAPTURE_CONFIG_PRODUCER,
                ATTESTATION_SIGNING_REQUEST_PRODUCER,
                ATTESTATION_SIGNER_DISPATCH_INTENT_PRODUCER,
                CAPTURE_ATTESTATION_PRODUCER,
                CAPTURE_TRUST_POLICY_PRODUCER,
            ]
            .contains(&arguments.producer.as_str())
            {
                return Err(AppError::operational(format!(
                    "producer `{}` is reserved for an internal pipeline stage",
                    arguments.producer
                )));
            }
            let session = open_session(root, &arguments.session)?;
            let lock = session.try_lock().map_err(AppError::operational)?;
            let artifacts = session
                .registered_artifacts(false)
                .map_err(AppError::operational)?;
            if portable_eq(&arguments.id, CAPTURE_CONFIG_ID)
                && artifacts.iter().any(is_controller_owned_artifact)
            {
                return Err(AppError::operational(
                    "controller-owned capture config is reserved after controller activity; external capture config remains available before a controller request",
                ));
            }
            if arguments.kind == crate::controller_qualification::FIRMWARE_ELF_ARTIFACT_KIND
                && artifacts.iter().any(|artifact| {
                    artifact.kind == crate::controller_qualification::FIRMWARE_ELF_ARTIFACT_KIND
                        && !portable_eq(&artifact.id, &arguments.id)
                })
            {
                return Err(AppError::operational(
                    "a Session can register only one firmware_elf resource artifact",
                ));
            }
            crate::controller::ensure_controller_session_releasable(root, &session)?;
            ensure_controller_capture_complete_for_ingest(root, &session, &artifacts)?;
            let staged = ArtifactPath::new(arguments.staged).map_err(AppError::operational)?;
            let spec = ArtifactSpec {
                id: arguments.id,
                kind: arguments.kind,
                relative_path: ArtifactPath::new(arguments.destination)
                    .map_err(AppError::operational)?,
                media_type: arguments.media_type,
                producer: arguments.producer,
                input_artifact_ids: arguments.input_artifact_ids,
            };
            let initial = session.read_state().map_err(AppError::operational)?;
            if !matches!(
                initial.status,
                SessionStatus::Created | SessionStatus::Capturing | SessionStatus::Captured
            ) {
                return Err(AppError::operational(format!(
                    "session `{}` cannot ingest artifacts while its status is {:?}",
                    session.id(),
                    initial.status
                )));
            }
            let preexisting_intents = match session.inspect_ingest_intents() {
                Ok(inspections) => inspections,
                Err(error) => {
                    return Err(terminal_ingest_failure(
                        &session,
                        &lock,
                        initial.status,
                        true,
                        AppError::operational(error),
                    ));
                }
            };
            if initial.status == SessionStatus::Created && preexisting_intents.is_empty() {
                session
                    .transition(&lock, SessionStatus::Capturing, None)
                    .map_err(AppError::operational)?;
            }
            let artifact = match session.ingest_staged(&lock, &staged, spec) {
                Ok(artifact) => artifact,
                Err(error) => {
                    let inspections = session.inspect_ingest_intents();
                    if !matches!(&error, SessionStoreError::IngestIntentConflict { .. })
                        && let Ok(inspections) = &inspections
                        && !inspections.is_empty()
                        && inspections.iter().all(is_recoverable_ingest_intent)
                    {
                        return Err(ingest_recovery_required(
                            &session,
                            initial.status,
                            &error,
                            inspections,
                        ));
                    }
                    let durable_conflict = inspections
                        .as_ref()
                        .map_or(true, |inspections| !inspections.is_empty());
                    let mut original = AppError::operational(&error);
                    if let Err(inspection_error) = inspections {
                        original.details = json!({
                            "inspection_error": bounded_ingest_text(&inspection_error.to_string()),
                        });
                    }
                    return Err(terminal_ingest_failure(
                        &session,
                        &lock,
                        initial.status,
                        durable_conflict,
                        original,
                    ));
                }
            };
            let state = persist_ingest_captured_state(&session, &lock, initial)?;
            success(
                "session.ingest",
                json!({"artifact": artifact, "status": state.status}),
            )
        }
        SessionSubcommand::Attest(arguments) => {
            let session = open_session(root, &arguments.session)?;
            let lock = session.try_lock().map_err(AppError::operational)?;
            crate::controller::ensure_controller_session_releasable(root, &session)?;
            let initial = session.read_state().map_err(AppError::operational)?;
            if initial.status != SessionStatus::Captured {
                return Err(AppError::operational(format!(
                    "session `{}` can only accept a capture attestation while captured; current status is {:?}",
                    session.id(),
                    initial.status
                )));
            }
            let attested = (|| {
                let staged = ArtifactPath::new(arguments.staged)?;
                attest_captured_session(&session, &lock, &staged, &arguments.policy)
            })();
            let attested = match attested {
                Ok(attested) => attested,
                Err(error) => {
                    let message = error.to_string();
                    let original = AppError::operational(&message);
                    if let Err(state_error) = session.transition(
                        &lock,
                        SessionStatus::Failed,
                        Some(SessionError {
                            code: "CAPTURE_ATTESTATION_FAILED".to_owned(),
                            message: message.clone(),
                            details: Default::default(),
                        }),
                    ) {
                        return Err(AppError::state_persistence(
                            "capture_attestation",
                            &original,
                            state_error,
                        ));
                    }
                    return Err(original);
                }
            };
            let state = session.read_state().map_err(AppError::operational)?;
            success(
                "session.attest",
                json!({
                    "session_id": session.id().as_str(),
                    "status": state.status,
                    "producer": attested.producer,
                    "policy_id": attested.policy_id,
                    "key_id": attested.key_id,
                    "artifacts": [
                        attested.attestation_artifact,
                        attested.policy_artifact,
                        attested.receipt_artifact,
                    ],
                }),
            )
        }
    }
}

fn preflight_external_ingest(arguments: &SessionIngestArgs) -> Result<(), AppError> {
    let staged = ArtifactPath::new(arguments.staged.clone()).map_err(AppError::operational)?;
    let spec = ArtifactSpec {
        id: arguments.id.clone(),
        kind: arguments.kind.clone(),
        relative_path: ArtifactPath::new(arguments.destination.clone())
            .map_err(AppError::operational)?,
        media_type: arguments.media_type.clone(),
        producer: arguments.producer.clone(),
        input_artifact_ids: arguments.input_artifact_ids.clone(),
    };
    let _ = staged;
    spec.validate().map_err(AppError::from_session_store)?;
    let capture_config_fields = [
        portable_eq(&arguments.id, CAPTURE_CONFIG_ID),
        arguments.kind == CAPTURE_CONFIG_KIND,
        portable_eq(&arguments.destination, CAPTURE_CONFIG_PATH),
    ];
    if capture_config_fields.iter().any(|matches| *matches)
        && !capture_config_fields.iter().all(|matches| *matches)
    {
        return Err(AppError::operational(format!(
            "capture config must use ID `{CAPTURE_CONFIG_ID}`, kind `{CAPTURE_CONFIG_KIND}`, and destination `{CAPTURE_CONFIG_PATH}` together"
        )));
    }
    let reserved_capture_provenance = portable_matches_any(
        &arguments.id,
        &[
            ATTESTATION_SIGNING_REQUEST_ID,
            ATTESTATION_SIGNER_DISPATCH_INTENT_ID,
            CAPTURE_ATTESTATION_ID,
            CAPTURE_TRUST_POLICY_ID,
            crate::receipt::CAPTURE_RECEIPT_ID,
        ],
    ) || [
        ATTESTATION_SIGNING_REQUEST_KIND,
        ATTESTATION_SIGNER_DISPATCH_INTENT_KIND,
        CAPTURE_ATTESTATION_KIND,
        CAPTURE_TRUST_POLICY_KIND,
        "capture_receipt",
    ]
    .contains(&arguments.kind.as_str())
        || portable_matches_any(
            &arguments.destination,
            &[
                ATTESTATION_SIGNING_REQUEST_PATH,
                ATTESTATION_SIGNER_DISPATCH_INTENT_PATH,
                CAPTURE_ATTESTATION_PATH,
                CAPTURE_TRUST_POLICY_PATH,
                CAPTURE_RECEIPT_PATH,
            ],
        );
    if reserved_capture_provenance {
        return Err(AppError::operational(format!(
            "artifact ID `{}`, kind `{}`, or destination `{}` is reserved for verified capture provenance",
            arguments.id, arguments.kind, arguments.destination
        )));
    }
    if is_reserved_controller_claim(
        &arguments.id,
        &arguments.kind,
        &arguments.destination,
        &arguments.producer,
    ) {
        return Err(AppError::operational(
            "controller artifact identifiers, kinds, paths, and producer are reserved for the typed t32mcp transaction boundary",
        ));
    }
    if is_reserved_sampling_claim(
        &arguments.id,
        &arguments.kind,
        &arguments.destination,
        &arguments.producer,
    ) || is_reserved_stack_claim(
        &arguments.id,
        &arguments.kind,
        &arguments.destination,
        &arguments.producer,
    ) {
        return Err(AppError::operational(
            "sampling artifact identifiers, kinds, paths, and producers are reserved for the typed sampling boundary",
        ));
    }
    let reserved_semantic_mapping = portable_matches_any(
        &arguments.id,
        &[
            crate::normalize::TRACE32_SYMBOL_MAPPING_ARTIFACT_ID,
            crate::normalize::TRACE32_TASK_EVENTS_MAPPING_ARTIFACT_ID,
        ],
    ) || [
        crate::normalize::TRACE32_SYMBOL_MAPPING_ARTIFACT_KIND,
        crate::normalize::TRACE32_TASK_EVENTS_MAPPING_ARTIFACT_KIND,
        crate::normalize::C_WIRE_COUNTER_MAPPING_ARTIFACT_KIND,
    ]
    .contains(&arguments.kind.as_str())
        || portable_matches_any(
            &arguments.destination,
            &[
                crate::normalize::TRACE32_SYMBOL_MAPPING_ARTIFACT_PATH,
                crate::normalize::TRACE32_TASK_EVENTS_MAPPING_ARTIFACT_PATH,
            ],
        )
        || [
            crate::normalize::TRACE32_TASK_EVENTS_MAPPING_PRODUCER,
            crate::normalize::C_WIRE_COUNTER_MAPPING_PRODUCER,
        ]
        .contains(&arguments.producer.as_str());
    if reserved_semantic_mapping {
        return Err(AppError::operational(
            "semantic mapping artifact identifiers, kinds, paths, and producers are reserved for trusted host derivation or deployment qualification",
        ));
    }
    if is_reserved_analysis_request(
        &arguments.id,
        &arguments.kind,
        &arguments.destination,
        &arguments.producer,
    ) {
        return Err(AppError::operational(
            "analysis request identifiers, kinds, paths, and producers are reserved for the immutable Host analysis binding",
        ));
    }
    if [
        SYNTHETIC_RECEIPT_PRODUCER,
        ANALYSIS_STAGE_PRODUCER,
        "t32perf-static-ram",
        "t32perf-stack-usage",
        "t32perf-perfetto",
        ANALYSIS_REQUEST_PRODUCER,
        "t32perf-normalize/v1",
        SYNTHETIC_CAPTURE_CONFIG_PRODUCER,
        ATTESTATION_SIGNING_REQUEST_PRODUCER,
        ATTESTATION_SIGNER_DISPATCH_INTENT_PRODUCER,
        CAPTURE_ATTESTATION_PRODUCER,
        CAPTURE_TRUST_POLICY_PRODUCER,
    ]
    .contains(&arguments.producer.as_str())
    {
        return Err(AppError::operational(format!(
            "producer `{}` is reserved for an internal pipeline stage",
            arguments.producer
        )));
    }
    Ok(())
}

pub(crate) fn is_recoverable_ingest_intent(inspection: &IngestIntentInspection) -> bool {
    matches!(
        inspection.classification,
        IngestIntentClassification::Pending
            | IngestIntentClassification::Resumable
            | IngestIntentClassification::CommittedStale
    )
}

pub(crate) fn ingest_recovery_required(
    session: &Session,
    initial_status: SessionStatus,
    error: &SessionStoreError,
    inspections: &[IngestIntentInspection],
) -> AppError {
    let reported = inspections
        .iter()
        .take(MAX_INGEST_RECOVERY_INSPECTIONS)
        .map(|inspection| {
            json!({
                "intent_relative_path": inspection.intent_relative_path,
                "artifact_id": inspection.artifact_id,
                "staged_relative_path": inspection.staged_relative_path,
                "destination_relative_path": inspection.destination_relative_path,
                "classification": inspection.classification,
                "detail": bounded_ingest_text(&inspection.detail),
            })
        })
        .collect::<Vec<_>>();
    AppError {
        code: "INGEST_RECOVERY_REQUIRED",
        message:
            "staged ingest has durable recovery metadata; retry with exactly the same arguments"
                .to_owned(),
        details: json!({
            "session_id": session.id().as_str(),
            "initial_status": initial_status,
            "ingest_error": bounded_ingest_text(&error.to_string()),
            "intent_count": inspections.len(),
            "reported_intent_count": reported.len(),
            "intents_truncated": inspections.len() > reported.len(),
            "intents": reported,
        }),
        exit_code: EXIT_OPERATIONAL,
    }
}

pub(crate) fn terminal_ingest_failure(
    session: &Session,
    lock: &SessionLock,
    initial_status: SessionStatus,
    durable_conflict: bool,
    original: AppError,
) -> AppError {
    let terminal = matches!(
        initial_status,
        SessionStatus::Created | SessionStatus::Capturing
    ) || durable_conflict;
    if terminal
        && let Err(state_error) = session.transition(
            lock,
            SessionStatus::Failed,
            Some(SessionError {
                code: "INGEST_FAILED".to_owned(),
                message: bounded_ingest_text(&original.message),
                details: Default::default(),
            }),
        )
    {
        return AppError::state_persistence("ingest", &original, state_error);
    }
    original
}

pub(crate) fn persist_ingest_captured_state(
    session: &Session,
    lock: &SessionLock,
    initial: SessionState,
) -> Result<SessionState, AppError> {
    if initial.status == SessionStatus::Captured {
        return Ok(initial);
    }
    let original =
        AppError::operational("ingest committed its artifact but could not persist captured state");
    let current = session
        .read_state()
        .map_err(|error| AppError::state_persistence("ingest", &original, error))?;
    let capturing = match current.status {
        SessionStatus::Created => session
            .transition(lock, SessionStatus::Capturing, None)
            .map_err(|error| AppError::state_persistence("ingest", &original, error))?,
        SessionStatus::Capturing => current,
        status => {
            return Err(AppError::state_persistence(
                "ingest",
                &original,
                format!("unexpected post-ingest Session status {status:?}"),
            ));
        }
    };
    debug_assert_eq!(capturing.status, SessionStatus::Capturing);
    session
        .transition(lock, SessionStatus::Captured, None)
        .map_err(|error| AppError::state_persistence("ingest", &original, error))
}

pub(crate) fn ensure_controller_capture_complete_for_ingest(
    root: &ArtifactRoot,
    session: &Session,
    artifacts: &[Artifact],
) -> Result<(), AppError> {
    let has_controller_artifacts = artifacts.iter().any(is_controller_owned_artifact);
    if !has_controller_artifacts {
        return Ok(());
    }

    let progress = crate::controller::controller_capture_progress(root, session.id().as_str())?;
    if progress.phase == crate::controller::ControllerCapturePhase::Complete {
        return Ok(());
    }

    Err(AppError {
        code: "CONTROLLER_CAPTURE_INCOMPLETE",
        message: format!(
            "session `{}` cannot ingest capture artifacts before the controller capture chain is complete; current phase is `{}`",
            session.id(),
            progress.phase.as_str(),
        ),
        details: json!({
            "session_id": session.id().as_str(),
            "capture_phase": progress.phase.as_str(),
            "next_required_operation": progress.phase.expected_operation(),
            "completed_operations": progress.completed_operations,
        }),
        exit_code: EXIT_OPERATIONAL,
    })
}

fn bounded_ingest_text(value: &str) -> String {
    value.chars().take(MAX_INGEST_RECOVERY_TEXT_CHARS).collect()
}

fn validate(root: &ArtifactRoot, session_id: &str, deep: bool) -> Result<CommandOutcome, AppError> {
    let session = open_session(root, session_id)?;
    let state = session.read_state().map_err(AppError::operational)?;
    let artifacts = session
        .registered_artifacts(deep)
        .map_err(AppError::operational)?;
    if let Some(manifest) = session.manifest().map_err(AppError::operational)? {
        session
            .validate_manifest(&manifest, deep)
            .map_err(AppError::operational)?;
    }
    if state.status == SessionStatus::Failed {
        return Ok(CommandOutcome {
            command: "validate",
            result: json!({
                "session_id": session.id().as_str(),
                "status": state.status,
                "deep": deep,
                "artifact_count": artifacts.len(),
                "trust_status": "INCOMPLETE",
                "health_verdict": Value::Null,
                "valid": false,
                "error": state.error,
            }),
            exit_code: EXIT_OPERATIONAL,
        });
    }

    let stage_artifact = find_artifact(&artifacts, ANALYSIS_STAGE_ID);
    if matches!(
        state.status,
        SessionStatus::Processing | SessionStatus::Complete
    ) && stage_artifact.is_none()
    {
        return Ok(CommandOutcome {
            command: "validate",
            result: json!({
                "session_id": session.id().as_str(),
                "status": state.status,
                "deep": deep,
                "artifact_count": artifacts.len(),
                "trust_status": "INCOMPLETE",
                "health_verdict": Value::Null,
                "valid": false,
                "reason": "analysis stage receipt is not registered",
            }),
            exit_code: EXIT_OPERATIONAL,
        });
    }

    let Some(stage_artifact) = stage_artifact else {
        return Ok(CommandOutcome {
            command: "validate",
            result: json!({
                "session_id": session.id().as_str(),
                "status": state.status,
                "deep": deep,
                "artifact_count": artifacts.len(),
                "trust_status": "NOT_EVALUATED",
                "health_verdict": Value::Null,
                "valid": false,
                "reason": "trusted health has not been produced by a completed analysis stage",
            }),
            exit_code: EXIT_UNSUPPORTED,
        });
    };
    let stage = read_artifact_json::<AnalysisStageReceipt>(&session, stage_artifact)?;
    validate_analysis_stage_receipt(&stage, stage_artifact, &artifacts, session.id().as_str())?;
    let health_artifact = find_artifact(&artifacts, "health").ok_or_else(|| {
        AppError::operational("analysis stage completed without a registered health artifact")
    })?;
    let health = read_artifact_json::<HealthReport>(&session, health_artifact)?;
    validate_health_document(&session, &health, &stage)?;
    let summary_artifact = find_artifact(&artifacts, "analysis-summary").ok_or_else(|| {
        AppError::operational("analysis stage completed without a registered summary artifact")
    })?;
    let summary = read_artifact_json::<AnalysisSummaryDocument>(&session, summary_artifact)?;
    validate_summary_document(&session, summary_artifact, &summary, &stage, &artifacts)?;
    let derived_artifact = find_artifact(&artifacts, "derived").ok_or_else(|| {
        AppError::operational("analysis stage completed without a registered derived artifact")
    })?;
    let derived = open_derived(&session, derived_artifact)?;
    if derived.header().schema != stage.contracts.derived_stream_schema
        || derived.header().input_artifact_ids != derived_artifact.input_artifact_ids
    {
        return Err(AppError::operational(
            "derived stream schema or inputs do not match the analysis stage contract",
        ));
    }
    if health.verdict == HealthVerdict::Valid {
        let hotspots_artifact = find_artifact(&artifacts, "hotspots").ok_or_else(|| {
            AppError::operational("VALID analysis stage has no registered hotspots artifact")
        })?;
        let hotspots = read_artifact_json::<HotspotReport>(&session, hotspots_artifact)?;
        hotspots.validate().map_err(AppError::operational)?;
        if hotspots.schema != stage.contracts.hotspots_schema
            || hotspots.session_id != session.id().as_str()
        {
            return Err(AppError::operational(
                "hotspot report schema or session does not match the completed analysis stage",
            ));
        }
    }
    let verdict = health.verdict;
    Ok(CommandOutcome {
        command: "validate",
        result: json!({
            "session_id": session.id().as_str(),
            "status": state.status,
            "deep": deep,
            "artifact_count": artifacts.len(),
            "trust_status": verdict,
            "health_verdict": verdict,
            "valid": verdict != HealthVerdict::Invalid,
        }),
        exit_code: health_exit_code(verdict),
    })
}

fn artifacts_list(
    root: &ArtifactRoot,
    session_id: &str,
    limit: usize,
    after: Option<&str>,
) -> Result<CommandOutcome, AppError> {
    if after.is_some_and(|id| !is_portable_artifact_id(id)) {
        return Err(AppError::operational(
            "artifacts list --after must be a portable artifact identifier",
        ));
    }
    let session = open_session(root, session_id)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    let total_count = artifacts.len();
    let mut artifacts = artifacts
        .into_iter()
        .filter(|artifact| after.is_none_or(|after| artifact.id.as_str() > after))
        .take(limit.saturating_add(1))
        .collect::<Vec<_>>();
    let truncated = artifacts.len() > limit;
    if truncated {
        artifacts.truncate(limit);
    }
    let next_after = truncated
        .then(|| artifacts.last().map(|artifact| artifact.id.clone()))
        .flatten();
    let returned_count = artifacts.len();
    let artifacts = artifacts
        .iter()
        .map(artifact_list_entry)
        .collect::<Vec<_>>();
    success(
        "artifacts.list",
        json!({
            "session_id": session.id().as_str(),
            "artifacts": artifacts,
            "total_count": total_count,
            "returned_count": returned_count,
            "limit": limit,
            "after": after,
            "truncated": truncated,
            "next_after": next_after,
        }),
    )
}

fn artifact_list_entry(artifact: &Artifact) -> Value {
    let input_artifact_ids = artifact
        .input_artifact_ids
        .iter()
        .take(MAX_LISTED_ARTIFACT_INPUTS)
        .collect::<Vec<_>>();
    let returned_count = input_artifact_ids.len();
    json!({
        "id": artifact.id,
        "kind": artifact.kind,
        "relative_path": artifact.relative_path,
        "media_type": artifact.media_type,
        "size_bytes": artifact.size_bytes,
        "sha256": artifact.sha256,
        "producer": artifact.producer,
        "input_artifact_ids": input_artifact_ids,
        "input_artifact_ids_total_count": artifact.input_artifact_ids.len(),
        "input_artifact_ids_returned_count": returned_count,
        "input_artifact_ids_truncated": artifact.input_artifact_ids.len() > returned_count,
    })
}

fn artifacts_verify(
    root: &ArtifactRoot,
    session_id: &str,
    artifact_id: Option<&str>,
    deep: bool,
) -> Result<CommandOutcome, AppError> {
    let session = open_session(root, session_id)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    let selected = match artifact_id {
        Some(id) => vec![
            artifacts
                .iter()
                .find(|artifact| artifact.id == id)
                .cloned()
                .ok_or_else(|| {
                    AppError::operational(format!("artifact `{id}` is not registered"))
                })?,
        ],
        None => artifacts,
    };
    for artifact in &selected {
        session
            .verify_artifact(artifact, deep)
            .map_err(AppError::operational)?;
    }
    success(
        "artifacts.verify",
        json!({
            "session_id": session.id().as_str(),
            "deep": deep,
            "verified": selected.iter().map(|artifact| artifact.id.as_str()).collect::<Vec<_>>(),
        }),
    )
}

fn capture_synthetic(
    root: &ArtifactRoot,
    requested_id: Option<String>,
    event_count: u64,
    command: &'static str,
) -> Result<CommandOutcome, AppError> {
    let request = json!({
        "provider": "synthetic",
        "events": event_count,
    });
    let session_id = requested_id
        .map(SessionId::new)
        .transpose()
        .map_err(AppError::operational)?
        .unwrap_or_else(SessionId::generate);
    let _lease = crate::perf_run::try_acquire_session_id_execution_lease(root, &session_id)?;
    let session = root
        .create_session_with_id(session_id, &request)
        .map_err(AppError::operational)?;
    let lock = session.try_lock().map_err(AppError::operational)?;
    session
        .transition(&lock, SessionStatus::Capturing, None)
        .map_err(AppError::operational)?;
    let generated = match fixture::generate(&session, &lock, event_count) {
        Ok(generated) => generated,
        Err(error) => {
            if let Err(state_error) = session.transition(
                &lock,
                SessionStatus::Failed,
                Some(SessionError {
                    code: error.code.to_owned(),
                    message: error.message.clone(),
                    details: error
                        .details
                        .as_object()
                        .map(|details| {
                            details
                                .iter()
                                .map(|(key, value)| (key.clone(), value.clone()))
                                .collect()
                        })
                        .unwrap_or_default(),
                }),
            ) {
                return Err(AppError::state_persistence(
                    "capture_synthetic",
                    &error,
                    state_error,
                ));
            }
            return Err(error);
        }
    };
    let state = session
        .transition(&lock, SessionStatus::Captured, None)
        .map_err(|state_error| {
            let original = AppError::operational(
                "synthetic capture committed artifacts but could not persist captured state",
            );
            AppError::state_persistence("capture_synthetic", &original, state_error)
        })?;
    success(
        command,
        json!({
            "session_id": session.id().as_str(),
            "status": state.status,
            "event_count": generated.event_count,
            "artifacts": [
                generated.capture_config,
                generated.observations,
                generated.capture_receipt
            ],
        }),
    )
}

fn doctor(root: &ArtifactRoot) -> Result<CommandOutcome, AppError> {
    let t32mcp = find_executable("t32mcp");
    let trace32 = ["t32marm", "t32marm64", "t32m"]
        .into_iter()
        .find_map(find_executable);
    let adapters = AdapterRegistry::conservative_defaults().map_err(AppError::operational)?;
    let adapter_ids = adapters.ids().collect::<Vec<_>>();
    let trace_ascii = probe_trace32_adapter(&adapters, TRACE_ASCII_ADAPTER_ID)?;
    let task_events = probe_trace32_adapter(&adapters, TRACE_TASK_EVENTS_ADAPTER_ID)?;
    Ok(CommandOutcome {
        command: "doctor",
        result: json!({
            "status": "unsupported",
            "checks": [
                {
                    "name": "artifact_root",
                    "status": "ok",
                    "path": root.path(),
                },
                {
                    "name": "synthetic_provider",
                    "status": "ok",
                },
                {
                    "name": "adapter_registry",
                    "status": "ok",
                    "adapters": adapter_ids,
                    "canonical_ndjson": CANONICAL_NDJSON_ADAPTER_ID,
                },
                trace_ascii,
                task_events,
                {
                    "name": "t32mcp",
                    "status": if t32mcp.is_some() { "available" } else { "unsupported" },
                    "executable": t32mcp,
                },
                {
                    "name": "trace32_tool",
                    "status": if trace32.is_some() { "available" } else { "unsupported" },
                    "executable": trace32,
                },
                {
                    "name": "trace32_hardware",
                    "status": "unsupported",
                    "reason": "hardware probing is intentionally delegated to the external t32mcp skill control plane",
                }
            ],
        }),
        exit_code: EXIT_UNSUPPORTED,
    })
}

fn probe_trace32_adapter(registry: &AdapterRegistry, adapter_id: &str) -> Result<Value, AppError> {
    match registry.open(adapter_id, AdapterRequest::new("doctor", "doctor")) {
        Err(AdapterError::UnsupportedNeedsTrace32 { requirement, .. }) => Ok(json!({
            "name": adapter_id,
            "status": "unsupported",
            "reason": requirement,
        })),
        Err(AdapterError::MissingInput { .. }) => Ok(json!({
            "name": adapter_id,
            "status": "available",
            "reason": "adapter requires a trusted input artifact",
        })),
        Err(error) => Err(AppError::operational(error)),
        Ok(_) => Ok(json!({
            "name": adapter_id,
            "status": "available",
        })),
    }
}

fn find_executable(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    let extensions = executable_extensions();
    for directory in env::split_paths(&path) {
        for extension in &extensions {
            let candidate = directory.join(format!("{name}{extension}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn executable_extensions() -> Vec<String> {
    #[cfg(windows)]
    {
        let mut values = vec![String::new()];
        if let Some(extensions) = env::var_os("PATHEXT") {
            values.extend(
                extensions
                    .to_string_lossy()
                    .split(';')
                    .filter(|value| !value.is_empty())
                    .map(str::to_ascii_lowercase),
            );
        } else {
            values.extend([".exe".to_owned(), ".cmd".to_owned(), ".bat".to_owned()]);
        }
        values
    }
    #[cfg(not(windows))]
    {
        vec![String::new()]
    }
}

pub(crate) fn open_session(root: &ArtifactRoot, session_id: &str) -> Result<Session, AppError> {
    root.session(&SessionId::new(session_id).map_err(AppError::operational)?)
        .map_err(AppError::operational)
}

fn find_artifact<'a>(artifacts: &'a [Artifact], id: &str) -> Option<&'a Artifact> {
    artifacts.iter().find(|artifact| artifact.id == id)
}

fn read_artifact_json<T: DeserializeOwned>(
    session: &Session,
    artifact: &Artifact,
) -> Result<T, AppError> {
    if artifact.size_bytes > MAX_APP_JSON_ARTIFACT_BYTES {
        return Err(AppError::operational(format!(
            "JSON artifact `{}` is {} bytes; maximum is {MAX_APP_JSON_ARTIFACT_BYTES}",
            artifact.id, artifact.size_bytes
        )));
    }
    let mut file = session
        .open_artifact(artifact)
        .map_err(AppError::operational)?;
    let mut bytes = Vec::with_capacity(usize::try_from(artifact.size_bytes).unwrap_or(0));
    (&mut file)
        .take(MAX_APP_JSON_ARTIFACT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(AppError::operational)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_APP_JSON_ARTIFACT_BYTES {
        return Err(AppError::operational(format!(
            "JSON artifact `{}` grew beyond {MAX_APP_JSON_ARTIFACT_BYTES} bytes while reading",
            artifact.id
        )));
    }
    strict_json::from_slice(&bytes).map_err(AppError::operational)
}

pub(crate) fn health_exit_code(verdict: HealthVerdict) -> u8 {
    match verdict {
        HealthVerdict::Valid => EXIT_SUCCESS,
        HealthVerdict::Degraded => EXIT_DEGRADED,
        HealthVerdict::Invalid => EXIT_INVALID,
    }
}

fn success(command: &'static str, result: Value) -> Result<CommandOutcome, AppError> {
    Ok(CommandOutcome {
        command,
        result,
        exit_code: EXIT_SUCCESS,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        execute, is_reserved_analysis_request, is_reserved_controller_claim,
        with_session_execution_lease,
    };
    use crate::cli::{
        AbandonCommand, AbandonPlanArgs, AbandonSubcommand, Cli, Command, MaintenanceCommand,
        MaintenanceSubcommand, SessionCommand, SessionCreateArgs, SessionIngestArgs,
        SessionSubcommand,
    };
    use crate::target_adapter_provisioning::{
        BUILD_RESOURCE_PRODUCER, LINKER_MAP_ARTIFACT_ID, PERFORMANCE_RUN_DEPLOYMENT_BINDING_ID,
        PERFORMANCE_RUN_DEPLOYMENT_BINDING_PRODUCER,
    };
    use t32perf_model::{
        PerformanceReportFormat, PerformanceRunRequest, PerformanceRunRequestSchemaVersion,
    };
    use t32perf_session::{ArtifactRoot, SessionId, SessionLimits};
    use tempfile::TempDir;

    #[test]
    fn build_resource_claims_cannot_enter_external_ingest() {
        assert!(is_reserved_controller_claim(
            LINKER_MAP_ARTIFACT_ID,
            "unrelated",
            "unrelated",
            "unrelated",
        ));
        assert!(is_reserved_controller_claim(
            "unrelated",
            "unrelated",
            "unrelated",
            BUILD_RESOURCE_PRODUCER,
        ));
        assert!(is_reserved_controller_claim(
            PERFORMANCE_RUN_DEPLOYMENT_BINDING_ID,
            "unrelated",
            "unrelated",
            "unrelated",
        ));
        assert!(is_reserved_controller_claim(
            "unrelated",
            "unrelated",
            "unrelated",
            PERFORMANCE_RUN_DEPLOYMENT_BINDING_PRODUCER,
        ));
    }

    #[test]
    fn analysis_request_claims_cannot_enter_external_ingest() {
        assert!(is_reserved_analysis_request(
            "unrelated",
            "unrelated",
            "analysis/request.json",
            "unrelated",
        ));
        assert!(is_reserved_analysis_request(
            "unrelated",
            "unrelated",
            "unrelated",
            "t32perf-analysis-request/v1",
        ));
    }

    #[test]
    fn held_session_execution_lease_rejects_ingest_before_session_mutation() {
        let temporary = TempDir::new().expect("temporary artifact root");
        let root =
            ArtifactRoot::open(temporary.path(), SessionLimits::default()).expect("artifact root");
        let session_id = SessionId::new("busy-ingest").expect("session ID");
        let session = root
            .create_session_with_id(session_id.clone(), &serde_json::json!({}))
            .expect("ordinary Session");
        let before = session.read_state().expect("initial state");
        let _lease = crate::perf_run::try_acquire_session_id_execution_lease(&root, &session_id)
            .expect("held Session execution lease");

        let result = execute(Cli {
            artifact_root: PathBuf::from(temporary.path()),
            max_file_bytes: SessionLimits::default().max_file_bytes,
            max_session_bytes: SessionLimits::default().max_session_bytes,
            json: true,
            command: Command::Session(SessionCommand {
                command: SessionSubcommand::Ingest(SessionIngestArgs {
                    session: session_id.as_str().to_owned(),
                    staged: "incoming.json".to_owned(),
                    id: "external-input".to_owned(),
                    kind: "external_input".to_owned(),
                    destination: "capture/external-input.json".to_owned(),
                    media_type: "application/json".to_owned(),
                    producer: "external-test".to_owned(),
                    input_artifact_ids: Vec::new(),
                }),
            }),
        });
        let error = match result {
            Ok(_) => panic!("held Session execution lease must reject external ingest"),
            Err(error) => error,
        };

        assert_eq!(error.code, "SESSION_EXECUTION_BUSY");
        assert_eq!(session.read_state().expect("state after rejection"), before);
        assert!(
            session
                .registered_artifacts(false)
                .expect("artifacts after rejection")
                .is_empty()
        );
    }

    #[test]
    fn ingest_claim_validation_precedes_perf_run_lease_discovery() {
        let temporary = TempDir::new().expect("temporary artifact root");
        let root =
            ArtifactRoot::open(temporary.path(), SessionLimits::default()).expect("artifact root");
        let request = PerformanceRunRequest {
            schema: PerformanceRunRequestSchemaVersion,
            duration_ns: 1_000_000,
            top: 1,
            report_format: PerformanceReportFormat::PerfettoJson,
        };
        let session_id = SessionId::new("ingest-preflight").expect("session ID");
        root.create_session_with_id(session_id.clone(), &serde_json::to_value(request).unwrap())
            .expect("strict performance-run Session");
        let _lease = crate::perf_run::try_acquire_session_id_execution_lease(&root, &session_id)
            .expect("held performance-run lease");

        let result = execute(Cli {
            artifact_root: PathBuf::from(temporary.path()),
            max_file_bytes: SessionLimits::default().max_file_bytes,
            max_session_bytes: SessionLimits::default().max_session_bytes,
            json: true,
            command: Command::Session(SessionCommand {
                command: SessionSubcommand::Ingest(SessionIngestArgs {
                    session: session_id.as_str().to_owned(),
                    staged: "incoming.json".to_owned(),
                    id: super::CAPTURE_ATTESTATION_ID.to_owned(),
                    kind: "external_input".to_owned(),
                    destination: "capture/external-input.json".to_owned(),
                    media_type: "application/json".to_owned(),
                    producer: "external-test".to_owned(),
                    input_artifact_ids: Vec::new(),
                }),
            }),
        });
        let error = match result {
            Ok(_) => panic!("reserved ingest claim unexpectedly dispatched"),
            Err(error) => error,
        };
        assert_eq!(error.code, "OPERATIONAL_ERROR");
        assert!(
            error
                .message
                .contains("reserved for verified capture provenance")
        );
    }

    #[test]
    fn ingest_spec_validation_precedes_session_execution_lease() {
        let temporary = TempDir::new().expect("temporary artifact root");
        let root =
            ArtifactRoot::open(temporary.path(), SessionLimits::default()).expect("artifact root");
        let session_id = SessionId::new("ingest-spec-preflight").expect("session ID");
        root.create_session_with_id(session_id.clone(), &serde_json::json!({}))
            .expect("Session");
        let _lease = crate::perf_run::try_acquire_session_id_execution_lease(&root, &session_id)
            .expect("held Session execution lease");

        let result = execute(Cli {
            artifact_root: PathBuf::from(temporary.path()),
            max_file_bytes: SessionLimits::default().max_file_bytes,
            max_session_bytes: SessionLimits::default().max_session_bytes,
            json: true,
            command: Command::Session(SessionCommand {
                command: SessionSubcommand::Ingest(SessionIngestArgs {
                    session: session_id.as_str().to_owned(),
                    staged: "incoming.json".to_owned(),
                    id: "invalid/artifact".to_owned(),
                    kind: "external_input".to_owned(),
                    destination: "capture/external-input.json".to_owned(),
                    media_type: "not-a-media-type".to_owned(),
                    producer: "external-test".to_owned(),
                    input_artifact_ids: Vec::new(),
                }),
            }),
        });
        let error = match result {
            Ok(_) => panic!("invalid ingest specification unexpectedly dispatched"),
            Err(error) => error,
        };
        assert_eq!(error.code, "OPERATIONAL_ERROR");
        assert!(error.message.contains("artifact id"));
    }

    #[test]
    fn invalid_perf_run_schema_claim_is_rejected_after_lease_before_dispatch() {
        let temporary = TempDir::new().expect("temporary artifact root");
        let root =
            ArtifactRoot::open(temporary.path(), SessionLimits::default()).expect("artifact root");
        let session_id = SessionId::new("invalid-perf-run").expect("session ID");
        let session = root
            .create_session_with_id(
                session_id.clone(),
                &serde_json::json!({
                    "schema": "t32perf.performance-run-request/v1",
                    "unexpected": true,
                }),
            )
            .expect("hostile immutable request fixture");
        let before = session.read_state().expect("initial state");

        let result = with_session_execution_lease(&root, session_id.as_str(), || {
            panic!("invalid performance-run schema claim reached external dispatch")
        });
        let error = match result {
            Ok(_) => panic!("invalid performance-run schema claim unexpectedly dispatched"),
            Err(error) => error,
        };
        assert_eq!(error.code, "OPERATIONAL_ERROR");
        assert!(error.message.contains("invalid immutable request"));
        assert_eq!(session.read_state().expect("state after rejection"), before);
        assert!(
            session
                .registered_artifacts(false)
                .expect("artifacts after rejection")
                .is_empty()
        );
    }

    #[test]
    fn strict_perf_run_maintenance_command_uses_its_target_guard_once() {
        let temporary = TempDir::new().expect("temporary artifact root");
        let root =
            ArtifactRoot::open(temporary.path(), SessionLimits::default()).expect("artifact root");
        let request = PerformanceRunRequest {
            schema: PerformanceRunRequestSchemaVersion,
            duration_ns: 1_000_000,
            top: 1,
            report_format: PerformanceReportFormat::PerfettoJson,
        };
        let session_id = SessionId::new("maintenance-perf-run").expect("session ID");
        root.create_session_with_id(session_id.clone(), &serde_json::to_value(request).unwrap())
            .expect("strict performance-run Session");

        let outcome = execute(Cli {
            artifact_root: PathBuf::from(temporary.path()),
            max_file_bytes: SessionLimits::default().max_file_bytes,
            max_session_bytes: SessionLimits::default().max_session_bytes,
            json: true,
            command: Command::Maintenance(MaintenanceCommand {
                command: MaintenanceSubcommand::Abandon(AbandonCommand {
                    command: AbandonSubcommand::Plan(AbandonPlanArgs {
                        session: session_id.as_str().to_owned(),
                    }),
                }),
            }),
        })
        .expect("operations target guard should acquire the strict perf-run lease exactly once");

        assert_eq!(outcome.command, "maintenance.abandon.plan");
        assert_eq!(outcome.result["session_id"], session_id.as_str());
    }

    #[test]
    fn external_session_create_cannot_claim_the_perf_run_schema() {
        let temporary = TempDir::new().expect("temporary artifact root");
        let session_id = "external-perf-run";
        let result = execute(Cli {
            artifact_root: PathBuf::from(temporary.path()),
            max_file_bytes: SessionLimits::default().max_file_bytes,
            max_session_bytes: SessionLimits::default().max_session_bytes,
            json: true,
            command: Command::Session(SessionCommand {
                command: SessionSubcommand::Create(SessionCreateArgs {
                    id: Some(session_id.to_owned()),
                    request: serde_json::json!({
                        "schema": "t32perf.performance-run-request/v1",
                    })
                    .to_string(),
                }),
            }),
        });
        let error = match result {
            Ok(_) => panic!("external Session creation claimed the perf-run schema"),
            Err(error) => error,
        };
        assert_eq!(error.code, "UNSUPPORTED");
        assert!(error.message.contains("created only by perf_run"));
        assert!(!temporary.path().join(session_id).exists());
    }
}
