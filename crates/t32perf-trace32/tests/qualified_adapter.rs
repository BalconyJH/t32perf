use std::{collections::BTreeMap, io::Cursor};

use sha2::{Digest as _, Sha256};
use t32perf_model::{
    CaptureCapabilities, ContextKind, MetricSupportEntry, MetricSupportLevel, Sha256Digest,
};
use t32perf_trace32::{
    AdapterError, AdapterRegistry, AdapterRequest, ControllerHealthSignal, ControllerTargetState,
    LineLimits, ObservationSource, TRACE32_SYMBOL_MAPPING_SCHEMA,
    TRACE32_TASK_EVENTS_MAPPING_SCHEMA, TargetAdapterBuildGate, TargetAdapterCaptureContract,
    TargetAdapterCaptureKind, TargetAdapterControllerProtocol, TargetAdapterProfile,
    TargetAdapterProfileSchemaVersion, TargetAdapterQualificationReceipt,
    TargetAdapterQualificationReceiptSchemaVersion, TargetAdapterScenario,
    TargetAdapterScenarioContract, Trace32SymbolMappingDocument, Trace32TaskEventsMappingDocument,
    Trace32ValidatedAdapterContext as Trace32QualifiedAdapterContext,
    Trace32ValidatedCaptureKind as Trace32QualifiedCaptureKind,
    Trace32ValidatedMapping as Trace32QualifiedMapping,
    Trace32ValidatedRuntime as Trace32QualifiedRuntime, TraceArtifactBinding, TraceContextMapping,
    TraceFunctionMapping, TraceTaskMetadataBinding, TraceTaskMetadataRole,
    ValidatedTargetAdapterReceipt as QualifiedTargetAdapter,
    ValidatedTrace32AdapterRegistry as QualifiedTrace32AdapterRegistry,
    ValidatedTrace32ObservationAdapter as QualifiedTrace32ObservationAdapter,
};

fn digest(c: char) -> Sha256Digest {
    Sha256Digest::new(c.to_string().repeat(64)).unwrap()
}
fn binding(id: &str) -> TraceArtifactBinding {
    TraceArtifactBinding {
        artifact_id: id.to_owned(),
        sha256: digest('a'),
    }
}

struct AmbiguousFixture;

impl QualifiedTrace32ObservationAdapter for AmbiguousFixture {
    fn id(&self) -> &str {
        "ambiguous-fixture"
    }
    fn matches(&self, _: &Trace32QualifiedAdapterContext) -> Result<bool, AdapterError> {
        Ok(true)
    }
    fn open_validated(
        &self,
        _: Trace32QualifiedAdapterContext,
        _: AdapterRequest,
    ) -> Result<Box<dyn ObservationSource + Send>, AdapterError> {
        unreachable!("selection must reject ambiguity before opening")
    }
}

fn profile(task_events: bool) -> TargetAdapterProfile {
    let kind = if task_events {
        TargetAdapterCaptureKind::ProgramFlowTaskEvents {
            export_profile_id: "ignored".to_owned(),
            rtos_awareness: "fixture-orti/v1".to_owned(),
            timestamp_clock_id: "fixture-clock/v1".to_owned(),
            orti_artifact_id: "orti".to_owned(),
            task_marker_artifact_id: "markers".to_owned(),
        }
    } else {
        TargetAdapterCaptureKind::Sampling {
            capacity_records: 64,
        }
    };
    let unavailable = MetricSupportEntry::unavailable("fixture");
    TargetAdapterProfile {
        schema: TargetAdapterProfileSchemaVersion::V1,
        adapter_id: if task_events {
            "fixture-task"
        } else {
            "fixture-ascii"
        }
        .to_owned(),
        adapter_version: "1".to_owned(),
        implementation_sha256: digest('1'),
        qualification_sha256: None,
        build_gate: TargetAdapterBuildGate {
            trace32_release: "fixture-release".to_owned(),
            minimum_build: 1,
            maximum_build: 1,
            architecture_package: "fixture-arch".to_owned(),
        },
        target_identifier: "fixture-target".to_owned(),
        probe_identifier: "fixture-probe".to_owned(),
        license_features: vec!["fixture-license".to_owned()],
        trace_routing: vec!["fixture-route".to_owned()],
        firmware_elf_sha256: digest('7'),
        health_signals: if task_events {
            t32perf_trace32::PROGRAM_FLOW_HEALTH_SIGNALS.to_vec()
        } else {
            vec![ControllerHealthSignal::SamplingBufferFull]
        },
        capabilities: CaptureCapabilities {
            function_events: if task_events {
                MetricSupportEntry::new(MetricSupportLevel::Exact)
            } else {
                unavailable.clone()
            },
            context_switches: if task_events {
                MetricSupportEntry::new(MetricSupportLevel::Exact)
            } else {
                unavailable.clone()
            },
            interrupt_events: if task_events {
                MetricSupportEntry::new(MetricSupportLevel::Exact)
            } else {
                unavailable.clone()
            },
            samples: unavailable.clone(),
            custom_events: unavailable.clone(),
            counters: unavailable,
        },
        controller_protocol: TargetAdapterControllerProtocol::V1,
        custom_event_collector: None,
        scenarios: vec![TargetAdapterScenarioContract {
            scenario: TargetAdapterScenario::Normal,
            fault_point: None,
            capture: TargetAdapterCaptureContract {
                configuration_sha256_by_initial_state: BTreeMap::from([(
                    ControllerTargetState::Running,
                    digest('3'),
                )]),
                capture_mode: "fixture-mode".to_owned(),
                trace_sink: "fixture-sink".to_owned(),
                capture_kind: kind,
                timestamp_enabled: true,
                workload_identity: "fixture-workload".to_owned(),
                covered_cores: vec![0],
                supported_initial_states: vec![ControllerTargetState::Running],
            },
        }],
    }
}

fn qualified(
    task_events: bool,
) -> (
    QualifiedTargetAdapter,
    TargetAdapterProfile,
    TraceArtifactBinding,
    Vec<u8>,
) {
    let mut profile = profile(task_events);
    let receipt = TargetAdapterQualificationReceipt {
        schema: TargetAdapterQualificationReceiptSchemaVersion::V1,
        adapter_id: profile.adapter_id.clone(),
        adapter_version: profile.adapter_version.clone(),
        candidate_profile_sha256: profile.qualification_identity_digest().unwrap(),
        implementation_sha256: profile.implementation_sha256.clone(),
        trace32_release: profile.build_gate.trace32_release.clone(),
        trace32_build: 1,
        architecture_package: profile.build_gate.architecture_package.clone(),
        target_identifier: profile.target_identifier.clone(),
        probe_identifier: profile.probe_identifier.clone(),
        firmware_elf_sha256: profile.firmware_elf_sha256.clone(),
        t32mcp_version: "0.2.2".to_owned(),
        hil_verification_receipt_sha256: digest('8'),
    };
    let bytes = serde_json::to_vec(&receipt).unwrap();
    let receipt_digest = Sha256Digest::new(
        Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
    .unwrap();
    profile.qualification_sha256 = Some(receipt_digest.clone());
    let receipt_binding = TraceArtifactBinding {
        artifact_id: "qualification".to_owned(),
        sha256: receipt_digest,
    };
    (
        QualifiedTargetAdapter::validate_for(profile.clone(), &bytes, receipt_binding.clone())
            .unwrap(),
        profile,
        receipt_binding,
        bytes,
    )
}

fn function() -> TraceFunctionMapping {
    TraceFunctionMapping {
        export_name: "Function".to_owned(),
        function_id: "fn:function".to_owned(),
        display_name: "Function".to_owned(),
        module: None,
        address: Some(0x1000),
        end_address: Some(0x1010),
        file: None,
        line: None,
    }
}

fn context(task_events: bool) -> Trace32QualifiedAdapterContext {
    let (proof, profile, receipt, _) = qualified(task_events);
    let raw = binding("trace-export");
    let runtime = Trace32QualifiedRuntime {
        trace32_release: "fixture-release".to_owned(),
        trace32_build: 1,
        architecture_package: "fixture-arch".to_owned(),
        target_identifier: "fixture-target".to_owned(),
        core_id: 0,
        clock_domain: "fixture-clock/v1".to_owned(),
        elf: TraceArtifactBinding {
            artifact_id: "firmware".to_owned(),
            sha256: digest('7'),
        },
        controller_health: binding("health"),
        time_origin_evidence: binding("origin"),
        raw_input: raw.clone(),
    };
    let mapping = if task_events {
        Trace32QualifiedMapping::TaskEventsMapping(Trace32TaskEventsMappingDocument {
            schema: TRACE32_TASK_EVENTS_MAPPING_SCHEMA.to_owned(),
            profile_id: "ignored".to_owned(),
            profile_sha256: profile.digest().unwrap(),
            trace32_release: runtime.trace32_release.clone(),
            trace32_build: 1,
            architecture_package: runtime.architecture_package.clone(),
            target_identifier: runtime.target_identifier.clone(),
            core_id: 0,
            elf_artifact_id: "firmware".to_owned(),
            elf_sha256: digest('7'),
            metadata_artifacts: vec![
                TraceTaskMetadataBinding {
                    role: TraceTaskMetadataRole::Orti,
                    artifact: binding("orti"),
                },
                TraceTaskMetadataBinding {
                    role: TraceTaskMetadataRole::Markers,
                    artifact: binding("markers"),
                },
            ],
            controller_health: runtime.controller_health.clone(),
            time_origin_evidence: runtime.time_origin_evidence.clone(),
            qualification_receipt: receipt,
            contexts: vec![TraceContextMapping {
                export_name: "NO_TASK".to_owned(),
                context_id: "idle:0".to_owned(),
                kind: ContextKind::Idle,
                display_name: "idle".to_owned(),
                priority: None,
                entry_function_id: None,
            }],
            functions: vec![function()],
            runnables: vec![],
        })
    } else {
        Trace32QualifiedMapping::AsciiSymbolMapping(Trace32SymbolMappingDocument {
            schema: TRACE32_SYMBOL_MAPPING_SCHEMA.to_owned(),
            profile_id: t32perf_trace32::TC234L_SNOOPER_ASCII_PROFILE_V1.to_owned(),
            profile_sha256: Some(profile.digest().unwrap()),
            trace32_release: runtime.trace32_release.clone(),
            trace32_build: 1,
            architecture_package: runtime.architecture_package.clone(),
            target_identifier: runtime.target_identifier.clone(),
            elf_artifact_id: "firmware".to_owned(),
            elf_sha256: digest('7'),
            controller_health: runtime.controller_health.clone(),
            time_origin_evidence: runtime.time_origin_evidence.clone(),
            qualification_receipt: receipt,
            address_classes: vec!["P".to_owned()],
            functions: vec![function()],
        })
    };
    Trace32QualifiedAdapterContext {
        validated_receipt: proof,
        raw_input: t32perf_trace32::Trace32ValidatedRawInputIdentity {
            artifact: raw,
            capture_kind: if task_events {
                Trace32QualifiedCaptureKind::TaskEventsMapping
            } else {
                Trace32QualifiedCaptureKind::AsciiSymbolMapping
            },
        },
        mapping,
        runtime,
        limits: LineLimits::default(),
    }
}

#[test]
fn qualified_ascii_and_taskevents_open_with_test_only_receipts() {
    let registry = QualifiedTrace32AdapterRegistry::defaults().unwrap();
    registry
        .open(
            context(false),
            AdapterRequest::new("session", "ascii").with_input(Cursor::new("")),
        )
        .unwrap();
    let header = "############################\n# Task events trace file\n# time(ns); task name; event;\n############################\n";
    registry
        .open(
            context(true),
            AdapterRequest::new("session", "task").with_input(Cursor::new(header)),
        )
        .unwrap();
}

#[test]
fn ordinary_open_remains_unsupported_and_proofs_require_exact_receipts() {
    let ordinary = AdapterRegistry::conservative_defaults().unwrap();
    assert!(matches!(
        ordinary.open("trace32-export-ascii", AdapterRequest::new("s", "x")),
        Err(AdapterError::UnsupportedNeedsTrace32 { .. })
    ));
    let candidate = profile(false);
    assert!(
        QualifiedTargetAdapter::validate_for(candidate, b"{}", binding("qualification")).is_err()
    );
    let (_, mut profile, receipt, bytes) = qualified(false);
    profile.adapter_version = "wrong".to_owned();
    assert!(QualifiedTargetAdapter::validate_for(profile, &bytes, receipt).is_err());
}

#[test]
fn qualified_registry_rejects_identity_mismatches_no_match_and_ambiguity() {
    let registry = QualifiedTrace32AdapterRegistry::defaults().unwrap();
    let mut raw = context(false);
    raw.runtime.raw_input.artifact_id = "other".to_owned();
    assert!(
        registry
            .open(
                raw,
                AdapterRequest::new("s", "x").with_input(Cursor::new(""))
            )
            .is_err()
    );
    let mut runtime = context(false);
    runtime.runtime.trace32_build = 2;
    assert!(
        registry
            .open(
                runtime,
                AdapterRequest::new("s", "x").with_input(Cursor::new(""))
            )
            .is_err()
    );
    let mut mapping = context(false);
    if let Trace32QualifiedMapping::AsciiSymbolMapping(ref mut value) = mapping.mapping {
        value.profile_id = "wrong".to_owned();
    }
    assert!(
        registry
            .open(
                mapping,
                AdapterRequest::new("s", "x").with_input(Cursor::new(""))
            )
            .is_err()
    );
    let mut legacy_mapping = context(false);
    if let Trace32QualifiedMapping::AsciiSymbolMapping(ref mut value) = legacy_mapping.mapping {
        value.profile_sha256 = None;
        value.validate().unwrap();
    }
    assert!(
        registry
            .open(
                legacy_mapping,
                AdapterRequest::new("s", "x").with_input(Cursor::new(""))
            )
            .is_err()
    );
    let mut no_match = context(false);
    no_match.raw_input.capture_kind = Trace32QualifiedCaptureKind::TaskEventsMapping;
    assert!(matches!(
        registry.open(
            no_match,
            AdapterRequest::new("s", "x").with_input(Cursor::new(""))
        ),
        Err(AdapterError::NoValidatedTrace32Adapter)
    ));
    let mut ambiguous = QualifiedTrace32AdapterRegistry::defaults().unwrap();
    ambiguous.register(Box::new(AmbiguousFixture)).unwrap();
    assert!(matches!(
        ambiguous.register(Box::new(AmbiguousFixture)),
        Err(AdapterError::DuplicateAdapter { .. })
    ));
    assert!(matches!(
        ambiguous.open(
            context(false),
            AdapterRequest::new("s", "x").with_input(Cursor::new(""))
        ),
        Err(AdapterError::AmbiguousValidatedTrace32Adapters { .. })
    ));
}
