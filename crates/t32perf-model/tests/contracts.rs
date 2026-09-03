use std::{
    fmt::Debug,
    fs,
    path::{Path, PathBuf},
};

use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use t32perf_model::*;

fn digest(character: char) -> Sha256Digest {
    Sha256Digest::new(character.to_string().repeat(64)).unwrap()
}

fn sample_pc_hit_histogram() -> PcHitHistogram {
    PcHitHistogram {
        schema: PcHitHistogramSchemaVersion,
        session_id: "session-01".to_owned(),
        endpoint_fingerprint: digest('f'),
        endpoint_fingerprint_scheme: EndpointFingerprintScheme::T32PerfEndpointFingerprintV2,
        trace32: "R.2026.02.000190766".to_owned(),
        cpu: "CortexM0+".to_owned(),
        address_space: "P:".to_owned(),
        core_id: 0,
        method: PcSamplingMethod::Realtime,
        intrusive: false,
        requested_duration_ns: 1_000_000,
        observed_duration_ns: 1_100_000,
        last_sample_rate_hz: 2_000,
        snoop_failures: 0,
        target_state_before: TargetExecutionState {
            powered: true,
            running: true,
            halted: false,
        },
        target_state_after: TargetExecutionState {
            powered: true,
            running: true,
            halted: false,
        },
        firmware: FirmwareBinding {
            status: FirmwareBindingStatus::Verified,
            elf_sha256: Some(digest('e')),
            proof: Some(FirmwareBindingProof::DigestBoundDeployment {
                evidence_artifact_sha256: digest('d'),
            }),
        },
        cleanup_complete: true,
        in_scope_hits: 10,
        buckets: vec![
            PcHitBucket {
                start_address: 0x1000,
                end_address: 0x1010,
                hits: 6,
            },
            PcHitBucket {
                start_address: 0x1010,
                end_address: 0x1020,
                hits: 4,
            },
        ],
        debugger_symbolization: None,
    }
}

fn sample_heatmap() -> Heatmap {
    Heatmap {
        schema: HeatmapSchemaVersion,
        session_id: "session-01".to_owned(),
        histogram_sha256: digest('a'),
        quality: HeatmapQuality::Statistical,
        projection_kind: HeatmapProjectionKind::Function,
        quantitative_policy: QuantitativePolicy {
            min_in_scope_hits: 1,
            min_observed_duration_ns: 1,
            min_stop_and_go_retained_runtime_percent: 0.0,
            max_snoop_failures: 0,
        },
        denominator_hits: 10,
        attributed_hits: 8,
        unattributed_hits: 2,
        out_of_scope_hits: OutOfScopeHits::Unknown,
        cells: vec![
            HeatmapCell {
                key: HeatmapCellKey::Function {
                    function_id: "main".to_owned(),
                },
                display_name: "main".to_owned(),
                hits: 6,
                debugger_location: None,
            },
            HeatmapCell {
                key: HeatmapCellKey::Function {
                    function_id: "worker".to_owned(),
                },
                display_name: "worker".to_owned(),
                hits: 2,
                debugger_location: None,
            },
        ],
    }
}

fn sample_firmware_binding_evidence() -> FirmwareBindingEvidence {
    FirmwareBindingEvidence {
        schema: FirmwareBindingEvidenceSchemaVersion,
        session_id: "session-01".to_owned(),
        endpoint_fingerprint: digest('f'),
        endpoint_fingerprint_scheme: EndpointFingerprintScheme::T32PerfEndpointFingerprintV2,
        elf_sha256: digest('e'),
        proof_kind: FirmwareBindingProofKind::DigestBoundDeployment,
        result: FirmwareBindingEvidenceResult::Verified,
    }
}

fn sample_sampling_driver_event() -> SamplingDriverEvent {
    SamplingDriverEvent {
        schema: SamplingDriverEventSchemaVersion,
        transaction_id: "123e4567-e89b-42d3-a456-426614174000".to_owned(),
        endpoint_fingerprint: digest('f'),
        endpoint_fingerprint_scheme: EndpointFingerprintScheme::T32PerfEndpointFingerprintV2,
        owner: SamplingDriverOwner::LauterbachSamplingMcpV1,
        sequence: 1,
        observed_at: "2026-08-29T12:00:00Z".to_owned(),
        details: SamplingDriverEventDetails::ConfigureIntent {
            method: SamplingConfigureMethod::Realtime,
        },
    }
}

fn sample_sampling_capture_receipt() -> SamplingCaptureReceipt {
    let events = [
        SamplingDriverEventName::ConfigureIntent,
        SamplingDriverEventName::ConfigureObserved,
        SamplingDriverEventName::StartIntent,
        SamplingDriverEventName::StartObserved,
        SamplingDriverEventName::StopIntent,
        SamplingDriverEventName::StopObserved,
        SamplingDriverEventName::CleanupIntent,
        SamplingDriverEventName::CleanupObserved,
        SamplingDriverEventName::ExportIntent,
        SamplingDriverEventName::ExportObserved,
    ];
    SamplingCaptureReceipt {
        schema: SamplingCaptureReceiptSchemaVersion,
        session_id: "session-01".to_owned(),
        session_operation_id: "0123456789abcdef0123456789abcdef".to_owned(),
        transaction_id: "123e4567-e89b-42d3-a456-426614174000".to_owned(),
        endpoint_fingerprint: digest('f'),
        endpoint_fingerprint_scheme: EndpointFingerprintScheme::T32PerfEndpointFingerprintV2,
        session_request_sha256: digest('b'),
        histogram_sha256: digest('a'),
        histogram_size_bytes: 128,
        journal_event_claims: events
            .into_iter()
            .enumerate()
            .map(|(index, event)| SamplingJournalEventClaim {
                sequence: (index + 1) as u64,
                event,
                sha256: digest(char::from_digit(index as u32 + 1, 16).unwrap()),
            })
            .collect(),
    }
}

fn sample_sampling_capture_request() -> SamplingCaptureRequest {
    SamplingCaptureRequest {
        schema: SamplingCaptureRequestSchemaVersion,
        ranges: vec![SamplingAddressRange {
            start_address: 0x1000,
            end_address: 0x1024,
        }],
        bucket_size: 0x10,
        duration_ms: 100,
        method_policy: SamplingMethodPolicy::RealtimeOnly,
        core_id: 0,
        address_space: SamplingAddressSpace::P,
        deployed_firmware_elf_sha256: None,
    }
}

fn sample_manifest() -> Manifest {
    Manifest {
        schema: ManifestSchemaVersion,
        session_id: "session-01".to_owned(),
        created_at: "2026-08-23T08:00:00Z".to_owned(),
        tool: ToolInfo {
            name: "t32perf".to_owned(),
            version: "0.1.0".to_owned(),
            commit: Some("0123456".to_owned()),
        },
        capture: CaptureInfo {
            provider: None,
            mode: "etm".to_owned(),
            adapter: AdapterInfo {
                id: "trace32-csv".to_owned(),
                version: "1".to_owned(),
            },
            target: Some(TargetInfo {
                architecture: Some("armv8-m".to_owned()),
                device: Some("example-mcu".to_owned()),
                board: None,
                core_count: Some(1),
                properties: Properties::new(),
            }),
            trace32: Some(Trace32Info {
                build: Some("R.2026.02".to_owned()),
                probe: Some("PowerTrace".to_owned()),
                architecture_package: Some("ARM".to_owned()),
                properties: Properties::new(),
            }),
            request_sha256: Some(digest('a')),
            covered_cores: Vec::new(),
            capabilities: None,
            capture_config: None,
            instrumentation: None,
        },
        firmware: FirmwareInfo {
            elf_path: Some("firmware/example.elf".to_owned()),
            elf_sha256: Some(digest('b')),
            build_id: Some("golden".to_owned()),
        },
        clocks: vec![ClockInfo {
            id: "trace".to_owned(),
            frequency_hz: Some(100_000_000),
            source: Some("target".to_owned()),
            properties: Properties::new(),
        }],
        stages: vec![StageInfo {
            name: "capture".to_owned(),
            status: StageStatus::Complete,
            started_at: Some("2026-08-23T08:00:01Z".to_owned()),
            completed_at: Some("2026-08-23T08:00:02Z".to_owned()),
            input_artifact_ids: Vec::new(),
            output_artifact_ids: vec!["raw".to_owned()],
            message: None,
        }],
        artifacts: vec![
            Artifact {
                id: "raw".to_owned(),
                kind: "raw_trace".to_owned(),
                relative_path: ArtifactPath::new("raw/trace.bin").unwrap(),
                media_type: "application/octet-stream".to_owned(),
                size_bytes: 16,
                sha256: digest('c'),
                producer: "capture".to_owned(),
                input_artifact_ids: Vec::new(),
            },
            Artifact {
                id: "observations".to_owned(),
                kind: "observations".to_owned(),
                relative_path: ArtifactPath::new("normalized/observations.ndjson").unwrap(),
                media_type: "application/x-ndjson".to_owned(),
                size_bytes: 32,
                sha256: digest('d'),
                producer: "normalize".to_owned(),
                input_artifact_ids: vec!["raw".to_owned()],
            },
        ],
    }
}

fn sample_capture_receipt() -> CaptureReceipt {
    let exact = MetricSupportEntry::new(MetricSupportLevel::Exact);
    let unavailable = MetricSupportEntry {
        support: MetricSupportLevel::Unavailable,
        reasons: vec!["not captured".to_owned()],
    };
    CaptureReceipt {
        schema: CaptureReceiptSchemaVersion,
        session_id: "session-01".to_owned(),
        provider: "trace32".to_owned(),
        mode: "etm".to_owned(),
        adapter: AdapterInfo {
            id: "trace32-build-validated".to_owned(),
            version: "1".to_owned(),
        },
        target: Some(TargetInfo {
            architecture: Some("armv8-m".to_owned()),
            device: Some("example-mcu".to_owned()),
            board: Some("example-board".to_owned()),
            core_count: Some(1),
            properties: Properties::new(),
        }),
        trace32: Some(Trace32Info {
            build: Some("R.2026.02".to_owned()),
            probe: Some("PowerTrace".to_owned()),
            architecture_package: Some("ARM".to_owned()),
            properties: Properties::new(),
        }),
        firmware: FirmwareInfo {
            elf_path: Some("firmware/example.elf".to_owned()),
            elf_sha256: Some(digest('b')),
            build_id: Some("golden".to_owned()),
        },
        clocks: vec![ClockInfo {
            id: "trace".to_owned(),
            frequency_hz: Some(100_000_000),
            source: Some("target".to_owned()),
            properties: Properties::new(),
        }],
        covered_cores: vec![0],
        capabilities: CaptureCapabilities {
            function_events: exact.clone(),
            context_switches: exact.clone(),
            interrupt_events: exact,
            samples: unavailable.clone(),
            custom_events: unavailable.clone(),
            counters: unavailable,
        },
        health_observations: Vec::new(),
        request_sha256: digest('a'),
        capture_config: Some(CaptureConfigArtifactClaim {
            artifact_id: "capture-config".to_owned(),
            sha256: digest('f'),
            configuration_sha256: digest('e'),
        }),
        controller_health: None,
        properties: Properties::new(),
    }
}

fn sample_capture_config() -> CaptureConfigDocument {
    CaptureConfigDocument {
        schema: CaptureConfigSchemaVersion,
        session_id: "session-01".to_owned(),
        provider: "trace32".to_owned(),
        adapter: AdapterInfo {
            id: "trace32-build-validated".to_owned(),
            version: "1".to_owned(),
        },
        mode: "etm".to_owned(),
        covered_cores: vec![0],
        sink: CaptureSinkConfig {
            kind: "probe_buffer".to_owned(),
            id: "powertrace-0".to_owned(),
            capacity_bytes: Some(1_048_576),
            stream_destination_identity: None,
        },
        timestamp: CaptureTimestampConfig {
            enabled: true,
            clock_id: Some("trace".to_owned()),
        },
        filters: vec![CaptureFilterConfig {
            kind: "address_range".to_owned(),
            identity: "firmware-text".to_owned(),
            enabled: true,
            parameters: Properties::from([
                ("start".to_owned(), json!(4096)),
                ("end".to_owned(), json!(8192)),
            ]),
        }],
        trigger: CaptureTriggerConfig {
            kind: "condition".to_owned(),
            pre_trigger_ns: Some(250_000),
            post_trigger_ns: Some(750_000),
            condition_identity: Some("workload-complete".to_owned()),
        },
        duration: CaptureDurationConfig {
            duration_ns: Some(1_000_000),
            observation_limit: None,
        },
        workload_identity: "golden-workload/v1".to_owned(),
        initial_target_state: InitialTargetState::Halted,
        rtos_awareness: CaptureRtosAwarenessConfig {
            kind: "orti-v1".to_owned(),
            metadata_artifact_ids: vec!["orti".to_owned()],
        },
        instrumentation: Some(CaptureInstrumentationConfig {
            method: "t32perf-c-wire/v1".to_owned(),
            transport: "shared-memory-ring-buffer/v1".to_owned(),
            overhead: CaptureInstrumentationOverhead {
                measurement_method: "golden-overhead-benchmark/v1".to_owned(),
                baseline_duration_ns: 100_000,
                instrumented_duration_ns: 112_000,
                emitted_event_count: 1_000,
                evidence_artifact_id: "instrumentation-overhead".to_owned(),
            },
        }),
        adapter_parameters: Properties::from([
            ("trace_source_identity".to_owned(), json!("etm-core-0")),
            ("firmware.elf_sha256".to_owned(), json!("b".repeat(64))),
        ]),
    }
}

fn sample_instrumentation_overhead_evidence() -> InstrumentationOverheadEvidenceDocument {
    InstrumentationOverheadEvidenceDocument {
        schema: InstrumentationOverheadEvidenceSchemaVersion,
        instrumentation_method: "t32perf-c-wire/v1".to_owned(),
        transport: "shared-memory-ring-buffer/v1".to_owned(),
        measurement_method: "controlled-paired-run/v1".to_owned(),
        baseline_duration_ns: 100_000,
        instrumented_duration_ns: 112_000,
        emitted_event_count: 1_000,
    }
}

fn sample_capture_attestation() -> CaptureAttestation {
    CaptureAttestation {
        payload: CaptureAttestationPayload {
            schema: CaptureAttestationSchemaVersion,
            key_id: "lab-key-1".to_owned(),
            nonce: "operation-01".to_owned(),
            receipt: sample_capture_receipt(),
            observation_artifact_id: "observations".to_owned(),
            observation_sha256: digest('e'),
            capture_config: Some(CaptureConfigArtifactClaim {
                artifact_id: "capture-config".to_owned(),
                sha256: digest('f'),
                configuration_sha256: digest('e'),
            }),
            controller_health: None,
        },
        signature_ed25519: "2".repeat(128),
    }
}

fn sample_capture_trust_policy() -> CaptureTrustPolicy {
    let receipt = sample_capture_receipt();
    CaptureTrustPolicy {
        schema: CaptureTrustPolicySchemaVersion,
        policy_id: "lab-policy-1".to_owned(),
        keys: vec![CaptureTrustKey {
            key_id: "lab-key-1".to_owned(),
            public_key_ed25519: "1".repeat(64),
            producer: "lab.trace32.adapter/v1".to_owned(),
            provider: receipt.provider,
            adapter: receipt.adapter,
            allowed_modes: vec![receipt.mode],
            target: receipt.target.unwrap(),
            trace32: receipt.trace32,
            clocks: receipt.clocks,
            allowed_cores: receipt.covered_cores,
            allowed_firmware_elf_sha256: vec![digest('b')],
            capability_ceiling: receipt.capabilities,
            config_constraints: None,
        }],
    }
}

fn sample_dictionary() -> ObservationDictionary {
    ObservationDictionary {
        schema: DictionarySchemaVersion,
        session_id: "session-01".to_owned(),
        entries: vec![
            DictionaryEntry::DefineContext {
                id: "task:1".to_owned(),
                kind: ContextKind::Task,
                name: "main".to_owned(),
                core_id: Some(0),
                priority: Some(1),
            },
            DictionaryEntry::DefineFunction {
                id: "function:1".to_owned(),
                name: "work".to_owned(),
                module: Some("firmware".to_owned()),
                address: Some(0x0800_0100),
                file: Some("src/main.c".to_owned()),
                line: Some(42),
            },
            DictionaryEntry::DefineCounter {
                id: "counter:heap".to_owned(),
                name: "heap usage".to_owned(),
                unit: Some("bytes".to_owned()),
                description: None,
                semantic: None,
                subject: None,
            },
        ],
    }
}

fn sample_observations() -> ObservationDocument {
    ObservationDocument {
        schema: ObservationSchemaVersion,
        session_id: "session-01".to_owned(),
        time_unit: TimeUnit::Nanoseconds,
        time_origin: TimeOrigin::SessionRelative,
        observations: vec![
            Observation::new(
                "trace32",
                1,
                Quality::Exact,
                ObservationEvent::FunctionEnter {
                    ts_ns: -5,
                    core_id: 0,
                    context_id: "task:1".to_owned(),
                    function_id: "function:1".to_owned(),
                    frame_id: Some("frame:1".to_owned()),
                },
            ),
            Observation::new(
                "trace32",
                2,
                Quality::Exact,
                ObservationEvent::Counter {
                    ts_ns: 25,
                    core_id: Some(0),
                    context_id: Some("task:1".to_owned()),
                    counter_id: "counter:heap".to_owned(),
                    value: 1024.0,
                    args: Properties::new(),
                },
            ),
            Observation::new(
                "trace32",
                3,
                Quality::Inferred,
                ObservationEvent::TraceGap {
                    ts_ns: 50,
                    duration_ns: 10,
                    reason: "overflow".to_owned(),
                },
            ),
        ],
    }
}

fn sample_span() -> FunctionSpan {
    FunctionSpan {
        source_id: "trace32".to_owned(),
        source_seq_start: Some(1),
        source_seq_end: Some(4),
        core_id: 0,
        context_id: "task:1".to_owned(),
        function_id: "function:1".to_owned(),
        frame_id: Some("frame:1".to_owned()),
        start_ns: 0,
        end_ns: 100,
        elapsed_ns: 100,
        active_ns: 80,
        self_active_ns: 60,
        preempted_ns: 20,
        quality: Quality::Exact,
        incomplete: false,
    }
}

fn sample_derived() -> DerivedDocument {
    DerivedDocument {
        schema: DerivedSchemaVersion,
        session_id: "session-01".to_owned(),
        input_artifact_ids: vec!["observations".to_owned()],
        function_spans: vec![sample_span()],
    }
}

fn sample_hotspots() -> HotspotReport {
    HotspotReport {
        schema: HotspotsSchemaVersion,
        session_id: "session-01".to_owned(),
        quality: Quality::Exact,
        functions: vec![FunctionHotspot {
            function_id: "function:1".to_owned(),
            context_id: Some("task:1".to_owned()),
            inclusive_active_ns: 80,
            self_active_ns: 60,
            count: 1,
            min_active_ns: 80,
            max_active_ns: 80,
            avg_active_ns: 80,
            incomplete_count: 0,
            quality: Quality::Exact,
        }],
        sampling: vec![SamplingHotspot {
            function_id: Some("function:1".to_owned()),
            address: Some(0x0800_0100),
            context_id: Some("task:1".to_owned()),
            sample_count: 10,
            estimated_share: 1.0,
            quality: Quality::Statistical,
        }],
    }
}

fn sample_health() -> HealthReport {
    HealthReport {
        schema: HealthSchemaVersion,
        session_id: "session-01".to_owned(),
        verdict: HealthVerdict::Valid,
        policy_version: "health-policy/1".to_owned(),
        observations: vec![HealthObservation {
            code: "trace_complete".to_owned(),
            source: "trace32".to_owned(),
            artifact_id: Some("raw".to_owned()),
            record: None,
            start_ns: Some(0),
            end_ns: Some(100),
            evidence: Properties::from([("complete".to_owned(), json!(true))]),
        }],
        issues: Vec::new(),
        metric_support: MetricSupport::uniform(MetricSupportLevel::Exact),
    }
}

fn artifact_claim(
    id: &str,
    kind: &str,
    path: &str,
    digest_character: char,
    producer: &str,
    inputs: &[&str],
) -> Artifact {
    Artifact {
        id: id.to_owned(),
        kind: kind.to_owned(),
        relative_path: ArtifactPath::new(path).unwrap(),
        media_type: "application/json".to_owned(),
        size_bytes: 128,
        sha256: digest(digest_character),
        producer: producer.to_owned(),
        input_artifact_ids: inputs.iter().map(|input| (*input).to_owned()).collect(),
    }
}

fn sample_quantitative_summary() -> AnalysisQuantitativeSummary {
    AnalysisQuantitativeSummary {
        analysis: AnalysisSummary {
            observation_count: 3,
            function_span_count: 1,
            incomplete_function_span_count: 0,
            call_depth: CallDepthSummary {
                max_depth: 1,
                context_id: Some("task:1".to_owned()),
                deepest_path: vec!["function:1".to_owned()],
            },
            context_cpu: vec![ContextCpuSummary {
                context_id: "task:1".to_owned(),
                kind: ContextKind::Task,
                active_ns: 80,
            }],
            task_cpu_ns: 80,
            isr_cpu_ns: 0,
            idle_cpu_ns: 20,
            resources: ResourceSummary {
                counters: Vec::new(),
                derived: Vec::new(),
            },
        },
        static_ram: None,
        stack_usage: None,
    }
}

fn sample_diagnostic_counts() -> AnalysisDiagnosticCounts {
    AnalysisDiagnosticCounts {
        observation_count: 3,
        function_span_count: 1,
        incomplete_function_span_count: 0,
        health_observation_count: 1,
        health_issue_count: 0,
    }
}

fn sample_analysis_summary_document() -> AnalysisSummaryDocument {
    AnalysisSummaryDocument {
        schema: AnalysisSummarySchemaVersion,
        session_id: "session-01".to_owned(),
        health_verdict: HealthVerdict::Valid,
        metric_support: MetricSupport::uniform(MetricSupportLevel::Exact),
        input_artifacts: vec![artifact_claim(
            "health",
            "health",
            "analysis/health.json",
            'e',
            "t32perf-analysis",
            &["observations", "capture-receipt"],
        )],
        diagnostics: sample_diagnostic_counts(),
        quantitative: Some(sample_quantitative_summary()),
    }
}

fn sample_analysis_stage_receipt() -> AnalysisStageReceipt {
    AnalysisStageReceipt {
        schema: AnalysisStageSchemaVersion,
        session_id: "session-01".to_owned(),
        tool: ToolInfo {
            name: "t32perf".to_owned(),
            version: "0.1.0".to_owned(),
            commit: None,
        },
        contracts: AnalysisContracts {
            analyzer: ANALYZER_CONTRACT.to_owned(),
            health_policy: "health-policy/1".to_owned(),
            health_schema: HealthSchemaVersion,
            derived_stream_schema: DerivedStreamSchemaVersion,
            hotspots_schema: HotspotsSchemaVersion,
            analysis_summary_schema: AnalysisSummarySchemaVersion,
        },
        health_verdict: HealthVerdict::Valid,
        metric_support: MetricSupport::uniform(MetricSupportLevel::Exact),
        diagnostics: sample_diagnostic_counts(),
        input_artifacts: vec![artifact_claim(
            "observations",
            "observations",
            "normalized/observations.ndjson",
            'd',
            "normalize",
            &[],
        )],
        output_artifacts: vec![artifact_claim(
            "health",
            "health",
            "analysis/health.json",
            'e',
            "t32perf-analysis",
            &["observations"],
        )],
    }
}

fn sample_comparison() -> ComparisonReport {
    ComparisonReport {
        schema: ComparisonSchemaVersion,
        baseline_session_id: "session-00".to_owned(),
        candidate_session_id: "session-01".to_owned(),
        baseline_health: HealthVerdict::Valid,
        candidate_health: HealthVerdict::Valid,
        verdict: ComparisonVerdict::Improved,
        metrics: vec![MetricComparison {
            subject: ComparisonSubject {
                kind: ComparisonSubjectKind::Function,
                id: "function:1".to_owned(),
                context_id: None,
            },
            metric: ComparisonMetricKind::SelfActiveNs,
            baseline: 100.0,
            candidate: 80.0,
            delta: -20.0,
            relative_change: Some(-0.2),
            quality: Quality::Exact,
            outcome: MetricComparisonOutcome::Improved,
            reasons: vec!["lower_is_better".to_owned()],
        }],
        resource_metrics: Vec::new(),
        static_ram_metrics: Vec::new(),
        reasons: Vec::new(),
    }
}

fn sample_report() -> AnalysisReport {
    AnalysisReport {
        schema: ReportSchemaVersion,
        session_id: "session-01".to_owned(),
        generated_at: "2026-08-23T08:00:03Z".to_owned(),
        title: "Golden capture".to_owned(),
        health_verdict: HealthVerdict::Valid,
        summary: ReportSummary {
            capture_duration_ns: Some(100),
            function_span_count: 1,
            sample_count: 10,
            comparison_verdict: Some(ComparisonVerdict::Improved),
        },
        findings: vec![ReportFinding {
            code: "top_hotspot".to_owned(),
            severity: HealthSeverity::Info,
            title: "Top hotspot".to_owned(),
            message: "function:1 has the highest self active time".to_owned(),
            evidence: Properties::from([("function_id".to_owned(), json!("function:1"))]),
        }],
        artifacts: vec![ReportArtifactLink {
            artifact_id: "observations".to_owned(),
            role: "timeline".to_owned(),
        }],
    }
}

fn sample_state() -> SessionState {
    SessionState {
        schema: StateSchemaVersion,
        created_at: "2026-08-23T08:00:00Z".to_owned(),
        status: SessionStatus::Complete,
        operation_id: "operation-01".to_owned(),
        revision: 5,
        updated_at: "2026-08-23T08:00:03Z".to_owned(),
        error: None,
    }
}

fn sample_perf_surface() -> PerfSurfaceEnvelope {
    PerfSurfaceEnvelope::new(PerfSurfaceResponse::Capabilities(PerfControlPayload {
        session_id: "session-01".to_owned(),
        state: SessionStatus::Created,
        capture_phase: PerfCapturePhase::CapabilitiesRequired,
        status: PerfControlStatus::CapabilitiesComplete,
        completed_operations: vec![PerfControllerOperation::GetCapabilities],
        pending_operation: None,
        transaction_id: None,
        request_artifact: None,
        capture_artifacts: Vec::new(),
        next_action: PerfNextAction::Invoke {
            operation: PerfSurfaceOperation::Capture,
            required_controller_operation: Some(PerfControllerOperation::Configure),
        },
    }))
}

fn sample_performance_run_payload() -> PerfRunPayload {
    PerfRunPayload {
        session_id: "session-01".to_owned(),
        phase: PerformanceRunPhase::Provision,
        state: SessionStatus::Created,
        trust_status: PerfTrustStatus::NotEvaluated,
        health_verdict: None,
        summary: None,
        report_artifact: None,
        manifest_sha256: None,
        resumed: false,
    }
}

fn assert_roundtrip<T>(value: &T)
where
    T: Debug + PartialEq + Serialize + DeserializeOwned,
{
    let encoded = serde_json::to_vec(value).unwrap();
    let decoded = serde_json::from_slice::<T>(&encoded).unwrap();
    assert_eq!(&decoded, value);
}

fn assert_schema_accepts<T: Serialize>(filename: &str, value: &T) {
    let schemas = schema_documents();
    let schema = &schemas[filename];
    let validator = jsonschema::validator_for(schema).unwrap();
    let instance = serde_json::to_value(value).unwrap();
    assert!(
        validator.is_valid(&instance),
        "{filename} rejected {}",
        serde_json::to_string_pretty(&instance).unwrap()
    );
}

#[test]
fn every_document_roundtrips_and_matches_its_schema() {
    let manifest = sample_manifest();
    let capture_receipt = sample_capture_receipt();
    let capture_attestation = sample_capture_attestation();
    let capture_trust_policy = sample_capture_trust_policy();
    let capture_config = sample_capture_config();
    let dictionary = sample_dictionary();
    let observations = sample_observations();
    let derived = sample_derived();
    let derived_stream = DerivedStreamHeader::ndjson("session-01");
    let hotspots = sample_hotspots();
    let health = sample_health();
    let comparison = sample_comparison();
    let report = sample_report();
    let analysis_summary = sample_analysis_summary_document();
    let analysis_stage = sample_analysis_stage_receipt();
    let state = sample_state();
    let perf_surface = sample_perf_surface();
    let performance_run_payload = sample_performance_run_payload();

    capture_receipt.validate().unwrap();
    capture_attestation.validate().unwrap();
    capture_trust_policy.validate().unwrap();
    capture_config.validate().unwrap();

    assert_roundtrip(&manifest);
    assert_roundtrip(&capture_receipt);
    assert_roundtrip(&capture_attestation);
    assert_roundtrip(&capture_trust_policy);
    assert_roundtrip(&capture_config);
    assert_roundtrip(&dictionary);
    assert_roundtrip(&observations);
    assert_roundtrip(&derived);
    assert_roundtrip(&derived_stream);
    assert_roundtrip(&hotspots);
    assert_roundtrip(&health);
    assert_roundtrip(&comparison);
    assert_roundtrip(&report);
    assert_roundtrip(&analysis_summary);
    assert_roundtrip(&analysis_stage);
    assert_roundtrip(&state);
    assert_roundtrip(&perf_surface);
    assert_roundtrip(&performance_run_payload);

    assert_schema_accepts("manifest.schema.json", &manifest);
    assert_schema_accepts("capture-receipt.schema.json", &capture_receipt);
    assert_schema_accepts("capture-attestation.schema.json", &capture_attestation);
    assert_schema_accepts("capture-trust-policy.schema.json", &capture_trust_policy);
    assert_schema_accepts("capture-config.schema.json", &capture_config);
    assert_schema_accepts("dictionary.schema.json", &dictionary);
    assert_schema_accepts("observation.schema.json", &observations);
    assert_schema_accepts(
        "observation.schema.json",
        &ObservationStreamHeader::ndjson("session-01"),
    );
    assert_schema_accepts("derived.schema.json", &derived);
    assert_schema_accepts("derived-stream.schema.json", &derived_stream);
    assert_schema_accepts("hotspots.schema.json", &hotspots);
    assert_schema_accepts("health.schema.json", &health);
    assert_schema_accepts("comparison.schema.json", &comparison);
    assert_schema_accepts("report.schema.json", &report);
    assert_schema_accepts("analysis-summary.schema.json", &analysis_summary);
    assert_schema_accepts("analysis-stage.schema.json", &analysis_stage);
    assert_schema_accepts("state.schema.json", &state);
    assert_schema_accepts("perf-surface.schema.json", &perf_surface);
    assert_schema_accepts(
        "performance-run-payload.schema.json",
        &performance_run_payload,
    );
}

#[test]
fn perf_surface_rejects_arbitrary_payload_fields() {
    let mut value = serde_json::to_value(sample_perf_surface()).unwrap();
    value["payload"]["untyped_escape_hatch"] = json!(true);
    assert!(serde_json::from_value::<PerfSurfaceEnvelope>(value.clone()).is_err());
    let validator =
        jsonschema::validator_for(&schema_documents()["perf-surface.schema.json"]).unwrap();
    assert!(!validator.is_valid(&value));
}

#[test]
fn schema_versions_reject_unknown_family_and_major() {
    let unsupported = serde_json::from_str::<ManifestSchemaVersion>("\"t32perf.manifest/v2\"")
        .unwrap_err()
        .to_string();
    assert!(unsupported.contains("unsupported"));

    let wrong_family = serde_json::from_str::<ManifestSchemaVersion>("\"t32perf.health/v1\"")
        .unwrap_err()
        .to_string();
    assert!(wrong_family.contains("does not match"));

    assert!(matches!(
        validate_schema_version("t32perf.manifest/v9", MANIFEST_SCHEMA),
        Err(SchemaVersionError::UnsupportedMajor { actual: 9, .. })
    ));
    assert!(serde_json::from_str::<ManifestSchemaVersion>("\"t32perf.manifest/v01\"").is_err());
}

#[test]
fn release_provenance_schema_is_closed_and_models_platform_linkage_policies() {
    let schema = &schema_documents()["release-provenance.schema.json"];
    let validator = jsonschema::validator_for(schema).unwrap();
    let windows = json!({
        "schema": "t32perf.release-provenance/v1",
        "package": {
            "name": "t32perf",
            "version": "0.1.0",
            "bundle_name": "t32perf-0.1.0-windows-x86_64"
        },
        "target": {
            "os": "windows",
            "arch": "x86_64",
            "triple": "x86_64-pc-windows-msvc"
        },
        "toolchain": {
            "rustc": "rustc 1.95.0",
            "cargo": "cargo 1.95.0"
        },
        "source": {
            "commit": "a".repeat(40),
            "cargo_lock": {
                "path": "Cargo.lock",
                "size_bytes": 1,
                "sha256": "b".repeat(64)
            }
        },
        "binary": {
            "path": "t32perf.exe",
            "size_bytes": 2,
            "sha256": "c".repeat(64)
        },
        "linkage": {
            "policy": "windows-msvc-static-crt",
            "audit": "pe-import-table/v1",
            "imported_libraries": ["kernel32.dll", "ntdll.dll"]
        }
    });
    validator.validate(&windows).unwrap();

    let mut unknown = windows.clone();
    unknown["unexpected"] = json!(true);
    assert!(!validator.is_valid(&unknown));

    let mut dynamic_crt_policy = windows;
    dynamic_crt_policy["linkage"]["policy"] = json!("system-libc-dynamic-allowed");
    assert!(!validator.is_valid(&dynamic_crt_policy));
}

#[test]
fn v1_readers_accept_future_optional_fields() {
    let mut manifest = serde_json::to_value(sample_manifest()).unwrap();
    manifest["future_optional"] = json!({ "enabled": true });
    manifest["capture"]["future_optional"] = json!(42);

    let decoded = serde_json::from_value::<Manifest>(manifest.clone()).unwrap();
    assert_eq!(decoded.session_id, "session-01");

    let schemas = schema_documents();
    let validator = jsonschema::validator_for(&schemas["manifest.schema.json"]).unwrap();
    assert!(validator.is_valid(&manifest));
}

#[test]
fn durations_are_nonnegative_in_serde_and_json_schema() {
    let mut derived = serde_json::to_value(sample_derived()).unwrap();
    derived["function_spans"][0]["elapsed_ns"] = json!(-1);
    assert!(serde_json::from_value::<DerivedDocument>(derived.clone()).is_err());

    let schemas = schema_documents();
    let validator = jsonschema::validator_for(&schemas["derived.schema.json"]).unwrap();
    assert!(!validator.is_valid(&derived));

    let observations = sample_observations();
    assert_eq!(observations.observations[0].ts_ns(), -5);
}

#[test]
fn artifact_paths_reject_absolute_and_traversal_forms() {
    let schemas = schema_documents();
    let validator = jsonschema::validator_for(&schemas["manifest.schema.json"]).unwrap();
    for path in [
        "/absolute/file",
        "C:/absolute/file",
        "../escape",
        "nested/../escape",
        "nested\\file",
        "nested//file",
        "nested/file/",
        "name:stream",
        "nested/CON",
        "nested/com1.log",
        "nested/COM¹.log",
        "nested/CONIN$.txt",
        "nested/CON .txt",
        "nested/LPT9.txt",
        "nested/trailing.",
        "nested/trailing ",
        "nested/invalid?.bin",
        "nested/control\u{001f}.bin",
        "\u{6570}\u{636e}/\u{62a5}\u{544a}.bin",
        "nested/Ä.bin",
        "nested/ä.bin",
        "nested/COM¹.log",
    ] {
        assert!(ArtifactPath::new(path).is_err(), "accepted `{path}`");
        let mut manifest = serde_json::to_value(sample_manifest()).unwrap();
        manifest["artifacts"][0]["relative_path"] = json!(path);
        assert!(serde_json::from_value::<Manifest>(manifest.clone()).is_err());
        assert!(!validator.is_valid(&manifest), "schema accepted `{path}`");
    }
    assert_eq!(
        ArtifactPath::new("Analysis/Report.JSON")
            .unwrap()
            .portable_key(),
        "analysis/report.json"
    );
}

#[test]
fn portable_artifact_and_session_names_reject_cross_platform_aliases() {
    for id in ["CON", "nul.json", "com1.log", "LPT9"] {
        let mut artifact = sample_manifest().artifacts.remove(0);
        artifact.id = id.to_owned();
        assert!(artifact.validate().is_err(), "accepted artifact id `{id}`");
    }

    let mut manifest = sample_manifest();
    manifest.session_id = "CON".to_owned();
    assert!(matches!(
        manifest.validate(),
        Err(ManifestValidationError::InvalidMetadata {
            field: "session_id",
            ..
        })
    ));

    let mut manifest = sample_manifest();
    manifest.artifacts[1].id = "RAW".to_owned();
    manifest.artifacts[1].input_artifact_ids.clear();
    assert!(matches!(
        manifest.validate(),
        Err(ManifestValidationError::DuplicateArtifactId { .. })
    ));

    let mut manifest = sample_manifest();
    manifest.artifacts[1].relative_path = ArtifactPath::new("RAW/TRACE.BIN").unwrap();
    assert!(matches!(
        manifest.validate(),
        Err(ManifestValidationError::DuplicateArtifactPath { .. })
    ));

    let mut artifact = sample_manifest().artifacts.remove(0);
    artifact.id = "Raw".to_owned();
    artifact.input_artifact_ids = vec!["raw".to_owned()];
    assert!(matches!(
        artifact.validate(),
        Err(ArtifactValidationError::SelfReference)
    ));
}

#[test]
fn semantic_invariants_reject_inconsistent_derived_data() {
    let mut span = sample_span();
    span.elapsed_ns = 99;
    assert!(matches!(
        span.validate(),
        Err(DerivedValidationError::ElapsedMismatch { .. })
    ));

    let mut hotspot = sample_hotspots().functions.remove(0);
    hotspot.self_active_ns = hotspot.inclusive_active_ns + 1;
    assert!(matches!(
        hotspot.validate(),
        Err(HotspotValidationError::SelfTimeExceedsInclusive { .. })
    ));

    let mut hotspot = sample_hotspots().functions.remove(0);
    hotspot.inclusive_active_ns = 161;
    hotspot.count = 2;
    hotspot.min_active_ns = 80;
    hotspot.max_active_ns = 81;
    hotspot.avg_active_ns = 81;
    assert!(matches!(
        hotspot.validate(),
        Err(HotspotValidationError::AverageMismatch {
            expected_avg_active_ns: 80,
            actual_avg_active_ns: 81,
            ..
        })
    ));
}

#[test]
fn observation_sequences_are_strictly_monotonic_per_source() {
    let mut observations = sample_observations();
    observations.observations[2].source_seq = 2;
    assert!(matches!(
        observations.validate(),
        Err(ObservationValidationError::NonMonotonicSourceSequence { .. })
    ));
}

#[test]
fn observation_and_dictionary_identities_are_semantically_required() {
    let mut observations = sample_observations();
    observations.observations[0].source_id.clear();
    assert!(matches!(
        observations.validate(),
        Err(ObservationValidationError::EmptyField {
            field: "source_id",
            ..
        })
    ));

    let sample = Observation::new(
        "sampler",
        1,
        Quality::Statistical,
        ObservationEvent::Sample {
            ts_ns: 0,
            core_id: 0,
            context_id: None,
            function_id: None,
            address: None,
            weight_ns: Some(1),
        },
    );
    assert!(matches!(
        sample.validate(),
        Err(ObservationValidationError::MissingSampleIdentity { .. })
    ));

    let mut dictionary = sample_dictionary();
    if let DictionaryEntry::DefineFunction { line, .. } = &mut dictionary.entries[1] {
        *line = Some(0);
    }
    assert!(matches!(
        dictionary.validate(),
        Err(DictionaryValidationError::InvalidSourceLine { .. })
    ));
}

#[test]
fn health_verdict_and_metric_support_cannot_overstate_trust() {
    let mut health = sample_health();
    health.issues.push(HealthIssue {
        code: "trace_gap".to_owned(),
        severity: HealthSeverity::Warning,
        source: "parser".to_owned(),
        artifact_id: Some("raw".to_owned()),
        record: Some(1),
        start_ns: Some(10),
        end_ns: Some(20),
        evidence: Properties::new(),
        message: "trace contains a gap".to_owned(),
    });
    assert!(matches!(
        health.validate(),
        Err(HealthValidationError::VerdictUnderstatesSeverity { .. })
    ));

    health.verdict = HealthVerdict::Degraded;
    health.metric_support.active = MetricSupportEntry::new(MetricSupportLevel::Inferred);
    assert!(matches!(
        health.validate(),
        Err(HealthValidationError::NonExactWithoutReason { .. })
    ));
}

#[test]
fn analysis_summary_persists_quantitative_values_only_for_valid_health() {
    let mut summary = sample_analysis_summary_document();
    summary.health_verdict = HealthVerdict::Invalid;
    assert!(matches!(
        summary.validate(),
        Err(AnalysisContractValidationError::UntrustedQuantitativeSummary { .. })
    ));

    summary.quantitative = None;
    assert!(summary.validate().is_ok());

    summary.health_verdict = HealthVerdict::Degraded;
    assert!(summary.validate().is_ok());

    summary.health_verdict = HealthVerdict::Valid;
    assert!(matches!(
        summary.validate(),
        Err(AnalysisContractValidationError::MissingQuantitativeSummary)
    ));
}

#[test]
fn analysis_receipt_rejects_ambiguous_or_overlapping_claims() {
    let mut receipt = sample_analysis_stage_receipt();
    receipt
        .output_artifacts
        .push(receipt.output_artifacts[0].clone());
    assert!(matches!(
        receipt.validate(),
        Err(AnalysisContractValidationError::DuplicateArtifactClaim { .. })
    ));

    let mut receipt = sample_analysis_stage_receipt();
    receipt.output_artifacts[0] = receipt.input_artifacts[0].clone();
    assert!(matches!(
        receipt.validate(),
        Err(AnalysisContractValidationError::InputOutputOverlap { .. })
    ));

    let mut encoded = serde_json::to_value(sample_analysis_stage_receipt()).unwrap();
    encoded["future_constraint"] = json!("must-not-be-ignored");
    assert!(serde_json::from_value::<AnalysisStageReceipt>(encoded).is_err());
}

#[test]
fn capture_receipt_rejects_unexplained_capabilities_and_empty_health_evidence() {
    let mut receipt = sample_capture_receipt();
    receipt.capabilities.samples = MetricSupportEntry::new(MetricSupportLevel::Statistical);
    assert!(matches!(
        receipt.validate(),
        Err(CaptureReceiptValidationError::NonExactWithoutReason { .. })
    ));

    receipt.capabilities.samples.reasons = vec!["pc_sampling".to_owned()];
    receipt.health_observations.push(HealthObservation {
        code: "trace_complete".to_owned(),
        source: " ".to_owned(),
        artifact_id: None,
        record: None,
        start_ns: None,
        end_ns: None,
        evidence: Properties::new(),
    });
    assert!(matches!(
        receipt.validate(),
        Err(CaptureReceiptValidationError::EmptyField { .. })
    ));
}

#[test]
fn trace32_firmware_identity_requires_an_elf_digest_and_key_allowlist() {
    let mut receipt = sample_capture_receipt();
    receipt.firmware.elf_sha256 = None;
    assert!(matches!(
        receipt.validate(),
        Err(CaptureReceiptValidationError::MissingTrace32FirmwareElfSha256)
    ));

    let mut policy = sample_capture_trust_policy();
    policy.keys[0].allowed_firmware_elf_sha256.clear();
    assert!(matches!(
        policy.validate(),
        Err(CaptureTrustPolicyValidationError::InvalidFirmwareElfAllowlist { .. })
    ));

    let mut policy = sample_capture_trust_policy();
    policy.keys[0].allowed_firmware_elf_sha256.push(digest('b'));
    assert!(matches!(
        policy.validate(),
        Err(CaptureTrustPolicyValidationError::InvalidFirmwareElfAllowlist { .. })
    ));
}

#[test]
fn capture_attestation_and_policy_validate_replay_and_key_encodings() {
    let mut attestation = sample_capture_attestation();
    attestation.payload.nonce.clear();
    assert!(matches!(
        attestation.validate(),
        Err(CaptureAttestationValidationError::EmptyField { .. })
    ));

    let mut attestation = sample_capture_attestation();
    attestation.payload.capture_config.as_mut().unwrap().sha256 = digest('1');
    assert!(matches!(
        attestation.validate(),
        Err(CaptureAttestationValidationError::CaptureConfigClaimMismatch)
    ));

    let mut attestation = sample_capture_attestation();
    attestation.payload.receipt.controller_health = Some(ControllerHealthArtifactClaim {
        artifact_id: "controller-health".to_owned(),
        sha256: digest('2'),
    });
    attestation.payload.controller_health = Some(ControllerHealthArtifactClaim {
        artifact_id: "controller-health".to_owned(),
        sha256: digest('3'),
    });
    assert!(matches!(
        attestation.validate(),
        Err(CaptureAttestationValidationError::ControllerHealthClaimMismatch)
    ));

    let mut policy = sample_capture_trust_policy();
    policy.keys[0].public_key_ed25519 = "not-a-key".to_owned();
    assert!(matches!(
        policy.validate(),
        Err(CaptureTrustPolicyValidationError::InvalidPublicKeyEncoding { .. })
    ));

    let mut policy_json = serde_json::to_value(sample_capture_trust_policy()).unwrap();
    policy_json["keys"][0]["future_constraint"] = json!("must-not-be-ignored");
    assert!(serde_json::from_value::<CaptureTrustPolicy>(policy_json).is_err());

    let mut legacy = serde_json::to_value(sample_capture_attestation()).unwrap();
    legacy["payload"]
        .as_object_mut()
        .unwrap()
        .remove("capture_config");
    legacy["payload"]["receipt"]
        .as_object_mut()
        .unwrap()
        .remove("capture_config");
    let legacy: CaptureAttestation = serde_json::from_value(legacy).unwrap();
    assert!(legacy.validate().is_ok());
    assert!(legacy.payload.capture_config.is_none());
}

#[test]
fn capture_config_rejects_ambiguous_or_unbounded_authoritative_state() {
    let mut config = sample_capture_config();
    config.covered_cores.push(0);
    assert!(matches!(
        config.validate(),
        Err(CaptureConfigValidationError::DuplicateCore { core_id: 0 })
    ));

    let mut config = sample_capture_config();
    config.timestamp.clock_id = None;
    assert!(matches!(
        config.validate(),
        Err(CaptureConfigValidationError::TimestampClockMissing)
    ));

    let mut config = sample_capture_config();
    config.duration.duration_ns = Some(0);
    assert!(matches!(
        config.validate(),
        Err(CaptureConfigValidationError::ZeroDurationBound {
            field: "duration.duration_ns"
        })
    ));

    let mut config = sample_capture_config();
    config.duration.duration_ns = None;
    config.duration.observation_limit = Some(0);
    assert!(matches!(
        config.validate(),
        Err(CaptureConfigValidationError::ZeroDurationBound {
            field: "duration.observation_limit"
        })
    ));

    let schema = schema_documents()["capture-config.schema.json"].clone();
    let validator = jsonschema::validator_for(&schema).unwrap();
    for field in ["duration_ns", "observation_limit"] {
        let mut document = serde_json::to_value(sample_capture_config()).unwrap();
        document["duration"][field] = json!(0);
        assert!(
            !validator.is_valid(&document),
            "schema accepted zero {field}"
        );
    }

    let mut config = sample_capture_config();
    config.filters.push(config.filters[0].clone());
    assert!(matches!(
        config.validate(),
        Err(CaptureConfigValidationError::DuplicateFilter { .. })
    ));

    let mut config = sample_capture_config();
    config
        .rtos_awareness
        .metadata_artifact_ids
        .push("ORTI".to_owned());
    assert!(matches!(
        config.validate(),
        Err(CaptureConfigValidationError::DuplicateMetadataArtifact { .. })
    ));

    let mut config = sample_capture_config();
    let instrumentation = config.instrumentation.as_mut().unwrap();
    instrumentation.overhead.emitted_event_count = 0;
    assert!(matches!(
        config.validate(),
        Err(CaptureConfigValidationError::ZeroInstrumentationEventCount)
    ));

    let mut config = sample_capture_config();
    let instrumentation = config.instrumentation.as_mut().unwrap();
    instrumentation.overhead.instrumented_duration_ns =
        instrumentation.overhead.baseline_duration_ns - 1;
    assert!(matches!(
        config.validate(),
        Err(CaptureConfigValidationError::NegativeInstrumentationOverhead)
    ));

    let mut config = sample_capture_config();
    config
        .rtos_awareness
        .metadata_artifact_ids
        .push("INSTRUMENTATION-OVERHEAD".to_owned());
    assert!(matches!(
        config.validate(),
        Err(CaptureConfigValidationError::DuplicateMetadataArtifact { .. })
    ));

    assert_eq!(
        sample_capture_config().input_artifact_ids(),
        vec!["orti", "instrumentation-overhead"]
    );

    let mut config = sample_capture_config();
    config
        .adapter_parameters
        .insert("oversized".to_owned(), json!("x".repeat(4_097)));
    assert!(matches!(
        config.validate(),
        Err(CaptureConfigValidationError::InvalidProperties { .. })
    ));

    let mut second_session = sample_capture_config();
    second_session.session_id = "session-02".to_owned();
    assert_eq!(
        config_identity(&sample_capture_config()),
        config_identity(&second_session)
    );
    second_session.mode = "sampling".to_owned();
    assert_ne!(
        config_identity(&sample_capture_config()),
        config_identity(&second_session)
    );
}

#[test]
fn instrumentation_overhead_evidence_is_strict_and_binds_its_artifact() {
    let evidence = sample_instrumentation_overhead_evidence();
    evidence.validate().unwrap();
    assert_eq!(
        evidence
            .capture_config("instrumentation-overhead".to_owned())
            .unwrap(),
        CaptureInstrumentationConfig {
            method: "t32perf-c-wire/v1".to_owned(),
            transport: "shared-memory-ring-buffer/v1".to_owned(),
            overhead: CaptureInstrumentationOverhead {
                measurement_method: "controlled-paired-run/v1".to_owned(),
                baseline_duration_ns: 100_000,
                instrumented_duration_ns: 112_000,
                emitted_event_count: 1_000,
                evidence_artifact_id: "instrumentation-overhead".to_owned(),
            },
        }
    );

    let mut zero_events = evidence.clone();
    zero_events.emitted_event_count = 0;
    assert!(matches!(
        zero_events.validate(),
        Err(CaptureConfigValidationError::ZeroInstrumentationEventCount)
    ));

    let mut negative = evidence.clone();
    negative.instrumented_duration_ns = negative.baseline_duration_ns - 1;
    assert!(matches!(
        negative.validate(),
        Err(CaptureConfigValidationError::NegativeInstrumentationOverhead)
    ));

    let mut unknown = serde_json::to_value(&evidence).unwrap();
    unknown["future"] = json!(true);
    assert!(serde_json::from_value::<InstrumentationOverheadEvidenceDocument>(unknown).is_err());
    assert!(matches!(
        evidence.capture_config("../overhead".to_owned()),
        Err(CaptureConfigValidationError::InvalidArtifactId { .. })
    ));

    let schema = schema_documents()["instrumentation-overhead-evidence.schema.json"].clone();
    assert!(
        jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&serde_json::to_value(evidence).unwrap())
    );
}

fn config_identity(config: &CaptureConfigDocument) -> Vec<u8> {
    config
        .configuration_identity_bytes()
        .expect("serialize config identity")
}

#[test]
fn manifest_requires_acyclic_artifact_provenance() {
    let mut manifest = sample_manifest();
    manifest.artifacts[0].input_artifact_ids = vec!["observations".to_owned()];
    assert!(matches!(
        manifest.validate(),
        Err(ManifestValidationError::CyclicArtifactProvenance { .. })
    ));
}

#[test]
fn manifest_capture_receipt_facts_are_version_compatible_and_consistent() {
    let mut manifest = sample_manifest();
    manifest.capture.provider = Some("trace32".to_owned());
    manifest.capture.covered_cores = vec![0];
    let receipt = sample_capture_receipt();
    manifest.capture.capabilities = Some(receipt.capabilities);
    manifest.capture.capture_config = receipt.capture_config.clone();
    let config_claim = receipt.capture_config.expect("sample capture config claim");
    manifest.artifacts.push(Artifact {
        id: config_claim.artifact_id,
        kind: "capture_config".to_owned(),
        relative_path: ArtifactPath::new("capture/capture-config.json").unwrap(),
        media_type: "application/json".to_owned(),
        size_bytes: 1,
        sha256: config_claim.sha256,
        producer: "test".to_owned(),
        input_artifact_ids: Vec::new(),
    });
    assert!(manifest.validate().is_ok());

    manifest.capture.provider = None;
    assert!(matches!(
        manifest.validate(),
        Err(ManifestValidationError::InvalidMetadata {
            field: "capture",
            ..
        })
    ));

    manifest.capture.provider = Some("trace32".to_owned());
    manifest.capture.covered_cores = vec![1];
    assert!(matches!(
        manifest.validate(),
        Err(ManifestValidationError::InvalidMetadata {
            field: "capture.covered_cores",
            ..
        })
    ));

    let mut manifest = sample_manifest();
    manifest.clocks[0].frequency_hz = Some(0);
    assert!(matches!(
        manifest.validate(),
        Err(ManifestValidationError::InvalidMetadata {
            field: "clocks[].frequency_hz",
            ..
        })
    ));
    let encoded = serde_json::to_value(&manifest).unwrap();
    let schemas = schema_documents();
    let validator = jsonschema::validator_for(&schemas["manifest.schema.json"]).unwrap();
    assert!(!validator.is_valid(&encoded));
}

#[test]
fn manifest_instrumentation_requires_registered_config_owned_evidence() {
    let mut manifest = sample_manifest();
    let receipt = sample_capture_receipt();
    manifest.capture.provider = Some("trace32".to_owned());
    manifest.capture.capabilities = Some(receipt.capabilities);
    manifest.capture.capture_config = receipt.capture_config.clone();
    manifest.capture.instrumentation = sample_capture_config().instrumentation;
    let config_claim = receipt.capture_config.unwrap();
    manifest.artifacts.push(Artifact {
        id: "instrumentation-overhead".to_owned(),
        kind: "instrumentation_overhead".to_owned(),
        relative_path: ArtifactPath::new("capture/instrumentation-overhead.json").unwrap(),
        media_type: "application/json".to_owned(),
        size_bytes: 1,
        sha256: digest('7'),
        producer: "firmware-benchmark".to_owned(),
        input_artifact_ids: Vec::new(),
    });
    manifest.artifacts.push(Artifact {
        id: config_claim.artifact_id,
        kind: "capture_config".to_owned(),
        relative_path: ArtifactPath::new("capture/capture-config.json").unwrap(),
        media_type: "application/json".to_owned(),
        size_bytes: 1,
        sha256: config_claim.sha256,
        producer: "capture".to_owned(),
        input_artifact_ids: vec!["instrumentation-overhead".to_owned()],
    });
    assert!(manifest.validate().is_ok());

    manifest
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.id == "capture-config")
        .unwrap()
        .input_artifact_ids
        .clear();
    assert!(matches!(
        manifest.validate(),
        Err(ManifestValidationError::InvalidMetadata {
            field: "capture.instrumentation",
            ..
        })
    ));
}

#[test]
fn artifact_and_manifest_metadata_are_bounded_and_unambiguous() {
    let mut artifact = sample_manifest().artifacts.remove(0);
    artifact.kind = "x".repeat(257);
    assert!(matches!(
        artifact.validate(),
        Err(ArtifactValidationError::InvalidField {
            field: "artifact.kind",
            ..
        })
    ));

    artifact.kind = "raw_trace".to_owned();
    artifact.input_artifact_ids = vec!["input".to_owned(), "input".to_owned()];
    assert!(matches!(
        artifact.validate(),
        Err(ArtifactValidationError::DuplicateInput { .. })
    ));

    artifact.input_artifact_ids = (0..=MAX_ARTIFACT_INPUTS)
        .map(|index| format!("input-{index}"))
        .collect();
    assert!(matches!(
        artifact.validate(),
        Err(ArtifactValidationError::TooManyInputs { .. })
    ));

    assert!(matches!(
        ArtifactPath::new("x".repeat(MAX_ARTIFACT_PATH_BYTES + 1)),
        Err(ArtifactPathError::TooLong { .. })
    ));

    let mut manifest = sample_manifest();
    manifest.artifacts = vec![manifest.artifacts[0].clone(); MAX_MANIFEST_ARTIFACTS + 1];
    assert!(matches!(
        manifest.validate(),
        Err(ManifestValidationError::TooManyArtifacts { .. })
    ));

    let mut manifest = sample_manifest();
    manifest.stages[0].output_artifact_ids = vec!["raw".to_owned(), "raw".to_owned()];
    assert!(matches!(
        manifest.validate(),
        Err(ManifestValidationError::DuplicateStageArtifactReference { .. })
    ));

    let mut manifest = sample_manifest();
    manifest
        .capture
        .target
        .as_mut()
        .unwrap()
        .properties
        .insert("oversized".to_owned(), json!("x".repeat(16 * 1024 + 1)));
    assert!(matches!(
        manifest.validate(),
        Err(ManifestValidationError::InvalidMetadata { .. })
    ));
}

#[test]
fn comparison_cannot_bypass_health_gate() {
    let mut comparison = sample_comparison();
    comparison.candidate_health = HealthVerdict::Degraded;
    assert!(matches!(
        comparison.validate(),
        Err(ComparisonValidationError::HealthGateBypassed)
    ));
}

#[test]
fn resource_comparison_rows_validate_identity_policy_and_health_gating() {
    let semantic = CounterSemantic::new(CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES).unwrap();
    let metric = ResourceMetricComparison {
        semantic: semantic.clone(),
        subject: CounterSubject::Allocator {
            allocator_id: "system".to_owned(),
        },
        aggregate: ResourceComparisonAggregate::Latest,
        baseline_source: Some(ResourceMetricSource::Counter {
            counter_id: "heap.old".to_owned(),
        }),
        candidate_source: Some(ResourceMetricSource::Counter {
            counter_id: "heap.new".to_owned(),
        }),
        baseline_unit: Some("bytes".to_owned()),
        candidate_unit: Some("bytes".to_owned()),
        baseline_support: Some(MetricSupportLevel::Exact),
        candidate_support: Some(MetricSupportLevel::Exact),
        baseline: 100.0,
        candidate: 120.0,
        delta: 20.0,
        relative_change: Some(0.2),
        quality: Quality::Exact,
        direction: Some(ResourceComparisonDirection::LowerIsBetter),
        absolute_threshold: Some(0.0),
        relative_threshold: Some(0.05),
        outcome: ResourceMetricComparisonOutcome::Regressed,
        reasons: Vec::new(),
    };
    assert!(metric.validate().is_ok());

    let mut comparison = sample_comparison();
    comparison.resource_metrics.push(metric.clone());
    assert_roundtrip(&comparison);
    assert!(comparison.validate().is_ok());

    comparison.candidate_health = HealthVerdict::Degraded;
    comparison.verdict = ComparisonVerdict::Inconclusive;
    comparison.metrics.clear();
    assert!(matches!(
        comparison.validate(),
        Err(ComparisonValidationError::QuantitativeHealthGateBypassed)
    ));

    let mut malformed = metric;
    malformed.baseline_source = Some(ResourceMetricSource::Derived {
        source_counter_ids: vec!["z".to_owned(), "a".to_owned()],
    });
    assert!(matches!(
        malformed.validate(),
        Err(ComparisonValidationError::InvalidResourceDiagnostic { semantic: actual })
            if actual == semantic
    ));
}

#[test]
fn presentation_report_is_quantitative_and_valid_only() {
    let mut report = sample_report();
    assert!(report.validate().is_ok());
    report.health_verdict = HealthVerdict::Degraded;
    assert!(matches!(
        report.validate(),
        Err(AnalysisReportValidationError::NonvalidQuantitativeReport { .. })
    ));
}

#[test]
fn state_error_is_present_only_for_failed_state() {
    let mut state = sample_state();
    state.error = Some(SessionError {
        code: "capture_failed".to_owned(),
        message: "capture failed".to_owned(),
        details: Properties::new(),
    });
    assert_eq!(
        state.validate(),
        Err(SessionStateValidationError::UnexpectedError)
    );

    state.status = SessionStatus::Failed;
    assert!(state.validate().is_ok());
}

#[test]
fn completion_is_exclusive_to_the_finalize_contract() {
    assert!(!SessionStatus::Captured.can_transition_to(SessionStatus::Complete));
    assert!(!SessionStatus::Processing.can_transition_to(SessionStatus::Complete));
    assert!(!SessionStatus::Complete.can_transition_to(SessionStatus::Complete));
    assert!(SessionStatus::Captured.can_finalize());
    assert!(SessionStatus::Processing.can_finalize());
    assert!(SessionStatus::Complete.can_finalize());
    assert!(!SessionStatus::Failed.can_finalize());
}

#[test]
fn pc_hit_histogram_is_strict_roundtrips_and_enforces_accounting() {
    let histogram = sample_pc_hit_histogram();
    histogram.validate().unwrap();
    assert_roundtrip(&histogram);

    let schema = schema_documents()["pc-hit-histogram.schema.json"].clone();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let document = serde_json::to_value(&histogram).unwrap();
    assert!(validator.is_valid(&document));

    let mut zero_duration = document.clone();
    zero_duration["requested_duration_ns"] = json!(0);
    assert!(!validator.is_valid(&zero_duration));

    let mut zero_rate = document.clone();
    zero_rate["last_sample_rate_hz"] = json!(0);
    assert!(validator.is_valid(&zero_rate));

    let mut unknown = document.clone();
    unknown["future"] = json!(true);
    assert!(serde_json::from_value::<PcHitHistogram>(unknown).is_err());

    let mut wrong_schema = document;
    wrong_schema["schema"] = json!("t32perf.pc-hit-histogram/v2");
    assert!(serde_json::from_value::<PcHitHistogram>(wrong_schema).is_err());

    let mut overlapping = histogram.clone();
    overlapping.buckets[1].start_address = 0x100f;
    assert!(matches!(
        overlapping.validate(),
        Err(PcHitHistogramValidationError::UnsortedOrOverlappingBuckets { .. })
    ));

    let mut wrong_total = histogram.clone();
    wrong_total.in_scope_hits = 9;
    assert!(matches!(
        wrong_total.validate(),
        Err(PcHitHistogramValidationError::InScopeHitMismatch { .. })
    ));

    let mut wrong_method = histogram;
    wrong_method.intrusive = true;
    assert_eq!(
        wrong_method.validate(),
        Err(PcHitHistogramValidationError::IntrusiveMethodMismatch)
    );

    let mut stop_and_go = sample_pc_hit_histogram();
    stop_and_go.method = PcSamplingMethod::StopAndGo {
        configured_retained_runtime_percent: 99.0,
        observed_retained_runtime_percent: 98.5,
    };
    stop_and_go.intrusive = true;
    stop_and_go.last_sample_rate_hz = 0;
    assert!(stop_and_go.validate().is_ok());

    let mut unproved = sample_pc_hit_histogram();
    unproved.firmware.proof = None;
    assert_eq!(
        unproved.validate(),
        Err(PcHitHistogramValidationError::InvalidFirmwareBinding)
    );

    let mut deployment_asserted = sample_pc_hit_histogram();
    deployment_asserted.firmware.status = FirmwareBindingStatus::DeploymentAsserted;
    deployment_asserted.firmware.proof = Some(FirmwareBindingProof::PrecommittedElfAssertion {
        evidence_artifact_sha256: digest('d'),
    });
    deployment_asserted.validate().unwrap();

    let mut verified_precommitted = deployment_asserted.clone();
    verified_precommitted.firmware.status = FirmwareBindingStatus::Verified;
    assert_eq!(
        verified_precommitted.validate(),
        Err(PcHitHistogramValidationError::InvalidFirmwareBinding)
    );

    let mut mismatch = sample_pc_hit_histogram();
    mismatch.firmware.status = FirmwareBindingStatus::Mismatch;
    assert_eq!(
        mismatch.validate(),
        Err(PcHitHistogramValidationError::MismatchRequiresTargetComparison)
    );

    let mut unverified = sample_pc_hit_histogram();
    unverified.firmware.status = FirmwareBindingStatus::Unverified;
    assert_eq!(
        unverified.validate(),
        Err(PcHitHistogramValidationError::UnexpectedFirmwareProof)
    );

    let mut unclean = sample_pc_hit_histogram();
    unclean.cleanup_complete = false;
    assert_eq!(
        unclean.validate(),
        Err(PcHitHistogramValidationError::CleanupIncomplete)
    );
}

#[test]
fn debugger_symbolization_is_bounded_and_does_not_upgrade_firmware_binding() {
    let mut histogram = sample_pc_hit_histogram();
    histogram.firmware.status = FirmwareBindingStatus::Unverified;
    histogram.firmware.elf_sha256 = None;
    histogram.firmware.proof = None;
    let location = DebuggerHotspotLocation {
        bucket_start_address: 0x1000,
        bucket_end_address: 0x1010,
        hits: 6,
        dominant_start_address: 0x1004,
        dominant_end_address: 0x1008,
        dominant_hits: 5,
        function_name: Some("main".to_owned()),
        source_file: Some("main.c".to_owned()),
        source_line: Some(42),
    };
    histogram.debugger_symbolization = Some(DebuggerSymbolization {
        source: DebuggerSymbolizationSource::Trace32SymbolTable,
        trust: DebuggerSymbolizationTrust::DebuggerReported,
        refinement_granularity_bytes: 4,
        locations: vec![location.clone()],
    });
    histogram.validate().unwrap();
    assert_eq!(histogram.firmware.status, FirmwareBindingStatus::Unverified);

    let mut invalid_path = histogram.clone();
    invalid_path
        .debugger_symbolization
        .as_mut()
        .unwrap()
        .locations[0]
        .source_file = Some("src/main.c".to_owned());
    assert!(matches!(
        invalid_path.validate(),
        Err(PcHitHistogramValidationError::InvalidDebuggerLocationText { .. })
    ));

    let mut invalid_function_path = histogram.clone();
    invalid_function_path
        .debugger_symbolization
        .as_mut()
        .unwrap()
        .locations[0]
        .function_name = Some("namespace/main".to_owned());
    assert!(matches!(
        invalid_function_path.validate(),
        Err(PcHitHistogramValidationError::InvalidDebuggerLocationText { .. })
    ));

    let mut invalid_control = histogram.clone();
    invalid_control
        .debugger_symbolization
        .as_mut()
        .unwrap()
        .locations[0]
        .function_name = Some("main\n".to_owned());
    assert!(matches!(
        invalid_control.validate(),
        Err(PcHitHistogramValidationError::InvalidDebuggerLocationText { .. })
    ));

    let mut mismatched_bucket = histogram;
    mismatched_bucket
        .debugger_symbolization
        .as_mut()
        .unwrap()
        .locations[0]
        .hits = 5;
    assert_eq!(
        mismatched_bucket.validate(),
        Err(PcHitHistogramValidationError::DebuggerLocationHitMismatch)
    );
}

#[test]
fn heatmap_is_strict_statistical_and_rejects_duplicate_or_invalid_cells() {
    let heatmap = sample_heatmap();
    heatmap.validate().unwrap();
    assert_roundtrip(&heatmap);

    let schema = schema_documents()["heatmap.schema.json"].clone();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let document = serde_json::to_value(&heatmap).unwrap();
    assert!(validator.is_valid(&document));

    let mut unknown = document.clone();
    unknown["future"] = json!(true);
    assert!(serde_json::from_value::<Heatmap>(unknown).is_err());

    let mut non_statistical = document;
    non_statistical["quality"] = json!("exact");
    assert!(!validator.is_valid(&non_statistical));
    assert!(serde_json::from_value::<Heatmap>(non_statistical).is_err());

    let mut duplicate = heatmap.clone();
    duplicate.cells.push(duplicate.cells[0].clone());
    assert_eq!(
        duplicate.validate(),
        Err(HeatmapValidationError::DuplicateCellKey)
    );

    let mut mixed_projection = heatmap.clone();
    mixed_projection.cells[0].key = HeatmapCellKey::AddressRange {
        start_address: 0x1000,
        end_address: 0x1010,
    };
    assert_eq!(
        mixed_projection.validate(),
        Err(HeatmapValidationError::MixedProjectionKinds)
    );

    let mut wrong_denominator = heatmap;
    wrong_denominator.denominator_hits = 11;
    assert!(matches!(
        wrong_denominator.validate(),
        Err(HeatmapValidationError::DenominatorMismatch { .. })
    ));

    let mut missing_display_name = sample_heatmap();
    missing_display_name.cells[0].display_name.clear();
    assert_eq!(
        missing_display_name.validate(),
        Err(HeatmapValidationError::InvalidDisplayName)
    );
}

#[test]
fn heatmap_projections_bind_exactly_to_histogram_evidence() {
    let histogram = sample_pc_hit_histogram();
    let histogram_digest = digest('a');

    let address = Heatmap {
        schema: HeatmapSchemaVersion,
        session_id: histogram.session_id.clone(),
        histogram_sha256: histogram_digest.clone(),
        quality: HeatmapQuality::Statistical,
        projection_kind: HeatmapProjectionKind::AddressRange,
        quantitative_policy: QuantitativePolicy {
            min_in_scope_hits: 1,
            min_observed_duration_ns: 1,
            min_stop_and_go_retained_runtime_percent: 0.0,
            max_snoop_failures: 0,
        },
        denominator_hits: histogram.in_scope_hits,
        attributed_hits: histogram.in_scope_hits,
        unattributed_hits: 0,
        out_of_scope_hits: OutOfScopeHits::Known { hits: 3 },
        cells: histogram
            .buckets
            .iter()
            .map(|bucket| HeatmapCell {
                key: HeatmapCellKey::AddressRange {
                    start_address: bucket.start_address,
                    end_address: bucket.end_address,
                },
                display_name: format!("{:#x}..{:#x}", bucket.start_address, bucket.end_address),
                hits: bucket.hits,
                debugger_location: None,
            })
            .collect(),
    };
    address
        .validate_against(&histogram, histogram_digest.clone())
        .unwrap();

    let mut symbolized_histogram = histogram.clone();
    let debugger_location = DebuggerHotspotLocation {
        bucket_start_address: 0x1000,
        bucket_end_address: 0x1010,
        hits: 6,
        dominant_start_address: 0x1004,
        dominant_end_address: 0x1008,
        dominant_hits: 5,
        function_name: Some("main".to_owned()),
        source_file: Some("main.c".to_owned()),
        source_line: Some(42),
    };
    symbolized_histogram.debugger_symbolization = Some(DebuggerSymbolization {
        source: DebuggerSymbolizationSource::Trace32SymbolTable,
        trust: DebuggerSymbolizationTrust::DebuggerReported,
        refinement_granularity_bytes: 4,
        locations: vec![debugger_location.clone()],
    });
    let mut symbolized_address = address.clone();
    symbolized_address.cells[0].debugger_location = Some(debugger_location.clone());
    symbolized_address
        .validate_against(&symbolized_histogram, histogram_digest.clone())
        .unwrap();
    symbolized_address.cells[0]
        .debugger_location
        .as_mut()
        .unwrap()
        .function_name = Some("forged".to_owned());
    assert_eq!(
        symbolized_address.validate_against(&symbolized_histogram, histogram_digest.clone()),
        Err(HeatmapAgainstHistogramValidationError::DebuggerLocationMismatch)
    );

    let function = sample_heatmap();
    function
        .validate_against(&histogram, histogram_digest.clone())
        .unwrap();

    let source_line = Heatmap {
        projection_kind: HeatmapProjectionKind::SourceLine,
        cells: vec![HeatmapCell {
            key: HeatmapCellKey::SourceLine {
                source_path: "src/main.c".to_owned(),
                line: 42,
            },
            display_name: "src/main.c:42".to_owned(),
            hits: 8,
            debugger_location: None,
        }],
        ..function.clone()
    };
    source_line
        .validate_against(&histogram, histogram_digest.clone())
        .unwrap();

    let mut deployment_asserted_histogram = histogram.clone();
    deployment_asserted_histogram.firmware.status = FirmwareBindingStatus::DeploymentAsserted;
    deployment_asserted_histogram.firmware.proof =
        Some(FirmwareBindingProof::PrecommittedElfAssertion {
            evidence_artifact_sha256: digest('d'),
        });
    function
        .validate_against(&deployment_asserted_histogram, histogram_digest.clone())
        .unwrap();

    let mut missing_bucket = address;
    missing_bucket.cells.pop();
    missing_bucket.attributed_hits = 6;
    missing_bucket.unattributed_hits = 4;
    assert_eq!(
        missing_bucket.validate_against(&histogram, histogram_digest),
        Err(HeatmapAgainstHistogramValidationError::AddressCoverageMismatch)
    );

    let mut unverified_histogram = histogram;
    unverified_histogram.firmware.status = FirmwareBindingStatus::Unverified;
    unverified_histogram.firmware.proof = None;
    assert_eq!(
        function.validate_against(&unverified_histogram, digest('a')),
        Err(HeatmapAgainstHistogramValidationError::AttributedFirmwareBindingRequired)
    );
}

#[test]
fn firmware_binding_evidence_is_strict_and_result_bound_to_proof_kind() {
    let evidence = sample_firmware_binding_evidence();
    evidence.validate().unwrap();
    assert_roundtrip(&evidence);

    let schema = schema_documents()["firmware-binding-evidence.schema.json"].clone();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let document = serde_json::to_value(&evidence).unwrap();
    assert!(validator.is_valid(&document));

    let mut unknown = document;
    unknown["future"] = json!(true);
    assert!(serde_json::from_value::<FirmwareBindingEvidence>(unknown).is_err());

    let mut mismatch = evidence;
    mismatch.result = FirmwareBindingEvidenceResult::Mismatch;
    assert_eq!(
        mismatch.validate(),
        Err(FirmwareBindingEvidenceValidationError::MismatchRequiresTargetComparison)
    );

    let mut asserted = sample_firmware_binding_evidence();
    asserted.proof_kind = FirmwareBindingProofKind::PrecommittedElfAssertion;
    asserted.result = FirmwareBindingEvidenceResult::Asserted;
    asserted.validate().unwrap();

    let mut asserted_without_precommitted = asserted.clone();
    asserted_without_precommitted.proof_kind = FirmwareBindingProofKind::DigestBoundDeployment;
    assert_eq!(
        asserted_without_precommitted.validate(),
        Err(FirmwareBindingEvidenceValidationError::AssertedRequiresPrecommittedAssertion)
    );

    let mut verified_precommitted = asserted.clone();
    verified_precommitted.result = FirmwareBindingEvidenceResult::Verified;
    assert_eq!(
        verified_precommitted.validate(),
        Err(FirmwareBindingEvidenceValidationError::VerifiedRejectsPrecommittedAssertion)
    );
}

#[test]
fn quantitative_policy_cannot_be_bypassed_when_binding_heatmaps() {
    assert_eq!(
        QuantitativePolicy::default(),
        QuantitativePolicy {
            min_in_scope_hits: 100,
            min_observed_duration_ns: 100_000_000,
            min_stop_and_go_retained_runtime_percent: 90.0,
            max_snoop_failures: 0,
        }
    );

    let histogram = sample_pc_hit_histogram();
    let mut heatmap = sample_heatmap();
    heatmap.quantitative_policy = QuantitativePolicy::default();
    assert_eq!(
        heatmap.validate_against(&histogram, digest('a')),
        Err(HeatmapAgainstHistogramValidationError::InsufficientInScopeHits)
    );

    let mut zero_rate = histogram.clone();
    zero_rate.last_sample_rate_hz = 0;
    assert_eq!(
        sample_heatmap().validate_against(&zero_rate, digest('a')),
        Err(HeatmapAgainstHistogramValidationError::ZeroSampleRate)
    );

    let mut failed_snoop = histogram.clone();
    failed_snoop.snoop_failures = 1;
    assert_eq!(
        sample_heatmap().validate_against(&failed_snoop, digest('a')),
        Err(HeatmapAgainstHistogramValidationError::TooManySnoopFailures)
    );

    let mut stop_and_go = histogram;
    stop_and_go.method = PcSamplingMethod::StopAndGo {
        configured_retained_runtime_percent: 99.0,
        observed_retained_runtime_percent: 80.0,
    };
    stop_and_go.intrusive = true;
    let mut policy = sample_heatmap();
    policy
        .quantitative_policy
        .min_stop_and_go_retained_runtime_percent = 90.0;
    assert_eq!(
        policy.validate_against(&stop_and_go, digest('a')),
        Err(HeatmapAgainstHistogramValidationError::InsufficientRetainedRuntime)
    );
}

#[test]
fn sampling_control_plane_contracts_are_strict_and_receipts_require_complete_journals() {
    let binding = SamplingEndpointBinding {
        schema: SamplingEndpointBindingSchemaVersion,
        endpoint_fingerprint: digest('f'),
        endpoint_fingerprint_scheme: EndpointFingerprintScheme::T32PerfEndpointFingerprintV2,
    };
    binding.validate().unwrap();
    assert_roundtrip(&binding);

    let event = sample_sampling_driver_event();
    event.validate().unwrap();
    assert_roundtrip(&event);
    let event_schema = schema_documents()["sampling-driver-event.schema.json"].clone();
    let event_validator = jsonschema::validator_for(&event_schema).unwrap();
    let event_json = serde_json::to_value(&event).unwrap();
    assert!(event_validator.is_valid(&event_json));
    assert_eq!(event_json["event"], json!("configure_intent"));
    assert_eq!(event_json["details"]["method"], json!("realtime"));

    let mut bad_uuid = event.clone();
    bad_uuid.transaction_id = "123E4567-e89b-42d3-a456-426614174000".to_owned();
    assert_eq!(
        bad_uuid.validate(),
        Err(SamplingDriverEventValidationError::InvalidTransactionId)
    );
    let mut recovery_false = serde_json::to_value(&event).unwrap();
    recovery_false["event"] = json!("cleanup_intent");
    recovery_false["details"] = json!({"recovery": false});
    assert!(serde_json::from_value::<SamplingDriverEvent>(recovery_false).is_err());
    let export = SamplingDriverEvent {
        details: SamplingDriverEventDetails::ExportObserved {
            relative_path: ArtifactPath::new("capture/histogram.json").unwrap(),
            sha256: digest('a'),
            size_bytes: 1,
        },
        ..event
    };
    export.validate().unwrap();

    let receipt = sample_sampling_capture_receipt();
    receipt.validate().unwrap();
    assert_roundtrip(&receipt);
    let receipt_schema = schema_documents()["sampling-capture-receipt.schema.json"].clone();
    assert!(
        jsonschema::validator_for(&receipt_schema)
            .unwrap()
            .is_valid(&serde_json::to_value(&receipt).unwrap())
    );

    let mut wrong_order = receipt.clone();
    wrong_order.journal_event_claims.swap(0, 1);
    assert_eq!(
        wrong_order.validate(),
        Err(SamplingCaptureReceiptValidationError::InvalidSuccessfulEventOrder)
    );
    let mut duplicate_digest = receipt;
    duplicate_digest.journal_event_claims[1].sha256 =
        duplicate_digest.journal_event_claims[0].sha256.clone();
    assert_eq!(
        duplicate_digest.validate(),
        Err(SamplingCaptureReceiptValidationError::DuplicateJournalClaimDigest)
    );

    let mut invalid_operation = sample_sampling_capture_receipt();
    invalid_operation.session_operation_id = "0123456789ABCDEF0123456789ABCDEF".to_owned();
    assert_eq!(
        invalid_operation.validate(),
        Err(SamplingCaptureReceiptValidationError::InvalidSessionOperationId)
    );
}

#[test]
fn sampling_capture_request_expands_exact_bounded_half_open_buckets() {
    let request = sample_sampling_capture_request();
    request.validate().unwrap();
    assert_roundtrip(&request);
    assert_eq!(
        request.buckets().unwrap(),
        vec![
            SamplingAddressRange {
                start_address: 0x1000,
                end_address: 0x1010,
            },
            SamplingAddressRange {
                start_address: 0x1010,
                end_address: 0x1020,
            },
            SamplingAddressRange {
                start_address: 0x1020,
                end_address: 0x1024,
            },
        ]
    );

    let schema = schema_documents()["sampling-capture-request.schema.json"].clone();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let document = serde_json::to_value(&request).unwrap();
    assert!(validator.is_valid(&document));
    assert_eq!(document["address_space"], json!("P"));
    assert!(document.get("deployed_firmware_elf_sha256").is_none());

    let mut with_deployed_elf = request.clone();
    with_deployed_elf.deployed_firmware_elf_sha256 = Some(digest('f'));
    let document = serde_json::to_value(&with_deployed_elf).unwrap();
    assert!(validator.is_valid(&document));
    assert_eq!(
        document["deployed_firmware_elf_sha256"],
        json!("f".repeat(64))
    );

    let malformed = serde_json::json!({
        "schema": "t32perf.sampling-capture-request/v1",
        "ranges": [{"start_address": 4096, "end_address": 4128}],
        "bucket_size": 16,
        "duration_ms": 100,
        "method_policy": "realtime_only",
        "core_id": 0,
        "address_space": "P",
        "deployed_firmware_elf_sha256": "F".repeat(64),
    });
    assert!(!validator.is_valid(&malformed));

    let null_digest = serde_json::json!({
        "schema": "t32perf.sampling-capture-request/v1",
        "ranges": [{"start_address": 4096, "end_address": 4128}],
        "bucket_size": 16,
        "duration_ms": 100,
        "method_policy": "realtime_only",
        "core_id": 0,
        "address_space": "P",
        "deployed_firmware_elf_sha256": null,
    });
    assert!(!validator.is_valid(&null_digest));
    assert!(serde_json::from_value::<SamplingCaptureRequest>(null_digest).is_err());

    let mut overlapping = request.clone();
    overlapping.ranges.push(SamplingAddressRange {
        start_address: 0x1010,
        end_address: 0x1030,
    });
    assert_eq!(
        overlapping.validate(),
        Err(SamplingCaptureRequestValidationError::UnsortedOrOverlappingRanges)
    );

    let mut too_many = request;
    too_many.ranges[0].end_address = 0x3000;
    too_many.bucket_size = 1;
    assert_eq!(
        too_many.validate(),
        Err(SamplingCaptureRequestValidationError::TooManyBuckets)
    );
}

fn schemas_directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("schemas/v1")
}

#[test]
fn model_owned_checked_in_schemas_match_generated_documents() {
    let directory = schemas_directory();
    let update = std::env::var_os("T32PERF_UPDATE_SCHEMAS").is_some();
    if update {
        fs::create_dir_all(&directory).unwrap();
    }

    let documents = schema_documents();
    if update {
        for (filename, expected_value) in &documents {
            let expected_text = serde_json::to_string_pretty(expected_value).unwrap() + "\n";
            fs::write(directory.join(filename), expected_text).unwrap();
        }
    }
    for (filename, expected_value) in documents {
        let path = directory.join(filename);
        let expected_text = serde_json::to_string_pretty(&expected_value).unwrap() + "\n";
        let actual_text = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let actual_value: Value = serde_json::from_str(&actual_text).unwrap();
        assert_eq!(actual_value, expected_value, "schema drift in {filename}");
        if !matches!(
            filename,
            "normalize-config.schema.json" | "release-provenance.schema.json"
        ) {
            assert_eq!(actual_text, expected_text, "format drift in {filename}");
        }
    }
}
