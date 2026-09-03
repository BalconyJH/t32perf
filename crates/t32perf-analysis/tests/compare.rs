use t32perf_analysis::*;
use t32perf_model::*;

struct ComparedAnalysis {
    analysis: AnalysisResult,
    summary: AnalysisSummaryDocument,
}

impl std::ops::Deref for ComparedAnalysis {
    type Target = AnalysisResult;

    fn deref(&self) -> &Self::Target {
        &self.analysis
    }
}

impl std::ops::DerefMut for ComparedAnalysis {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.analysis
    }
}

fn observation(sequence: u64, event: ObservationEvent) -> Observation {
    Observation::new("test", sequence, Quality::Exact, event)
}

fn analyzed(session_id: &str, duration_ns: i64) -> ComparedAnalysis {
    let config = AnalyzerConfig {
        capabilities: AnalysisCapabilities::exact_program_flow(),
        ..AnalyzerConfig::default()
    };
    let mut analyzer = Analyzer::new(session_id, config);
    analyzer
        .ingest(&observation(
            1,
            ObservationEvent::FunctionEnter {
                ts_ns: 0,
                core_id: 0,
                context_id: "task".to_owned(),
                function_id: "work".to_owned(),
                frame_id: None,
            },
        ))
        .unwrap();
    analyzer
        .ingest(&observation(
            2,
            ObservationEvent::FunctionExit {
                ts_ns: duration_ns,
                core_id: 0,
                context_id: "task".to_owned(),
                function_id: "work".to_owned(),
                frame_id: None,
            },
        ))
        .unwrap();
    let analysis = analyzer.finish(None).unwrap();
    let summary = AnalysisSummaryDocument {
        schema: AnalysisSummarySchemaVersion,
        session_id: session_id.to_owned(),
        health_verdict: analysis.health.verdict,
        metric_support: analysis.health.metric_support.clone(),
        input_artifacts: Vec::new(),
        diagnostics: AnalysisDiagnosticCounts {
            observation_count: analysis.summary.observation_count,
            function_span_count: analysis.summary.function_span_count,
            incomplete_function_span_count: analysis.summary.incomplete_function_span_count,
            health_observation_count: analysis.health.observations.len() as u64,
            health_issue_count: analysis.health.issues.len() as u64,
        },
        quantitative: Some(AnalysisQuantitativeSummary {
            analysis: analysis.summary.clone(),
            static_ram: None,
            stack_usage: None,
        }),
    };
    ComparedAnalysis { analysis, summary }
}

fn manifest(session_id: &str, mode: &str) -> Manifest {
    Manifest {
        schema: ManifestSchemaVersion,
        session_id: session_id.to_owned(),
        created_at: "2026-08-23T08:00:00Z".to_owned(),
        tool: ToolInfo {
            name: "t32perf".to_owned(),
            version: "0.1.0".to_owned(),
            commit: None,
        },
        capture: CaptureInfo {
            provider: Some("trace32".to_owned()),
            mode: mode.to_owned(),
            adapter: AdapterInfo {
                id: "trace32".to_owned(),
                version: "1".to_owned(),
            },
            target: Some(TargetInfo {
                architecture: Some("armv8-m".to_owned()),
                device: Some("mcu".to_owned()),
                board: Some("board".to_owned()),
                core_count: Some(1),
                properties: Properties::new(),
            }),
            trace32: None,
            request_sha256: Some(Sha256Digest::new("a".repeat(64)).unwrap()),
            covered_cores: vec![0],
            capabilities: Some(program_flow_capabilities()),
            capture_config: Some(CaptureConfigArtifactClaim {
                artifact_id: "capture-config".to_owned(),
                sha256: Sha256Digest::new("f".repeat(64)).unwrap(),
                configuration_sha256: Sha256Digest::new("e".repeat(64)).unwrap(),
            }),
            instrumentation: None,
        },
        firmware: FirmwareInfo {
            elf_path: None,
            elf_sha256: None,
            build_id: Some("firmware-build-1".to_owned()),
        },
        clocks: vec![ClockInfo {
            id: "trace".to_owned(),
            frequency_hz: Some(100_000_000),
            source: None,
            properties: Properties::new(),
        }],
        stages: Vec::new(),
        artifacts: vec![Artifact {
            id: "capture-config".to_owned(),
            kind: "capture_config".to_owned(),
            relative_path: ArtifactPath::new("capture/capture-config.json").unwrap(),
            media_type: "application/json".to_owned(),
            size_bytes: 1,
            sha256: Sha256Digest::new("f".repeat(64)).unwrap(),
            producer: "test".to_owned(),
            input_artifact_ids: Vec::new(),
        }],
    }
}

fn program_flow_capabilities() -> CaptureCapabilities {
    let exact = MetricSupportEntry::new(MetricSupportLevel::Exact);
    CaptureCapabilities {
        function_events: exact.clone(),
        context_switches: exact.clone(),
        interrupt_events: exact.clone(),
        samples: MetricSupportEntry {
            support: MetricSupportLevel::Unavailable,
            reasons: vec!["samples_not_captured".to_owned()],
        },
        custom_events: exact.clone(),
        counters: exact,
    }
}

fn quantitative_mut(analysis: &mut ComparedAnalysis) -> &mut AnalysisQuantitativeSummary {
    analysis.summary.quantitative.as_mut().unwrap()
}

fn enable_resource_support(analysis: &mut ComparedAnalysis) {
    let support = MetricSupportEntry::new(MetricSupportLevel::Exact);
    analysis.health.metric_support.resource_counters = support.clone();
    analysis.summary.metric_support.resource_counters = support;
}

struct ResourceValues {
    first: f64,
    latest: f64,
    min: f64,
    max: f64,
    mean: f64,
    delta: Option<f64>,
    rate_per_second: Option<f64>,
}

fn resource_counter(
    counter_id: &str,
    semantic: &str,
    subject: CounterSubject,
    unit: &str,
    values: ResourceValues,
) -> ResourceCounterSummary {
    let ResourceValues {
        first,
        latest,
        min,
        max,
        mean,
        delta,
        rate_per_second,
    } = values;
    let semantic = CounterSemantic::new(semantic).unwrap();
    ResourceCounterSummary {
        counter_id: counter_id.to_owned(),
        name: None,
        unit: Some(unit.to_owned()),
        class: semantic
            .standard_spec()
            .map_or(ResourceClass::Other, |spec| spec.class),
        semantic: Some(semantic),
        subject: Some(subject),
        sample_count: 2,
        first_ts_ns: Some(0),
        last_ts_ns: Some(1_000_000_000),
        first: Some(first),
        latest,
        min,
        max,
        mean,
        delta,
        window_ns: Some(1_000_000_000),
        rate_per_second,
        quality: Quality::Exact,
        support: MetricSupportEntry::new(MetricSupportLevel::Exact),
    }
}

fn push_counter(analysis: &mut ComparedAnalysis, counter: ResourceCounterSummary) {
    enable_resource_support(analysis);
    quantitative_mut(analysis)
        .analysis
        .resources
        .counters
        .push(counter);
}

fn push_derived(
    analysis: &mut ComparedAnalysis,
    semantic: &str,
    subject: CounterSubject,
    unit: &str,
    value: f64,
    source_counter_ids: &[&str],
) {
    enable_resource_support(analysis);
    quantitative_mut(analysis)
        .analysis
        .resources
        .derived
        .push(DerivedResourceMetricSummary {
            semantic: CounterSemantic::new(semantic).unwrap(),
            subject,
            unit: unit.to_owned(),
            value: Some(value),
            source_counter_ids: source_counter_ids
                .iter()
                .map(|counter_id| (*counter_id).to_owned())
                .collect(),
            first_ts_ns: Some(0),
            last_ts_ns: Some(1_000_000_000),
            window_ns: Some(1_000_000_000),
            quality: Some(Quality::Exact),
            support: MetricSupportEntry::new(MetricSupportLevel::Exact),
        });
}

fn allocator(allocator_id: &str) -> CounterSubject {
    CounterSubject::Allocator {
        allocator_id: allocator_id.to_owned(),
    }
}

fn compare_analyses(
    baseline: &ComparedAnalysis,
    candidate: &ComparedAnalysis,
    policy: &ComparisonPolicy,
) -> ComparisonReport {
    let baseline_manifest = manifest(&baseline.summary.session_id, "etm");
    let candidate_manifest = manifest(&candidate.summary.session_id, "etm");
    compare_sessions(
        ComparisonInput {
            manifest: &baseline_manifest,
            health: &baseline.health,
            hotspots: &baseline.hotspots,
            summary: &baseline.summary,
        },
        ComparisonInput {
            manifest: &candidate_manifest,
            health: &candidate.health,
            hotspots: &candidate.hotspots,
            summary: &candidate.summary,
        },
        policy,
    )
}

fn static_ram_summary(
    digest_character: char,
    totals: StaticRamKindTotals,
) -> StaticRamAnalysisSummary {
    StaticRamAnalysisSummary {
        artifact_id: "static-ram".to_owned(),
        source_artifact_id: "linker-map".to_owned(),
        flavor: "gnu-ld-map/v1".to_owned(),
        config: Some(StaticRamConfigProvenance {
            artifact_id: None,
            sha256: Sha256Digest::new(digest_character.to_string().repeat(64)).unwrap(),
        }),
        total_bytes: totals.checked_total().unwrap(),
        totals,
        support: MetricSupportEntry::new(MetricSupportLevel::Exact),
    }
}

#[test]
fn comparison_detects_regression_after_comparability_checks() {
    let baseline_result = analyzed("baseline", 100);
    let candidate_result = analyzed("candidate", 120);
    let baseline_manifest = manifest("baseline", "etm");
    let candidate_manifest = manifest("candidate", "etm");

    let comparison = compare_sessions(
        ComparisonInput {
            manifest: &baseline_manifest,
            health: &baseline_result.health,
            hotspots: &baseline_result.hotspots,
            summary: &baseline_result.summary,
        },
        ComparisonInput {
            manifest: &candidate_manifest,
            health: &candidate_result.health,
            hotspots: &candidate_result.hotspots,
            summary: &candidate_result.summary,
        },
        &ComparisonPolicy::default(),
    );

    assert_eq!(
        comparison.verdict,
        ComparisonVerdict::Regressed,
        "comparison={comparison:#?}; baseline={:#?}; candidate={:#?}",
        baseline_result.hotspots,
        candidate_result.hotspots,
    );
    assert!(comparison.validate().is_ok());
    assert!(comparison.metrics.iter().any(|metric| {
        metric.metric == ComparisonMetricKind::SelfActiveNs
            && metric.outcome == MetricComparisonOutcome::Regressed
    }));
}

#[test]
fn complete_cross_build_provenance_is_comparable_by_default() {
    let baseline_result = analyzed("baseline", 100);
    let candidate_result = analyzed("candidate", 120);
    let baseline_manifest = manifest("baseline", "etm");
    let mut candidate_manifest = manifest("candidate", "etm");
    candidate_manifest.firmware.build_id = Some("firmware-build-2".to_owned());

    let comparison = compare_sessions(
        ComparisonInput {
            manifest: &baseline_manifest,
            health: &baseline_result.health,
            hotspots: &baseline_result.hotspots,
            summary: &baseline_result.summary,
        },
        ComparisonInput {
            manifest: &candidate_manifest,
            health: &candidate_result.health,
            hotspots: &candidate_result.hotspots,
            summary: &candidate_result.summary,
        },
        &ComparisonPolicy::default(),
    );
    assert_eq!(comparison.verdict, ComparisonVerdict::Regressed);
    assert!(!comparison.reasons.iter().any(|reason| {
        reason == "capture_firmware_mismatch" || reason == "capture_firmware_identity_incomplete"
    }));

    let strict_identity = ComparisonPolicy {
        require_same_firmware_identity: true,
        ..ComparisonPolicy::default()
    };
    let comparison = compare_sessions(
        ComparisonInput {
            manifest: &baseline_manifest,
            health: &baseline_result.health,
            hotspots: &baseline_result.hotspots,
            summary: &baseline_result.summary,
        },
        ComparisonInput {
            manifest: &candidate_manifest,
            health: &candidate_result.health,
            hotspots: &candidate_result.hotspots,
            summary: &candidate_result.summary,
        },
        &strict_identity,
    );
    assert_eq!(comparison.verdict, ComparisonVerdict::Inconclusive);
    assert!(
        comparison
            .reasons
            .contains(&"capture_firmware_mismatch".to_owned())
    );
}

#[test]
fn complete_provenance_and_same_firmware_are_independent_requirements() {
    let baseline_result = analyzed("baseline", 100);
    let candidate_result = analyzed("candidate", 100);
    let mut baseline_manifest = manifest("baseline", "etm");
    let mut candidate_manifest = manifest("candidate", "etm");
    baseline_manifest.firmware.build_id = None;
    candidate_manifest.firmware.build_id = None;

    let compare = |policy: &ComparisonPolicy| {
        compare_sessions(
            ComparisonInput {
                manifest: &baseline_manifest,
                health: &baseline_result.health,
                hotspots: &baseline_result.hotspots,
                summary: &baseline_result.summary,
            },
            ComparisonInput {
                manifest: &candidate_manifest,
                health: &candidate_result.health,
                hotspots: &candidate_result.hotspots,
                summary: &candidate_result.summary,
            },
            policy,
        )
    };

    let comparison = compare(&ComparisonPolicy::default());
    assert_eq!(comparison.verdict, ComparisonVerdict::Inconclusive);
    assert!(
        comparison
            .reasons
            .contains(&"capture_firmware_identity_incomplete".to_owned())
    );
    assert!(
        !comparison
            .reasons
            .contains(&"capture_firmware_mismatch".to_owned())
    );

    let provenance_optional = ComparisonPolicy {
        require_complete_provenance: false,
        ..ComparisonPolicy::default()
    };
    assert_eq!(
        compare(&provenance_optional).verdict,
        ComparisonVerdict::Unchanged
    );

    let same_identity_required = ComparisonPolicy {
        require_complete_provenance: false,
        require_same_firmware_identity: true,
        ..ComparisonPolicy::default()
    };
    let comparison = compare(&same_identity_required);
    assert_eq!(comparison.verdict, ComparisonVerdict::Inconclusive);
    assert!(
        comparison
            .reasons
            .contains(&"capture_firmware_mismatch".to_owned())
    );
}

#[test]
fn analyzer_policy_and_tool_contract_must_match_by_default() {
    let baseline_result = analyzed("baseline", 100);
    let mut candidate_result = analyzed("candidate", 100);
    let baseline_manifest = manifest("baseline", "etm");
    let mut candidate_manifest = manifest("candidate", "etm");
    candidate_result.health.policy_version = "t32perf.health-policy/v2".to_owned();
    candidate_manifest.tool.version = "0.2.0".to_owned();

    let compare = |policy: &ComparisonPolicy| {
        compare_sessions(
            ComparisonInput {
                manifest: &baseline_manifest,
                health: &baseline_result.health,
                hotspots: &baseline_result.hotspots,
                summary: &baseline_result.summary,
            },
            ComparisonInput {
                manifest: &candidate_manifest,
                health: &candidate_result.health,
                hotspots: &candidate_result.hotspots,
                summary: &candidate_result.summary,
            },
            policy,
        )
    };

    let comparison = compare(&ComparisonPolicy::default());
    assert_eq!(comparison.verdict, ComparisonVerdict::Inconclusive);
    assert!(
        comparison
            .reasons
            .contains(&"health_policy_version_mismatch".to_owned())
    );
    assert!(
        comparison
            .reasons
            .contains(&"tool_contract_mismatch".to_owned())
    );

    let explicitly_compatible = ComparisonPolicy {
        require_same_health_policy_version: false,
        require_same_tool_contract: false,
        ..ComparisonPolicy::default()
    };
    assert_eq!(
        compare(&explicitly_compatible).verdict,
        ComparisonVerdict::Unchanged
    );
}

#[test]
fn function_set_changes_are_inconclusive_unless_explicitly_compared() {
    let baseline_result = analyzed("baseline", 100);
    let mut candidate_result = analyzed("candidate", 100);
    let baseline_manifest = manifest("baseline", "etm");
    let candidate_manifest = manifest("candidate", "etm");
    let mut added = candidate_result.hotspots.functions[0].clone();
    added.function_id = "new_work".to_owned();
    candidate_result.hotspots.functions.push(added);

    let compare = |policy: &ComparisonPolicy| {
        compare_sessions(
            ComparisonInput {
                manifest: &baseline_manifest,
                health: &baseline_result.health,
                hotspots: &baseline_result.hotspots,
                summary: &baseline_result.summary,
            },
            ComparisonInput {
                manifest: &candidate_manifest,
                health: &candidate_result.health,
                hotspots: &candidate_result.hotspots,
                summary: &candidate_result.summary,
            },
            policy,
        )
    };

    let comparison = compare(&ComparisonPolicy::default());
    assert_eq!(comparison.verdict, ComparisonVerdict::Inconclusive);
    assert!(
        comparison
            .reasons
            .contains(&"function_set_differs".to_owned())
    );

    let compare_membership = ComparisonPolicy {
        allow_function_set_changes: true,
        ..ComparisonPolicy::default()
    };
    let comparison = compare(&compare_membership);
    assert_eq!(comparison.verdict, ComparisonVerdict::Regressed);
    assert!(comparison.metrics.iter().any(|metric| {
        metric.subject.id == "new_work"
            && metric.metric == ComparisonMetricKind::Count
            && metric.baseline == 0.0
            && metric.candidate == 1.0
            && metric.outcome == MetricComparisonOutcome::Regressed
            && metric.reasons == ["function_added"]
    }));

    let mut removed_candidate = analyzed("candidate", 100);
    removed_candidate.hotspots.functions.clear();
    let comparison = compare_sessions(
        ComparisonInput {
            manifest: &baseline_manifest,
            health: &baseline_result.health,
            hotspots: &baseline_result.hotspots,
            summary: &baseline_result.summary,
        },
        ComparisonInput {
            manifest: &candidate_manifest,
            health: &removed_candidate.health,
            hotspots: &removed_candidate.hotspots,
            summary: &removed_candidate.summary,
        },
        &compare_membership,
    );
    assert_eq!(comparison.verdict, ComparisonVerdict::Improved);
    assert!(comparison.metrics.iter().any(|metric| {
        metric.subject.id == "work"
            && metric.metric == ComparisonMetricKind::Count
            && metric.baseline == 1.0
            && metric.candidate == 0.0
            && metric.outcome == MetricComparisonOutcome::Improved
            && metric.reasons == ["function_removed"]
    }));
}

#[test]
fn unhealthy_or_capture_mismatched_inputs_are_inconclusive() {
    let baseline_result = analyzed("baseline", 100);
    let mut candidate_result = analyzed("candidate", 120);
    let baseline_manifest = manifest("baseline", "etm");
    let candidate_manifest = manifest("candidate", "sampling");
    candidate_result.health.verdict = HealthVerdict::Degraded;

    let comparison = compare_sessions(
        ComparisonInput {
            manifest: &baseline_manifest,
            health: &baseline_result.health,
            hotspots: &baseline_result.hotspots,
            summary: &baseline_result.summary,
        },
        ComparisonInput {
            manifest: &candidate_manifest,
            health: &candidate_result.health,
            hotspots: &candidate_result.hotspots,
            summary: &candidate_result.summary,
        },
        &ComparisonPolicy::default(),
    );

    assert_eq!(comparison.verdict, ComparisonVerdict::Inconclusive);
    assert!(comparison.metrics.is_empty());
    assert!(
        comparison
            .reasons
            .iter()
            .any(|reason| reason == "candidate_health_not_valid")
    );
    assert!(
        comparison
            .reasons
            .iter()
            .any(|reason| reason == "capture_mode_mismatch")
    );
}

#[test]
fn incompatible_metric_support_prevents_regression_judgment() {
    let baseline_result = analyzed("baseline", 100);
    let mut candidate_result = analyzed("candidate", 120);
    candidate_result.health.metric_support.active = MetricSupportEntry {
        support: MetricSupportLevel::Inferred,
        reasons: vec!["context_switches_unavailable".to_owned()],
    };
    candidate_result.health.metric_support.self_time = MetricSupportEntry {
        support: MetricSupportLevel::Inferred,
        reasons: vec!["context_switches_unavailable".to_owned()],
    };
    let baseline_manifest = manifest("baseline", "etm");
    let candidate_manifest = manifest("candidate", "etm");

    let comparison = compare_sessions(
        ComparisonInput {
            manifest: &baseline_manifest,
            health: &baseline_result.health,
            hotspots: &baseline_result.hotspots,
            summary: &baseline_result.summary,
        },
        ComparisonInput {
            manifest: &candidate_manifest,
            health: &candidate_result.health,
            hotspots: &candidate_result.hotspots,
            summary: &candidate_result.summary,
        },
        &ComparisonPolicy::default(),
    );

    assert_eq!(comparison.verdict, ComparisonVerdict::Inconclusive);
    assert!(
        comparison
            .reasons
            .iter()
            .any(|reason| reason == "metric_support_mismatch:active")
    );
}

#[test]
fn strict_provenance_rejects_present_but_incomplete_capture_identity() {
    let baseline_result = analyzed("baseline", 100);
    let candidate_result = analyzed("candidate", 100);
    let compare =
        |baseline_manifest: &Manifest, candidate_manifest: &Manifest, policy: &ComparisonPolicy| {
            compare_sessions(
                ComparisonInput {
                    manifest: baseline_manifest,
                    health: &baseline_result.health,
                    hotspots: &baseline_result.hotspots,
                    summary: &baseline_result.summary,
                },
                ComparisonInput {
                    manifest: candidate_manifest,
                    health: &candidate_result.health,
                    hotspots: &candidate_result.hotspots,
                    summary: &candidate_result.summary,
                },
                policy,
            )
        };

    let mut baseline_manifest = manifest("baseline", "etm");
    let mut candidate_manifest = manifest("candidate", "etm");
    baseline_manifest.capture.target = Some(TargetInfo {
        architecture: None,
        device: None,
        board: None,
        core_count: None,
        properties: Properties::new(),
    });
    candidate_manifest.capture.target = baseline_manifest.capture.target.clone();
    let comparison = compare(
        &baseline_manifest,
        &candidate_manifest,
        &ComparisonPolicy::default(),
    );
    assert!(
        comparison
            .reasons
            .contains(&"capture_target_mismatch".to_owned())
    );

    let mut baseline_manifest = manifest("baseline", "etm");
    let mut candidate_manifest = manifest("candidate", "etm");
    baseline_manifest.clocks[0].frequency_hz = None;
    candidate_manifest.clocks[0].frequency_hz = None;
    let comparison = compare(
        &baseline_manifest,
        &candidate_manifest,
        &ComparisonPolicy::default(),
    );
    assert!(
        comparison
            .reasons
            .contains(&"capture_clock_mismatch".to_owned())
    );

    let mut baseline_manifest = manifest("baseline", "etm");
    let mut candidate_manifest = manifest("candidate", "etm");
    baseline_manifest.clocks[0].frequency_hz = Some(0);
    candidate_manifest.clocks[0].frequency_hz = Some(0);
    let comparison = compare(
        &baseline_manifest,
        &candidate_manifest,
        &ComparisonPolicy::default(),
    );
    assert!(
        comparison
            .reasons
            .contains(&"capture_clock_mismatch".to_owned())
    );

    let mut baseline_manifest = manifest("baseline", "etm");
    let mut candidate_manifest = manifest("candidate", "etm");
    baseline_manifest.capture.request_sha256 = None;
    candidate_manifest.capture.request_sha256 = None;
    let policy = ComparisonPolicy {
        require_matching_request: false,
        ..ComparisonPolicy::default()
    };
    let comparison = compare(&baseline_manifest, &candidate_manifest, &policy);
    assert!(
        comparison
            .reasons
            .contains(&"capture_request_mismatch".to_owned())
    );

    let mut baseline_manifest = manifest("baseline", "etm");
    let mut candidate_manifest = manifest("candidate", "etm");
    let trace32 = Trace32Info {
        build: None,
        probe: Some("probe".to_owned()),
        architecture_package: Some("ARM".to_owned()),
        properties: Properties::new(),
    };
    baseline_manifest.capture.trace32 = Some(trace32.clone());
    candidate_manifest.capture.trace32 = Some(trace32);
    let comparison = compare(
        &baseline_manifest,
        &candidate_manifest,
        &ComparisonPolicy::default(),
    );
    assert!(
        comparison
            .reasons
            .contains(&"capture_trace32_mismatch".to_owned())
    );
}

#[test]
fn strict_provenance_requires_matching_receipt_provider_cores_and_capabilities() {
    let baseline_result = analyzed("baseline", 100);
    let candidate_result = analyzed("candidate", 100);
    let compare = |baseline_manifest: &Manifest, candidate_manifest: &Manifest| {
        compare_sessions(
            ComparisonInput {
                manifest: baseline_manifest,
                health: &baseline_result.health,
                hotspots: &baseline_result.hotspots,
                summary: &baseline_result.summary,
            },
            ComparisonInput {
                manifest: candidate_manifest,
                health: &candidate_result.health,
                hotspots: &candidate_result.hotspots,
                summary: &candidate_result.summary,
            },
            &ComparisonPolicy::default(),
        )
    };

    let mut baseline = manifest("baseline", "etm");
    let mut candidate = manifest("candidate", "etm");
    baseline.capture.provider = None;
    baseline.capture.capabilities = None;
    candidate.capture.provider = None;
    candidate.capture.capabilities = None;
    let comparison = compare(&baseline, &candidate);
    assert!(
        comparison
            .reasons
            .contains(&"capture_provider_incomplete".to_owned())
    );
    assert!(
        comparison
            .reasons
            .contains(&"capture_capabilities_incomplete".to_owned())
    );

    let baseline = manifest("baseline", "etm");
    let mut candidate = manifest("candidate", "etm");
    candidate.capture.provider = Some("other-provider".to_owned());
    let comparison = compare(&baseline, &candidate);
    assert!(
        comparison
            .reasons
            .contains(&"capture_provider_mismatch".to_owned())
    );

    let mut baseline = manifest("baseline", "etm");
    let mut candidate = manifest("candidate", "etm");
    baseline.capture.covered_cores.clear();
    candidate.capture.covered_cores.clear();
    let comparison = compare(&baseline, &candidate);
    assert!(
        comparison
            .reasons
            .contains(&"capture_core_coverage_incomplete".to_owned())
    );

    let mut baseline = manifest("baseline", "etm");
    let mut candidate = manifest("candidate", "etm");
    baseline.capture.target.as_mut().unwrap().core_count = Some(2);
    candidate.capture.target.as_mut().unwrap().core_count = Some(2);
    candidate.capture.covered_cores = vec![1];
    let comparison = compare(&baseline, &candidate);
    assert!(
        comparison
            .reasons
            .contains(&"capture_core_coverage_mismatch".to_owned())
    );

    let baseline = manifest("baseline", "etm");
    let mut candidate = manifest("candidate", "etm");
    candidate
        .capture
        .capabilities
        .as_mut()
        .unwrap()
        .samples
        .reasons = vec!["different_sampling_contract".to_owned()];
    let comparison = compare(&baseline, &candidate);
    assert!(
        comparison
            .reasons
            .contains(&"capture_capabilities_mismatch".to_owned())
    );

    let mut baseline = manifest("baseline", "etm");
    let mut candidate = manifest("candidate", "etm");
    baseline.capture.capture_config = None;
    candidate.capture.capture_config = None;
    let comparison = compare(&baseline, &candidate);
    assert!(
        comparison
            .reasons
            .contains(&"capture_config_incomplete".to_owned())
    );

    let baseline = manifest("baseline", "etm");
    let mut candidate = manifest("candidate", "etm");
    candidate
        .capture
        .capture_config
        .as_mut()
        .unwrap()
        .configuration_sha256 = Sha256Digest::new("d".repeat(64)).unwrap();
    let comparison = compare(&baseline, &candidate);
    assert!(
        comparison
            .reasons
            .contains(&"capture_config_digest_mismatch".to_owned())
    );
}

#[test]
fn malicious_health_artifacts_cannot_claim_valid() {
    let mut baseline_result = analyzed("baseline", 100);
    let candidate_result = analyzed("candidate", 100);
    let baseline_manifest = manifest("baseline", "etm");
    let candidate_manifest = manifest("candidate", "etm");

    baseline_result.health.issues.push(HealthIssue {
        code: "hidden_warning".to_owned(),
        severity: HealthSeverity::Warning,
        source: "malicious".to_owned(),
        artifact_id: None,
        record: None,
        start_ns: None,
        end_ns: None,
        evidence: Properties::new(),
        message: "warning hidden behind VALID".to_owned(),
    });
    let comparison = compare_sessions(
        ComparisonInput {
            manifest: &baseline_manifest,
            health: &baseline_result.health,
            hotspots: &baseline_result.hotspots,
            summary: &baseline_result.summary,
        },
        ComparisonInput {
            manifest: &candidate_manifest,
            health: &candidate_result.health,
            hotspots: &candidate_result.hotspots,
            summary: &candidate_result.summary,
        },
        &ComparisonPolicy::default(),
    );
    assert!(
        comparison
            .reasons
            .contains(&"baseline_health_invalid".to_owned())
    );

    baseline_result.health.issues.clear();
    baseline_result.health.observations.push(HealthObservation {
        code: String::new(),
        source: String::new(),
        artifact_id: None,
        record: None,
        start_ns: None,
        end_ns: None,
        evidence: Properties::new(),
    });
    let comparison = compare_sessions(
        ComparisonInput {
            manifest: &baseline_manifest,
            health: &baseline_result.health,
            hotspots: &baseline_result.hotspots,
            summary: &baseline_result.summary,
        },
        ComparisonInput {
            manifest: &candidate_manifest,
            health: &candidate_result.health,
            hotspots: &candidate_result.hotspots,
            summary: &candidate_result.summary,
        },
        &ComparisonPolicy::default(),
    );
    assert!(
        comparison
            .reasons
            .contains(&"baseline_health_invalid".to_owned())
    );
}

#[test]
fn resource_identity_ignores_counter_dictionary_renames() {
    let mut baseline = analyzed("baseline", 100);
    let mut candidate = analyzed("candidate", 100);
    let subject = allocator("system");
    push_counter(
        &mut baseline,
        resource_counter(
            "heap.used.old",
            CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES,
            subject.clone(),
            "bytes",
            ResourceValues {
                first: 80.0,
                latest: 100.0,
                min: 80.0,
                max: 100.0,
                mean: 90.0,
                delta: Some(20.0),
                rate_per_second: None,
            },
        ),
    );
    push_counter(
        &mut candidate,
        resource_counter(
            "heap.used.new",
            CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES,
            subject,
            "bytes",
            ResourceValues {
                first: 90.0,
                latest: 120.0,
                min: 90.0,
                max: 120.0,
                mean: 105.0,
                delta: Some(30.0),
                rate_per_second: None,
            },
        ),
    );

    let comparison = compare_analyses(&baseline, &candidate, &ComparisonPolicy::default());

    assert_eq!(comparison.verdict, ComparisonVerdict::Regressed);
    assert!(comparison.validate().is_ok());
    let metric = comparison
        .resource_metrics
        .iter()
        .find(|metric| metric.semantic.as_str() == CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES)
        .unwrap();
    assert_eq!(metric.outcome, ResourceMetricComparisonOutcome::Regressed);
    assert_eq!(
        metric.baseline_source,
        Some(ResourceMetricSource::Counter {
            counter_id: "heap.used.old".to_owned(),
        })
    );
    assert_eq!(
        metric.candidate_source,
        Some(ResourceMetricSource::Counter {
            counter_id: "heap.used.new".to_owned(),
        })
    );
}

#[test]
fn unconfigured_count_and_derived_rate_are_informational() {
    let mut baseline = analyzed("baseline", 100);
    let mut candidate = analyzed("candidate", 100);
    let subject = allocator("system");
    for (analysis, counter_id, count, rate) in [
        (&mut baseline, "allocations.old", 10.0, 10.0),
        (&mut candidate, "allocations.new", 20.0, 20.0),
    ] {
        push_counter(
            analysis,
            resource_counter(
                counter_id,
                CounterSemantic::HEAP_ALLOCATION_COUNT,
                subject.clone(),
                "count",
                ResourceValues {
                    first: 0.0,
                    latest: count,
                    min: 0.0,
                    max: count,
                    mean: count / 2.0,
                    delta: Some(count),
                    rate_per_second: Some(rate),
                },
            ),
        );
        push_derived(
            analysis,
            CounterSemantic::HEAP_ALLOCATION_RATE_PER_SECOND,
            subject.clone(),
            "1/s",
            rate,
            &[counter_id],
        );
    }

    let comparison = compare_analyses(&baseline, &candidate, &ComparisonPolicy::default());
    assert_eq!(comparison.verdict, ComparisonVerdict::Unchanged);
    assert!(comparison.resource_metrics.iter().any(|metric| {
        metric.semantic.as_str() == CounterSemantic::HEAP_ALLOCATION_COUNT
            && metric.outcome == ResourceMetricComparisonOutcome::Informational
    }));
    assert!(comparison.resource_metrics.iter().any(|metric| {
        metric.semantic.as_str() == CounterSemantic::HEAP_ALLOCATION_RATE_PER_SECOND
            && metric.outcome == ResourceMetricComparisonOutcome::Informational
            && matches!(
                metric.baseline_source,
                Some(ResourceMetricSource::Derived { .. })
            )
    }));

    let policy = ComparisonPolicy {
        resource_rules: vec![ResourceComparisonRule {
            semantic: CounterSemantic::new(CounterSemantic::HEAP_ALLOCATION_RATE_PER_SECOND)
                .unwrap(),
            subject: None,
            aggregate: ResourceComparisonAggregate::RatePerSecond,
            direction: ResourceComparisonDirection::LowerIsBetter,
            absolute_threshold: 0.0,
            relative_threshold: 0.05,
        }],
        ..ComparisonPolicy::default()
    };
    let comparison = compare_analyses(&baseline, &candidate, &policy);
    assert_eq!(comparison.verdict, ComparisonVerdict::Regressed);
    assert!(comparison.resource_metrics.iter().any(|metric| {
        metric.semantic.as_str() == CounterSemantic::HEAP_ALLOCATION_RATE_PER_SECOND
            && metric.aggregate == ResourceComparisonAggregate::RatePerSecond
            && metric.outcome == ResourceMetricComparisonOutcome::Regressed
    }));
}

#[test]
fn default_fragmentation_rule_consumes_derived_evidence() {
    let mut baseline = analyzed("baseline", 100);
    let mut candidate = analyzed("candidate", 100);
    let subject = allocator("system");
    for (analysis, suffix, fragmentation) in [
        (&mut baseline, "baseline", 0.10),
        (&mut candidate, "candidate", 0.20),
    ] {
        let free_id = format!("heap.free.{suffix}");
        let largest_id = format!("heap.largest.{suffix}");
        push_counter(
            analysis,
            resource_counter(
                &free_id,
                CounterSemantic::HEAP_FREE_BYTES,
                subject.clone(),
                "bytes",
                ResourceValues {
                    first: 1000.0,
                    latest: 1000.0,
                    min: 1000.0,
                    max: 1000.0,
                    mean: 1000.0,
                    delta: Some(0.0),
                    rate_per_second: None,
                },
            ),
        );
        push_counter(
            analysis,
            resource_counter(
                &largest_id,
                CounterSemantic::HEAP_LARGEST_FREE_BLOCK_BYTES,
                subject.clone(),
                "bytes",
                ResourceValues {
                    first: 900.0,
                    latest: 900.0,
                    min: 900.0,
                    max: 900.0,
                    mean: 900.0,
                    delta: Some(0.0),
                    rate_per_second: None,
                },
            ),
        );
        let mut source_ids = [free_id.as_str(), largest_id.as_str()];
        source_ids.sort_unstable();
        push_derived(
            analysis,
            CounterSemantic::HEAP_EXTERNAL_FRAGMENTATION_RATIO,
            subject.clone(),
            "ratio",
            fragmentation,
            &source_ids,
        );
    }

    let comparison = compare_analyses(&baseline, &candidate, &ComparisonPolicy::default());
    assert_eq!(comparison.verdict, ComparisonVerdict::Regressed);
    let metric = comparison
        .resource_metrics
        .iter()
        .find(|metric| {
            metric.semantic.as_str() == CounterSemantic::HEAP_EXTERNAL_FRAGMENTATION_RATIO
        })
        .unwrap();
    assert_eq!(metric.aggregate, ResourceComparisonAggregate::Latest);
    assert_eq!(metric.outcome, ResourceMetricComparisonOutcome::Regressed);
    assert!(matches!(
        metric.baseline_source,
        Some(ResourceMetricSource::Derived { .. })
    ));
}

#[test]
fn configured_resource_membership_and_counter_id_reuse_are_strict() {
    let mut baseline = analyzed("baseline", 100);
    let mut candidate = analyzed("candidate", 100);
    push_counter(
        &mut baseline,
        resource_counter(
            "heap.shared",
            CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES,
            allocator("a"),
            "bytes",
            ResourceValues {
                first: 100.0,
                latest: 100.0,
                min: 100.0,
                max: 100.0,
                mean: 100.0,
                delta: Some(0.0),
                rate_per_second: None,
            },
        ),
    );
    push_counter(
        &mut candidate,
        resource_counter(
            "heap.candidate",
            CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES,
            allocator("b"),
            "bytes",
            ResourceValues {
                first: 100.0,
                latest: 100.0,
                min: 100.0,
                max: 100.0,
                mean: 100.0,
                delta: Some(0.0),
                rate_per_second: None,
            },
        ),
    );

    let comparison = compare_analyses(&baseline, &candidate, &ComparisonPolicy::default());
    assert_eq!(comparison.verdict, ComparisonVerdict::Inconclusive);
    assert!(
        comparison
            .reasons
            .iter()
            .any(|reason| reason.starts_with("resource_subject_set_differs:"))
    );

    let allow_membership = ComparisonPolicy {
        allow_resource_subject_set_changes: true,
        ..ComparisonPolicy::default()
    };
    let comparison = compare_analyses(&baseline, &candidate, &allow_membership);
    assert_eq!(comparison.verdict, ComparisonVerdict::Regressed);
    assert_eq!(
        comparison
            .resource_metrics
            .iter()
            .filter(|metric| {
                metric.semantic.as_str() == CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES
            })
            .count(),
        2
    );

    quantitative_mut(&mut candidate).analysis.resources.counters[0].counter_id =
        "heap.shared".to_owned();
    let comparison = compare_analyses(&baseline, &candidate, &allow_membership);
    assert_eq!(comparison.verdict, ComparisonVerdict::Inconclusive);
    assert!(
        comparison
            .reasons
            .contains(&"resource_counter_identity_mismatch:heap.shared".to_owned())
    );
    assert!(comparison.resource_metrics.is_empty());
}

#[test]
fn configured_resource_unit_and_support_mismatches_are_inconclusive() {
    let mut baseline = analyzed("baseline", 100);
    let mut candidate = analyzed("candidate", 100);
    let subject = allocator("system");
    for (analysis, unit) in [(&mut baseline, "bytes"), (&mut candidate, "items")] {
        push_counter(
            analysis,
            resource_counter(
                "heap.used",
                "custom.memory_pressure",
                subject.clone(),
                unit,
                ResourceValues {
                    first: 100.0,
                    latest: 100.0,
                    min: 100.0,
                    max: 100.0,
                    mean: 100.0,
                    delta: Some(0.0),
                    rate_per_second: None,
                },
            ),
        );
    }

    let policy = ComparisonPolicy {
        resource_rules: vec![ResourceComparisonRule {
            semantic: CounterSemantic::new("custom.memory_pressure").unwrap(),
            subject: Some(subject),
            aggregate: ResourceComparisonAggregate::Latest,
            direction: ResourceComparisonDirection::LowerIsBetter,
            absolute_threshold: 0.0,
            relative_threshold: 0.05,
        }],
        ..ComparisonPolicy::default()
    };

    let comparison = compare_analyses(&baseline, &candidate, &policy);
    assert_eq!(comparison.verdict, ComparisonVerdict::Inconclusive);
    assert!(
        comparison
            .reasons
            .iter()
            .any(|reason| reason.starts_with("resource_unit_mismatch:")),
        "{comparison:#?}"
    );
    assert_eq!(
        comparison.resource_metrics[0].outcome,
        ResourceMetricComparisonOutcome::Inconclusive
    );

    quantitative_mut(&mut candidate).analysis.resources.counters[0].unit = Some("bytes".to_owned());
    quantitative_mut(&mut candidate).analysis.resources.counters[0].support = MetricSupportEntry {
        support: MetricSupportLevel::Inferred,
        reasons: vec!["inferred_resource".to_owned()],
    };
    let comparison = compare_analyses(&baseline, &candidate, &policy);
    assert_eq!(comparison.verdict, ComparisonVerdict::Inconclusive);
    assert!(
        comparison
            .reasons
            .iter()
            .any(|reason| reason.starts_with("resource_support_mismatch:"))
    );
}

#[test]
fn explicit_direction_and_thresholds_control_resource_outcomes() {
    let mut baseline = analyzed("baseline", 100);
    let mut candidate = analyzed("candidate", 100);
    let subject = allocator("system");
    for (analysis, latest) in [(&mut baseline, 100.0), (&mut candidate, 105.0)] {
        push_counter(
            analysis,
            resource_counter(
                "heap.free",
                CounterSemantic::HEAP_FREE_BYTES,
                subject.clone(),
                "bytes",
                ResourceValues {
                    first: latest,
                    latest,
                    min: latest,
                    max: latest,
                    mean: latest,
                    delta: Some(0.0),
                    rate_per_second: None,
                },
            ),
        );
    }
    let policy = ComparisonPolicy {
        resource_rules: vec![ResourceComparisonRule {
            semantic: CounterSemantic::new(CounterSemantic::HEAP_FREE_BYTES).unwrap(),
            subject: Some(subject),
            aggregate: ResourceComparisonAggregate::Latest,
            direction: ResourceComparisonDirection::HigherIsBetter,
            absolute_threshold: 0.0,
            relative_threshold: 0.05,
        }],
        ..ComparisonPolicy::default()
    };

    let comparison = compare_analyses(&baseline, &candidate, &policy);
    assert_eq!(comparison.verdict, ComparisonVerdict::Unchanged);
    quantitative_mut(&mut candidate).analysis.resources.counters[0].latest = 106.0;
    quantitative_mut(&mut candidate).analysis.resources.counters[0].min = 106.0;
    quantitative_mut(&mut candidate).analysis.resources.counters[0].max = 106.0;
    quantitative_mut(&mut candidate).analysis.resources.counters[0].mean = 106.0;
    let comparison = compare_analyses(&baseline, &candidate, &policy);
    assert_eq!(comparison.verdict, ComparisonVerdict::Improved);
}

#[test]
fn static_ram_requires_matching_config_and_compares_every_kind() {
    let mut baseline = analyzed("baseline", 100);
    let mut candidate = analyzed("candidate", 100);
    quantitative_mut(&mut baseline).static_ram = Some(static_ram_summary(
        'a',
        StaticRamKindTotals {
            data_bytes: 100,
            bss_bytes: 100,
            ..StaticRamKindTotals::default()
        },
    ));
    quantitative_mut(&mut candidate).static_ram = Some(static_ram_summary(
        'a',
        StaticRamKindTotals {
            data_bytes: 110,
            bss_bytes: 90,
            ..StaticRamKindTotals::default()
        },
    ));

    let comparison = compare_analyses(&baseline, &candidate, &ComparisonPolicy::default());
    assert_eq!(comparison.verdict, ComparisonVerdict::Regressed);
    assert_eq!(comparison.static_ram_metrics.len(), 7);
    assert!(comparison.static_ram_metrics.iter().any(|metric| {
        metric.metric == StaticRamMetricKind::Data
            && metric.outcome == MetricComparisonOutcome::Regressed
    }));
    assert!(comparison.static_ram_metrics.iter().any(|metric| {
        metric.metric == StaticRamMetricKind::Bss
            && metric.outcome == MetricComparisonOutcome::Improved
    }));
    assert!(comparison.static_ram_metrics.iter().any(|metric| {
        metric.metric == StaticRamMetricKind::Total
            && metric.outcome == MetricComparisonOutcome::Unchanged
    }));

    quantitative_mut(&mut candidate)
        .static_ram
        .as_mut()
        .unwrap()
        .config
        .as_mut()
        .unwrap()
        .sha256 = Sha256Digest::new("b".repeat(64)).unwrap();
    let comparison = compare_analyses(&baseline, &candidate, &ComparisonPolicy::default());
    assert_eq!(comparison.verdict, ComparisonVerdict::Inconclusive);
    assert!(comparison.static_ram_metrics.is_empty());
    assert!(
        comparison
            .reasons
            .contains(&"static_ram_config_digest_mismatch".to_owned())
    );
}

#[test]
fn nonvalid_or_invalid_summaries_never_leak_quantitative_rows() {
    let mut baseline = analyzed("baseline", 100);
    let mut candidate = analyzed("candidate", 100);
    for analysis in [&mut baseline, &mut candidate] {
        push_counter(
            analysis,
            resource_counter(
                "heap.used",
                CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES,
                allocator("system"),
                "bytes",
                ResourceValues {
                    first: 100.0,
                    latest: 100.0,
                    min: 100.0,
                    max: 100.0,
                    mean: 100.0,
                    delta: Some(0.0),
                    rate_per_second: None,
                },
            ),
        );
    }

    candidate.health.verdict = HealthVerdict::Degraded;
    candidate.summary.health_verdict = HealthVerdict::Degraded;
    candidate.summary.quantitative = None;
    let comparison = compare_analyses(&baseline, &candidate, &ComparisonPolicy::default());
    assert_eq!(comparison.verdict, ComparisonVerdict::Inconclusive);
    assert!(comparison.metrics.is_empty());
    assert!(comparison.resource_metrics.is_empty());
    assert!(comparison.static_ram_metrics.is_empty());

    candidate.health.verdict = HealthVerdict::Valid;
    candidate.summary.health_verdict = HealthVerdict::Valid;
    let comparison = compare_analyses(&baseline, &candidate, &ComparisonPolicy::default());
    assert_eq!(comparison.verdict, ComparisonVerdict::Inconclusive);
    assert!(comparison.metrics.is_empty());
    assert!(comparison.resource_metrics.is_empty());
    assert!(comparison.static_ram_metrics.is_empty());
    assert!(
        comparison
            .reasons
            .contains(&"candidate_summary_invalid".to_owned())
    );
}

#[test]
fn legacy_policy_without_resource_rules_remains_unconfigured() {
    let mut encoded = serde_json::to_value(ComparisonPolicy::default()).unwrap();
    let object = encoded.as_object_mut().unwrap();
    object.remove("resource_rules");
    object.remove("allow_resource_subject_set_changes");
    let decoded = serde_json::from_value::<ComparisonPolicy>(encoded).unwrap();
    assert!(decoded.resource_rules.is_empty());
    assert!(!decoded.allow_resource_subject_set_changes);

    let mut encoded = serde_json::to_value(ComparisonPolicy::default()).unwrap();
    encoded["resource_rules"][0]["unknown_constraint"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ComparisonPolicy>(encoded).is_err());
}
