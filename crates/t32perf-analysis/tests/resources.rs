use t32perf_analysis::{AnalysisCapabilities, Analyzer, AnalyzerConfig};
use t32perf_model::{
    CounterSemantic, CounterSubject, DictionaryEntry, DictionarySchemaVersion, HealthObservation,
    HealthVerdict, MetricSupportLevel, Observation, ObservationDictionary, ObservationEvent,
    Quality, ResourceClass, StackRole,
};

fn semantic(value: &'static str) -> CounterSemantic {
    CounterSemantic::new(value).unwrap()
}

fn definition(
    id: &str,
    semantic: Option<CounterSemantic>,
    subject: Option<CounterSubject>,
    unit: &str,
) -> DictionaryEntry {
    DictionaryEntry::DefineCounter {
        id: id.to_owned(),
        name: "heap-stack-ram misleading name".to_owned(),
        unit: Some(unit.to_owned()),
        description: None,
        semantic,
        subject,
    }
}

fn dictionary(entries: Vec<DictionaryEntry>) -> ObservationDictionary {
    ObservationDictionary {
        schema: DictionarySchemaVersion,
        session_id: "resources".to_owned(),
        entries,
    }
}

fn counter(sequence: u64, ts_ns: i64, id: &str, value: f64) -> Observation {
    Observation::new(
        "counter-source",
        sequence,
        Quality::Exact,
        ObservationEvent::Counter {
            ts_ns,
            core_id: Some(0),
            context_id: None,
            counter_id: id.to_owned(),
            value,
            args: Default::default(),
        },
    )
}

fn build_analyzer(dictionary: &ObservationDictionary) -> Analyzer {
    let mut analyzer = Analyzer::new(
        "resources",
        AnalyzerConfig {
            capabilities: AnalysisCapabilities::exact_program_flow(),
            ..AnalyzerConfig::default()
        },
    );
    analyzer.register_dictionary(dictionary).unwrap();
    analyzer
}

#[test]
fn opaque_ids_use_only_explicit_semantics_and_legacy_names_remain_generic() {
    let allocator = CounterSubject::Allocator {
        allocator_id: "system".to_owned(),
    };
    let dictionary = dictionary(vec![
        definition(
            "counter-7f3a",
            Some(semantic(CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES)),
            Some(allocator.clone()),
            "bytes",
        ),
        definition("heap-stack-ram", None, None, "widgets"),
    ]);
    let mut analyzer = build_analyzer(&dictionary);
    analyzer
        .ingest(&counter(0, 0, "counter-7f3a", 64.0))
        .unwrap();
    analyzer
        .ingest(&counter(1, 1, "heap-stack-ram", -7.0))
        .unwrap();
    let result = analyzer.finish(None).unwrap();

    let explicit = result
        .summary
        .resources
        .counters
        .iter()
        .find(|counter| counter.counter_id == "counter-7f3a")
        .unwrap();
    assert_eq!(explicit.class, ResourceClass::Heap);
    assert_eq!(explicit.subject.as_ref(), Some(&allocator));

    let generic = result
        .summary
        .resources
        .counters
        .iter()
        .find(|counter| counter.counter_id == "heap-stack-ram")
        .unwrap();
    assert_eq!(generic.class, ResourceClass::Other);
    assert!(generic.semantic.is_none());
    assert_eq!(generic.latest, -7.0);
}

#[test]
fn absent_optional_counters_are_unavailable_without_invalidating_other_metrics() {
    let dictionary = dictionary(Vec::new());
    let result = build_analyzer(&dictionary).finish(None).unwrap();
    assert_eq!(result.health.verdict, HealthVerdict::Valid);
    assert_eq!(
        result.health.metric_support.resource_counters.support,
        MetricSupportLevel::Unavailable
    );
    assert_eq!(
        result.health.metric_support.resource_counters.reasons,
        ["no_resource_counters_observed"]
    );
    assert!(result.summary.resources.counters.is_empty());
}

#[test]
fn monotonic_count_aggregates_window_rate_and_support() {
    let dictionary = dictionary(vec![definition(
        "opaque-count",
        Some(semantic(CounterSemantic::HEAP_ALLOCATION_COUNT)),
        Some(CounterSubject::Allocator {
            allocator_id: "pool-a".to_owned(),
        }),
        "count",
    )]);
    let mut analyzer = build_analyzer(&dictionary);
    for observation in [
        counter(0, 0, "opaque-count", 100.0),
        counter(1, 1_000_000_000, "opaque-count", 130.0),
        counter(2, 2_000_000_000, "opaque-count", 160.0),
    ] {
        analyzer.ingest(&observation).unwrap();
    }
    let result = analyzer.finish(None).unwrap();
    let summary = &result.summary.resources.counters[0];
    assert_eq!(summary.first, Some(100.0));
    assert_eq!(summary.latest, 160.0);
    assert_eq!(summary.min, 100.0);
    assert_eq!(summary.max, 160.0);
    assert_eq!(summary.mean, 130.0);
    assert_eq!(summary.delta, Some(60.0));
    assert_eq!(summary.window_ns, Some(2_000_000_000));
    assert_eq!(summary.rate_per_second, Some(30.0));
    assert_eq!(summary.support.support, MetricSupportLevel::Exact);

    let derived = result
        .summary
        .resources
        .derived
        .iter()
        .find(|metric| metric.semantic.as_str() == CounterSemantic::HEAP_ALLOCATION_RATE_PER_SECOND)
        .unwrap();
    assert_eq!(derived.value, Some(30.0));
    assert_eq!(derived.window_ns, Some(2_000_000_000));
}

#[test]
fn counter_reset_and_stack_capacity_violation_are_health_facts() {
    let stack = CounterSubject::Stack {
        stack_id: "msp-0".to_owned(),
        role: StackRole::Msp,
        context_id: None,
        core_id: Some(0),
    };
    let dictionary = dictionary(vec![
        definition(
            "count-a",
            Some(semantic(CounterSemantic::HEAP_ALLOCATION_COUNT)),
            Some(CounterSubject::Allocator {
                allocator_id: "pool-a".to_owned(),
            }),
            "count",
        ),
        definition(
            "capacity-a",
            Some(semantic(CounterSemantic::STACK_CAPACITY_BYTES)),
            Some(stack.clone()),
            "bytes",
        ),
        definition(
            "peak-a",
            Some(semantic(CounterSemantic::STACK_PEAK_USED_BYTES)),
            Some(stack),
            "bytes",
        ),
    ]);
    let mut analyzer = build_analyzer(&dictionary);
    for observation in [
        counter(0, 0, "count-a", 10.0),
        counter(1, 1, "count-a", 2.0),
        counter(2, 2, "capacity-a", 1024.0),
        counter(3, 3, "peak-a", 2048.0),
    ] {
        analyzer.ingest(&observation).unwrap();
    }
    let result = analyzer.finish(None).unwrap();
    assert_eq!(result.health.verdict, HealthVerdict::Degraded);
    assert_eq!(
        result.health.metric_support.resource_counters.support,
        MetricSupportLevel::Unavailable
    );
    assert!(
        result
            .health
            .issues
            .iter()
            .any(|issue| { issue.code == "resource_counter_not_monotonic" })
    );
    assert!(
        result
            .health
            .issues
            .iter()
            .any(|issue| { issue.code == "resource_counter_invariant_violation" })
    );
    assert!(
        result
            .summary
            .resources
            .counters
            .iter()
            .find(|counter| counter.counter_id == "count-a")
            .unwrap()
            .rate_per_second
            .is_none()
    );
}

#[test]
fn fragmentation_is_derived_only_from_synchronized_sufficient_evidence() {
    let allocator = CounterSubject::Allocator {
        allocator_id: "pool-a".to_owned(),
    };
    let dictionary = dictionary(vec![
        definition(
            "free-a",
            Some(semantic(CounterSemantic::HEAP_FREE_BYTES)),
            Some(allocator.clone()),
            "bytes",
        ),
        definition(
            "largest-a",
            Some(semantic(CounterSemantic::HEAP_LARGEST_FREE_BLOCK_BYTES)),
            Some(allocator),
            "bytes",
        ),
    ]);
    let mut analyzer = build_analyzer(&dictionary);
    analyzer.ingest(&counter(0, 10, "free-a", 1000.0)).unwrap();
    analyzer
        .ingest(&counter(1, 10, "largest-a", 400.0))
        .unwrap();
    let result = analyzer.finish(None).unwrap();
    let fragmentation = result
        .summary
        .resources
        .derived
        .iter()
        .find(|metric| {
            metric.semantic.as_str() == CounterSemantic::HEAP_EXTERNAL_FRAGMENTATION_RATIO
        })
        .unwrap();
    assert!((fragmentation.value.unwrap() - 0.6).abs() < f64::EPSILON);
    assert_eq!(fragmentation.first_ts_ns, Some(10));

    let mut unsynchronized = build_analyzer(&dictionary);
    unsynchronized
        .ingest(&counter(0, 10, "free-a", 1000.0))
        .unwrap();
    unsynchronized
        .ingest(&counter(1, 11, "largest-a", 400.0))
        .unwrap();
    let result = unsynchronized.finish(None).unwrap();
    let fragmentation = &result.summary.resources.derived[0];
    assert!(fragmentation.value.is_none());
    assert_eq!(
        fragmentation.support.support,
        MetricSupportLevel::Unavailable
    );

    let mut zero_free = build_analyzer(&dictionary);
    zero_free.ingest(&counter(0, 10, "free-a", 0.0)).unwrap();
    zero_free.ingest(&counter(1, 10, "largest-a", 0.0)).unwrap();
    let result = zero_free.finish(None).unwrap();
    let fragmentation = &result.summary.resources.derived[0];
    assert!(fragmentation.value.is_none());
    assert!(
        fragmentation
            .support
            .reasons
            .iter()
            .any(|reason| reason == "free_bytes_zero")
    );
}

#[test]
fn trace_gap_makes_allocation_rate_unavailable_instead_of_guessing() {
    let dictionary = dictionary(vec![definition(
        "opaque-count",
        Some(semantic(CounterSemantic::HEAP_ALLOCATION_COUNT)),
        Some(CounterSubject::Allocator {
            allocator_id: "pool-a".to_owned(),
        }),
        "count",
    )]);
    let mut analyzer = build_analyzer(&dictionary);
    analyzer
        .ingest(&counter(0, 0, "opaque-count", 10.0))
        .unwrap();
    analyzer
        .ingest(&counter(1, 1_000_000_000, "opaque-count", 20.0))
        .unwrap();
    analyzer.record_health_observation(HealthObservation {
        code: "trace_gap".to_owned(),
        source: "test".to_owned(),
        artifact_id: None,
        record: Some(1),
        start_ns: Some(100),
        end_ns: Some(200),
        evidence: Default::default(),
    });
    let result = analyzer.finish(None).unwrap();
    let rate = result
        .summary
        .resources
        .derived
        .iter()
        .find(|metric| metric.semantic.as_str() == CounterSemantic::HEAP_ALLOCATION_RATE_PER_SECOND)
        .unwrap();
    assert!(rate.value.is_none());
    assert_eq!(rate.support.support, MetricSupportLevel::Unavailable);
    assert!(
        rate.support
            .reasons
            .iter()
            .any(|reason| reason == "trace_gap")
    );
}

#[test]
fn one_million_counter_samples_keep_constant_resident_state() {
    let dictionary = dictionary(vec![definition(
        "opaque-million",
        Some(semantic(CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES)),
        Some(CounterSubject::Allocator {
            allocator_id: "pool-a".to_owned(),
        }),
        "bytes",
    )]);
    let mut analyzer = build_analyzer(&dictionary);
    for sequence in 0..1_000_000_u64 {
        analyzer
            .ingest(&counter(
                sequence,
                i64::try_from(sequence).unwrap(),
                "opaque-million",
                (sequence % 4096) as f64,
            ))
            .unwrap();
    }
    assert_eq!(analyzer.resident_counter_count(), 1);
    assert_eq!(analyzer.resident_resource_subject_count(), 0);
    let result = analyzer.finish(None).unwrap();
    assert_eq!(result.summary.resources.counters[0].sample_count, 1_000_000);
}
