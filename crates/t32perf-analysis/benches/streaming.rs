use std::{hint::black_box, time::Duration};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use t32perf_analysis::{AnalysisCapabilities, Analyzer, AnalyzerConfig};
use t32perf_model::{Observation, ObservationEvent, Properties, Quality};

const DEFAULT_EVENT_COUNT: u64 = 1_000_000;
const EXTENDED_EVENT_COUNT: u64 = 10_000_000;
const DRAIN_BATCH_SPANS: usize = 4_096;
const DEEP_STACK_DEPTHS: [u64; 2] = [64, 1_024];

fn exact_analyzer(session_id: &str) -> Analyzer {
    let config = AnalyzerConfig {
        capabilities: AnalysisCapabilities::exact_program_flow(),
        ..AnalyzerConfig::default()
    };
    Analyzer::new(session_id, config)
}

fn analyze_generated_events(event_count: u64) -> u64 {
    assert_eq!(event_count % 2, 0);
    let mut analyzer = exact_analyzer("benchmark-functions");
    let mut drained_spans = 0_u64;

    for activation in 0..event_count / 2 {
        let enter_sequence = activation * 2 + 1;
        let exit_sequence = enter_sequence + 1;
        analyzer
            .ingest(&Observation::new(
                "benchmark",
                enter_sequence,
                Quality::Exact,
                ObservationEvent::FunctionEnter {
                    ts_ns: (activation * 2) as i64,
                    core_id: 0,
                    context_id: "task".to_owned(),
                    function_id: "work".to_owned(),
                    frame_id: None,
                },
            ))
            .unwrap();
        analyzer
            .ingest(&Observation::new(
                "benchmark",
                exit_sequence,
                Quality::Exact,
                ObservationEvent::FunctionExit {
                    ts_ns: (activation * 2 + 1) as i64,
                    core_id: 0,
                    context_id: "task".to_owned(),
                    function_id: "work".to_owned(),
                    frame_id: None,
                },
            ))
            .unwrap();
        if analyzer.resident_completed_span_count() >= DRAIN_BATCH_SPANS {
            drained_spans += analyzer.drain_completed_spans().len() as u64;
        }
    }

    let result = analyzer.finish(None).unwrap();
    assert_eq!(result.summary.observation_count, event_count);
    assert_eq!(
        drained_spans + result.derived.function_spans.len() as u64,
        event_count / 2
    );
    black_box(result.summary.function_span_count)
}

fn analyze_context_switches(event_count: u64) -> u64 {
    let mut analyzer = exact_analyzer("benchmark-context-switches");
    let mut previous: Option<&str> = None;

    for index in 0..event_count {
        let next = if index % 2 == 0 { "task-a" } else { "task-b" };
        analyzer
            .ingest(&Observation::new(
                "benchmark",
                index + 1,
                Quality::Exact,
                ObservationEvent::ContextSwitch {
                    ts_ns: index as i64,
                    core_id: 0,
                    prev_context_id: previous.map(str::to_owned),
                    next_context_id: next.to_owned(),
                    reason: Some("benchmark".to_owned()),
                },
            ))
            .unwrap();
        previous = Some(next);
    }

    let result = analyzer.finish(None).unwrap();
    assert_eq!(result.summary.observation_count, event_count);
    black_box(result.summary.context_cpu.len() as u64)
}

fn analyze_interrupt_boundaries(activation_count: u64) -> u64 {
    let mut analyzer = exact_analyzer("benchmark-interrupts");
    analyzer
        .ingest(&Observation::new(
            "benchmark",
            1,
            Quality::Exact,
            ObservationEvent::ContextSwitch {
                ts_ns: 0,
                core_id: 0,
                prev_context_id: None,
                next_context_id: "task".to_owned(),
                reason: Some("benchmark-seed".to_owned()),
            },
        ))
        .unwrap();

    for activation in 0..activation_count {
        let enter_sequence = activation * 2 + 2;
        let exit_sequence = enter_sequence + 1;
        let enter_ts = activation * 2 + 1;
        analyzer
            .ingest(&Observation::new(
                "benchmark",
                enter_sequence,
                Quality::Exact,
                ObservationEvent::InterruptEnter {
                    ts_ns: enter_ts as i64,
                    core_id: 0,
                    interrupt_id: "irq".to_owned(),
                    priority: Some(1),
                    activation_id: "activation".to_owned(),
                },
            ))
            .unwrap();
        analyzer
            .ingest(&Observation::new(
                "benchmark",
                exit_sequence,
                Quality::Exact,
                ObservationEvent::InterruptExit {
                    ts_ns: (enter_ts + 1) as i64,
                    core_id: 0,
                    interrupt_id: "irq".to_owned(),
                    priority: Some(1),
                    activation_id: "activation".to_owned(),
                },
            ))
            .unwrap();
    }

    let result = analyzer.finish(None).unwrap();
    let event_count = activation_count * 2 + 1;
    assert_eq!(result.summary.observation_count, event_count);
    assert_eq!(result.summary.isr_cpu_ns, activation_count);
    black_box(result.summary.isr_cpu_ns)
}

fn analyze_custom_instants(event_count: u64) -> u64 {
    let mut analyzer = exact_analyzer("benchmark-custom-instants");

    for index in 0..event_count {
        analyzer
            .ingest(&Observation::new(
                "benchmark",
                index + 1,
                Quality::Exact,
                ObservationEvent::Instant {
                    ts_ns: index as i64,
                    core_id: Some(0),
                    context_id: Some("task".to_owned()),
                    name: "marker".to_owned(),
                    args: Properties::new(),
                },
            ))
            .unwrap();
    }

    let result = analyzer.finish(None).unwrap();
    assert_eq!(result.summary.observation_count, event_count);
    black_box(result.summary.observation_count)
}

fn analyze_deep_call_stack(depth: u64) -> u64 {
    let mut analyzer = exact_analyzer("benchmark-deep-stack");

    for level in 0..depth {
        analyzer
            .ingest(&Observation::new(
                "benchmark",
                level + 1,
                Quality::Exact,
                ObservationEvent::FunctionEnter {
                    ts_ns: level as i64,
                    core_id: 0,
                    context_id: "task".to_owned(),
                    function_id: "recursive".to_owned(),
                    frame_id: None,
                },
            ))
            .unwrap();
    }
    for level in 0..depth {
        analyzer
            .ingest(&Observation::new(
                "benchmark",
                depth + level + 1,
                Quality::Exact,
                ObservationEvent::FunctionExit {
                    ts_ns: (depth + level) as i64,
                    core_id: 0,
                    context_id: "task".to_owned(),
                    function_id: "recursive".to_owned(),
                    frame_id: None,
                },
            ))
            .unwrap();
    }

    let result = analyzer.finish(None).unwrap();
    assert_eq!(result.summary.observation_count, depth * 2);
    assert_eq!(result.summary.function_span_count, depth);
    black_box(result.summary.function_span_count)
}

fn streaming_function_events(criterion: &mut Criterion) {
    let mut event_counts = vec![DEFAULT_EVENT_COUNT];
    // The 10M case is explicit to keep ordinary local benchmark runs bounded.
    if std::env::var_os("T32PERF_BENCH_10M").is_some() {
        event_counts.push(EXTENDED_EVENT_COUNT);
    }

    let mut group = criterion.benchmark_group("streaming_analyzer");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));
    for event_count in event_counts {
        group.throughput(Throughput::Elements(event_count));
        group.bench_with_input(
            BenchmarkId::new("generated_events", event_count),
            &event_count,
            |bencher, event_count| {
                bencher.iter(|| analyze_generated_events(*event_count));
            },
        );
    }
    group.finish();
}

fn high_frequency_workloads(criterion: &mut Criterion) {
    let event_count = DEFAULT_EVENT_COUNT;
    let mut group = criterion.benchmark_group("streaming_workload_matrix");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    group.throughput(Throughput::Elements(event_count));
    group.bench_function("context_switches", |bencher| {
        bencher.iter(|| analyze_context_switches(event_count));
    });

    let activation_count = event_count / 2;
    group.throughput(Throughput::Elements(activation_count * 2 + 1));
    group.bench_function("interrupt_boundaries", |bencher| {
        bencher.iter(|| analyze_interrupt_boundaries(activation_count));
    });

    group.throughput(Throughput::Elements(event_count));
    group.bench_function("custom_instants", |bencher| {
        bencher.iter(|| analyze_custom_instants(event_count));
    });
    group.finish();
}

fn deep_call_stacks(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("deep_call_stack");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));
    for depth in DEEP_STACK_DEPTHS {
        group.throughput(Throughput::Elements(depth * 2));
        group.bench_with_input(
            BenchmarkId::new("recursive_depth", depth),
            &depth,
            |bencher, depth| bencher.iter(|| analyze_deep_call_stack(*depth)),
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    streaming_function_events,
    high_frequency_workloads,
    deep_call_stacks
);
criterion_main!(benches);
