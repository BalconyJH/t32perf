use std::collections::BTreeSet;

use proptest::prelude::*;
use serde_json::json;
use t32perf_analysis::*;
use t32perf_model::*;

fn observation(sequence: u64, event: ObservationEvent) -> Observation {
    Observation::new("test", sequence, Quality::Exact, event)
}

fn dictionary(session_id: &str) -> ObservationDictionary {
    ObservationDictionary {
        schema: DictionarySchemaVersion,
        session_id: session_id.to_owned(),
        entries: vec![
            DictionaryEntry::DefineContext {
                id: "task-a".to_owned(),
                kind: ContextKind::Task,
                name: "task-a".to_owned(),
                core_id: Some(0),
                priority: Some(1),
            },
            DictionaryEntry::DefineContext {
                id: "task-b".to_owned(),
                kind: ContextKind::Task,
                name: "task-b".to_owned(),
                core_id: Some(0),
                priority: Some(2),
            },
            DictionaryEntry::DefineContext {
                id: "irq-1".to_owned(),
                kind: ContextKind::Isr,
                name: "irq-1".to_owned(),
                core_id: Some(0),
                priority: Some(10),
            },
            DictionaryEntry::DefineContext {
                id: "irq-2".to_owned(),
                kind: ContextKind::Isr,
                name: "irq-2".to_owned(),
                core_id: Some(0),
                priority: Some(20),
            },
            DictionaryEntry::DefineCounter {
                id: "heap.used".to_owned(),
                name: "Heap used".to_owned(),
                unit: Some("bytes".to_owned()),
                description: None,
                semantic: Some(
                    CounterSemantic::new(CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES).unwrap(),
                ),
                subject: Some(CounterSubject::Allocator {
                    allocator_id: "system".to_owned(),
                }),
            },
            DictionaryEntry::DefineCounter {
                id: "stack.high_water".to_owned(),
                name: "Stack high water".to_owned(),
                unit: Some("bytes".to_owned()),
                description: None,
                semantic: Some(
                    CounterSemantic::new(CounterSemantic::STACK_PEAK_USED_BYTES).unwrap(),
                ),
                subject: Some(CounterSubject::Stack {
                    stack_id: "task-a-stack".to_owned(),
                    role: StackRole::Task,
                    context_id: Some("task-a".to_owned()),
                    core_id: Some(0),
                }),
            },
            DictionaryEntry::DefineCounter {
                id: "ram.used".to_owned(),
                name: "RAM used".to_owned(),
                unit: Some("bytes".to_owned()),
                description: None,
                semantic: Some(
                    CounterSemantic::new(CounterSemantic::RAM_CURRENT_USED_BYTES).unwrap(),
                ),
                subject: Some(CounterSubject::MemoryRegion {
                    region_id: "runtime".to_owned(),
                }),
            },
        ],
    }
}

fn analyze(session_id: &str, events: &[Observation]) -> AnalysisResult {
    let config = AnalyzerConfig {
        capabilities: AnalysisCapabilities::exact_program_flow(),
        ..AnalyzerConfig::default()
    };
    let mut analyzer = Analyzer::new(session_id, config);
    analyzer
        .register_dictionary(&dictionary(session_id))
        .unwrap();
    for event in events {
        analyzer.ingest(event).unwrap();
    }
    analyzer.finish(None).unwrap()
}

#[test]
fn nested_isr_and_task_suspension_use_context_virtual_cpu_time() {
    let events = vec![
        observation(
            1,
            ObservationEvent::FunctionEnter {
                ts_ns: 0,
                core_id: 0,
                context_id: "task-a".to_owned(),
                function_id: "root".to_owned(),
                frame_id: Some("root-frame".to_owned()),
            },
        ),
        observation(
            2,
            ObservationEvent::FunctionEnter {
                ts_ns: 2,
                core_id: 0,
                context_id: "task-a".to_owned(),
                function_id: "child".to_owned(),
                frame_id: Some("child-frame".to_owned()),
            },
        ),
        observation(
            3,
            ObservationEvent::FunctionExit {
                ts_ns: 6,
                core_id: 0,
                context_id: "task-a".to_owned(),
                function_id: "child".to_owned(),
                frame_id: Some("child-frame".to_owned()),
            },
        ),
        observation(
            4,
            ObservationEvent::InterruptEnter {
                ts_ns: 10,
                core_id: 0,
                interrupt_id: "irq-1".to_owned(),
                priority: Some(10),
                activation_id: "irq-1:1".to_owned(),
            },
        ),
        observation(
            5,
            ObservationEvent::FunctionEnter {
                ts_ns: 10,
                core_id: 0,
                context_id: "irq-1".to_owned(),
                function_id: "irq-1-handler".to_owned(),
                frame_id: None,
            },
        ),
        observation(
            6,
            ObservationEvent::InterruptEnter {
                ts_ns: 15,
                core_id: 0,
                interrupt_id: "irq-2".to_owned(),
                priority: Some(20),
                activation_id: "irq-2:1".to_owned(),
            },
        ),
        observation(
            7,
            ObservationEvent::FunctionEnter {
                ts_ns: 15,
                core_id: 0,
                context_id: "irq-2".to_owned(),
                function_id: "irq-2-handler".to_owned(),
                frame_id: None,
            },
        ),
        observation(
            8,
            ObservationEvent::FunctionExit {
                ts_ns: 20,
                core_id: 0,
                context_id: "irq-2".to_owned(),
                function_id: "irq-2-handler".to_owned(),
                frame_id: None,
            },
        ),
        observation(
            9,
            ObservationEvent::InterruptExit {
                ts_ns: 20,
                core_id: 0,
                interrupt_id: "irq-2".to_owned(),
                priority: Some(20),
                activation_id: "irq-2:1".to_owned(),
            },
        ),
        observation(
            10,
            ObservationEvent::FunctionExit {
                ts_ns: 25,
                core_id: 0,
                context_id: "irq-1".to_owned(),
                function_id: "irq-1-handler".to_owned(),
                frame_id: None,
            },
        ),
        observation(
            11,
            ObservationEvent::InterruptExit {
                ts_ns: 25,
                core_id: 0,
                interrupt_id: "irq-1".to_owned(),
                priority: Some(10),
                activation_id: "irq-1:1".to_owned(),
            },
        ),
        observation(
            12,
            ObservationEvent::ContextSwitch {
                ts_ns: 30,
                core_id: 0,
                prev_context_id: Some("task-a".to_owned()),
                next_context_id: "task-b".to_owned(),
                reason: Some("preempt".to_owned()),
            },
        ),
        observation(
            13,
            ObservationEvent::ContextSwitch {
                ts_ns: 50,
                core_id: 0,
                prev_context_id: Some("task-b".to_owned()),
                next_context_id: "task-a".to_owned(),
                reason: Some("resume".to_owned()),
            },
        ),
        observation(
            14,
            ObservationEvent::FunctionExit {
                ts_ns: 60,
                core_id: 0,
                context_id: "task-a".to_owned(),
                function_id: "root".to_owned(),
                frame_id: Some("root-frame".to_owned()),
            },
        ),
    ];

    let result = analyze("nested", &events);
    assert_eq!(result.health.verdict, HealthVerdict::Valid);

    let root = result
        .derived
        .function_spans
        .iter()
        .find(|span| span.function_id == "root")
        .unwrap();
    assert_eq!(root.elapsed_ns, 60);
    assert_eq!(root.active_ns, 25);
    assert_eq!(root.preempted_ns, 35);
    assert_eq!(root.self_active_ns, 21);
    assert!(!root.incomplete);

    let irq_1 = result
        .derived
        .function_spans
        .iter()
        .find(|span| span.function_id == "irq-1-handler")
        .unwrap();
    assert_eq!(irq_1.elapsed_ns, 15);
    assert_eq!(irq_1.active_ns, 10);
    assert_eq!(irq_1.preempted_ns, 5);

    assert_eq!(result.summary.call_depth.max_depth, 2);
    assert_eq!(result.summary.call_depth.deepest_path, ["root", "child"]);
    assert_eq!(result.summary.task_cpu_ns, 45);
    assert_eq!(result.summary.isr_cpu_ns, 15);

    let root_hotspot = result
        .hotspots
        .functions
        .iter()
        .find(|row| row.function_id == "root")
        .unwrap();
    assert_eq!(root_hotspot.inclusive_active_ns, 25);
    assert_eq!(root_hotspot.self_active_ns, 21);
}

#[test]
fn same_named_nested_isr_activations_have_independent_stacks_and_clocks() {
    let result = analyze(
        "same-isr",
        &[
            observation(
                1,
                ObservationEvent::ContextSwitch {
                    ts_ns: 0,
                    core_id: 0,
                    prev_context_id: None,
                    next_context_id: "task-a".to_owned(),
                    reason: None,
                },
            ),
            observation(
                2,
                ObservationEvent::InterruptEnter {
                    ts_ns: 10,
                    core_id: 0,
                    interrupt_id: "irq-1".to_owned(),
                    priority: Some(10),
                    activation_id: "outer".to_owned(),
                },
            ),
            observation(
                3,
                ObservationEvent::FunctionEnter {
                    ts_ns: 10,
                    core_id: 0,
                    context_id: "irq-1".to_owned(),
                    function_id: "outer-handler".to_owned(),
                    frame_id: None,
                },
            ),
            observation(
                4,
                ObservationEvent::InterruptEnter {
                    ts_ns: 15,
                    core_id: 0,
                    interrupt_id: "irq-1".to_owned(),
                    priority: Some(20),
                    activation_id: "inner".to_owned(),
                },
            ),
            observation(
                5,
                ObservationEvent::FunctionEnter {
                    ts_ns: 15,
                    core_id: 0,
                    context_id: "irq-1".to_owned(),
                    function_id: "inner-handler".to_owned(),
                    frame_id: None,
                },
            ),
            observation(
                6,
                ObservationEvent::FunctionExit {
                    ts_ns: 20,
                    core_id: 0,
                    context_id: "irq-1".to_owned(),
                    function_id: "inner-handler".to_owned(),
                    frame_id: None,
                },
            ),
            observation(
                7,
                ObservationEvent::InterruptExit {
                    ts_ns: 20,
                    core_id: 0,
                    interrupt_id: "irq-1".to_owned(),
                    priority: Some(20),
                    activation_id: "inner".to_owned(),
                },
            ),
            observation(
                8,
                ObservationEvent::FunctionExit {
                    ts_ns: 25,
                    core_id: 0,
                    context_id: "irq-1".to_owned(),
                    function_id: "outer-handler".to_owned(),
                    frame_id: None,
                },
            ),
            observation(
                9,
                ObservationEvent::InterruptExit {
                    ts_ns: 25,
                    core_id: 0,
                    interrupt_id: "irq-1".to_owned(),
                    priority: Some(10),
                    activation_id: "outer".to_owned(),
                },
            ),
        ],
    );

    assert_eq!(result.health.verdict, HealthVerdict::Valid);
    let outer = result
        .derived
        .function_spans
        .iter()
        .find(|span| span.function_id == "outer-handler")
        .unwrap();
    let inner = result
        .derived
        .function_spans
        .iter()
        .find(|span| span.function_id == "inner-handler")
        .unwrap();
    assert_eq!(outer.context_id, "irq-1");
    assert_eq!(outer.elapsed_ns, 15);
    assert_eq!(outer.active_ns, 10);
    assert_eq!(outer.preempted_ns, 5);
    assert_eq!(inner.context_id, "irq-1");
    assert_eq!(inner.elapsed_ns, 5);
    assert_eq!(inner.active_ns, 5);
    let irq_cpu = result
        .summary
        .context_cpu
        .iter()
        .find(|context| context.context_id == "irq-1")
        .unwrap();
    assert_eq!(irq_cpu.active_ns, 15);
}

#[test]
fn same_isr_running_on_two_cores_has_independent_activation_contexts() {
    let result = analyze(
        "multicore-isr",
        &[
            observation(
                1,
                ObservationEvent::ContextSwitch {
                    ts_ns: 0,
                    core_id: 0,
                    prev_context_id: None,
                    next_context_id: "task-a".to_owned(),
                    reason: None,
                },
            ),
            observation(
                2,
                ObservationEvent::ContextSwitch {
                    ts_ns: 0,
                    core_id: 1,
                    prev_context_id: None,
                    next_context_id: "task-b".to_owned(),
                    reason: None,
                },
            ),
            observation(
                3,
                ObservationEvent::InterruptEnter {
                    ts_ns: 0,
                    core_id: 0,
                    interrupt_id: "irq-1".to_owned(),
                    priority: Some(10),
                    activation_id: "shared-activation".to_owned(),
                },
            ),
            observation(
                4,
                ObservationEvent::FunctionEnter {
                    ts_ns: 0,
                    core_id: 0,
                    context_id: "irq-1".to_owned(),
                    function_id: "handler-0".to_owned(),
                    frame_id: None,
                },
            ),
            observation(
                5,
                ObservationEvent::InterruptEnter {
                    ts_ns: 0,
                    core_id: 1,
                    interrupt_id: "irq-1".to_owned(),
                    priority: Some(10),
                    activation_id: "shared-activation".to_owned(),
                },
            ),
            observation(
                6,
                ObservationEvent::FunctionEnter {
                    ts_ns: 0,
                    core_id: 1,
                    context_id: "irq-1".to_owned(),
                    function_id: "handler-1".to_owned(),
                    frame_id: None,
                },
            ),
            observation(
                7,
                ObservationEvent::FunctionExit {
                    ts_ns: 10,
                    core_id: 0,
                    context_id: "irq-1".to_owned(),
                    function_id: "handler-0".to_owned(),
                    frame_id: None,
                },
            ),
            observation(
                8,
                ObservationEvent::InterruptExit {
                    ts_ns: 10,
                    core_id: 0,
                    interrupt_id: "irq-1".to_owned(),
                    priority: Some(10),
                    activation_id: "shared-activation".to_owned(),
                },
            ),
            observation(
                9,
                ObservationEvent::FunctionExit {
                    ts_ns: 20,
                    core_id: 1,
                    context_id: "irq-1".to_owned(),
                    function_id: "handler-1".to_owned(),
                    frame_id: None,
                },
            ),
            observation(
                10,
                ObservationEvent::InterruptExit {
                    ts_ns: 20,
                    core_id: 1,
                    interrupt_id: "irq-1".to_owned(),
                    priority: Some(10),
                    activation_id: "shared-activation".to_owned(),
                },
            ),
        ],
    );

    assert_eq!(result.health.verdict, HealthVerdict::Valid);
    let handler_0 = result
        .derived
        .function_spans
        .iter()
        .find(|span| span.function_id == "handler-0")
        .unwrap();
    let handler_1 = result
        .derived
        .function_spans
        .iter()
        .find(|span| span.function_id == "handler-1")
        .unwrap();
    assert_eq!(handler_0.active_ns, 10);
    assert_eq!(handler_1.active_ns, 20);
    assert_eq!(handler_0.context_id, "irq-1");
    assert_eq!(handler_1.context_id, "irq-1");
    let irq_cpu = result
        .summary
        .context_cpu
        .iter()
        .find(|context| context.context_id == "irq-1")
        .unwrap();
    assert_eq!(irq_cpu.active_ns, 30);
}

#[test]
fn task_scheduled_on_two_cores_is_invalid_and_not_double_counted() {
    let result = analyze(
        "invalid-multicore-task",
        &[
            observation(
                1,
                ObservationEvent::ContextSwitch {
                    ts_ns: 0,
                    core_id: 0,
                    prev_context_id: None,
                    next_context_id: "task-a".to_owned(),
                    reason: None,
                },
            ),
            observation(
                2,
                ObservationEvent::ContextSwitch {
                    ts_ns: 0,
                    core_id: 1,
                    prev_context_id: None,
                    next_context_id: "task-a".to_owned(),
                    reason: None,
                },
            ),
            observation(
                3,
                ObservationEvent::FunctionEnter {
                    ts_ns: 0,
                    core_id: 0,
                    context_id: "task-a".to_owned(),
                    function_id: "root".to_owned(),
                    frame_id: None,
                },
            ),
            observation(
                4,
                ObservationEvent::Instant {
                    ts_ns: 10,
                    core_id: Some(0),
                    context_id: Some("task-a".to_owned()),
                    name: "tick".to_owned(),
                    args: Properties::new(),
                },
            ),
            observation(
                5,
                ObservationEvent::Instant {
                    ts_ns: 10,
                    core_id: Some(1),
                    context_id: Some("task-a".to_owned()),
                    name: "tick".to_owned(),
                    args: Properties::new(),
                },
            ),
            observation(
                6,
                ObservationEvent::FunctionExit {
                    ts_ns: 20,
                    core_id: 0,
                    context_id: "task-a".to_owned(),
                    function_id: "root".to_owned(),
                    frame_id: None,
                },
            ),
        ],
    );

    assert_eq!(result.health.verdict, HealthVerdict::Invalid);
    assert!(
        result
            .health
            .issues
            .iter()
            .any(|issue| issue.code == "concurrent_context")
    );
    let span = result
        .derived
        .function_spans
        .iter()
        .find(|span| span.function_id == "root")
        .unwrap();
    assert!(span.incomplete);
    assert_eq!(span.active_ns, 20);
    let task_cpu = result
        .summary
        .context_cpu
        .iter()
        .find(|context| context.context_id == "task-a")
        .unwrap();
    assert_eq!(task_cpu.active_ns, 20);
    assert!(result.hotspots.functions.is_empty());
}

#[test]
fn task_migration_at_one_timestamp_is_not_reported_as_concurrent() {
    let result = analyze(
        "task-migration",
        &[
            observation(
                1,
                ObservationEvent::ContextSwitch {
                    ts_ns: 0,
                    core_id: 0,
                    prev_context_id: None,
                    next_context_id: "task-a".to_owned(),
                    reason: None,
                },
            ),
            observation(
                2,
                ObservationEvent::FunctionEnter {
                    ts_ns: 0,
                    core_id: 0,
                    context_id: "task-a".to_owned(),
                    function_id: "migrating".to_owned(),
                    frame_id: None,
                },
            ),
            observation(
                3,
                ObservationEvent::ContextSwitch {
                    ts_ns: 10,
                    core_id: 1,
                    prev_context_id: None,
                    next_context_id: "task-a".to_owned(),
                    reason: Some("migration-in".to_owned()),
                },
            ),
            observation(
                4,
                ObservationEvent::ContextSwitch {
                    ts_ns: 10,
                    core_id: 0,
                    prev_context_id: Some("task-a".to_owned()),
                    next_context_id: "task-b".to_owned(),
                    reason: Some("migration-out".to_owned()),
                },
            ),
            observation(
                5,
                ObservationEvent::FunctionExit {
                    ts_ns: 20,
                    core_id: 1,
                    context_id: "task-a".to_owned(),
                    function_id: "migrating".to_owned(),
                    frame_id: None,
                },
            ),
        ],
    );

    assert_eq!(result.health.verdict, HealthVerdict::Valid);
    assert!(
        result
            .health
            .issues
            .iter()
            .all(|issue| issue.code != "concurrent_context")
    );
    let span = result
        .derived
        .function_spans
        .iter()
        .find(|span| span.function_id == "migrating")
        .unwrap();
    assert_eq!(span.active_ns, 20);
    assert_eq!(span.preempted_ns, 0);
    assert!(!span.incomplete);
}

#[test]
fn gap_marks_open_spans_incomplete_and_excludes_them_from_hotspots() {
    let result = analyze(
        "gap",
        &[
            observation(
                1,
                ObservationEvent::FunctionEnter {
                    ts_ns: 0,
                    core_id: 0,
                    context_id: "task-a".to_owned(),
                    function_id: "root".to_owned(),
                    frame_id: None,
                },
            ),
            observation(
                2,
                ObservationEvent::TraceGap {
                    ts_ns: 10,
                    duration_ns: 5,
                    reason: "decoder gap".to_owned(),
                },
            ),
            observation(
                3,
                ObservationEvent::FunctionExit {
                    ts_ns: 20,
                    core_id: 0,
                    context_id: "task-a".to_owned(),
                    function_id: "root".to_owned(),
                    frame_id: None,
                },
            ),
        ],
    );

    assert_eq!(result.health.verdict, HealthVerdict::Degraded);
    assert_eq!(
        result.health.metric_support.call_count.support,
        MetricSupportLevel::Unavailable
    );
    let span = &result.derived.function_spans[0];
    assert!(span.incomplete);
    assert_eq!(span.elapsed_ns, 20);
    assert_eq!(span.active_ns, 15);
    assert_eq!(span.preempted_ns, 5);
    assert!(result.hotspots.functions.is_empty());
    assert!(result.trusted_hotspots().is_none());
    assert!(result.trusted_summary().is_none());
}

#[test]
fn fifo_full_gap_is_promoted_to_fatal_trace_overflow() {
    let result = analyze(
        "fifo-full",
        &[observation(
            1,
            ObservationEvent::TraceGap {
                ts_ns: 10,
                duration_ns: 5,
                reason: "TRACE32 FIFO full".to_owned(),
            },
        )],
    );

    assert_eq!(result.health.verdict, HealthVerdict::Invalid);
    assert!(
        result
            .health
            .issues
            .iter()
            .any(|issue| issue.code == "trace_overflow")
    );
    assert!(result.trusted_hotspots().is_none());
    assert!(result.trusted_summary().is_none());
}

#[test]
fn mismatched_exit_invalidates_program_flow() {
    let result = analyze(
        "bad-exit",
        &[
            observation(
                1,
                ObservationEvent::FunctionEnter {
                    ts_ns: 0,
                    core_id: 0,
                    context_id: "task-a".to_owned(),
                    function_id: "root".to_owned(),
                    frame_id: None,
                },
            ),
            observation(
                2,
                ObservationEvent::FunctionEnter {
                    ts_ns: 1,
                    core_id: 0,
                    context_id: "task-a".to_owned(),
                    function_id: "child".to_owned(),
                    frame_id: None,
                },
            ),
            observation(
                3,
                ObservationEvent::FunctionExit {
                    ts_ns: 2,
                    core_id: 0,
                    context_id: "task-a".to_owned(),
                    function_id: "root".to_owned(),
                    frame_id: None,
                },
            ),
        ],
    );

    assert_eq!(result.health.verdict, HealthVerdict::Invalid);
    assert!(
        result
            .health
            .issues
            .iter()
            .any(|issue| issue.code == "mismatched_function_exit")
    );
    assert!(
        result
            .derived
            .function_spans
            .iter()
            .all(|span| span.incomplete)
    );
    assert!(result.hotspots.functions.is_empty());
}

#[test]
fn out_of_order_and_unclosed_spans_are_invalid_and_incomplete() {
    let out_of_order = analyze(
        "out-of-order",
        &[
            observation(
                1,
                ObservationEvent::FunctionEnter {
                    ts_ns: 10,
                    core_id: 0,
                    context_id: "task-a".to_owned(),
                    function_id: "root".to_owned(),
                    frame_id: None,
                },
            ),
            observation(
                2,
                ObservationEvent::FunctionExit {
                    ts_ns: 5,
                    core_id: 0,
                    context_id: "task-a".to_owned(),
                    function_id: "root".to_owned(),
                    frame_id: None,
                },
            ),
        ],
    );
    assert_eq!(out_of_order.health.verdict, HealthVerdict::Invalid);
    assert!(out_of_order.derived.function_spans[0].incomplete);

    let unclosed = analyze(
        "unclosed",
        &[observation(
            1,
            ObservationEvent::FunctionEnter {
                ts_ns: 0,
                core_id: 0,
                context_id: "task-a".to_owned(),
                function_id: "root".to_owned(),
                frame_id: None,
            },
        )],
    );
    assert_eq!(unclosed.health.verdict, HealthVerdict::Invalid);
    assert!(unclosed.derived.function_spans[0].incomplete);
    assert!(unclosed.hotspots.functions.is_empty());
}

#[test]
fn sampling_and_resource_counters_are_aggregated_separately() {
    let result = analyze(
        "resources",
        &[
            observation(
                1,
                ObservationEvent::ContextSwitch {
                    ts_ns: 0,
                    core_id: 0,
                    prev_context_id: None,
                    next_context_id: "task-a".to_owned(),
                    reason: None,
                },
            ),
            observation(
                2,
                ObservationEvent::Sample {
                    ts_ns: 1,
                    core_id: 0,
                    context_id: Some("task-a".to_owned()),
                    function_id: Some("hot".to_owned()),
                    address: Some(0x1000),
                    weight_ns: Some(3),
                },
            ),
            observation(
                3,
                ObservationEvent::Sample {
                    ts_ns: 2,
                    core_id: 0,
                    context_id: Some("task-a".to_owned()),
                    function_id: Some("cold".to_owned()),
                    address: Some(0x2000),
                    weight_ns: Some(1),
                },
            ),
            observation(
                4,
                ObservationEvent::Counter {
                    ts_ns: 2,
                    core_id: None,
                    context_id: None,
                    counter_id: "heap.used".to_owned(),
                    value: 10.0,
                    args: Properties::new(),
                },
            ),
            observation(
                5,
                ObservationEvent::Counter {
                    ts_ns: 3,
                    core_id: None,
                    context_id: None,
                    counter_id: "heap.used".to_owned(),
                    value: 20.0,
                    args: Properties::new(),
                },
            ),
            observation(
                6,
                ObservationEvent::Counter {
                    ts_ns: 4,
                    core_id: None,
                    context_id: None,
                    counter_id: "stack.high_water".to_owned(),
                    value: 512.0,
                    args: Properties::new(),
                },
            ),
            observation(
                7,
                ObservationEvent::Counter {
                    ts_ns: 5,
                    core_id: None,
                    context_id: None,
                    counter_id: "ram.used".to_owned(),
                    value: 4096.0,
                    args: Properties::new(),
                },
            ),
        ],
    );

    assert!(result.hotspots.functions.is_empty());
    assert_eq!(result.hotspots.sampling.len(), 2);
    assert_eq!(
        result.hotspots.sampling[0].function_id.as_deref(),
        Some("hot")
    );
    assert_eq!(result.hotspots.sampling[0].estimated_share, 0.75);

    let heap = result
        .summary
        .resources
        .by_class(ResourceClass::Heap)
        .next()
        .unwrap();
    assert_eq!(heap.sample_count, 2);
    assert_eq!(heap.min, 10.0);
    assert_eq!(heap.max, 20.0);
    assert_eq!(heap.mean, 15.0);
    assert_eq!(heap.latest, 20.0);
    assert_eq!(
        result
            .summary
            .resources
            .by_class(ResourceClass::Stack)
            .count(),
        1
    );
    assert_eq!(
        result
            .summary
            .resources
            .by_class(ResourceClass::Ram)
            .count(),
        1
    );
}

#[test]
fn overflow_and_elf_mismatch_are_invalid_health_facts() {
    let policy = HealthPolicy::default();
    for code in [
        "overflow",
        "elf_mismatch",
        "truncated_input",
        "malformed_input",
        "flow_error",
        "timestamp_discontinuity",
        "program_flow_unclosed",
    ] {
        let report = policy.evaluate(
            "health",
            &[HealthObservation {
                code: code.to_owned(),
                source: "parser".to_owned(),
                artifact_id: None,
                record: Some(1),
                start_ns: Some(0),
                end_ns: Some(1),
                evidence: Properties::from([("fact".to_owned(), json!(true))]),
            }],
            &AnalysisCapabilities::default(),
        );
        assert_eq!(report.verdict, HealthVerdict::Invalid, "code={code}");
        assert!(!report.metric_support.active.is_available());
    }
}

#[test]
fn health_observation_limit_retains_one_invalid_truncation_sentinel() {
    let config = AnalyzerConfig {
        capabilities: AnalysisCapabilities::exact_program_flow(),
        max_health_observations: 3,
        ..AnalyzerConfig::default()
    };
    let mut analyzer = Analyzer::new("bounded-health", config);
    for record in 0..10 {
        analyzer.record_health_observation(HealthObservation {
            code: "trace_gap".to_owned(),
            source: "fuzzer".to_owned(),
            artifact_id: None,
            record: Some(record),
            start_ns: Some(record as i64),
            end_ns: Some(record as i64),
            evidence: Properties::new(),
        });
    }

    let result = analyzer.finish(None).unwrap();
    assert_eq!(result.health.verdict, HealthVerdict::Invalid);
    assert_eq!(result.health.observations.len(), 3);
    let sentinel = result
        .health
        .observations
        .iter()
        .find(|observation| observation.code == "diagnostics_truncated")
        .unwrap();
    assert_eq!(sentinel.evidence["limit"], json!(3));
    assert_eq!(sentinel.evidence["dropped_observations"], json!(8));
    assert!(
        result
            .health
            .issues
            .iter()
            .any(|issue| issue.code == "diagnostics_truncated")
    );
}

#[test]
fn receipt_support_levels_are_preserved_without_promotion_to_exact() {
    let capabilities = AnalysisCapabilities {
        function_events: MetricSupportEntry {
            support: MetricSupportLevel::Inferred,
            reasons: vec!["decoder_reconstructed_calls".to_owned()],
        },
        context_switches: MetricSupportEntry::new(MetricSupportLevel::Exact),
        interrupt_events: MetricSupportEntry {
            support: MetricSupportLevel::Statistical,
            reasons: vec!["sampled_interrupts".to_owned()],
        },
        samples: MetricSupportEntry {
            support: MetricSupportLevel::Statistical,
            reasons: vec!["pc_sampling".to_owned()],
        },
        resource_counters: MetricSupportEntry::new(MetricSupportLevel::Exact),
    };
    let report = HealthPolicy::default().evaluate("support", &[], &capabilities);

    assert_eq!(report.verdict, HealthVerdict::Valid);
    assert_eq!(
        report.metric_support.function_timeline.support,
        MetricSupportLevel::Inferred
    );
    assert_eq!(
        report.metric_support.isr_timeline.support,
        MetricSupportLevel::Statistical
    );
    assert_eq!(
        report.metric_support.active.support,
        MetricSupportLevel::Statistical
    );
    assert_eq!(
        report.metric_support.self_time.support,
        MetricSupportLevel::Statistical
    );
    assert!(
        report
            .metric_support
            .active
            .reasons
            .iter()
            .any(|reason| reason == "sampled_interrupts")
    );
    assert!(report.validate().is_ok());
}

#[test]
fn default_capabilities_are_fail_closed_until_receipt_mapping() {
    let report =
        HealthPolicy::default().evaluate("fail-closed", &[], &AnalysisCapabilities::default());

    assert_eq!(
        report.metric_support.function_timeline.support,
        MetricSupportLevel::Unavailable
    );
    assert_eq!(
        report.metric_support.call_count.support,
        MetricSupportLevel::Unavailable
    );
    assert_eq!(
        report.metric_support.active.support,
        MetricSupportLevel::Unavailable
    );
    assert!(
        report
            .metric_support
            .active
            .reasons
            .iter()
            .any(|reason| reason.starts_with("capture_receipt_missing"))
    );
    assert!(report.validate().is_ok());
}

#[test]
fn empty_capture_health_identity_is_replaced_by_invalid_diagnostic() {
    let config = AnalyzerConfig {
        capabilities: AnalysisCapabilities::exact_program_flow(),
        ..AnalyzerConfig::default()
    };
    let mut analyzer = Analyzer::new("health-identity", config);
    analyzer.record_health_observation(HealthObservation {
        code: String::new(),
        source: String::new(),
        artifact_id: None,
        record: Some(1),
        start_ns: Some(0),
        end_ns: Some(0),
        evidence: Properties::new(),
    });

    let result = analyzer.finish(None).unwrap();
    assert_eq!(result.health.verdict, HealthVerdict::Invalid);
    assert_eq!(
        result.health.observations[0].code,
        "invalid_health_observation"
    );
    assert_eq!(result.health.observations[0].source, "analyzer");
}

#[test]
fn malformed_custom_span_boundaries_are_invalid_health_facts() {
    let empty = Properties::new();
    let events = vec![
        observation(
            1,
            ObservationEvent::SpanBegin {
                ts_ns: 0,
                core_id: None,
                context_id: Some("task-a".to_owned()),
                span_id: "sync".to_owned(),
                name: "sync work".to_owned(),
                args: empty.clone(),
            },
        ),
        observation(
            2,
            ObservationEvent::SpanBegin {
                ts_ns: 1,
                core_id: None,
                context_id: Some("task-a".to_owned()),
                span_id: "sync".to_owned(),
                name: "duplicate sync work".to_owned(),
                args: empty.clone(),
            },
        ),
        observation(
            3,
            ObservationEvent::SpanEnd {
                ts_ns: 2,
                core_id: None,
                context_id: Some("task-a".to_owned()),
                span_id: "sync".to_owned(),
                args: empty.clone(),
            },
        ),
        observation(
            4,
            ObservationEvent::SpanEnd {
                ts_ns: 3,
                core_id: None,
                context_id: Some("task-a".to_owned()),
                span_id: "sync".to_owned(),
                args: empty.clone(),
            },
        ),
        observation(
            5,
            ObservationEvent::AsyncBegin {
                ts_ns: 4,
                core_id: None,
                context_id: Some("task-a".to_owned()),
                correlation_id: "async".to_owned(),
                name: "async work".to_owned(),
                args: empty.clone(),
            },
        ),
        observation(
            6,
            ObservationEvent::AsyncBegin {
                ts_ns: 5,
                core_id: None,
                context_id: None,
                correlation_id: "async".to_owned(),
                name: "duplicate async work".to_owned(),
                args: empty.clone(),
            },
        ),
        observation(
            7,
            ObservationEvent::AsyncEnd {
                ts_ns: 6,
                core_id: None,
                context_id: None,
                correlation_id: "async".to_owned(),
                args: empty.clone(),
            },
        ),
        observation(
            8,
            ObservationEvent::AsyncEnd {
                ts_ns: 7,
                core_id: None,
                context_id: None,
                correlation_id: "async".to_owned(),
                args: empty.clone(),
            },
        ),
        observation(
            9,
            ObservationEvent::SpanBegin {
                ts_ns: 8,
                core_id: None,
                context_id: None,
                span_id: "unclosed-sync".to_owned(),
                name: "unclosed sync".to_owned(),
                args: empty.clone(),
            },
        ),
        observation(
            10,
            ObservationEvent::AsyncBegin {
                ts_ns: 9,
                core_id: None,
                context_id: None,
                correlation_id: "unclosed-async".to_owned(),
                name: "unclosed async".to_owned(),
                args: empty,
            },
        ),
    ];

    let result = analyze("custom-boundaries", &events);
    assert_eq!(result.health.verdict, HealthVerdict::Invalid);
    let codes = result
        .health
        .issues
        .iter()
        .map(|issue| issue.code.as_str())
        .collect::<BTreeSet<_>>();
    for expected in [
        "duplicate_span_begin",
        "unmatched_span_end",
        "duplicate_async_begin",
        "unmatched_async_end",
        "unclosed_span",
        "unclosed_async",
    ] {
        assert!(codes.contains(expected), "missing health issue {expected}");
    }
}

#[test]
fn matched_custom_span_boundaries_preserve_valid_health() {
    let events = [
        observation(
            1,
            ObservationEvent::SpanBegin {
                ts_ns: 0,
                core_id: None,
                context_id: None,
                span_id: "sync".to_owned(),
                name: "sync".to_owned(),
                args: Properties::new(),
            },
        ),
        observation(
            2,
            ObservationEvent::SpanEnd {
                ts_ns: 1,
                core_id: None,
                context_id: None,
                span_id: "sync".to_owned(),
                args: Properties::new(),
            },
        ),
    ];

    assert_eq!(
        analyze("matched-custom", &events).health.verdict,
        HealthVerdict::Valid
    );
}

proptest! {
    #[test]
    fn virtual_cpu_decomposition_is_preserved(
        run_before_suspend in 1_i64..1_000,
        task_suspension in 1_i64..1_000,
        run_before_isr in 1_i64..1_000,
        isr_duration in 1_i64..1_000,
        run_after_isr in 1_i64..1_000,
    ) {
        let suspend_at = run_before_suspend;
        let resume_at = suspend_at + task_suspension;
        let isr_enter = resume_at + run_before_isr;
        let isr_exit = isr_enter + isr_duration;
        let exit_at = isr_exit + run_after_isr;
        let events = vec![
            observation(1, ObservationEvent::FunctionEnter {
                ts_ns: 0,
                core_id: 0,
                context_id: "task-a".to_owned(),
                function_id: "root".to_owned(),
                frame_id: None,
            }),
            observation(2, ObservationEvent::ContextSwitch {
                ts_ns: suspend_at,
                core_id: 0,
                prev_context_id: Some("task-a".to_owned()),
                next_context_id: "task-b".to_owned(),
                reason: None,
            }),
            observation(3, ObservationEvent::ContextSwitch {
                ts_ns: resume_at,
                core_id: 0,
                prev_context_id: Some("task-b".to_owned()),
                next_context_id: "task-a".to_owned(),
                reason: None,
            }),
            observation(4, ObservationEvent::InterruptEnter {
                ts_ns: isr_enter,
                core_id: 0,
                interrupt_id: "irq-1".to_owned(),
                priority: Some(10),
                activation_id: "irq:1".to_owned(),
            }),
            observation(5, ObservationEvent::InterruptExit {
                ts_ns: isr_exit,
                core_id: 0,
                interrupt_id: "irq-1".to_owned(),
                priority: Some(10),
                activation_id: "irq:1".to_owned(),
            }),
            observation(6, ObservationEvent::FunctionExit {
                ts_ns: exit_at,
                core_id: 0,
                context_id: "task-a".to_owned(),
                function_id: "root".to_owned(),
                frame_id: None,
            }),
        ];
        let result = analyze("property", &events);
        let span = &result.derived.function_spans[0];
        prop_assert!(span.validate().is_ok());
        prop_assert_eq!(span.elapsed_ns, exit_at as u64);
        prop_assert_eq!(span.active_ns, (run_before_suspend + run_before_isr + run_after_isr) as u64);
        prop_assert_eq!(span.preempted_ns, (task_suspension + isr_duration) as u64);
        prop_assert_eq!(span.elapsed_ns, span.active_ns + span.preempted_ns);
        prop_assert!(span.self_active_ns <= span.active_ns);
        prop_assert_eq!(result.health.verdict, HealthVerdict::Valid);
    }
}
