use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::{Value, json};
use t32perf_model::{
    ContextKind, CounterSemantic, CounterSubject, DictionaryEntry, FunctionSpan, HealthVerdict,
    Observation, ObservationDictionary, ObservationEvent, Quality, StackRole,
};
use t32perf_perfetto::{ChromeTraceWriter, ExportError, TraceConfig, export_atomic, write_trace};

static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[test]
fn golden_trace_is_stable_and_valid_json() {
    let dictionary = dictionary();
    let span = function_span();
    let observations = observations();

    let output = write_trace(
        Vec::new(),
        TraceConfig::new("session-a", HealthVerdict::Valid).with_origin_ns(1_000_000),
        [&dictionary],
        [&span],
        &observations,
    )
    .expect("trace should export");
    let actual = String::from_utf8(output).expect("writer emits UTF-8 JSON");
    let expected = include_str!("golden/basic.json").trim_end();

    assert_eq!(actual, expected);
    let document: Value = serde_json::from_str(&actual).expect("golden output must parse");
    assert_eq!(document["displayTimeUnit"], "ns");
    assert_eq!(document["otherData"]["t32perf"]["health_verdict"], "VALID");
    let pids: BTreeSet<_> = document["traceEvents"]
        .as_array()
        .expect("traceEvents is an array")
        .iter()
        .filter_map(|event| event["pid"].as_u64())
        .collect();
    assert_eq!(pids, BTreeSet::from([1]));

    let function = document["traceEvents"]
        .as_array()
        .expect("traceEvents is an array")
        .iter()
        .find(|event| event["cat"] == "function")
        .expect("function slice exists");
    assert_eq!(function["args"]["active_ns"], 900);
    assert_eq!(function["args"]["self_ns"], 700);
    assert_eq!(function["args"]["preempted_ns"], 110);
    assert_eq!(function["args"]["quality"], "inferred");
    assert_eq!(function["args"]["incomplete"], true);
}

#[test]
fn nanoseconds_are_written_as_exact_relative_microseconds() {
    let observations = [Observation::new(
        "source",
        0,
        Quality::Exact,
        ObservationEvent::Instant {
            ts_ns: i64::MAX,
            core_id: None,
            context_id: None,
            name: "edge".to_owned(),
            args: BTreeMap::new(),
        },
    )];
    let output = write_trace(
        Vec::new(),
        TraceConfig::new("session", HealthVerdict::Valid).with_origin_ns(i64::MIN),
        std::iter::empty::<&ObservationDictionary>(),
        std::iter::empty::<&FunctionSpan>(),
        &observations,
    )
    .expect("extreme relative timestamp should export");
    let output = String::from_utf8(output).expect("UTF-8");
    assert!(output.contains(r#""ts":18446744073709551.615"#));

    let negative = [Observation::new(
        "source",
        1,
        Quality::Exact,
        ObservationEvent::Instant {
            ts_ns: -1,
            core_id: None,
            context_id: None,
            name: "pre-trigger".to_owned(),
            args: BTreeMap::new(),
        },
    )];
    let output = write_trace(
        Vec::new(),
        TraceConfig::new("session", HealthVerdict::Valid),
        std::iter::empty::<&ObservationDictionary>(),
        std::iter::empty::<&FunctionSpan>(),
        &negative,
    )
    .expect("negative relative timestamp should export");
    assert!(
        String::from_utf8(output)
            .expect("UTF-8")
            .contains(r#""ts":-0.001"#)
    );
}

#[test]
fn invalid_health_still_produces_a_diagnostic_trace() {
    let output = write_trace(
        Vec::new(),
        TraceConfig::new("invalid-session", HealthVerdict::Invalid),
        std::iter::empty::<&ObservationDictionary>(),
        std::iter::empty::<&FunctionSpan>(),
        std::iter::empty::<&Observation>(),
    )
    .expect("INVALID health is diagnostic, not an export error");
    let document: Value = serde_json::from_slice(&output).expect("diagnostic trace is valid JSON");

    assert_eq!(document["otherData"]["t32perf"]["diagnostic_only"], true);
    assert!(
        document["traceEvents"]
            .as_array()
            .expect("traceEvents")
            .iter()
            .any(|event| event["name"] == "INVALID trace: diagnostic use only")
    );
}

#[test]
fn invalid_model_data_and_writer_state_return_precise_errors() {
    let mut invalid_span = function_span();
    invalid_span.end_ns = invalid_span.start_ns - 1;
    let error = write_trace(
        Vec::new(),
        TraceConfig::new("session-a", HealthVerdict::Valid),
        std::iter::empty::<&ObservationDictionary>(),
        [&invalid_span],
        std::iter::empty::<&Observation>(),
    )
    .expect_err("invalid span must fail");
    assert!(matches!(error, ExportError::InvalidSpan(_)));

    let invalid_counter = Observation::new(
        "source",
        9,
        Quality::Exact,
        ObservationEvent::Counter {
            ts_ns: 0,
            core_id: None,
            context_id: None,
            counter_id: "heap".to_owned(),
            value: f64::NAN,
            args: BTreeMap::new(),
        },
    );
    let error = write_trace(
        Vec::new(),
        TraceConfig::new("session-a", HealthVerdict::Valid),
        std::iter::empty::<&ObservationDictionary>(),
        std::iter::empty::<&FunctionSpan>(),
        [&invalid_counter],
    )
    .expect_err("nonfinite counter must fail");
    assert!(matches!(error, ExportError::InvalidObservation(_)));

    let dictionary = dictionary();
    let instant = &observations()[0];
    let mut writer = ChromeTraceWriter::new(
        Vec::new(),
        TraceConfig::new("session-a", HealthVerdict::Valid),
    )
    .expect("writer starts");
    writer.write_observation(instant).expect("event writes");
    let error = writer
        .register_dictionary(&dictionary)
        .expect_err("late dictionary must fail");
    assert!(matches!(error, ExportError::DictionaryAfterEvents));
}

#[test]
fn every_observation_kind_streams_without_an_event_vector() {
    let properties = BTreeMap::new();
    let events = vec![
        ObservationEvent::FunctionEnter {
            ts_ns: 0,
            core_id: 0,
            context_id: "task-worker".to_owned(),
            function_id: "fn-work".to_owned(),
            frame_id: Some("raw-frame".to_owned()),
        },
        ObservationEvent::FunctionExit {
            ts_ns: 1,
            core_id: 0,
            context_id: "task-worker".to_owned(),
            function_id: "fn-work".to_owned(),
            frame_id: Some("raw-frame".to_owned()),
        },
        ObservationEvent::ContextSwitch {
            ts_ns: 2,
            core_id: 0,
            prev_context_id: None,
            next_context_id: "task-worker".to_owned(),
            reason: Some("ready".to_owned()),
        },
        ObservationEvent::InterruptEnter {
            ts_ns: 3,
            core_id: 0,
            interrupt_id: "irq-1".to_owned(),
            priority: Some(1),
            activation_id: "irq-active".to_owned(),
        },
        ObservationEvent::InterruptExit {
            ts_ns: 4,
            core_id: 0,
            interrupt_id: "irq-1".to_owned(),
            priority: Some(1),
            activation_id: "irq-active".to_owned(),
        },
        ObservationEvent::Sample {
            ts_ns: 5,
            core_id: 0,
            context_id: Some("task-worker".to_owned()),
            function_id: Some("fn-work".to_owned()),
            address: Some(u64::MAX),
            weight_ns: Some(7),
        },
        ObservationEvent::Instant {
            ts_ns: 6,
            core_id: None,
            context_id: None,
            name: "instant".to_owned(),
            args: properties.clone(),
        },
        ObservationEvent::SpanBegin {
            ts_ns: 7,
            core_id: Some(0),
            context_id: Some("task-worker".to_owned()),
            span_id: "sync-1".to_owned(),
            name: "sync work".to_owned(),
            args: properties.clone(),
        },
        ObservationEvent::SpanEnd {
            ts_ns: 8,
            core_id: Some(0),
            context_id: Some("task-worker".to_owned()),
            span_id: "sync-1".to_owned(),
            args: properties.clone(),
        },
        ObservationEvent::AsyncBegin {
            ts_ns: 9,
            core_id: Some(0),
            context_id: Some("task-worker".to_owned()),
            correlation_id: "async:1".to_owned(),
            name: "async work".to_owned(),
            args: properties.clone(),
        },
        ObservationEvent::AsyncEnd {
            ts_ns: 10,
            core_id: None,
            context_id: None,
            correlation_id: "async:1".to_owned(),
            args: properties.clone(),
        },
        ObservationEvent::Counter {
            ts_ns: 11,
            core_id: None,
            context_id: None,
            counter_id: "heap".to_owned(),
            value: 1.0,
            args: properties,
        },
        ObservationEvent::TraceGap {
            ts_ns: 12,
            duration_ns: 1,
            reason: "gap".to_owned(),
        },
        ObservationEvent::Metadata {
            ts_ns: 13,
            key: "clock".to_owned(),
            value: json!({"hz": 100_000_000}),
        },
    ];
    let observations = events
        .into_iter()
        .enumerate()
        .map(|(sequence, event)| {
            Observation::new("source:a", sequence as u64, Quality::Exact, event)
        })
        .collect::<Vec<_>>();
    let dictionary = dictionary();
    let output = write_trace(
        Vec::new(),
        TraceConfig::new("session-a", HealthVerdict::Valid).with_source_function_events(true),
        [&dictionary],
        std::iter::empty::<&FunctionSpan>(),
        &observations,
    )
    .expect("every observation kind should export");
    let document: Value = serde_json::from_slice(&output).expect("valid JSON");
    let trace_events = document["traceEvents"].as_array().expect("traceEvents");

    for phase in ["X", "i", "B", "E", "b", "e", "C"] {
        assert!(
            trace_events.iter().any(|event| event["ph"] == phase),
            "phase {phase} missing"
        );
    }
    let async_events = trace_events
        .iter()
        .filter(|event| event["cat"] == "async")
        .collect::<Vec<_>>();
    assert_eq!(async_events.len(), 2);
    assert_eq!(async_events[0]["name"], "async work");
    assert_eq!(async_events[1]["name"], "async work");
    assert_eq!(async_events[0]["id"], async_events[1]["id"]);
}

#[test]
fn atomic_export_commits_only_valid_complete_json() {
    let directory = TestDirectory::new();
    let target = directory.path().join("report.json");
    let dictionary = dictionary();
    let span = function_span();
    let observations = observations();

    export_atomic(
        &target,
        TraceConfig::new("session-a", HealthVerdict::Valid).with_origin_ns(1_000_000),
        [&dictionary],
        [&span],
        &observations,
    )
    .expect("atomic export should commit");
    let committed = fs::read(&target).expect("committed artifact exists");
    serde_json::from_slice::<Value>(&committed).expect("committed artifact is valid JSON");
    assert_no_temporary_files(directory.path(), "report.json");

    let error = export_atomic(
        &target,
        TraceConfig::new("session-a", HealthVerdict::Valid),
        std::iter::empty::<&ObservationDictionary>(),
        std::iter::empty::<&FunctionSpan>(),
        std::iter::empty::<&Observation>(),
    )
    .expect_err("existing artifacts are immutable");
    assert!(matches!(error, ExportError::TargetExists(path) if path == target));
    assert_eq!(fs::read(&target).expect("artifact remains"), committed);

    let failed_target = directory.path().join("failed.json");
    let mut invalid_span = function_span();
    invalid_span.elapsed_ns += 1;
    let error = export_atomic(
        &failed_target,
        TraceConfig::new("session-a", HealthVerdict::Valid),
        std::iter::empty::<&ObservationDictionary>(),
        [&invalid_span],
        std::iter::empty::<&Observation>(),
    )
    .expect_err("invalid input must not commit");
    assert!(matches!(error, ExportError::InvalidSpan(_)));
    assert!(!failed_target.exists());
    assert_no_temporary_files(directory.path(), "failed.json");
}

#[test]
fn isr_tracks_are_core_scoped_while_task_tracks_survive_migration() {
    let mut dictionary = dictionary();
    dictionary.entries.push(DictionaryEntry::DefineContext {
        id: "irq-shared".to_owned(),
        kind: ContextKind::Isr,
        name: "Shared IRQ".to_owned(),
        core_id: None,
        priority: Some(10),
    });
    let events = [
        ObservationEvent::Instant {
            ts_ns: 0,
            core_id: Some(0),
            context_id: Some("task-worker".to_owned()),
            name: "task on core 0".to_owned(),
            args: BTreeMap::new(),
        },
        ObservationEvent::Instant {
            ts_ns: 1,
            core_id: Some(1),
            context_id: Some("task-worker".to_owned()),
            name: "task on core 1".to_owned(),
            args: BTreeMap::new(),
        },
        ObservationEvent::InterruptEnter {
            ts_ns: 2,
            core_id: 0,
            interrupt_id: "irq-shared".to_owned(),
            priority: Some(10),
            activation_id: "core-0".to_owned(),
        },
        ObservationEvent::InterruptExit {
            ts_ns: 3,
            core_id: 0,
            interrupt_id: "irq-shared".to_owned(),
            priority: Some(10),
            activation_id: "core-0".to_owned(),
        },
        ObservationEvent::InterruptEnter {
            ts_ns: 4,
            core_id: 1,
            interrupt_id: "irq-shared".to_owned(),
            priority: Some(10),
            activation_id: "core-1".to_owned(),
        },
        ObservationEvent::InterruptExit {
            ts_ns: 5,
            core_id: 1,
            interrupt_id: "irq-shared".to_owned(),
            priority: Some(10),
            activation_id: "core-1".to_owned(),
        },
    ];
    let observations = events
        .into_iter()
        .enumerate()
        .map(|(sequence, event)| Observation::new("source", sequence as u64, Quality::Exact, event))
        .collect::<Vec<_>>();

    let first = write_trace(
        Vec::new(),
        TraceConfig::new("session-a", HealthVerdict::Valid),
        [&dictionary],
        std::iter::empty::<&FunctionSpan>(),
        &observations,
    )
    .unwrap();
    let second = write_trace(
        Vec::new(),
        TraceConfig::new("session-a", HealthVerdict::Valid),
        [&dictionary],
        std::iter::empty::<&FunctionSpan>(),
        &observations,
    )
    .unwrap();
    assert_eq!(first, second, "track allocation must be deterministic");

    let document: Value = serde_json::from_slice(&first).unwrap();
    let trace_events = document["traceEvents"].as_array().unwrap();
    let task_tids = trace_events
        .iter()
        .filter(|event| event["cat"] == "custom")
        .map(|event| event["tid"].as_u64().unwrap())
        .collect::<BTreeSet<_>>();
    let interrupt_tids = trace_events
        .iter()
        .filter(|event| event["cat"] == "interrupt")
        .map(|event| event["tid"].as_u64().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(task_tids.len(), 1, "task migration keeps one context track");
    assert_eq!(
        interrupt_tids.len(),
        2,
        "each core gets a distinct ISR track"
    );
    assert!(task_tids.is_disjoint(&interrupt_tids));
}

#[test]
fn resource_counter_tracks_are_stable_by_semantic_subject_and_preserve_observation_context() {
    let semantic = CounterSemantic::new(CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES).unwrap();
    let allocator_a = CounterSubject::Allocator {
        allocator_id: "allocator-a".to_owned(),
    };
    let allocator_b = CounterSubject::Allocator {
        allocator_id: "allocator-b".to_owned(),
    };
    let mut dictionary = ObservationDictionary::new("resource-counters");
    dictionary.entries = vec![
        DictionaryEntry::DefineCounter {
            id: "opaque:7f3a".to_owned(),
            name: "Allocated bytes A".to_owned(),
            unit: Some("bytes".to_owned()),
            description: Some("Allocator A usage".to_owned()),
            semantic: Some(semantic.clone()),
            subject: Some(allocator_a.clone()),
        },
        DictionaryEntry::DefineCounter {
            id: "opaque:91bc".to_owned(),
            name: "Allocated bytes B".to_owned(),
            unit: Some("bytes".to_owned()),
            description: None,
            semantic: Some(semantic.clone()),
            subject: Some(allocator_b.clone()),
        },
    ];
    dictionary.validate().unwrap();
    let observations = [
        Observation::new(
            "source",
            0,
            Quality::Exact,
            ObservationEvent::Counter {
                ts_ns: 1_001,
                core_id: Some(0),
                context_id: Some("task-a".to_owned()),
                counter_id: "opaque:7f3a".to_owned(),
                value: 10.0,
                args: BTreeMap::new(),
            },
        ),
        Observation::new(
            "source",
            1,
            Quality::Exact,
            ObservationEvent::Counter {
                ts_ns: 1_002,
                core_id: Some(1),
                context_id: Some("task-b".to_owned()),
                counter_id: "opaque:7f3a".to_owned(),
                value: 11.0,
                args: BTreeMap::new(),
            },
        ),
        Observation::new(
            "source",
            2,
            Quality::Exact,
            ObservationEvent::Counter {
                ts_ns: 1_003,
                core_id: Some(0),
                context_id: Some("task-a".to_owned()),
                counter_id: "opaque:91bc".to_owned(),
                value: 20.0,
                args: BTreeMap::new(),
            },
        ),
    ];

    let output = write_trace(
        Vec::new(),
        TraceConfig::new("resource-counters", HealthVerdict::Valid).with_origin_ns(1_000),
        [&dictionary],
        std::iter::empty::<&FunctionSpan>(),
        &observations,
    )
    .unwrap();
    let document: Value = serde_json::from_slice(&output).unwrap();
    let trace_events = document["traceEvents"].as_array().unwrap();
    let counters = trace_events
        .iter()
        .filter(|event| event["cat"] == "counter")
        .collect::<Vec<_>>();
    assert_eq!(counters.len(), 3);

    let allocator_a_tid = counters[0]["tid"].as_u64().unwrap();
    assert_eq!(counters[1]["tid"], allocator_a_tid);
    assert_ne!(counters[2]["tid"], allocator_a_tid);
    assert_eq!(counters[0]["ts"], json!(0.001));
    assert_eq!(counters[1]["ts"], json!(0.002));
    assert_eq!(counters[2]["ts"], json!(0.003));

    let metadata = &counters[0]["t32perf"];
    assert_eq!(metadata["counter_id"], "opaque:7f3a");
    assert_eq!(metadata["semantic"], semantic.as_str());
    assert_eq!(
        metadata["subject"],
        serde_json::to_value(&allocator_a).unwrap()
    );
    assert_eq!(metadata["unit"], "bytes");
    assert_eq!(metadata["core_id"], 0);
    assert_eq!(metadata["context_id"], "task-a");
    assert_eq!(counters[1]["t32perf"]["core_id"], 1);
    assert_eq!(counters[1]["t32perf"]["context_id"], "task-b");

    let track_name = trace_events
        .iter()
        .find(|event| event["name"] == "thread_name" && event["tid"] == allocator_a_tid)
        .unwrap()["args"]["name"]
        .as_str()
        .unwrap();
    assert_eq!(
        track_name,
        "Allocator allocator-a: heap.current_allocated_bytes"
    );
    assert!(!track_name.contains("opaque:7f3a"));
}

#[test]
fn resource_counter_subject_variants_get_distinct_descriptive_tracks() {
    let stack_semantic = CounterSemantic::new(CounterSemantic::STACK_CURRENT_USED_BYTES).unwrap();
    let entries = [
        (
            "task-stack",
            CounterSubject::Stack {
                stack_id: "task-stack-physical".to_owned(),
                role: StackRole::Task,
                context_id: Some("task-worker".to_owned()),
                core_id: None,
            },
        ),
        (
            "isr-stack",
            CounterSubject::Stack {
                stack_id: "isr-stack-physical".to_owned(),
                role: StackRole::Isr,
                context_id: Some("irq-timer".to_owned()),
                core_id: Some(0),
            },
        ),
        (
            "msp-stack",
            CounterSubject::Stack {
                stack_id: "msp-0".to_owned(),
                role: StackRole::Msp,
                context_id: None,
                core_id: Some(0),
            },
        ),
        (
            "psp-stack",
            CounterSubject::Stack {
                stack_id: "psp-0".to_owned(),
                role: StackRole::Psp,
                context_id: None,
                core_id: Some(0),
            },
        ),
    ];
    let mut dictionary = ObservationDictionary::new("subject-variants");
    dictionary.entries = vec![
        DictionaryEntry::DefineContext {
            id: "task-worker".to_owned(),
            kind: ContextKind::Task,
            name: "Worker".to_owned(),
            core_id: Some(0),
            priority: Some(5),
        },
        DictionaryEntry::DefineContext {
            id: "irq-timer".to_owned(),
            kind: ContextKind::Isr,
            name: "Timer IRQ".to_owned(),
            core_id: Some(0),
            priority: Some(1),
        },
    ];
    dictionary.entries.extend(
        entries
            .iter()
            .map(|(id, subject)| DictionaryEntry::DefineCounter {
                id: (*id).to_owned(),
                name: (*id).to_owned(),
                unit: Some("bytes".to_owned()),
                description: None,
                semantic: Some(stack_semantic.clone()),
                subject: Some(subject.clone()),
            }),
    );
    dictionary.entries.extend([
        DictionaryEntry::DefineCounter {
            id: "memory-region".to_owned(),
            name: "Memory region".to_owned(),
            unit: Some("bytes".to_owned()),
            description: None,
            semantic: Some(CounterSemantic::new(CounterSemantic::RAM_CURRENT_USED_BYTES).unwrap()),
            subject: Some(CounterSubject::MemoryRegion {
                region_id: "sram-1".to_owned(),
            }),
        },
        DictionaryEntry::DefineCounter {
            id: "trace-buffer".to_owned(),
            name: "Trace buffer".to_owned(),
            unit: Some("bytes".to_owned()),
            description: None,
            semantic: Some(
                CounterSemantic::new(CounterSemantic::TRACE_BUFFER_CURRENT_USED_BYTES).unwrap(),
            ),
            subject: Some(CounterSubject::TraceBuffer {
                buffer_id: "etm-0".to_owned(),
                core_id: Some(0),
            }),
        },
        DictionaryEntry::DefineCounter {
            id: "custom-resource".to_owned(),
            name: "Custom resource".to_owned(),
            unit: Some("count".to_owned()),
            description: None,
            semantic: Some(CounterSemantic::new("vendor.queue_depth").unwrap()),
            subject: Some(CounterSubject::Custom {
                namespace: "vendor".to_owned(),
                id: "queue-a".to_owned(),
            }),
        },
    ]);
    dictionary.validate().unwrap();
    let counter_ids = [
        "task-stack",
        "isr-stack",
        "msp-stack",
        "psp-stack",
        "memory-region",
        "trace-buffer",
        "custom-resource",
    ];
    let observations = counter_ids
        .into_iter()
        .enumerate()
        .map(|(sequence, counter_id)| {
            Observation::new(
                "source",
                sequence as u64,
                Quality::Exact,
                ObservationEvent::Counter {
                    ts_ns: sequence as i64,
                    core_id: None,
                    context_id: None,
                    counter_id: counter_id.to_owned(),
                    value: sequence as f64,
                    args: BTreeMap::new(),
                },
            )
        })
        .collect::<Vec<_>>();

    let output = write_trace(
        Vec::new(),
        TraceConfig::new("subject-variants", HealthVerdict::Valid),
        [&dictionary],
        std::iter::empty::<&FunctionSpan>(),
        &observations,
    )
    .unwrap();
    let document: Value = serde_json::from_slice(&output).unwrap();
    let trace_events = document["traceEvents"].as_array().unwrap();
    let tids = trace_events
        .iter()
        .filter(|event| event["cat"] == "counter")
        .map(|event| event["tid"].as_u64().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(tids.len(), counter_ids.len());
    let track_names = trace_events
        .iter()
        .filter(|event| event["name"] == "thread_name")
        .filter_map(|event| event["args"]["name"].as_str())
        .collect::<BTreeSet<_>>();
    for fragment in [
        "Task stack task-stack-physical (Worker)",
        "ISR stack isr-stack-physical (Timer IRQ) (Core 0)",
        "MSP stack msp-0 (Core 0)",
        "PSP stack psp-0 (Core 0)",
        "Memory region sram-1",
        "Trace buffer etm-0 (Core 0)",
        "Custom resource vendor:queue-a",
    ] {
        assert!(
            track_names.iter().any(|name| name.starts_with(fragment)),
            "missing resource counter track {fragment}"
        );
    }
}

#[test]
fn generic_counters_keep_observation_context_and_core_tracks() {
    let dictionary = dictionary();
    let observations = [
        Observation::new(
            "source",
            0,
            Quality::Exact,
            ObservationEvent::Instant {
                ts_ns: 0,
                core_id: Some(0),
                context_id: Some("task-worker".to_owned()),
                name: "context marker".to_owned(),
                args: BTreeMap::new(),
            },
        ),
        Observation::new(
            "source",
            1,
            Quality::Exact,
            ObservationEvent::Counter {
                ts_ns: 1,
                core_id: Some(0),
                context_id: Some("task-worker".to_owned()),
                counter_id: "heap".to_owned(),
                value: 1.0,
                args: BTreeMap::new(),
            },
        ),
        Observation::new(
            "source",
            2,
            Quality::Exact,
            ObservationEvent::Instant {
                ts_ns: 2,
                core_id: Some(1),
                context_id: None,
                name: "core marker".to_owned(),
                args: BTreeMap::new(),
            },
        ),
        Observation::new(
            "source",
            3,
            Quality::Exact,
            ObservationEvent::Counter {
                ts_ns: 3,
                core_id: Some(1),
                context_id: None,
                counter_id: "heap".to_owned(),
                value: 2.0,
                args: BTreeMap::new(),
            },
        ),
    ];
    let output = write_trace(
        Vec::new(),
        TraceConfig::new("session-a", HealthVerdict::Valid),
        [&dictionary],
        std::iter::empty::<&FunctionSpan>(),
        &observations,
    )
    .unwrap();
    let document: Value = serde_json::from_slice(&output).unwrap();
    let trace_events = document["traceEvents"].as_array().unwrap();
    let event = |name: &str| {
        trace_events
            .iter()
            .find(|event| event["name"] == name)
            .unwrap()
    };
    let counters = trace_events
        .iter()
        .filter(|event| event["cat"] == "counter")
        .collect::<Vec<_>>();
    assert_eq!(counters[0]["tid"], event("context marker")["tid"]);
    assert_eq!(counters[1]["tid"], event("core marker")["tid"]);
    assert_ne!(counters[0]["tid"], counters[1]["tid"]);
    assert_eq!(counters[0]["t32perf"]["core_id"], 0);
    assert_eq!(counters[0]["t32perf"]["context_id"], "task-worker");
    assert!(counters[0]["t32perf"].get("semantic").is_none());
    assert!(counters[0]["t32perf"].get("subject").is_none());
}

#[test]
fn unmatched_and_unclosed_custom_boundaries_are_writer_errors() {
    let unmatched_sync = Observation::new(
        "source",
        0,
        Quality::Exact,
        ObservationEvent::SpanEnd {
            ts_ns: 0,
            core_id: None,
            context_id: None,
            span_id: "missing".to_owned(),
            args: BTreeMap::new(),
        },
    );
    let mut writer = ChromeTraceWriter::new(
        Vec::new(),
        TraceConfig::new("session", HealthVerdict::Valid),
    )
    .unwrap();
    assert!(matches!(
        writer.write_observation(&unmatched_sync),
        Err(ExportError::UnmatchedSpanEnd { .. })
    ));

    let unmatched_async = Observation::new(
        "source",
        1,
        Quality::Exact,
        ObservationEvent::AsyncEnd {
            ts_ns: 1,
            core_id: None,
            context_id: None,
            correlation_id: "missing".to_owned(),
            args: BTreeMap::new(),
        },
    );
    assert!(matches!(
        writer.write_observation(&unmatched_async),
        Err(ExportError::UnmatchedAsyncEnd { .. })
    ));

    let open_sync = Observation::new(
        "source",
        2,
        Quality::Exact,
        ObservationEvent::SpanBegin {
            ts_ns: 2,
            core_id: None,
            context_id: None,
            span_id: "open".to_owned(),
            name: "open".to_owned(),
            args: BTreeMap::new(),
        },
    );
    writer.write_observation(&open_sync).unwrap();
    assert!(matches!(
        writer.finish(),
        Err(ExportError::UnclosedCustomSpans {
            sync_count: 1,
            async_count: 0
        })
    ));
}

#[test]
fn writer_open_custom_span_state_is_explicitly_bounded() {
    let mut writer = ChromeTraceWriter::new(
        Vec::new(),
        TraceConfig::new("session", HealthVerdict::Invalid).with_max_open_custom_spans(1),
    )
    .unwrap();
    let begin = |sequence, span_id: &str| {
        Observation::new(
            "source",
            sequence,
            Quality::Exact,
            ObservationEvent::SpanBegin {
                ts_ns: sequence as i64,
                core_id: None,
                context_id: None,
                span_id: span_id.to_owned(),
                name: span_id.to_owned(),
                args: BTreeMap::new(),
            },
        )
    };
    writer.write_observation(&begin(0, "first")).unwrap();
    assert!(matches!(
        writer.write_observation(&begin(1, "second")),
        Err(ExportError::OpenCustomSpanLimitExceeded { limit: 1 })
    ));
}

fn dictionary() -> ObservationDictionary {
    let mut dictionary = ObservationDictionary::new("session-a");
    dictionary.entries = vec![
        DictionaryEntry::DefineContext {
            id: "core-0".to_owned(),
            kind: ContextKind::Core,
            name: "CPU 0".to_owned(),
            core_id: Some(0),
            priority: None,
        },
        DictionaryEntry::DefineContext {
            id: "task-worker".to_owned(),
            kind: ContextKind::Task,
            name: "Worker".to_owned(),
            core_id: Some(0),
            priority: Some(5),
        },
        DictionaryEntry::DefineFunction {
            id: "fn-work".to_owned(),
            name: "work()".to_owned(),
            module: Some("firmware".to_owned()),
            address: Some(0x1234),
            file: Some("src/work.c".to_owned()),
            line: Some(42),
        },
        DictionaryEntry::DefineCounter {
            id: "heap".to_owned(),
            name: "Heap allocated".to_owned(),
            unit: Some("bytes".to_owned()),
            description: Some("Current allocator usage".to_owned()),
            semantic: None,
            subject: None,
        },
    ];
    dictionary
}

fn function_span() -> FunctionSpan {
    FunctionSpan {
        source_id: "etm".to_owned(),
        source_seq_start: Some(10),
        source_seq_end: Some(11),
        core_id: 0,
        context_id: "task-worker".to_owned(),
        function_id: "fn-work".to_owned(),
        frame_id: Some("frame-1".to_owned()),
        start_ns: 1_000_001,
        end_ns: 1_001_011,
        elapsed_ns: 1_010,
        active_ns: 900,
        self_active_ns: 700,
        preempted_ns: 110,
        quality: Quality::Inferred,
        incomplete: true,
    }
}

fn observations() -> Vec<Observation> {
    let mut marker_args = BTreeMap::new();
    marker_args.insert("state".to_owned(), json!("ready"));
    vec![
        Observation::new(
            "itm",
            20,
            Quality::Exact,
            ObservationEvent::Instant {
                ts_ns: 1_001_012,
                core_id: Some(0),
                context_id: Some("task-worker".to_owned()),
                name: "marker".to_owned(),
                args: marker_args,
            },
        ),
        Observation::new(
            "itm",
            21,
            Quality::Exact,
            ObservationEvent::Counter {
                ts_ns: 1_001_020,
                core_id: Some(0),
                context_id: Some("task-worker".to_owned()),
                counter_id: "heap".to_owned(),
                value: 42.5,
                args: BTreeMap::new(),
            },
        ),
        Observation::new(
            "itm",
            22,
            Quality::Inferred,
            ObservationEvent::TraceGap {
                ts_ns: 1_001_100,
                duration_ns: 2_001,
                reason: "transport_overflow".to_owned(),
            },
        ),
    ]
}

fn assert_no_temporary_files(directory: &Path, target_name: &str) {
    let prefix = format!("{target_name}.tmp-");
    let temporary = fs::read_dir(directory)
        .expect("test directory exists")
        .filter_map(Result::ok)
        .any(|entry| entry.file_name().to_string_lossy().starts_with(&prefix));
    assert!(!temporary, "temporary artifact leaked");
}

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "t32perf-perfetto-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("unique test directory should be creatable");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
