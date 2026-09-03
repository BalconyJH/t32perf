use t32perf_analysis::{AnalysisCapabilities, AnalysisResult, Analyzer, AnalyzerConfig};
use t32perf_model::{Observation, ObservationEvent, Quality};

fn run_stream(event_count: u64, drain_batch_spans: Option<usize>) -> (AnalysisResult, u64, usize) {
    assert_eq!(event_count % 2, 0);
    let config = AnalyzerConfig {
        capabilities: AnalysisCapabilities::exact_program_flow(),
        ..AnalyzerConfig::default()
    };
    let mut analyzer = Analyzer::new("scale", config);
    let mut drained_span_count = 0_u64;
    let mut max_resident_spans = 0_usize;

    for activation in 0..event_count / 2 {
        let enter_sequence = activation * 2 + 1;
        let exit_sequence = enter_sequence + 1;
        analyzer
            .ingest(&Observation::new(
                "scale",
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
                "scale",
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
        max_resident_spans = max_resident_spans.max(analyzer.resident_completed_span_count());
        if drain_batch_spans.is_some_and(|batch| analyzer.resident_completed_span_count() >= batch)
        {
            drained_span_count += analyzer.drain_completed_spans().len() as u64;
        }
    }

    let result = analyzer.finish(None).unwrap();
    (result, drained_span_count, max_resident_spans)
}

fn assert_aggregate(result: &AnalysisResult, expected_events: u64) {
    let expected_spans = expected_events / 2;
    assert_eq!(result.summary.observation_count, expected_events);
    assert_eq!(result.summary.function_span_count, expected_spans);
    assert_eq!(result.summary.incomplete_function_span_count, 0);
    let hotspot = result
        .hotspots
        .functions
        .iter()
        .find(|hotspot| hotspot.function_id == "work")
        .unwrap();
    assert_eq!(hotspot.count, expected_spans);
    assert_eq!(hotspot.inclusive_active_ns, expected_spans);
    assert_eq!(hotspot.self_active_ns, expected_spans);
    assert_eq!(hotspot.min_active_ns, 1);
    assert_eq!(hotspot.max_active_ns, 1);
    assert_eq!(hotspot.avg_active_ns, 1);
}

#[test]
fn draining_100k_events_matches_undrained_aggregation() {
    let (undrained, _, _) = run_stream(100_000, None);
    let (drained, drained_count, max_resident) = run_stream(100_000, Some(1_024));

    assert_aggregate(&undrained, 100_000);
    assert_aggregate(&drained, 100_000);
    assert_eq!(drained.hotspots, undrained.hotspots);
    assert_eq!(drained.summary, undrained.summary);
    assert_eq!(
        drained_count + drained.derived.function_spans.len() as u64,
        50_000
    );
    assert!(max_resident <= 1_024);
    assert_eq!(undrained.derived.function_spans.len(), 50_000);
}

#[test]
fn draining_one_million_events_keeps_resident_span_queue_bounded() {
    let (result, drained_count, max_resident) = run_stream(1_000_000, Some(2_048));

    assert_aggregate(&result, 1_000_000);
    assert_eq!(
        drained_count + result.derived.function_spans.len() as u64,
        500_000
    );
    assert!(max_resident <= 2_048);
    assert!(result.derived.function_spans.len() < 2_048);
}
