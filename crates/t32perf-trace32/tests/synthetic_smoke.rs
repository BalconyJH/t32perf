use std::io;

use t32perf_model::{ObservationDictionary, ObservationStreamHeader};
use t32perf_trace32::{
    LineLimits, NdjsonObservationWriter, ObservationSource, SourceError, SyntheticConfig,
    SyntheticSource,
};

#[test]
fn synthetic_generation_is_byte_for_byte_deterministic() {
    let mut config = SyntheticConfig::new("synthetic", 1_000);
    config.start_ns = -100;
    config.step_ns = 7;
    config.source_seq_start = 50;
    config.order_key_start = Some(10_000);

    let collect = |config: SyntheticConfig| {
        let mut source = SyntheticSource::new(config).unwrap();
        let mut records = Vec::new();
        while let Some(record) = source.next_observation().unwrap() {
            records.push(serde_json::to_vec(&record.observation).unwrap());
        }
        records
    };
    assert_eq!(collect(config.clone()), collect(config));
}

#[test]
fn streaming_smoke_bench_writes_one_hundred_thousand_records_to_sink() {
    let count = 100_000;
    let source_config = SyntheticConfig::new("smoke", count);
    let mut source = SyntheticSource::new(source_config).unwrap();
    let header = ObservationStreamHeader::ndjson("smoke-session");
    let dictionary = ObservationDictionary::new("smoke-session");
    let mut writer = NdjsonObservationWriter::new(
        io::sink(),
        &header,
        &dictionary,
        LineLimits {
            max_line_bytes: 4096,
            max_records: count + 2,
            ..LineLimits::default()
        },
    )
    .unwrap();
    let mut written = 0;
    while let Some(record) = source.next_observation().unwrap() {
        writer.write_observation(&record.observation).unwrap();
        written += 1;
    }
    writer.finish().unwrap();
    assert_eq!(written, count);
}

#[test]
fn synthetic_ranges_are_rejected_before_generation() {
    let mut config = SyntheticConfig::new("synthetic", 2);
    config.start_ns = i64::MAX;
    config.step_ns = 1;
    assert!(matches!(
        SyntheticSource::new(config),
        Err(SourceError::Invariant { .. })
    ));
}
