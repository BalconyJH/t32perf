use std::{fs::File, io::BufReader, io::Cursor, io::Read, path::Path};

use serde_json::{Value, json};
use t32perf_model::{
    ContextKind, DictionaryEntry, Observation, ObservationDictionary, ObservationEvent,
    ObservationStreamHeader, Properties, Quality,
};
use t32perf_trace32::{
    InputErrorKind, LineLimits, NdjsonErrorKind, NdjsonObservationReader, NdjsonObservationWriter,
    ObservationOrderError,
};

fn instant(sequence: u64, timestamp: i64) -> Observation {
    Observation::new(
        "source-a",
        sequence,
        Quality::Exact,
        ObservationEvent::Instant {
            ts_ns: timestamp,
            core_id: Some(0),
            context_id: None,
            name: "tick".to_owned(),
            args: Properties::new(),
        },
    )
}

fn canonical(observations: &[Observation]) -> Vec<u8> {
    let header = ObservationStreamHeader::ndjson("session-1");
    let dictionary = ObservationDictionary::new("session-1");
    let mut writer =
        NdjsonObservationWriter::new(Vec::new(), &header, &dictionary, LineLimits::default())
            .unwrap();
    for observation in observations {
        writer.write_observation(observation).unwrap();
    }
    writer.finish().unwrap()
}

fn metadata_prefix() -> Vec<u8> {
    canonical(&[])
}

struct GeneratedCanonical {
    dictionary_entries: u64,
    observations: u64,
    next_record: u64,
    pending: Vec<u8>,
    pending_offset: usize,
}

impl GeneratedCanonical {
    fn new(dictionary_entries: u64, observations: u64) -> Self {
        Self {
            dictionary_entries,
            observations,
            next_record: 0,
            pending: Vec::new(),
            pending_offset: 0,
        }
    }

    fn generate_record(&mut self) -> bool {
        let total = 1 + self.dictionary_entries + self.observations;
        if self.next_record >= total {
            return false;
        }
        self.pending = if self.next_record == 0 {
            b"{\"schema\":\"t32perf.observation/v1\",\"session_id\":\"session-1\",\"encoding\":\"ndjson\",\"time_unit\":\"ns\",\"time_origin\":\"session_relative\",\"properties\":{}}\n".to_vec()
        } else if self.next_record <= self.dictionary_entries {
            let index = self.next_record - 1;
            format!(
                "{{\"type\":\"DefineFunction\",\"id\":\"function-{index}\",\"name\":\"namespace::function_{index}\"}}\n"
            )
            .into_bytes()
        } else {
            let index = self.next_record - self.dictionary_entries - 1;
            format!(
                "{{\"source_id\":\"generated\",\"source_seq\":{index},\"quality\":\"exact\",\"type\":\"Instant\",\"ts_ns\":{index},\"name\":\"tick\"}}\n"
            )
            .into_bytes()
        };
        self.pending_offset = 0;
        self.next_record += 1;
        true
    }
}

impl Read for GeneratedCanonical {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.pending_offset == self.pending.len() && !self.generate_record() {
            return Ok(0);
        }
        let remaining = &self.pending[self.pending_offset..];
        let copied = remaining.len().min(output.len());
        output[..copied].copy_from_slice(&remaining[..copied]);
        self.pending_offset += copied;
        Ok(copied)
    }
}

#[test]
fn canonical_roundtrip_survives_one_byte_buffer_boundaries() {
    let observations = vec![instant(1, -5), instant(2, 10), instant(3, 10)];
    let encoded = canonical(&observations);
    assert_eq!(encoded.iter().filter(|byte| **byte == b'\n').count(), 4);

    let input = BufReader::with_capacity(1, Cursor::new(encoded));
    let reader = NdjsonObservationReader::new(input, LineLimits::default()).unwrap();
    assert_eq!(reader.header().session_id, "session-1");
    assert_eq!(reader.dictionary().session_id, "session-1");
    let decoded = reader.collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(decoded, observations);
}

#[test]
fn truncated_final_record_reports_exact_eof_location() {
    let mut encoded = canonical(&[instant(1, 0)]);
    encoded.pop();
    let eof = encoded.len() as u64;
    let error = NdjsonObservationReader::new(Cursor::new(encoded), LineLimits::default())
        .err()
        .expect("truncated first observation");
    assert_eq!(error.location.byte_offset, eof);
    assert_eq!(error.location.line, 2);
    assert_eq!(error.location.record, 1);
    assert_eq!(
        error.kind,
        NdjsonErrorKind::Input(InputErrorKind::TruncatedLine)
    );
}

#[test]
fn invalid_utf8_reports_the_failing_byte() {
    let mut encoded = metadata_prefix();
    let record_start = encoded.len() as u64;
    encoded.extend_from_slice(b"{");
    encoded.push(0xff);
    encoded.extend_from_slice(b"}\n");
    let error = NdjsonObservationReader::new(Cursor::new(encoded), LineLimits::default())
        .err()
        .expect("invalid UTF-8 first observation");
    assert_eq!(error.location.byte_offset, record_start + 1);
    assert_eq!(error.location.line, 2);
    assert_eq!(error.location.record, 1);
    assert_eq!(error.kind, NdjsonErrorKind::InvalidUtf8);
}

#[test]
fn invalid_json_reports_serde_byte_column() {
    let mut encoded = metadata_prefix();
    let bad = br#"{"source_id":}"#;
    let record_start = encoded.len() as u64;
    let expected_column = serde_json::from_slice::<Value>(bad)
        .unwrap_err()
        .column()
        .saturating_sub(1) as u64;
    encoded.extend_from_slice(bad);
    encoded.push(b'\n');
    let error = NdjsonObservationReader::new(Cursor::new(encoded), LineLimits::default())
        .err()
        .expect("invalid JSON first observation");
    assert_eq!(error.location.byte_offset, record_start + expected_column);
    assert!(matches!(error.kind, NdjsonErrorKind::InvalidJson { .. }));
}

#[test]
fn typed_header_error_retains_the_original_serde_column() {
    let bad = br#"{"schema":"t32perf.observation/v1","session_id":42,"encoding":"ndjson","time_unit":"ns","time_origin":"session_relative","properties":{}}"#;
    let expected_column = serde_json::from_slice::<ObservationStreamHeader>(bad)
        .expect_err("typed header error")
        .column()
        .saturating_sub(1) as u64;
    let mut encoded = bad.to_vec();
    encoded.push(b'\n');

    let error = NdjsonObservationReader::new(Cursor::new(encoded), LineLimits::default())
        .err()
        .expect("invalid typed header");

    assert_eq!(error.location.byte_offset, expected_column);
    assert_eq!(error.location.line, 1);
    assert_eq!(error.location.record, 0);
    assert!(matches!(error.kind, NdjsonErrorKind::InvalidJson { .. }));
}

#[test]
fn typed_observation_error_retains_the_original_serde_column() {
    let bad = br#"{"source_id":"source-a","source_seq":"one","quality":"exact","type":"Instant","ts_ns":0,"name":"tick"}"#;
    let expected_column = serde_json::from_slice::<Observation>(bad)
        .expect_err("typed observation error")
        .column()
        .saturating_sub(1) as u64;
    let mut encoded = metadata_prefix();
    let record_start = encoded.len() as u64;
    encoded.extend_from_slice(bad);
    encoded.push(b'\n');

    let error = NdjsonObservationReader::new(Cursor::new(encoded), LineLimits::default())
        .err()
        .expect("invalid typed observation");

    assert_eq!(error.location.byte_offset, record_start + expected_column);
    assert_eq!(error.location.line, 2);
    assert_eq!(error.location.record, 1);
    assert!(matches!(error.kind, NdjsonErrorKind::InvalidJson { .. }));
}

#[test]
fn duplicate_members_are_rejected_in_header_and_observation_properties() {
    let duplicated_header = b"{\"schema\":\"t32perf.observation/v1\",\"session_id\":\"session-1\",\"encoding\":\"ndjson\",\"time_unit\":\"ns\",\"time_origin\":\"session_relative\",\"properties\":{\"producer\":\"first\",\"producer\":\"last\"}}\n";
    let error = NdjsonObservationReader::new(
        Cursor::new(duplicated_header.as_slice()),
        LineLimits::default(),
    )
    .err()
    .expect("duplicate header property");
    assert_eq!(error.location.line, 1);
    assert!(matches!(
        error.kind,
        NdjsonErrorKind::InvalidJson { ref message }
            if message.contains("duplicate JSON object member name `producer`")
    ));

    let mut encoded = metadata_prefix();
    encoded.extend_from_slice(
        b"{\"source_id\":\"source-a\",\"source_seq\":1,\"quality\":\"exact\",\"properties\":{\"mode\":\"first\",\"mode\":\"last\"},\"type\":\"Instant\",\"ts_ns\":0,\"name\":\"tick\"}\n",
    );
    let error = NdjsonObservationReader::new(Cursor::new(encoded), LineLimits::default())
        .err()
        .expect("duplicate observation property");
    assert_eq!(error.location.line, 2);
    assert!(matches!(
        error.kind,
        NdjsonErrorKind::InvalidJson { ref message }
            if message.contains("duplicate JSON object member name `mode`")
    ));
}

#[test]
fn unknown_field_is_rejected_at_its_key() {
    let mut encoded = metadata_prefix();
    let mut value = serde_json::to_value(instant(1, 0)).unwrap();
    value["future_field"] = json!(true);
    let record = serde_json::to_vec(&value).unwrap();
    let relative = record
        .windows(b"\"future_field\"".len())
        .position(|window| window == b"\"future_field\"")
        .unwrap();
    let record_start = encoded.len() as u64;
    encoded.extend_from_slice(&record);
    encoded.push(b'\n');

    let error = NdjsonObservationReader::new(Cursor::new(encoded), LineLimits::default())
        .err()
        .expect("unknown field in first observation");
    assert_eq!(error.location.byte_offset, record_start + relative as u64);
    assert_eq!(
        error.kind,
        NdjsonErrorKind::UnknownField {
            field: "future_field".to_owned()
        }
    );
}

#[test]
fn unknown_schema_major_is_rejected_before_deserialization() {
    let mut header = serde_json::to_value(ObservationStreamHeader::ndjson("session-1")).unwrap();
    header["schema"] = json!("t32perf.observation/v2");
    let mut encoded = serde_json::to_vec(&header).unwrap();
    encoded.push(b'\n');
    let error = NdjsonObservationReader::new(Cursor::new(encoded), LineLimits::default())
        .err()
        .expect("unsupported schema");
    assert_eq!(error.location.line, 1);
    assert_eq!(error.location.record, 0);
    assert!(matches!(
        error.kind,
        NdjsonErrorKind::UnsupportedSchema { .. }
    ));
}

#[test]
fn source_sequence_and_timestamp_order_are_strict() {
    let mut encoded = metadata_prefix();
    for observation in [instant(2, 10), instant(2, 11)] {
        encoded.extend_from_slice(&serde_json::to_vec(&observation).unwrap());
        encoded.push(b'\n');
    }
    let mut reader =
        NdjsonObservationReader::new(Cursor::new(encoded), LineLimits::default()).unwrap();
    assert!(reader.next().unwrap().is_ok());
    let error = reader.next().unwrap().unwrap_err();
    assert!(matches!(
        error.kind,
        NdjsonErrorKind::Ordering(ObservationOrderError::SourceSequence { .. })
    ));

    let mut encoded = metadata_prefix();
    for observation in [instant(1, 10), instant(2, 9)] {
        encoded.extend_from_slice(&serde_json::to_vec(&observation).unwrap());
        encoded.push(b'\n');
    }
    let mut reader =
        NdjsonObservationReader::new(Cursor::new(encoded), LineLimits::default()).unwrap();
    assert!(reader.next().unwrap().is_ok());
    let error = reader.next().unwrap().unwrap_err();
    assert!(matches!(
        error.kind,
        NdjsonErrorKind::Ordering(ObservationOrderError::SourceTimestamp { .. })
    ));
}

#[test]
fn strict_line_and_record_limits_fail_before_unbounded_growth() {
    let encoded = canonical(&[instant(1, 0)]);
    let error = NdjsonObservationReader::new(
        Cursor::new(encoded.clone()),
        LineLimits {
            max_line_bytes: 8,
            max_records: 100,
            ..LineLimits::default()
        },
    )
    .err()
    .expect("line limit");
    assert_eq!(error.location.byte_offset, 8);
    assert!(matches!(
        error.kind,
        NdjsonErrorKind::Input(InputErrorKind::LineTooLong { limit: 8 })
    ));

    let error = NdjsonObservationReader::new(
        Cursor::new(encoded),
        LineLimits {
            max_line_bytes: 1024 * 1024,
            max_records: 1,
            ..LineLimits::default()
        },
    )
    .err()
    .expect("record limit before first observation");
    assert_eq!(error.location.line, 2);
    assert_eq!(error.location.record, 1);
    assert!(matches!(
        error.kind,
        NdjsonErrorKind::Input(InputErrorKind::RecordLimitExceeded { limit: 1 })
    ));
}

#[test]
fn dictionary_entries_are_individually_bounded_records() {
    let header = ObservationStreamHeader::ndjson("session-1");
    let mut dictionary = ObservationDictionary::new("session-1");
    dictionary.entries = vec![
        DictionaryEntry::DefineContext {
            id: "task-main".to_owned(),
            kind: ContextKind::Task,
            name: "Main".to_owned(),
            core_id: Some(0),
            priority: Some(5),
        },
        DictionaryEntry::DefineFunction {
            id: "fn-main".to_owned(),
            name: "main".to_owned(),
            module: None,
            address: Some(0x1000),
            file: None,
            line: None,
        },
        DictionaryEntry::DefineCounter {
            id: "heap".to_owned(),
            name: "Heap".to_owned(),
            unit: Some("bytes".to_owned()),
            description: None,
            semantic: None,
            subject: None,
        },
    ];
    let mut writer = NdjsonObservationWriter::new(
        Vec::new(),
        &header,
        &dictionary,
        LineLimits {
            max_line_bytes: 256,
            max_records: 5,
            ..LineLimits::default()
        },
    )
    .unwrap();
    writer.write_observation(&instant(1, 0)).unwrap();
    let encoded = writer.finish().unwrap();
    let lines = encoded.split(|byte| *byte == b'\n').collect::<Vec<_>>();
    assert_eq!(lines.len(), 6);
    for (line, expected_type) in
        lines[1..4]
            .iter()
            .zip(["DefineContext", "DefineFunction", "DefineCounter"])
    {
        let value: Value = serde_json::from_slice(line).unwrap();
        assert_eq!(value["type"], expected_type);
        assert!(value.get("entries").is_none());
        assert!(value.get("schema").is_none());
    }

    let mut reader = NdjsonObservationReader::new(
        BufReader::with_capacity(1, Cursor::new(encoded)),
        LineLimits::default(),
    )
    .unwrap();
    assert_eq!(reader.dictionary(), &dictionary);
    assert_eq!(reader.next().unwrap().unwrap(), instant(1, 0));
    assert!(reader.next().is_none());
}

#[test]
fn large_dictionary_never_becomes_one_large_physical_line() {
    let header = ObservationStreamHeader::ndjson("session-1");
    let mut dictionary = ObservationDictionary::new("session-1");
    dictionary.entries = (0..20_000)
        .map(|index| DictionaryEntry::DefineFunction {
            id: format!("function-{index}"),
            name: format!("namespace::function_{index}"),
            module: Some("firmware".to_owned()),
            address: Some(0x1000 + index),
            file: None,
            line: None,
        })
        .collect();
    let limits = LineLimits {
        max_line_bytes: 256,
        max_records: 20_001,
        ..LineLimits::default()
    };
    let encoded = NdjsonObservationWriter::new(Vec::new(), &header, &dictionary, limits)
        .unwrap()
        .finish()
        .unwrap();
    assert!(encoded.len() > 1024 * 1024);
    assert!(
        encoded
            .split(|byte| *byte == b'\n')
            .all(|line| line.len() <= limits.max_line_bytes)
    );
    let reader =
        NdjsonObservationReader::new(BufReader::with_capacity(17, Cursor::new(encoded)), limits)
            .unwrap();
    assert_eq!(reader.dictionary().entries.len(), 20_000);
    assert_eq!(reader.count(), 0);
}

#[test]
fn dictionary_entry_and_byte_limits_are_independent_and_location_exact() {
    let header = ObservationStreamHeader::ndjson("session-1");
    let entries = [
        DictionaryEntry::DefineFunction {
            id: "first".to_owned(),
            name: "first".to_owned(),
            module: None,
            address: None,
            file: None,
            line: None,
        },
        DictionaryEntry::DefineFunction {
            id: "second".to_owned(),
            name: "second".to_owned(),
            module: None,
            address: None,
            file: None,
            line: None,
        },
    ];
    let mut encoded = serde_json::to_vec(&header).unwrap();
    encoded.push(b'\n');
    let first = serde_json::to_vec(&entries[0]).unwrap();
    encoded.extend_from_slice(&first);
    encoded.push(b'\n');
    let second_start = encoded.len() as u64;
    encoded.extend_from_slice(&serde_json::to_vec(&entries[1]).unwrap());
    encoded.push(b'\n');

    let error = NdjsonObservationReader::new(
        Cursor::new(encoded.clone()),
        LineLimits {
            max_dictionary_entries: 1,
            ..LineLimits::default()
        },
    )
    .err()
    .expect("independent dictionary entry limit");
    assert_eq!(error.location.byte_offset, second_start);
    assert_eq!(error.location.line, 3);
    assert!(matches!(
        error.kind,
        NdjsonErrorKind::DictionaryEntryLimitExceeded { limit: 1 }
    ));

    let dictionary_bytes = first.len() as u64;
    let header_bytes = serde_json::to_vec(&header).unwrap().len() as u64 + 1;
    let error = NdjsonObservationReader::new(
        Cursor::new(encoded),
        LineLimits {
            max_dictionary_bytes: dictionary_bytes,
            ..LineLimits::default()
        },
    )
    .err()
    .expect("LF crosses independent dictionary byte limit");
    assert_eq!(error.location.byte_offset, header_bytes + dictionary_bytes);
    assert_eq!(error.location.line, 2);
    assert!(matches!(
        error.kind,
        NdjsonErrorKind::DictionaryByteLimitExceeded { limit } if limit == dictionary_bytes
    ));
}

#[test]
fn writer_enforces_dictionary_limits_before_writing_the_rejected_definition() {
    let header = ObservationStreamHeader::ndjson("session-1");
    let mut dictionary = ObservationDictionary::new("session-1");
    dictionary.entries = vec![
        DictionaryEntry::DefineFunction {
            id: "first".to_owned(),
            name: "first".to_owned(),
            module: None,
            address: None,
            file: None,
            line: None,
        },
        DictionaryEntry::DefineFunction {
            id: "second".to_owned(),
            name: "second".to_owned(),
            module: None,
            address: None,
            file: None,
            line: None,
        },
    ];
    let error = NdjsonObservationWriter::new(
        Vec::new(),
        &header,
        &dictionary,
        LineLimits {
            max_dictionary_entries: 1,
            ..LineLimits::default()
        },
    )
    .err()
    .expect("writer dictionary entry limit");
    assert_eq!(error.location.line, 3);
    assert!(matches!(
        error.kind,
        NdjsonErrorKind::DictionaryEntryLimitExceeded { limit: 1 }
    ));
}

#[test]
fn million_observations_with_large_dictionary_are_consumed_streamingly() {
    const DICTIONARY_ENTRIES: u64 = 20_000;
    const OBSERVATIONS: u64 = 1_000_000;
    let generated = GeneratedCanonical::new(DICTIONARY_ENTRIES, OBSERVATIONS);
    let reader = NdjsonObservationReader::new(
        BufReader::with_capacity(4096, generated),
        LineLimits {
            max_line_bytes: 1024,
            max_records: 1 + DICTIONARY_ENTRIES + OBSERVATIONS,
            max_dictionary_entries: DICTIONARY_ENTRIES,
            max_dictionary_bytes: 8 * 1024 * 1024,
        },
    )
    .unwrap();
    assert_eq!(reader.dictionary().entries.len() as u64, DICTIONARY_ENTRIES);
    assert!(reader.dictionary_physical_bytes() < 8 * 1024 * 1024);
    assert_eq!(reader.count() as u64, OBSERVATIONS);
}

#[test]
fn dictionary_hard_limits_are_rejected_at_stream_origin() {
    let error = NdjsonObservationReader::new(
        Cursor::new(metadata_prefix()),
        LineLimits {
            max_dictionary_entries: t32perf_trace32::HARD_MAX_DICTIONARY_ENTRIES + 1,
            ..LineLimits::default()
        },
    )
    .err()
    .expect("dictionary hard limit");
    assert_eq!(error.location.byte_offset, 0);
    assert!(matches!(
        error.kind,
        NdjsonErrorKind::Input(InputErrorKind::DictionaryEntryLimitTooLarge { .. })
    ));
}

#[test]
fn dictionary_is_closed_by_the_first_observation() {
    let mut encoded = canonical(&[instant(1, 0)]);
    let entry = DictionaryEntry::DefineCounter {
        id: "late".to_owned(),
        name: "Late".to_owned(),
        unit: None,
        description: None,
        semantic: None,
        subject: None,
    };
    encoded.extend_from_slice(&serde_json::to_vec(&entry).unwrap());
    encoded.push(b'\n');
    let mut reader =
        NdjsonObservationReader::new(Cursor::new(encoded), LineLimits::default()).unwrap();
    assert!(reader.next().unwrap().is_ok());
    let error = reader.next().unwrap().unwrap_err();
    assert_eq!(error.location.line, 3);
    assert!(matches!(
        error.kind,
        NdjsonErrorKind::DictionaryAfterObservation { .. }
    ));
}

#[test]
fn duplicate_dictionary_id_reports_the_second_definition_line() {
    let header = ObservationStreamHeader::ndjson("session-1");
    let entry = DictionaryEntry::DefineFunction {
        id: "duplicate".to_owned(),
        name: "function".to_owned(),
        module: None,
        address: None,
        file: None,
        line: None,
    };
    let mut encoded = serde_json::to_vec(&header).unwrap();
    encoded.push(b'\n');
    for _ in 0..2 {
        encoded.extend_from_slice(&serde_json::to_vec(&entry).unwrap());
        encoded.push(b'\n');
    }
    let error = NdjsonObservationReader::new(Cursor::new(encoded), LineLimits::default())
        .err()
        .expect("duplicate dictionary ID");
    assert_eq!(error.location.line, 3);
    assert_eq!(error.location.record, 2);
    assert!(matches!(
        error.kind,
        NdjsonErrorKind::InvalidDictionary { .. }
    ));
}

#[test]
fn writer_rejects_out_of_order_observations() {
    let header = ObservationStreamHeader::ndjson("session-1");
    let dictionary = ObservationDictionary::new("session-1");
    let mut writer =
        NdjsonObservationWriter::new(Vec::new(), &header, &dictionary, LineLimits::default())
            .unwrap();
    writer.write_observation(&instant(1, 10)).unwrap();
    let error = writer.write_observation(&instant(2, 9)).unwrap_err();
    assert!(matches!(
        error.kind,
        NdjsonErrorKind::Ordering(ObservationOrderError::SourceTimestamp { .. })
    ));
}

#[test]
fn shared_golden_fixture_matches_the_canonical_reader() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fixtures/golden/observations.jsonl");
    let input = BufReader::new(File::open(path).unwrap());
    let reader = NdjsonObservationReader::new(input, LineLimits::default()).unwrap();
    assert_eq!(reader.header().session_id, "golden-basic");
    assert_eq!(reader.dictionary().entries.len(), 3);
    let observations = reader.collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(observations.len(), 4);
    assert_eq!(observations.first().unwrap().source_seq, 0);
    assert_eq!(observations.last().unwrap().source_seq, 3);
}
