use std::io::{BufReader, Cursor};

use t32perf_analysis::*;
use t32perf_model::*;

fn span(function_id: &str, start_ns: i64, end_ns: i64) -> FunctionSpan {
    let elapsed_ns = u64::try_from(end_ns - start_ns).unwrap();
    FunctionSpan {
        source_id: "test".to_owned(),
        source_seq_start: Some(1),
        source_seq_end: Some(2),
        core_id: 0,
        context_id: "task".to_owned(),
        function_id: function_id.to_owned(),
        frame_id: None,
        start_ns,
        end_ns,
        elapsed_ns,
        active_ns: elapsed_ns,
        self_active_ns: elapsed_ns,
        preempted_ns: 0,
        quality: Quality::Exact,
        incomplete: false,
    }
}

#[test]
fn derived_ndjson_roundtrips_header_and_spans() {
    let mut header = DerivedStreamHeader::ndjson("session-1");
    header.input_artifact_ids.push("observations".to_owned());
    let spans = [span("a", 0, 10), span("b", 10, 25)];

    let mut writer = DerivedNdjsonWriter::new(Vec::new(), header.clone()).unwrap();
    writer.write_spans(&spans).unwrap();
    assert_eq!(writer.spans_written(), 2);
    let bytes = writer.finish().unwrap();

    let mut reader =
        DerivedNdjsonReader::new(BufReader::new(Cursor::new(bytes)), "session-1").unwrap();
    assert_eq!(reader.header(), &header);
    assert_eq!(reader.read_span().unwrap(), Some(spans[0].clone()));
    assert_eq!(reader.read_span().unwrap(), Some(spans[1].clone()));
    assert_eq!(reader.read_span().unwrap(), None);
}

#[test]
fn reader_rejects_wrong_session_and_unknown_schema_on_line_one() {
    let header = DerivedStreamHeader::ndjson("actual-session");
    let bytes = serde_json::to_vec(&header).unwrap();
    let error = DerivedNdjsonReader::new(BufReader::new(Cursor::new(bytes)), "expected-session")
        .unwrap_err();
    assert!(matches!(error, DerivedStreamError::SessionMismatch { .. }));

    let unsupported =
        b"{\"schema\":\"t32perf.derived-stream/v2\",\"session_id\":\"session-1\",\"encoding\":\"ndjson\"}\n";
    let error = DerivedNdjsonReader::new(
        BufReader::new(Cursor::new(unsupported.as_slice())),
        "session-1",
    )
    .unwrap_err();
    assert!(matches!(
        error,
        DerivedStreamError::InvalidJson {
            line: 1,
            record: DerivedRecordKind::Header,
            ..
        }
    ));
}

#[test]
fn reader_reports_exact_span_line_and_becomes_poisoned() {
    let header = serde_json::to_string(&DerivedStreamHeader::ndjson("session-1")).unwrap();
    let bytes = format!("{header}\n{{not-json}}\n");
    let mut reader =
        DerivedNdjsonReader::new(BufReader::new(Cursor::new(bytes)), "session-1").unwrap();
    let error = reader.read_span().unwrap_err();
    assert!(matches!(
        error,
        DerivedStreamError::InvalidJson {
            line: 2,
            record: DerivedRecordKind::FunctionSpan,
            ..
        }
    ));
    assert!(matches!(
        reader.read_span(),
        Err(DerivedStreamError::ReaderPoisoned)
    ));
}

#[test]
fn reader_rejects_duplicate_members_per_line() {
    let duplicated_header = b"{\"schema\":\"t32perf.derived-stream/v1\",\"session_id\":\"session-1\",\"session_id\":\"shadow\",\"encoding\":\"ndjson\"}\n";
    let error = DerivedNdjsonReader::new(
        BufReader::new(Cursor::new(duplicated_header.as_slice())),
        "session-1",
    )
    .expect_err("duplicate derived header member");
    assert!(matches!(
        error,
        DerivedStreamError::InvalidJson {
            line: 1,
            record: DerivedRecordKind::Header,
            ref source,
        } if source
            .to_string()
            .contains("duplicate JSON object member name `session_id`")
    ));
}

#[test]
fn reader_and_writer_enforce_span_invariants() {
    let header = DerivedStreamHeader::ndjson("session-1");
    let mut invalid = span("bad", 0, 10);
    invalid.elapsed_ns = 9;

    let mut writer = DerivedNdjsonWriter::new(Vec::new(), header.clone()).unwrap();
    let error = writer.write_span(&invalid).unwrap_err();
    assert!(matches!(
        error,
        DerivedStreamError::InvalidSpan { line: 2, .. }
    ));

    let bytes = format!(
        "{}\n{}\n",
        serde_json::to_string(&header).unwrap(),
        serde_json::to_string(&invalid).unwrap()
    );
    let mut reader =
        DerivedNdjsonReader::new(BufReader::new(Cursor::new(bytes)), "session-1").unwrap();
    let error = reader.read_span().unwrap_err();
    assert!(matches!(
        error,
        DerivedStreamError::InvalidSpan { line: 2, .. }
    ));
}

#[test]
fn line_limits_bound_reader_and_writer_allocations() {
    let header = DerivedStreamHeader::ndjson("session-1");
    let header_len = serde_json::to_vec(&header).unwrap().len();
    let large_span = span(&"x".repeat(header_len * 2), 0, 10);

    let mut writer =
        DerivedNdjsonWriter::with_line_limit(Vec::new(), header.clone(), header_len).unwrap();
    let error = writer.write_span(&large_span).unwrap_err();
    assert!(matches!(
        error,
        DerivedStreamError::LineTooLong { line: 2, .. }
    ));

    let bytes = format!(
        "{}\n{}\n",
        serde_json::to_string(&header).unwrap(),
        serde_json::to_string(&large_span).unwrap()
    );
    let mut reader = DerivedNdjsonReader::with_line_limit(
        BufReader::new(Cursor::new(bytes)),
        "session-1",
        header_len,
    )
    .unwrap();
    let error = reader.read_span().unwrap_err();
    assert!(matches!(
        error,
        DerivedStreamError::LineTooLong { line: 2, .. }
    ));
}

#[test]
fn empty_stream_and_empty_record_have_distinct_errors() {
    let error =
        DerivedNdjsonReader::new(BufReader::new(Cursor::new(Vec::<u8>::new())), "session-1")
            .unwrap_err();
    assert!(matches!(error, DerivedStreamError::EmptyStream));

    let header = serde_json::to_string(&DerivedStreamHeader::ndjson("session-1")).unwrap();
    let bytes = format!("{header}\n\n");
    let mut reader =
        DerivedNdjsonReader::new(BufReader::new(Cursor::new(bytes)), "session-1").unwrap();
    assert!(matches!(
        reader.read_span(),
        Err(DerivedStreamError::EmptyLine { line: 2 })
    ));
}
