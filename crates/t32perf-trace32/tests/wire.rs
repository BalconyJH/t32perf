use std::io::{Cursor, Read};

use jsonschema::validator_for;
use serde_json::json;
use t32perf_model::{CounterSemantic, CounterSubject, ObservationEvent, StackRole};
use t32perf_trace32::{
    C_WIRE_COUNTER_MAPPING_SCHEMA, C_WIRE_DEFAULT_MAX_PAYLOAD, CWireContextKind,
    CWireContextMapping, CWireCounterMapping, CWireCounterMappingDocument,
    CWireCounterMappingError, CWireCounterMappingSchema, CWireDecoder, CWireObservationSource,
    CWireSourceConfig, ClockDomainSpec, MAX_C_WIRE_COUNTER_MAPPING_DOCUMENT_BYTES,
    MAX_C_WIRE_COUNTER_MAPPINGS, MAX_C_WIRE_COUNTER_TEXT_BYTES, ObservationSource,
    RationalTickScale, SourceError, WireErrorKind, WireEventKind, WireLimits,
    c_wire_schema_documents, parse_c_wire_counter_mapping,
};

struct ChunkedRead<R> {
    inner: R,
    chunk: usize,
}

impl<R: Read> Read for ChunkedRead<R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let limit = output.len().min(self.chunk);
        self.inner.read(&mut output[..limit])
    }
}

fn record(
    kind: u8,
    flags: u16,
    sequence: u32,
    ticks: u64,
    context: u32,
    event: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 + payload.len());
    bytes.extend_from_slice(b"T3PF");
    bytes.push(1);
    bytes.push(kind);
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.extend_from_slice(&ticks.to_le_bytes());
    bytes.extend_from_slice(&context.to_le_bytes());
    bytes.extend_from_slice(&event.to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn source_config() -> CWireSourceConfig {
    CWireSourceConfig {
        source_id: "sdk".to_owned(),
        core_id: 0,
        clock: ClockDomainSpec::new(
            "sdk-clock",
            RationalTickScale::new(1, 1).unwrap(),
            None,
            None,
        )
        .unwrap(),
        origin_ticks: Some(0),
        origin_ns: 0,
        limits: WireLimits::default(),
    }
}

fn counter_mapping(event_id: u32, counter_id: &str) -> CWireCounterMapping {
    CWireCounterMapping {
        event_id,
        counter_id: counter_id.to_owned(),
        name: "Heap current allocation".to_owned(),
        unit: "bytes".to_owned(),
        description: "Current allocated bytes for the primary allocator.".to_owned(),
        semantic: CounterSemantic::new(CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES).unwrap(),
        subject: CounterSubject::Allocator {
            allocator_id: "primary".to_owned(),
        },
    }
}

fn counter_mapping_document(event_id: u32, counter_id: &str) -> CWireCounterMappingDocument {
    CWireCounterMappingDocument {
        schema: CWireCounterMappingSchema::V1,
        contexts: vec![task_context_mapping(7, "task:control")],
        counters: vec![counter_mapping(event_id, counter_id)],
    }
}

fn task_context_mapping(wire_context_id: u32, context_id: &str) -> CWireContextMapping {
    CWireContextMapping {
        wire_context_id,
        context_id: context_id.to_owned(),
        name: "control-task".to_owned(),
        kind: CWireContextKind::Task,
        core_id: Some(0),
        priority: Some(7),
    }
}

fn task_stack_counter_mapping(
    event_id: u32,
    counter_id: &str,
    context_id: &str,
) -> CWireCounterMapping {
    CWireCounterMapping {
        event_id,
        counter_id: counter_id.to_owned(),
        name: "Control task stack high-water mark".to_owned(),
        unit: "bytes".to_owned(),
        description: "Measured stack high-water mark for the control task.".to_owned(),
        semantic: CounterSemantic::new(CounterSemantic::STACK_PEAK_USED_BYTES).unwrap(),
        subject: CounterSubject::Stack {
            stack_id: "control-task-stack".to_owned(),
            role: StackRole::Task,
            context_id: Some(context_id.to_owned()),
            core_id: None,
        },
    }
}

#[test]
fn decoder_matches_c_sdk_golden_record_across_chunk_boundaries() {
    let bytes = record(
        1,
        0,
        0x1122_3344,
        0x0102_0304_0506_0708,
        0xa1b2_c3d4,
        0x0a0b_0c0d,
        b"abc",
    );
    let reader = ChunkedRead {
        inner: Cursor::new(bytes),
        chunk: 1,
    };
    let mut decoder = CWireDecoder::new(reader, WireLimits::default()).unwrap();
    let decoded = decoder.next_record().unwrap().unwrap();
    assert_eq!(decoded.kind, WireEventKind::Instant);
    assert_eq!(decoded.sequence, 0x1122_3344);
    assert_eq!(decoded.timestamp_ticks, 0x0102_0304_0506_0708);
    assert_eq!(decoded.context_id, 0xa1b2_c3d4);
    assert_eq!(decoded.event_id, 0x0a0b_0c0d);
    assert_eq!(decoded.payload, b"abc");
    assert!(decoder.next_record().unwrap().is_none());
}

#[test]
fn decoder_reports_exact_version_and_truncation_locations() {
    let mut bytes = record(1, 0, 1, 0, 0, 0, b"");
    bytes[4] = 9;
    let mut decoder = CWireDecoder::new(Cursor::new(bytes), WireLimits::default()).unwrap();
    let error = decoder.next_record().unwrap_err();
    assert_eq!(error.location.byte_offset, 4);
    assert_eq!(error.location.record, 0);
    assert!(matches!(
        error.kind,
        WireErrorKind::UnsupportedVersion {
            supported: 1,
            actual: 9
        }
    ));

    let bytes = record(1, 0, 1, 0, 0, 0, b"abc");
    let truncated = bytes[..bytes.len() - 1].to_vec();
    let mut decoder = CWireDecoder::new(Cursor::new(truncated), WireLimits::default()).unwrap();
    let error = decoder.next_record().unwrap_err();
    assert_eq!(error.location.byte_offset, 34);
    assert!(matches!(
        error.kind,
        WireErrorKind::TruncatedPayload {
            expected: 3,
            available: 2
        }
    ));
}

#[test]
fn decoder_rejects_event_specific_payload_lengths() {
    let bytes = record(4, 0, 1, 0, 0, 0, &[0; 7]);
    let mut decoder = CWireDecoder::new(Cursor::new(bytes), WireLimits::default()).unwrap();
    let error = decoder.next_record().unwrap_err();
    assert_eq!(error.location.byte_offset, 8);
    assert!(matches!(
        error.kind,
        WireErrorKind::InvalidPayloadLength {
            kind: WireEventKind::Counter,
            actual: 7
        }
    ));

    let bytes = record(5, 0, 1, 0, 0, 0, &[0; 7]);
    let mut decoder = CWireDecoder::new(Cursor::new(bytes), WireLimits::default()).unwrap();
    assert!(matches!(
        decoder.next_record(),
        Err(error)
            if matches!(
                error.kind,
                WireErrorKind::InvalidPayloadLength {
                    kind: WireEventKind::AsyncBegin,
                    actual: 7
                }
            )
    ));
}

#[test]
fn sequence_loss_becomes_a_gap_before_the_actual_observation() {
    let mut bytes = record(1, 0, 10, 100, 1, 2, b"first");
    bytes.extend_from_slice(&record(1, 0, 12, 200, 1, 3, b"second"));
    let mut source = CWireObservationSource::new(Cursor::new(bytes), source_config()).unwrap();

    let first = source.next_observation().unwrap().unwrap();
    assert_eq!(first.observation.source_seq, 21);
    assert_eq!(first.observation.ts_ns(), 100);

    let gap = source.next_observation().unwrap().unwrap();
    assert_eq!(gap.observation.source_seq, 24);
    assert!(matches!(
        gap.observation.event,
        ObservationEvent::TraceGap { ref reason, .. } if reason == "source_sequence_loss:1"
    ));

    let second = source.next_observation().unwrap().unwrap();
    assert_eq!(second.observation.source_seq, 25);
    assert!(matches!(
        second.observation.event,
        ObservationEvent::Instant { ref name, .. } if name == "second"
    ));
    assert!(source.next_observation().unwrap().is_none());
}

#[test]
fn explicit_sdk_drop_record_becomes_trace_gap() {
    let mut bytes = record(1, 0, 1, 10, 1, 1, b"kept");
    bytes.extend_from_slice(&record(7, 0, 2, 20, 1, 0, &3_u32.to_le_bytes()));
    let mut source = CWireObservationSource::new(Cursor::new(bytes), source_config()).unwrap();
    source.next_observation().unwrap().unwrap();
    let dropped = source.next_observation().unwrap().unwrap();
    assert!(matches!(
        dropped.observation.event,
        ObservationEvent::TraceGap { ref reason, .. } if reason == "sdk_reported_drop:3"
    ));
}

#[test]
fn wire_timestamp_wrap_uses_the_declared_clock_domain() {
    let mut config = source_config();
    config.clock = ClockDomainSpec::new(
        "timer8",
        RationalTickScale::new(10, 1).unwrap(),
        Some(256),
        Some(20),
    )
    .unwrap();
    config.origin_ticks = Some(250);
    let mut bytes = record(1, 0, 1, 250, 1, 1, b"a");
    bytes.extend_from_slice(&record(1, 0, 2, 3, 1, 2, b"b"));
    let mut source = CWireObservationSource::new(Cursor::new(bytes), config).unwrap();
    assert_eq!(
        source
            .next_observation()
            .unwrap()
            .unwrap()
            .observation
            .ts_ns(),
        0
    );
    assert_eq!(
        source
            .next_observation()
            .unwrap()
            .unwrap()
            .observation
            .ts_ns(),
        90
    );
}

#[test]
fn wire_rejects_counter_precision_loss_and_oversized_payloads() {
    let value = (1_i64 << 53) + 1;
    let bytes = record(4, 0, 1, 0, 0, 0, &value.to_le_bytes());
    let mut source = CWireObservationSource::new(Cursor::new(bytes), source_config()).unwrap();
    assert!(matches!(
        source.next_observation(),
        Err(SourceError::Wire(error))
            if matches!(error.kind, WireErrorKind::CounterPrecisionLoss { .. })
    ));

    let payload = vec![0_u8; C_WIRE_DEFAULT_MAX_PAYLOAD + 1];
    let bytes = record(1, 0, 1, 0, 0, 0, &payload);
    let mut decoder = CWireDecoder::new(Cursor::new(bytes), WireLimits::default()).unwrap();
    assert!(matches!(
        decoder.next_record(),
        Err(error) if matches!(error.kind, WireErrorKind::PayloadTooLarge { .. })
    ));
}

#[test]
fn async_name_utf8_error_reports_the_payload_subfield_offset() {
    let mut payload = 42_u64.to_le_bytes().to_vec();
    payload.extend_from_slice(&[b'a', 0xff]);
    let bytes = record(5, 0, 1, 0, 0, 0, &payload);
    let mut source = CWireObservationSource::new(Cursor::new(bytes), source_config()).unwrap();
    let error = source.next_observation().unwrap_err();
    let SourceError::Wire(error) = error else {
        panic!("expected wire error");
    };
    assert_eq!(error.location.byte_offset, 41);
    assert_eq!(error.location.record, 0);
    assert!(matches!(error.kind, WireErrorKind::InvalidUtf8));
}

#[test]
fn mapped_counter_uses_the_verified_dictionary_identity() {
    let bytes = record(4, 0, 1, 10, 7, 42, &123_i64.to_le_bytes());
    let mut source = CWireObservationSource::new_with_counter_mapping(
        Cursor::new(bytes),
        source_config(),
        "session-1",
        counter_mapping_document(42, "heap:primary:current"),
    )
    .unwrap();
    let dictionary = source.dictionary().unwrap();
    assert_eq!(dictionary.session_id, "session-1");
    dictionary.validate().unwrap();

    let observation = source.next_observation().unwrap().unwrap();
    assert!(matches!(
        observation.observation.event,
        ObservationEvent::Counter { ref counter_id, value, .. }
            if counter_id == "heap:primary:current" && value == 123.0
    ));
}

#[test]
fn mapped_counter_rejects_unmapped_event_id_at_its_wire_record() {
    let bytes = record(4, 0, 1, 10, 7, 43, &123_i64.to_le_bytes());
    let mut source = CWireObservationSource::new_with_counter_mapping(
        Cursor::new(bytes),
        source_config(),
        "session-1",
        counter_mapping_document(42, "heap:primary:current"),
    )
    .unwrap();
    assert!(matches!(
        source.next_observation(),
        Err(SourceError::Wire(error))
            if error.location.byte_offset == 0
                && matches!(error.kind, WireErrorKind::UnmappedCounterEvent { event_id: 43 })
    ));
}

#[test]
fn mapped_task_stack_counter_defines_and_requires_its_context() {
    let mapping = CWireCounterMappingDocument {
        schema: CWireCounterMappingSchema::V1,
        contexts: vec![task_context_mapping(7, "task:control")],
        counters: vec![task_stack_counter_mapping(
            42,
            "stack:control:high-water",
            "task:control",
        )],
    };
    let bytes = record(4, 0, 1, 10, 7, 42, &123_i64.to_le_bytes());
    let mut source = CWireObservationSource::new_with_counter_mapping(
        Cursor::new(bytes),
        source_config(),
        "session-1",
        mapping,
    )
    .unwrap();

    let dictionary = source.dictionary().unwrap();
    dictionary.validate().unwrap();
    assert!(matches!(
        dictionary.entries.first(),
        Some(t32perf_model::DictionaryEntry::DefineContext {
            id,
            kind: t32perf_model::ContextKind::Task,
            core_id: Some(0),
            priority: Some(7),
            ..
        }) if id == "task:control"
    ));
    assert!(matches!(
        source.next_observation().unwrap().unwrap().observation.event,
        ObservationEvent::Counter { ref counter_id, context_id: Some(ref context_id), .. }
            if counter_id == "stack:control:high-water" && context_id == "task:control"
    ));
}

#[test]
fn mapped_isr_stack_counter_defines_and_requires_its_context() {
    let mut isr_context = task_context_mapping(11, "isr:can-rx");
    isr_context.name = "CAN receive ISR".to_owned();
    isr_context.kind = CWireContextKind::Isr;
    isr_context.priority = Some(3);
    let mut counter = task_stack_counter_mapping(43, "stack:can-rx:peak", "isr:can-rx");
    counter.subject = CounterSubject::Stack {
        stack_id: "can-rx-stack".to_owned(),
        role: StackRole::Isr,
        context_id: Some("isr:can-rx".to_owned()),
        core_id: None,
    };
    let mapping = CWireCounterMappingDocument {
        schema: CWireCounterMappingSchema::V1,
        contexts: vec![isr_context],
        counters: vec![counter],
    };
    let bytes = record(4, 0, 1, 10, 11, 43, &123_i64.to_le_bytes());
    let mut source = CWireObservationSource::new_with_counter_mapping(
        Cursor::new(bytes),
        source_config(),
        "session-1",
        mapping,
    )
    .unwrap();
    source.dictionary().unwrap().validate().unwrap();
    assert!(matches!(
        source.next_observation().unwrap().unwrap().observation.event,
        ObservationEvent::Counter { ref counter_id, context_id: Some(ref context_id), .. }
            if counter_id == "stack:can-rx:peak" && context_id == "isr:can-rx"
    ));
}

#[test]
fn deployment_context_mapping_normalizes_every_wire_event_kind() {
    let mapping = CWireCounterMappingDocument {
        schema: CWireCounterMappingSchema::V1,
        contexts: vec![task_context_mapping(7, "task:control")],
        counters: vec![counter_mapping(42, "heap:primary:current")],
    };
    let mut bytes = record(1, 0, 1, 10, 7, 10, b"instant");
    bytes.extend_from_slice(&record(2, 0, 2, 20, 7, 11, b"span"));
    bytes.extend_from_slice(&record(3, 0, 3, 30, 7, 11, b""));
    bytes.extend_from_slice(&record(4, 0, 4, 40, 7, 42, &123_i64.to_le_bytes()));
    let mut async_begin = 99_u64.to_le_bytes().to_vec();
    async_begin.extend_from_slice(b"async");
    bytes.extend_from_slice(&record(5, 0, 5, 50, 7, 12, &async_begin));
    bytes.extend_from_slice(&record(6, 0, 6, 60, 7, 12, &99_u64.to_le_bytes()));
    bytes.extend_from_slice(&record(7, 0, 7, 70, 7, 0, &1_u32.to_le_bytes()));
    let mut source = CWireObservationSource::new_with_counter_mapping(
        Cursor::new(bytes),
        source_config(),
        "session-1",
        mapping,
    )
    .unwrap();

    for expected_kind in [
        "instant",
        "span_begin",
        "span_end",
        "counter",
        "async_begin",
        "async_end",
        "dropped",
    ] {
        let observation = source.next_observation().unwrap().unwrap();
        match (expected_kind, observation.observation.event) {
            ("instant", ObservationEvent::Instant { context_id, .. })
            | ("span_begin", ObservationEvent::SpanBegin { context_id, .. })
            | ("span_end", ObservationEvent::SpanEnd { context_id, .. })
            | ("counter", ObservationEvent::Counter { context_id, .. })
            | ("async_begin", ObservationEvent::AsyncBegin { context_id, .. })
            | ("async_end", ObservationEvent::AsyncEnd { context_id, .. }) => {
                assert_eq!(
                    context_id.as_deref(),
                    Some("task:control"),
                    "{expected_kind}"
                );
            }
            ("dropped", ObservationEvent::TraceGap { .. }) => {}
            (actual, event) => panic!("expected {actual}, got {event:?}"),
        }
    }
    assert!(source.next_observation().unwrap().is_none());
}

#[test]
fn deployment_context_mapping_rejects_unknown_context_for_every_wire_event_kind() {
    let mapping = CWireCounterMappingDocument {
        schema: CWireCounterMappingSchema::V1,
        contexts: vec![task_context_mapping(7, "task:control")],
        counters: vec![counter_mapping(42, "heap:primary:current")],
    };
    let mut async_begin = 99_u64.to_le_bytes().to_vec();
    async_begin.extend_from_slice(b"async");
    let counter_payload = 123_i64.to_le_bytes();
    let async_end_payload = 99_u64.to_le_bytes();
    let dropped_payload = 1_u32.to_le_bytes();
    for (kind, event_id, payload) in [
        (1, 10, b"instant".as_slice()),
        (2, 11, b"span".as_slice()),
        (3, 11, b"".as_slice()),
        (4, 42, counter_payload.as_slice()),
        (5, 12, async_begin.as_slice()),
        (6, 12, async_end_payload.as_slice()),
        (7, 0, dropped_payload.as_slice()),
    ] {
        let bytes = record(kind, 0, 1, 10, 8, event_id, payload);
        let mut source = CWireObservationSource::new_with_counter_mapping(
            Cursor::new(bytes),
            source_config(),
            "session-1",
            mapping.clone(),
        )
        .unwrap();
        assert!(matches!(
            source.next_observation(),
            Err(SourceError::Wire(error))
                if matches!(error.kind, WireErrorKind::UnmappedContext { context_id: 8 })
        ));
    }
}

#[test]
fn mapped_stack_counter_rejects_wrong_wire_context_at_its_record() {
    let mapping = CWireCounterMappingDocument {
        schema: CWireCounterMappingSchema::V1,
        contexts: vec![
            task_context_mapping(7, "task:control"),
            task_context_mapping(8, "task:other"),
        ],
        counters: vec![task_stack_counter_mapping(
            42,
            "stack:control:high-water",
            "task:control",
        )],
    };
    let bytes = record(4, 0, 1, 10, 8, 42, &123_i64.to_le_bytes());
    let mut source = CWireObservationSource::new_with_counter_mapping(
        Cursor::new(bytes),
        source_config(),
        "session-1",
        mapping,
    )
    .unwrap();
    assert!(matches!(
        source.next_observation(),
        Err(SourceError::Wire(error))
            if matches!(
                error.kind,
                WireErrorKind::CounterContextMismatch {
                    event_id: 42,
                    expected_context_id: 7,
                    actual_context_id: 8,
                }
            )
    ));
}

#[test]
fn stack_counter_mapping_rejects_missing_wrong_kind_duplicate_and_cross_core_contexts() {
    let missing = CWireCounterMappingDocument {
        schema: CWireCounterMappingSchema::V1,
        contexts: Vec::new(),
        counters: vec![task_stack_counter_mapping(
            42,
            "stack:control:high-water",
            "task:control",
        )],
    };
    assert!(matches!(
        missing.validate(),
        Err(CWireCounterMappingError::MissingStackContext { .. })
    ));

    let mut wrong_kind_context = task_context_mapping(7, "task:control");
    wrong_kind_context.kind = CWireContextKind::Isr;
    let wrong_kind = CWireCounterMappingDocument {
        schema: CWireCounterMappingSchema::V1,
        contexts: vec![wrong_kind_context],
        counters: vec![task_stack_counter_mapping(
            42,
            "stack:control:high-water",
            "task:control",
        )],
    };
    assert!(matches!(
        wrong_kind.validate(),
        Err(CWireCounterMappingError::StackContextKindMismatch {
            expected: CWireContextKind::Task,
            ..
        })
    ));

    let duplicate = CWireCounterMappingDocument {
        schema: CWireCounterMappingSchema::V1,
        contexts: vec![
            task_context_mapping(7, "task:control"),
            task_context_mapping(7, "task:backup"),
        ],
        counters: vec![counter_mapping(42, "heap:primary:current")],
    };
    assert!(matches!(
        duplicate.validate(),
        Err(CWireCounterMappingError::DuplicateWireContextId { context_id: 7 })
    ));

    let duplicate_identity = CWireCounterMappingDocument {
        schema: CWireCounterMappingSchema::V1,
        contexts: vec![
            task_context_mapping(7, "task:control"),
            task_context_mapping(8, "task:control"),
        ],
        counters: vec![counter_mapping(42, "heap:primary:current")],
    };
    assert!(matches!(
        duplicate_identity.validate(),
        Err(CWireCounterMappingError::DuplicateContextId { ref context_id })
            if context_id == "task:control"
    ));

    let mut cross_core_context = task_context_mapping(7, "task:control");
    cross_core_context.core_id = Some(1);
    let cross_core = CWireCounterMappingDocument {
        schema: CWireCounterMappingSchema::V1,
        contexts: vec![cross_core_context],
        counters: vec![task_stack_counter_mapping(
            42,
            "stack:control:high-water",
            "task:control",
        )],
    };
    let result = CWireObservationSource::new_with_counter_mapping(
        Cursor::new(Vec::<u8>::new()),
        source_config(),
        "session-1",
        cross_core,
    );
    assert!(matches!(
        result,
        Err(error)
            if matches!(
                &error.kind,
                WireErrorKind::InvalidCounterMapping { message }
                    if message.contains("does not match source core 0")
            )
    ));
}

#[test]
fn counter_mapping_rejects_duplicate_wire_and_resource_identities() {
    let duplicate_wire = CWireCounterMappingDocument {
        schema: CWireCounterMappingSchema::V1,
        contexts: Vec::new(),
        counters: vec![
            counter_mapping(42, "heap:one"),
            counter_mapping(42, "heap:two"),
        ],
    };
    assert!(matches!(
        duplicate_wire.validate(),
        Err(CWireCounterMappingError::DuplicateEventId { event_id: 42 })
    ));

    let duplicate_resource = CWireCounterMappingDocument {
        schema: CWireCounterMappingSchema::V1,
        contexts: Vec::new(),
        counters: vec![
            counter_mapping(42, "heap:one"),
            counter_mapping(43, "heap:two"),
        ],
    };
    assert!(matches!(
        duplicate_resource.validate(),
        Err(CWireCounterMappingError::InvalidDictionary(_))
    ));

    let duplicate_counter_id = CWireCounterMappingDocument {
        schema: CWireCounterMappingSchema::V1,
        contexts: Vec::new(),
        counters: vec![
            counter_mapping(42, "heap:one"),
            CWireCounterMapping {
                subject: CounterSubject::Allocator {
                    allocator_id: "secondary".to_owned(),
                },
                ..counter_mapping(43, "heap:one")
            },
        ],
    };
    assert!(matches!(
        duplicate_counter_id.validate(),
        Err(CWireCounterMappingError::DuplicateCounterId { .. })
    ));
}

#[test]
fn counter_mapping_enforces_count_text_and_document_bounds() {
    let too_many = CWireCounterMappingDocument {
        schema: CWireCounterMappingSchema::V1,
        contexts: Vec::new(),
        counters: vec![
            counter_mapping(42, "heap:primary:current");
            MAX_C_WIRE_COUNTER_MAPPINGS + 1
        ],
    };
    assert!(matches!(
        too_many.validate(),
        Err(CWireCounterMappingError::TooManyMappings { .. })
    ));

    let mut oversized_text = counter_mapping_document(42, "heap:primary:current");
    oversized_text.counters[0].description = "x".repeat(MAX_C_WIRE_COUNTER_TEXT_BYTES + 1);
    assert!(matches!(
        oversized_text.validate(),
        Err(CWireCounterMappingError::InvalidText {
            field: "description",
            ..
        })
    ));
    assert!(matches!(
        parse_c_wire_counter_mapping(&vec![b' '; MAX_C_WIRE_COUNTER_MAPPING_DOCUMENT_BYTES + 1]),
        Err(CWireCounterMappingError::DocumentTooLarge { .. })
    ));
}

#[test]
fn counter_mapping_json_is_strict_closed_and_schema_validated() {
    let document = json!({
        "schema": C_WIRE_COUNTER_MAPPING_SCHEMA,
        "contexts": [{
            "wire_context_id": 7,
            "context_id": "task:control",
            "name": "control-task",
            "kind": "task",
            "core_id": 0,
            "priority": 7
        }],
        "counters": [{
            "event_id": 42,
            "counter_id": "heap:primary:current",
            "name": "Heap current allocation",
            "unit": "bytes",
            "description": "Current allocated bytes for the primary allocator.",
            "semantic": CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES,
            "subject": {"kind": "allocator", "allocator_id": "primary"}
        }]
    });
    let bytes = serde_json::to_vec(&document).unwrap();
    let parsed = parse_c_wire_counter_mapping(&bytes).unwrap();
    parsed.validate().unwrap();

    let duplicate_key = br#"{"schema":"t32perf.c-wire-counter-mapping/v1","schema":"t32perf.c-wire-counter-mapping/v1","counters":[]}"#;
    assert!(matches!(
        parse_c_wire_counter_mapping(duplicate_key),
        Err(CWireCounterMappingError::InvalidJson { .. })
    ));
    let unknown = br#"{"schema":"t32perf.c-wire-counter-mapping/v1","counters":[],"extra":true}"#;
    assert!(matches!(
        parse_c_wire_counter_mapping(unknown),
        Err(CWireCounterMappingError::InvalidJson { .. })
    ));

    let schemas = c_wire_schema_documents();
    let schema = schemas.get("c-wire-counter-mapping.schema.json").unwrap();
    assert_eq!(schema["$id"], C_WIRE_COUNTER_MAPPING_SCHEMA);
    let validator = validator_for(schema).unwrap();
    assert!(validator.is_valid(&document));
    assert!(!validator.is_valid(&json!({
        "schema": "t32perf.c-wire-counter-mapping/v2",
        "counters": []
    })));
}
