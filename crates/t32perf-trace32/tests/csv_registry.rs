use std::io::Cursor;

use t32perf_model::{ObservationDictionary, ObservationEvent, ObservationStreamHeader, Quality};
use t32perf_trace32::{
    AdapterCompatibility, AdapterDescriptor, AdapterError, AdapterRegistry, AdapterRequest,
    AdapterSelectionRequest, CANONICAL_NDJSON_ADAPTER_ID, ClockDomainSpec, CsvAdapterConfig,
    CsvAdapterErrorKind, CsvColumnMap, CsvField, ExplicitCsvSource, LineLimits,
    NdjsonObservationWriter, ObservationAdapter, ObservationSource, RationalTickScale, SourceError,
    TRACE_ASCII_ADAPTER_ID, TRACE_TASK_EVENTS_ADAPTER_ID,
};

struct FakeVerifiedAdapter {
    descriptor: AdapterDescriptor,
}

impl FakeVerifiedAdapter {
    fn new(id: &str, minimum_build: u64, maximum_build: u64) -> Self {
        Self {
            descriptor: AdapterDescriptor::new(
                id,
                "trace32-test-format/v1",
                vec![AdapterCompatibility::new(
                    "2026.02",
                    minimum_build,
                    maximum_build,
                    "arm-v8m",
                )],
            ),
        }
    }
}

impl ObservationAdapter for FakeVerifiedAdapter {
    fn id(&self) -> &str {
        &self.descriptor.adapter_id
    }

    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn open(
        &self,
        _request: AdapterRequest,
    ) -> Result<Box<dyn ObservationSource + Send>, AdapterError> {
        Err(AdapterError::InvalidConfiguration {
            adapter: self.id().to_owned(),
            message: "selection-only fake adapter".to_owned(),
        })
    }
}

fn map() -> CsvColumnMap {
    let mut map = CsvColumnMap::new();
    map.insert(CsvField::TimestampTicks, "tick");
    map.insert(CsvField::SourceSequence, "ordinal");
    map.insert(CsvField::EventType, "event-kind");
    map.insert(CsvField::CoreId, "cpu");
    map.insert(CsvField::ContextId, "thread");
    map.insert(CsvField::Name, "label");
    map.insert(CsvField::CounterId, "metric");
    map.insert(CsvField::Value, "reading");
    map
}

fn config() -> CsvAdapterConfig {
    CsvAdapterConfig {
        columns: map(),
        clock: ClockDomainSpec::new(
            "csv-clock",
            RationalTickScale::new(10, 1).unwrap(),
            None,
            None,
        )
        .unwrap(),
        origin_ticks: Some(100),
        origin_ns: -50,
        quality: Quality::Exact,
        limits: LineLimits::default(),
    }
}

#[test]
fn explicit_column_map_decodes_without_assuming_trace32_names() {
    let input = concat!(
        "tick,ordinal,event-kind,cpu,thread,label,metric,reading\n",
        "100,7,instant,2,task:main,boot,,\n",
        "105,8,counter,2,task:main,,heap,42.5\n",
    );
    let mut source = ExplicitCsvSource::new(Cursor::new(input), "mapped-csv", config()).unwrap();
    let first = source.next_observation().unwrap().unwrap();
    assert_eq!(first.observation.source_seq, 7);
    assert_eq!(first.observation.ts_ns(), -50);
    assert!(matches!(
        first.observation.event,
        ObservationEvent::Instant {
            core_id: Some(2),
            ref name,
            ..
        } if name == "boot"
    ));
    let second = source.next_observation().unwrap().unwrap();
    assert_eq!(second.observation.ts_ns(), 0);
    assert!(matches!(
        second.observation.event,
        ObservationEvent::Counter {
            ref counter_id,
            value,
            ..
        } if counter_id == "heap" && value == 42.5
    ));
    assert!(source.next_observation().unwrap().is_none());
}

#[test]
fn csv_requires_every_header_column_to_be_mapped_or_ignored() {
    let input = "tick,ordinal,event-kind,cpu,thread,label,metric,reading,mystery\n";
    let error = ExplicitCsvSource::new(Cursor::new(input), "mapped-csv", config())
        .err()
        .expect("unmapped column");
    assert_eq!(
        error.kind,
        CsvAdapterErrorKind::UnmappedHeaderColumn {
            column: "mystery".to_owned()
        }
    );

    let mut accepted = config();
    accepted.columns.ignore("mystery");
    ExplicitCsvSource::new(Cursor::new(input), "mapped-csv", accepted).unwrap();
}

#[test]
fn csv_rejects_unknown_event_and_out_of_order_sequence() {
    let unknown = concat!(
        "tick,ordinal,event-kind,cpu,thread,label,metric,reading\n",
        "100,1,trace32_magic,0,task:main,,,\n",
    );
    let mut source = ExplicitCsvSource::new(Cursor::new(unknown), "mapped-csv", config()).unwrap();
    assert!(matches!(
        source.next_observation(),
        Err(SourceError::Csv(error))
            if matches!(error.kind, CsvAdapterErrorKind::UnsupportedEventType { .. })
    ));

    let out_of_order = concat!(
        "tick,ordinal,event-kind,cpu,thread,label,metric,reading\n",
        "100,2,instant,0,task:main,a,,\n",
        "101,1,instant,0,task:main,b,,\n",
    );
    let mut source =
        ExplicitCsvSource::new(Cursor::new(out_of_order), "mapped-csv", config()).unwrap();
    source.next_observation().unwrap().unwrap();
    assert!(matches!(
        source.next_observation(),
        Err(SourceError::Csv(error))
            if matches!(error.kind, CsvAdapterErrorKind::Ordering(_))
    ));

    let wrong_width = concat!(
        "tick,ordinal,event-kind,cpu,thread,label,metric,reading\n",
        "100,1,instant,0,task:main,boot,,,extra\n",
    );
    let mut source =
        ExplicitCsvSource::new(Cursor::new(wrong_width), "mapped-csv", config()).unwrap();
    assert!(matches!(
        source.next_observation(),
        Err(SourceError::Csv(error))
            if matches!(error.kind, CsvAdapterErrorKind::RecordWidth { .. })
    ));
}

#[test]
fn csv_metadata_json_rejects_duplicate_members() {
    let mut config = config();
    config.columns.insert(CsvField::MetadataKey, "meta-key");
    config.columns.insert(CsvField::MetadataValue, "meta-value");
    let input = concat!(
        "tick,ordinal,event-kind,cpu,thread,label,metric,reading,meta-key,meta-value\n",
        "100,1,metadata,,,,,,build,\"{\"\"mode\"\":\"\"first\"\",\"\"mode\"\":\"\"last\"\"}\"\n",
    );
    let mut source = ExplicitCsvSource::new(Cursor::new(input), "mapped-csv", config).unwrap();

    assert!(matches!(
        source.next_observation(),
        Err(SourceError::Csv(error))
            if matches!(
                error.kind,
                CsvAdapterErrorKind::InvalidValue {
                    field: CsvField::MetadataValue,
                    ..
                }
            )
    ));
}

#[test]
fn conservative_registry_exposes_safe_and_explicitly_unsupported_adapters() {
    let registry = AdapterRegistry::conservative_defaults().unwrap();
    assert_eq!(
        registry.ids().collect::<Vec<_>>(),
        vec![
            CANONICAL_NDJSON_ADAPTER_ID,
            TRACE_ASCII_ADAPTER_ID,
            TRACE_TASK_EVENTS_ADAPTER_ID,
        ]
    );
    for id in [TRACE_ASCII_ADAPTER_ID, TRACE_TASK_EVENTS_ADAPTER_ID] {
        assert!(
            registry
                .descriptor(id)
                .unwrap()
                .verified_compatibility
                .is_empty(),
            "unverified TRACE32 placeholders must never participate in selection"
        );
        let error = registry
            .open(id, AdapterRequest::new("session-1", "trace32"))
            .err()
            .expect("unsupported TRACE32 adapter");
        assert!(matches!(
            error,
            AdapterError::UnsupportedNeedsTrace32 { .. }
        ));
        assert!(error.to_string().contains("UNSUPPORTED_NEEDS_TRACE32"));
    }
}

#[test]
fn verified_adapter_selection_handles_exact_range_and_no_match() {
    let mut registry = AdapterRegistry::new();
    registry
        .register(Box::new(FakeVerifiedAdapter::new("exact", 100, 100)))
        .unwrap();
    registry
        .register(Box::new(FakeVerifiedAdapter::new("range", 200, 299)))
        .unwrap();

    assert_eq!(
        registry
            .select_verified(&AdapterSelectionRequest::new(
                "trace32-test-format/v1",
                "2026.02",
                100,
                "arm-v8m",
            ))
            .unwrap(),
        "exact"
    );
    assert_eq!(
        registry
            .select_verified(&AdapterSelectionRequest::new(
                "trace32-test-format/v1",
                "2026.02",
                250,
                "arm-v8m",
            ))
            .unwrap(),
        "range"
    );
    assert!(matches!(
        registry.select_verified(&AdapterSelectionRequest::new(
            "trace32-test-format/v1",
            "2026.02",
            300,
            "arm-v8m",
        )),
        Err(AdapterError::NoCompatibleAdapter { .. })
    ));
    assert!(matches!(
        registry.select_verified(&AdapterSelectionRequest::new(
            "trace32-test-format/v1",
            "2026.02",
            250,
            "riscv",
        )),
        Err(AdapterError::NoCompatibleAdapter { .. })
    ));
}

#[test]
fn verified_adapter_selection_rejects_ambiguity() {
    let mut registry = AdapterRegistry::new();
    registry
        .register(Box::new(FakeVerifiedAdapter::new("left", 200, 299)))
        .unwrap();
    registry
        .register(Box::new(FakeVerifiedAdapter::new("right", 250, 350)))
        .unwrap();
    let error = registry
        .select_verified(&AdapterSelectionRequest::new(
            "trace32-test-format/v1",
            "2026.02",
            275,
            "arm-v8m",
        ))
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "verified adapter selection is ambiguous: [\"left\", \"right\"]"
    );
}

#[test]
fn verified_adapter_selection_rejects_unknown_zero_builds() {
    let mut registry = AdapterRegistry::new();
    let invalid = FakeVerifiedAdapter::new("invalid-zero-range", 0, 0);
    assert!(matches!(
        registry.register(Box::new(invalid)),
        Err(AdapterError::InvalidDescriptor { .. })
    ));

    registry
        .register(Box::new(FakeVerifiedAdapter::new("known", 1, 10)))
        .unwrap();
    assert!(matches!(
        registry.select_verified(&AdapterSelectionRequest::new(
            "trace32-test-format/v1",
            "2026.02",
            0,
            "arm-v8m",
        )),
        Err(AdapterError::InvalidSelection { .. })
    ));
}

#[test]
fn canonical_ndjson_adapter_is_usable_through_registry() {
    let header = ObservationStreamHeader::ndjson("session-1");
    let dictionary = ObservationDictionary::new("session-1");
    let encoded =
        NdjsonObservationWriter::new(Vec::new(), &header, &dictionary, LineLimits::default())
            .unwrap()
            .finish()
            .unwrap();
    let registry = AdapterRegistry::conservative_defaults().unwrap();
    let mut source = registry
        .open(
            CANONICAL_NDJSON_ADAPTER_ID,
            AdapterRequest::new("session-1", "canonical").with_input(Cursor::new(encoded)),
        )
        .unwrap();
    assert_eq!(source.dictionary().unwrap().session_id, "session-1");
    assert!(source.next_observation().unwrap().is_none());
}
