use std::{collections::BTreeMap, io::Cursor};

use object::{
    Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope,
    write::{Object, StandardSection, Symbol, SymbolSection},
};
use t32perf_model::{ContextKind, ObservationEvent, Quality, Sha256Digest};
use t32perf_trace32::{
    LineLimits, MAX_TRACE32_TASK_EVENTS_CONTEXTS, ObservationSource, SourceError,
    TRACE_ASCII_EXPORT_ITEMS_V1, TRACE_ASCII_FORMAT_V1, TRACE_TASK_EVENTS_FORMAT_V1,
    TRACE32_SYMBOL_MAPPING_SCHEMA, TRACE32_TASK_EVENTS_MAPPING_SCHEMA,
    TRACE32_TASK_EVENTS_MAPPING_TEMPLATE_SCHEMA, Trace32SymbolMappingDocument,
    Trace32TaskEventsMappingDocument, Trace32TaskEventsMappingTemplateDocument,
    TraceArtifactBinding, TraceAsciiConfig, TraceAsciiSource, TraceContextMapping,
    TraceExportErrorKind, TraceFunctionMapping, TraceRunnableMapping, TraceTaskEventsConfig,
    TraceTaskEventsRuntimeBinding, TraceTaskEventsSource, TraceTaskEventsTrace32Identity,
    TraceTaskMetadataBinding, TraceTaskMetadataRole, materialize_trace32_task_events_mapping,
    parse_trace32_symbol_mapping, parse_trace32_task_events_mapping,
    parse_trace32_task_events_mapping_template, trace_export_schema_documents,
    trace_function_mappings_from_elf,
};

const HEADER: &str = concat!(
    "############################\n",
    "# Task events trace file\n",
    "# time(ns); task name; event;\n",
    "############################\n",
);

fn function(export_name: &str, id: &str) -> TraceFunctionMapping {
    TraceFunctionMapping {
        export_name: export_name.to_owned(),
        function_id: id.to_owned(),
        display_name: export_name.to_owned(),
        module: Some("firmware.elf".to_owned()),
        address: None,
        end_address: None,
        file: None,
        line: None,
    }
}

fn context(
    export_name: &str,
    id: &str,
    kind: ContextKind,
    priority: Option<i32>,
    entry_function_id: Option<&str>,
) -> TraceContextMapping {
    TraceContextMapping {
        export_name: export_name.to_owned(),
        context_id: id.to_owned(),
        kind,
        display_name: export_name.to_owned(),
        priority,
        entry_function_id: entry_function_id.map(str::to_owned),
    }
}

fn task_config() -> TraceTaskEventsConfig {
    TraceTaskEventsConfig {
        core_id: 0,
        clock_domain: "trace32-zero".to_owned(),
        contexts: vec![
            context("NO_TASK", "idle:0", ContextKind::Idle, None, None),
            context(
                "TaskA",
                "task:a",
                ContextKind::Task,
                Some(3),
                Some("fn:task-a"),
            ),
            context(
                "ISR_A",
                "isr:a",
                ContextKind::Isr,
                Some(1),
                Some("fn:isr-a"),
            ),
        ],
        functions: vec![
            function("TaskA", "fn:task-a"),
            function("ISR_A", "fn:isr-a"),
            function("Runnable A", "fn:runnable-a"),
        ],
        runnables: BTreeMap::from([("Runnable A".to_owned(), "fn:runnable-a".to_owned())]),
        initial_context_id: None,
        limits: LineLimits::default(),
    }
}

fn vendor_sample_config() -> TraceTaskEventsConfig {
    let mut config = task_config();
    config.contexts = vec![
        context("NO_TASK", "idle:0", ContextKind::Idle, None, None),
        context(
            "Trace_1MS_0",
            "task:trace-1ms-0",
            ContextKind::Task,
            None,
            Some("fn:trace-1ms-0"),
        ),
    ];
    config.functions = vec![function("Trace_1MS_0", "fn:trace-1ms-0")];
    config.runnables.clear();
    config
}

fn ascii_config() -> TraceAsciiConfig {
    TraceAsciiConfig {
        clock_domain: "trace32-zero".to_owned(),
        core_id: 0,
        address_classes: ["P".to_owned()].into_iter().collect(),
        functions: vec![TraceFunctionMapping {
            export_name: "\\\\User\\Global\\tc234l_loop".to_owned(),
            function_id: "fn:sampled".to_owned(),
            display_name: "tc234l_loop".to_owned(),
            module: Some("firmware.elf".to_owned()),
            address: Some(0x7010_0000),
            end_address: Some(0x7010_0010),
            file: None,
            line: None,
        }],
        limits: LineLimits::default(),
    }
}

fn x86_ascii_config() -> TraceAsciiConfig {
    let mut config = ascii_config();
    config.address_classes = ["C".to_owned()].into_iter().collect();
    config.functions = vec![TraceFunctionMapping {
        export_name: "*cs_x86\\sieve_funcs\\func2c".to_owned(),
        function_id: "fn:sampled".to_owned(),
        display_name: "func2c".to_owned(),
        module: Some("simulator.elf".to_owned()),
        address: Some(0x0804_81b5),
        end_address: Some(0x0804_8200),
        file: None,
        line: None,
    }];
    config
}

fn executable_elf_fixture() -> Vec<u8> {
    let mut object = Object::new(BinaryFormat::Elf, Architecture::Arm, Endianness::Little);
    let text = object.section_id(StandardSection::Text);
    object.set_section_data(text, vec![0_u8; 64], 4);
    for (name, value, size) in [("first", 0_u64, 16_u64), ("second", 16, 32)] {
        object.add_symbol(Symbol {
            name: name.as_bytes().to_vec(),
            value,
            size,
            kind: SymbolKind::Text,
            scope: SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Section(text),
            flags: SymbolFlags::None,
        });
    }
    let mut bytes = object.write().unwrap();
    // object::write emits ET_REL. The production path requires ET_EXEC; this
    // fixture changes only the ELF e_type field while retaining its symbol table.
    bytes[16] = 2;
    bytes[17] = 0;
    bytes
}

fn stripped_executable_elf_fixture() -> Vec<u8> {
    let mut object = Object::new(BinaryFormat::Elf, Architecture::Arm, Endianness::Little);
    let text = object.section_id(StandardSection::Text);
    object.set_section_data(text, vec![0_u8; 64], 4);
    let mut bytes = object.write().unwrap();
    bytes[16] = 2;
    bytes[17] = 0;
    bytes
}

#[test]
fn fixed_ascii_command_and_format_identity_are_exact() {
    assert_eq!(
        TRACE_ASCII_EXPORT_ITEMS_V1,
        "Address CYcle %TimeFixed TIme.Zero sYmbol /ShowRecord"
    );
    assert_eq!(
        TRACE_ASCII_FORMAT_V1,
        "trace32.export-ascii/snooper-single-core-show-record-address-cycle-time-zero-symbol/v1"
    );
    assert_eq!(
        TRACE_TASK_EVENTS_FORMAT_V1,
        "trace32.export-taskevents/time-name-event-no-trace-record/v1"
    );
    let cmm = include_str!(
        "../../../skill-trace32-perf/scripts/adapters/tc234l-build190766/perf_export.cmm"
    );
    assert!(cmm.contains(
        "SNOOPer.EXPORT.Ascii \"&output\" Address CYcle %TimeFixed TIme.Zero sYmbol /ShowRecord"
    ));
    assert!(cmm.contains("SNOOPer.ZERO SNOOPer.FIRST()"));
}

#[test]
fn taskevents_maps_task_isr_runnable_and_wait_semantics() {
    let input = format!(
        "{HEADER}{}",
        concat!(
            "0; NO_TASK; switch;\n",
            "10; TaskA; switch;\n",
            "11; TaskA; start;\n",
            "12; TaskA; preempt;\n",
            "12; ISR_A; isrstart;\n",
            "13; Runnable A; runnablestart;\n",
            "14; Runnable A; runnablestop;\n",
            "15; ISR_A; isrend;\n",
            "16; TaskA; resume;\n",
            "17; TaskA; wait;\n",
            "17; NO_TASK; switch;\n",
            "18; TaskA; release;\n",
            "19; TaskA; stop;\n",
            "19; TaskA; terminate;\n",
            "20; NO_TASK; switch;\n",
        )
    );
    let mut source =
        TraceTaskEventsSource::new(Cursor::new(input), "session", "taskevents", task_config())
            .unwrap();
    assert_eq!(source.dictionary().unwrap().entries.len(), 6);
    let mut events = Vec::new();
    while let Some(observation) = source.next_observation().unwrap() {
        events.push(observation.observation.event);
    }

    assert!(events.iter().any(|event| matches!(
        event,
        ObservationEvent::Instant { name, .. } if name == "trace32.taskevents.resume"
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        ObservationEvent::InterruptEnter {
            interrupt_id,
            priority: Some(1),
            ..
        } if interrupt_id == "isr:a"
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        ObservationEvent::FunctionEnter {
            context_id,
            function_id,
            ..
        } if context_id == "isr:a" && function_id == "fn:runnable-a"
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        ObservationEvent::Instant { name, .. } if name == "trace32.taskevents.wait"
    )));
}

#[test]
fn installed_r2026_02_vendor_fixture_is_rejected_without_session_time_origin() {
    let input = include_str!("fixtures/trace32/taskevents-r2026.02-vendor-sample.csv");
    let mut source = TraceTaskEventsSource::new(
        Cursor::new(input),
        "session",
        "taskevents",
        vendor_sample_config(),
    )
    .unwrap();
    assert!(matches!(
        source.next_observation(),
        Err(SourceError::TraceExport(error))
            if matches!(
                error.kind,
                TraceExportErrorKind::InvalidState { ref message }
                    if message.contains("first TASKEVENTS record is 478000ns")
            )
    ));
}

#[test]
fn taskevents_accepts_the_official_initial_empty_preempt_boundary() {
    let input = format!("{HEADER}0; ; preempt;\n1; NO_TASK; switch;\n");
    let mut source =
        TraceTaskEventsSource::new(Cursor::new(input), "session", "taskevents", task_config())
            .unwrap();
    let first = source.next_observation().unwrap().unwrap();
    assert!(matches!(
        first.observation.event,
        ObservationEvent::Instant {
            context_id: None,
            ref name,
            ..
        } if name == "trace32.taskevents.preempt"
    ));
}

#[test]
fn taskevents_preserves_known_and_unknown_left_boundaries_and_same_tick_order() {
    let input = format!("{HEADER}0; TaskA; switch;\n0; TaskA; start;\n1; TaskA; stop;\n");
    let mut unknown =
        TraceTaskEventsSource::new(Cursor::new(&input), "session", "taskevents", task_config())
            .unwrap();
    let first = unknown.next_observation().unwrap().unwrap();
    let second = unknown.next_observation().unwrap().unwrap();
    assert!(matches!(
        first.observation.event,
        ObservationEvent::ContextSwitch {
            prev_context_id: None,
            ..
        }
    ));
    assert_eq!(first.observation.ts_ns(), second.observation.ts_ns());
    assert!(first.order_key < second.order_key);

    let mut config = task_config();
    config.initial_context_id = Some("idle:0".to_owned());
    let mut known =
        TraceTaskEventsSource::new(Cursor::new(input), "session", "taskevents", config).unwrap();
    let first = known.next_observation().unwrap().unwrap();
    assert!(matches!(
        first.observation.event,
        ObservationEvent::ContextSwitch {
            prev_context_id: Some(ref previous),
            ..
        } if previous == "idle:0"
    ));
}

#[test]
fn taskevents_rejects_unknown_variants_with_exact_location() {
    let input = format!("{HEADER}0; NO_TASK; teleport;\n");
    let mut source =
        TraceTaskEventsSource::new(Cursor::new(input), "session", "taskevents", task_config())
            .unwrap();
    let error = source.next_observation().unwrap_err();
    assert!(matches!(
        error,
        SourceError::TraceExport(ref error)
            if error.location.line == 5
                && error.location.record == 4
                && matches!(
                    error.kind,
                    TraceExportErrorKind::UnsupportedTaskEvent { ref event }
                        if event == "teleport"
                )
    ));
}

#[test]
fn taskevents_rejects_trace_record_and_legacy_header_variants() {
    let wrong_header = concat!(
        "########\n",
        "# Task events trace file\n",
        "# time(ns); task name; event\n",
        "########\n",
    );
    let error = TraceTaskEventsSource::new(
        Cursor::new(wrong_header),
        "session",
        "taskevents",
        task_config(),
    )
    .err()
    .expect("legacy header must be rejected");
    assert!(matches!(
        error.kind,
        TraceExportErrorKind::InvalidTaskEventsHeader { .. }
    ));

    let with_record = format!("{HEADER}0; 17; NO_TASK; switch;\n");
    let mut source = TraceTaskEventsSource::new(
        Cursor::new(with_record),
        "session",
        "taskevents",
        task_config(),
    )
    .unwrap();
    assert!(matches!(
        source.next_observation(),
        Err(SourceError::TraceExport(error))
            if matches!(error.kind, TraceExportErrorKind::TaskEventsRecordWidth { actual: 5 })
    ));
}

#[test]
fn taskevents_truncated_header_reports_the_physical_eof() {
    let prefixes = [
        "",
        "############################\n",
        concat!(
            "############################\n",
            "# Task events trace file\n"
        ),
        concat!(
            "############################\n",
            "# Task events trace file\n",
            "# time(ns); task name; event;\n"
        ),
    ];
    for (index, input) in prefixes.into_iter().enumerate() {
        let missing_line = u64::try_from(index + 1).unwrap();
        let error =
            TraceTaskEventsSource::new(Cursor::new(input), "session", "taskevents", task_config())
                .err()
                .expect("truncated header must fail");
        assert_eq!(error.location.byte_offset, input.len() as u64);
        assert_eq!(error.location.line, missing_line);
        assert_eq!(error.location.record, missing_line - 1);
        assert!(matches!(
            error.kind,
            TraceExportErrorKind::InvalidTaskEventsHeader { ref message }
                if message.contains(&format!("missing header line {missing_line}"))
        ));
    }

    let invalid_closing = concat!(
        "############################\n",
        "# Task events trace file\n",
        "# time(ns); task name; event;\n",
        "invalid-closing-rule\n"
    );
    let error = TraceTaskEventsSource::new(
        Cursor::new(invalid_closing),
        "session",
        "taskevents",
        task_config(),
    )
    .err()
    .expect("invalid closing rule must fail");
    assert_eq!(error.location.line, 4);
    assert_eq!(
        error.location.byte_offset,
        invalid_closing
            .lines()
            .take(3)
            .map(|line| line.len() as u64 + 1)
            .sum::<u64>()
    );
}

#[test]
fn taskevents_truncated_open_activation_fails_closed() {
    let input = format!("{HEADER}0; TaskA; switch;\n1; TaskA; start;\n");
    let mut source =
        TraceTaskEventsSource::new(Cursor::new(input), "session", "taskevents", task_config())
            .unwrap();
    loop {
        match source.next_observation() {
            Ok(Some(_)) => {}
            Ok(None) => panic!("truncated input was accepted"),
            Err(SourceError::TraceExport(error)) => {
                assert!(matches!(
                    error.kind,
                    TraceExportErrorKind::InvalidState { ref message }
                        if message.contains("EOF left an open task")
                ));
                break;
            }
            Err(error) => panic!("unexpected error: {error}"),
        }
    }
}

#[test]
fn taskevents_rejects_unresolved_deschedule_at_exact_eof_location() {
    let input = format!(
        "{HEADER}{}",
        concat!("0; TaskA; switch;\n", "1; TaskA; preempt;\n")
    );
    let expected_byte = u64::try_from(input.len()).unwrap();
    let mut source =
        TraceTaskEventsSource::new(Cursor::new(input), "session", "taskevents", task_config())
            .unwrap();
    assert!(source.next_observation().unwrap().is_some());
    assert!(source.next_observation().unwrap().is_some());
    assert!(matches!(
        source.next_observation(),
        Err(SourceError::TraceExport(error))
            if error.location.byte_offset == expected_byte
                && error.location.line == 7
                && matches!(
                    error.kind,
                    TraceExportErrorKind::InvalidState { ref message }
                        if message.contains("deschedule transition")
                )
    ));
}

#[test]
fn taskevents_keeps_unknown_schedule_state_as_instant_and_rejects_contradictions() {
    let input = format!("{HEADER}0; TaskA; schedule;\n");
    let mut source =
        TraceTaskEventsSource::new(Cursor::new(input), "session", "taskevents", task_config())
            .unwrap();
    let observation = source.next_observation().unwrap().unwrap();
    assert!(matches!(
        observation.observation.event,
        ObservationEvent::Instant { ref args, .. }
            if args.get("state_validation")
                == Some(&serde_json::json!("left_boundary_unknown"))
    ));

    let input = format!(
        "{HEADER}{}",
        concat!(
            "0; TaskA; switch;\n",
            "1; TaskA; wait;\n",
            "2; TaskA; schedule;\n"
        )
    );
    let mut source =
        TraceTaskEventsSource::new(Cursor::new(input), "session", "taskevents", task_config())
            .unwrap();
    assert!(source.next_observation().unwrap().is_some());
    assert!(source.next_observation().unwrap().is_some());
    assert!(matches!(
        source.next_observation(),
        Err(SourceError::TraceExport(error))
            if matches!(
                error.kind,
                TraceExportErrorKind::InvalidState { ref message }
                    if message.contains("requires lifecycle Ready")
            )
    ));
}

#[test]
fn taskevents_rejects_task_stop_outside_the_active_context() {
    let input = format!(
        "{HEADER}{}",
        concat!(
            "0; TaskA; switch;\n",
            "1; TaskA; start;\n",
            "2; TaskA; preempt;\n",
            "3; NO_TASK; switch;\n",
            "4; TaskA; stop;\n"
        )
    );
    let mut source =
        TraceTaskEventsSource::new(Cursor::new(input), "session", "taskevents", task_config())
            .unwrap();
    for _ in 0..4 {
        assert!(source.next_observation().unwrap().is_some());
    }
    assert!(matches!(
        source.next_observation(),
        Err(SourceError::TraceExport(error))
            if matches!(
                error.kind,
                TraceExportErrorKind::InvalidState { ref message }
                    if message.contains("not active at stop")
            )
    ));
}

#[test]
fn taskevents_rejects_outer_function_exit_before_nested_runnable() {
    let input = format!(
        "{HEADER}{}",
        concat!(
            "0; TaskA; switch;\n",
            "1; TaskA; start;\n",
            "2; Runnable A; runnablestart;\n",
            "3; TaskA; stop;\n"
        )
    );
    let mut source =
        TraceTaskEventsSource::new(Cursor::new(input), "session", "taskevents", task_config())
            .unwrap();
    for _ in 0..3 {
        assert!(source.next_observation().unwrap().is_some());
    }
    assert!(matches!(
        source.next_observation(),
        Err(SourceError::TraceExport(error))
            if matches!(
                error.kind,
                TraceExportErrorKind::InvalidState { ref message }
                    if message.contains("open runnable frame")
            )
    ));

    let input = format!(
        "{HEADER}{}",
        concat!(
            "0; TaskA; switch;\n",
            "1; ISR_A; isrstart;\n",
            "2; Runnable A; runnablestart;\n",
            "3; ISR_A; isrend;\n"
        )
    );
    let mut source =
        TraceTaskEventsSource::new(Cursor::new(input), "session", "taskevents", task_config())
            .unwrap();
    for _ in 0..4 {
        assert!(source.next_observation().unwrap().is_some());
    }
    assert!(matches!(
        source.next_observation(),
        Err(SourceError::TraceExport(error))
            if matches!(
                error.kind,
                TraceExportErrorKind::InvalidState { ref message }
                    if message.contains("open runnable frame")
            )
    ));
}

#[test]
fn taskevents_rejects_runnable_crossing_same_isr_id_activations() {
    let input = format!(
        "{HEADER}{}",
        concat!(
            "0; TaskA; switch;\n",
            "1; ISR_A; isrstart;\n",
            "2; Runnable A; runnablestart;\n",
            "3; ISR_A; isrstart;\n",
            "4; Runnable A; runnablestop;\n"
        )
    );
    let mut source =
        TraceTaskEventsSource::new(Cursor::new(input), "session", "taskevents", task_config())
            .unwrap();
    loop {
        match source.next_observation() {
            Ok(Some(_)) => {}
            Err(SourceError::TraceExport(error)) => {
                assert!(matches!(
                    error.kind,
                    TraceExportErrorKind::InvalidState { ref message }
                        if message.contains("crossed an ISR activation boundary")
                ));
                break;
            }
            other => panic!("same-ID ISR activation crossing was not rejected: {other:?}"),
        }
    }
}

#[test]
fn x86_simulator_fixture_proves_default_zero_is_not_session_origin() {
    let input = include_str!("fixtures/trace32/snooper-x86-simulator-build190766.txt")
        .replace('\n', "\r\n");
    let mut source =
        TraceAsciiSource::new(Cursor::new(input), "session", "snooper", x86_ascii_config())
            .unwrap();
    assert!(matches!(
        source.next_observation(),
        Err(SourceError::TraceExport(error))
            if matches!(
                error.kind,
                TraceExportErrorKind::InvalidAsciiRow { ref message }
                    if message.contains("requires 0ns")
            )
    ));
}

#[test]
fn ascii_internal_pc_uses_elf_range_without_parsing_symbol_offset() {
    let input = "1 C:080481FB snoop 0s *cs_x86\\sieve_funcs\\func2c+0x46\n";
    let mut source =
        TraceAsciiSource::new(Cursor::new(input), "session", "snooper", x86_ascii_config())
            .unwrap();
    let observation = source.next_observation().unwrap().unwrap();
    assert!(matches!(
        observation.observation.event,
        ObservationEvent::Sample {
            address: Some(0x0804_81fb),
            function_id: Some(ref id),
            ..
        } if id == "fn:sampled"
    ));
}

#[test]
fn tc234l_build190766_simulator_fixture_uses_program_access_class_and_no_run_column() {
    let input = include_str!("fixtures/trace32/snooper-tc234l-simulator-build190766.txt")
        .replace('\n', "\r\n");
    let mut source =
        TraceAsciiSource::new(Cursor::new(input), "session", "snooper", ascii_config()).unwrap();
    for expected_order in 1..=3 {
        let observation = source.next_observation().unwrap().unwrap();
        assert_eq!(
            observation.order_key,
            Some(i64::MIN.unsigned_abs() + expected_order)
        );
        assert!(matches!(
            observation.observation.event,
            ObservationEvent::Sample {
                core_id: 0,
                address: Some(0x7010_0000),
                function_id: Some(ref function_id),
                ..
            } if function_id == "fn:sampled"
        ));
    }
    assert!(source.next_observation().unwrap().is_none());
}

#[test]
fn ascii_profile_rejects_unknown_cycle_and_nonintegral_nanoseconds() {
    let mut unknown = TraceAsciiSource::new(
        Cursor::new("-1 P:70100000 magic 0ns symbol\n"),
        "session",
        "snooper",
        ascii_config(),
    )
    .unwrap();
    assert!(matches!(
        unknown.next_observation(),
        Err(SourceError::TraceExport(error))
            if matches!(error.kind, TraceExportErrorKind::UnsupportedAsciiCycle { .. })
    ));

    let mut fractional = TraceAsciiSource::new(
        Cursor::new("-1 P:70100000 snoop 0.5ns symbol\n"),
        "session",
        "snooper",
        ascii_config(),
    )
    .unwrap();
    assert!(matches!(
        fractional.next_observation(),
        Err(SourceError::TraceExport(error))
            if matches!(error.kind, TraceExportErrorKind::InvalidTimestamp { .. })
    ));
}

#[test]
fn ascii_show_record_rejects_legacy_marker_suffixes() {
    for token in ["-1.", "+1|"] {
        let mut source = TraceAsciiSource::new(
            Cursor::new(format!("{token} P:70100000 snoop 0ns symbol\n")),
            "session",
            "snooper",
            ascii_config(),
        )
        .unwrap();
        assert!(matches!(
            source.next_observation(),
            Err(SourceError::TraceExport(error))
                if matches!(
                    error.kind,
                    TraceExportErrorKind::InvalidAsciiRow { ref message }
                        if message.contains("ShowRecord")
                )
        ));
    }
}

#[test]
fn ascii_show_record_must_be_contiguous() {
    let mut source = TraceAsciiSource::new(
        Cursor::new(concat!(
            "+1 P:70100000 snoop 0ns symbol\n",
            "+3 P:70100000 snoop 1ns symbol\n"
        )),
        "session",
        "snooper",
        ascii_config(),
    )
    .unwrap();
    assert!(source.next_observation().unwrap().is_some());
    assert!(matches!(
        source.next_observation(),
        Err(SourceError::TraceExport(error))
            if matches!(
                error.kind,
                TraceExportErrorKind::InvalidAsciiRow { ref message }
                    if message.contains("not contiguous")
            )
    ));
}

#[test]
fn ascii_profile_rejects_unqualified_address_classes() {
    let mut source = TraceAsciiSource::new(
        Cursor::new("-1 C:080481FB snoop 0ns symbol\n"),
        "session",
        "snooper",
        ascii_config(),
    )
    .unwrap();
    assert!(matches!(
        source.next_observation(),
        Err(SourceError::TraceExport(error))
            if matches!(
                error.kind,
                TraceExportErrorKind::InvalidAsciiRow { ref message }
                    if message.contains("Address class")
            )
    ));
}

#[test]
fn ascii_function_attribution_uses_address_ranges_and_rejects_exact_symbol_conflicts() {
    let mut config = ascii_config();
    config.functions.push(TraceFunctionMapping {
        export_name: "OtherFunction".to_owned(),
        function_id: "fn:other".to_owned(),
        display_name: "OtherFunction".to_owned(),
        module: Some("firmware.elf".to_owned()),
        address: Some(0x7020_0000),
        end_address: Some(0x7020_0100),
        file: None,
        line: None,
    });

    let mut conflict = TraceAsciiSource::new(
        Cursor::new("-1 P:70100000 snoop 0ns OtherFunction\n"),
        "session",
        "snooper",
        config.clone(),
    )
    .unwrap();
    assert!(matches!(
        conflict.next_observation(),
        Err(SourceError::TraceExport(error))
            if matches!(
                error.kind,
                TraceExportErrorKind::InvalidAsciiRow { ref message }
                    if message.contains("exact symbol")
            )
    ));

    let mut no_range = function("NoRange", "fn:no-range");
    no_range.address = None;
    no_range.end_address = None;
    config.functions.push(no_range);
    let mut source = TraceAsciiSource::new(
        Cursor::new("-1 P:70300000 snoop 0ns NoRange\n"),
        "session",
        "snooper",
        config,
    )
    .unwrap();
    let observation = source.next_observation().unwrap().unwrap();
    assert!(matches!(
        observation.observation.event,
        ObservationEvent::Sample {
            function_id: None,
            address: Some(0x7030_0000),
            ..
        }
    ));
}

#[test]
fn ascii_range_mapping_is_nonoverlapping_and_scales_to_large_elf_dictionaries() {
    let mut overlap = ascii_config();
    overlap.functions.push(TraceFunctionMapping {
        export_name: "Overlap".to_owned(),
        function_id: "fn:overlap".to_owned(),
        display_name: "Overlap".to_owned(),
        module: None,
        address: Some(0x7010_0008),
        end_address: Some(0x7010_0100),
        file: None,
        line: None,
    });
    assert!(TraceAsciiSource::new(Cursor::new(""), "session", "snooper", overlap).is_err());

    let mut large = ascii_config();
    large.functions.clear();
    for index in 0..20_000_u64 {
        let start = 0x1000_0000 + index * 0x10;
        large.functions.push(TraceFunctionMapping {
            export_name: format!("fn_{index}"),
            function_id: format!("fn:{index}"),
            display_name: format!("fn_{index}"),
            module: None,
            address: Some(start),
            end_address: Some(start + 0x10),
            file: None,
            line: None,
        });
    }
    let address = 0x1000_0000 + 19_999 * 0x10 + 0xf;
    let input = format!("1 P:{address:08X} snoop 0ns fn_19999+0xF\n");
    let mut source =
        TraceAsciiSource::new(Cursor::new(input), "session", "snooper", large).unwrap();
    let observation = source.next_observation().unwrap().unwrap();
    assert!(matches!(
        observation.observation.event,
        ObservationEvent::Sample {
            function_id: Some(ref function_id),
            ..
        } if function_id == "fn:19999"
    ));
}

#[test]
fn taskevents_event_tokens_are_case_sensitive() {
    let input = format!("{HEADER}0; NO_TASK; Switch;\n");
    let mut source =
        TraceTaskEventsSource::new(Cursor::new(input), "session", "taskevents", task_config())
            .unwrap();
    assert!(matches!(
        source.next_observation(),
        Err(SourceError::TraceExport(error))
            if matches!(
                error.kind,
                TraceExportErrorKind::UnsupportedTaskEvent { ref event }
                    if event == "Switch"
            )
    ));
}

#[test]
fn snooper_profile_always_emits_statistical_quality() {
    let mut source = TraceAsciiSource::new(
        Cursor::new("+1 P:70100000 snoop 0ns symbol\n"),
        "session",
        "snooper",
        ascii_config(),
    )
    .unwrap();
    assert_eq!(
        source
            .next_observation()
            .unwrap()
            .unwrap()
            .observation
            .quality,
        Quality::Statistical
    );
}

#[test]
fn executable_elf_ranges_are_deterministic_and_bounded() {
    let functions =
        trace_function_mappings_from_elf(&executable_elf_fixture(), "firmware.elf", 16).unwrap();
    assert_eq!(functions.len(), 2);
    assert_eq!(functions[0].export_name, "first");
    assert_eq!(functions[0].address, Some(0));
    assert_eq!(functions[0].end_address, Some(16));
    assert_eq!(functions[1].address, Some(16));
    assert_eq!(functions[1].end_address, Some(48));
    assert!(
        trace_function_mappings_from_elf(&executable_elf_fixture(), "firmware.elf", 1).is_err()
    );
    assert!(matches!(
        trace_function_mappings_from_elf(
            &stripped_executable_elf_fixture(),
            "firmware.elf",
            16
        ),
        Err(error)
            if matches!(
                error.kind,
                TraceExportErrorKind::InvalidConfiguration { ref message }
                    if message.contains("no defined nonzero-size text functions")
            )
    ));
}

#[test]
fn trace_export_dictionary_limits_apply_before_source_construction() {
    let mut ascii = ascii_config();
    ascii.functions.push(TraceFunctionMapping {
        export_name: "second".to_owned(),
        function_id: "fn:second".to_owned(),
        display_name: "second".to_owned(),
        module: None,
        address: Some(0x7020_0000),
        end_address: Some(0x7020_0010),
        file: None,
        line: None,
    });
    ascii.limits.max_dictionary_entries = 1;
    assert!(matches!(
        TraceAsciiSource::new(Cursor::new(""), "session", "snooper", ascii),
        Err(error)
            if matches!(
                error.kind,
                TraceExportErrorKind::InvalidConfiguration { ref message }
                    if message.contains("dictionary entry count")
            )
    ));

    let mut task = task_config();
    task.limits.max_dictionary_bytes = 1;
    assert!(matches!(
        TraceTaskEventsSource::new(Cursor::new(HEADER), "session", "taskevents", task),
        Err(error)
            if matches!(
                error.kind,
                TraceExportErrorKind::InvalidConfiguration { ref message }
                    if message.contains("dictionary physical bytes")
            )
    ));
}

#[test]
fn mapping_documents_are_strict_versioned_and_schema_backed() {
    let digest = Sha256Digest::new("a".repeat(64)).unwrap();
    let binding = |artifact_id: &str| TraceArtifactBinding {
        artifact_id: artifact_id.to_owned(),
        sha256: digest.clone(),
    };
    let symbol_mapping = Trace32SymbolMappingDocument {
        schema: TRACE32_SYMBOL_MAPPING_SCHEMA.to_owned(),
        profile_id: "t32perf.trace32-ascii-profile/tc234l-build190766-v1".to_owned(),
        profile_sha256: None,
        trace32_release: "2026.02".to_owned(),
        trace32_build: 190_766,
        architecture_package: "tricore".to_owned(),
        target_identifier: "infineon-tc234l-core0".to_owned(),
        elf_artifact_id: "firmware-elf".to_owned(),
        elf_sha256: digest.clone(),
        controller_health: binding("controller-health"),
        time_origin_evidence: binding("controller-export"),
        qualification_receipt: binding("trace32-qualification"),
        address_classes: vec!["P".to_owned()],
        functions: vec![TraceFunctionMapping {
            export_name: "tc234l_loop".to_owned(),
            function_id: "elf:0000000070100000-0000000070100010".to_owned(),
            display_name: "tc234l_loop".to_owned(),
            module: Some("firmware.elf".to_owned()),
            address: Some(0x7010_0000),
            end_address: Some(0x7010_0010),
            file: None,
            line: None,
        }],
    };
    symbol_mapping.validate().unwrap();
    let bytes = serde_json::to_vec(&symbol_mapping).unwrap();
    assert_eq!(
        parse_trace32_symbol_mapping(&bytes).unwrap(),
        symbol_mapping
    );
    let duplicate = String::from_utf8(bytes).unwrap().replacen(
        r#""profile_id":"t32perf.trace32-ascii-profile/tc234l-build190766-v1""#,
        r#""profile_id":"t32perf.trace32-ascii-profile/tc234l-build190766-v1","profile_id":"duplicate""#,
        1,
    );
    assert!(parse_trace32_symbol_mapping(duplicate.as_bytes()).is_err());

    let task_mapping = Trace32TaskEventsMappingDocument {
        schema: TRACE32_TASK_EVENTS_MAPPING_SCHEMA.to_owned(),
        profile_id: "task-events-profile/v1".to_owned(),
        profile_sha256: digest.clone(),
        trace32_release: "2026.02".to_owned(),
        trace32_build: 190_766,
        architecture_package: "tricore".to_owned(),
        target_identifier: "qualified-target".to_owned(),
        core_id: 0,
        elf_artifact_id: "firmware-elf".to_owned(),
        elf_sha256: digest.clone(),
        metadata_artifacts: vec![
            TraceTaskMetadataBinding {
                role: TraceTaskMetadataRole::Orti,
                artifact: binding("orti"),
            },
            TraceTaskMetadataBinding {
                role: TraceTaskMetadataRole::Markers,
                artifact: binding("markers"),
            },
        ],
        controller_health: binding("controller-health"),
        time_origin_evidence: binding("controller-export"),
        qualification_receipt: binding("task-events-qualification"),
        contexts: task_config().contexts,
        functions: task_config().functions,
        runnables: vec![TraceRunnableMapping {
            export_name: "Runnable A".to_owned(),
            function_id: "fn:runnable-a".to_owned(),
        }],
    };
    task_mapping.validate().unwrap();
    let bytes = serde_json::to_vec(&task_mapping).unwrap();
    assert_eq!(
        parse_trace32_task_events_mapping(&bytes).unwrap(),
        task_mapping
    );
    let mut invalid_profile_digest = serde_json::to_value(&task_mapping).unwrap();
    invalid_profile_digest["profile_sha256"] = serde_json::json!("not-a-sha256-digest");
    assert!(
        parse_trace32_task_events_mapping(
            serde_json::to_vec(&invalid_profile_digest)
                .unwrap()
                .as_slice()
        )
        .is_err()
    );
    let mut duplicate_runnable = task_mapping.clone();
    duplicate_runnable
        .runnables
        .push(duplicate_runnable.runnables[0].clone());
    assert!(matches!(
        duplicate_runnable.validate(),
        Err(error)
            if matches!(
                error.kind,
                TraceExportErrorKind::InvalidConfiguration { ref message }
                    if message.contains("duplicate TASKEVENTS runnable")
            )
    ));
    let schemas = trace_export_schema_documents();
    assert_eq!(
        schemas["trace32-symbol-mapping.schema.json"]["$id"],
        TRACE32_SYMBOL_MAPPING_SCHEMA
    );
    assert_eq!(
        schemas["trace32-task-events-mapping.schema.json"]["$id"],
        TRACE32_TASK_EVENTS_MAPPING_SCHEMA
    );
}

#[test]
fn task_events_template_materializes_only_exact_closed_runtime_bindings() {
    let digest = Sha256Digest::new("a".repeat(64)).unwrap();
    let binding = |artifact_id: &str| TraceArtifactBinding {
        artifact_id: artifact_id.to_owned(),
        sha256: digest.clone(),
    };
    let config = task_config();
    let template = Trace32TaskEventsMappingTemplateDocument {
        schema: TRACE32_TASK_EVENTS_MAPPING_TEMPLATE_SCHEMA.to_owned(),
        profile_id: "task-events-profile/v1".to_owned(),
        core_id: 0,
        contexts: config.contexts,
        functions: config.functions,
        runnables: vec![TraceRunnableMapping {
            export_name: "Runnable A".to_owned(),
            function_id: "fn:runnable-a".to_owned(),
        }],
    };
    template.validate().unwrap();
    let template_bytes = serde_json::to_vec(&template).unwrap();
    assert_eq!(
        parse_trace32_task_events_mapping_template(&template_bytes).unwrap(),
        template
    );
    let duplicate = String::from_utf8(template_bytes).unwrap().replacen(
        r#""profile_id":"task-events-profile/v1""#,
        r#""profile_id":"task-events-profile/v1","profile_id":"duplicate""#,
        1,
    );
    assert!(parse_trace32_task_events_mapping_template(duplicate.as_bytes()).is_err());
    let mut unknown_entry = template.clone();
    unknown_entry.contexts[1].entry_function_id = Some("fn:not-qualified".to_owned());
    assert!(matches!(
        unknown_entry.validate(),
        Err(error)
            if matches!(
                error.kind,
                TraceExportErrorKind::InvalidConfiguration { ref message }
                    if message.contains("entry function is absent")
            )
    ));
    let mut duplicate_runnable = template.clone();
    duplicate_runnable
        .runnables
        .push(duplicate_runnable.runnables[0].clone());
    assert!(matches!(
        duplicate_runnable.validate(),
        Err(error)
            if matches!(
                error.kind,
                TraceExportErrorKind::InvalidConfiguration { ref message }
                    if message.contains("duplicate TASKEVENTS runnable")
            )
    ));
    let mut excessive_contexts = template.clone();
    excessive_contexts.contexts = vec![
        context("NO_TASK", "idle:0", ContextKind::Idle, None, None);
        MAX_TRACE32_TASK_EVENTS_CONTEXTS + 1
    ];
    assert!(matches!(
        excessive_contexts.validate(),
        Err(error)
            if matches!(
                error.kind,
                TraceExportErrorKind::InvalidConfiguration { ref message }
                    if message.contains("context count exceeds")
            )
    ));

    let runtime = TraceTaskEventsRuntimeBinding {
        profile_id: "task-events-profile/v1".to_owned(),
        profile_sha256: digest.clone(),
        core_id: 0,
        trace32: TraceTaskEventsTrace32Identity {
            release: "2026.02".to_owned(),
            build: 190_766,
            architecture_package: "tricore".to_owned(),
        },
        target_identifier: "qualified-target".to_owned(),
        elf: binding("firmware-elf"),
        metadata_artifacts: vec![
            TraceTaskMetadataBinding {
                role: TraceTaskMetadataRole::Orti,
                artifact: binding("orti"),
            },
            TraceTaskMetadataBinding {
                role: TraceTaskMetadataRole::Markers,
                artifact: binding("markers"),
            },
        ],
        controller_health: binding("controller-health"),
        stop_time_origin_evidence: binding("controller-stop"),
        qualification_receipt: binding("qualification"),
    };
    let materialized = materialize_trace32_task_events_mapping(&template, &runtime).unwrap();
    assert_eq!(materialized.profile_sha256, digest);
    assert_eq!(
        materialized.time_origin_evidence.artifact_id,
        "controller-stop"
    );

    let mut wrong_core = runtime.clone();
    wrong_core.core_id = 1;
    assert!(matches!(
        materialize_trace32_task_events_mapping(&template, &wrong_core),
        Err(error)
            if matches!(
                error.kind,
                TraceExportErrorKind::InvalidConfiguration { ref message }
                    if message.contains("template core")
            )
    ));
    let mut duplicate_metadata = runtime;
    duplicate_metadata.metadata_artifacts[1].artifact = binding("orti");
    assert!(matches!(
        materialize_trace32_task_events_mapping(&template, &duplicate_metadata),
        Err(error)
            if matches!(
                error.kind,
                TraceExportErrorKind::InvalidConfiguration { ref message }
                    if message.contains("duplicate TASKEVENTS metadata artifact")
            )
    ));

    let mut missing_metadata = materialized;
    missing_metadata.metadata_artifacts.pop();
    assert!(matches!(
        missing_metadata.validate(),
        Err(error)
            if matches!(
                error.kind,
                TraceExportErrorKind::InvalidConfiguration { ref message }
                    if message.contains("exactly ORTI and marker")
            )
    ));

    let schemas = trace_export_schema_documents();
    assert_eq!(
        schemas["trace32-task-events-mapping-template.schema.json"]["$id"],
        TRACE32_TASK_EVENTS_MAPPING_TEMPLATE_SCHEMA
    );
}
