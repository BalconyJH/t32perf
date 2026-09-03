use serde_json::json;
use t32perf_model::*;

fn semantic(value: &'static str) -> CounterSemantic {
    CounterSemantic::new(value).unwrap()
}

fn counter(
    id: &str,
    semantic: Option<CounterSemantic>,
    subject: Option<CounterSubject>,
    unit: Option<&str>,
) -> DictionaryEntry {
    DictionaryEntry::DefineCounter {
        id: id.to_owned(),
        name: "opaque counter".to_owned(),
        unit: unit.map(str::to_owned),
        description: None,
        semantic,
        subject,
    }
}

#[test]
fn semantic_is_extensible_but_standard_contracts_are_exact() {
    let custom = CounterSemantic::new("vendor.pool_pressure").unwrap();
    assert!(custom.standard_spec().is_none());
    assert!(CounterSemantic::new("Heap.Current").is_err());
    assert!(CounterSemantic::new("heap..current").is_err());

    let standard = semantic(CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES);
    let spec = standard.standard_spec().unwrap();
    assert_eq!(spec.unit, "bytes");
    assert_eq!(spec.class, ResourceClass::Heap);
    assert!(spec.value_is_valid(MAX_EXACT_COUNTER_INTEGER));
    assert!(!spec.value_is_valid(MAX_EXACT_COUNTER_INTEGER + 2.0));
    assert!(!spec.value_is_valid(1.5));
}

#[test]
fn dictionary_requires_paired_semantics_units_subjects_and_unique_identity() {
    let allocator = CounterSubject::Allocator {
        allocator_id: "system".to_owned(),
    };
    let mut dictionary = ObservationDictionary::new("session");
    dictionary.entries.push(counter(
        "opaque-a",
        Some(semantic(CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES)),
        Some(allocator.clone()),
        Some("bytes"),
    ));
    assert!(dictionary.validate().is_ok());

    dictionary.entries.push(counter(
        "opaque-b",
        Some(semantic(CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES)),
        Some(allocator.clone()),
        Some("bytes"),
    ));
    assert!(matches!(
        dictionary.validate(),
        Err(DictionaryValidationError::DuplicateCounterIdentity { .. })
    ));

    let mut partial = ObservationDictionary::new("session");
    partial.entries.push(counter(
        "partial",
        Some(semantic(CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES)),
        None,
        Some("bytes"),
    ));
    assert!(matches!(
        partial.validate(),
        Err(DictionaryValidationError::IncompleteCounterSemantics { .. })
    ));

    let mut wrong_unit = ObservationDictionary::new("session");
    wrong_unit.entries.push(counter(
        "wrong-unit",
        Some(semantic(CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES)),
        Some(allocator),
        Some("count"),
    ));
    assert!(matches!(
        wrong_unit.validate(),
        Err(DictionaryValidationError::CounterUnitMismatch { .. })
    ));
}

#[test]
fn stack_subject_references_the_required_context_kind() {
    let mut dictionary = ObservationDictionary::new("session");
    dictionary.entries = vec![
        DictionaryEntry::DefineContext {
            id: "irq".to_owned(),
            kind: ContextKind::Isr,
            name: "IRQ".to_owned(),
            core_id: Some(0),
            priority: Some(1),
        },
        counter(
            "opaque-stack",
            Some(semantic(CounterSemantic::STACK_PEAK_USED_BYTES)),
            Some(CounterSubject::Stack {
                stack_id: "task-stack".to_owned(),
                role: StackRole::Task,
                context_id: Some("irq".to_owned()),
                core_id: Some(0),
            }),
            Some("bytes"),
        ),
    ];
    assert!(matches!(
        dictionary.validate(),
        Err(DictionaryValidationError::StackContextKindMismatch { .. })
    ));
}

#[test]
fn legacy_generic_counter_and_health_document_remain_readable() {
    let generic: DictionaryEntry = serde_json::from_value(json!({
        "type": "DefineCounter",
        "id": "heap-stack-ram",
        "name": "misleading legacy name",
        "unit": "widgets"
    }))
    .unwrap();
    let dictionary = ObservationDictionary {
        schema: DictionarySchemaVersion,
        session_id: "session".to_owned(),
        entries: vec![generic],
    };
    dictionary.validate().unwrap();

    let mut support =
        serde_json::to_value(MetricSupport::uniform(MetricSupportLevel::Exact)).unwrap();
    support.as_object_mut().unwrap().remove("resource_counters");
    let report: HealthReport = serde_json::from_value(json!({
        "schema": "t32perf.health/v1",
        "session_id": "session",
        "verdict": "VALID",
        "policy_version": "t32perf.health-policy/v1",
        "observations": [],
        "issues": [],
        "metric_support": support
    }))
    .unwrap();
    assert_eq!(
        report.metric_support.resource_counters.support,
        MetricSupportLevel::Unavailable
    );
    assert_eq!(
        report.metric_support.resource_counters.reasons,
        ["resource_counter_support_not_recorded"]
    );
    report.validate().unwrap();
}

#[test]
fn static_ram_config_accepts_only_exact_additions() {
    let mut config = StaticRamConfigDocument::gnu_ld_map_v1();
    config.additional_sections = vec![
        StaticRamSectionConfig {
            name: ".dma_buffers".to_owned(),
            kind: StaticRamAdditionalSectionKind::Dma,
        },
        StaticRamSectionConfig {
            name: ".rtos_objects".to_owned(),
            kind: StaticRamAdditionalSectionKind::Rtos,
        },
        StaticRamSectionConfig {
            name: ".project_cache".to_owned(),
            kind: StaticRamAdditionalSectionKind::Custom,
        },
    ];
    config.validate().unwrap();

    let mut elf_config = StaticRamConfigDocument::elf_sections_v1();
    elf_config.additional_sections = config.additional_sections.clone();
    elf_config.validate().unwrap();

    for name in [".dma*", ".bss", "dma_buffers"] {
        let mut invalid = StaticRamConfigDocument::gnu_ld_map_v1();
        invalid.additional_sections.push(StaticRamSectionConfig {
            name: name.to_owned(),
            kind: StaticRamAdditionalSectionKind::Dma,
        });
        assert!(invalid.validate().is_err(), "{name} must be rejected");
    }

    let mut too_many = StaticRamConfigDocument::elf_sections_v1();
    too_many.additional_sections = (0..=MAX_STATIC_RAM_ADDITIONAL_SECTIONS)
        .map(|index| StaticRamSectionConfig {
            name: format!(".custom_{index}"),
            kind: StaticRamAdditionalSectionKind::Custom,
        })
        .collect();
    assert!(matches!(
        too_many.validate(),
        Err(StaticRamConfigValidationError::TooManyAdditionalSections { .. })
    ));
}
