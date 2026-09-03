use std::io::{BufReader, Cursor, Read};

use object::{Architecture, BinaryFormat, Endianness, SectionKind, write::Object};
use t32perf_model::{
    StaticRamAdditionalSectionKind, StaticRamConfigDocument, StaticRamConfigSchemaVersion,
    StaticRamConfigValidationError, StaticRamSectionConfig,
};
use t32perf_trace32::{
    AdditionalStaticRamSectionKind, ELF_SECTIONS_V1_FLAVOR, ELF_SECTIONS_V1_SCHEMA,
    ElfStaticRamArchitecture, ElfStaticRamClass, ElfStaticRamEndianness, ElfStaticRamObjectKind,
    GCC_STACK_USAGE_V1_FLAVOR, GCC_STACK_USAGE_V1_SCHEMA, GNU_LD_MAP_V1_FLAVOR,
    GNU_LD_MAP_V1_SCHEMA, GccStackUsageReader, GnuLdMapConfig, LineLimits,
    STACK_USAGE_REPORT_SCHEMA, STATIC_RAM_REPORT_SCHEMA, StackUsageError, StackUsageKind,
    StackUsageReport, StaticRamConfigError, StaticRamError, StaticRamReport, StaticRamSectionKind,
    parse_stack_usage_report, parse_static_ram_report, resource_schema_documents,
};

struct RepeatedRead {
    pattern: &'static [u8],
    repetitions: u64,
    pattern_offset: usize,
    suffix: Cursor<Vec<u8>>,
}

impl RepeatedRead {
    fn new(pattern: &'static [u8], repetitions: u64, suffix: &[u8]) -> Self {
        Self {
            pattern,
            repetitions,
            pattern_offset: 0,
            suffix: Cursor::new(suffix.to_vec()),
        }
    }
}

impl Read for RepeatedRead {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let mut written = 0;
        while written < output.len() && self.repetitions != 0 {
            let available = &self.pattern[self.pattern_offset..];
            let count = available.len().min(output.len() - written);
            output[written..written + count].copy_from_slice(&available[..count]);
            written += count;
            self.pattern_offset += count;
            if self.pattern_offset == self.pattern.len() {
                self.pattern_offset = 0;
                self.repetitions -= 1;
            }
        }
        if written == output.len() || self.repetitions != 0 {
            return Ok(written);
        }
        self.suffix
            .read(&mut output[written..])
            .map(|count| written + count)
    }
}

fn map_config() -> GnuLdMapConfig {
    let mut config = GnuLdMapConfig::new();
    config
        .insert_section(".dma", AdditionalStaticRamSectionKind::Dma)
        .unwrap();
    config
        .insert_section(".rtos", AdditionalStaticRamSectionKind::Rtos)
        .unwrap();
    config
        .insert_section(".project_ram", AdditionalStaticRamSectionKind::Custom)
        .unwrap();
    config
}

fn elf_fixture(architecture: Architecture, sections: &[(&str, SectionKind, u64)]) -> Vec<u8> {
    elf_fixture_with_endianness(architecture, Endianness::Little, sections)
}

fn elf_fixture_with_endianness(
    architecture: Architecture,
    endianness: Endianness,
    sections: &[(&str, SectionKind, u64)],
) -> Vec<u8> {
    let mut object = Object::new(BinaryFormat::Elf, architecture, endianness);
    for (name, kind, size) in sections {
        let id = object.add_section(Vec::new(), name.as_bytes().to_vec(), *kind);
        if kind.is_bss() {
            object.append_section_bss(id, *size, 4);
        } else {
            object.append_section_data(id, &vec![0_u8; usize::try_from(*size).unwrap()], 4);
        }
    }
    object.write().unwrap()
}

#[derive(Clone, Copy)]
enum TriCoreFixtureEndianness {
    Little,
    Big,
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16, endianness: TriCoreFixtureEndianness) {
    let encoded = match endianness {
        TriCoreFixtureEndianness::Little => value.to_le_bytes(),
        TriCoreFixtureEndianness::Big => value.to_be_bytes(),
    };
    bytes[offset..offset + encoded.len()].copy_from_slice(&encoded);
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32, endianness: TriCoreFixtureEndianness) {
    let encoded = match endianness {
        TriCoreFixtureEndianness::Little => value.to_le_bytes(),
        TriCoreFixtureEndianness::Big => value.to_be_bytes(),
    };
    bytes[offset..offset + encoded.len()].copy_from_slice(&encoded);
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64, endianness: TriCoreFixtureEndianness) {
    let encoded = match endianness {
        TriCoreFixtureEndianness::Little => value.to_le_bytes(),
        TriCoreFixtureEndianness::Big => value.to_be_bytes(),
    };
    bytes[offset..offset + encoded.len()].copy_from_slice(&encoded);
}

fn tricore_elf_fixture(
    endianness: TriCoreFixtureEndianness,
    machine: u16,
    data_flags: u32,
) -> Vec<u8> {
    const ELF_HEADER_SIZE: usize = 52;
    const SECTION_HEADER_SIZE: usize = 40;
    const SECTION_HEADER_OFFSET: usize = 0x100;
    const SECTION_COUNT: usize = 6;
    const SECTION_NAME_TABLE: &[u8] = b"\0.shstrtab\0.data\0.bss\0.noinit\0.dma_buffers\0";
    const SECTION_NAME_TABLE_OFFSET: usize = ELF_HEADER_SIZE;
    const DATA_OFFSET: usize = SECTION_HEADER_OFFSET + SECTION_HEADER_SIZE * SECTION_COUNT;
    const SECTION_HEADER_FLAGS_OFFSET: usize = 8;
    const SHF_WRITE_ALLOC: u32 = 0x3;

    let mut bytes = vec![0_u8; DATA_OFFSET + 80];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 1; // ELFCLASS32
    bytes[5] = match endianness {
        TriCoreFixtureEndianness::Little => 1,
        TriCoreFixtureEndianness::Big => 2,
    };
    bytes[6] = 1; // EV_CURRENT
    put_u16(&mut bytes, 16, 1, endianness); // ET_REL
    put_u16(&mut bytes, 18, machine, endianness);
    put_u32(&mut bytes, 20, 1, endianness); // EV_CURRENT
    put_u32(
        &mut bytes,
        32,
        u32::try_from(SECTION_HEADER_OFFSET).unwrap(),
        endianness,
    );
    put_u16(
        &mut bytes,
        40,
        u16::try_from(ELF_HEADER_SIZE).unwrap(),
        endianness,
    );
    put_u16(
        &mut bytes,
        46,
        u16::try_from(SECTION_HEADER_SIZE).unwrap(),
        endianness,
    );
    put_u16(
        &mut bytes,
        48,
        u16::try_from(SECTION_COUNT).unwrap(),
        endianness,
    );
    put_u16(&mut bytes, 50, 1, endianness); // .shstrtab
    bytes[SECTION_NAME_TABLE_OFFSET..SECTION_NAME_TABLE_OFFSET + SECTION_NAME_TABLE.len()]
        .copy_from_slice(SECTION_NAME_TABLE);

    let write_section = |bytes: &mut [u8],
                         index: usize,
                         name_offset: u32,
                         section_type: u32,
                         flags: u32,
                         address: u32,
                         offset: u32,
                         size: u32,
                         endianness| {
        let base = SECTION_HEADER_OFFSET + index * SECTION_HEADER_SIZE;
        put_u32(bytes, base, name_offset, endianness);
        put_u32(bytes, base + 4, section_type, endianness);
        put_u32(bytes, base + SECTION_HEADER_FLAGS_OFFSET, flags, endianness);
        put_u32(bytes, base + 12, address, endianness);
        put_u32(bytes, base + 16, offset, endianness);
        put_u32(bytes, base + 20, size, endianness);
        put_u32(bytes, base + 32, 4, endianness);
    };
    write_section(
        &mut bytes,
        1,
        1,
        3,
        0,
        0,
        u32::try_from(SECTION_NAME_TABLE_OFFSET).unwrap(),
        u32::try_from(SECTION_NAME_TABLE.len()).unwrap(),
        endianness,
    );
    write_section(
        &mut bytes,
        2,
        11,
        1,
        data_flags,
        0x7000_0000,
        u32::try_from(DATA_OFFSET).unwrap(),
        16,
        endianness,
    );
    write_section(
        &mut bytes,
        3,
        17,
        8,
        SHF_WRITE_ALLOC,
        0x7000_0010,
        0,
        32,
        endianness,
    );
    write_section(
        &mut bytes,
        4,
        22,
        8,
        SHF_WRITE_ALLOC,
        0x7000_0030,
        0,
        8,
        endianness,
    );
    write_section(
        &mut bytes,
        5,
        30,
        1,
        SHF_WRITE_ALLOC,
        0x7000_0040,
        u32::try_from(DATA_OFFSET + 16).unwrap(),
        64,
        endianness,
    );
    bytes
}

fn write_tricore_little_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn gnu_ld_map_v1_counts_only_selected_top_level_output_sections() {
    let input = concat!(
        "Memory Configuration\r\n",
        ".text 0x08000000 0x100\r\n",
        ".data 0x20000000 0x10 load address 0x08000100\r\n",
        " .data.member 0x20000000 0x10 input.o\r\n",
        ".bss 0x20000010 32\r\n",
        ".noinit 0x20000030 0x8\r\n",
        ".dma 0x20000038 0x40\r\n",
        ".rtos 0x20000078 0x18\r\n",
        ".project_ram 0x20000090 16",
    );
    let report =
        parse_static_ram_report(GNU_LD_MAP_V1_FLAVOR, Cursor::new(input), &map_config()).unwrap();
    assert_eq!(report.total_bytes, 160);
    assert_eq!(report.totals.data_bytes, 16);
    assert_eq!(report.totals.bss_bytes, 32);
    assert_eq!(report.totals.noinit_bytes, 8);
    assert_eq!(report.totals.dma_bytes, 64);
    assert_eq!(report.totals.rtos_bytes, 24);
    assert_eq!(report.totals.custom_bytes, 16);
    assert_eq!(report.totals.checked_total(), Some(report.total_bytes));
    assert_eq!(report.sections.len(), 6);
    assert_eq!(report.sections[0].name, ".data");
    assert_eq!(report.sections[0].source_line, Some(3));
    assert_eq!(report.sections[0].source_section_index, None);
    assert_eq!(report.sections[3].kind, StaticRamSectionKind::Dma);
    assert_eq!(report.sections[4].kind, StaticRamSectionKind::Rtos);
    assert_eq!(report.sections[5].kind, StaticRamSectionKind::Custom);
    let mut json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["schema"], GNU_LD_MAP_V1_SCHEMA);
    assert_eq!(json["totals"]["dma_bytes"], 64);
    assert_eq!(
        serde_json::from_value::<StaticRamReport>(json.clone()).unwrap(),
        report
    );
    let mut legacy_json = json.clone();
    legacy_json.as_object_mut().unwrap().remove("totals");
    assert_eq!(
        serde_json::from_value::<StaticRamReport>(legacy_json).unwrap(),
        report
    );
    json["schema"] = "t32perf.static-ram/gnu-ld-map-v2".into();
    assert!(serde_json::from_value::<StaticRamReport>(json).is_err());
}

#[test]
fn elf_sections_v1_counts_only_exact_allocated_writable_sections() {
    let input = elf_fixture(
        Architecture::Arm,
        &[
            (".text", SectionKind::Text, 128),
            (".rodata", SectionKind::ReadOnlyData, 64),
            (".data", SectionKind::Data, 16),
            (".bss", SectionKind::UninitializedData, 32),
            (".noinit", SectionKind::UninitializedData, 8),
            (".dma", SectionKind::Data, 64),
            (".rtos", SectionKind::UninitializedData, 24),
            (".project_ram", SectionKind::Data, 16),
        ],
    );
    let report =
        parse_static_ram_report(ELF_SECTIONS_V1_FLAVOR, Cursor::new(input), &map_config()).unwrap();
    assert_eq!(
        report.schema,
        t32perf_trace32::StaticRamReportSchema::ElfSectionsV1
    );
    assert_eq!(report.total_bytes, 160);
    assert_eq!(report.sections.len(), 6);
    assert_eq!(report.totals.data_bytes, 16);
    assert_eq!(report.totals.bss_bytes, 32);
    assert_eq!(report.totals.noinit_bytes, 8);
    assert_eq!(report.totals.dma_bytes, 64);
    assert_eq!(report.totals.rtos_bytes, 24);
    assert_eq!(report.totals.custom_bytes, 16);
    assert!(report.sections.iter().all(|section| {
        section.source_line.is_none() && section.source_section_index.is_some_and(|index| index > 0)
    }));
    let elf = report.elf.as_ref().unwrap();
    assert_eq!(elf.architecture, ElfStaticRamArchitecture::Arm);
    assert_eq!(elf.object_kind, ElfStaticRamObjectKind::Relocatable);
    assert_eq!(elf.class, ElfStaticRamClass::Elf32);
    assert_eq!(elf.endianness, ElfStaticRamEndianness::Little);

    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["schema"], ELF_SECTIONS_V1_SCHEMA);
    assert_eq!(
        serde_json::from_value::<StaticRamReport>(json).unwrap(),
        report
    );
}

#[test]
fn elf_sections_v1_accepts_little_endian_tricore_exact_sections() {
    let mut config = GnuLdMapConfig::new();
    config
        .insert_section(".dma_buffers", AdditionalStaticRamSectionKind::Dma)
        .unwrap();
    let report = parse_static_ram_report(
        ELF_SECTIONS_V1_FLAVOR,
        Cursor::new(tricore_elf_fixture(
            TriCoreFixtureEndianness::Little,
            object::elf::EM_TRICORE.0,
            0x3,
        )),
        &config,
    )
    .unwrap();

    assert_eq!(
        report.elf.unwrap().architecture,
        ElfStaticRamArchitecture::TriCore
    );
    assert_eq!(report.total_bytes, 120);
    assert_eq!(
        report
            .sections
            .iter()
            .map(|section| section.name.as_str())
            .collect::<Vec<_>>(),
        vec![".data", ".bss", ".noinit", ".dma_buffers"]
    );
    assert_eq!(report.totals.data_bytes, 16);
    assert_eq!(report.totals.bss_bytes, 32);
    assert_eq!(report.totals.noinit_bytes, 8);
    assert_eq!(report.totals.dma_bytes, 64);
}

#[test]
fn elf_sections_v1_rejects_invalid_tricore_identity_and_section_flags() {
    let config = GnuLdMapConfig::new();
    assert!(matches!(
        parse_static_ram_report(
            ELF_SECTIONS_V1_FLAVOR,
            Cursor::new(tricore_elf_fixture(
                TriCoreFixtureEndianness::Big,
                object::elf::EM_TRICORE.0,
                0x3,
            )),
            &config,
        ),
        Err(StaticRamError::UnsupportedElfArchitecture { .. })
    ));
    assert!(matches!(
        parse_static_ram_report(
            ELF_SECTIONS_V1_FLAVOR,
            Cursor::new(tricore_elf_fixture(
                TriCoreFixtureEndianness::Little,
                object::elf::EM_TRICORE.0 + 1,
                0x3,
            )),
            &config,
        ),
        Err(StaticRamError::UnsupportedElfArchitecture { .. })
    ));
    assert!(matches!(
        parse_static_ram_report(
            ELF_SECTIONS_V1_FLAVOR,
            Cursor::new(tricore_elf_fixture(
                TriCoreFixtureEndianness::Little,
                object::elf::EM_TRICORE.0,
                0x2,
            )),
            &config,
        ),
        Err(StaticRamError::ElfSectionNotWritableRam { name, .. }) if name == ".data"
    ));
}

#[test]
fn elf_sections_v1_rejects_selected_progbits_payload_range_failures() {
    const DATA_SECTION_INDEX: usize = 2;
    const SECTION_HEADER_OFFSET: usize = 0x100;
    const SECTION_HEADER_SIZE: usize = 40;
    const DATA_OFFSET: usize = SECTION_HEADER_OFFSET + SECTION_HEADER_SIZE * 6;
    let data_header = SECTION_HEADER_OFFSET + DATA_SECTION_INDEX * SECTION_HEADER_SIZE;
    let config = GnuLdMapConfig::new();

    let mut malformed_offset = tricore_elf_fixture(
        TriCoreFixtureEndianness::Little,
        object::elf::EM_TRICORE.0,
        0x3,
    );
    let invalid_offset = u32::try_from(malformed_offset.len() + 1).unwrap();
    write_tricore_little_u32(&mut malformed_offset, data_header + 16, invalid_offset);
    assert!(matches!(
        parse_static_ram_report(
            ELF_SECTIONS_V1_FLAVOR,
            Cursor::new(malformed_offset),
            &config,
        ),
        Err(StaticRamError::InvalidElf { .. })
    ));

    let mut malformed_size = tricore_elf_fixture(
        TriCoreFixtureEndianness::Little,
        object::elf::EM_TRICORE.0,
        0x3,
    );
    write_tricore_little_u32(&mut malformed_size, data_header + 20, u32::MAX);
    assert!(matches!(
        parse_static_ram_report(ELF_SECTIONS_V1_FLAVOR, Cursor::new(malformed_size), &config,),
        Err(StaticRamError::InvalidElf { .. })
    ));

    let mut truncated_payload = tricore_elf_fixture(
        TriCoreFixtureEndianness::Little,
        object::elf::EM_TRICORE.0,
        0x3,
    );
    truncated_payload.truncate(DATA_OFFSET + 8);
    assert!(matches!(
        parse_static_ram_report(
            ELF_SECTIONS_V1_FLAVOR,
            Cursor::new(truncated_payload),
            &config,
        ),
        Err(StaticRamError::InvalidElf { .. })
    ));
}

#[test]
fn elf_sections_v1_fails_closed_on_flags_duplicates_architecture_kind_and_format() {
    let mut readonly_config = GnuLdMapConfig::new();
    readonly_config
        .insert_section(".readonly", AdditionalStaticRamSectionKind::Custom)
        .unwrap();
    let readonly = elf_fixture(
        Architecture::Arm,
        &[(".readonly", SectionKind::ReadOnlyData, 16)],
    );
    assert!(matches!(
        parse_static_ram_report(
            ELF_SECTIONS_V1_FLAVOR,
            Cursor::new(readonly),
            &readonly_config,
        ),
        Err(StaticRamError::ElfSectionNotWritableRam { name, .. }) if name == ".readonly"
    ));

    let duplicate = elf_fixture(
        Architecture::Arm,
        &[
            (".data", SectionKind::Data, 8),
            (".data", SectionKind::Data, 16),
        ],
    );
    assert!(matches!(
        parse_static_ram_report(
            ELF_SECTIONS_V1_FLAVOR,
            Cursor::new(duplicate),
            &GnuLdMapConfig::new(),
        ),
        Err(StaticRamError::DuplicateElfSection { name, .. }) if name == ".data"
    ));

    let unsupported_architecture =
        elf_fixture(Architecture::X86_64, &[(".data", SectionKind::Data, 8)]);
    assert!(matches!(
        parse_static_ram_report(
            ELF_SECTIONS_V1_FLAVOR,
            Cursor::new(unsupported_architecture),
            &GnuLdMapConfig::new(),
        ),
        Err(StaticRamError::UnsupportedElfArchitecture { .. })
    ));

    let mut core = elf_fixture(Architecture::Arm, &[(".data", SectionKind::Data, 8)]);
    core[16] = 4; // ELF ET_CORE.
    core[17] = 0;
    assert!(matches!(
        parse_static_ram_report(
            ELF_SECTIONS_V1_FLAVOR,
            Cursor::new(core),
            &GnuLdMapConfig::new(),
        ),
        Err(StaticRamError::UnsupportedElfObjectKind { .. })
    ));

    assert!(matches!(
        parse_static_ram_report(
            ELF_SECTIONS_V1_FLAVOR,
            Cursor::new(b"not-elf"),
            &GnuLdMapConfig::new(),
        ),
        Err(StaticRamError::UnsupportedFileFormat)
    ));
    assert!(matches!(
        parse_static_ram_report(
            ELF_SECTIONS_V1_FLAVOR,
            Cursor::new(b"\x7fELF\x01"),
            &GnuLdMapConfig::new(),
        ),
        Err(StaticRamError::InvalidElf { .. })
    ));
}

#[test]
fn elf_sections_v1_enforces_byte_and_section_bounds() {
    let input = elf_fixture(Architecture::Arm, &[(".data", SectionKind::Data, 32)]);
    let mut byte_limited = GnuLdMapConfig::new();
    byte_limited.max_elf_bytes = u64::try_from(input.len() - 1).unwrap();
    assert!(matches!(
        parse_static_ram_report(ELF_SECTIONS_V1_FLAVOR, Cursor::new(&input), &byte_limited,),
        Err(StaticRamError::ElfInputTooLarge { .. })
    ));

    let mut section_limited = GnuLdMapConfig::new();
    section_limited.max_elf_sections = 1;
    assert!(matches!(
        parse_static_ram_report(ELF_SECTIONS_V1_FLAVOR, Cursor::new(input), &section_limited,),
        Err(StaticRamError::ElfSectionLimitExceeded { limit: 1 })
    ));
}

#[test]
fn elf_sections_v1_preflights_class_and_byte_order_before_object_parsing() {
    for (architecture, endianness, class, byte_order) in [
        (
            Architecture::Arm,
            Endianness::Little,
            ElfStaticRamClass::Elf32,
            ElfStaticRamEndianness::Little,
        ),
        (
            Architecture::Arm,
            Endianness::Big,
            ElfStaticRamClass::Elf32,
            ElfStaticRamEndianness::Big,
        ),
        (
            Architecture::Aarch64,
            Endianness::Little,
            ElfStaticRamClass::Elf64,
            ElfStaticRamEndianness::Little,
        ),
        (
            Architecture::Aarch64,
            Endianness::Big,
            ElfStaticRamClass::Elf64,
            ElfStaticRamEndianness::Big,
        ),
    ] {
        let report = parse_static_ram_report(
            ELF_SECTIONS_V1_FLAVOR,
            Cursor::new(elf_fixture_with_endianness(
                architecture,
                endianness,
                &[(".data", SectionKind::Data, 8)],
            )),
            &GnuLdMapConfig::new(),
        )
        .unwrap();
        let elf = report.elf.unwrap();
        assert_eq!(elf.class, class);
        assert_eq!(elf.endianness, byte_order);
    }
}

#[test]
fn elf_sections_v1_preflight_rejects_extended_section_table_abuse() {
    const SECTION_HEADER_OFFSET: usize = 0x100;
    const SECTION_HEADER_SIZE: usize = 40;
    let config = GnuLdMapConfig::new();

    let mut extended_count = tricore_elf_fixture(
        TriCoreFixtureEndianness::Little,
        object::elf::EM_TRICORE.0,
        0x3,
    );
    put_u16(&mut extended_count, 48, 0, TriCoreFixtureEndianness::Little);
    put_u32(
        &mut extended_count,
        SECTION_HEADER_OFFSET + 20,
        u32::MAX,
        TriCoreFixtureEndianness::Little,
    );
    assert!(matches!(
        parse_static_ram_report(ELF_SECTIONS_V1_FLAVOR, Cursor::new(extended_count), &config,),
        Err(StaticRamError::ElfSectionLimitExceeded { .. })
    ));

    let mut truncated_section_zero = tricore_elf_fixture(
        TriCoreFixtureEndianness::Little,
        object::elf::EM_TRICORE.0,
        0x3,
    );
    put_u16(
        &mut truncated_section_zero,
        48,
        0,
        TriCoreFixtureEndianness::Little,
    );
    truncated_section_zero.truncate(SECTION_HEADER_OFFSET + SECTION_HEADER_SIZE - 1);
    assert!(matches!(
        parse_static_ram_report(
            ELF_SECTIONS_V1_FLAVOR,
            Cursor::new(truncated_section_zero),
            &config,
        ),
        Err(StaticRamError::InvalidElf { .. })
    ));

    let mut overflowing_offset = tricore_elf_fixture(
        TriCoreFixtureEndianness::Little,
        object::elf::EM_TRICORE.0,
        0x3,
    );
    write_tricore_little_u32(&mut overflowing_offset, 32, u32::MAX);
    assert!(matches!(
        parse_static_ram_report(
            ELF_SECTIONS_V1_FLAVOR,
            Cursor::new(overflowing_offset),
            &config,
        ),
        Err(StaticRamError::InvalidElf { .. })
    ));

    let mut overflowing_elf64_offset =
        elf_fixture(Architecture::Aarch64, &[(".data", SectionKind::Data, 8)]);
    put_u64(
        &mut overflowing_elf64_offset,
        40,
        u64::MAX,
        TriCoreFixtureEndianness::Little,
    );
    assert!(matches!(
        parse_static_ram_report(
            ELF_SECTIONS_V1_FLAVOR,
            Cursor::new(overflowing_elf64_offset),
            &config,
        ),
        Err(StaticRamError::InvalidElf { .. })
    ));

    let mut invalid_entry_size = tricore_elf_fixture(
        TriCoreFixtureEndianness::Little,
        object::elf::EM_TRICORE.0,
        0x3,
    );
    put_u16(
        &mut invalid_entry_size,
        46,
        SECTION_HEADER_SIZE as u16 - 1,
        TriCoreFixtureEndianness::Little,
    );
    assert!(matches!(
        parse_static_ram_report(
            ELF_SECTIONS_V1_FLAVOR,
            Cursor::new(invalid_entry_size),
            &config,
        ),
        Err(StaticRamError::InvalidElf { .. })
    ));
}

#[test]
fn elf_sections_v1_checks_per_kind_and_combined_totals() {
    let mut config = GnuLdMapConfig::new();
    config
        .insert_section(".dma_a", AdditionalStaticRamSectionKind::Dma)
        .unwrap();
    config
        .insert_section(".dma_b", AdditionalStaticRamSectionKind::Dma)
        .unwrap();
    let input = elf_fixture(
        Architecture::Aarch64,
        &[
            (".dma_a", SectionKind::UninitializedData, u64::MAX),
            (".dma_b", SectionKind::UninitializedData, 1),
        ],
    );
    assert!(matches!(
        parse_static_ram_report(ELF_SECTIONS_V1_FLAVOR, Cursor::new(input), &config),
        Err(StaticRamError::ElfKindTotalOverflow {
            name,
            kind: StaticRamSectionKind::Dma,
            ..
        }) if name == ".dma_b"
    ));

    let mut combined_config = GnuLdMapConfig::new();
    combined_config
        .insert_section(".dma", AdditionalStaticRamSectionKind::Dma)
        .unwrap();
    let input = elf_fixture(
        Architecture::Aarch64,
        &[
            (".data", SectionKind::UninitializedData, u64::MAX),
            (".dma", SectionKind::UninitializedData, 1),
        ],
    );
    assert!(matches!(
        parse_static_ram_report(
            ELF_SECTIONS_V1_FLAVOR,
            Cursor::new(input),
            &combined_config,
        ),
        Err(StaticRamError::ElfTotalOverflow { name, .. }) if name == ".dma"
    ));
}

#[test]
fn gnu_ld_map_config_document_builds_exact_classifications() {
    let document = StaticRamConfigDocument {
        schema: StaticRamConfigSchemaVersion,
        flavor: GNU_LD_MAP_V1_FLAVOR.to_owned(),
        additional_sections: vec![
            StaticRamSectionConfig {
                name: ".dma_buffers".to_owned(),
                kind: StaticRamAdditionalSectionKind::Dma,
            },
            StaticRamSectionConfig {
                name: ".rtos.heap".to_owned(),
                kind: StaticRamAdditionalSectionKind::Rtos,
            },
            StaticRamSectionConfig {
                name: ".project_ram".to_owned(),
                kind: StaticRamAdditionalSectionKind::Custom,
            },
        ],
    };
    let config = GnuLdMapConfig::from_document(&document).unwrap();
    assert_eq!(
        config.sections().collect::<Vec<_>>(),
        vec![
            (".bss", StaticRamSectionKind::Bss),
            (".data", StaticRamSectionKind::Data),
            (".dma_buffers", StaticRamSectionKind::Dma),
            (".noinit", StaticRamSectionKind::NoInit),
            (".project_ram", StaticRamSectionKind::Custom),
            (".rtos.heap", StaticRamSectionKind::Rtos),
        ]
    );

    let report = parse_static_ram_report(
        &document.flavor,
        Cursor::new(".dma_buffers 0 11\n.rtos.heap 11 13\n.project_ram 24 17\n.data 41 19\n"),
        &config,
    )
    .unwrap();
    assert_eq!(report.totals.dma_bytes, 11);
    assert_eq!(report.totals.rtos_bytes, 13);
    assert_eq!(report.totals.custom_bytes, 17);
    assert_eq!(report.totals.data_bytes, 19);
    assert_eq!(report.total_bytes, 60);
    assert_eq!(report.totals.checked_total(), Some(report.total_bytes));
}

#[test]
fn gnu_ld_map_config_document_rejects_non_exact_duplicate_and_builtin_names() {
    for name in [".dma*", ".dma[0-9]+", "^\\.dma$", ".dma\\..*"] {
        let mut document = StaticRamConfigDocument::gnu_ld_map_v1();
        document.additional_sections.push(StaticRamSectionConfig {
            name: name.to_owned(),
            kind: StaticRamAdditionalSectionKind::Dma,
        });
        assert!(matches!(
            GnuLdMapConfig::try_from(&document),
            Err(StaticRamConfigValidationError::InvalidExactSectionName { .. })
        ));
    }

    let mut duplicate = StaticRamConfigDocument::gnu_ld_map_v1();
    duplicate.additional_sections = vec![
        StaticRamSectionConfig {
            name: ".dma".to_owned(),
            kind: StaticRamAdditionalSectionKind::Dma,
        },
        StaticRamSectionConfig {
            name: ".dma".to_owned(),
            kind: StaticRamAdditionalSectionKind::Custom,
        },
    ];
    assert!(matches!(
        GnuLdMapConfig::from_document(&duplicate),
        Err(StaticRamConfigValidationError::DuplicateSection { name }) if name == ".dma"
    ));

    for name in [".data", ".bss", ".noinit"] {
        let mut reclassification = StaticRamConfigDocument::gnu_ld_map_v1();
        reclassification
            .additional_sections
            .push(StaticRamSectionConfig {
                name: name.to_owned(),
                kind: StaticRamAdditionalSectionKind::Custom,
            });
        assert!(matches!(
            GnuLdMapConfig::from_document(&reclassification),
            Err(StaticRamConfigValidationError::BuiltinReclassification { name: rejected })
                if rejected == name
        ));
    }

    let mut unsupported = StaticRamConfigDocument::gnu_ld_map_v1();
    unsupported.flavor = "vendor-map-v1".to_owned();
    assert!(matches!(
        GnuLdMapConfig::from_document(&unsupported),
        Err(StaticRamConfigValidationError::UnsupportedFlavor { .. })
    ));

    let mut legacy = GnuLdMapConfig::new();
    assert!(matches!(
        legacy.insert_section(".dma*", AdditionalStaticRamSectionKind::Dma),
        Err(StaticRamConfigError::InvalidSectionName { .. })
    ));
}

#[test]
fn static_ram_report_deserialization_rejects_inconsistent_totals() {
    let report = parse_static_ram_report(
        GNU_LD_MAP_V1_FLAVOR,
        Cursor::new(".data 0 16\n"),
        &GnuLdMapConfig::new(),
    )
    .unwrap();
    let mut json = serde_json::to_value(report).unwrap();
    json["total_bytes"] = 15.into();
    assert!(serde_json::from_value::<StaticRamReport>(json).is_err());

    let report = parse_static_ram_report(
        GNU_LD_MAP_V1_FLAVOR,
        Cursor::new(".data 0 16\n"),
        &GnuLdMapConfig::new(),
    )
    .unwrap();
    let mut json = serde_json::to_value(report).unwrap();
    json["unknown"] = true.into();
    assert!(serde_json::from_value::<StaticRamReport>(json).is_err());
}

#[test]
fn gnu_ld_map_v1_reports_duplicate_malformed_and_overflow_lines() {
    let duplicate = ".data 0x20000000 0x10\n.data 0x20000010 0x20\n";
    assert!(matches!(
        parse_static_ram_report(
            GNU_LD_MAP_V1_FLAVOR,
            Cursor::new(duplicate),
            &GnuLdMapConfig::new(),
        ),
        Err(StaticRamError::DuplicateSection {
            previous_line: 1,
            line: 2,
            ..
        })
    ));

    let malformed = "ignored\n.data 0x20000000\n";
    assert!(matches!(
        parse_static_ram_report(
            GNU_LD_MAP_V1_FLAVOR,
            Cursor::new(malformed),
            &GnuLdMapConfig::new(),
        ),
        Err(StaticRamError::MalformedSection { line: 2, .. })
    ));

    let invalid_size = ".data 0x20000000 not-a-size\n";
    assert!(matches!(
        parse_static_ram_report(
            GNU_LD_MAP_V1_FLAVOR,
            Cursor::new(invalid_size),
            &GnuLdMapConfig::new(),
        ),
        Err(StaticRamError::InvalidInteger {
            field: "size",
            line: 1,
            ..
        })
    ));

    let address_overflow = ".data 0xffffffffffffffff 1\n";
    assert!(matches!(
        parse_static_ram_report(
            GNU_LD_MAP_V1_FLAVOR,
            Cursor::new(address_overflow),
            &GnuLdMapConfig::new(),
        ),
        Err(StaticRamError::AddressOverflow { line: 1, .. })
    ));

    let total_overflow = ".data 0 18446744073709551615\n.bss 0 1\n";
    assert!(matches!(
        parse_static_ram_report(
            GNU_LD_MAP_V1_FLAVOR,
            Cursor::new(total_overflow),
            &GnuLdMapConfig::new(),
        ),
        Err(StaticRamError::TotalOverflow { line: 2, .. })
    ));

    let mut per_kind_config = GnuLdMapConfig::new();
    per_kind_config
        .insert_section(".dma_a", AdditionalStaticRamSectionKind::Dma)
        .unwrap();
    per_kind_config
        .insert_section(".dma_b", AdditionalStaticRamSectionKind::Dma)
        .unwrap();
    let kind_overflow = ".dma_a 0 18446744073709551615\n.dma_b 0 1\n";
    assert!(matches!(
        parse_static_ram_report(
            GNU_LD_MAP_V1_FLAVOR,
            Cursor::new(kind_overflow),
            &per_kind_config,
        ),
        Err(StaticRamError::KindTotalOverflow {
            name,
            kind: StaticRamSectionKind::Dma,
            line: 2,
        }) if name == ".dma_b"
    ));
}

#[test]
fn gnu_ld_map_flavor_is_explicit_and_large_irrelevant_input_is_streamed() {
    assert!(matches!(
        parse_static_ram_report(
            "vendor-map-latest",
            Cursor::new(Vec::<u8>::new()),
            &GnuLdMapConfig::new(),
        ),
        Err(StaticRamError::UnsupportedFlavor { .. })
    ));

    let reader = RepeatedRead::new(
        b" .data.input 0x0 0x1 object.o\r\n",
        100_000,
        b".data 0x20000000 0x20\r\n",
    );
    let mut config = GnuLdMapConfig::new();
    config.limits = LineLimits {
        max_line_bytes: 128,
        max_records: 100_001,
        ..LineLimits::default()
    };
    let report = parse_static_ram_report(
        GNU_LD_MAP_V1_FLAVOR,
        BufReader::with_capacity(7, reader),
        &config,
    )
    .unwrap();
    assert_eq!(report.total_bytes, 32);
    assert_eq!(report.sections.len(), 1);
    assert_eq!(report.sections[0].source_line, Some(100_001));
}

#[test]
fn gcc_stack_usage_v1_parses_static_dynamic_and_bounded_entries() {
    let input = concat!(
        "C:\\src\\main.c:12:3:static_frame\t128\tstatic\r\n",
        "src/lib.cc:44:9:ns::dynamic_frame(int)\t64\tdynamic\r\n",
        "src/lib.cc:51:2:ns::bounded_frame(unsigned)\t96\tdynamic,bounded",
    );
    let report = parse_stack_usage_report(
        GCC_STACK_USAGE_V1_FLAVOR,
        Cursor::new(input),
        LineLimits::default(),
    )
    .unwrap();
    assert_eq!(report.maximum_static_bytes, Some(128));
    assert_eq!(report.functions.len(), 3);
    assert_eq!(report.functions[0].file, "C:\\src\\main.c");
    assert_eq!(report.functions[0].line, 12);
    assert_eq!(report.functions[1].function, "ns::dynamic_frame(int)");
    assert_eq!(report.functions[1].kind, StackUsageKind::Dynamic);
    assert_eq!(report.functions[2].kind, StackUsageKind::DynamicBounded);
    let mut json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["schema"], GCC_STACK_USAGE_V1_SCHEMA);
    assert_eq!(
        serde_json::from_value::<StackUsageReport>(json.clone()).unwrap(),
        report
    );
    json["schema"] = "t32perf.stack-usage/gcc-stack-usage-v2".into();
    assert!(serde_json::from_value::<StackUsageReport>(json).is_err());
}

#[test]
fn resource_report_schemas_validate_generated_reports_and_reject_unknown_fields() {
    let static_report = parse_static_ram_report(
        ELF_SECTIONS_V1_FLAVOR,
        Cursor::new(elf_fixture(
            Architecture::Riscv32,
            &[(".data", SectionKind::Data, 16)],
        )),
        &GnuLdMapConfig::new(),
    )
    .unwrap();
    let stack_report = parse_stack_usage_report(
        GCC_STACK_USAGE_V1_FLAVOR,
        Cursor::new("src/main.c:1:1:frame\t32\tstatic\n"),
        LineLimits::default(),
    )
    .unwrap();
    let documents = resource_schema_documents();
    assert_eq!(documents.len(), 2);
    assert_eq!(
        documents["static-ram-report.schema.json"]["$id"],
        STATIC_RAM_REPORT_SCHEMA
    );
    assert_eq!(
        documents["stack-usage-report.schema.json"]["$id"],
        STACK_USAGE_REPORT_SCHEMA
    );
    let static_validator =
        jsonschema::validator_for(&documents["static-ram-report.schema.json"]).unwrap();
    let static_json = serde_json::to_value(static_report).unwrap();
    static_validator.validate(&static_json).unwrap();
    let mut missing_elf_metadata = static_json.clone();
    missing_elf_metadata.as_object_mut().unwrap().remove("elf");
    assert!(!static_validator.is_valid(&missing_elf_metadata));
    let mut wrong_source_location = static_json;
    wrong_source_location["sections"][0]
        .as_object_mut()
        .unwrap()
        .insert("source_line".to_owned(), 1.into());
    assert!(!static_validator.is_valid(&wrong_source_location));
    jsonschema::validator_for(&documents["stack-usage-report.schema.json"])
        .unwrap()
        .validate(&serde_json::to_value(&stack_report).unwrap())
        .unwrap();

    let mut invalid_stack = serde_json::to_value(stack_report).unwrap();
    invalid_stack["unexpected"] = true.into();
    assert!(serde_json::from_value::<StackUsageReport>(invalid_stack).is_err());
}

#[test]
fn gcc_stack_usage_v1_reports_exact_corrupt_record_lines() {
    let invalid_qualifier = concat!("src/a.c:1:1:a\t8\tstatic\n", "src/b.c:2:1:b\t16\tbounded\n",);
    assert!(matches!(
        parse_stack_usage_report(
            GCC_STACK_USAGE_V1_FLAVOR,
            Cursor::new(invalid_qualifier),
            LineLimits::default(),
        ),
        Err(StackUsageError::UnsupportedQualifier { line: 2, .. })
    ));

    let ambiguous = "src/a.c:1:1:function:2:3:tail\t8\tstatic\n";
    assert!(matches!(
        parse_stack_usage_report(
            GCC_STACK_USAGE_V1_FLAVOR,
            Cursor::new(ambiguous),
            LineLimits::default(),
        ),
        Err(StackUsageError::AmbiguousLocation { line: 1, .. })
    ));

    let overflow = "src/a.c:1:1:a\t18446744073709551616\tstatic\n";
    assert!(matches!(
        parse_stack_usage_report(
            GCC_STACK_USAGE_V1_FLAVOR,
            Cursor::new(overflow),
            LineLimits::default(),
        ),
        Err(StackUsageError::InvalidInteger {
            field: "bytes",
            line: 1,
            ..
        })
    ));

    let invalid_utf8 = b"src/a.c:1:1:a\t8\tstatic\n\xff\t8\tstatic\n";
    assert!(matches!(
        parse_stack_usage_report(
            GCC_STACK_USAGE_V1_FLAVOR,
            Cursor::new(invalid_utf8),
            LineLimits::default(),
        ),
        Err(StackUsageError::InvalidUtf8 { line: 2, .. })
    ));
}

#[test]
fn gcc_stack_usage_reader_streams_large_inputs_and_rejects_unknown_flavor() {
    assert!(matches!(
        parse_stack_usage_report(
            "clang-stack-usage",
            Cursor::new(Vec::<u8>::new()),
            LineLimits::default(),
        ),
        Err(StackUsageError::UnsupportedFlavor { .. })
    ));

    let reader = RepeatedRead::new(b"src/a.c:1:1:a\t32\tstatic\r\n", 100_000, b"");
    let mut parser = GccStackUsageReader::new(
        BufReader::with_capacity(5, reader),
        LineLimits {
            max_line_bytes: 64,
            max_records: 100_000,
            ..LineLimits::default()
        },
    )
    .unwrap();
    let mut count = 0;
    while parser.next_entry().unwrap().is_some() {
        count += 1;
    }
    assert_eq!(count, 100_000);

    let error = parse_stack_usage_report(
        GCC_STACK_USAGE_V1_FLAVOR,
        BufReader::new(RepeatedRead::new(
            b"src/a.c:1:1:a\t32\tstatic\n",
            100_001,
            b"",
        )),
        LineLimits {
            max_line_bytes: 64,
            max_records: 100_001,
            ..LineLimits::default()
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        StackUsageError::FunctionLimitExceeded { maximum: 100_000 }
    ));
}

#[test]
fn stack_usage_report_deserialization_checks_aggregate_and_source_order() {
    let report = parse_stack_usage_report(
        GCC_STACK_USAGE_V1_FLAVOR,
        Cursor::new("src/a.c:1:1:a\t32\tstatic\nsrc/b.c:2:1:b\t64\tdynamic\n"),
        LineLimits::default(),
    )
    .unwrap();
    let mut wrong_maximum = serde_json::to_value(&report).unwrap();
    wrong_maximum["maximum_static_bytes"] = 31.into();
    assert!(serde_json::from_value::<StackUsageReport>(wrong_maximum).is_err());

    let mut wrong_order = serde_json::to_value(report).unwrap();
    wrong_order["functions"][1]["artifact_line"] = 1.into();
    assert!(serde_json::from_value::<StackUsageReport>(wrong_order).is_err());
}
