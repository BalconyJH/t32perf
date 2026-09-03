//! Explicit, bounded static-RAM parsing for GNU ld maps and ELF section tables.

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{BufRead, Read as _},
    marker::PhantomData,
    str,
};

use object::{Object as _, ObjectSection as _};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as _, SeqAccess, Visitor},
};
use t32perf_model::{
    MAX_STATIC_RAM_ADDITIONAL_SECTIONS, STATIC_RAM_ELF_SECTIONS_V1_FLAVOR,
    STATIC_RAM_GNU_LD_MAP_V1_FLAVOR, StaticRamAdditionalSectionKind, StaticRamConfigDocument,
    StaticRamConfigValidationError, StaticRamKindTotals,
};
use thiserror::Error;

use crate::{LineLimits, ResourceTextError, ResourceTextLine, ResourceTextReader};

/// Exact host-input flavor supported by the GNU ld map parser.
pub const GNU_LD_MAP_V1_FLAVOR: &str = STATIC_RAM_GNU_LD_MAP_V1_FLAVOR;
/// Exact host-input flavor supported by the ELF section-table parser.
pub const ELF_SECTIONS_V1_FLAVOR: &str = STATIC_RAM_ELF_SECTIONS_V1_FLAVOR;
/// Schema identifier emitted by GNU ld static-RAM reports.
pub const GNU_LD_MAP_V1_SCHEMA: &str = "t32perf.static-ram/gnu-ld-map-v1";
/// Schema identifier emitted by ELF static-RAM reports.
pub const ELF_SECTIONS_V1_SCHEMA: &str = "t32perf.static-ram/elf-sections-v1";
/// Public JSON Schema identifier for every static-RAM report flavor.
pub const STATIC_RAM_REPORT_SCHEMA: &str = "t32perf.static-ram-report/v1";
/// Default and hard maximum ELF artifact size accepted by the parser.
pub const MAX_ELF_STATIC_RAM_INPUT_BYTES: u64 = 256 * 1024 * 1024;
/// Maximum total ELF section count accepted before selected-section filtering.
pub const MAX_ELF_SECTION_COUNT: u64 = 65_536;
/// Maximum selected section count in a serialized static-RAM report.
pub const MAX_STATIC_RAM_REPORT_SECTIONS: usize = MAX_STATIC_RAM_ADDITIONAL_SECTIONS + 3;

/// Schema marker for one supported static-RAM report flavor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum StaticRamReportSchema {
    /// Strict GNU ld map v1 subset.
    #[default]
    GnuLdMapV1,
    /// Strict ELF section-table v1 subset.
    ElfSectionsV1,
}

impl Serialize for StaticRamReportSchema {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match self {
            Self::GnuLdMapV1 => GNU_LD_MAP_V1_SCHEMA,
            Self::ElfSectionsV1 => ELF_SECTIONS_V1_SCHEMA,
        })
    }
}

impl<'de> Deserialize<'de> for StaticRamReportSchema {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match String::deserialize(deserializer)?.as_str() {
            GNU_LD_MAP_V1_SCHEMA => Ok(Self::GnuLdMapV1),
            ELF_SECTIONS_V1_SCHEMA => Ok(Self::ElfSectionsV1),
            value => Err(D::Error::custom(format!(
                "unsupported static RAM report schema `{value}`"
            ))),
        }
    }
}

impl JsonSchema for StaticRamReportSchema {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("StaticRamReportSchema")
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "enum": [GNU_LD_MAP_V1_SCHEMA, ELF_SECTIONS_V1_SCHEMA]
        })
    }
}

/// Classification assigned to a selected output section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StaticRamSectionKind {
    /// Initialized static data.
    Data,
    /// Zero-initialized static data.
    Bss,
    /// Retained or otherwise non-initialized static data.
    #[serde(rename = "noinit")]
    NoInit,
    /// Caller-declared DMA storage.
    Dma,
    /// Caller-declared RTOS static storage.
    Rtos,
    /// Caller-declared project-specific static storage.
    Custom,
}

/// Classification allowed for caller-added output-section names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdditionalStaticRamSectionKind {
    /// DMA storage.
    Dma,
    /// RTOS static storage.
    Rtos,
    /// Project-specific static storage.
    Custom,
}

impl From<AdditionalStaticRamSectionKind> for StaticRamSectionKind {
    fn from(value: AdditionalStaticRamSectionKind) -> Self {
        match value {
            AdditionalStaticRamSectionKind::Dma => Self::Dma,
            AdditionalStaticRamSectionKind::Rtos => Self::Rtos,
            AdditionalStaticRamSectionKind::Custom => Self::Custom,
        }
    }
}

impl From<StaticRamAdditionalSectionKind> for StaticRamSectionKind {
    fn from(value: StaticRamAdditionalSectionKind) -> Self {
        match value {
            StaticRamAdditionalSectionKind::Dma => Self::Dma,
            StaticRamAdditionalSectionKind::Rtos => Self::Rtos,
            StaticRamAdditionalSectionKind::Custom => Self::Custom,
        }
    }
}

/// Supported embedded architecture recorded for an ELF resource report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ElfStaticRamArchitecture {
    /// 32-bit Arm ELF.
    Arm,
    /// 64-bit Arm ELF.
    Aarch64,
    /// 32-bit RISC-V ELF.
    Riscv32,
    /// 64-bit RISC-V ELF.
    Riscv64,
    /// 32-bit Siemens TriCore ELF.
    TriCore,
}

/// Supported ELF object kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ElfStaticRamObjectKind {
    /// Linker-relocatable ELF object.
    Relocatable,
    /// Firmware executable ELF image.
    Executable,
}

/// ELF address class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ElfStaticRamClass {
    /// ELFCLASS32.
    Elf32,
    /// ELFCLASS64.
    Elf64,
}

/// ELF byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ElfStaticRamEndianness {
    /// Little-endian ELF.
    Little,
    /// Big-endian ELF.
    Big,
}

/// Validated ELF identity attached to an `elf-sections-v1` report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ElfStaticRamMetadata {
    /// Supported machine architecture from the ELF header.
    pub architecture: ElfStaticRamArchitecture,
    /// Accepted ELF object kind.
    pub object_kind: ElfStaticRamObjectKind,
    /// ELF32 or ELF64 class.
    pub class: ElfStaticRamClass,
    /// ELF byte order.
    pub endianness: ElfStaticRamEndianness,
}

/// One reliably recognized static-RAM output section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StaticRamSection {
    /// Exact output-section name.
    #[schemars(length(min = 2, max = 128), regex(pattern = r"^\.[A-Za-z0-9._-]+$"))]
    pub name: String,
    /// Virtual memory address from the source artifact.
    pub address: u64,
    /// Output-section size in bytes.
    pub size_bytes: u64,
    /// Static-RAM classification.
    pub kind: StaticRamSectionKind,
    /// One-based map-file line for a GNU ld report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub source_line: Option<u64>,
    /// One-based ELF section-table index for an ELF report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub source_section_index: Option<u64>,
}

/// Selected static-RAM sections and their checked size sum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StaticRamReport {
    /// Versioned, flavor-specific report schema marker.
    pub schema: StaticRamReportSchema,
    /// ELF identity; present exactly for `elf-sections-v1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elf: Option<ElfStaticRamMetadata>,
    /// Selected output sections in source order.
    #[schemars(length(max = 4099))]
    pub sections: Vec<StaticRamSection>,
    /// Checked sum of selected output-section sizes.
    pub total_bytes: u64,
    /// Checked totals kept separate for every static-RAM classification.
    pub totals: StaticRamKindTotals,
}

impl<'de> Deserialize<'de> for StaticRamReport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            schema: StaticRamReportSchema,
            #[serde(default)]
            elf: Option<ElfStaticRamMetadata>,
            #[serde(deserialize_with = "deserialize_static_ram_sections")]
            sections: Vec<StaticRamSection>,
            total_bytes: u64,
            #[serde(default)]
            totals: Option<StaticRamKindTotals>,
        }

        let fields = Fields::deserialize(deserializer)?;
        let calculated_totals =
            validate_report_sections(fields.schema, fields.elf.as_ref(), &fields.sections)
                .map_err(D::Error::custom)?;
        let checked_total = calculated_totals
            .checked_total()
            .ok_or_else(|| D::Error::custom("static RAM per-kind totals overflow"))?;
        if fields.total_bytes != checked_total {
            return Err(D::Error::custom(format!(
                "static RAM total_bytes {} does not equal checked per-kind sum {checked_total}",
                fields.total_bytes
            )));
        }
        if fields
            .totals
            .as_ref()
            .is_some_and(|totals| totals != &calculated_totals)
        {
            return Err(D::Error::custom(
                "static RAM per-kind totals do not match the parsed sections",
            ));
        }
        Ok(Self {
            schema: fields.schema,
            elf: fields.elf,
            sections: fields.sections,
            total_bytes: checked_total,
            totals: calculated_totals,
        })
    }
}

fn deserialize_static_ram_sections<'de, D>(
    deserializer: D,
) -> Result<Vec<StaticRamSection>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedSections(PhantomData<StaticRamSection>);

    impl<'de> Visitor<'de> for BoundedSections {
        type Value = Vec<StaticRamSection>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {MAX_STATIC_RAM_REPORT_SECTIONS} static RAM sections"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let capacity = sequence
                .size_hint()
                .unwrap_or(0)
                .min(MAX_STATIC_RAM_REPORT_SECTIONS);
            let mut sections = Vec::with_capacity(capacity);
            while let Some(section) = sequence.next_element()? {
                if sections.len() == MAX_STATIC_RAM_REPORT_SECTIONS {
                    return Err(A::Error::custom(format!(
                        "static RAM report exceeds {MAX_STATIC_RAM_REPORT_SECTIONS} sections"
                    )));
                }
                sections.push(section);
            }
            Ok(sections)
        }
    }

    deserializer.deserialize_seq(BoundedSections(PhantomData))
}

fn validate_report_sections(
    schema: StaticRamReportSchema,
    elf: Option<&ElfStaticRamMetadata>,
    sections: &[StaticRamSection],
) -> Result<StaticRamKindTotals, String> {
    match (schema, elf) {
        (StaticRamReportSchema::GnuLdMapV1, None)
        | (StaticRamReportSchema::ElfSectionsV1, Some(_)) => {}
        (StaticRamReportSchema::GnuLdMapV1, Some(_)) => {
            return Err("GNU ld static RAM report must not contain ELF metadata".to_owned());
        }
        (StaticRamReportSchema::ElfSectionsV1, None) => {
            return Err("ELF static RAM report omits ELF metadata".to_owned());
        }
    }

    let mut totals = StaticRamKindTotals::default();
    let mut names = BTreeSet::new();
    for section in sections {
        validate_section_name(&section.name).map_err(|error| error.to_string())?;
        if !names.insert(section.name.as_str()) {
            return Err(format!(
                "static RAM report repeats output section `{}`",
                section.name
            ));
        }
        section
            .address
            .checked_add(section.size_bytes)
            .ok_or_else(|| {
                format!(
                    "static RAM section `{}` address range overflows",
                    section.name
                )
            })?;
        match schema {
            StaticRamReportSchema::GnuLdMapV1
                if section.source_line.is_some() && section.source_section_index.is_none() => {}
            StaticRamReportSchema::ElfSectionsV1
                if section.source_line.is_none() && section.source_section_index.is_some() => {}
            StaticRamReportSchema::GnuLdMapV1 => {
                return Err(format!(
                    "GNU ld section `{}` requires only source_line",
                    section.name
                ));
            }
            StaticRamReportSchema::ElfSectionsV1 => {
                return Err(format!(
                    "ELF section `{}` requires only source_section_index",
                    section.name
                ));
            }
        }
        if section.source_line == Some(0) || section.source_section_index == Some(0) {
            return Err(format!(
                "static RAM section `{}` has a zero source location",
                section.name
            ));
        }
        add_to_kind_total(&mut totals, section.kind, section.size_bytes).ok_or_else(|| {
            format!(
                "static RAM {:?} total overflows at output section `{}`",
                section.kind, section.name
            )
        })?;
    }
    Ok(totals)
}

/// Shared exact-section configuration for every static-RAM parser flavor.
#[derive(Debug, Clone)]
pub struct StaticRamParserConfig {
    sections: BTreeMap<String, StaticRamSectionKind>,
    /// Physical-line and record limits for a GNU ld map artifact.
    pub limits: LineLimits,
    /// Maximum ELF bytes read before parsing.
    pub max_elf_bytes: u64,
    /// Maximum total ELF section count inspected.
    pub max_elf_sections: u64,
}

impl Default for StaticRamParserConfig {
    fn default() -> Self {
        Self {
            sections: BTreeMap::from([
                (".bss".to_owned(), StaticRamSectionKind::Bss),
                (".data".to_owned(), StaticRamSectionKind::Data),
                (".noinit".to_owned(), StaticRamSectionKind::NoInit),
            ]),
            limits: LineLimits::default(),
            max_elf_bytes: MAX_ELF_STATIC_RAM_INPUT_BYTES,
            max_elf_sections: MAX_ELF_SECTION_COUNT,
        }
    }
}

impl StaticRamParserConfig {
    /// Creates a configuration containing only `.data`, `.bss`, and `.noinit`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a strict parser configuration from a versioned model document.
    pub fn from_document(
        document: &StaticRamConfigDocument,
    ) -> Result<Self, StaticRamConfigValidationError> {
        document.validate()?;
        let mut config = Self::new();
        for section in &document.additional_sections {
            let previous = config
                .sections
                .insert(section.name.clone(), section.kind.into());
            debug_assert!(previous.is_none(), "validated section names are unique");
        }
        Ok(config)
    }

    /// Adds one exact DMA, RTOS, or custom output-section name.
    pub fn insert_section(
        &mut self,
        name: impl Into<String>,
        kind: AdditionalStaticRamSectionKind,
    ) -> Result<(), StaticRamConfigError> {
        let name = name.into();
        validate_section_name(&name)?;
        if self.sections.contains_key(&name) {
            return Err(StaticRamConfigError::DuplicateSection { name });
        }
        if self.sections.len() >= MAX_STATIC_RAM_REPORT_SECTIONS {
            return Err(StaticRamConfigError::TooManySections {
                maximum: MAX_STATIC_RAM_ADDITIONAL_SECTIONS,
            });
        }
        self.sections.insert(name, kind.into());
        Ok(())
    }

    /// Returns configured section names and classifications in lexical order.
    pub fn sections(&self) -> impl Iterator<Item = (&str, StaticRamSectionKind)> {
        self.sections
            .iter()
            .map(|(name, kind)| (name.as_str(), *kind))
    }
}

impl TryFrom<&StaticRamConfigDocument> for StaticRamParserConfig {
    type Error = StaticRamConfigValidationError;

    fn try_from(document: &StaticRamConfigDocument) -> Result<Self, Self::Error> {
        Self::from_document(document)
    }
}

impl TryFrom<StaticRamConfigDocument> for StaticRamParserConfig {
    type Error = StaticRamConfigValidationError;

    fn try_from(document: StaticRamConfigDocument) -> Result<Self, Self::Error> {
        Self::from_document(&document)
    }
}

/// Backward-compatible name for the shared static-RAM parser configuration.
pub type GnuLdMapConfig = StaticRamParserConfig;

/// Invalid static-RAM parser configuration.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StaticRamConfigError {
    /// A section name is not an exact supported output-section name.
    #[error("invalid exact output-section name `{name}`")]
    InvalidSectionName {
        /// Rejected name.
        name: String,
    },
    /// A built-in or caller-added section name was configured twice.
    #[error("output section `{name}` is already configured")]
    DuplicateSection {
        /// Duplicate name.
        name: String,
    },
    /// The exact-section configuration reached its bounded ceiling.
    #[error("static RAM configuration exceeds {maximum} additional sections")]
    TooManySections {
        /// Maximum caller-added section count.
        maximum: usize,
    },
}

/// A strict static-RAM input or aggregation failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StaticRamError {
    /// The caller requested an unimplemented static-RAM flavor.
    #[error("UNSUPPORTED: static RAM input flavor `{flavor}` is not supported")]
    UnsupportedFlavor {
        /// Rejected flavor identifier.
        flavor: String,
    },
    /// A configured ELF parser limit is zero or above the hard ceiling.
    #[error("invalid ELF {field} limit {value}; supported range is 1..={maximum}")]
    InvalidElfLimit {
        /// Limit name.
        field: &'static str,
        /// Rejected value.
        value: u64,
        /// Hard ceiling.
        maximum: u64,
    },
    /// Reading the bounded ELF artifact failed.
    #[error("ELF input I/O error: {message}")]
    ElfIo {
        /// Original I/O error text.
        message: String,
    },
    /// The ELF artifact exceeds the configured byte ceiling.
    #[error("ELF input exceeds {limit} bytes")]
    ElfInputTooLarge {
        /// Configured maximum byte length.
        limit: u64,
    },
    /// The selected flavor received a non-ELF artifact.
    #[error("UNSUPPORTED: elf-sections-v1 requires an ELF artifact")]
    UnsupportedFileFormat,
    /// The ELF header or section table is malformed.
    #[error("invalid ELF artifact: {message}")]
    InvalidElf {
        /// Parser diagnostic.
        message: String,
    },
    /// The ELF machine is not in the explicitly supported embedded set.
    #[error("UNSUPPORTED: ELF architecture `{architecture}` is not supported")]
    UnsupportedElfArchitecture {
        /// Rejected architecture.
        architecture: String,
    },
    /// The ELF object kind is not a relocatable object or executable firmware image.
    #[error("UNSUPPORTED: ELF object kind `{kind}` is not supported")]
    UnsupportedElfObjectKind {
        /// Rejected object kind.
        kind: String,
    },
    /// More ELF sections were present than the configured inspection ceiling.
    #[error("ELF section count exceeds {limit}")]
    ElfSectionLimitExceeded {
        /// Configured maximum section count.
        limit: u64,
    },
    /// A selected ELF section is not unambiguously allocated and writable.
    #[error("ELF section `{name}` at index {index} is not allocated+writable RAM (flags {flags})")]
    ElfSectionNotWritableRam {
        /// Selected section name.
        name: String,
        /// One-based ELF section-table index.
        index: u64,
        /// Decoded ELF flag diagnostic.
        flags: String,
    },
    /// Address plus size cannot fit in the supported ELF address space.
    #[error("address range for ELF section `{name}` overflows at index {index}")]
    ElfAddressOverflow {
        /// Selected section name.
        name: String,
        /// One-based ELF section-table index.
        index: u64,
    },
    /// A selected ELF output-section name appears twice.
    #[error(
        "duplicate ELF section `{name}` at index {index}; first definition was index {previous_index}"
    )]
    DuplicateElfSection {
        /// Duplicate section name.
        name: String,
        /// First definition index.
        previous_index: u64,
        /// Duplicate definition index.
        index: u64,
    },
    /// The checked ELF section-size sum overflowed.
    #[error("static RAM total overflows while adding ELF section `{name}` at index {index}")]
    ElfTotalOverflow {
        /// Section whose size overflowed the total.
        name: String,
        /// One-based ELF section-table index.
        index: u64,
    },
    /// One checked per-kind ELF section-size sum overflowed.
    #[error(
        "static RAM {kind:?} total overflows while adding ELF section `{name}` at index {index}"
    )]
    ElfKindTotalOverflow {
        /// Section whose size overflowed its classification total.
        name: String,
        /// Classification whose total overflowed.
        kind: StaticRamSectionKind,
        /// One-based ELF section-table index.
        index: u64,
    },
    /// Bounded platform-text input failed.
    #[error(transparent)]
    Input(#[from] ResourceTextError),
    /// A selected output-section line is not valid UTF-8.
    #[error("invalid UTF-8 in selected output section at byte {byte_offset}, line {line}")]
    InvalidUtf8 {
        /// Zero-based byte offset.
        byte_offset: u64,
        /// One-based physical line.
        line: u64,
    },
    /// A selected output-section header lacks its required address or size.
    #[error("malformed output section `{name}` at line {line}; expected name, address, and size")]
    MalformedSection {
        /// Selected section name.
        name: String,
        /// One-based physical line.
        line: u64,
    },
    /// An address or size token is not an unsigned decimal or hexadecimal integer.
    #[error("invalid {field} `{value}` for output section `{name}` at line {line}")]
    InvalidInteger {
        /// Selected section name.
        name: String,
        /// Field name (`address` or `size`).
        field: &'static str,
        /// Rejected token.
        value: String,
        /// One-based physical line.
        line: u64,
    },
    /// Address plus size cannot fit in the supported map address space.
    #[error("address range for output section `{name}` overflows at line {line}")]
    AddressOverflow {
        /// Selected section name.
        name: String,
        /// One-based physical line.
        line: u64,
    },
    /// A selected top-level map output-section name appears twice.
    #[error(
        "duplicate output section `{name}` at line {line}; first top-level definition was line {previous_line}"
    )]
    DuplicateSection {
        /// Duplicate section name.
        name: String,
        /// First definition line.
        previous_line: u64,
        /// Duplicate definition line.
        line: u64,
    },
    /// The checked map section-size sum overflowed.
    #[error("static RAM total overflows while adding `{name}` at line {line}")]
    TotalOverflow {
        /// Section whose size overflowed the total.
        name: String,
        /// One-based physical line.
        line: u64,
    },
    /// One checked per-kind map section-size sum overflowed.
    #[error(
        "static RAM {kind:?} total overflows while adding output section `{name}` at line {line}"
    )]
    KindTotalOverflow {
        /// Section whose size overflowed its classification total.
        name: String,
        /// Classification whose total overflowed.
        kind: StaticRamSectionKind,
        /// One-based physical line.
        line: u64,
    },
}

/// Dispatches an explicitly selected, versioned static-RAM artifact parser.
pub fn parse_static_ram_report<R: BufRead>(
    flavor: &str,
    reader: R,
    config: &StaticRamParserConfig,
) -> Result<StaticRamReport, StaticRamError> {
    match flavor {
        GNU_LD_MAP_V1_FLAVOR => parse_gnu_ld_map_v1(reader, config),
        ELF_SECTIONS_V1_FLAVOR => parse_elf_sections_v1(reader, config),
        _ => Err(StaticRamError::UnsupportedFlavor {
            flavor: flavor.to_owned(),
        }),
    }
}

/// Parses the strict `gnu-ld-map-v1` top-level output-section subset.
pub fn parse_gnu_ld_map_v1<R: BufRead>(
    reader: R,
    config: &StaticRamParserConfig,
) -> Result<StaticRamReport, StaticRamError> {
    let mut lines = ResourceTextReader::new(reader, config.limits)?;
    let mut seen = BTreeMap::<String, u64>::new();
    let mut sections = Vec::new();
    let mut totals = StaticRamKindTotals::default();

    while let Some(line) = lines.next_line()? {
        let Some((name, kind)) = selected_section(&line, config) else {
            continue;
        };
        let text = str::from_utf8(&line.bytes).map_err(|error| StaticRamError::InvalidUtf8 {
            byte_offset: line.location.byte_offset + error.valid_up_to() as u64,
            line: line.location.line,
        })?;
        let mut fields = text.split_ascii_whitespace();
        let parsed_name = fields.next().expect("selected lines contain a name");
        let Some(address_text) = fields.next() else {
            return Err(StaticRamError::MalformedSection {
                name,
                line: line.location.line,
            });
        };
        let Some(size_text) = fields.next() else {
            return Err(StaticRamError::MalformedSection {
                name,
                line: line.location.line,
            });
        };
        debug_assert_eq!(parsed_name, name);
        let address =
            parse_integer(address_text).ok_or_else(|| StaticRamError::InvalidInteger {
                name: name.clone(),
                field: "address",
                value: address_text.to_owned(),
                line: line.location.line,
            })?;
        let size_bytes =
            parse_integer(size_text).ok_or_else(|| StaticRamError::InvalidInteger {
                name: name.clone(),
                field: "size",
                value: size_text.to_owned(),
                line: line.location.line,
            })?;
        address
            .checked_add(size_bytes)
            .ok_or_else(|| StaticRamError::AddressOverflow {
                name: name.clone(),
                line: line.location.line,
            })?;
        if let Some(previous_line) = seen.insert(name.clone(), line.location.line) {
            return Err(StaticRamError::DuplicateSection {
                name,
                previous_line,
                line: line.location.line,
            });
        }
        add_to_kind_total(&mut totals, kind, size_bytes).ok_or_else(|| {
            StaticRamError::KindTotalOverflow {
                name: name.clone(),
                kind,
                line: line.location.line,
            }
        })?;
        totals
            .checked_total()
            .ok_or_else(|| StaticRamError::TotalOverflow {
                name: name.clone(),
                line: line.location.line,
            })?;
        sections.push(StaticRamSection {
            name,
            address,
            size_bytes,
            kind,
            source_line: Some(line.location.line),
            source_section_index: None,
        });
    }

    let total_bytes = totals
        .checked_total()
        .expect("the combined total was checked after every section");

    Ok(StaticRamReport {
        schema: StaticRamReportSchema::GnuLdMapV1,
        elf: None,
        sections,
        total_bytes,
        totals,
    })
}

/// Parses selected allocated+writable sections from a bounded ELF section table.
pub fn parse_elf_sections_v1<R: BufRead>(
    reader: R,
    config: &StaticRamParserConfig,
) -> Result<StaticRamReport, StaticRamError> {
    validate_elf_limit("byte", config.max_elf_bytes, MAX_ELF_STATIC_RAM_INPUT_BYTES)?;
    validate_elf_limit(
        "section-count",
        config.max_elf_sections,
        MAX_ELF_SECTION_COUNT,
    )?;

    let mut bytes = Vec::new();
    reader
        .take(config.max_elf_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| StaticRamError::ElfIo {
            message: error.to_string(),
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > config.max_elf_bytes {
        return Err(StaticRamError::ElfInputTooLarge {
            limit: config.max_elf_bytes,
        });
    }
    if bytes.get(..4) != Some(b"\x7fELF") {
        return Err(StaticRamError::UnsupportedFileFormat);
    }
    let class = preflight_elf_section_table(&bytes, config.max_elf_sections)?;
    let file =
        object::File::parse(bytes.as_slice()).map_err(|error| StaticRamError::InvalidElf {
            message: error.to_string(),
        })?;
    if file.format() != object::BinaryFormat::Elf {
        return Err(StaticRamError::UnsupportedFileFormat);
    }
    let object_kind = supported_elf_object_kind(file.kind())?;
    let endianness = if file.is_little_endian() {
        ElfStaticRamEndianness::Little
    } else {
        ElfStaticRamEndianness::Big
    };
    let architecture = supported_elf_architecture(file.architecture(), &bytes, class, endianness)?;

    let mut seen = BTreeMap::<String, u64>::new();
    let mut sections = Vec::new();
    let mut totals = StaticRamKindTotals::default();
    let mut section_count = 0_u64;
    for section in file.sections() {
        section_count =
            section_count
                .checked_add(1)
                .ok_or(StaticRamError::ElfSectionLimitExceeded {
                    limit: config.max_elf_sections,
                })?;
        if section_count > config.max_elf_sections {
            return Err(StaticRamError::ElfSectionLimitExceeded {
                limit: config.max_elf_sections,
            });
        }
        let index = u64::try_from(section.index().0).map_err(|_| {
            StaticRamError::ElfSectionLimitExceeded {
                limit: config.max_elf_sections,
            }
        })?;
        let name_bytes = section
            .name_bytes()
            .map_err(|error| StaticRamError::InvalidElf {
                message: format!("section {index} name: {error}"),
            })?;
        let Some((name, kind)) = str::from_utf8(name_bytes)
            .ok()
            .and_then(|name| config.sections.get_key_value(name))
            .map(|(name, kind)| (name.clone(), *kind))
        else {
            continue;
        };
        if let Some(previous_index) = seen.insert(name.clone(), index) {
            return Err(StaticRamError::DuplicateElfSection {
                name,
                previous_index,
                index,
            });
        }
        let flags = section.flags();
        let writable_ram = matches!(
            flags,
            object::SectionFlags::Elf { sh_flags, .. }
                if sh_flags.contains(object::elf::SHF_ALLOC)
                    && sh_flags.contains(object::elf::SHF_WRITE)
        );
        if !writable_ram {
            return Err(StaticRamError::ElfSectionNotWritableRam {
                name,
                index,
                flags: format!("{flags:?}"),
            });
        }
        let address = section.address();
        let size_bytes = section.size();
        if section.file_range().is_some() {
            let payload = section.data().map_err(|error| StaticRamError::InvalidElf {
                message: format!("section {index} payload: {error}"),
            })?;
            if u64::try_from(payload.len()).ok() != Some(size_bytes) {
                return Err(StaticRamError::InvalidElf {
                    message: format!(
                        "section {index} payload size {} does not match declared size {size_bytes}",
                        payload.len()
                    ),
                });
            }
        }
        address
            .checked_add(size_bytes)
            .ok_or_else(|| StaticRamError::ElfAddressOverflow {
                name: name.clone(),
                index,
            })?;
        add_to_kind_total(&mut totals, kind, size_bytes).ok_or_else(|| {
            StaticRamError::ElfKindTotalOverflow {
                name: name.clone(),
                kind,
                index,
            }
        })?;
        totals
            .checked_total()
            .ok_or_else(|| StaticRamError::ElfTotalOverflow {
                name: name.clone(),
                index,
            })?;
        sections.push(StaticRamSection {
            name,
            address,
            size_bytes,
            kind,
            source_line: None,
            source_section_index: Some(index),
        });
    }

    let total_bytes = totals
        .checked_total()
        .expect("the combined total was checked after every section");
    Ok(StaticRamReport {
        schema: StaticRamReportSchema::ElfSectionsV1,
        elf: Some(ElfStaticRamMetadata {
            architecture,
            object_kind,
            class,
            endianness,
        }),
        sections,
        total_bytes,
        totals,
    })
}

fn validate_elf_limit(field: &'static str, value: u64, maximum: u64) -> Result<(), StaticRamError> {
    if value == 0 || value > maximum {
        Err(StaticRamError::InvalidElfLimit {
            field,
            value,
            maximum,
        })
    } else {
        Ok(())
    }
}

/// Validates the ELF section table before handing attacker-controlled input to
/// the general object parser.
///
/// ELF uses `e_shnum == 0` to store the actual section count in section zero.
/// Read only that fixed field after proving the first section header is present,
/// then bound the complete table with checked arithmetic.
fn preflight_elf_section_table(
    bytes: &[u8],
    maximum_sections: u64,
) -> Result<ElfStaticRamClass, StaticRamError> {
    const ELF_IDENT_SIZE: usize = 16;
    const ELF32_HEADER_SIZE: usize = 52;
    const ELF64_HEADER_SIZE: usize = 64;
    const ELF32_SECTION_HEADER_SIZE: u64 = 40;
    const ELF64_SECTION_HEADER_SIZE: u64 = 64;

    let class = match bytes.get(4).copied() {
        Some(1) => ElfStaticRamClass::Elf32,
        Some(2) => ElfStaticRamClass::Elf64,
        Some(value) => return Err(invalid_elf(format!("unsupported ELF class {value}"))),
        None => return Err(invalid_elf("truncated ELF identification")),
    };
    let little_endian = match bytes.get(5).copied() {
        Some(1) => true,
        Some(2) => false,
        Some(value) => {
            return Err(invalid_elf(format!(
                "unsupported ELF data encoding {value}"
            )));
        }
        None => return Err(invalid_elf("truncated ELF identification")),
    };
    if bytes.len() < ELF_IDENT_SIZE {
        return Err(invalid_elf("truncated ELF identification"));
    }

    let (
        header_size,
        section_offset_offset,
        section_entry_size_offset,
        section_count_offset,
        section_header_size,
        section_size_offset,
        section_size_width,
    ) = match class {
        ElfStaticRamClass::Elf32 => (
            ELF32_HEADER_SIZE,
            32,
            46,
            48,
            ELF32_SECTION_HEADER_SIZE,
            20,
            4,
        ),
        ElfStaticRamClass::Elf64 => (
            ELF64_HEADER_SIZE,
            40,
            58,
            60,
            ELF64_SECTION_HEADER_SIZE,
            32,
            8,
        ),
    };
    if bytes.len() < header_size {
        return Err(invalid_elf("truncated ELF header"));
    }

    let section_offset = read_elf_unsigned(
        bytes,
        section_offset_offset,
        match class {
            ElfStaticRamClass::Elf32 => 4,
            ElfStaticRamClass::Elf64 => 8,
        },
        little_endian,
    )?;
    let section_entry_size = read_elf_unsigned(bytes, section_entry_size_offset, 2, little_endian)?;
    if section_entry_size != section_header_size {
        return Err(invalid_elf(format!(
            "ELF section header entry size {section_entry_size} is not {section_header_size}"
        )));
    }
    let encoded_section_count = read_elf_unsigned(bytes, section_count_offset, 2, little_endian)?;
    let section_count = if encoded_section_count == 0 {
        let section_zero_end = section_offset
            .checked_add(section_header_size)
            .ok_or_else(|| invalid_elf("ELF section zero range overflows"))?;
        ensure_elf_range(
            bytes,
            section_offset,
            section_zero_end,
            "ELF section zero is truncated",
        )?;
        read_elf_unsigned_at(
            bytes,
            section_offset,
            section_size_offset,
            section_size_width,
            little_endian,
        )?
    } else {
        encoded_section_count
    };
    if section_count > maximum_sections {
        return Err(StaticRamError::ElfSectionLimitExceeded {
            limit: maximum_sections,
        });
    }
    let section_table_size = section_entry_size
        .checked_mul(section_count)
        .ok_or_else(|| invalid_elf("ELF section table size overflows"))?;
    let section_table_end = section_offset
        .checked_add(section_table_size)
        .ok_or_else(|| invalid_elf("ELF section table range overflows"))?;
    ensure_elf_range(
        bytes,
        section_offset,
        section_table_end,
        "ELF section table is truncated",
    )?;

    Ok(class)
}

fn read_elf_unsigned(
    bytes: &[u8],
    offset: usize,
    width: usize,
    little_endian: bool,
) -> Result<u64, StaticRamError> {
    let end = offset
        .checked_add(width)
        .ok_or_else(|| invalid_elf("ELF header field range overflows"))?;
    let field = bytes
        .get(offset..end)
        .ok_or_else(|| invalid_elf("truncated ELF header field"))?;
    let value = match (width, little_endian) {
        (2, true) => u16::from_le_bytes([field[0], field[1]]) as u64,
        (2, false) => u16::from_be_bytes([field[0], field[1]]) as u64,
        (4, true) => u32::from_le_bytes([field[0], field[1], field[2], field[3]]) as u64,
        (4, false) => u32::from_be_bytes([field[0], field[1], field[2], field[3]]) as u64,
        (8, true) => u64::from_le_bytes([
            field[0], field[1], field[2], field[3], field[4], field[5], field[6], field[7],
        ]),
        (8, false) => u64::from_be_bytes([
            field[0], field[1], field[2], field[3], field[4], field[5], field[6], field[7],
        ]),
        _ => return Err(invalid_elf("unsupported ELF integer width")),
    };
    Ok(value)
}

fn read_elf_unsigned_at(
    bytes: &[u8],
    base: u64,
    offset: usize,
    width: usize,
    little_endian: bool,
) -> Result<u64, StaticRamError> {
    let offset = usize::try_from(base)
        .ok()
        .and_then(|base| base.checked_add(offset))
        .ok_or_else(|| invalid_elf("ELF section field offset overflows"))?;
    read_elf_unsigned(bytes, offset, width, little_endian)
}

fn ensure_elf_range(
    bytes: &[u8],
    start: u64,
    end: u64,
    message: &'static str,
) -> Result<(), StaticRamError> {
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if start > end || end > length {
        return Err(invalid_elf(message));
    }
    Ok(())
}

fn invalid_elf(message: impl Into<String>) -> StaticRamError {
    StaticRamError::InvalidElf {
        message: message.into(),
    }
}

fn supported_elf_architecture(
    architecture: object::Architecture,
    bytes: &[u8],
    class: ElfStaticRamClass,
    endianness: ElfStaticRamEndianness,
) -> Result<ElfStaticRamArchitecture, StaticRamError> {
    match architecture {
        object::Architecture::Arm => Ok(ElfStaticRamArchitecture::Arm),
        object::Architecture::Aarch64 => Ok(ElfStaticRamArchitecture::Aarch64),
        object::Architecture::Riscv32 => Ok(ElfStaticRamArchitecture::Riscv32),
        object::Architecture::Riscv64 => Ok(ElfStaticRamArchitecture::Riscv64),
        object::Architecture::Unknown
            if class == ElfStaticRamClass::Elf32
                && endianness == ElfStaticRamEndianness::Little
                && elf_machine(bytes) == Some(object::elf::EM_TRICORE.0) =>
        {
            Ok(ElfStaticRamArchitecture::TriCore)
        }
        unsupported => Err(StaticRamError::UnsupportedElfArchitecture {
            architecture: format!("{unsupported:?}"),
        }),
    }
}

/// Reads `e_machine` after object has authenticated the artifact as an ELF file.
///
/// `object` does not currently expose TriCore as an `Architecture` variant. The
/// fallback is deliberately limited to the fixed ELF header field and is only
/// used when `object` reports an otherwise unknown architecture.
fn elf_machine(bytes: &[u8]) -> Option<u16> {
    const ELF_MACHINE_OFFSET: usize = 18;
    let machine = bytes.get(ELF_MACHINE_OFFSET..ELF_MACHINE_OFFSET + 2)?;
    Some(u16::from_le_bytes([machine[0], machine[1]]))
}

fn supported_elf_object_kind(
    kind: object::ObjectKind,
) -> Result<ElfStaticRamObjectKind, StaticRamError> {
    match kind {
        object::ObjectKind::Relocatable => Ok(ElfStaticRamObjectKind::Relocatable),
        object::ObjectKind::Executable => Ok(ElfStaticRamObjectKind::Executable),
        unsupported => Err(StaticRamError::UnsupportedElfObjectKind {
            kind: format!("{unsupported:?}"),
        }),
    }
}

fn add_to_kind_total(
    totals: &mut StaticRamKindTotals,
    kind: StaticRamSectionKind,
    size_bytes: u64,
) -> Option<()> {
    let total = match kind {
        StaticRamSectionKind::Data => &mut totals.data_bytes,
        StaticRamSectionKind::Bss => &mut totals.bss_bytes,
        StaticRamSectionKind::NoInit => &mut totals.noinit_bytes,
        StaticRamSectionKind::Dma => &mut totals.dma_bytes,
        StaticRamSectionKind::Rtos => &mut totals.rtos_bytes,
        StaticRamSectionKind::Custom => &mut totals.custom_bytes,
    };
    *total = total.checked_add(size_bytes)?;
    Some(())
}

fn selected_section(
    line: &ResourceTextLine,
    config: &StaticRamParserConfig,
) -> Option<(String, StaticRamSectionKind)> {
    if line.bytes.first().is_none_or(u8::is_ascii_whitespace) {
        return None;
    }
    let end = line
        .bytes
        .iter()
        .position(u8::is_ascii_whitespace)
        .unwrap_or(line.bytes.len());
    let name = str::from_utf8(&line.bytes[..end]).ok()?;
    config
        .sections
        .get(name)
        .copied()
        .map(|kind| (name.to_owned(), kind))
}

fn parse_integer(value: &str) -> Option<u64> {
    if let Some(digits) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        if digits.is_empty() {
            return None;
        }
        u64::from_str_radix(digits, 16).ok()
    } else if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        value.parse().ok()
    } else {
        None
    }
}

fn validate_section_name(name: &str) -> Result<(), StaticRamConfigError> {
    if !name.starts_with('.')
        || name.len() == 1
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(StaticRamConfigError::InvalidSectionName {
            name: name.to_owned(),
        });
    }
    Ok(())
}
