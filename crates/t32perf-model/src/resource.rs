//! Explicit resource-counter semantics, subjects, and static-RAM configuration.

use std::{collections::BTreeSet, fmt, str::FromStr};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use thiserror::Error;

use crate::{MetricSupportEntry, Quality, Sha256Digest, StaticRamConfigSchemaVersion, TimestampNs};

/// Largest integer exactly representable by the normalized `f64` counter wire type.
pub const MAX_EXACT_COUNTER_INTEGER: f64 = 9_007_199_254_740_992.0;
/// Strict GNU ld map flavor for static-RAM inputs.
pub const STATIC_RAM_GNU_LD_MAP_V1_FLAVOR: &str = "gnu-ld-map-v1";
/// Strict ELF section-table flavor for static-RAM inputs.
pub const STATIC_RAM_ELF_SECTIONS_V1_FLAVOR: &str = "elf-sections-v1";
/// Maximum number of caller-classified static-RAM sections in one config.
pub const MAX_STATIC_RAM_ADDITIONAL_SECTIONS: usize = 4_096;

/// Stable, extensible semantic identity for one counter family.
///
/// Values use lower-case dot-separated identifiers. Standard semantics are
/// interpreted only through [`Self::standard_spec`]; unknown valid identifiers
/// remain extension-defined generic counters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct CounterSemantic(
    #[schemars(
        length(min = 3, max = 128),
        regex(pattern = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
    )]
    String,
);

impl CounterSemantic {
    /// Heap bytes currently allocated by one allocator.
    pub const HEAP_CURRENT_ALLOCATED_BYTES: &'static str = "heap.current_allocated_bytes";
    /// Heap allocation high-watermark reported by one allocator.
    pub const HEAP_PEAK_ALLOCATED_BYTES: &'static str = "heap.peak_allocated_bytes";
    /// Monotonic successful-allocation count reported by one allocator.
    pub const HEAP_ALLOCATION_COUNT: &'static str = "heap.allocation_count";
    /// Monotonic free-operation count reported by one allocator.
    pub const HEAP_FREE_COUNT: &'static str = "heap.free_count";
    /// Largest observed allocation reported by one allocator.
    pub const HEAP_LARGEST_ALLOCATION_BYTES: &'static str = "heap.largest_allocation_bytes";
    /// Heap bytes currently free in one allocator.
    pub const HEAP_FREE_BYTES: &'static str = "heap.free_bytes";
    /// Largest currently free contiguous block in one allocator.
    pub const HEAP_LARGEST_FREE_BLOCK_BYTES: &'static str = "heap.largest_free_block_bytes";
    /// Allocation rate explicitly measured or derived for one allocator.
    pub const HEAP_ALLOCATION_RATE_PER_SECOND: &'static str = "heap.allocation_rate_per_second";
    /// External-fragmentation ratio for one allocator.
    pub const HEAP_EXTERNAL_FRAGMENTATION_RATIO: &'static str = "heap.external_fragmentation_ratio";
    /// Declared capacity of one runtime stack.
    pub const STACK_CAPACITY_BYTES: &'static str = "stack.capacity_bytes";
    /// Current used bytes of one runtime stack.
    pub const STACK_CURRENT_USED_BYTES: &'static str = "stack.current_used_bytes";
    /// Runtime stack high-watermark.
    pub const STACK_PEAK_USED_BYTES: &'static str = "stack.peak_used_bytes";
    /// Current used bytes in one explicitly identified memory region.
    pub const RAM_CURRENT_USED_BYTES: &'static str = "ram.current_used_bytes";
    /// Used-byte high-watermark in one explicitly identified memory region.
    pub const RAM_PEAK_USED_BYTES: &'static str = "ram.peak_used_bytes";
    /// Declared capacity of one trace buffer.
    pub const TRACE_BUFFER_CAPACITY_BYTES: &'static str = "trace_buffer.capacity_bytes";
    /// Current used bytes of one trace buffer.
    pub const TRACE_BUFFER_CURRENT_USED_BYTES: &'static str = "trace_buffer.current_used_bytes";
    /// Used-byte high-watermark of one trace buffer.
    pub const TRACE_BUFFER_PEAK_USED_BYTES: &'static str = "trace_buffer.peak_used_bytes";

    /// Creates and validates a semantic identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, CounterSemanticError> {
        let value = value.into();
        validate_semantic(&value)?;
        Ok(Self(value))
    }

    /// Returns the semantic identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the exact built-in contract for a standard semantic.
    #[must_use]
    pub fn standard_spec(&self) -> Option<StandardCounterSpec> {
        StandardCounterSpec::for_semantic(self.as_str())
    }
}

impl fmt::Display for CounterSemantic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for CounterSemantic {
    type Err = CounterSemanticError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for CounterSemantic {
    type Error = CounterSemanticError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for CounterSemantic {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Invalid resource-counter semantic identifier.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid counter semantic `{value}`; expected lower-case dot-separated identifiers")]
pub struct CounterSemanticError {
    /// Rejected identifier.
    pub value: String,
}

fn validate_semantic(value: &str) -> Result<(), CounterSemanticError> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value.split('.').count() >= 2
        && value.split('.').all(|segment| {
            let mut bytes = segment.bytes();
            bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
                && bytes
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        });
    if valid {
        Ok(())
    } else {
        Err(CounterSemanticError {
            value: value.to_owned(),
        })
    }
}

/// Broad resource group derived exclusively from an explicit standard semantic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResourceClass {
    /// Dynamic allocator state.
    Heap,
    /// Runtime stack state.
    Stack,
    /// Explicit target memory-region state.
    Ram,
    /// Trace-capture buffer state.
    TraceBuffer,
    /// Generic or extension-defined counter state.
    Other,
}

/// Runtime behavior required by one standard counter semantic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CounterBehavior {
    /// An instantaneous gauge that may rise or fall.
    Gauge,
    /// A value that must never decrease.
    HighWatermark,
    /// A cumulative count that must never decrease within a capture.
    Monotonic,
    /// A nonnegative rate.
    Rate,
    /// An inclusive ratio in the range zero to one.
    Ratio,
    /// A stable declared capacity.
    Capacity,
}

/// Kind of subject required by a standard semantic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterSubjectKind {
    /// Allocator subject.
    Allocator,
    /// Runtime stack subject.
    Stack,
    /// Explicit memory-region subject.
    MemoryRegion,
    /// Trace-buffer subject.
    TraceBuffer,
}

/// Exact contract attached to one standard counter semantic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StandardCounterSpec {
    /// Required unit string.
    pub unit: &'static str,
    /// Runtime value behavior.
    pub behavior: CounterBehavior,
    /// Presentation resource group.
    pub class: ResourceClass,
    /// Required subject kind.
    pub subject_kind: CounterSubjectKind,
    /// Whether every value must be an exactly representable integer.
    pub exact_integer: bool,
}

impl StandardCounterSpec {
    fn for_semantic(semantic: &str) -> Option<Self> {
        use CounterBehavior::{Capacity, Gauge, HighWatermark, Monotonic, Rate, Ratio};
        use CounterSubjectKind::{Allocator, MemoryRegion, Stack, TraceBuffer};
        use ResourceClass::{Heap, Ram};

        let spec = match semantic {
            CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES
            | CounterSemantic::HEAP_FREE_BYTES
            | CounterSemantic::HEAP_LARGEST_FREE_BLOCK_BYTES => Self {
                unit: "bytes",
                behavior: Gauge,
                class: Heap,
                subject_kind: Allocator,
                exact_integer: true,
            },
            CounterSemantic::HEAP_PEAK_ALLOCATED_BYTES
            | CounterSemantic::HEAP_LARGEST_ALLOCATION_BYTES => Self {
                unit: "bytes",
                behavior: HighWatermark,
                class: Heap,
                subject_kind: Allocator,
                exact_integer: true,
            },
            CounterSemantic::HEAP_ALLOCATION_COUNT | CounterSemantic::HEAP_FREE_COUNT => Self {
                unit: "count",
                behavior: Monotonic,
                class: Heap,
                subject_kind: Allocator,
                exact_integer: true,
            },
            CounterSemantic::HEAP_ALLOCATION_RATE_PER_SECOND => Self {
                unit: "1/s",
                behavior: Rate,
                class: Heap,
                subject_kind: Allocator,
                exact_integer: false,
            },
            CounterSemantic::HEAP_EXTERNAL_FRAGMENTATION_RATIO => Self {
                unit: "ratio",
                behavior: Ratio,
                class: Heap,
                subject_kind: Allocator,
                exact_integer: false,
            },
            CounterSemantic::STACK_CAPACITY_BYTES => Self {
                unit: "bytes",
                behavior: Capacity,
                class: ResourceClass::Stack,
                subject_kind: Stack,
                exact_integer: true,
            },
            CounterSemantic::STACK_CURRENT_USED_BYTES => Self {
                unit: "bytes",
                behavior: Gauge,
                class: ResourceClass::Stack,
                subject_kind: Stack,
                exact_integer: true,
            },
            CounterSemantic::STACK_PEAK_USED_BYTES => Self {
                unit: "bytes",
                behavior: HighWatermark,
                class: ResourceClass::Stack,
                subject_kind: Stack,
                exact_integer: true,
            },
            CounterSemantic::RAM_CURRENT_USED_BYTES => Self {
                unit: "bytes",
                behavior: Gauge,
                class: Ram,
                subject_kind: MemoryRegion,
                exact_integer: true,
            },
            CounterSemantic::RAM_PEAK_USED_BYTES => Self {
                unit: "bytes",
                behavior: HighWatermark,
                class: Ram,
                subject_kind: MemoryRegion,
                exact_integer: true,
            },
            CounterSemantic::TRACE_BUFFER_CAPACITY_BYTES => Self {
                unit: "bytes",
                behavior: Capacity,
                class: ResourceClass::TraceBuffer,
                subject_kind: TraceBuffer,
                exact_integer: true,
            },
            CounterSemantic::TRACE_BUFFER_CURRENT_USED_BYTES => Self {
                unit: "bytes",
                behavior: Gauge,
                class: ResourceClass::TraceBuffer,
                subject_kind: TraceBuffer,
                exact_integer: true,
            },
            CounterSemantic::TRACE_BUFFER_PEAK_USED_BYTES => Self {
                unit: "bytes",
                behavior: HighWatermark,
                class: ResourceClass::TraceBuffer,
                subject_kind: TraceBuffer,
                exact_integer: true,
            },
            _ => return None,
        };
        Some(spec)
    }

    /// Validates a value against this standard semantic contract.
    #[must_use]
    pub fn value_is_valid(self, value: f64) -> bool {
        value.is_finite()
            && value >= 0.0
            && (!self.exact_integer || (value <= MAX_EXACT_COUNTER_INTEGER && value.fract() == 0.0))
            && (self.behavior != CounterBehavior::Ratio || value <= 1.0)
    }
}

/// Semantic role assigned to one runtime stack.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum StackRole {
    /// RTOS Task stack.
    Task,
    /// Dedicated ISR stack.
    Isr,
    /// Arm Main Stack Pointer stack.
    Msp,
    /// Arm Process Stack Pointer stack.
    Psp,
    /// Extension-defined stack role.
    Custom,
}

/// Stable identity of the resource measured by a counter.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CounterSubject {
    /// The complete capture session.
    Capture,
    /// One allocator instance.
    Allocator {
        /// Stable allocator identity.
        allocator_id: String,
    },
    /// One execution context.
    Context {
        /// Referenced context dictionary identity.
        context_id: String,
    },
    /// One processor core.
    Core {
        /// Zero-based core identity.
        core_id: u32,
    },
    /// One runtime stack.
    Stack {
        /// Stable physical-stack identity.
        stack_id: String,
        /// Semantic role of the stack.
        role: StackRole,
        /// Referenced Task or ISR context when applicable.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        context_id: Option<String>,
        /// Referenced core for MSP, PSP, or core-local stacks.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        core_id: Option<u32>,
    },
    /// One target memory region.
    MemoryRegion {
        /// Stable region identity.
        region_id: String,
    },
    /// One trace-capture buffer.
    TraceBuffer {
        /// Stable buffer identity.
        buffer_id: String,
        /// Core owning the buffer when it is core-local.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        core_id: Option<u32>,
    },
    /// Extension-defined resource identity.
    Custom {
        /// Lower-case extension namespace.
        namespace: String,
        /// Stable identity within the namespace.
        id: String,
    },
}

impl CounterSubject {
    /// Validates required identities and stack-role constraints.
    pub fn validate(&self) -> Result<(), CounterSubjectValidationError> {
        match self {
            Self::Capture | Self::Core { .. } => Ok(()),
            Self::Allocator { allocator_id } => validate_subject_id("allocator_id", allocator_id),
            Self::Context { context_id } => validate_subject_id("context_id", context_id),
            Self::Stack {
                stack_id,
                role,
                context_id,
                core_id,
            } => {
                validate_subject_id("stack_id", stack_id)?;
                match role {
                    StackRole::Task | StackRole::Isr if context_id.is_none() => {
                        Err(CounterSubjectValidationError::MissingStackContext { role: *role })
                    }
                    StackRole::Msp | StackRole::Psp if core_id.is_none() => {
                        Err(CounterSubjectValidationError::MissingStackCore { role: *role })
                    }
                    _ => {
                        if let Some(context_id) = context_id {
                            validate_subject_id("context_id", context_id)?;
                        }
                        Ok(())
                    }
                }
            }
            Self::MemoryRegion { region_id } => validate_subject_id("region_id", region_id),
            Self::TraceBuffer { buffer_id, .. } => validate_subject_id("buffer_id", buffer_id),
            Self::Custom { namespace, id } => {
                validate_extension_namespace(namespace)?;
                validate_subject_id("id", id)
            }
        }
    }

    /// Returns the coarse kind used by standard-semantic validation.
    #[must_use]
    pub const fn kind(&self) -> Option<CounterSubjectKind> {
        match self {
            Self::Allocator { .. } => Some(CounterSubjectKind::Allocator),
            Self::Stack { .. } => Some(CounterSubjectKind::Stack),
            Self::MemoryRegion { .. } => Some(CounterSubjectKind::MemoryRegion),
            Self::TraceBuffer { .. } => Some(CounterSubjectKind::TraceBuffer),
            Self::Capture | Self::Context { .. } | Self::Core { .. } | Self::Custom { .. } => None,
        }
    }
}

fn validate_subject_id(
    field: &'static str,
    value: &str,
) -> Result<(), CounterSubjectValidationError> {
    if value.trim().is_empty() || value.len() > 256 {
        Err(CounterSubjectValidationError::InvalidIdentity {
            field,
            value: value.to_owned(),
        })
    } else {
        Ok(())
    }
}

fn validate_extension_namespace(value: &str) -> Result<(), CounterSubjectValidationError> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
    if valid {
        Ok(())
    } else {
        Err(CounterSubjectValidationError::InvalidIdentity {
            field: "namespace",
            value: value.to_owned(),
        })
    }
}

/// Invalid resource-counter subject.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CounterSubjectValidationError {
    /// A required subject identity is empty or too long.
    #[error("counter subject field `{field}` has invalid identity `{value}`")]
    InvalidIdentity {
        /// Invalid field.
        field: &'static str,
        /// Rejected value.
        value: String,
    },
    /// A Task or ISR stack omitted its context identity.
    #[error("{role:?} stack subject requires context_id")]
    MissingStackContext {
        /// Stack role requiring the context.
        role: StackRole,
    },
    /// An MSP or PSP stack omitted its core identity.
    #[error("{role:?} stack subject requires core_id")]
    MissingStackCore {
        /// Stack role requiring the core.
        role: StackRole,
    },
}

/// One derived resource value supported by explicitly identified source counters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DerivedResourceMetricSummary {
    /// Derived standard semantic.
    pub semantic: CounterSemantic,
    /// Resource to which the value belongs.
    pub subject: CounterSubject,
    /// Exact unit required by the standard semantic.
    pub unit: String,
    /// Derived value, absent when evidence is insufficient.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    /// Counter IDs that supplied the evidence.
    pub source_counter_ids: Vec<String>,
    /// First timestamp in a rate window or synchronized point timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_ts_ns: Option<TimestampNs>,
    /// Last timestamp in a rate window or synchronized point timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_ts_ns: Option<TimestampNs>,
    /// Positive derivation window for rate metrics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_ns: Option<u64>,
    /// Worst contributing evidence quality when any evidence exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality: Option<Quality>,
    /// Effective support after capability, quality, and health-policy gating.
    pub support: MetricSupportEntry,
}

/// Classification allowed for a caller-declared static-RAM output section.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum StaticRamAdditionalSectionKind {
    /// DMA-visible static storage.
    Dma,
    /// RTOS-owned static storage.
    Rtos,
    /// Project-defined static storage.
    Custom,
}

/// One exact additional static-RAM output-section classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StaticRamSectionConfig {
    /// Exact top-level output-section name.
    #[schemars(length(min = 2, max = 128), regex(pattern = r"^\.[A-Za-z0-9._-]+$"))]
    pub name: String,
    /// Explicit classification.
    pub kind: StaticRamAdditionalSectionKind,
}

/// Versioned static-RAM parser configuration artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StaticRamConfigDocument {
    /// Static-RAM configuration schema.
    pub schema: StaticRamConfigSchemaVersion,
    /// Exact static-RAM parser flavor; input format is never inferred.
    #[schemars(regex(pattern = r"^(gnu-ld-map-v1|elf-sections-v1)$"))]
    pub flavor: String,
    /// Additional exact output-section classifications.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 4096))]
    pub additional_sections: Vec<StaticRamSectionConfig>,
}

impl StaticRamConfigDocument {
    /// Creates the built-in-only GNU ld configuration.
    #[must_use]
    pub fn gnu_ld_map_v1() -> Self {
        Self {
            schema: StaticRamConfigSchemaVersion,
            flavor: STATIC_RAM_GNU_LD_MAP_V1_FLAVOR.to_owned(),
            additional_sections: Vec::new(),
        }
    }

    /// Creates the built-in-only ELF section-table configuration.
    #[must_use]
    pub fn elf_sections_v1() -> Self {
        Self {
            schema: StaticRamConfigSchemaVersion,
            flavor: STATIC_RAM_ELF_SECTIONS_V1_FLAVOR.to_owned(),
            additional_sections: Vec::new(),
        }
    }

    /// Validates flavor, bounds, exact names, duplicates, and built-in reclassification.
    pub fn validate(&self) -> Result<(), StaticRamConfigValidationError> {
        if !matches!(
            self.flavor.as_str(),
            STATIC_RAM_GNU_LD_MAP_V1_FLAVOR | STATIC_RAM_ELF_SECTIONS_V1_FLAVOR
        ) {
            return Err(StaticRamConfigValidationError::UnsupportedFlavor {
                flavor: self.flavor.clone(),
            });
        }
        if self.additional_sections.len() > MAX_STATIC_RAM_ADDITIONAL_SECTIONS {
            return Err(StaticRamConfigValidationError::TooManyAdditionalSections {
                count: self.additional_sections.len(),
                maximum: MAX_STATIC_RAM_ADDITIONAL_SECTIONS,
            });
        }
        let mut names = BTreeSet::new();
        for section in &self.additional_sections {
            validate_static_section_name(&section.name)?;
            if matches!(section.name.as_str(), ".data" | ".bss" | ".noinit") {
                return Err(StaticRamConfigValidationError::BuiltinReclassification {
                    name: section.name.clone(),
                });
            }
            if !names.insert(section.name.as_str()) {
                return Err(StaticRamConfigValidationError::DuplicateSection {
                    name: section.name.clone(),
                });
            }
        }
        Ok(())
    }
}

fn validate_static_section_name(name: &str) -> Result<(), StaticRamConfigValidationError> {
    let valid = name.starts_with('.')
        && name.len() > 1
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(StaticRamConfigValidationError::InvalidExactSectionName {
            name: name.to_owned(),
        })
    }
}

/// Invalid static-RAM configuration artifact.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StaticRamConfigValidationError {
    /// The artifact requests an unsupported parser flavor.
    #[error("unsupported static RAM configuration flavor `{flavor}`")]
    UnsupportedFlavor {
        /// Rejected flavor.
        flavor: String,
    },
    /// The artifact contains more exact classifications than the parser ceiling.
    #[error("static RAM configuration has {count} additional sections; maximum is {maximum}")]
    TooManyAdditionalSections {
        /// Declared section count.
        count: usize,
        /// Supported section-count ceiling.
        maximum: usize,
    },
    /// An output-section name is not an exact supported name.
    #[error("invalid exact GNU ld output-section name `{name}`")]
    InvalidExactSectionName {
        /// Rejected name.
        name: String,
    },
    /// The artifact attempts to reclassify a fixed built-in section.
    #[error("built-in GNU ld output section `{name}` cannot be reclassified")]
    BuiltinReclassification {
        /// Rejected built-in name.
        name: String,
    },
    /// The artifact repeats an additional section name.
    #[error("static RAM configuration repeats output section `{name}`")]
    DuplicateSection {
        /// Repeated name.
        name: String,
    },
}

/// Checked per-kind static-RAM totals.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StaticRamKindTotals {
    /// Initialized `.data` bytes.
    pub data_bytes: u64,
    /// Zero-initialized `.bss` bytes.
    pub bss_bytes: u64,
    /// Non-initialized `.noinit` bytes.
    pub noinit_bytes: u64,
    /// Explicit DMA-section bytes.
    pub dma_bytes: u64,
    /// Explicit RTOS-section bytes.
    pub rtos_bytes: u64,
    /// Explicit custom-section bytes.
    pub custom_bytes: u64,
}

impl StaticRamKindTotals {
    /// Returns the checked sum of every classified kind.
    #[must_use]
    pub fn checked_total(&self) -> Option<u64> {
        [
            self.data_bytes,
            self.bss_bytes,
            self.noinit_bytes,
            self.dma_bytes,
            self.rtos_bytes,
            self.custom_bytes,
        ]
        .into_iter()
        .try_fold(0_u64, u64::checked_add)
    }
}

/// Static-RAM parser configuration provenance persisted with an analysis summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StaticRamConfigProvenance {
    /// Explicit configuration input artifact, absent for the versioned built-in default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<String>,
    /// Digest of the explicit artifact or canonical built-in default document.
    pub sha256: Sha256Digest,
}
