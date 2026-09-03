//! Bounded ELF executable scopes and function ranges for PC-hit attribution.
//!
//! The mapping deliberately trusts ELF `PT_LOAD` permissions, rather than
//! section names or section flags. A PC-hit histogram therefore cannot expand
//! its denominator into data or debug sections by accident.

use std::collections::BTreeMap;

use object::{
    Architecture, BinaryFormat, Object as _, ObjectKind, ObjectSegment as _, ObjectSymbol as _,
    SymbolKind,
};
use thiserror::Error;

use t32perf_model::MAX_PC_HIT_BUCKETS;

/// Largest executable ELF input accepted by the mapping helpers.
pub const MAX_ELF_MAPPING_INPUT_BYTES: usize = 256 * 1024 * 1024;
/// Maximum disjoint executable ranges accepted from one ELF.
pub const MAX_ELF_EXECUTABLE_RANGES: usize = MAX_PC_HIT_BUCKETS;
/// Maximum normalized function ranges accepted from one ELF.
pub const MAX_ELF_FUNCTION_RANGES: usize = MAX_PC_HIT_BUCKETS;

const MAX_MODULE_TEXT_BYTES: usize = 128;
const MAX_DISPLAY_NAME_BYTES: usize = 256;

/// One nonempty half-open executable address range from an ELF `PT_LOAD` segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfExecutableRange {
    /// Inclusive address.
    pub start: u64,
    /// Exclusive address.
    pub end: u64,
}

/// The bounded, sorted, nonoverlapping executable address scope of one ELF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfExecutableScope {
    /// Executable `PT_LOAD` ranges, in ascending address order.
    pub ranges: Vec<ElfExecutableRange>,
}

/// One deterministic function range suitable for PC-hit attribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfFunctionRange {
    /// Stable identity containing the normalized half-open address range.
    pub function_id: String,
    /// Deterministically selected human-readable symbol name.
    pub display_name: String,
    /// Inclusive address.
    pub start: u64,
    /// Exclusive address.
    pub end: u64,
}

/// Failures while deriving PC-hit scopes or function ranges from an ELF.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ElfMappingError {
    /// The supplied module identity is not safe to publish in an artifact.
    #[error(
        "ELF module must be nonempty, at most {MAX_MODULE_TEXT_BYTES} bytes, and contain no control characters"
    )]
    InvalidModule,
    /// The supplied function limit was outside the supported bounded range.
    #[error("ELF function limit must be 1..={MAX_ELF_FUNCTION_RANGES}")]
    InvalidFunctionLimit,
    /// The input was larger than the supported parser bound.
    #[error("ELF mapping input has {actual} bytes; maximum is {limit}")]
    InputTooLarge {
        /// Supported input-size limit.
        limit: usize,
        /// Observed input size.
        actual: usize,
    },
    /// The bytes did not parse as an ELF object.
    #[error("invalid ELF: {message}")]
    InvalidElf {
        /// Parser diagnostic, bounded by the dependency.
        message: String,
    },
    /// Only executable ELF images provide a stable runtime address scope.
    #[error("ELF mapping requires an executable ELF")]
    RequiresExecutableElf,
    /// Sampling function attribution is only defined for 32-bit ELF images.
    #[error("sampling function attribution requires a 32-bit ELF image")]
    SamplingRequiresElf32,
    /// Sampling function attribution is only defined for little-endian images.
    #[error("sampling function attribution requires a little-endian ELF image")]
    SamplingRequiresLittleEndian,
    /// Sampling function attribution is only defined for ARM/Thumb images.
    #[error("sampling function attribution requires an ARM ELF image")]
    SamplingRequiresArmArchitecture,
    /// No executable `PT_LOAD` range was present.
    #[error("executable ELF contains no executable PT_LOAD range")]
    EmptyExecutableScope,
    /// There were too many executable `PT_LOAD` ranges.
    #[error("ELF has more than {limit} executable PT_LOAD ranges")]
    TooManyExecutableRanges {
        /// Maximum range count.
        limit: usize,
    },
    /// A segment address plus memory size did not fit in `u64`.
    #[error("executable PT_LOAD address range overflows u64")]
    ExecutableRangeOverflow,
    /// A function address plus its size did not fit in `u64`.
    #[error("ELF function `{name}` address range overflows u64")]
    FunctionRangeOverflow {
        /// Bounded symbol name.
        name: String,
    },
    /// A selected text symbol had no valid bounded UTF-8 name.
    #[error("ELF text symbol has an invalid name")]
    InvalidFunctionName,
    /// A text symbol crossed an executable-segment boundary.
    #[error("ELF text symbol `{name}` crosses an executable PT_LOAD boundary")]
    FunctionCrossesExecutableBoundary {
        /// Bounded symbol name.
        name: String,
    },
    /// Two distinct normalized text ranges overlapped.
    #[error("ELF text symbols `{first}` and `{second}` overlap")]
    OverlappingFunctions {
        /// Earlier range's selected name.
        first: String,
        /// Later range's selected name.
        second: String,
    },
    /// The selected function count exceeded the caller's bound.
    #[error("ELF function count exceeds {limit}")]
    TooManyFunctions {
        /// Caller-specified function limit.
        limit: usize,
    },
}

/// Extracts a bounded executable `PT_LOAD` scope from an executable ELF.
pub fn executable_scope_from_elf(bytes: &[u8]) -> Result<ElfExecutableScope, ElfMappingError> {
    let file = parse_executable_elf(bytes)?;
    executable_scope_from_file(&file)
}

/// Validates that an ELF can safely bind function attribution to Cortex-M PC samples.
///
/// This deliberately narrows the generic executable-ELF contract to the ABI
/// used by Cortex-M/Thumb firmware: ELF32, little-endian, and `EM_ARM`.
/// It does not inspect debug information or infer a particular MCU.
pub fn validate_sampling_function_elf(bytes: &[u8]) -> Result<(), ElfMappingError> {
    let file = parse_executable_elf(bytes)?;
    validate_sampling_function_file(&file)
}

/// Extracts function ranges for Cortex-M sampling attribution.
///
/// Unlike [`function_ranges_from_elf`], this rejects executable ELF files
/// that are not little-endian 32-bit ARM images before extracting symbols.
pub fn sampling_function_ranges_from_elf(
    bytes: &[u8],
    module: &str,
    maximum_functions: usize,
) -> Result<Vec<ElfFunctionRange>, ElfMappingError> {
    validate_module(module)?;
    if maximum_functions == 0 || maximum_functions > MAX_ELF_FUNCTION_RANGES {
        return Err(ElfMappingError::InvalidFunctionLimit);
    }

    let file = parse_executable_elf(bytes)?;
    validate_sampling_function_file(&file)?;
    function_ranges_from_file(&file, module, maximum_functions)
}

/// Extracts deterministic nonoverlapping function ranges from an executable ELF.
///
/// Only defined, nonzero-size `Text` symbols completely contained in one
/// executable `PT_LOAD` range are emitted. On ARM, the Thumb state bit is
/// removed before the half-open address range is formed.
pub fn function_ranges_from_elf(
    bytes: &[u8],
    module: &str,
    maximum_functions: usize,
) -> Result<Vec<ElfFunctionRange>, ElfMappingError> {
    validate_module(module)?;
    if maximum_functions == 0 || maximum_functions > MAX_ELF_FUNCTION_RANGES {
        return Err(ElfMappingError::InvalidFunctionLimit);
    }

    let file = parse_executable_elf(bytes)?;
    function_ranges_from_file(&file, module, maximum_functions)
}

fn function_ranges_from_file(
    file: &object::File<'_>,
    module: &str,
    maximum_functions: usize,
) -> Result<Vec<ElfFunctionRange>, ElfMappingError> {
    let scope = executable_scope_from_file(file)?;
    let arm_thumb_symbols = file.architecture() == Architecture::Arm;
    let mut names_by_range = BTreeMap::<(u64, u64), String>::new();

    for symbol in file.symbols() {
        if !symbol.is_definition() || symbol.kind() != SymbolKind::Text || symbol.size() == 0 {
            continue;
        }
        let name = symbol
            .name()
            .map_err(|_| ElfMappingError::InvalidFunctionName)?;
        if !valid_text(name, MAX_DISPLAY_NAME_BYTES) {
            return Err(ElfMappingError::InvalidFunctionName);
        }
        let start = normalized_symbol_start(arm_thumb_symbols, symbol.address());
        let end = function_end(start, symbol.size(), name)?;
        if start == end {
            continue;
        }

        if !scope_contains(&scope, start, end) {
            if scope_intersects(&scope, start, end) {
                return Err(ElfMappingError::FunctionCrossesExecutableBoundary {
                    name: name.to_owned(),
                });
            }
            // Defined text outside a loadable executable segment is not part
            // of the runtime PC denominator and is intentionally ignored.
            continue;
        }

        register_function_range(&mut names_by_range, maximum_functions, start, end, name)?;
    }

    normalize_function_ranges(names_by_range, module)
}

fn parse_executable_elf(bytes: &[u8]) -> Result<object::File<'_>, ElfMappingError> {
    if bytes.len() > MAX_ELF_MAPPING_INPUT_BYTES {
        return Err(ElfMappingError::InputTooLarge {
            limit: MAX_ELF_MAPPING_INPUT_BYTES,
            actual: bytes.len(),
        });
    }
    let file = object::File::parse(bytes).map_err(|error| ElfMappingError::InvalidElf {
        message: error.to_string(),
    })?;
    if file.format() != BinaryFormat::Elf || file.kind() != ObjectKind::Executable {
        return Err(ElfMappingError::RequiresExecutableElf);
    }
    Ok(file)
}

fn validate_sampling_function_file(file: &object::File<'_>) -> Result<(), ElfMappingError> {
    if file.is_64() {
        return Err(ElfMappingError::SamplingRequiresElf32);
    }
    if !file.is_little_endian() {
        return Err(ElfMappingError::SamplingRequiresLittleEndian);
    }
    if file.architecture() != Architecture::Arm {
        return Err(ElfMappingError::SamplingRequiresArmArchitecture);
    }
    Ok(())
}

fn executable_scope_from_file(
    file: &object::File<'_>,
) -> Result<ElfExecutableScope, ElfMappingError> {
    let mut ranges = Vec::new();
    for segment in file.segments() {
        if !segment.permissions().executable() || segment.size() == 0 {
            continue;
        }
        let start = segment.address();
        let end = start
            .checked_add(segment.size())
            .ok_or(ElfMappingError::ExecutableRangeOverflow)?;
        ranges.push(ElfExecutableRange { start, end });
        if ranges.len() > MAX_ELF_EXECUTABLE_RANGES {
            return Err(ElfMappingError::TooManyExecutableRanges {
                limit: MAX_ELF_EXECUTABLE_RANGES,
            });
        }
    }
    normalize_executable_scope(ranges)
}

fn normalize_executable_scope(
    mut ranges: Vec<ElfExecutableRange>,
) -> Result<ElfExecutableScope, ElfMappingError> {
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut normalized: Vec<ElfExecutableRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if range.start >= range.end {
            continue;
        }
        if let Some(previous) = normalized.last_mut()
            && range.start < previous.end
        {
            previous.end = previous.end.max(range.end);
            continue;
        }
        normalized.push(range);
    }
    if normalized.is_empty() {
        return Err(ElfMappingError::EmptyExecutableScope);
    }
    Ok(ElfExecutableScope { ranges: normalized })
}

fn normalize_function_ranges(
    names_by_range: BTreeMap<(u64, u64), String>,
    module: &str,
) -> Result<Vec<ElfFunctionRange>, ElfMappingError> {
    let mut functions = Vec::with_capacity(names_by_range.len());
    let mut previous: Option<(u64, String)> = None;
    for ((start, end), display_name) in names_by_range {
        if let Some((previous_end, previous_name)) = &previous
            && start < *previous_end
        {
            return Err(ElfMappingError::OverlappingFunctions {
                first: previous_name.to_owned(),
                second: display_name,
            });
        }
        let function_id = format!("elf:{module}:{start:016x}-{end:016x}");
        previous = Some((end, display_name.clone()));
        functions.push(ElfFunctionRange {
            function_id,
            display_name,
            start,
            end,
        });
    }
    Ok(functions)
}

fn validate_module(module: &str) -> Result<(), ElfMappingError> {
    if valid_text(module, MAX_MODULE_TEXT_BYTES) {
        Ok(())
    } else {
        Err(ElfMappingError::InvalidModule)
    }
}

fn valid_text(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= maximum_bytes && !value.chars().any(char::is_control)
}

fn normalized_symbol_start(arm_thumb_symbols: bool, address: u64) -> u64 {
    if arm_thumb_symbols {
        address & !1
    } else {
        address
    }
}

fn function_end(start: u64, size: u64, name: &str) -> Result<u64, ElfMappingError> {
    start
        .checked_add(size)
        .ok_or_else(|| ElfMappingError::FunctionRangeOverflow {
            name: name.to_owned(),
        })
}

fn register_function_range(
    names_by_range: &mut BTreeMap<(u64, u64), String>,
    maximum_functions: usize,
    start: u64,
    end: u64,
    name: &str,
) -> Result<(), ElfMappingError> {
    if !names_by_range.contains_key(&(start, end)) && names_by_range.len() >= maximum_functions {
        return Err(ElfMappingError::TooManyFunctions {
            limit: maximum_functions,
        });
    }
    insert_alias_name(names_by_range, start, end, name);
    Ok(())
}

fn insert_alias_name(
    names_by_range: &mut BTreeMap<(u64, u64), String>,
    start: u64,
    end: u64,
    name: &str,
) {
    let entry = names_by_range
        .entry((start, end))
        .or_insert_with(|| name.to_owned());
    if name < entry.as_str() {
        entry.clone_from(&name.to_owned());
    }
}

fn scope_contains(scope: &ElfExecutableScope, start: u64, end: u64) -> bool {
    scope
        .ranges
        .iter()
        .any(|range| range.start <= start && end <= range.end)
}

fn scope_intersects(scope: &ElfExecutableScope, start: u64, end: u64) -> bool {
    scope
        .ranges
        .iter()
        .any(|range| start < range.end && range.start < end)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(ranges: &[(u64, u64)]) -> ElfExecutableScope {
        normalize_executable_scope(
            ranges
                .iter()
                .map(|&(start, end)| ElfExecutableRange { start, end })
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn scope_normalization_keeps_adjacent_boundaries_and_merges_overlaps() {
        assert_eq!(
            scope(&[(0x30, 0x40), (0x10, 0x20), (0x18, 0x28), (0x28, 0x30)]).ranges,
            vec![
                ElfExecutableRange {
                    start: 0x10,
                    end: 0x28,
                },
                ElfExecutableRange {
                    start: 0x28,
                    end: 0x30,
                },
                ElfExecutableRange {
                    start: 0x30,
                    end: 0x40,
                },
            ]
        );
    }

    #[test]
    fn normalized_ranges_choose_alias_name_and_reject_partial_overlap() {
        let mut aliases = BTreeMap::new();
        insert_alias_name(&mut aliases, 0x100, 0x110, "z_alias");
        insert_alias_name(&mut aliases, 0x100, 0x110, "a_alias");
        insert_alias_name(&mut aliases, 0x120, 0x130, "next");
        let ranges = normalize_function_ranges(aliases, "fw").unwrap();
        assert_eq!(ranges[0].display_name, "a_alias");
        assert!(
            ranges[0]
                .function_id
                .contains("0000000000000100-0000000000000110")
        );

        let mut overlap = BTreeMap::new();
        overlap.insert((0x100, 0x120), "first".to_owned());
        overlap.insert((0x110, 0x130), "second".to_owned());
        assert!(matches!(
            normalize_function_ranges(overlap, "fw"),
            Err(ElfMappingError::OverlappingFunctions { .. })
        ));
    }

    #[test]
    fn scope_membership_distinguishes_non_executable_and_cross_boundary() {
        let scope = scope(&[(0x100, 0x110), (0x110, 0x120)]);
        assert!(scope_contains(&scope, 0x100, 0x110));
        assert!(!scope_contains(&scope, 0x108, 0x118));
        assert!(scope_intersects(&scope, 0x108, 0x118));
        assert!(!scope_intersects(&scope, 0x200, 0x210));
    }

    #[test]
    fn arm_thumb_symbol_addresses_are_normalized_before_range_math() {
        assert_eq!(normalized_symbol_start(true, 0x101), 0x100);
        assert_eq!(normalized_symbol_start(true, 0x100), 0x100);
        assert_eq!(normalized_symbol_start(false, 0x101), 0x101);
    }

    #[test]
    fn function_range_overflow_and_limit_are_rejected() {
        assert!(matches!(
            function_end(u64::MAX, 1, "overflow"),
            Err(ElfMappingError::FunctionRangeOverflow { .. })
        ));

        let mut ranges = BTreeMap::new();
        register_function_range(&mut ranges, 1, 0x100, 0x110, "one").unwrap();
        assert!(matches!(
            register_function_range(&mut ranges, 1, 0x120, 0x130, "two"),
            Err(ElfMappingError::TooManyFunctions { limit: 1 })
        ));
    }

    #[test]
    fn empty_scope_and_text_bounds_are_rejected() {
        assert!(matches!(
            normalize_executable_scope(Vec::new()),
            Err(ElfMappingError::EmptyExecutableScope)
        ));
        assert!(matches!(
            validate_module("\u{1}"),
            Err(ElfMappingError::InvalidModule)
        ));
        assert!(matches!(
            validate_module(&"x".repeat(MAX_MODULE_TEXT_BYTES + 1)),
            Err(ElfMappingError::InvalidModule)
        ));
    }
}
