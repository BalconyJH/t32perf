//! Streaming parser and bounded aggregate report for GCC `-fstack-usage` artifacts.

use std::{borrow::Cow, fmt, io::BufRead, marker::PhantomData, str};

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as _, SeqAccess, Visitor},
};
use thiserror::Error;

use crate::{LineLimits, ResourceTextError, ResourceTextLine, ResourceTextReader};

/// Exact host-input flavor supported by the GCC stack-usage parser.
pub const GCC_STACK_USAGE_V1_FLAVOR: &str = "gcc-stack-usage-v1";
/// Schema identifier emitted by GCC stack-usage reports.
pub const GCC_STACK_USAGE_V1_SCHEMA: &str = "t32perf.stack-usage/gcc-stack-usage-v1";
/// Public JSON Schema identifier for stack-usage reports.
pub const STACK_USAGE_REPORT_SCHEMA: &str = "t32perf.stack-usage-report/v1";
/// Maximum function entries retained in one aggregate stack-usage report.
pub const MAX_STACK_USAGE_REPORT_ENTRIES: usize = 100_000;
/// Maximum aggregate bytes retained across file and function strings.
pub const MAX_STACK_USAGE_REPORT_TEXT_BYTES: usize = 64 * 1024 * 1024;
/// Maximum UTF-8 bytes retained in one file or function field.
pub const MAX_STACK_USAGE_FIELD_BYTES: usize = 4_096;

/// Schema marker for a stack report parsed from `gcc-stack-usage-v1`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum StackUsageReportSchema {
    /// Strict GCC `-fstack-usage` v1 subset.
    #[default]
    GccStackUsageV1,
}

impl Serialize for StackUsageReportSchema {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(GCC_STACK_USAGE_V1_SCHEMA)
    }
}

impl<'de> Deserialize<'de> for StackUsageReportSchema {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value == GCC_STACK_USAGE_V1_SCHEMA {
            Ok(Self::GccStackUsageV1)
        } else {
            Err(D::Error::custom(format!(
                "unsupported stack usage report schema `{value}`"
            )))
        }
    }
}

impl JsonSchema for StackUsageReportSchema {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("StackUsageReportSchema")
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "const": GCC_STACK_USAGE_V1_SCHEMA
        })
    }
}

/// GCC stack-usage qualifier semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum StackUsageKind {
    /// Fixed frame size; no dynamic stack adjustment occurs in the function.
    #[serde(rename = "static")]
    Static,
    /// Dynamic adjustment has no compile-time upper bound; bytes cover only the bounded part.
    #[serde(rename = "dynamic")]
    Dynamic,
    /// Dynamic adjustment is compile-time bounded; bytes are an upper bound of total usage.
    #[serde(rename = "dynamic,bounded")]
    DynamicBounded,
}

/// One GCC `.su` function entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StackUsageEntry {
    /// Source file recorded by GCC.
    #[schemars(length(min = 1, max = 4096))]
    pub file: String,
    /// Source line recorded by GCC.
    pub line: u32,
    /// Source column recorded by GCC.
    pub column: u32,
    /// GCC function spelling, including any signature or qualification.
    #[schemars(length(min = 1, max = 4096))]
    pub function: String,
    /// Stack bytes with semantics determined by [`StackUsageEntry::kind`].
    pub bytes: u64,
    /// Static, dynamic, or bounded-dynamic semantics.
    pub kind: StackUsageKind,
    /// One-based `.su` artifact line containing this entry.
    #[schemars(range(min = 1))]
    pub artifact_line: u64,
}

/// Aggregate GCC stack-usage report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StackUsageReport {
    /// Versioned report schema.
    pub schema: StackUsageReportSchema,
    /// Largest byte count among entries qualified exactly as `static`.
    pub maximum_static_bytes: Option<u64>,
    /// Function table in artifact order.
    #[schemars(length(max = 100000))]
    pub functions: Vec<StackUsageEntry>,
}

impl<'de> Deserialize<'de> for StackUsageReport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            schema: StackUsageReportSchema,
            maximum_static_bytes: Option<u64>,
            #[serde(deserialize_with = "deserialize_stack_usage_entries")]
            functions: Vec<StackUsageEntry>,
        }

        let fields = Fields::deserialize(deserializer)?;
        let calculated_maximum =
            validate_stack_usage_entries(&fields.functions).map_err(D::Error::custom)?;
        if fields.maximum_static_bytes != calculated_maximum {
            return Err(D::Error::custom(format!(
                "maximum_static_bytes {:?} does not match calculated value {calculated_maximum:?}",
                fields.maximum_static_bytes
            )));
        }
        Ok(Self {
            schema: fields.schema,
            maximum_static_bytes: calculated_maximum,
            functions: fields.functions,
        })
    }
}

fn deserialize_stack_usage_entries<'de, D>(
    deserializer: D,
) -> Result<Vec<StackUsageEntry>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedEntries(PhantomData<StackUsageEntry>);

    impl<'de> Visitor<'de> for BoundedEntries {
        type Value = Vec<StackUsageEntry>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {MAX_STACK_USAGE_REPORT_ENTRIES} stack-usage entries"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let capacity = sequence
                .size_hint()
                .unwrap_or(0)
                .min(MAX_STACK_USAGE_REPORT_ENTRIES);
            let mut entries = Vec::with_capacity(capacity);
            while let Some(entry) = sequence.next_element()? {
                if entries.len() == MAX_STACK_USAGE_REPORT_ENTRIES {
                    return Err(A::Error::custom(format!(
                        "stack usage report exceeds {MAX_STACK_USAGE_REPORT_ENTRIES} entries"
                    )));
                }
                entries.push(entry);
            }
            Ok(entries)
        }
    }

    deserializer.deserialize_seq(BoundedEntries(PhantomData))
}

fn validate_stack_usage_entries(entries: &[StackUsageEntry]) -> Result<Option<u64>, String> {
    let mut previous_artifact_line = 0_u64;
    let mut total_text_bytes = 0_usize;
    let mut maximum_static_bytes = None;
    for entry in entries {
        validate_stack_usage_text("file", &entry.file).map_err(|error| error.to_string())?;
        validate_stack_usage_text("function", &entry.function)
            .map_err(|error| error.to_string())?;
        if entry.artifact_line == 0 || entry.artifact_line <= previous_artifact_line {
            return Err(format!(
                "stack usage artifact lines must be nonzero and strictly increasing; found {} after {previous_artifact_line}",
                entry.artifact_line
            ));
        }
        previous_artifact_line = entry.artifact_line;
        total_text_bytes = total_text_bytes
            .checked_add(entry.file.len())
            .and_then(|total| total.checked_add(entry.function.len()))
            .ok_or_else(|| "stack usage text byte total overflows usize".to_owned())?;
        if total_text_bytes > MAX_STACK_USAGE_REPORT_TEXT_BYTES {
            return Err(format!(
                "stack usage report text exceeds {MAX_STACK_USAGE_REPORT_TEXT_BYTES} bytes"
            ));
        }
        if entry.kind == StackUsageKind::Static {
            maximum_static_bytes = Some(
                maximum_static_bytes.map_or(entry.bytes, |maximum: u64| maximum.max(entry.bytes)),
            );
        }
    }
    Ok(maximum_static_bytes)
}

/// A strict GCC stack-usage input or aggregation failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StackUsageError {
    /// The caller requested an unimplemented compiler stack-usage flavor.
    #[error("UNSUPPORTED: stack usage input flavor `{flavor}` is not supported")]
    UnsupportedFlavor {
        /// Rejected flavor identifier.
        flavor: String,
    },
    /// The aggregate report reached its hard function-entry ceiling.
    #[error("stack usage report exceeds {maximum} function entries")]
    FunctionLimitExceeded {
        /// Supported function-entry ceiling.
        maximum: usize,
    },
    /// Aggregate retained source/function text reached its hard byte ceiling.
    #[error("stack usage report text exceeds {maximum} bytes")]
    TextLimitExceeded {
        /// Supported aggregate text ceiling.
        maximum: usize,
    },
    /// A retained source or function field is empty, too large, or contains controls.
    #[error("invalid {field} text at line {line}; maximum is {maximum} bytes")]
    InvalidText {
        /// Rejected field name.
        field: &'static str,
        /// One-based artifact line.
        line: u64,
        /// Supported UTF-8 byte ceiling.
        maximum: usize,
    },
    /// Bounded platform-text input failed.
    #[error(transparent)]
    Input(#[from] ResourceTextError),
    /// One `.su` record is not valid UTF-8.
    #[error("invalid UTF-8 at byte {byte_offset}, line {line}")]
    InvalidUtf8 {
        /// Zero-based byte offset.
        byte_offset: u64,
        /// One-based artifact line.
        line: u64,
    },
    /// A nonempty record does not contain exactly three tab-separated fields.
    #[error("malformed GCC stack-usage record at line {line}; expected three tab-separated fields")]
    MalformedRecord {
        /// One-based artifact line.
        line: u64,
    },
    /// GCC source location does not use `file:line:column:function`.
    #[error("malformed GCC source/function field `{value}` at line {line}")]
    MalformedLocation {
        /// Rejected field.
        value: String,
        /// One-based artifact line.
        line: u64,
    },
    /// More than one `:line:column:` boundary can be interpreted safely.
    #[error("ambiguous GCC source/function field `{value}` at line {line}")]
    AmbiguousLocation {
        /// Ambiguous field.
        value: String,
        /// One-based artifact line.
        line: u64,
    },
    /// A line, column, or byte-count field is not a bounded decimal integer.
    #[error("invalid {field} `{value}` in GCC stack-usage record at line {line}")]
    InvalidInteger {
        /// Field name.
        field: &'static str,
        /// Rejected token.
        value: String,
        /// One-based artifact line.
        line: u64,
    },
    /// Qualifiers are outside `static`, `dynamic`, or `dynamic,bounded`.
    #[error("unsupported GCC stack-usage qualifier `{qualifier}` at line {line}")]
    UnsupportedQualifier {
        /// Rejected qualifier text.
        qualifier: String,
        /// One-based artifact line.
        line: u64,
    },
}

/// Pull-based streaming reader for exact `gcc-stack-usage-v1` records.
pub struct GccStackUsageReader<R> {
    lines: ResourceTextReader<R>,
    finished: bool,
}

impl<R: BufRead> GccStackUsageReader<R> {
    /// Creates a reader with explicit physical-line and record limits.
    pub fn new(reader: R, limits: LineLimits) -> Result<Self, StackUsageError> {
        Ok(Self {
            lines: ResourceTextReader::new(reader, limits)?,
            finished: false,
        })
    }

    /// Reads the next nonempty function entry, or `None` at clean EOF.
    pub fn next_entry(&mut self) -> Result<Option<StackUsageEntry>, StackUsageError> {
        if self.finished {
            return Ok(None);
        }
        loop {
            let line = match self.lines.next_line() {
                Ok(Some(line)) => line,
                Ok(None) => {
                    self.finished = true;
                    return Ok(None);
                }
                Err(error) => {
                    self.finished = true;
                    return Err(error.into());
                }
            };
            if line.bytes.is_empty() {
                continue;
            }
            match parse_stack_usage_entry(&line) {
                Ok(entry) => return Ok(Some(entry)),
                Err(error) => {
                    self.finished = true;
                    return Err(error);
                }
            }
        }
    }
}

impl<R: BufRead> Iterator for GccStackUsageReader<R> {
    type Item = Result<StackUsageEntry, StackUsageError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_entry().transpose()
    }
}

/// Dispatches a versioned compiler stack-usage parser and aggregates its table.
///
/// Only [`GCC_STACK_USAGE_V1_FLAVOR`] is accepted; other compiler and GCC dump
/// variants must provide a separate, explicitly validated adapter.
pub fn parse_stack_usage_report<R: BufRead>(
    flavor: &str,
    reader: R,
    limits: LineLimits,
) -> Result<StackUsageReport, StackUsageError> {
    if flavor != GCC_STACK_USAGE_V1_FLAVOR {
        return Err(StackUsageError::UnsupportedFlavor {
            flavor: flavor.to_owned(),
        });
    }
    parse_gcc_stack_usage_v1(reader, limits)
}

/// Parses and aggregates exact `gcc-stack-usage-v1` records.
pub fn parse_gcc_stack_usage_v1<R: BufRead>(
    reader: R,
    limits: LineLimits,
) -> Result<StackUsageReport, StackUsageError> {
    let mut functions = Vec::new();
    let mut maximum_static_bytes = None;
    let mut total_text_bytes = 0_usize;
    for entry in GccStackUsageReader::new(reader, limits)? {
        let entry = entry?;
        if functions.len() == MAX_STACK_USAGE_REPORT_ENTRIES {
            return Err(StackUsageError::FunctionLimitExceeded {
                maximum: MAX_STACK_USAGE_REPORT_ENTRIES,
            });
        }
        total_text_bytes = total_text_bytes
            .checked_add(entry.file.len())
            .and_then(|total| total.checked_add(entry.function.len()))
            .ok_or(StackUsageError::TextLimitExceeded {
                maximum: MAX_STACK_USAGE_REPORT_TEXT_BYTES,
            })?;
        if total_text_bytes > MAX_STACK_USAGE_REPORT_TEXT_BYTES {
            return Err(StackUsageError::TextLimitExceeded {
                maximum: MAX_STACK_USAGE_REPORT_TEXT_BYTES,
            });
        }
        if entry.kind == StackUsageKind::Static {
            maximum_static_bytes = Some(
                maximum_static_bytes.map_or(entry.bytes, |maximum: u64| maximum.max(entry.bytes)),
            );
        }
        functions.push(entry);
    }
    Ok(StackUsageReport {
        schema: StackUsageReportSchema::GccStackUsageV1,
        maximum_static_bytes,
        functions,
    })
}

fn parse_stack_usage_entry(line: &ResourceTextLine) -> Result<StackUsageEntry, StackUsageError> {
    let text = str::from_utf8(&line.bytes).map_err(|error| StackUsageError::InvalidUtf8 {
        byte_offset: line.location.byte_offset + error.valid_up_to() as u64,
        line: line.location.line,
    })?;
    let fields = text.split('\t').collect::<Vec<_>>();
    let [location_and_function, bytes_text, qualifier] = fields.as_slice() else {
        return Err(StackUsageError::MalformedRecord {
            line: line.location.line,
        });
    };
    let (file, source_line, column, function) =
        parse_location(location_and_function, line.location.line)?;
    validate_stack_usage_text("file", &file).map_err(|_| StackUsageError::InvalidText {
        field: "file",
        line: line.location.line,
        maximum: MAX_STACK_USAGE_FIELD_BYTES,
    })?;
    validate_stack_usage_text("function", &function).map_err(|_| StackUsageError::InvalidText {
        field: "function",
        line: line.location.line,
        maximum: MAX_STACK_USAGE_FIELD_BYTES,
    })?;
    let bytes = parse_decimal_u64(bytes_text).ok_or_else(|| StackUsageError::InvalidInteger {
        field: "bytes",
        value: (*bytes_text).to_owned(),
        line: line.location.line,
    })?;
    let kind = match *qualifier {
        "static" => StackUsageKind::Static,
        "dynamic" => StackUsageKind::Dynamic,
        "dynamic,bounded" => StackUsageKind::DynamicBounded,
        _ => {
            return Err(StackUsageError::UnsupportedQualifier {
                qualifier: (*qualifier).to_owned(),
                line: line.location.line,
            });
        }
    };
    Ok(StackUsageEntry {
        file,
        line: source_line,
        column,
        function,
        bytes,
        kind,
        artifact_line: line.location.line,
    })
}

fn parse_location(
    value: &str,
    artifact_line: u64,
) -> Result<(String, u32, u32, String), StackUsageError> {
    let bytes = value.as_bytes();
    let mut candidates = Vec::new();
    for first in bytes
        .iter()
        .enumerate()
        .filter_map(|(index, byte)| (*byte == b':').then_some(index))
    {
        let Some(second_relative) = bytes[first + 1..].iter().position(|byte| *byte == b':') else {
            continue;
        };
        let second = first + 1 + second_relative;
        let Some(third_relative) = bytes[second + 1..].iter().position(|byte| *byte == b':') else {
            continue;
        };
        let third = second + 1 + third_relative;
        let line_text = &value[first + 1..second];
        let column_text = &value[second + 1..third];
        if !line_text.is_empty()
            && !column_text.is_empty()
            && line_text.bytes().all(|byte| byte.is_ascii_digit())
            && column_text.bytes().all(|byte| byte.is_ascii_digit())
            && first != 0
            && third + 1 < value.len()
        {
            candidates.push((first, second, third));
        }
    }
    let (first, second, third) = match candidates.as_slice() {
        [] => {
            return Err(StackUsageError::MalformedLocation {
                value: value.to_owned(),
                line: artifact_line,
            });
        }
        [candidate] => *candidate,
        _ => {
            return Err(StackUsageError::AmbiguousLocation {
                value: value.to_owned(),
                line: artifact_line,
            });
        }
    };
    let line_text = &value[first + 1..second];
    let column_text = &value[second + 1..third];
    let source_line = line_text
        .parse()
        .map_err(|_| StackUsageError::InvalidInteger {
            field: "source line",
            value: line_text.to_owned(),
            line: artifact_line,
        })?;
    let column = column_text
        .parse()
        .map_err(|_| StackUsageError::InvalidInteger {
            field: "source column",
            value: column_text.to_owned(),
            line: artifact_line,
        })?;
    Ok((
        value[..first].to_owned(),
        source_line,
        column,
        value[third + 1..].to_owned(),
    ))
}

fn parse_decimal_u64(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn validate_stack_usage_text(field: &'static str, value: &str) -> Result<(), &'static str> {
    if value.is_empty()
        || value.len() > MAX_STACK_USAGE_FIELD_BYTES
        || value.chars().any(char::is_control)
    {
        Err(field)
    } else {
        Ok(())
    }
}
