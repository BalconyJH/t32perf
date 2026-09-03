//! Canonical header, dictionary, and observation NDJSON transport.

use std::{collections::BTreeSet, io::BufRead, io::Write};

use serde::Serialize;
use serde_json::Value;
use t32perf_model::{
    DictionaryEntry, OBSERVATION_SCHEMA, Observation, ObservationDictionary, ObservationEncoding,
    ObservationStreamHeader, strict_json, validate_schema_version,
};
use thiserror::Error;

use crate::{
    AdapterError, AdapterRequest, BoundedLineReader, InputError, InputErrorKind, InputLocation,
    LineLimits, LocatedLine, ObservationAdapter, ObservationOrderError, ObservationOrderValidator,
    ObservationSource, OrderedObservation, SourceDescriptor, SourceError,
};

/// Registry ID for canonical T32Perf observation NDJSON.
pub const CANONICAL_NDJSON_ADAPTER_ID: &str = "t32perf-observation-ndjson";

/// A canonical observation-NDJSON failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{kind} at byte {location_byte}, line {location_line}, record {location_record}")]
pub struct NdjsonError {
    /// Exact input or output position.
    pub location: InputLocation,
    /// Failure category.
    pub kind: NdjsonErrorKind,
    location_byte: u64,
    location_line: u64,
    location_record: u64,
}

impl NdjsonError {
    fn new(location: InputLocation, kind: NdjsonErrorKind) -> Self {
        Self {
            location,
            kind,
            location_byte: location.byte_offset,
            location_line: location.line,
            location_record: location.record,
        }
    }

    fn at_byte(line: &LocatedLine, relative: usize, kind: NdjsonErrorKind) -> Self {
        Self::new(
            InputLocation::new(
                line.location.byte_offset + relative as u64,
                line.location.line,
                line.location.record,
            ),
            kind,
        )
    }
}

impl From<InputError> for NdjsonError {
    fn from(error: InputError) -> Self {
        Self::new(error.location, NdjsonErrorKind::Input(error.kind))
    }
}

/// The category of a canonical observation-NDJSON failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NdjsonErrorKind {
    /// Physical-line input failed.
    #[error(transparent)]
    Input(InputErrorKind),
    /// Bytes are not valid UTF-8.
    #[error("invalid UTF-8")]
    InvalidUtf8,
    /// JSON syntax or data conversion failed.
    #[error("invalid JSON: {message}")]
    InvalidJson {
        /// serde_json error text.
        message: String,
    },
    /// A strict record contained an unknown top-level field.
    #[error("unknown field `{field}`")]
    UnknownField {
        /// Rejected field name.
        field: String,
    },
    /// The schema family or major version is unsupported.
    #[error("unsupported schema: {message}")]
    UnsupportedSchema {
        /// Schema validation error.
        message: String,
    },
    /// A required stream metadata record is missing.
    #[error("missing {expected} record")]
    MissingRecord {
        /// Expected record kind.
        expected: &'static str,
    },
    /// The first stream record is not canonical NDJSON metadata.
    #[error("stream header does not declare NDJSON encoding")]
    InvalidEncoding,
    /// Header and dictionary sessions differ.
    #[error("dictionary session `{actual}` does not match header session `{expected}`")]
    SessionMismatch {
        /// Header session.
        expected: String,
        /// Dictionary session.
        actual: String,
    },
    /// A dictionary definition appeared after the observation stream began.
    #[error("dictionary entry `{entry_type}` appears after the first observation")]
    DictionaryAfterObservation {
        /// Rejected dictionary entry type.
        entry_type: String,
    },
    /// Dictionary semantic validation failed.
    #[error("invalid dictionary: {message}")]
    InvalidDictionary {
        /// Dictionary validation error.
        message: String,
    },
    /// More dictionary definitions were present than allowed.
    #[error("dictionary entry count exceeds {limit}")]
    DictionaryEntryLimitExceeded {
        /// Configured maximum dictionary definition count.
        limit: u64,
    },
    /// Dictionary physical bytes exceeded their independent bound.
    #[error("dictionary physical bytes exceed {limit}")]
    DictionaryByteLimitExceeded {
        /// Configured maximum dictionary bytes, including LF delimiters.
        limit: u64,
    },
    /// Observation semantic validation failed.
    #[error("invalid observation: {message}")]
    InvalidObservation {
        /// Observation validation error.
        message: String,
    },
    /// Observation order is invalid.
    #[error(transparent)]
    Ordering(ObservationOrderError),
    /// Serialization failed before writing a record.
    #[error("JSON serialization failed: {message}")]
    Serialization {
        /// Serialization error.
        message: String,
    },
    /// Writing or flushing failed.
    #[error("I/O error: {message}")]
    Io {
        /// I/O error text.
        message: String,
    },
}

/// Streaming reader for canonical T32Perf observation NDJSON.
pub struct NdjsonObservationReader<R> {
    lines: BoundedLineReader<R>,
    header: ObservationStreamHeader,
    dictionary: ObservationDictionary,
    dictionary_physical_bytes: u64,
    order: ObservationOrderValidator,
    pending_observation: Option<Observation>,
    finished: bool,
}

impl<R: BufRead> NdjsonObservationReader<R> {
    /// Reads and validates the mandatory header and dictionary records.
    pub fn new(reader: R, limits: LineLimits) -> Result<Self, NdjsonError> {
        let mut lines = BoundedLineReader::new(reader, limits)?;
        let header_line = lines.next_line()?.ok_or_else(|| {
            NdjsonError::new(
                InputLocation::new(0, 1, 0),
                NdjsonErrorKind::MissingRecord { expected: "header" },
            )
        })?;
        let header = parse_header(&header_line)?;
        if header.encoding != ObservationEncoding::Ndjson {
            return Err(NdjsonError::new(
                header_line.location,
                NdjsonErrorKind::InvalidEncoding,
            ));
        }

        let mut dictionary = ObservationDictionary::new(&header.session_id);
        let mut dictionary_ids = DictionaryIdValidator::default();
        let mut dictionary_entries = 0_u64;
        let mut dictionary_bytes = 0_u64;
        let mut order = ObservationOrderValidator::default();
        let mut pending_observation = None;
        while let Some(line) = lines.next_line()? {
            let value = parse_json_value(&line)?;
            if dictionary_entry_type(&value).is_some() {
                if dictionary_entries >= limits.max_dictionary_entries {
                    return Err(NdjsonError::new(
                        line.location,
                        NdjsonErrorKind::DictionaryEntryLimitExceeded {
                            limit: limits.max_dictionary_entries,
                        },
                    ));
                }
                let physical_bytes = u64::try_from(line.bytes.len())
                    .unwrap_or(u64::MAX)
                    .saturating_add(1);
                let remaining = limits.max_dictionary_bytes.saturating_sub(dictionary_bytes);
                if physical_bytes > remaining {
                    let relative = usize::try_from(remaining)
                        .unwrap_or(usize::MAX)
                        .min(line.bytes.len());
                    return Err(NdjsonError::at_byte(
                        &line,
                        relative,
                        NdjsonErrorKind::DictionaryByteLimitExceeded {
                            limit: limits.max_dictionary_bytes,
                        },
                    ));
                }
                dictionary_entries += 1;
                dictionary_bytes += physical_bytes;
                let entry = parse_dictionary_entry(&line, value)?;
                dictionary_ids.observe(&entry, &line)?;
                dictionary.entries.push(entry);
                continue;
            }
            let observation = parse_observation(&line, value)?;
            validate_observation(&line, &observation, &mut order)?;
            pending_observation = Some(observation);
            break;
        }
        dictionary.validate().map_err(|error| {
            NdjsonError::new(
                header_line.location,
                NdjsonErrorKind::InvalidDictionary {
                    message: error.to_string(),
                },
            )
        })?;

        Ok(Self {
            lines,
            header,
            dictionary,
            dictionary_physical_bytes: dictionary_bytes,
            order,
            pending_observation,
            finished: false,
        })
    }

    /// Returns the validated stream header.
    #[must_use]
    pub fn header(&self) -> &ObservationStreamHeader {
        &self.header
    }

    /// Returns the validated stream dictionary.
    #[must_use]
    pub fn dictionary(&self) -> &ObservationDictionary {
        &self.dictionary
    }

    /// Returns physical bytes occupied by dictionary records, including LF.
    #[must_use]
    pub const fn dictionary_physical_bytes(&self) -> u64 {
        self.dictionary_physical_bytes
    }
}

impl<R: BufRead> Iterator for NdjsonObservationReader<R> {
    type Item = Result<Observation, NdjsonError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        if let Some(observation) = self.pending_observation.take() {
            return Some(Ok(observation));
        }
        let line = match self.lines.next_line() {
            Ok(Some(line)) => line,
            Ok(None) => {
                self.finished = true;
                return None;
            }
            Err(error) => {
                self.finished = true;
                return Some(Err(error.into()));
            }
        };
        let value = match parse_json_value(&line) {
            Ok(value) => value,
            Err(error) => {
                self.finished = true;
                return Some(Err(error));
            }
        };
        if let Some(entry_type) = dictionary_entry_type(&value) {
            self.finished = true;
            return Some(Err(NdjsonError::new(
                line.location,
                NdjsonErrorKind::DictionaryAfterObservation {
                    entry_type: entry_type.to_owned(),
                },
            )));
        }
        let observation = match parse_observation(&line, value) {
            Ok(observation) => observation,
            Err(error) => {
                self.finished = true;
                return Some(Err(error));
            }
        };
        if let Err(error) = validate_observation(&line, &observation, &mut self.order) {
            self.finished = true;
            return Some(Err(error));
        }
        Some(Ok(observation))
    }
}

/// Streaming writer for canonical T32Perf observation NDJSON.
pub struct NdjsonObservationWriter<W> {
    writer: W,
    limits: LineLimits,
    byte_offset: u64,
    line: u64,
    record: u64,
    dictionary_entries: u64,
    dictionary_bytes: u64,
    order: ObservationOrderValidator,
}

impl<W: Write> NdjsonObservationWriter<W> {
    /// Writes a validated header and dictionary.
    pub fn new(
        writer: W,
        header: &ObservationStreamHeader,
        dictionary: &ObservationDictionary,
        limits: LineLimits,
    ) -> Result<Self, NdjsonError> {
        if let Err(kind) = limits.validate() {
            return Err(NdjsonError::new(
                InputLocation::new(0, 1, 0),
                NdjsonErrorKind::Input(kind),
            ));
        }
        if header.encoding != ObservationEncoding::Ndjson {
            return Err(NdjsonError::new(
                InputLocation::new(0, 1, 0),
                NdjsonErrorKind::InvalidEncoding,
            ));
        }
        if dictionary.session_id != header.session_id {
            return Err(NdjsonError::new(
                InputLocation::new(0, 1, 0),
                NdjsonErrorKind::SessionMismatch {
                    expected: header.session_id.clone(),
                    actual: dictionary.session_id.clone(),
                },
            ));
        }
        dictionary.validate().map_err(|error| {
            NdjsonError::new(
                InputLocation::new(0, 1, 0),
                NdjsonErrorKind::InvalidDictionary {
                    message: error.to_string(),
                },
            )
        })?;
        let mut result = Self {
            writer,
            limits,
            byte_offset: 0,
            line: 1,
            record: 0,
            dictionary_entries: 0,
            dictionary_bytes: 0,
            order: ObservationOrderValidator::default(),
        };
        result.write_record(header)?;
        for entry in &dictionary.entries {
            result.write_dictionary_record(entry)?;
        }
        Ok(result)
    }

    /// Writes one validated, globally sorted observation.
    pub fn write_observation(&mut self, observation: &Observation) -> Result<(), NdjsonError> {
        observation.validate().map_err(|error| {
            NdjsonError::new(
                self.location(),
                NdjsonErrorKind::InvalidObservation {
                    message: error.to_string(),
                },
            )
        })?;
        self.order
            .observe(observation)
            .map_err(|error| NdjsonError::new(self.location(), NdjsonErrorKind::Ordering(error)))?;
        self.write_record(observation)
    }

    /// Flushes the writer and returns it.
    pub fn finish(mut self) -> Result<W, NdjsonError> {
        self.writer.flush().map_err(|error| {
            NdjsonError::new(
                self.location(),
                NdjsonErrorKind::Io {
                    message: error.to_string(),
                },
            )
        })?;
        Ok(self.writer)
    }

    fn location(&self) -> InputLocation {
        InputLocation::new(self.byte_offset, self.line, self.record)
    }

    fn write_record<T: Serialize>(&mut self, value: &T) -> Result<(), NdjsonError> {
        let bytes = serde_json::to_vec(value).map_err(|error| {
            NdjsonError::new(
                self.location(),
                NdjsonErrorKind::Serialization {
                    message: error.to_string(),
                },
            )
        })?;
        self.write_serialized(&bytes)
    }

    fn write_dictionary_record<T: Serialize>(&mut self, value: &T) -> Result<(), NdjsonError> {
        if self.dictionary_entries >= self.limits.max_dictionary_entries {
            return Err(NdjsonError::new(
                self.location(),
                NdjsonErrorKind::DictionaryEntryLimitExceeded {
                    limit: self.limits.max_dictionary_entries,
                },
            ));
        }
        let bytes = serde_json::to_vec(value).map_err(|error| {
            NdjsonError::new(
                self.location(),
                NdjsonErrorKind::Serialization {
                    message: error.to_string(),
                },
            )
        })?;
        let physical_bytes = u64::try_from(bytes.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let remaining = self
            .limits
            .max_dictionary_bytes
            .saturating_sub(self.dictionary_bytes);
        if physical_bytes > remaining {
            return Err(NdjsonError::new(
                InputLocation::new(
                    self.byte_offset + remaining.min(bytes.len() as u64),
                    self.line,
                    self.record,
                ),
                NdjsonErrorKind::DictionaryByteLimitExceeded {
                    limit: self.limits.max_dictionary_bytes,
                },
            ));
        }
        self.write_serialized(&bytes)?;
        self.dictionary_entries += 1;
        self.dictionary_bytes += physical_bytes;
        Ok(())
    }

    fn write_serialized(&mut self, bytes: &[u8]) -> Result<(), NdjsonError> {
        if self.record >= self.limits.max_records {
            return Err(NdjsonError::new(
                self.location(),
                NdjsonErrorKind::Input(InputErrorKind::RecordLimitExceeded {
                    limit: self.limits.max_records,
                }),
            ));
        }
        if bytes.len() > self.limits.max_line_bytes {
            return Err(NdjsonError::new(
                InputLocation::new(
                    self.byte_offset + self.limits.max_line_bytes as u64,
                    self.line,
                    self.record,
                ),
                NdjsonErrorKind::Input(InputErrorKind::LineTooLong {
                    limit: self.limits.max_line_bytes,
                }),
            ));
        }
        self.writer.write_all(bytes).map_err(|error| {
            NdjsonError::new(
                self.location(),
                NdjsonErrorKind::Io {
                    message: error.to_string(),
                },
            )
        })?;
        self.writer.write_all(b"\n").map_err(|error| {
            NdjsonError::new(
                InputLocation::new(
                    self.byte_offset + bytes.len() as u64,
                    self.line,
                    self.record,
                ),
                NdjsonErrorKind::Io {
                    message: error.to_string(),
                },
            )
        })?;
        self.byte_offset += bytes.len() as u64 + 1;
        self.line += 1;
        self.record += 1;
        Ok(())
    }
}

/// Observation-source wrapper for canonical NDJSON.
pub struct CanonicalNdjsonSource {
    descriptor: SourceDescriptor,
    reader: NdjsonObservationReader<Box<dyn BufRead + Send>>,
}

impl CanonicalNdjsonSource {
    /// Opens a canonical NDJSON source while retaining access to its validated metadata.
    pub fn new(
        reader: impl BufRead + Send + 'static,
        source_id: impl Into<String>,
        limits: LineLimits,
    ) -> Result<Self, NdjsonError> {
        let reader =
            NdjsonObservationReader::new(Box::new(reader) as Box<dyn BufRead + Send>, limits)?;
        Ok(Self {
            descriptor: SourceDescriptor::new(source_id, "session"),
            reader,
        })
    }

    /// Returns the validated canonical stream header.
    #[must_use]
    pub fn header(&self) -> &ObservationStreamHeader {
        self.reader.header()
    }
}

impl ObservationSource for CanonicalNdjsonSource {
    fn descriptor(&self) -> &SourceDescriptor {
        &self.descriptor
    }

    fn dictionary(&self) -> Option<&ObservationDictionary> {
        Some(self.reader.dictionary())
    }

    fn next_observation(&mut self) -> Result<Option<OrderedObservation>, SourceError> {
        self.reader
            .next()
            .transpose()
            .map(|value| value.map(OrderedObservation::unordered))
            .map_err(Into::into)
    }
}

/// Adapter for canonical T32Perf observation NDJSON.
#[derive(Debug, Clone, Copy)]
pub struct CanonicalNdjsonAdapter {
    limits: LineLimits,
}

impl CanonicalNdjsonAdapter {
    /// Creates an adapter with explicit streaming limits.
    #[must_use]
    pub fn new(limits: LineLimits) -> Self {
        Self { limits }
    }
}

impl Default for CanonicalNdjsonAdapter {
    fn default() -> Self {
        Self::new(LineLimits::default())
    }
}

impl ObservationAdapter for CanonicalNdjsonAdapter {
    fn id(&self) -> &str {
        CANONICAL_NDJSON_ADAPTER_ID
    }

    fn open(
        &self,
        mut request: AdapterRequest,
    ) -> Result<Box<dyn ObservationSource + Send>, AdapterError> {
        request.reject_options(self.id())?;
        let input = request.take_input(self.id())?;
        let source = CanonicalNdjsonSource::new(input, request.source_id, self.limits)
            .map_err(SourceError::from)
            .map_err(AdapterError::from)?;
        if source.header().session_id != request.session_id {
            return Err(AdapterError::InvalidConfiguration {
                adapter: self.id().to_owned(),
                message: format!(
                    "stream session `{}` does not match request session `{}`",
                    source.header().session_id,
                    request.session_id
                ),
            });
        }
        Ok(Box::new(source))
    }
}

fn parse_header(line: &LocatedLine) -> Result<ObservationStreamHeader, NdjsonError> {
    let value = parse_json_value(line)?;
    reject_unknown_fields(
        line,
        &value,
        &[
            "schema",
            "session_id",
            "encoding",
            "time_unit",
            "time_origin",
            "properties",
        ],
    )?;
    validate_schema(line, &value, OBSERVATION_SCHEMA)?;
    deserialize_value(line, value)
}

fn parse_dictionary_entry(
    line: &LocatedLine,
    value: Value,
) -> Result<DictionaryEntry, NdjsonError> {
    let allowed = match dictionary_entry_type(&value) {
        Some("DefineContext") => &["type", "id", "kind", "name", "core_id", "priority"][..],
        Some("DefineFunction") => &["type", "id", "name", "module", "address", "file", "line"][..],
        Some("DefineCounter") => &[
            "type",
            "id",
            "name",
            "unit",
            "description",
            "semantic",
            "subject",
        ][..],
        _ => &["type"][..],
    };
    reject_unknown_fields(line, &value, allowed)?;
    deserialize_value(line, value)
}

fn parse_observation(line: &LocatedLine, value: Value) -> Result<Observation, NdjsonError> {
    let event_type = value.get("type").and_then(Value::as_str);
    let event_fields: &[&str] = match event_type {
        Some("FunctionEnter") | Some("FunctionExit") => {
            &["ts_ns", "core_id", "context_id", "function_id", "frame_id"]
        }
        Some("ContextSwitch") => &[
            "ts_ns",
            "core_id",
            "prev_context_id",
            "next_context_id",
            "reason",
        ],
        Some("InterruptEnter") | Some("InterruptExit") => &[
            "ts_ns",
            "core_id",
            "interrupt_id",
            "priority",
            "activation_id",
        ],
        Some("Sample") => &[
            "ts_ns",
            "core_id",
            "context_id",
            "function_id",
            "address",
            "weight_ns",
        ],
        Some("Instant") => &["ts_ns", "core_id", "context_id", "name", "args"],
        Some("SpanBegin") => &["ts_ns", "core_id", "context_id", "span_id", "name", "args"],
        Some("SpanEnd") => &["ts_ns", "core_id", "context_id", "span_id", "args"],
        Some("AsyncBegin") => &[
            "ts_ns",
            "core_id",
            "context_id",
            "correlation_id",
            "name",
            "args",
        ],
        Some("AsyncEnd") => &["ts_ns", "core_id", "context_id", "correlation_id", "args"],
        Some("Counter") => &[
            "ts_ns",
            "core_id",
            "context_id",
            "counter_id",
            "value",
            "args",
        ],
        Some("TraceGap") => &["ts_ns", "duration_ns", "reason"],
        Some("Metadata") => &["ts_ns", "key", "value"],
        _ => &[],
    };
    let mut allowed = BTreeSet::from(["source_id", "source_seq", "quality", "type"]);
    allowed.extend(event_fields.iter().copied());
    reject_unknown_field_set(line, &value, &allowed)?;
    deserialize_value(line, value)
}

fn dictionary_entry_type(value: &Value) -> Option<&str> {
    match value.get("type").and_then(Value::as_str) {
        Some(entry_type @ ("DefineContext" | "DefineFunction" | "DefineCounter")) => {
            Some(entry_type)
        }
        _ => None,
    }
}

fn validate_observation(
    line: &LocatedLine,
    observation: &Observation,
    order: &mut ObservationOrderValidator,
) -> Result<(), NdjsonError> {
    observation.validate().map_err(|error| {
        NdjsonError::new(
            line.location,
            NdjsonErrorKind::InvalidObservation {
                message: error.to_string(),
            },
        )
    })?;
    order
        .observe(observation)
        .map_err(|error| NdjsonError::new(line.location, NdjsonErrorKind::Ordering(error)))
}

#[derive(Debug, Default)]
struct DictionaryIdValidator {
    contexts: BTreeSet<String>,
    functions: BTreeSet<String>,
    counters: BTreeSet<String>,
}

impl DictionaryIdValidator {
    fn observe(&mut self, entry: &DictionaryEntry, line: &LocatedLine) -> Result<(), NdjsonError> {
        let (namespace, id, ids) = match entry {
            DictionaryEntry::DefineContext { id, .. } => ("context", id, &mut self.contexts),
            DictionaryEntry::DefineFunction { id, .. } => ("function", id, &mut self.functions),
            DictionaryEntry::DefineCounter { id, .. } => ("counter", id, &mut self.counters),
        };
        let message = if id.is_empty() {
            Some(format!("{namespace} dictionary entry has an empty id"))
        } else if !ids.insert(id.clone()) {
            Some(format!(
                "{namespace} dictionary contains duplicate id `{id}`"
            ))
        } else {
            None
        };
        match message {
            Some(message) => Err(NdjsonError::new(
                line.location,
                NdjsonErrorKind::InvalidDictionary { message },
            )),
            None => Ok(()),
        }
    }
}

fn parse_json_value(line: &LocatedLine) -> Result<Value, NdjsonError> {
    if let Err(error) = std::str::from_utf8(&line.bytes) {
        return Err(NdjsonError::at_byte(
            line,
            error.valid_up_to(),
            NdjsonErrorKind::InvalidUtf8,
        ));
    }
    strict_json::value_from_slice(&line.bytes).map_err(|error| {
        NdjsonError::at_byte(
            line,
            error.column().saturating_sub(1),
            NdjsonErrorKind::InvalidJson {
                message: error.to_string(),
            },
        )
    })
}

fn deserialize_value<T: serde::de::DeserializeOwned>(
    line: &LocatedLine,
    value: Value,
) -> Result<T, NdjsonError> {
    match serde_json::from_value(value) {
        Ok(value) => Ok(value),
        Err(_) => serde_json::from_slice(&line.bytes).map_err(|error| {
            NdjsonError::at_byte(
                line,
                error.column().saturating_sub(1),
                NdjsonErrorKind::InvalidJson {
                    message: error.to_string(),
                },
            )
        }),
    }
}

fn validate_schema(
    line: &LocatedLine,
    value: &Value,
    expected: &'static str,
) -> Result<(), NdjsonError> {
    let actual = value
        .get("schema")
        .and_then(Value::as_str)
        .unwrap_or("<missing-or-non-string>");
    validate_schema_version(actual, expected).map_err(|error| {
        NdjsonError::at_byte(
            line,
            find_json_key(&line.bytes, "schema").unwrap_or(0),
            NdjsonErrorKind::UnsupportedSchema {
                message: error.to_string(),
            },
        )
    })
}

fn reject_unknown_fields(
    line: &LocatedLine,
    value: &Value,
    allowed: &[&str],
) -> Result<(), NdjsonError> {
    reject_unknown_field_set(line, value, &allowed.iter().copied().collect())
}

fn reject_unknown_field_set(
    line: &LocatedLine,
    value: &Value,
    allowed: &BTreeSet<&str>,
) -> Result<(), NdjsonError> {
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(field.as_str()))
    {
        return Err(NdjsonError::at_byte(
            line,
            find_json_key(&line.bytes, field).unwrap_or(0),
            NdjsonErrorKind::UnknownField {
                field: field.clone(),
            },
        ));
    }
    Ok(())
}

fn find_json_key(bytes: &[u8], key: &str) -> Option<usize> {
    let needle = serde_json::to_vec(key).ok()?;
    bytes
        .windows(needle.len())
        .position(|window| window == needle)
}
