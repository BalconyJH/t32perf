//! Explicitly column-mapped, single-line CSV observation adapter.

use std::{collections::BTreeMap, collections::BTreeSet, io::BufRead, str};

use csv::{ByteRecord, ReaderBuilder};
use t32perf_model::{Observation, ObservationEvent, Properties, Quality, strict_json};
use thiserror::Error;

use crate::{
    AdapterError, AdapterRequest, BoundedLineReader, ClockDomainSpec, ClockError, InputError,
    InputErrorKind, InputLocation, LineLimits, LocatedLine, ObservationAdapter,
    ObservationOrderError, ObservationOrderValidator, ObservationSource, OrderedObservation,
    SourceDescriptor, SourceError, TimestampNormalizer,
};

/// Semantic fields that may be explicitly mapped to CSV columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CsvField {
    /// Raw timestamp tick.
    TimestampTicks,
    /// Source sequence number.
    SourceSequence,
    /// Optional cross-source order key.
    OrderKey,
    /// Event type discriminator.
    EventType,
    /// Core identifier.
    CoreId,
    /// Current context identifier.
    ContextId,
    /// Context switched out.
    PreviousContextId,
    /// Context switched in.
    NextContextId,
    /// Function identifier.
    FunctionId,
    /// Function activation identifier.
    FrameId,
    /// Interrupt identifier.
    InterruptId,
    /// Interrupt priority.
    Priority,
    /// Interrupt activation identifier.
    ActivationId,
    /// Raw address.
    Address,
    /// Sample weight in nanoseconds.
    WeightNs,
    /// Event or span name.
    Name,
    /// Synchronous span identifier.
    SpanId,
    /// Asynchronous correlation identifier.
    CorrelationId,
    /// Counter identifier.
    CounterId,
    /// Numeric counter value.
    Value,
    /// Trace-gap duration in nanoseconds.
    DurationNs,
    /// Switch or gap reason.
    Reason,
    /// Metadata key.
    MetadataKey,
    /// Metadata JSON value.
    MetadataValue,
}

/// Explicit semantic-to-column mapping for one CSV dialect.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CsvColumnMap {
    columns: BTreeMap<CsvField, String>,
    ignored_columns: BTreeSet<String>,
}

impl CsvColumnMap {
    /// Creates an empty mapping.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Maps one semantic field to an exact header name.
    pub fn insert(&mut self, field: CsvField, column: impl Into<String>) {
        self.columns.insert(field, column.into());
    }

    /// Explicitly permits an otherwise unused input column.
    pub fn ignore(&mut self, column: impl Into<String>) {
        self.ignored_columns.insert(column.into());
    }

    /// Returns the configured column for a semantic field.
    #[must_use]
    pub fn column(&self, field: CsvField) -> Option<&str> {
        self.columns.get(&field).map(String::as_str)
    }
}

/// Immutable configuration for an explicitly mapped CSV source.
#[derive(Debug, Clone)]
pub struct CsvAdapterConfig {
    /// Exact CSV column mapping.
    pub columns: CsvColumnMap,
    /// Raw timestamp clock domain.
    pub clock: ClockDomainSpec,
    /// Optional explicit raw timestamp origin.
    pub origin_ticks: Option<u64>,
    /// Session timestamp assigned to the origin.
    pub origin_ns: i64,
    /// Evidence quality assigned to decoded rows.
    pub quality: Quality,
    /// Physical-line and record limits, including the CSV header record.
    pub limits: LineLimits,
}

/// A mapped CSV parsing failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{kind} at byte {location_byte}, line {location_line}, record {location_record}")]
pub struct CsvAdapterError {
    /// Exact physical input position.
    pub location: InputLocation,
    /// Failure category.
    pub kind: CsvAdapterErrorKind,
    location_byte: u64,
    location_line: u64,
    location_record: u64,
}

impl CsvAdapterError {
    fn new(location: InputLocation, kind: CsvAdapterErrorKind) -> Self {
        Self {
            location,
            kind,
            location_byte: location.byte_offset,
            location_line: location.line,
            location_record: location.record,
        }
    }
}

impl From<InputError> for CsvAdapterError {
    fn from(error: InputError) -> Self {
        Self::new(error.location, CsvAdapterErrorKind::Input(error.kind))
    }
}

/// The category of a mapped CSV failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CsvAdapterErrorKind {
    /// Bounded physical-line input failed.
    #[error(transparent)]
    Input(InputErrorKind),
    /// A line is not valid UTF-8.
    #[error("invalid UTF-8")]
    InvalidUtf8,
    /// A single-line CSV record is malformed.
    #[error("invalid CSV record: {message}")]
    InvalidCsv {
        /// csv crate error text.
        message: String,
    },
    /// A data record has a different number of fields than the header.
    #[error("CSV record has {actual} fields; expected {expected}")]
    RecordWidth {
        /// Header field count.
        expected: usize,
        /// Data-record field count.
        actual: usize,
    },
    /// A required semantic field has no mapping.
    #[error("missing mapping for {field:?}")]
    MissingMapping {
        /// Unmapped semantic field.
        field: CsvField,
    },
    /// Two semantic fields map to the same header name.
    #[error("CSV column `{column}` is mapped more than once")]
    DuplicateMappedColumn {
        /// Duplicate mapped column.
        column: String,
    },
    /// A mapped or ignored column name is empty.
    #[error("CSV column names must be nonempty")]
    EmptyColumnName,
    /// The CSV header defines one name more than once.
    #[error("CSV header contains duplicate column `{column}`")]
    DuplicateHeaderColumn {
        /// Duplicate header name.
        column: String,
    },
    /// A mapped column is absent from the input header.
    #[error("mapped CSV column `{column}` is absent from the header")]
    MissingHeaderColumn {
        /// Missing column.
        column: String,
    },
    /// A header column was neither mapped nor explicitly ignored.
    #[error("CSV column `{column}` is not explicitly mapped or ignored")]
    UnmappedHeaderColumn {
        /// Unexpected column.
        column: String,
    },
    /// A required row value is empty.
    #[error("required CSV value for {field:?} is empty")]
    MissingValue {
        /// Missing semantic field.
        field: CsvField,
    },
    /// A row value cannot be converted to the declared semantic type.
    #[error("invalid value `{value}` for {field:?}")]
    InvalidValue {
        /// Semantic field.
        field: CsvField,
        /// Rejected text.
        value: String,
    },
    /// An event type is outside the explicitly supported canonical set.
    #[error("unsupported CSV event type `{value}`")]
    UnsupportedEventType {
        /// Rejected event type.
        value: String,
    },
    /// Timestamp normalization failed.
    #[error(transparent)]
    Clock(ClockError),
    /// Source sequence or timestamp order is invalid.
    #[error(transparent)]
    Ordering(ObservationOrderError),
    /// The decoded model observation violates a semantic invariant.
    #[error("invalid observation: {message}")]
    InvalidObservation {
        /// Model validation error.
        message: String,
    },
}

/// Pull-based source for an explicitly mapped CSV file.
pub struct ExplicitCsvSource<R> {
    descriptor: SourceDescriptor,
    lines: BoundedLineReader<R>,
    indices: BTreeMap<CsvField, usize>,
    normalizer: TimestampNormalizer,
    quality: Quality,
    order: ObservationOrderValidator,
    field_count: usize,
    finished: bool,
}

impl<R: BufRead> ExplicitCsvSource<R> {
    /// Reads and validates the CSV header without guessing any column.
    pub fn new(
        reader: R,
        source_id: impl Into<String>,
        config: CsvAdapterConfig,
    ) -> Result<Self, CsvAdapterError> {
        validate_column_map(&config.columns)?;
        let mut lines = BoundedLineReader::new(reader, config.limits)?;
        let header_line = lines.next_line()?.ok_or_else(|| {
            CsvAdapterError::new(
                InputLocation::new(0, 1, 0),
                CsvAdapterErrorKind::InvalidCsv {
                    message: "missing header record".to_owned(),
                },
            )
        })?;
        let header = parse_csv_record(&header_line)?;
        let indices = resolve_header(&header_line, &header, &config.columns)?;
        let normalizer =
            TimestampNormalizer::new(config.clock, config.origin_ticks, config.origin_ns).map_err(
                |error| {
                    CsvAdapterError::new(header_line.location, CsvAdapterErrorKind::Clock(error))
                },
            )?;
        let source_id = source_id.into();
        if source_id.is_empty() {
            return Err(CsvAdapterError::new(
                header_line.location,
                CsvAdapterErrorKind::InvalidCsv {
                    message: "source_id is empty".to_owned(),
                },
            ));
        }
        let descriptor = SourceDescriptor::new(&source_id, normalizer.domain_id());
        Ok(Self {
            descriptor,
            lines,
            indices,
            normalizer,
            quality: config.quality,
            order: ObservationOrderValidator::default(),
            field_count: header.len(),
            finished: false,
        })
    }

    fn read_next(&mut self) -> Result<Option<OrderedObservation>, CsvAdapterError> {
        let Some(line) = self.lines.next_line()? else {
            return Ok(None);
        };
        let record = parse_csv_record(&line)?;
        if record.len() != self.field_count {
            return Err(CsvAdapterError::new(
                line.location,
                CsvAdapterErrorKind::RecordWidth {
                    expected: self.field_count,
                    actual: record.len(),
                },
            ));
        }
        let raw_ticks = parse_u64(&line, &record, &self.indices, CsvField::TimestampTicks)?;
        let source_seq = parse_u64(&line, &record, &self.indices, CsvField::SourceSequence)?;
        let timestamp = self.normalizer.normalize(raw_ticks).map_err(|error| {
            CsvAdapterError::new(line.location, CsvAdapterErrorKind::Clock(error))
        })?;
        let event_type = required(&line, &record, &self.indices, CsvField::EventType)?;
        let event = build_event(&line, &record, &self.indices, timestamp, event_type)?;
        let observation = Observation::new(
            self.descriptor.source_id.clone(),
            source_seq,
            self.quality,
            event,
        );
        observation.validate().map_err(|error| {
            CsvAdapterError::new(
                line.location,
                CsvAdapterErrorKind::InvalidObservation {
                    message: error.to_string(),
                },
            )
        })?;
        self.order.observe(&observation).map_err(|error| {
            CsvAdapterError::new(line.location, CsvAdapterErrorKind::Ordering(error))
        })?;
        let order_key = optional(&record, &self.indices, CsvField::OrderKey)
            .map(|value| parse_text_u64(&line, CsvField::OrderKey, value))
            .transpose()?;
        Ok(Some(OrderedObservation {
            observation,
            order_key,
        }))
    }
}

impl<R: BufRead> ObservationSource for ExplicitCsvSource<R> {
    fn descriptor(&self) -> &SourceDescriptor {
        &self.descriptor
    }

    fn next_observation(&mut self) -> Result<Option<OrderedObservation>, SourceError> {
        if self.finished {
            return Ok(None);
        }
        match self.read_next() {
            Ok(Some(record)) => Ok(Some(record)),
            Ok(None) => {
                self.finished = true;
                Ok(None)
            }
            Err(error) => {
                self.finished = true;
                Err(error.into())
            }
        }
    }
}

/// Registry adapter with a fixed, explicit CSV mapping.
#[derive(Debug, Clone)]
pub struct ExplicitCsvAdapter {
    id: String,
    config: CsvAdapterConfig,
}

impl ExplicitCsvAdapter {
    /// Creates an explicitly mapped adapter.
    pub fn new(id: impl Into<String>, config: CsvAdapterConfig) -> Result<Self, AdapterError> {
        let id = id.into();
        if id.is_empty() {
            return Err(AdapterError::EmptyAdapterId);
        }
        validate_column_map(&config.columns).map_err(|error| {
            AdapterError::InvalidConfiguration {
                adapter: id.clone(),
                message: error.to_string(),
            }
        })?;
        Ok(Self { id, config })
    }
}

impl ObservationAdapter for ExplicitCsvAdapter {
    fn id(&self) -> &str {
        &self.id
    }

    fn open(
        &self,
        mut request: AdapterRequest,
    ) -> Result<Box<dyn ObservationSource + Send>, AdapterError> {
        request.reject_options(self.id())?;
        let input = request.take_input(self.id())?;
        let source = ExplicitCsvSource::new(input, request.source_id, self.config.clone())
            .map_err(SourceError::from)?;
        Ok(Box::new(source))
    }
}

fn validate_column_map(map: &CsvColumnMap) -> Result<(), CsvAdapterError> {
    let location = InputLocation::new(0, 1, 0);
    for required in [
        CsvField::TimestampTicks,
        CsvField::SourceSequence,
        CsvField::EventType,
    ] {
        if !map.columns.contains_key(&required) {
            return Err(CsvAdapterError::new(
                location,
                CsvAdapterErrorKind::MissingMapping { field: required },
            ));
        }
    }
    let mut names = BTreeSet::new();
    for name in map.columns.values().chain(&map.ignored_columns) {
        if name.is_empty() {
            return Err(CsvAdapterError::new(
                location,
                CsvAdapterErrorKind::EmptyColumnName,
            ));
        }
        if !names.insert(name) {
            return Err(CsvAdapterError::new(
                location,
                CsvAdapterErrorKind::DuplicateMappedColumn {
                    column: name.clone(),
                },
            ));
        }
    }
    Ok(())
}

fn resolve_header(
    line: &LocatedLine,
    header: &ByteRecord,
    map: &CsvColumnMap,
) -> Result<BTreeMap<CsvField, usize>, CsvAdapterError> {
    let mut header_indices = BTreeMap::new();
    for (index, raw) in header.iter().enumerate() {
        let name = str::from_utf8(raw).map_err(|error| {
            CsvAdapterError::new(
                InputLocation::new(
                    line.location.byte_offset + error.valid_up_to() as u64,
                    line.location.line,
                    line.location.record,
                ),
                CsvAdapterErrorKind::InvalidUtf8,
            )
        })?;
        if header_indices.insert(name.to_owned(), index).is_some() {
            return Err(CsvAdapterError::new(
                line.location,
                CsvAdapterErrorKind::DuplicateHeaderColumn {
                    column: name.to_owned(),
                },
            ));
        }
    }

    let mut indices = BTreeMap::new();
    for (field, column) in &map.columns {
        let index = header_indices.get(column).copied().ok_or_else(|| {
            CsvAdapterError::new(
                line.location,
                CsvAdapterErrorKind::MissingHeaderColumn {
                    column: column.clone(),
                },
            )
        })?;
        indices.insert(*field, index);
    }
    let mapped_names = map
        .columns
        .values()
        .chain(&map.ignored_columns)
        .collect::<BTreeSet<_>>();
    if let Some(column) = header_indices
        .keys()
        .find(|column| !mapped_names.contains(column))
    {
        return Err(CsvAdapterError::new(
            line.location,
            CsvAdapterErrorKind::UnmappedHeaderColumn {
                column: column.clone(),
            },
        ));
    }
    Ok(indices)
}

fn parse_csv_record(line: &LocatedLine) -> Result<ByteRecord, CsvAdapterError> {
    if let Err(error) = str::from_utf8(&line.bytes) {
        return Err(CsvAdapterError::new(
            InputLocation::new(
                line.location.byte_offset + error.valid_up_to() as u64,
                line.location.line,
                line.location.record,
            ),
            CsvAdapterErrorKind::InvalidUtf8,
        ));
    }
    let mut reader = ReaderBuilder::new()
        .has_headers(false)
        .flexible(false)
        .from_reader(line.bytes.as_slice());
    let mut records = reader.byte_records();
    let record = records
        .next()
        .ok_or_else(|| {
            CsvAdapterError::new(
                line.location,
                CsvAdapterErrorKind::InvalidCsv {
                    message: "empty CSV record".to_owned(),
                },
            )
        })?
        .map_err(|error| {
            CsvAdapterError::new(
                line.location,
                CsvAdapterErrorKind::InvalidCsv {
                    message: error.to_string(),
                },
            )
        })?;
    if records.next().is_some() {
        return Err(CsvAdapterError::new(
            line.location,
            CsvAdapterErrorKind::InvalidCsv {
                message: "one physical line produced multiple CSV records".to_owned(),
            },
        ));
    }
    Ok(record)
}

fn build_event(
    line: &LocatedLine,
    record: &ByteRecord,
    indices: &BTreeMap<CsvField, usize>,
    ts_ns: i64,
    event_type: &str,
) -> Result<ObservationEvent, CsvAdapterError> {
    let core = || parse_u32(line, record, indices, CsvField::CoreId);
    let context = || required(line, record, indices, CsvField::ContextId).map(str::to_owned);
    let optional_context = || optional(record, indices, CsvField::ContextId).map(str::to_owned);
    match event_type {
        "function_enter" | "function_exit" => {
            let event = (
                core()?,
                context()?,
                required(line, record, indices, CsvField::FunctionId)?.to_owned(),
                optional(record, indices, CsvField::FrameId).map(str::to_owned),
            );
            if event_type == "function_enter" {
                Ok(ObservationEvent::FunctionEnter {
                    ts_ns,
                    core_id: event.0,
                    context_id: event.1,
                    function_id: event.2,
                    frame_id: event.3,
                })
            } else {
                Ok(ObservationEvent::FunctionExit {
                    ts_ns,
                    core_id: event.0,
                    context_id: event.1,
                    function_id: event.2,
                    frame_id: event.3,
                })
            }
        }
        "context_switch" => Ok(ObservationEvent::ContextSwitch {
            ts_ns,
            core_id: core()?,
            prev_context_id: optional(record, indices, CsvField::PreviousContextId)
                .map(str::to_owned),
            next_context_id: required(line, record, indices, CsvField::NextContextId)?.to_owned(),
            reason: optional(record, indices, CsvField::Reason).map(str::to_owned),
        }),
        "interrupt_enter" | "interrupt_exit" => {
            let priority = optional(record, indices, CsvField::Priority)
                .map(|value| parse_text_i32(line, CsvField::Priority, value))
                .transpose()?;
            let interrupt_id = required(line, record, indices, CsvField::InterruptId)?.to_owned();
            let activation_id = required(line, record, indices, CsvField::ActivationId)?.to_owned();
            if event_type == "interrupt_enter" {
                Ok(ObservationEvent::InterruptEnter {
                    ts_ns,
                    core_id: core()?,
                    interrupt_id,
                    priority,
                    activation_id,
                })
            } else {
                Ok(ObservationEvent::InterruptExit {
                    ts_ns,
                    core_id: core()?,
                    interrupt_id,
                    priority,
                    activation_id,
                })
            }
        }
        "sample" => Ok(ObservationEvent::Sample {
            ts_ns,
            core_id: core()?,
            context_id: optional_context(),
            function_id: optional(record, indices, CsvField::FunctionId).map(str::to_owned),
            address: optional(record, indices, CsvField::Address)
                .map(|value| parse_text_address(line, CsvField::Address, value))
                .transpose()?,
            weight_ns: optional(record, indices, CsvField::WeightNs)
                .map(|value| parse_text_u64(line, CsvField::WeightNs, value))
                .transpose()?,
        }),
        "instant" => Ok(ObservationEvent::Instant {
            ts_ns,
            core_id: optional(record, indices, CsvField::CoreId)
                .map(|value| parse_text_u32(line, CsvField::CoreId, value))
                .transpose()?,
            context_id: optional_context(),
            name: required(line, record, indices, CsvField::Name)?.to_owned(),
            args: Properties::new(),
        }),
        "span_begin" => Ok(ObservationEvent::SpanBegin {
            ts_ns,
            core_id: optional(record, indices, CsvField::CoreId)
                .map(|value| parse_text_u32(line, CsvField::CoreId, value))
                .transpose()?,
            context_id: optional_context(),
            span_id: required(line, record, indices, CsvField::SpanId)?.to_owned(),
            name: required(line, record, indices, CsvField::Name)?.to_owned(),
            args: Properties::new(),
        }),
        "span_end" => Ok(ObservationEvent::SpanEnd {
            ts_ns,
            core_id: optional(record, indices, CsvField::CoreId)
                .map(|value| parse_text_u32(line, CsvField::CoreId, value))
                .transpose()?,
            context_id: optional_context(),
            span_id: required(line, record, indices, CsvField::SpanId)?.to_owned(),
            args: Properties::new(),
        }),
        "async_begin" => Ok(ObservationEvent::AsyncBegin {
            ts_ns,
            core_id: optional(record, indices, CsvField::CoreId)
                .map(|value| parse_text_u32(line, CsvField::CoreId, value))
                .transpose()?,
            context_id: optional_context(),
            correlation_id: required(line, record, indices, CsvField::CorrelationId)?.to_owned(),
            name: required(line, record, indices, CsvField::Name)?.to_owned(),
            args: Properties::new(),
        }),
        "async_end" => Ok(ObservationEvent::AsyncEnd {
            ts_ns,
            core_id: optional(record, indices, CsvField::CoreId)
                .map(|value| parse_text_u32(line, CsvField::CoreId, value))
                .transpose()?,
            context_id: optional_context(),
            correlation_id: required(line, record, indices, CsvField::CorrelationId)?.to_owned(),
            args: Properties::new(),
        }),
        "counter" => Ok(ObservationEvent::Counter {
            ts_ns,
            core_id: optional(record, indices, CsvField::CoreId)
                .map(|value| parse_text_u32(line, CsvField::CoreId, value))
                .transpose()?,
            context_id: optional_context(),
            counter_id: required(line, record, indices, CsvField::CounterId)?.to_owned(),
            value: parse_f64(line, record, indices, CsvField::Value)?,
            args: Properties::new(),
        }),
        "trace_gap" => Ok(ObservationEvent::TraceGap {
            ts_ns,
            duration_ns: parse_u64(line, record, indices, CsvField::DurationNs)?,
            reason: required(line, record, indices, CsvField::Reason)?.to_owned(),
        }),
        "metadata" => {
            let value_text = required(line, record, indices, CsvField::MetadataValue)?;
            let value = strict_json::from_str(value_text).map_err(|_| {
                CsvAdapterError::new(
                    line.location,
                    CsvAdapterErrorKind::InvalidValue {
                        field: CsvField::MetadataValue,
                        value: value_text.to_owned(),
                    },
                )
            })?;
            Ok(ObservationEvent::Metadata {
                ts_ns,
                key: required(line, record, indices, CsvField::MetadataKey)?.to_owned(),
                value,
            })
        }
        value => Err(CsvAdapterError::new(
            line.location,
            CsvAdapterErrorKind::UnsupportedEventType {
                value: value.to_owned(),
            },
        )),
    }
}

fn required<'a>(
    line: &LocatedLine,
    record: &'a ByteRecord,
    indices: &BTreeMap<CsvField, usize>,
    field: CsvField,
) -> Result<&'a str, CsvAdapterError> {
    let index = indices.get(&field).copied().ok_or_else(|| {
        CsvAdapterError::new(line.location, CsvAdapterErrorKind::MissingMapping { field })
    })?;
    let raw = record.get(index).unwrap_or_default();
    let value = str::from_utf8(raw)
        .map_err(|_| CsvAdapterError::new(line.location, CsvAdapterErrorKind::InvalidUtf8))?;
    if value.is_empty() {
        return Err(CsvAdapterError::new(
            line.location,
            CsvAdapterErrorKind::MissingValue { field },
        ));
    }
    Ok(value)
}

fn optional<'a>(
    record: &'a ByteRecord,
    indices: &BTreeMap<CsvField, usize>,
    field: CsvField,
) -> Option<&'a str> {
    let raw = record.get(*indices.get(&field)?)?;
    let value = str::from_utf8(raw).ok()?;
    (!value.is_empty()).then_some(value)
}

fn parse_u64(
    line: &LocatedLine,
    record: &ByteRecord,
    indices: &BTreeMap<CsvField, usize>,
    field: CsvField,
) -> Result<u64, CsvAdapterError> {
    parse_text_u64(line, field, required(line, record, indices, field)?)
}

fn parse_u32(
    line: &LocatedLine,
    record: &ByteRecord,
    indices: &BTreeMap<CsvField, usize>,
    field: CsvField,
) -> Result<u32, CsvAdapterError> {
    parse_text_u32(line, field, required(line, record, indices, field)?)
}

fn parse_f64(
    line: &LocatedLine,
    record: &ByteRecord,
    indices: &BTreeMap<CsvField, usize>,
    field: CsvField,
) -> Result<f64, CsvAdapterError> {
    let value = required(line, record, indices, field)?;
    value.parse().map_err(|_| invalid_value(line, field, value))
}

fn parse_text_u64(
    line: &LocatedLine,
    field: CsvField,
    value: &str,
) -> Result<u64, CsvAdapterError> {
    value.parse().map_err(|_| invalid_value(line, field, value))
}

fn parse_text_u32(
    line: &LocatedLine,
    field: CsvField,
    value: &str,
) -> Result<u32, CsvAdapterError> {
    value.parse().map_err(|_| invalid_value(line, field, value))
}

fn parse_text_i32(
    line: &LocatedLine,
    field: CsvField,
    value: &str,
) -> Result<i32, CsvAdapterError> {
    value.parse().map_err(|_| invalid_value(line, field, value))
}

fn parse_text_address(
    line: &LocatedLine,
    field: CsvField,
    value: &str,
) -> Result<u64, CsvAdapterError> {
    let result = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(|| value.parse(), |digits| u64::from_str_radix(digits, 16));
    result.map_err(|_| invalid_value(line, field, value))
}

fn invalid_value(line: &LocatedLine, field: CsvField, value: &str) -> CsvAdapterError {
    CsvAdapterError::new(
        line.location,
        CsvAdapterErrorKind::InvalidValue {
            field,
            value: value.to_owned(),
        },
    )
}
