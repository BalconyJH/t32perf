//! Decoder and normalized source for the T32Perf C SDK wire format.

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{ErrorKind, Read},
    marker::PhantomData,
};

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema, schema_for};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as _, SeqAccess, Visitor},
};
use serde_json::{Value, json};
use t32perf_model::{
    ContextKind, CounterSemantic, CounterSubject, DictionaryEntry, Observation,
    ObservationDictionary, ObservationEvent, Properties, Quality, StackRole, strict_json,
};
use thiserror::Error;

use crate::{
    ClockDomainSpec, ClockError, ObservationSource, OrderedObservation, SourceDescriptor,
    SourceError, TimestampNormalizer,
};

/// Size of the fixed T32Perf C SDK wire header.
pub const C_WIRE_HEADER_SIZE: usize = 32;
/// Current T32Perf C SDK wire version.
pub const C_WIRE_VERSION: u8 = 1;
/// Default maximum payload emitted by the checked-in C SDK.
pub const C_WIRE_DEFAULT_MAX_PAYLOAD: usize = 256;
/// Wire flag indicating transport loss before the current record.
pub const C_WIRE_FLAG_DROPPED_SINCE_LAST: u16 = 0x0001;
/// Schema identity for a versioned C SDK counter mapping document.
pub const C_WIRE_COUNTER_MAPPING_SCHEMA: &str = "t32perf.c-wire-counter-mapping/v1";
/// Maximum counter mappings accepted from one deployment-owned document.
pub const MAX_C_WIRE_COUNTER_MAPPINGS: usize = 65_536;
/// Maximum context definitions accepted from one deployment-owned document.
pub const MAX_C_WIRE_CONTEXT_MAPPINGS: usize = 65_536;
/// Maximum bytes retained by one counter identifier, name, unit, or description.
pub const MAX_C_WIRE_COUNTER_TEXT_BYTES: usize = 4_096;
/// Maximum UTF-8 bytes accepted for a complete C SDK counter mapping document.
pub const MAX_C_WIRE_COUNTER_MAPPING_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;

/// Exact schema marker for a C SDK counter mapping document.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CWireCounterMappingSchema {
    /// The closed v1 counter mapping contract.
    #[default]
    V1,
}

impl Serialize for CWireCounterMappingSchema {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(C_WIRE_COUNTER_MAPPING_SCHEMA)
    }
}

impl<'de> Deserialize<'de> for CWireCounterMappingSchema {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value == C_WIRE_COUNTER_MAPPING_SCHEMA {
            Ok(Self::V1)
        } else {
            Err(D::Error::custom(format!(
                "unsupported C SDK counter mapping schema `{value}`"
            )))
        }
    }
}

impl JsonSchema for CWireCounterMappingSchema {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("CWireCounterMappingSchema")
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({"type": "string", "const": C_WIRE_COUNTER_MAPPING_SCHEMA})
    }
}

/// One immutable mapping from a C SDK event identifier to a resource counter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CWireCounterMapping {
    /// Exact C SDK `event_id` carried by Counter records.
    pub event_id: u32,
    /// Stable normalized counter identifier.
    #[schemars(length(min = 1, max = 4096))]
    pub counter_id: String,
    /// Human-readable counter name.
    #[schemars(length(min = 1, max = 4096))]
    pub name: String,
    /// Unit required by the counter semantic.
    #[schemars(length(min = 1, max = 4096))]
    pub unit: String,
    /// Stable description of the counter source and meaning.
    #[schemars(length(min = 1, max = 4096))]
    pub description: String,
    /// Explicit semantic of the measured resource value.
    pub semantic: CounterSemantic,
    /// Explicit identity of the measured resource.
    pub subject: CounterSubject,
}

impl CWireCounterMapping {
    fn dictionary_entry(&self) -> DictionaryEntry {
        DictionaryEntry::DefineCounter {
            id: self.counter_id.clone(),
            name: self.name.clone(),
            unit: Some(self.unit.clone()),
            description: Some(self.description.clone()),
            semantic: Some(self.semantic.clone()),
            subject: Some(self.subject.clone()),
        }
    }
}

/// One closed mapping from a numeric C SDK context identifier to a dictionary context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CWireContextMapping {
    /// Exact C SDK `context_id` carried by wire records.
    pub wire_context_id: u32,
    /// Stable normalized dictionary context identifier.
    #[schemars(length(min = 1, max = 4096))]
    pub context_id: String,
    /// Human-readable context name.
    #[schemars(length(min = 1, max = 4096))]
    pub name: String,
    /// Closed context kind accepted by C SDK stack counters.
    pub kind: CWireContextKind,
    /// Core affinity when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_id: Option<u32>,
    /// Scheduling or interrupt priority when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
}

impl CWireContextMapping {
    fn dictionary_entry(&self) -> DictionaryEntry {
        DictionaryEntry::DefineContext {
            id: self.context_id.clone(),
            kind: self.kind.into(),
            name: self.name.clone(),
            core_id: self.core_id,
            priority: self.priority,
        }
    }
}

/// Closed kind of a context defined by a C SDK counter mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CWireContextKind {
    /// An RTOS task context.
    Task,
    /// An interrupt-service-routine context.
    Isr,
}

impl From<CWireContextKind> for ContextKind {
    fn from(value: CWireContextKind) -> Self {
        match value {
            CWireContextKind::Task => Self::Task,
            CWireContextKind::Isr => Self::Isr,
        }
    }
}

/// Deployment-owned, closed mapping for C SDK Counter event identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CWireCounterMappingDocument {
    /// Exact mapping document schema.
    pub schema: CWireCounterMappingSchema,
    /// Closed C SDK context definitions used by Task and ISR stack counters.
    #[serde(default)]
    #[schemars(length(max = 65536))]
    pub contexts: Vec<CWireContextMapping>,
    /// Counter definitions in deployment-defined order.
    #[schemars(length(min = 1, max = 65536))]
    pub counters: Vec<CWireCounterMapping>,
}

impl<'de> Deserialize<'de> for CWireCounterMappingDocument {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            schema: CWireCounterMappingSchema,
            #[serde(default, deserialize_with = "deserialize_c_wire_context_mappings")]
            contexts: Vec<CWireContextMapping>,
            #[serde(deserialize_with = "deserialize_c_wire_counter_mappings")]
            counters: Vec<CWireCounterMapping>,
        }

        let fields = Fields::deserialize(deserializer)?;
        let document = Self {
            schema: fields.schema,
            contexts: fields.contexts,
            counters: fields.counters,
        };
        document.validate().map_err(D::Error::custom)?;
        Ok(document)
    }
}

impl CWireCounterMappingDocument {
    /// Validates the closed mapping and its derived observation dictionary.
    pub fn validate(&self) -> Result<(), CWireCounterMappingError> {
        if self.counters.is_empty() {
            return Err(CWireCounterMappingError::Empty);
        }
        if self.counters.len() > MAX_C_WIRE_COUNTER_MAPPINGS {
            return Err(CWireCounterMappingError::TooManyMappings {
                limit: MAX_C_WIRE_COUNTER_MAPPINGS,
                actual: self.counters.len(),
            });
        }
        let mut event_ids = BTreeSet::new();
        let mut counter_ids = BTreeSet::new();
        let mut wire_context_ids = BTreeSet::new();
        let mut context_ids = BTreeSet::new();
        if self.contexts.len() > MAX_C_WIRE_CONTEXT_MAPPINGS {
            return Err(CWireCounterMappingError::TooManyContexts {
                limit: MAX_C_WIRE_CONTEXT_MAPPINGS,
                actual: self.contexts.len(),
            });
        }
        for context in &self.contexts {
            if !wire_context_ids.insert(context.wire_context_id) {
                return Err(CWireCounterMappingError::DuplicateWireContextId {
                    context_id: context.wire_context_id,
                });
            }
            if !context_ids.insert(context.context_id.as_str()) {
                return Err(CWireCounterMappingError::DuplicateContextId {
                    context_id: context.context_id.clone(),
                });
            }
            validate_counter_mapping_text("context_id", &context.context_id)?;
            validate_counter_mapping_text("context_name", &context.name)?;
        }
        for counter in &self.counters {
            if !event_ids.insert(counter.event_id) {
                return Err(CWireCounterMappingError::DuplicateEventId {
                    event_id: counter.event_id,
                });
            }
            if !counter_ids.insert(counter.counter_id.as_str()) {
                return Err(CWireCounterMappingError::DuplicateCounterId {
                    counter_id: counter.counter_id.clone(),
                });
            }
            for (field, value) in [
                ("counter_id", counter.counter_id.as_str()),
                ("name", counter.name.as_str()),
                ("unit", counter.unit.as_str()),
                ("description", counter.description.as_str()),
            ] {
                validate_counter_mapping_text(field, value)?;
            }
            if let CounterSubject::Stack {
                role: StackRole::Task | StackRole::Isr,
                context_id: Some(context_id),
                ..
            } = &counter.subject
            {
                let expected = match &counter.subject {
                    CounterSubject::Stack {
                        role: StackRole::Task,
                        ..
                    } => CWireContextKind::Task,
                    CounterSubject::Stack {
                        role: StackRole::Isr,
                        ..
                    } => CWireContextKind::Isr,
                    _ => unreachable!("matched Task or ISR stack counter subject"),
                };
                let Some(context) = self
                    .contexts
                    .iter()
                    .find(|context| context.context_id == *context_id)
                else {
                    return Err(CWireCounterMappingError::MissingStackContext {
                        counter_id: counter.counter_id.clone(),
                        context_id: context_id.clone(),
                    });
                };
                if context.kind != expected {
                    return Err(CWireCounterMappingError::StackContextKindMismatch {
                        counter_id: counter.counter_id.clone(),
                        context_id: context_id.clone(),
                        expected,
                    });
                }
            }
        }
        self.dictionary("counter-mapping-validation")
            .map(|_| ())
            .map_err(CWireCounterMappingError::InvalidDictionary)
    }

    /// Builds the validated dictionary associated with one normalized session.
    pub fn dictionary(
        &self,
        session_id: impl Into<String>,
    ) -> Result<ObservationDictionary, t32perf_model::DictionaryValidationError> {
        let mut dictionary = ObservationDictionary::new(session_id);
        dictionary.entries = self
            .contexts
            .iter()
            .map(CWireContextMapping::dictionary_entry)
            .chain(
                self.counters
                    .iter()
                    .map(CWireCounterMapping::dictionary_entry),
            )
            .collect();
        dictionary.validate()?;
        Ok(dictionary)
    }

    fn mapped_counters(&self) -> BTreeMap<u32, MappedCounter> {
        let contexts = self
            .contexts
            .iter()
            .map(|context| (context.context_id.as_str(), context))
            .collect::<BTreeMap<_, _>>();
        self.counters
            .iter()
            .map(|counter| {
                let required_wire_context_id = match &counter.subject {
                    CounterSubject::Stack {
                        role: StackRole::Task | StackRole::Isr,
                        context_id: Some(context_id),
                        ..
                    } => Some(
                        contexts
                            .get(context_id.as_str())
                            .expect("validated stack context mapping")
                            .wire_context_id,
                    ),
                    _ => None,
                };
                (
                    counter.event_id,
                    MappedCounter {
                        counter_id: counter.counter_id.clone(),
                        required_wire_context_id,
                    },
                )
            })
            .collect()
    }

    fn mapped_contexts(&self) -> BTreeMap<u32, String> {
        self.contexts
            .iter()
            .map(|context| (context.wire_context_id, context.context_id.clone()))
            .collect()
    }

    fn validate_core_affinity(&self, source_core_id: u32) -> Result<(), CWireCounterMappingError> {
        for context in &self.contexts {
            if let Some(context_core_id) = context.core_id
                && context_core_id != source_core_id
            {
                return Err(CWireCounterMappingError::ContextCoreMismatch {
                    context_id: context.context_id.clone(),
                    context_core_id,
                    source_core_id,
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct MappedCounter {
    counter_id: String,
    required_wire_context_id: Option<u32>,
}

struct MappedWireContract {
    counters: BTreeMap<u32, MappedCounter>,
    contexts: BTreeMap<u32, String>,
    dictionary: ObservationDictionary,
}

fn deserialize_c_wire_counter_mappings<'de, D>(
    deserializer: D,
) -> Result<Vec<CWireCounterMapping>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedMappings(PhantomData<CWireCounterMapping>);

    impl<'de> Visitor<'de> for BoundedMappings {
        type Value = Vec<CWireCounterMapping>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {MAX_C_WIRE_COUNTER_MAPPINGS} C SDK counter mappings"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut mappings = Vec::new();
            while let Some(mapping) = sequence.next_element()? {
                if mappings.len() == MAX_C_WIRE_COUNTER_MAPPINGS {
                    return Err(A::Error::custom(format!(
                        "C SDK counter mapping count exceeds {MAX_C_WIRE_COUNTER_MAPPINGS}"
                    )));
                }
                mappings.push(mapping);
            }
            Ok(mappings)
        }
    }

    deserializer.deserialize_seq(BoundedMappings(PhantomData))
}

fn deserialize_c_wire_context_mappings<'de, D>(
    deserializer: D,
) -> Result<Vec<CWireContextMapping>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_mapping_sequence(deserializer, "context", MAX_C_WIRE_CONTEXT_MAPPINGS)
}

fn deserialize_bounded_mapping_sequence<'de, D, T>(
    deserializer: D,
    name: &'static str,
    limit: usize,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedMappings<T> {
        name: &'static str,
        limit: usize,
        marker: PhantomData<T>,
    }

    impl<'de, T> Visitor<'de> for BoundedMappings<T>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {} C SDK {} mappings",
                self.limit, self.name
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut mappings = Vec::new();
            while let Some(mapping) = sequence.next_element()? {
                if mappings.len() == self.limit {
                    return Err(A::Error::custom(format!(
                        "C SDK {} mapping count exceeds {}",
                        self.name, self.limit
                    )));
                }
                mappings.push(mapping);
            }
            Ok(mappings)
        }
    }

    deserializer.deserialize_seq(BoundedMappings {
        name,
        limit,
        marker: PhantomData,
    })
}

fn validate_counter_mapping_text(
    field: &'static str,
    value: &str,
) -> Result<(), CWireCounterMappingError> {
    if value.trim().is_empty() || value.len() > MAX_C_WIRE_COUNTER_TEXT_BYTES {
        return Err(CWireCounterMappingError::InvalidText {
            field,
            length: value.len(),
        });
    }
    Ok(())
}

/// C SDK counter mapping validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CWireCounterMappingError {
    /// The mapping contains no counter definitions.
    #[error("C SDK counter mapping is empty")]
    Empty,
    /// The mapping exceeded its bounded entry count.
    #[error("C SDK counter mapping count {actual} exceeds {limit}")]
    TooManyMappings {
        /// Maximum admitted mappings.
        limit: usize,
        /// Rejected mapping count.
        actual: usize,
    },
    /// The context mapping exceeded its bounded entry count.
    #[error("C SDK context mapping count {actual} exceeds {limit}")]
    TooManyContexts {
        /// Maximum admitted mappings.
        limit: usize,
        /// Rejected mapping count.
        actual: usize,
    },
    /// One C SDK event ID was declared more than once.
    #[error("duplicate C SDK counter event_id {event_id}")]
    DuplicateEventId {
        /// Repeated wire event ID.
        event_id: u32,
    },
    /// One stable counter ID was declared more than once.
    #[error("duplicate C SDK counter_id `{counter_id}`")]
    DuplicateCounterId {
        /// Repeated normalized counter identity.
        counter_id: String,
    },
    /// One wire context ID was declared more than once.
    #[error("duplicate C SDK wire context_id {context_id}")]
    DuplicateWireContextId {
        /// Repeated wire context ID.
        context_id: u32,
    },
    /// One normalized context ID was declared more than once.
    #[error("duplicate C SDK context_id `{context_id}`")]
    DuplicateContextId {
        /// Repeated normalized context ID.
        context_id: String,
    },
    /// A Task or ISR stack counter names no declared C SDK context.
    #[error("C SDK counter `{counter_id}` stack context `{context_id}` is missing")]
    MissingStackContext {
        /// Counter identity.
        counter_id: String,
        /// Missing normalized context identity.
        context_id: String,
    },
    /// A Task or ISR stack counter names a context with the wrong kind.
    #[error(
        "C SDK counter `{counter_id}` stack context `{context_id}` does not have kind {expected:?}"
    )]
    StackContextKindMismatch {
        /// Counter identity.
        counter_id: String,
        /// Referenced normalized context identity.
        context_id: String,
        /// Required context kind.
        expected: CWireContextKind,
    },
    /// A mapped context has a core affinity incompatible with the source.
    #[error(
        "C SDK context `{context_id}` core {context_core_id} does not match source core {source_core_id}"
    )]
    ContextCoreMismatch {
        /// Normalized context identity.
        context_id: String,
        /// Context core affinity.
        context_core_id: u32,
        /// Configured source core.
        source_core_id: u32,
    },
    /// A required text field is empty or too large.
    #[error("C SDK counter {field} has invalid byte length {length}")]
    InvalidText {
        /// Rejected field.
        field: &'static str,
        /// UTF-8 byte length.
        length: usize,
    },
    /// The derived observation dictionary is invalid.
    #[error("invalid C SDK counter dictionary: {0}")]
    InvalidDictionary(t32perf_model::DictionaryValidationError),
    /// Strict JSON decoding failed.
    #[error("invalid C SDK counter mapping JSON: {message}")]
    InvalidJson {
        /// Decoder diagnostic.
        message: String,
    },
    /// The supplied mapping document exceeds its byte limit.
    #[error("C SDK counter mapping document has {actual} bytes; maximum is {limit}")]
    DocumentTooLarge {
        /// Maximum admitted bytes.
        limit: usize,
        /// Rejected byte count.
        actual: usize,
    },
}

/// Strictly parses a bounded C SDK counter mapping document.
pub fn parse_c_wire_counter_mapping(
    bytes: &[u8],
) -> Result<CWireCounterMappingDocument, CWireCounterMappingError> {
    if bytes.len() > MAX_C_WIRE_COUNTER_MAPPING_DOCUMENT_BYTES {
        return Err(CWireCounterMappingError::DocumentTooLarge {
            limit: MAX_C_WIRE_COUNTER_MAPPING_DOCUMENT_BYTES,
            actual: bytes.len(),
        });
    }
    strict_json::from_slice(bytes).map_err(|error| CWireCounterMappingError::InvalidJson {
        message: error.to_string(),
    })
}

/// Generates the public C SDK counter mapping JSON Schema.
#[must_use]
pub fn c_wire_schema_documents() -> BTreeMap<&'static str, Value> {
    let mut schema = serde_json::to_value(schema_for!(CWireCounterMappingDocument))
        .expect("C SDK counter mapping schema serialization is infallible");
    schema
        .as_object_mut()
        .expect("C SDK counter mapping schema root is an object")
        .insert(
            "$id".to_owned(),
            Value::String(C_WIRE_COUNTER_MAPPING_SCHEMA.to_owned()),
        );
    BTreeMap::from([("c-wire-counter-mapping.schema.json", schema)])
}

/// Exact position in a binary C SDK stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireLocation {
    /// Zero-based byte offset.
    pub byte_offset: u64,
    /// Zero-based wire record number.
    pub record: u64,
}

/// Limits for C SDK wire decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireLimits {
    /// Maximum payload bytes accepted from one wire record.
    pub max_payload_bytes: usize,
    /// Maximum number of wire records.
    pub max_records: u64,
}

impl Default for WireLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: C_WIRE_DEFAULT_MAX_PAYLOAD,
            max_records: 10_000_000,
        }
    }
}

/// C SDK event kind encoded in the fixed header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireEventKind {
    /// Named instant event.
    Instant,
    /// Synchronous span begin.
    Begin,
    /// Synchronous span end.
    End,
    /// Signed 64-bit counter.
    Counter,
    /// Asynchronous span begin.
    AsyncBegin,
    /// Asynchronous span end.
    AsyncEnd,
    /// Explicit count of records dropped by the target transport.
    Dropped,
}

impl TryFrom<u8> for WireEventKind {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Instant),
            2 => Ok(Self::Begin),
            3 => Ok(Self::End),
            4 => Ok(Self::Counter),
            5 => Ok(Self::AsyncBegin),
            6 => Ok(Self::AsyncEnd),
            7 => Ok(Self::Dropped),
            _ => Err(value),
        }
    }
}

/// One decoded C SDK wire record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CWireRecord {
    /// Event kind.
    pub kind: WireEventKind,
    /// Wire flags.
    pub flags: u16,
    /// Wrapping 32-bit source sequence.
    pub sequence: u32,
    /// Raw target timestamp ticks.
    pub timestamp_ticks: u64,
    /// Target context identifier.
    pub context_id: u32,
    /// Target event identifier.
    pub event_id: u32,
    /// Event-specific payload.
    pub payload: Vec<u8>,
}

/// A C SDK wire decoding or normalization failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{kind} at byte {location_byte}, record {location_record}")]
pub struct WireError {
    /// Exact binary input position.
    pub location: WireLocation,
    /// Failure category.
    pub kind: WireErrorKind,
    location_byte: u64,
    location_record: u64,
}

impl WireError {
    fn new(location: WireLocation, kind: WireErrorKind) -> Self {
        Self {
            location,
            kind,
            location_byte: location.byte_offset,
            location_record: location.record,
        }
    }
}

/// The category of a C SDK wire failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WireErrorKind {
    /// A configured bound is zero.
    #[error("invalid zero wire limit")]
    InvalidLimit,
    /// The normalized source identifier is empty.
    #[error("wire source identifier is empty")]
    InvalidSourceId,
    /// Binary input failed.
    #[error("I/O error: {message}")]
    Io {
        /// I/O error text.
        message: String,
    },
    /// EOF split a fixed wire header.
    #[error("truncated 32-byte wire header after {available} bytes")]
    TruncatedHeader {
        /// Header bytes available before EOF.
        available: usize,
    },
    /// EOF split a payload.
    #[error("truncated payload: expected {expected} bytes, found {available}")]
    TruncatedPayload {
        /// Declared payload length.
        expected: usize,
        /// Payload bytes available before EOF.
        available: usize,
    },
    /// More records were present than configured.
    #[error("wire record count exceeds {limit}")]
    RecordLimitExceeded {
        /// Configured maximum.
        limit: u64,
    },
    /// Header magic is not `T3PF`.
    #[error("invalid wire magic")]
    InvalidMagic,
    /// Wire version is unsupported.
    #[error("unsupported wire version {actual}; expected {supported}")]
    UnsupportedVersion {
        /// Supported version.
        supported: u8,
        /// Rejected version.
        actual: u8,
    },
    /// Event kind is unknown.
    #[error("unknown wire event kind {value}")]
    UnknownEventKind {
        /// Rejected kind byte.
        value: u8,
    },
    /// Wire flags contain unsupported bits.
    #[error("unsupported wire flag bits 0x{bits:04x}")]
    UnsupportedFlags {
        /// Unsupported bits.
        bits: u16,
    },
    /// Reserved header bytes are nonzero.
    #[error("reserved wire field is nonzero")]
    ReservedField,
    /// Payload length exceeds the configured bound.
    #[error("wire payload length {actual} exceeds {limit}")]
    PayloadTooLarge {
        /// Configured maximum.
        limit: usize,
        /// Rejected payload length.
        actual: usize,
    },
    /// Payload length is invalid for its event kind.
    #[error("wire payload length {actual} is invalid for {kind:?}")]
    InvalidPayloadLength {
        /// Event kind.
        kind: WireEventKind,
        /// Rejected length.
        actual: usize,
    },
    /// A string payload is not UTF-8.
    #[error("wire string payload is not UTF-8")]
    InvalidUtf8,
    /// A signed 64-bit counter cannot be represented exactly by the model's f64 field.
    #[error("counter value {value} cannot be represented exactly as f64")]
    CounterPrecisionLoss {
        /// Rejected counter value.
        value: i64,
    },
    /// A Counter record was not declared by the selected mapping document.
    #[error("unmapped C SDK counter event_id {event_id}")]
    UnmappedCounterEvent {
        /// Wire event ID with no stable counter definition.
        event_id: u32,
    },
    /// A C SDK record context was not declared by the selected deployment mapping.
    #[error("unmapped C SDK wire context_id {context_id}")]
    UnmappedContext {
        /// Wire context ID with no canonical context definition.
        context_id: u32,
    },
    /// A mapped Task or ISR stack counter arrived from a different wire context.
    #[error(
        "C SDK counter event_id {event_id} has context_id {actual_context_id}; expected {expected_context_id}"
    )]
    CounterContextMismatch {
        /// Wire counter event ID.
        event_id: u32,
        /// Context ID declared by the counter mapping.
        expected_context_id: u32,
        /// Context ID carried by the wire record.
        actual_context_id: u32,
    },
    /// A supplied C SDK counter mapping document is invalid.
    #[error("invalid C SDK counter mapping: {message}")]
    InvalidCounterMapping {
        /// Stable validation diagnostic.
        message: String,
    },
    /// Wire sequence moved backward rather than wrapping forward.
    #[error("wire sequence {actual} is out of order after {previous}")]
    SequenceOutOfOrder {
        /// Previous raw sequence.
        previous: u32,
        /// Rejected sequence.
        actual: u32,
    },
    /// Expanded sequence cannot fit in the normalized sequence space.
    #[error("expanded wire sequence overflows normalized source_seq")]
    SequenceOverflow,
    /// Timestamp conversion or wrap expansion failed.
    #[error(transparent)]
    Clock(ClockError),
}

/// Streaming decoder for raw C SDK wire records.
pub struct CWireDecoder<R> {
    reader: R,
    limits: WireLimits,
    byte_offset: u64,
    record: u64,
    finished: bool,
}

impl<R: Read> CWireDecoder<R> {
    /// Creates a bounded decoder.
    pub fn new(reader: R, limits: WireLimits) -> Result<Self, WireError> {
        if limits.max_payload_bytes == 0 || limits.max_records == 0 {
            return Err(WireError::new(
                WireLocation {
                    byte_offset: 0,
                    record: 0,
                },
                WireErrorKind::InvalidLimit,
            ));
        }
        Ok(Self {
            reader,
            limits,
            byte_offset: 0,
            record: 0,
            finished: false,
        })
    }

    /// Decodes the next complete record, or `None` at a clean record boundary.
    pub fn next_record(&mut self) -> Result<Option<CWireRecord>, WireError> {
        if self.finished {
            return Ok(None);
        }
        let start = WireLocation {
            byte_offset: self.byte_offset,
            record: self.record,
        };
        if self.record >= self.limits.max_records {
            let mut probe = [0_u8; 1];
            match self.reader.read(&mut probe) {
                Ok(0) => {
                    self.finished = true;
                    return Ok(None);
                }
                Ok(_) => {
                    return Err(WireError::new(
                        start,
                        WireErrorKind::RecordLimitExceeded {
                            limit: self.limits.max_records,
                        },
                    ));
                }
                Err(error) => return Err(self.io_error(start, error)),
            }
        }

        let mut header = [0_u8; C_WIRE_HEADER_SIZE];
        let header_bytes = self.read_part(&mut header, true, start)?;
        if header_bytes == 0 {
            self.finished = true;
            return Ok(None);
        }
        if header_bytes != C_WIRE_HEADER_SIZE {
            return Err(WireError::new(
                WireLocation {
                    byte_offset: start.byte_offset + header_bytes as u64,
                    record: start.record,
                },
                WireErrorKind::TruncatedHeader {
                    available: header_bytes,
                },
            ));
        }
        if &header[0..4] != b"T3PF" {
            return Err(WireError::new(start, WireErrorKind::InvalidMagic));
        }
        if header[4] != C_WIRE_VERSION {
            return Err(WireError::new(
                WireLocation {
                    byte_offset: start.byte_offset + 4,
                    record: start.record,
                },
                WireErrorKind::UnsupportedVersion {
                    supported: C_WIRE_VERSION,
                    actual: header[4],
                },
            ));
        }
        let kind = WireEventKind::try_from(header[5]).map_err(|value| {
            WireError::new(
                WireLocation {
                    byte_offset: start.byte_offset + 5,
                    record: start.record,
                },
                WireErrorKind::UnknownEventKind { value },
            )
        })?;
        let flags = read_u16(&header[6..8]);
        let unsupported_flags = flags & !C_WIRE_FLAG_DROPPED_SINCE_LAST;
        if unsupported_flags != 0 {
            return Err(WireError::new(
                WireLocation {
                    byte_offset: start.byte_offset + 6,
                    record: start.record,
                },
                WireErrorKind::UnsupportedFlags {
                    bits: unsupported_flags,
                },
            ));
        }
        let payload_len = usize::from(read_u16(&header[8..10]));
        if read_u16(&header[10..12]) != 0 {
            return Err(WireError::new(
                WireLocation {
                    byte_offset: start.byte_offset + 10,
                    record: start.record,
                },
                WireErrorKind::ReservedField,
            ));
        }
        if payload_len > self.limits.max_payload_bytes {
            return Err(WireError::new(
                WireLocation {
                    byte_offset: start.byte_offset + 8,
                    record: start.record,
                },
                WireErrorKind::PayloadTooLarge {
                    limit: self.limits.max_payload_bytes,
                    actual: payload_len,
                },
            ));
        }
        validate_payload_length(kind, payload_len, start)?;
        let mut payload = vec![0_u8; payload_len];
        let payload_bytes = self.read_part(&mut payload, false, start)?;
        if payload_bytes != payload_len {
            return Err(WireError::new(
                WireLocation {
                    byte_offset: start.byte_offset
                        + C_WIRE_HEADER_SIZE as u64
                        + payload_bytes as u64,
                    record: start.record,
                },
                WireErrorKind::TruncatedPayload {
                    expected: payload_len,
                    available: payload_bytes,
                },
            ));
        }

        self.record += 1;
        Ok(Some(CWireRecord {
            kind,
            flags,
            sequence: read_u32(&header[12..16]),
            timestamp_ticks: read_u64(&header[16..24]),
            context_id: read_u32(&header[24..28]),
            event_id: read_u32(&header[28..32]),
            payload,
        }))
    }

    fn read_part(
        &mut self,
        output: &mut [u8],
        clean_eof_allowed: bool,
        location: WireLocation,
    ) -> Result<usize, WireError> {
        let mut filled = 0;
        while filled < output.len() {
            match self.reader.read(&mut output[filled..]) {
                Ok(0) => break,
                Ok(count) => {
                    filled += count;
                    self.byte_offset += count as u64;
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => {
                    return Err(self.io_error(
                        WireLocation {
                            byte_offset: self.byte_offset,
                            record: location.record,
                        },
                        error,
                    ));
                }
            }
        }
        if filled == 0 && clean_eof_allowed {
            return Ok(0);
        }
        Ok(filled)
    }

    fn io_error(&self, location: WireLocation, error: std::io::Error) -> WireError {
        WireError::new(
            location,
            WireErrorKind::Io {
                message: error.to_string(),
            },
        )
    }
}

/// Configuration for mapping C SDK wire records to model observations.
#[derive(Debug, Clone)]
pub struct CWireSourceConfig {
    /// Stable normalized source identifier.
    pub source_id: String,
    /// Core associated with SDK events.
    pub core_id: u32,
    /// Raw timestamp clock domain.
    pub clock: ClockDomainSpec,
    /// Optional explicit raw timestamp origin.
    pub origin_ticks: Option<u64>,
    /// Session timestamp assigned to the origin.
    pub origin_ns: i64,
    /// Wire decoder bounds.
    pub limits: WireLimits,
}

/// Normalized source for T32Perf C SDK records.
pub struct CWireObservationSource<R> {
    descriptor: SourceDescriptor,
    decoder: CWireDecoder<R>,
    normalizer: TimestampNormalizer,
    core_id: u32,
    counter_mappings: Option<BTreeMap<u32, MappedCounter>>,
    context_mappings: Option<BTreeMap<u32, String>>,
    dictionary: Option<ObservationDictionary>,
    last_raw_sequence: Option<u32>,
    sequence_epoch: u64,
    pending: Option<OrderedObservation>,
    finished: bool,
}

impl<R: Read> CWireObservationSource<R> {
    /// Creates a wire observation source.
    pub fn new(reader: R, config: CWireSourceConfig) -> Result<Self, WireError> {
        Self::new_inner(reader, config, None)
    }

    /// Creates a wire source with a deployment-owned counter/context dictionary.
    ///
    /// Every C SDK Counter record and every wire context must resolve through
    /// `mapping`; generic `counter:<event_id>` and `context:<wire_id>`
    /// identities are not emitted in this mode.
    pub fn new_with_counter_mapping(
        reader: R,
        config: CWireSourceConfig,
        session_id: impl Into<String>,
        mapping: CWireCounterMappingDocument,
    ) -> Result<Self, WireError> {
        mapping.validate().map_err(|error| {
            WireError::new(
                WireLocation {
                    byte_offset: 0,
                    record: 0,
                },
                WireErrorKind::InvalidCounterMapping {
                    message: error.to_string(),
                },
            )
        })?;
        mapping
            .validate_core_affinity(config.core_id)
            .map_err(|error| {
                WireError::new(
                    WireLocation {
                        byte_offset: 0,
                        record: 0,
                    },
                    WireErrorKind::InvalidCounterMapping {
                        message: error.to_string(),
                    },
                )
            })?;
        let dictionary = mapping.dictionary(session_id).map_err(|error| {
            WireError::new(
                WireLocation {
                    byte_offset: 0,
                    record: 0,
                },
                WireErrorKind::InvalidCounterMapping {
                    message: error.to_string(),
                },
            )
        })?;
        Self::new_inner(
            reader,
            config,
            Some(MappedWireContract {
                counters: mapping.mapped_counters(),
                contexts: mapping.mapped_contexts(),
                dictionary,
            }),
        )
    }

    fn new_inner(
        reader: R,
        config: CWireSourceConfig,
        counter_mapping: Option<MappedWireContract>,
    ) -> Result<Self, WireError> {
        if config.source_id.is_empty() {
            return Err(WireError::new(
                WireLocation {
                    byte_offset: 0,
                    record: 0,
                },
                WireErrorKind::InvalidSourceId,
            ));
        }
        let normalizer =
            TimestampNormalizer::new(config.clock, config.origin_ticks, config.origin_ns).map_err(
                |error| {
                    WireError::new(
                        WireLocation {
                            byte_offset: 0,
                            record: 0,
                        },
                        WireErrorKind::Clock(error),
                    )
                },
            )?;
        Ok(Self {
            descriptor: SourceDescriptor::new(&config.source_id, normalizer.domain_id()),
            decoder: CWireDecoder::new(reader, config.limits)?,
            normalizer,
            core_id: config.core_id,
            counter_mappings: counter_mapping
                .as_ref()
                .map(|mapping| mapping.counters.clone()),
            context_mappings: counter_mapping
                .as_ref()
                .map(|mapping| mapping.contexts.clone()),
            dictionary: counter_mapping.map(|mapping| mapping.dictionary),
            last_raw_sequence: None,
            sequence_epoch: 0,
            pending: None,
            finished: false,
        })
    }

    fn read_next(&mut self) -> Result<Option<OrderedObservation>, WireError> {
        if let Some(pending) = self.pending.take() {
            return Ok(Some(pending));
        }
        let Some(record) = self.decoder.next_record()? else {
            return Ok(None);
        };
        let location = WireLocation {
            byte_offset: self.decoder.byte_offset
                - record.payload.len() as u64
                - C_WIRE_HEADER_SIZE as u64,
            record: self.decoder.record - 1,
        };
        let timestamp = self
            .normalizer
            .normalize(record.timestamp_ticks)
            .map_err(|error| WireError::new(location, WireErrorKind::Clock(error)))?;
        let (expanded_sequence, missing) = self.expand_sequence(record.sequence, location)?;
        let normalized_sequence = expanded_sequence
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| WireError::new(location, WireErrorKind::SequenceOverflow))?;
        let actual = self.map_record(record.clone(), timestamp, normalized_sequence, location)?;

        if record.kind == WireEventKind::Dropped {
            return Ok(Some(actual));
        }
        if missing != 0 || record.flags & C_WIRE_FLAG_DROPPED_SINCE_LAST != 0 {
            let mut reasons = Vec::new();
            if missing != 0 {
                reasons.push(format!("source_sequence_loss:{missing}"));
            }
            if record.flags & C_WIRE_FLAG_DROPPED_SINCE_LAST != 0 {
                reasons.push("sdk_dropped_since_last".to_owned());
            }
            let gap_sequence = normalized_sequence - 1;
            let gap = Observation::new(
                self.descriptor.source_id.clone(),
                gap_sequence,
                Quality::Inferred,
                ObservationEvent::TraceGap {
                    ts_ns: timestamp,
                    duration_ns: 0,
                    reason: reasons.join("+"),
                },
            );
            self.pending = Some(actual);
            return Ok(Some(OrderedObservation::unordered(gap)));
        }
        Ok(Some(actual))
    }

    fn expand_sequence(
        &mut self,
        raw: u32,
        location: WireLocation,
    ) -> Result<(u64, u32), WireError> {
        let Some(previous) = self.last_raw_sequence else {
            self.last_raw_sequence = Some(raw);
            return Ok((u64::from(raw), 0));
        };
        let expected = previous.wrapping_add(1);
        let missing = raw.wrapping_sub(expected);
        if raw != expected && missing >= 0x8000_0000 {
            return Err(WireError::new(
                location,
                WireErrorKind::SequenceOutOfOrder {
                    previous,
                    actual: raw,
                },
            ));
        }
        if raw < previous {
            self.sequence_epoch = self
                .sequence_epoch
                .checked_add(1_u64 << 32)
                .ok_or_else(|| WireError::new(location, WireErrorKind::SequenceOverflow))?;
        }
        let expanded = self
            .sequence_epoch
            .checked_add(u64::from(raw))
            .ok_or_else(|| WireError::new(location, WireErrorKind::SequenceOverflow))?;
        self.last_raw_sequence = Some(raw);
        Ok((expanded, missing))
    }

    fn map_record(
        &self,
        record: CWireRecord,
        ts_ns: i64,
        source_seq: u64,
        location: WireLocation,
    ) -> Result<OrderedObservation, WireError> {
        let context_id = self
            .context_mappings
            .as_ref()
            .map(|contexts| {
                contexts.get(&record.context_id).cloned().ok_or_else(|| {
                    WireError::new(
                        location,
                        WireErrorKind::UnmappedContext {
                            context_id: record.context_id,
                        },
                    )
                })
            })
            .transpose()?
            .unwrap_or_else(|| format!("context:{}", record.context_id));
        let event_id = format!("event:{}", record.event_id);
        let event = match record.kind {
            WireEventKind::Instant => ObservationEvent::Instant {
                ts_ns,
                core_id: Some(self.core_id),
                context_id: Some(context_id),
                name: payload_string(&record.payload, location, 0)?,
                args: Properties::from([("event_id".to_owned(), json!(record.event_id))]),
            },
            WireEventKind::Begin => ObservationEvent::SpanBegin {
                ts_ns,
                core_id: Some(self.core_id),
                context_id: Some(context_id),
                span_id: event_id,
                name: payload_string(&record.payload, location, 0)?,
                args: Properties::new(),
            },
            WireEventKind::End => {
                let name = payload_string(&record.payload, location, 0)?;
                let args = if name.is_empty() {
                    Properties::new()
                } else {
                    Properties::from([("name".to_owned(), json!(name))])
                };
                ObservationEvent::SpanEnd {
                    ts_ns,
                    core_id: Some(self.core_id),
                    context_id: Some(context_id),
                    span_id: event_id,
                    args,
                }
            }
            WireEventKind::Counter => {
                require_payload(&record, 8, location)?;
                let value = i64::from_le_bytes(record.payload[..8].try_into().expect("8 bytes"));
                if value.unsigned_abs() > (1_u64 << 53) {
                    return Err(WireError::new(
                        location,
                        WireErrorKind::CounterPrecisionLoss { value },
                    ));
                }
                ObservationEvent::Counter {
                    ts_ns,
                    core_id: Some(self.core_id),
                    context_id: Some(context_id),
                    counter_id: self
                        .counter_mappings
                        .as_ref()
                        .map(|counter_mappings| {
                            let mapping =
                                counter_mappings.get(&record.event_id).ok_or_else(|| {
                                    WireError::new(
                                        location,
                                        WireErrorKind::UnmappedCounterEvent {
                                            event_id: record.event_id,
                                        },
                                    )
                                })?;
                            if let Some(expected_context_id) = mapping.required_wire_context_id
                                && record.context_id != expected_context_id
                            {
                                return Err(WireError::new(
                                    location,
                                    WireErrorKind::CounterContextMismatch {
                                        event_id: record.event_id,
                                        expected_context_id,
                                        actual_context_id: record.context_id,
                                    },
                                ));
                            }
                            Ok(mapping.counter_id.clone())
                        })
                        .transpose()?
                        .unwrap_or_else(|| format!("counter:{}", record.event_id)),
                    value: value as f64,
                    args: Properties::new(),
                }
            }
            WireEventKind::AsyncBegin => {
                if record.payload.len() < 8 {
                    return Err(WireError::new(
                        location,
                        WireErrorKind::InvalidPayloadLength {
                            kind: record.kind,
                            actual: record.payload.len(),
                        },
                    ));
                }
                let correlation = read_u64(&record.payload[..8]);
                ObservationEvent::AsyncBegin {
                    ts_ns,
                    core_id: Some(self.core_id),
                    context_id: Some(context_id),
                    correlation_id: format!("correlation:{correlation}"),
                    name: payload_string(&record.payload[8..], location, 8)?,
                    args: Properties::from([("event_id".to_owned(), json!(record.event_id))]),
                }
            }
            WireEventKind::AsyncEnd => {
                require_payload(&record, 8, location)?;
                let correlation = read_u64(&record.payload[..8]);
                ObservationEvent::AsyncEnd {
                    ts_ns,
                    core_id: Some(self.core_id),
                    context_id: Some(context_id),
                    correlation_id: format!("correlation:{correlation}"),
                    args: Properties::from([("event_id".to_owned(), json!(record.event_id))]),
                }
            }
            WireEventKind::Dropped => {
                require_payload(&record, 4, location)?;
                let count = read_u32(&record.payload[..4]);
                ObservationEvent::TraceGap {
                    ts_ns,
                    duration_ns: 0,
                    reason: format!("sdk_reported_drop:{count}"),
                }
            }
        };
        Ok(OrderedObservation::unordered(Observation::new(
            self.descriptor.source_id.clone(),
            source_seq,
            if record.kind == WireEventKind::Dropped {
                Quality::Inferred
            } else {
                Quality::Exact
            },
            event,
        )))
    }
}

impl<R: Read> ObservationSource for CWireObservationSource<R> {
    fn descriptor(&self) -> &SourceDescriptor {
        &self.descriptor
    }

    fn dictionary(&self) -> Option<&ObservationDictionary> {
        self.dictionary.as_ref()
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

fn require_payload(
    record: &CWireRecord,
    expected: usize,
    location: WireLocation,
) -> Result<(), WireError> {
    if record.payload.len() != expected {
        return Err(WireError::new(
            location,
            WireErrorKind::InvalidPayloadLength {
                kind: record.kind,
                actual: record.payload.len(),
            },
        ));
    }
    Ok(())
}

fn validate_payload_length(
    kind: WireEventKind,
    actual: usize,
    location: WireLocation,
) -> Result<(), WireError> {
    let valid = match kind {
        WireEventKind::Instant | WireEventKind::Begin | WireEventKind::End => true,
        WireEventKind::Counter | WireEventKind::AsyncEnd => actual == 8,
        WireEventKind::AsyncBegin => actual >= 8,
        WireEventKind::Dropped => actual == 4,
    };
    if valid {
        return Ok(());
    }
    Err(WireError::new(
        WireLocation {
            byte_offset: location.byte_offset + 8,
            record: location.record,
        },
        WireErrorKind::InvalidPayloadLength { kind, actual },
    ))
}

fn payload_string(
    payload: &[u8],
    location: WireLocation,
    payload_offset: usize,
) -> Result<String, WireError> {
    std::str::from_utf8(payload)
        .map(str::to_owned)
        .map_err(|error| {
            WireError::new(
                WireLocation {
                    byte_offset: location.byte_offset
                        + C_WIRE_HEADER_SIZE as u64
                        + payload_offset as u64
                        + error.valid_up_to() as u64,
                    record: location.record,
                },
                WireErrorKind::InvalidUtf8,
            )
        })
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes(bytes[..2].try_into().expect("2 bytes"))
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[..4].try_into().expect("4 bytes"))
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"))
}
