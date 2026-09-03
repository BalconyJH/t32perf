//! Normalized source observations and their dictionaries.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    CounterSemantic, CounterSubject, CounterSubjectKind, DictionarySchemaVersion, DurationNs,
    ObservationSchemaVersion, Properties, Quality, StackRole, TimestampNs,
};

/// The fixed unit used by every normalized timestamp and duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum TimeUnit {
    /// Integer nanoseconds.
    #[serde(rename = "ns")]
    Nanoseconds,
}

/// The fixed origin used by normalized timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TimeOrigin {
    /// Timestamp zero is the logical start of the capture session.
    SessionRelative,
}

/// The physical representation of an observation stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ObservationEncoding {
    /// One JSON object per line, beginning with an [`ObservationStreamHeader`].
    Ndjson,
    /// A single [`ObservationDocument`] JSON object.
    Json,
}

/// Header written as the first record of an NDJSON observation stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ObservationStreamHeader {
    /// The observation schema version.
    pub schema: ObservationSchemaVersion,
    /// The session that owns the stream.
    pub session_id: String,
    /// The stream encoding.
    pub encoding: ObservationEncoding,
    /// The timestamp and duration unit.
    pub time_unit: TimeUnit,
    /// The timestamp origin.
    pub time_origin: TimeOrigin,
    /// Optional producer metadata.
    #[serde(default, skip_serializing_if = "Properties::is_empty")]
    pub properties: Properties,
}

impl ObservationStreamHeader {
    /// Creates a header for a normalized NDJSON stream.
    #[must_use]
    pub fn ndjson(session_id: impl Into<String>) -> Self {
        Self {
            schema: ObservationSchemaVersion,
            session_id: session_id.into(),
            encoding: ObservationEncoding::Ndjson,
            time_unit: TimeUnit::Nanoseconds,
            time_origin: TimeOrigin::SessionRelative,
            properties: Properties::new(),
        }
    }
}

/// A complete in-memory JSON observation document.
///
/// Large captures should use NDJSON with [`ObservationStreamHeader`] instead.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ObservationDocument {
    /// The observation schema version.
    pub schema: ObservationSchemaVersion,
    /// The session that owns the observations.
    pub session_id: String,
    /// The timestamp and duration unit.
    pub time_unit: TimeUnit,
    /// The timestamp origin.
    pub time_origin: TimeOrigin,
    /// Normalized source observations in source order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observations: Vec<Observation>,
}

impl ObservationDocument {
    /// Creates an empty normalized observation document.
    #[must_use]
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            schema: ObservationSchemaVersion,
            session_id: session_id.into(),
            time_unit: TimeUnit::Nanoseconds,
            time_origin: TimeOrigin::SessionRelative,
            observations: Vec::new(),
        }
    }

    /// Validates semantic invariants not expressible by JSON Schema.
    pub fn validate(&self) -> Result<(), ObservationValidationError> {
        if self.session_id.trim().is_empty() {
            return Err(ObservationValidationError::EmptyDocumentSessionId);
        }
        let mut last_sequences = BTreeMap::new();
        for observation in &self.observations {
            observation.validate()?;
            if let Some(previous) =
                last_sequences.insert(&observation.source_id, observation.source_seq)
                && observation.source_seq <= previous
            {
                return Err(ObservationValidationError::NonMonotonicSourceSequence {
                    source_id: observation.source_id.clone(),
                    previous,
                    actual: observation.source_seq,
                });
            }
        }
        Ok(())
    }
}

/// A complete dictionary used by normalized observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ObservationDictionary {
    /// The dictionary schema version.
    pub schema: DictionarySchemaVersion,
    /// The session that owns the dictionary.
    pub session_id: String,
    /// Dictionary entries in definition order.
    pub entries: Vec<DictionaryEntry>,
}

impl ObservationDictionary {
    /// Creates an empty dictionary.
    #[must_use]
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            schema: DictionarySchemaVersion,
            session_id: session_id.into(),
            entries: Vec::new(),
        }
    }

    /// Validates that IDs are unique within each dictionary namespace.
    pub fn validate(&self) -> Result<(), DictionaryValidationError> {
        if self.session_id.trim().is_empty() {
            return Err(DictionaryValidationError::EmptySessionId);
        }
        let mut contexts = BTreeSet::new();
        let mut functions = BTreeSet::new();
        let mut counters = BTreeSet::new();
        let context_kinds =
            self.entries
                .iter()
                .filter_map(|entry| match entry {
                    DictionaryEntry::DefineContext { id, kind, .. } => Some((id.as_str(), *kind)),
                    DictionaryEntry::DefineFunction { .. }
                    | DictionaryEntry::DefineCounter { .. } => None,
                })
                .collect::<BTreeMap<_, _>>();
        let mut resource_identities = BTreeSet::new();
        for entry in &self.entries {
            let (namespace, id, name, ids) = match entry {
                DictionaryEntry::DefineContext { id, name, .. } => {
                    ("context", id, name, &mut contexts)
                }
                DictionaryEntry::DefineFunction {
                    id,
                    name,
                    module,
                    file,
                    line,
                    ..
                } => {
                    validate_dictionary_optional("function", id, "module", module.as_deref())?;
                    validate_dictionary_optional("function", id, "file", file.as_deref())?;
                    if *line == Some(0) {
                        return Err(DictionaryValidationError::InvalidSourceLine {
                            id: id.clone(),
                        });
                    }
                    ("function", id, name, &mut functions)
                }
                DictionaryEntry::DefineCounter {
                    id,
                    name,
                    unit,
                    description,
                    semantic,
                    subject,
                } => {
                    validate_dictionary_optional("counter", id, "unit", unit.as_deref())?;
                    validate_dictionary_optional(
                        "counter",
                        id,
                        "description",
                        description.as_deref(),
                    )?;
                    validate_counter_definition(
                        id,
                        unit.as_deref(),
                        semantic.as_ref(),
                        subject.as_ref(),
                        &context_kinds,
                        &mut resource_identities,
                    )?;
                    ("counter", id, name, &mut counters)
                }
            };
            if id.trim().is_empty() {
                return Err(DictionaryValidationError::EmptyId {
                    namespace: namespace.to_owned(),
                });
            }
            if name.trim().is_empty() {
                return Err(DictionaryValidationError::EmptyName {
                    namespace: namespace.to_owned(),
                    id: id.clone(),
                });
            }
            if !ids.insert(id) {
                return Err(DictionaryValidationError::DuplicateId {
                    namespace: namespace.to_owned(),
                    id: id.clone(),
                });
            }
        }
        Ok(())
    }
}

fn validate_dictionary_optional(
    namespace: &str,
    id: &str,
    field: &'static str,
    value: Option<&str>,
) -> Result<(), DictionaryValidationError> {
    if value.is_some_and(|value| value.trim().is_empty()) {
        return Err(DictionaryValidationError::EmptyOptionalField {
            namespace: namespace.to_owned(),
            id: id.to_owned(),
            field,
        });
    }
    Ok(())
}

/// A dictionary entry that assigns stable IDs to source entities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "PascalCase")]
pub enum DictionaryEntry {
    /// Defines a task, ISR, idle context, core, or unknown execution context.
    DefineContext {
        /// Stable context identifier referenced by observations.
        id: String,
        /// The semantic kind of the context.
        kind: ContextKind,
        /// Display name reported by the capture adapter.
        name: String,
        /// Core affinity when known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        core_id: Option<u32>,
        /// Scheduling or interrupt priority when known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        priority: Option<i32>,
    },
    /// Defines a function or symbol.
    DefineFunction {
        /// Stable function identifier referenced by observations.
        id: String,
        /// Demangled function name when available.
        name: String,
        /// Module, image, or compilation-unit name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        module: Option<String>,
        /// Function start address.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address: Option<u64>,
        /// Source file path reported by debug information.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        file: Option<String>,
        /// One-based source line reported by debug information.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        line: Option<u32>,
    },
    /// Defines a numeric counter.
    DefineCounter {
        /// Stable counter identifier referenced by observations.
        id: String,
        /// Human-readable counter name.
        name: String,
        /// Unit symbol such as `bytes`, `percent`, or `count`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unit: Option<String>,
        /// Optional longer description of the counter.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        /// Explicit extensible counter semantic. Must be paired with `subject`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        semantic: Option<CounterSemantic>,
        /// Explicit measured resource. Must be paired with `semantic`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subject: Option<CounterSubject>,
    },
}

fn validate_counter_definition(
    id: &str,
    unit: Option<&str>,
    semantic: Option<&CounterSemantic>,
    subject: Option<&CounterSubject>,
    context_kinds: &BTreeMap<&str, ContextKind>,
    resource_identities: &mut BTreeSet<(CounterSemantic, CounterSubject)>,
) -> Result<(), DictionaryValidationError> {
    let (semantic, subject) = match (semantic, subject) {
        (None, None) => return Ok(()),
        (Some(semantic), Some(subject)) => (semantic, subject),
        _ => {
            return Err(DictionaryValidationError::IncompleteCounterSemantics {
                id: id.to_owned(),
            });
        }
    };
    subject
        .validate()
        .map_err(|error| DictionaryValidationError::InvalidCounterSubject {
            id: id.to_owned(),
            message: error.to_string(),
        })?;
    if let Some(spec) = semantic.standard_spec() {
        if unit != Some(spec.unit) {
            return Err(DictionaryValidationError::CounterUnitMismatch {
                id: id.to_owned(),
                semantic: semantic.clone(),
                expected: spec.unit,
                actual: unit.map(str::to_owned),
            });
        }
        if subject.kind() != Some(spec.subject_kind) {
            return Err(DictionaryValidationError::CounterSubjectKindMismatch {
                id: id.to_owned(),
                semantic: semantic.clone(),
                expected: spec.subject_kind,
            });
        }
    }
    if let CounterSubject::Stack {
        role,
        context_id: Some(context_id),
        ..
    } = subject
    {
        let expected = match role {
            StackRole::Task => Some(ContextKind::Task),
            StackRole::Isr => Some(ContextKind::Isr),
            StackRole::Msp | StackRole::Psp | StackRole::Custom => None,
        };
        if let Some(expected) = expected
            && context_kinds.get(context_id.as_str()).copied() != Some(expected)
        {
            return Err(DictionaryValidationError::StackContextKindMismatch {
                id: id.to_owned(),
                context_id: context_id.clone(),
                expected,
            });
        }
    }
    if !resource_identities.insert((semantic.clone(), subject.clone())) {
        return Err(DictionaryValidationError::DuplicateCounterIdentity {
            id: id.to_owned(),
            semantic: semantic.clone(),
        });
    }
    Ok(())
}

/// The semantic kind of an execution context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContextKind {
    /// An RTOS task or thread.
    Task,
    /// An interrupt service routine context.
    Isr,
    /// An idle execution context.
    Idle,
    /// A core-level context used when no finer attribution exists.
    Core,
    /// A context whose precise kind is unavailable.
    Unknown,
}

/// One normalized observation emitted by a capture adapter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Observation {
    /// Stable identifier for the producer or input channel.
    pub source_id: String,
    /// Monotonic sequence number in the source's logical record stream.
    pub source_seq: u64,
    /// Evidence quality of this observation.
    pub quality: Quality,
    /// The event-specific payload, flattened into the JSON record.
    #[serde(flatten)]
    pub event: ObservationEvent,
}

impl Observation {
    /// Creates an observation with explicit provenance and quality.
    #[must_use]
    pub fn new(
        source_id: impl Into<String>,
        source_seq: u64,
        quality: Quality,
        event: ObservationEvent,
    ) -> Self {
        Self {
            source_id: source_id.into(),
            source_seq,
            quality,
            event,
        }
    }

    /// Returns the session-relative event timestamp.
    #[must_use]
    pub fn ts_ns(&self) -> TimestampNs {
        self.event.ts_ns()
    }

    /// Validates semantic invariants not expressible by JSON Schema.
    pub fn validate(&self) -> Result<(), ObservationValidationError> {
        self.require("source_id", &self.source_id)?;
        match &self.event {
            ObservationEvent::FunctionEnter {
                context_id,
                function_id,
                frame_id,
                ..
            }
            | ObservationEvent::FunctionExit {
                context_id,
                function_id,
                frame_id,
                ..
            } => {
                self.require("context_id", context_id)?;
                self.require("function_id", function_id)?;
                self.require_optional("frame_id", frame_id.as_deref())?;
            }
            ObservationEvent::ContextSwitch {
                prev_context_id,
                next_context_id,
                reason,
                ..
            } => {
                self.require_optional("prev_context_id", prev_context_id.as_deref())?;
                self.require("next_context_id", next_context_id)?;
                self.require_optional("reason", reason.as_deref())?;
            }
            ObservationEvent::InterruptEnter {
                interrupt_id,
                activation_id,
                ..
            }
            | ObservationEvent::InterruptExit {
                interrupt_id,
                activation_id,
                ..
            } => {
                self.require("interrupt_id", interrupt_id)?;
                self.require("activation_id", activation_id)?;
            }
            ObservationEvent::Sample {
                context_id,
                function_id,
                address,
                weight_ns,
                ..
            } => {
                self.require_optional("context_id", context_id.as_deref())?;
                self.require_optional("function_id", function_id.as_deref())?;
                if function_id.is_none() && address.is_none() {
                    return Err(ObservationValidationError::MissingSampleIdentity {
                        source_id: self.source_id.clone(),
                        source_seq: self.source_seq,
                    });
                }
                if *weight_ns == Some(0) {
                    return Err(ObservationValidationError::ZeroSampleWeight {
                        source_id: self.source_id.clone(),
                        source_seq: self.source_seq,
                    });
                }
            }
            ObservationEvent::Instant {
                context_id, name, ..
            } => {
                self.require_optional("context_id", context_id.as_deref())?;
                self.require("name", name)?;
            }
            ObservationEvent::SpanBegin {
                context_id,
                span_id,
                name,
                ..
            } => {
                self.require_optional("context_id", context_id.as_deref())?;
                self.require("span_id", span_id)?;
                self.require("name", name)?;
            }
            ObservationEvent::SpanEnd {
                context_id,
                span_id,
                ..
            } => {
                self.require_optional("context_id", context_id.as_deref())?;
                self.require("span_id", span_id)?;
            }
            ObservationEvent::AsyncBegin {
                context_id,
                correlation_id,
                name,
                ..
            } => {
                self.require_optional("context_id", context_id.as_deref())?;
                self.require("correlation_id", correlation_id)?;
                self.require("name", name)?;
            }
            ObservationEvent::AsyncEnd {
                context_id,
                correlation_id,
                ..
            } => {
                self.require_optional("context_id", context_id.as_deref())?;
                self.require("correlation_id", correlation_id)?;
            }
            ObservationEvent::Counter {
                context_id,
                counter_id,
                ..
            } => {
                self.require_optional("context_id", context_id.as_deref())?;
                self.require("counter_id", counter_id)?;
            }
            ObservationEvent::TraceGap {
                duration_ns,
                reason,
                ..
            } => {
                self.require("reason", reason)?;
                if *duration_ns == 0 {
                    return Err(ObservationValidationError::ZeroTraceGapDuration {
                        source_id: self.source_id.clone(),
                        source_seq: self.source_seq,
                    });
                }
            }
            ObservationEvent::Metadata { key, .. } => self.require("key", key)?,
        }
        if let ObservationEvent::Counter { value, .. } = self.event
            && !value.is_finite()
        {
            return Err(ObservationValidationError::NonFiniteCounter {
                source_id: self.source_id.clone(),
                source_seq: self.source_seq,
            });
        }
        Ok(())
    }

    fn require(&self, field: &'static str, value: &str) -> Result<(), ObservationValidationError> {
        if value.trim().is_empty() {
            return Err(ObservationValidationError::EmptyField {
                source_id: self.source_id.clone(),
                source_seq: self.source_seq,
                field,
            });
        }
        Ok(())
    }

    fn require_optional(
        &self,
        field: &'static str,
        value: Option<&str>,
    ) -> Result<(), ObservationValidationError> {
        if let Some(value) = value {
            self.require(field, value)?;
        }
        Ok(())
    }
}

/// Event-specific normalized observation data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "PascalCase")]
pub enum ObservationEvent {
    /// A function activation begins.
    FunctionEnter {
        /// Session-relative timestamp.
        ts_ns: TimestampNs,
        /// Core that executed the function.
        core_id: u32,
        /// Active execution context.
        context_id: String,
        /// Function dictionary identifier.
        function_id: String,
        /// Optional adapter-provided activation identifier.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        frame_id: Option<String>,
    },
    /// A function activation ends.
    FunctionExit {
        /// Session-relative timestamp.
        ts_ns: TimestampNs,
        /// Core that executed the function.
        core_id: u32,
        /// Active execution context.
        context_id: String,
        /// Function dictionary identifier.
        function_id: String,
        /// Optional adapter-provided activation identifier.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        frame_id: Option<String>,
    },
    /// The running context on a core changes.
    ContextSwitch {
        /// Session-relative timestamp.
        ts_ns: TimestampNs,
        /// Core whose context changed.
        core_id: u32,
        /// Context switched out, if known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prev_context_id: Option<String>,
        /// Context switched in.
        next_context_id: String,
        /// Adapter-provided switch reason.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// An interrupt activation begins.
    InterruptEnter {
        /// Session-relative timestamp.
        ts_ns: TimestampNs,
        /// Core handling the interrupt.
        core_id: u32,
        /// Interrupt dictionary or target identifier.
        interrupt_id: String,
        /// Interrupt priority when known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        priority: Option<i32>,
        /// Identifier pairing nested interrupt enter and exit records.
        activation_id: String,
    },
    /// An interrupt activation ends.
    InterruptExit {
        /// Session-relative timestamp.
        ts_ns: TimestampNs,
        /// Core handling the interrupt.
        core_id: u32,
        /// Interrupt dictionary or target identifier.
        interrupt_id: String,
        /// Interrupt priority when known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        priority: Option<i32>,
        /// Identifier pairing nested interrupt enter and exit records.
        activation_id: String,
    },
    /// A statistical program-counter sample.
    Sample {
        /// Session-relative timestamp.
        ts_ns: TimestampNs,
        /// Core sampled by the capture source.
        core_id: u32,
        /// Active context when known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        context_id: Option<String>,
        /// Resolved function when known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        function_id: Option<String>,
        /// Raw sampled address when available.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address: Option<u64>,
        /// Time represented by this sample when known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        weight_ns: Option<DurationNs>,
    },
    /// A named instantaneous marker.
    Instant {
        /// Session-relative timestamp.
        ts_ns: TimestampNs,
        /// Core associated with the marker.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        core_id: Option<u32>,
        /// Context associated with the marker.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        context_id: Option<String>,
        /// Marker name.
        name: String,
        /// Structured marker arguments.
        #[serde(default, skip_serializing_if = "Properties::is_empty")]
        args: Properties,
    },
    /// A synchronous custom span begins.
    SpanBegin {
        /// Session-relative timestamp.
        ts_ns: TimestampNs,
        /// Core associated with the span.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        core_id: Option<u32>,
        /// Context associated with the span.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        context_id: Option<String>,
        /// Identifier pairing the begin and end records.
        span_id: String,
        /// Span name.
        name: String,
        /// Structured span arguments.
        #[serde(default, skip_serializing_if = "Properties::is_empty")]
        args: Properties,
    },
    /// A synchronous custom span ends.
    SpanEnd {
        /// Session-relative timestamp.
        ts_ns: TimestampNs,
        /// Core associated with the span.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        core_id: Option<u32>,
        /// Context associated with the span.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        context_id: Option<String>,
        /// Identifier pairing the begin and end records.
        span_id: String,
        /// Structured end arguments.
        #[serde(default, skip_serializing_if = "Properties::is_empty")]
        args: Properties,
    },
    /// An asynchronous span begins.
    AsyncBegin {
        /// Session-relative timestamp.
        ts_ns: TimestampNs,
        /// Core associated with the event.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        core_id: Option<u32>,
        /// Context associated with the event.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        context_id: Option<String>,
        /// Identifier pairing events across contexts or cores.
        correlation_id: String,
        /// Asynchronous operation name.
        name: String,
        /// Structured operation arguments.
        #[serde(default, skip_serializing_if = "Properties::is_empty")]
        args: Properties,
    },
    /// An asynchronous span ends.
    AsyncEnd {
        /// Session-relative timestamp.
        ts_ns: TimestampNs,
        /// Core associated with the event.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        core_id: Option<u32>,
        /// Context associated with the event.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        context_id: Option<String>,
        /// Identifier pairing events across contexts or cores.
        correlation_id: String,
        /// Structured completion arguments.
        #[serde(default, skip_serializing_if = "Properties::is_empty")]
        args: Properties,
    },
    /// A numeric counter value changes.
    Counter {
        /// Session-relative timestamp.
        ts_ns: TimestampNs,
        /// Core associated with the value.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        core_id: Option<u32>,
        /// Context associated with the value.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        context_id: Option<String>,
        /// Counter dictionary identifier.
        counter_id: String,
        /// Finite numeric value.
        value: f64,
        /// Structured value arguments.
        #[serde(default, skip_serializing_if = "Properties::is_empty")]
        args: Properties,
    },
    /// A bounded interval of missing or unusable trace data.
    TraceGap {
        /// Session-relative start timestamp of the gap.
        ts_ns: TimestampNs,
        /// Nonnegative duration of the gap.
        duration_ns: DurationNs,
        /// Machine-readable or human-readable gap reason.
        reason: String,
    },
    /// Source metadata that changes at a point in the stream.
    Metadata {
        /// Session-relative timestamp.
        ts_ns: TimestampNs,
        /// Metadata key.
        key: String,
        /// Arbitrary JSON metadata value.
        value: Value,
    },
}

impl ObservationEvent {
    /// Returns the session-relative event timestamp.
    #[must_use]
    pub fn ts_ns(&self) -> TimestampNs {
        match self {
            Self::FunctionEnter { ts_ns, .. }
            | Self::FunctionExit { ts_ns, .. }
            | Self::ContextSwitch { ts_ns, .. }
            | Self::InterruptEnter { ts_ns, .. }
            | Self::InterruptExit { ts_ns, .. }
            | Self::Sample { ts_ns, .. }
            | Self::Instant { ts_ns, .. }
            | Self::SpanBegin { ts_ns, .. }
            | Self::SpanEnd { ts_ns, .. }
            | Self::AsyncBegin { ts_ns, .. }
            | Self::AsyncEnd { ts_ns, .. }
            | Self::Counter { ts_ns, .. }
            | Self::TraceGap { ts_ns, .. }
            | Self::Metadata { ts_ns, .. } => *ts_ns,
        }
    }
}

/// An observation invariant violation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ObservationValidationError {
    /// An in-memory observation document has no Session identity.
    #[error("observation document session_id is empty")]
    EmptyDocumentSessionId,
    /// A required event identity or name is empty.
    #[error("observation at {source_id}:{source_seq} has empty field `{field}`")]
    EmptyField {
        /// Source containing the invalid field.
        source_id: String,
        /// Logical source sequence.
        source_seq: u64,
        /// Empty field name.
        field: &'static str,
    },
    /// A sample has neither a resolved function nor a raw address.
    #[error("sample at {source_id}:{source_seq} has neither function_id nor address")]
    MissingSampleIdentity {
        /// Source containing the invalid sample.
        source_id: String,
        /// Logical source sequence.
        source_seq: u64,
    },
    /// A sample explicitly declares a zero weight.
    #[error("sample at {source_id}:{source_seq} has zero weight")]
    ZeroSampleWeight {
        /// Source containing the invalid sample.
        source_id: String,
        /// Logical source sequence.
        source_seq: u64,
    },
    /// A trace gap explicitly declares a zero duration.
    #[error("trace gap at {source_id}:{source_seq} has zero duration")]
    ZeroTraceGapDuration {
        /// Source containing the invalid gap.
        source_id: String,
        /// Logical source sequence.
        source_seq: u64,
    },
    /// A counter contains NaN or infinity, neither of which is valid JSON data.
    #[error("counter at {source_id}:{source_seq} is not finite")]
    NonFiniteCounter {
        /// Source containing the invalid counter.
        source_id: String,
        /// Logical source sequence of the invalid counter.
        source_seq: u64,
    },
    /// Source sequence numbers do not increase strictly within a source.
    #[error(
        "source `{source_id}` sequence is not monotonic: record {actual} follows record {previous}"
    )]
    NonMonotonicSourceSequence {
        /// Source containing the out-of-order observation.
        source_id: String,
        /// Previous source sequence.
        previous: u64,
        /// Rejected source sequence.
        actual: u64,
    },
}

/// A semantic invariant violation in an observation dictionary.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DictionaryValidationError {
    /// The dictionary has no owning Session identity.
    #[error("observation dictionary session_id is empty")]
    EmptySessionId,
    /// A dictionary definition has an empty identifier.
    #[error("{namespace} dictionary entry has an empty id")]
    EmptyId {
        /// Dictionary namespace containing the empty ID.
        namespace: String,
    },
    /// A dictionary definition has no display name.
    #[error("{namespace} dictionary entry `{id}` has an empty name")]
    EmptyName {
        /// Dictionary namespace containing the entry.
        namespace: String,
        /// Entry identifier.
        id: String,
    },
    /// An optional dictionary string is present but empty.
    #[error("{namespace} dictionary entry `{id}` has an empty `{field}`")]
    EmptyOptionalField {
        /// Dictionary namespace containing the entry.
        namespace: String,
        /// Entry identifier.
        id: String,
        /// Empty optional field.
        field: &'static str,
    },
    /// A function source line is present but not one-based.
    #[error("function dictionary entry `{id}` has source line zero")]
    InvalidSourceLine {
        /// Function entry identifier.
        id: String,
    },
    /// A dictionary namespace defines the same ID more than once.
    #[error("{namespace} dictionary contains duplicate id `{id}`")]
    DuplicateId {
        /// Dictionary namespace containing the duplicate.
        namespace: String,
        /// Duplicated identifier.
        id: String,
    },
    /// A counter declares only one half of its semantic identity.
    #[error("counter dictionary entry `{id}` must declare semantic and subject together")]
    IncompleteCounterSemantics {
        /// Counter entry identifier.
        id: String,
    },
    /// A counter subject violates its own identity invariants.
    #[error("counter dictionary entry `{id}` has invalid subject: {message}")]
    InvalidCounterSubject {
        /// Counter entry identifier.
        id: String,
        /// Subject validation detail.
        message: String,
    },
    /// A standard semantic uses a unit other than its exact contract unit.
    #[error(
        "counter dictionary entry `{id}` semantic `{semantic}` requires unit `{expected}`, found {actual:?}"
    )]
    CounterUnitMismatch {
        /// Counter entry identifier.
        id: String,
        /// Standard semantic.
        semantic: CounterSemantic,
        /// Required unit.
        expected: &'static str,
        /// Rejected unit or absence.
        actual: Option<String>,
    },
    /// A standard semantic is attached to the wrong subject variant.
    #[error(
        "counter dictionary entry `{id}` semantic `{semantic}` requires subject kind {expected:?}"
    )]
    CounterSubjectKindMismatch {
        /// Counter entry identifier.
        id: String,
        /// Standard semantic.
        semantic: CounterSemantic,
        /// Required subject kind.
        expected: CounterSubjectKind,
    },
    /// A Task or ISR stack references a missing or incompatible context.
    #[error("counter dictionary entry `{id}` stack context `{context_id}` is not {expected:?}")]
    StackContextKindMismatch {
        /// Counter entry identifier.
        id: String,
        /// Referenced context identity.
        context_id: String,
        /// Required context kind.
        expected: ContextKind,
    },
    /// Two counter IDs claim the same semantic resource identity.
    #[error("counter dictionary entry `{id}` duplicates semantic `{semantic}` and its subject")]
    DuplicateCounterIdentity {
        /// Later counter entry identifier.
        id: String,
        /// Duplicated semantic.
        semantic: CounterSemantic,
    },
}
