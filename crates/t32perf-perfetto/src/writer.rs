use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
};

use serde::Serialize;
use serde_json::{Map, Number, Value};
use t32perf_model::{
    ContextKind, CounterSemantic, CounterSubject, DictionaryEntry, FunctionSpan, HealthVerdict,
    Observation, ObservationDictionary, ObservationEvent, Properties, Quality, StackRole,
    TimestampNs,
};

use crate::ExportError;

const TARGET_PID: u64 = 1;
const GAP_TRACK_TID: u32 = 1;
const METADATA_TRACK_TID: u32 = 2;
const UNATTRIBUTED_TRACK_TID: u32 = 3;
const DIAGNOSTIC_TRACK_TID: u32 = 4;
const FIRST_CORE_TRACK_TID: u32 = 16;
const FIRST_CONTEXT_TID: u32 = 1024;
const DEFAULT_MAX_OPEN_CUSTOM_SPANS: usize = 65_536;

/// Configuration shared by every event in one Chrome Trace export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceConfig {
    session_id: String,
    origin_ns: TimestampNs,
    health_verdict: HealthVerdict,
    emit_source_function_events: bool,
    max_open_custom_spans: usize,
}

impl TraceConfig {
    /// Creates a session-relative export configuration with timestamp origin zero.
    #[must_use]
    pub fn new(session_id: impl Into<String>, health_verdict: HealthVerdict) -> Self {
        Self {
            session_id: session_id.into(),
            origin_ns: 0,
            health_verdict,
            emit_source_function_events: false,
            max_open_custom_spans: DEFAULT_MAX_OPEN_CUSTOM_SPANS,
        }
    }

    /// Changes the nanosecond origin subtracted from every event timestamp.
    #[must_use]
    pub const fn with_origin_ns(mut self, origin_ns: TimestampNs) -> Self {
        self.origin_ns = origin_ns;
        self
    }

    /// Enables raw function enter/exit events in addition to derived function spans.
    ///
    /// The default is disabled to avoid drawing the same activation twice when
    /// [`FunctionSpan`] values are exported.
    #[must_use]
    pub const fn with_source_function_events(mut self, enabled: bool) -> Self {
        self.emit_source_function_events = enabled;
        self
    }

    /// Sets the combined resident-state limit for open custom spans.
    ///
    /// Values below one are treated as one.
    #[must_use]
    pub const fn with_max_open_custom_spans(mut self, limit: usize) -> Self {
        self.max_open_custom_spans = limit;
        self
    }

    /// Returns the session identifier written into trace metadata.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns the nanosecond timestamp origin.
    #[must_use]
    pub const fn origin_ns(&self) -> TimestampNs {
        self.origin_ns
    }

    /// Returns the capture health verdict written into trace metadata.
    #[must_use]
    pub const fn health_verdict(&self) -> HealthVerdict {
        self.health_verdict
    }
}

/// A synchronous, event-at-a-time Chrome Trace JSON writer.
///
/// Register all dictionaries before writing the first span or observation. The
/// writer emits process and thread metadata lazily when a track first appears.
pub struct ChromeTraceWriter<W: Write> {
    output: W,
    config: TraceConfig,
    catalog: Catalog,
    first_event: bool,
    started: bool,
    event_count: u64,
    emitted_processes: BTreeSet<u64>,
    emitted_tracks: BTreeSet<(u64, u32)>,
    track_owners: BTreeMap<u32, TrackOwner>,
    owner_tracks: BTreeMap<TrackOwner, u32>,
    open_spans: BTreeMap<(u64, u32, String), String>,
    open_async: BTreeMap<(String, String), String>,
}

impl<W: Write> ChromeTraceWriter<W> {
    /// Starts a trace document on `output`.
    pub fn new(mut output: W, config: TraceConfig) -> Result<Self, ExportError> {
        if config.session_id.is_empty() {
            return Err(ExportError::EmptySessionId);
        }
        output.write_all(br#"{"traceEvents":["#)?;
        Ok(Self {
            output,
            config,
            catalog: Catalog::default(),
            first_event: true,
            started: false,
            event_count: 0,
            emitted_processes: BTreeSet::new(),
            emitted_tracks: BTreeSet::new(),
            track_owners: BTreeMap::new(),
            owner_tracks: BTreeMap::new(),
            open_spans: BTreeMap::new(),
            open_async: BTreeMap::new(),
        })
    }

    /// Registers names and metadata used to resolve subsequent model identifiers.
    pub fn register_dictionary(
        &mut self,
        dictionary: &ObservationDictionary,
    ) -> Result<(), ExportError> {
        if self.started {
            return Err(ExportError::DictionaryAfterEvents);
        }
        if dictionary.session_id != self.config.session_id {
            return Err(ExportError::DictionarySessionMismatch {
                dictionary_session_id: dictionary.session_id.clone(),
                export_session_id: self.config.session_id.clone(),
            });
        }
        for entry in &dictionary.entries {
            self.catalog.register(entry)?;
        }
        Ok(())
    }

    /// Writes one validated derived function activation as a complete slice.
    pub fn write_function_span(&mut self, span: &FunctionSpan) -> Result<(), ExportError> {
        span.validate()?;
        self.start_if_needed()?;

        let track = self.ensure_track(Some(span.core_id), Some(&span.context_id))?;
        let function = self.catalog.functions.get(&span.function_id).cloned();
        let name = function.as_ref().map_or_else(
            || span.function_id.clone(),
            |definition| definition.name.clone(),
        );
        let mut args = Map::new();
        args.insert(
            "active_ns".to_owned(),
            Value::Number(Number::from(span.active_ns)),
        );
        args.insert(
            "core_id".to_owned(),
            Value::Number(Number::from(span.core_id)),
        );
        args.insert(
            "self_ns".to_owned(),
            Value::Number(Number::from(span.self_active_ns)),
        );
        args.insert(
            "preempted_ns".to_owned(),
            Value::Number(Number::from(span.preempted_ns)),
        );
        args.insert(
            "quality".to_owned(),
            Value::String(quality_name(span.quality).to_owned()),
        );
        args.insert("incomplete".to_owned(), Value::Bool(span.incomplete));
        args.insert(
            "function_id".to_owned(),
            Value::String(span.function_id.clone()),
        );
        args.insert(
            "source_id".to_owned(),
            Value::String(span.source_id.clone()),
        );
        insert_optional_u64(&mut args, "source_seq_start", span.source_seq_start);
        insert_optional_u64(&mut args, "source_seq_end", span.source_seq_end);
        insert_optional_string(&mut args, "frame_id", span.frame_id.as_deref());
        if let Some(function) = function {
            insert_optional_string(&mut args, "module", function.module.as_deref());
            insert_optional_string(&mut args, "file", function.file.as_deref());
            insert_optional_u32(&mut args, "line", function.line);
            if let Some(address) = function.address {
                args.insert(
                    "address".to_owned(),
                    Value::String(format!("0x{address:x}")),
                );
            }
        }

        let mut first = self.begin_timed_event(&name, "function", "X", track, span.start_ns)?;
        self.field_duration_us(&mut first, "dur", span.elapsed_ns)?;
        self.field_json(&mut first, "args", &Value::Object(args))?;
        self.end_event()
    }

    /// Writes one normalized source observation.
    pub fn write_observation(&mut self, observation: &Observation) -> Result<(), ExportError> {
        observation.validate()?;
        if !self.config.emit_source_function_events
            && matches!(
                observation.event,
                ObservationEvent::FunctionEnter { .. } | ObservationEvent::FunctionExit { .. }
            )
        {
            return Ok(());
        }
        self.start_if_needed()?;

        match &observation.event {
            ObservationEvent::FunctionEnter {
                ts_ns,
                core_id,
                context_id,
                function_id,
                frame_id,
            } => self.write_raw_function_boundary(
                observation,
                *ts_ns,
                *core_id,
                context_id,
                function_id,
                frame_id.as_deref(),
                "B",
            ),
            ObservationEvent::FunctionExit {
                ts_ns,
                core_id,
                context_id,
                function_id,
                frame_id,
            } => self.write_raw_function_boundary(
                observation,
                *ts_ns,
                *core_id,
                context_id,
                function_id,
                frame_id.as_deref(),
                "E",
            ),
            ObservationEvent::ContextSwitch {
                ts_ns,
                core_id,
                prev_context_id,
                next_context_id,
                reason,
            } => self.write_context_switch(
                observation,
                *ts_ns,
                *core_id,
                prev_context_id.as_deref(),
                next_context_id,
                reason.as_deref(),
            ),
            ObservationEvent::InterruptEnter {
                ts_ns,
                core_id,
                interrupt_id,
                priority,
                activation_id,
            } => self.write_interrupt(
                observation,
                *ts_ns,
                *core_id,
                interrupt_id,
                *priority,
                activation_id,
                "B",
            ),
            ObservationEvent::InterruptExit {
                ts_ns,
                core_id,
                interrupt_id,
                priority,
                activation_id,
            } => self.write_interrupt(
                observation,
                *ts_ns,
                *core_id,
                interrupt_id,
                *priority,
                activation_id,
                "E",
            ),
            ObservationEvent::Sample {
                ts_ns,
                core_id,
                context_id,
                function_id,
                address,
                weight_ns,
            } => self.write_sample(
                observation,
                *ts_ns,
                *core_id,
                context_id.as_deref(),
                function_id.as_deref(),
                *address,
                *weight_ns,
            ),
            ObservationEvent::Instant {
                ts_ns,
                core_id,
                context_id,
                name,
                args,
            } => self.write_instant(
                observation,
                *ts_ns,
                *core_id,
                context_id.as_deref(),
                name,
                args,
            ),
            ObservationEvent::SpanBegin {
                ts_ns,
                core_id,
                context_id,
                span_id,
                name,
                args,
            } => self.write_span_begin(
                observation,
                *ts_ns,
                *core_id,
                context_id.as_deref(),
                span_id,
                name,
                args,
            ),
            ObservationEvent::SpanEnd {
                ts_ns,
                core_id,
                context_id,
                span_id,
                args,
            } => self.write_span_end(
                observation,
                *ts_ns,
                *core_id,
                context_id.as_deref(),
                span_id,
                args,
            ),
            ObservationEvent::AsyncBegin {
                ts_ns,
                core_id,
                context_id,
                correlation_id,
                name,
                args,
            } => self.write_async_begin(
                observation,
                *ts_ns,
                *core_id,
                context_id.as_deref(),
                correlation_id,
                name,
                args,
            ),
            ObservationEvent::AsyncEnd {
                ts_ns,
                core_id,
                context_id,
                correlation_id,
                args,
            } => self.write_async_end(
                observation,
                *ts_ns,
                *core_id,
                context_id.as_deref(),
                correlation_id,
                args,
            ),
            ObservationEvent::Counter {
                ts_ns,
                core_id,
                context_id,
                counter_id,
                value,
                args,
            } => self.write_counter(
                observation,
                *ts_ns,
                *core_id,
                context_id.as_deref(),
                counter_id,
                *value,
                args,
            ),
            ObservationEvent::TraceGap {
                ts_ns,
                duration_ns,
                reason,
            } => self.write_gap(observation, *ts_ns, *duration_ns, reason),
            ObservationEvent::Metadata { ts_ns, key, value } => {
                self.write_source_metadata(observation, *ts_ns, key, value)
            }
        }
    }

    /// Finishes and flushes the JSON document, returning the wrapped output sink.
    pub fn finish(mut self) -> Result<W, ExportError> {
        if !self.open_spans.is_empty() || !self.open_async.is_empty() {
            return Err(ExportError::UnclosedCustomSpans {
                sync_count: self.open_spans.len(),
                async_count: self.open_async.len(),
            });
        }
        self.start_if_needed()?;
        let other_data = serde_json::json!({
            "session_id": self.config.session_id,
            "health_verdict": verdict_name(self.config.health_verdict),
            "diagnostic_only": self.config.health_verdict == HealthVerdict::Invalid,
            "time_origin_ns": self.config.origin_ns,
            "trace_event_count": self.event_count,
            "open_sync_spans": self.open_spans.len(),
            "open_async_spans": self.open_async.len(),
        });
        self.output
            .write_all(br#"],"displayTimeUnit":"ns","otherData":{"t32perf":"#)?;
        serde_json::to_writer(&mut self.output, &other_data)?;
        self.output.write_all(b"}}")?;
        self.output.flush()?;
        Ok(self.output)
    }

    fn start_if_needed(&mut self) -> Result<(), ExportError> {
        if self.started {
            return Ok(());
        }
        self.started = true;
        match self.config.health_verdict {
            HealthVerdict::Valid => Ok(()),
            HealthVerdict::Degraded => self.write_health_warning(
                "DEGRADED trace: timing conclusions require caution",
                "terrible",
            ),
            HealthVerdict::Invalid => {
                self.write_health_warning("INVALID trace: diagnostic use only", "bad")
            }
        }
    }

    fn write_health_warning(&mut self, name: &str, color: &str) -> Result<(), ExportError> {
        let track = self.ensure_special_track(
            TARGET_PID,
            DIAGNOSTIC_TRACK_TID,
            "Trace health diagnostics",
        )?;
        let mut first =
            self.begin_timed_event(name, "trace_health", "i", track, self.config.origin_ns)?;
        self.field_string(&mut first, "s", "t")?;
        self.field_string(&mut first, "cname", color)?;
        let args = serde_json::json!({
            "health_verdict": verdict_name(self.config.health_verdict),
            "diagnostic_only": self.config.health_verdict == HealthVerdict::Invalid,
        });
        self.field_json(&mut first, "args", &args)?;
        self.end_event()
    }

    #[allow(clippy::too_many_arguments)]
    fn write_raw_function_boundary(
        &mut self,
        observation: &Observation,
        ts_ns: TimestampNs,
        core_id: u32,
        context_id: &str,
        function_id: &str,
        frame_id: Option<&str>,
        phase: &str,
    ) -> Result<(), ExportError> {
        let track = self.ensure_track(Some(core_id), Some(context_id))?;
        let name = self
            .catalog
            .functions
            .get(function_id)
            .map_or(function_id, |definition| definition.name.as_str())
            .to_owned();
        let mut args = provenance_args(observation, None)?;
        args.insert(
            "function_id".to_owned(),
            Value::String(function_id.to_owned()),
        );
        insert_optional_string(&mut args, "frame_id", frame_id);
        self.write_phase_event(&name, "raw_function", phase, track, ts_ns, None, args)
    }

    fn write_context_switch(
        &mut self,
        observation: &Observation,
        ts_ns: TimestampNs,
        core_id: u32,
        prev_context_id: Option<&str>,
        next_context_id: &str,
        reason: Option<&str>,
    ) -> Result<(), ExportError> {
        let track = self.ensure_track(Some(core_id), None)?;
        let mut args = provenance_args(observation, None)?;
        if let Some(previous) = prev_context_id {
            args.insert(
                "previous_context".to_owned(),
                Value::String(self.context_name(previous).to_owned()),
            );
        }
        args.insert(
            "next_context".to_owned(),
            Value::String(self.context_name(next_context_id).to_owned()),
        );
        insert_optional_string(&mut args, "reason", reason);
        self.write_phase_event(
            "Context switch",
            "scheduler",
            "i",
            track,
            ts_ns,
            Some("t"),
            args,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn write_interrupt(
        &mut self,
        observation: &Observation,
        ts_ns: TimestampNs,
        core_id: u32,
        interrupt_id: &str,
        priority: Option<i32>,
        activation_id: &str,
        phase: &str,
    ) -> Result<(), ExportError> {
        let track = self.ensure_interrupt_track(core_id, interrupt_id)?;
        let name = self.context_name(interrupt_id).to_owned();
        let mut args = provenance_args(observation, None)?;
        args.insert(
            "activation_id".to_owned(),
            Value::String(activation_id.to_owned()),
        );
        if let Some(priority) = priority {
            args.insert("priority".to_owned(), Value::Number(Number::from(priority)));
        }
        self.write_phase_event(&name, "interrupt", phase, track, ts_ns, None, args)
    }

    #[allow(clippy::too_many_arguments)]
    fn write_sample(
        &mut self,
        observation: &Observation,
        ts_ns: TimestampNs,
        core_id: u32,
        context_id: Option<&str>,
        function_id: Option<&str>,
        address: Option<u64>,
        weight_ns: Option<u64>,
    ) -> Result<(), ExportError> {
        let track = self.ensure_track(Some(core_id), context_id)?;
        let name = function_id
            .and_then(|id| self.catalog.functions.get(id))
            .map_or("PC sample", |definition| definition.name.as_str())
            .to_owned();
        let mut args = provenance_args(observation, None)?;
        insert_optional_string(&mut args, "function_id", function_id);
        insert_optional_u64(&mut args, "weight_ns", weight_ns);
        if let Some(address) = address {
            args.insert(
                "address".to_owned(),
                Value::String(format!("0x{address:x}")),
            );
        }
        self.write_phase_event(&name, "sample", "i", track, ts_ns, Some("t"), args)
    }

    fn write_instant(
        &mut self,
        observation: &Observation,
        ts_ns: TimestampNs,
        core_id: Option<u32>,
        context_id: Option<&str>,
        name: &str,
        properties: &Properties,
    ) -> Result<(), ExportError> {
        let track = self.ensure_track(core_id, context_id)?;
        let args = provenance_args(observation, Some(properties))?;
        self.write_phase_event(name, "custom", "i", track, ts_ns, Some("t"), args)
    }

    #[allow(clippy::too_many_arguments)]
    fn write_span_begin(
        &mut self,
        observation: &Observation,
        ts_ns: TimestampNs,
        core_id: Option<u32>,
        context_id: Option<&str>,
        span_id: &str,
        name: &str,
        properties: &Properties,
    ) -> Result<(), ExportError> {
        let track = self.ensure_track(core_id, context_id)?;
        let key = (track.pid, track.tid, span_id.to_owned());
        if self.open_spans.contains_key(&key) {
            return Err(ExportError::DuplicateOpenSpan {
                pid: track.pid,
                tid: track.tid,
                span_id: span_id.to_owned(),
            });
        }
        self.ensure_open_custom_span_capacity()?;
        let mut args = provenance_args(observation, Some(properties))?;
        args.insert("span_id".to_owned(), Value::String(span_id.to_owned()));
        self.write_phase_event(name, "custom_span", "B", track, ts_ns, None, args)?;
        self.open_spans.insert(key, name.to_owned());
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn write_span_end(
        &mut self,
        observation: &Observation,
        ts_ns: TimestampNs,
        core_id: Option<u32>,
        context_id: Option<&str>,
        span_id: &str,
        properties: &Properties,
    ) -> Result<(), ExportError> {
        let track = self.ensure_track(core_id, context_id)?;
        let key = (track.pid, track.tid, span_id.to_owned());
        let Some(name) = self.open_spans.get(&key).cloned() else {
            return Err(ExportError::UnmatchedSpanEnd {
                pid: track.pid,
                tid: track.tid,
                span_id: span_id.to_owned(),
            });
        };
        let mut args = provenance_args(observation, Some(properties))?;
        args.insert("span_id".to_owned(), Value::String(span_id.to_owned()));
        self.write_phase_event(&name, "custom_span", "E", track, ts_ns, None, args)?;
        self.open_spans.remove(&key);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn write_async_begin(
        &mut self,
        observation: &Observation,
        ts_ns: TimestampNs,
        core_id: Option<u32>,
        context_id: Option<&str>,
        correlation_id: &str,
        name: &str,
        properties: &Properties,
    ) -> Result<(), ExportError> {
        let track = self.ensure_track(core_id, context_id)?;
        let key = (observation.source_id.clone(), correlation_id.to_owned());
        if self.open_async.contains_key(&key) {
            return Err(ExportError::DuplicateOpenAsync {
                source_id: observation.source_id.clone(),
                correlation_id: correlation_id.to_owned(),
            });
        }
        self.ensure_open_custom_span_capacity()?;
        let id = async_trace_id(&observation.source_id, correlation_id);
        let mut args = provenance_args(observation, Some(properties))?;
        args.insert(
            "correlation_id".to_owned(),
            Value::String(correlation_id.to_owned()),
        );
        let mut first = self.begin_timed_event(name, "async", "b", track, ts_ns)?;
        self.field_string(&mut first, "id", &id)?;
        self.field_json(&mut first, "args", &Value::Object(args))?;
        self.end_event()?;
        self.open_async.insert(key, name.to_owned());
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn write_async_end(
        &mut self,
        observation: &Observation,
        ts_ns: TimestampNs,
        core_id: Option<u32>,
        context_id: Option<&str>,
        correlation_id: &str,
        properties: &Properties,
    ) -> Result<(), ExportError> {
        let track = self.ensure_track(core_id, context_id)?;
        let key = (observation.source_id.clone(), correlation_id.to_owned());
        let Some(name) = self.open_async.get(&key).cloned() else {
            return Err(ExportError::UnmatchedAsyncEnd {
                source_id: observation.source_id.clone(),
                correlation_id: correlation_id.to_owned(),
            });
        };
        let id = async_trace_id(&observation.source_id, correlation_id);
        let mut args = provenance_args(observation, Some(properties))?;
        args.insert(
            "correlation_id".to_owned(),
            Value::String(correlation_id.to_owned()),
        );
        let mut first = self.begin_timed_event(&name, "async", "e", track, ts_ns)?;
        self.field_string(&mut first, "id", &id)?;
        self.field_json(&mut first, "args", &Value::Object(args))?;
        self.end_event()?;
        self.open_async.remove(&key);
        Ok(())
    }

    fn ensure_open_custom_span_capacity(&self) -> Result<(), ExportError> {
        let limit = self.config.max_open_custom_spans.max(1);
        if self.open_spans.len().saturating_add(self.open_async.len()) >= limit {
            return Err(ExportError::OpenCustomSpanLimitExceeded { limit });
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn write_counter(
        &mut self,
        observation: &Observation,
        ts_ns: TimestampNs,
        core_id: Option<u32>,
        context_id: Option<&str>,
        counter_id: &str,
        value: f64,
        properties: &Properties,
    ) -> Result<(), ExportError> {
        let counter = self.catalog.counters.get(counter_id).cloned();
        let track = match counter.as_ref() {
            Some(CounterDefinition {
                semantic: Some(semantic),
                subject: Some(subject),
                ..
            }) => self.ensure_resource_counter_track(semantic, subject)?,
            _ => self.ensure_track(core_id, context_id)?,
        };
        let name = counter.as_ref().map_or_else(
            || counter_id.to_owned(),
            |definition| definition.name.clone(),
        );
        let mut args = Map::new();
        args.insert(
            "value".to_owned(),
            Value::Number(
                Number::from_f64(value).expect("observation validation rejects nonfinite values"),
            ),
        );
        let mut metadata = provenance_args(observation, Some(properties))?;
        metadata.insert(
            "counter_id".to_owned(),
            Value::String(counter_id.to_owned()),
        );
        insert_optional_u32(&mut metadata, "core_id", core_id);
        insert_optional_string(&mut metadata, "context_id", context_id);
        if let Some(counter) = counter {
            insert_optional_string(&mut metadata, "unit", counter.unit.as_deref());
            insert_optional_string(&mut metadata, "description", counter.description.as_deref());
            if let Some(semantic) = counter.semantic {
                metadata.insert(
                    "semantic".to_owned(),
                    Value::String(semantic.as_str().to_owned()),
                );
            }
            if let Some(subject) = counter.subject {
                metadata.insert("subject".to_owned(), serde_json::to_value(subject)?);
            }
        }
        let mut first = self.begin_timed_event(&name, "counter", "C", track, ts_ns)?;
        self.field_json(&mut first, "args", &Value::Object(args))?;
        self.field_json(&mut first, "t32perf", &Value::Object(metadata))?;
        self.end_event()
    }

    fn write_gap(
        &mut self,
        observation: &Observation,
        ts_ns: TimestampNs,
        duration_ns: u64,
        reason: &str,
    ) -> Result<(), ExportError> {
        let track = self.ensure_special_track(TARGET_PID, GAP_TRACK_TID, "Trace gaps")?;
        let mut args = provenance_args(observation, None)?;
        args.insert("reason".to_owned(), Value::String(reason.to_owned()));
        let mut first = self.begin_timed_event("Trace gap", "trace_gap", "X", track, ts_ns)?;
        self.field_duration_us(&mut first, "dur", duration_ns)?;
        self.field_string(&mut first, "cname", "bad")?;
        self.field_json(&mut first, "args", &Value::Object(args))?;
        self.end_event()
    }

    fn write_source_metadata(
        &mut self,
        observation: &Observation,
        ts_ns: TimestampNs,
        key: &str,
        value: &Value,
    ) -> Result<(), ExportError> {
        let track = self.ensure_special_track(TARGET_PID, METADATA_TRACK_TID, "Source metadata")?;
        let mut args = provenance_args(observation, None)?;
        args.insert("key".to_owned(), Value::String(key.to_owned()));
        args.insert("value".to_owned(), value.clone());
        self.write_phase_event(
            "Source metadata",
            "metadata",
            "i",
            track,
            ts_ns,
            Some("t"),
            args,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn write_phase_event(
        &mut self,
        name: &str,
        category: &str,
        phase: &str,
        track: Track,
        ts_ns: TimestampNs,
        instant_scope: Option<&str>,
        args: Map<String, Value>,
    ) -> Result<(), ExportError> {
        let mut first = self.begin_timed_event(name, category, phase, track, ts_ns)?;
        if let Some(scope) = instant_scope {
            self.field_string(&mut first, "s", scope)?;
        }
        self.field_json(&mut first, "args", &Value::Object(args))?;
        self.end_event()
    }

    fn ensure_track(
        &mut self,
        core_id: Option<u32>,
        context_id: Option<&str>,
    ) -> Result<Track, ExportError> {
        let context = context_id
            .and_then(|id| self.catalog.contexts.get(id))
            .cloned();
        let effective_core = core_id.or_else(|| context.as_ref().and_then(|entry| entry.core_id));
        self.ensure_process(TARGET_PID, "T32Perf target")?;

        let (tid, name, sort_index) = match (context_id, context) {
            (Some(_), Some(definition))
                if definition.kind == ContextKind::Core && effective_core.is_some() =>
            {
                (
                    core_track_tid(effective_core.expect("guarded core"))?,
                    definition.name,
                    definition.priority,
                )
            }
            (Some(id), Some(definition))
                if definition.kind == ContextKind::Isr && effective_core.is_some() =>
            {
                let core_id = effective_core.expect("guarded core");
                (
                    self.dynamic_track_tid(TrackOwner::Interrupt {
                        core_id,
                        interrupt_id: id.to_owned(),
                    })?,
                    format!("{} (Core {core_id})", definition.name),
                    definition.priority,
                )
            }
            (Some(id), Some(definition)) => (
                self.dynamic_track_tid(TrackOwner::Context(id.to_owned()))?,
                definition.name,
                definition.priority,
            ),
            (Some(id), None) => (
                self.dynamic_track_tid(TrackOwner::Context(id.to_owned()))?,
                id.to_owned(),
                None,
            ),
            (None, _) if effective_core.is_some() => {
                let core_id = effective_core.expect("guarded core");
                (
                    core_track_tid(core_id)?,
                    format!("{} scheduler", self.catalog.core_name(core_id)),
                    None,
                )
            }
            (None, _) => (
                UNATTRIBUTED_TRACK_TID,
                "Unattributed events".to_owned(),
                None,
            ),
        };
        self.ensure_thread(TARGET_PID, tid, &name, sort_index)?;
        Ok(Track {
            pid: TARGET_PID,
            tid,
        })
    }

    fn ensure_resource_counter_track(
        &mut self,
        semantic: &CounterSemantic,
        subject: &CounterSubject,
    ) -> Result<Track, ExportError> {
        self.ensure_process(TARGET_PID, "T32Perf target")?;
        let name = self.resource_counter_track_name(semantic, subject);
        let tid = self.dynamic_track_tid(TrackOwner::ResourceCounter {
            semantic: semantic.clone(),
            subject: subject.clone(),
        })?;
        self.ensure_thread(TARGET_PID, tid, &name, None)?;
        Ok(Track {
            pid: TARGET_PID,
            tid,
        })
    }

    fn resource_counter_track_name(
        &self,
        semantic: &CounterSemantic,
        subject: &CounterSubject,
    ) -> String {
        let subject_name = match subject {
            CounterSubject::Capture => "Capture".to_owned(),
            CounterSubject::Allocator { allocator_id } => {
                format!("Allocator {allocator_id}")
            }
            CounterSubject::Context { context_id } => {
                format!("Context {}", self.context_name(context_id))
            }
            CounterSubject::Core { core_id } => self.catalog.core_name(*core_id),
            CounterSubject::Stack {
                stack_id,
                role,
                context_id,
                core_id,
            } => {
                let mut name = format!("{} stack {stack_id}", stack_role_name(*role));
                if let Some(context_id) = context_id {
                    name.push_str(" (");
                    name.push_str(self.context_name(context_id));
                    name.push(')');
                }
                if let Some(core_id) = core_id {
                    name.push_str(&format!(" (Core {core_id})"));
                }
                name
            }
            CounterSubject::MemoryRegion { region_id } => {
                format!("Memory region {region_id}")
            }
            CounterSubject::TraceBuffer { buffer_id, core_id } => core_id.map_or_else(
                || format!("Trace buffer {buffer_id}"),
                |core_id| format!("Trace buffer {buffer_id} (Core {core_id})"),
            ),
            CounterSubject::Custom { namespace, id } => {
                format!("Custom resource {namespace}:{id}")
            }
        };
        format!("{subject_name}: {semantic}")
    }

    fn ensure_interrupt_track(
        &mut self,
        core_id: u32,
        interrupt_id: &str,
    ) -> Result<Track, ExportError> {
        self.ensure_process(TARGET_PID, "T32Perf target")?;
        let definition = self.catalog.contexts.get(interrupt_id).cloned();
        let name = definition.as_ref().map_or_else(
            || format!("{interrupt_id} (Core {core_id})"),
            |definition| format!("{} (Core {core_id})", definition.name),
        );
        let sort_index = definition.and_then(|definition| definition.priority);
        let tid = self.dynamic_track_tid(TrackOwner::Interrupt {
            core_id,
            interrupt_id: interrupt_id.to_owned(),
        })?;
        self.ensure_thread(TARGET_PID, tid, &name, sort_index)?;
        Ok(Track {
            pid: TARGET_PID,
            tid,
        })
    }

    fn ensure_special_track(
        &mut self,
        pid: u64,
        tid: u32,
        name: &str,
    ) -> Result<Track, ExportError> {
        self.ensure_process(pid, "T32Perf target")?;
        self.ensure_thread(pid, tid, name, None)?;
        Ok(Track { pid, tid })
    }

    fn ensure_process(&mut self, pid: u64, name: &str) -> Result<(), ExportError> {
        if !self.emitted_processes.insert(pid) {
            return Ok(());
        }
        self.begin_event()?;
        let mut first = true;
        self.field_string(&mut first, "name", "process_name")?;
        self.field_string(&mut first, "ph", "M")?;
        self.field_u64(&mut first, "pid", pid)?;
        self.field_u64(&mut first, "tid", 0)?;
        self.field_json(&mut first, "args", &serde_json::json!({"name": name}))?;
        self.end_event()
    }

    fn ensure_thread(
        &mut self,
        pid: u64,
        tid: u32,
        name: &str,
        sort_index: Option<i32>,
    ) -> Result<(), ExportError> {
        if !self.emitted_tracks.insert((pid, tid)) {
            return Ok(());
        }
        self.begin_event()?;
        let mut first = true;
        self.field_string(&mut first, "name", "thread_name")?;
        self.field_string(&mut first, "ph", "M")?;
        self.field_u64(&mut first, "pid", pid)?;
        self.field_u64(&mut first, "tid", u64::from(tid))?;
        self.field_json(&mut first, "args", &serde_json::json!({"name": name}))?;
        self.end_event()?;

        if let Some(sort_index) = sort_index {
            self.begin_event()?;
            let mut first = true;
            self.field_string(&mut first, "name", "thread_sort_index")?;
            self.field_string(&mut first, "ph", "M")?;
            self.field_u64(&mut first, "pid", pid)?;
            self.field_u64(&mut first, "tid", u64::from(tid))?;
            self.field_json(
                &mut first,
                "args",
                &serde_json::json!({"sort_index": sort_index}),
            )?;
            self.end_event()?;
        }
        Ok(())
    }

    fn dynamic_track_tid(&mut self, owner: TrackOwner) -> Result<u32, ExportError> {
        if let Some(tid) = self.owner_tracks.get(&owner) {
            return Ok(*tid);
        }
        let range = i32::MAX as u32 - FIRST_CONTEXT_TID;
        let start = stable_track_tid(&owner);
        for offset in 0..range {
            let relative = start - FIRST_CONTEXT_TID;
            let tid = FIRST_CONTEXT_TID + relative.wrapping_add(offset) % range;
            if self.track_owners.contains_key(&tid) {
                continue;
            }
            self.track_owners.insert(tid, owner.clone());
            self.owner_tracks.insert(owner, tid);
            return Ok(tid);
        }
        Err(ExportError::TrackIdSpaceExhausted)
    }

    fn context_name<'a>(&'a self, context_id: &'a str) -> &'a str {
        self.catalog
            .contexts
            .get(context_id)
            .map_or(context_id, |definition| definition.name.as_str())
    }

    fn begin_timed_event(
        &mut self,
        name: &str,
        category: &str,
        phase: &str,
        track: Track,
        ts_ns: TimestampNs,
    ) -> Result<bool, ExportError> {
        self.begin_event()?;
        let mut first = true;
        self.field_string(&mut first, "name", name)?;
        self.field_string(&mut first, "cat", category)?;
        self.field_string(&mut first, "ph", phase)?;
        self.field_timestamp_us(&mut first, "ts", ts_ns)?;
        self.field_u64(&mut first, "pid", track.pid)?;
        self.field_u64(&mut first, "tid", u64::from(track.tid))?;
        Ok(first)
    }

    fn begin_event(&mut self) -> Result<(), ExportError> {
        if self.first_event {
            self.first_event = false;
        } else {
            self.output.write_all(b",")?;
        }
        self.output.write_all(b"{")?;
        self.event_count = self.event_count.saturating_add(1);
        Ok(())
    }

    fn end_event(&mut self) -> Result<(), ExportError> {
        self.output.write_all(b"}")?;
        Ok(())
    }

    fn field_prefix(&mut self, first: &mut bool, name: &str) -> Result<(), ExportError> {
        if *first {
            *first = false;
        } else {
            self.output.write_all(b",")?;
        }
        serde_json::to_writer(&mut self.output, name)?;
        self.output.write_all(b":")?;
        Ok(())
    }

    fn field_string(
        &mut self,
        first: &mut bool,
        name: &str,
        value: &str,
    ) -> Result<(), ExportError> {
        self.field_prefix(first, name)?;
        serde_json::to_writer(&mut self.output, value)?;
        Ok(())
    }

    fn field_u64(&mut self, first: &mut bool, name: &str, value: u64) -> Result<(), ExportError> {
        self.field_prefix(first, name)?;
        write!(self.output, "{value}")?;
        Ok(())
    }

    fn field_json<T: Serialize + ?Sized>(
        &mut self,
        first: &mut bool,
        name: &str,
        value: &T,
    ) -> Result<(), ExportError> {
        self.field_prefix(first, name)?;
        serde_json::to_writer(&mut self.output, value)?;
        Ok(())
    }

    fn field_timestamp_us(
        &mut self,
        first: &mut bool,
        name: &str,
        timestamp_ns: TimestampNs,
    ) -> Result<(), ExportError> {
        self.field_prefix(first, name)?;
        let relative_ns = i128::from(timestamp_ns) - i128::from(self.config.origin_ns);
        write_ns_as_us(&mut self.output, relative_ns)?;
        Ok(())
    }

    fn field_duration_us(
        &mut self,
        first: &mut bool,
        name: &str,
        duration_ns: u64,
    ) -> Result<(), ExportError> {
        self.field_prefix(first, name)?;
        write_ns_as_us(&mut self.output, i128::from(duration_ns))?;
        Ok(())
    }
}

/// Writes dictionaries, derived spans, and observations without collecting trace events.
pub fn write_trace<'dictionary, 'span, 'observation, W, D, S, O>(
    output: W,
    config: TraceConfig,
    dictionaries: D,
    spans: S,
    observations: O,
) -> Result<W, ExportError>
where
    W: Write,
    D: IntoIterator<Item = &'dictionary ObservationDictionary>,
    S: IntoIterator<Item = &'span FunctionSpan>,
    O: IntoIterator<Item = &'observation Observation>,
{
    let mut writer = ChromeTraceWriter::new(output, config)?;
    for dictionary in dictionaries {
        writer.register_dictionary(dictionary)?;
    }
    for span in spans {
        writer.write_function_span(span)?;
    }
    for observation in observations {
        writer.write_observation(observation)?;
    }
    writer.finish()
}

#[derive(Debug, Clone, Copy)]
struct Track {
    pid: u64,
    tid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum TrackOwner {
    Context(String),
    Interrupt {
        core_id: u32,
        interrupt_id: String,
    },
    ResourceCounter {
        semantic: CounterSemantic,
        subject: CounterSubject,
    },
}

#[derive(Debug, Clone)]
struct ContextDefinition {
    kind: ContextKind,
    name: String,
    core_id: Option<u32>,
    priority: Option<i32>,
}

#[derive(Debug, Clone)]
struct FunctionDefinition {
    name: String,
    module: Option<String>,
    address: Option<u64>,
    file: Option<String>,
    line: Option<u32>,
}

#[derive(Debug, Clone)]
struct CounterDefinition {
    name: String,
    unit: Option<String>,
    description: Option<String>,
    semantic: Option<CounterSemantic>,
    subject: Option<CounterSubject>,
}

#[derive(Debug, Default)]
struct Catalog {
    contexts: BTreeMap<String, ContextDefinition>,
    functions: BTreeMap<String, FunctionDefinition>,
    counters: BTreeMap<String, CounterDefinition>,
}

impl Catalog {
    fn register(&mut self, entry: &DictionaryEntry) -> Result<(), ExportError> {
        match entry {
            DictionaryEntry::DefineContext {
                id,
                kind,
                name,
                core_id,
                priority,
            } => insert_unique(
                &mut self.contexts,
                id,
                ContextDefinition {
                    kind: *kind,
                    name: name.clone(),
                    core_id: *core_id,
                    priority: *priority,
                },
                "context",
            ),
            DictionaryEntry::DefineFunction {
                id,
                name,
                module,
                address,
                file,
                line,
            } => insert_unique(
                &mut self.functions,
                id,
                FunctionDefinition {
                    name: name.clone(),
                    module: module.clone(),
                    address: *address,
                    file: file.clone(),
                    line: *line,
                },
                "function",
            ),
            DictionaryEntry::DefineCounter {
                id,
                name,
                unit,
                description,
                semantic,
                subject,
            } => insert_unique(
                &mut self.counters,
                id,
                CounterDefinition {
                    name: name.clone(),
                    unit: unit.clone(),
                    description: description.clone(),
                    semantic: semantic.clone(),
                    subject: subject.clone(),
                },
                "counter",
            ),
        }
    }

    fn core_name(&self, core_id: u32) -> String {
        self.contexts
            .values()
            .find(|definition| {
                definition.kind == ContextKind::Core && definition.core_id == Some(core_id)
            })
            .map_or_else(
                || format!("Core {core_id}"),
                |definition| definition.name.clone(),
            )
    }
}

fn insert_unique<T>(
    entries: &mut BTreeMap<String, T>,
    id: &str,
    value: T,
    entity_kind: &'static str,
) -> Result<(), ExportError> {
    if entries.insert(id.to_owned(), value).is_some() {
        return Err(ExportError::DuplicateDictionaryEntry {
            entity_kind,
            id: id.to_owned(),
        });
    }
    Ok(())
}

fn provenance_args(
    observation: &Observation,
    properties: Option<&Properties>,
) -> Result<Map<String, Value>, ExportError> {
    let mut args = Map::new();
    if let Some(properties) = properties
        && !properties.is_empty()
    {
        args.insert("data".to_owned(), serde_json::to_value(properties)?);
    }
    args.insert(
        "source_id".to_owned(),
        Value::String(observation.source_id.clone()),
    );
    args.insert(
        "source_seq".to_owned(),
        Value::Number(Number::from(observation.source_seq)),
    );
    args.insert(
        "quality".to_owned(),
        Value::String(quality_name(observation.quality).to_owned()),
    );
    Ok(args)
}

fn insert_optional_string(args: &mut Map<String, Value>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        args.insert(key.to_owned(), Value::String(value.to_owned()));
    }
}

fn insert_optional_u64(args: &mut Map<String, Value>, key: &str, value: Option<u64>) {
    if let Some(value) = value {
        args.insert(key.to_owned(), Value::Number(Number::from(value)));
    }
}

fn insert_optional_u32(args: &mut Map<String, Value>, key: &str, value: Option<u32>) {
    if let Some(value) = value {
        args.insert(key.to_owned(), Value::Number(Number::from(value)));
    }
}

fn core_track_tid(core_id: u32) -> Result<u32, ExportError> {
    let tid = FIRST_CORE_TRACK_TID
        .checked_add(core_id)
        .filter(|tid| *tid < FIRST_CONTEXT_TID)
        .ok_or(ExportError::CoreIdOutOfRange { core_id })?;
    Ok(tid)
}

fn stable_track_tid(owner: &TrackOwner) -> u32 {
    let mut hash = 0xcbf29ce484222325_u64;
    let bytes = match owner {
        TrackOwner::Context(context_id) => {
            let mut bytes = b"t32perf-context\0".to_vec();
            bytes.extend_from_slice(context_id.as_bytes());
            bytes
        }
        TrackOwner::Interrupt {
            core_id,
            interrupt_id,
        } => {
            let mut bytes = b"t32perf-interrupt\0".to_vec();
            bytes.extend_from_slice(&core_id.to_le_bytes());
            bytes.extend_from_slice(interrupt_id.as_bytes());
            bytes
        }
        TrackOwner::ResourceCounter { semantic, subject } => {
            let mut bytes = b"t32perf-resource-counter\0".to_vec();
            append_track_string(&mut bytes, semantic.as_str());
            append_counter_subject(&mut bytes, subject);
            bytes
        }
    };
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let range = u64::from(i32::MAX as u32 - FIRST_CONTEXT_TID);
    FIRST_CONTEXT_TID + u32::try_from(hash % range).expect("hash remainder fits u32")
}

fn append_counter_subject(bytes: &mut Vec<u8>, subject: &CounterSubject) {
    match subject {
        CounterSubject::Capture => bytes.push(0),
        CounterSubject::Allocator { allocator_id } => {
            bytes.push(1);
            append_track_string(bytes, allocator_id);
        }
        CounterSubject::Context { context_id } => {
            bytes.push(2);
            append_track_string(bytes, context_id);
        }
        CounterSubject::Core { core_id } => {
            bytes.push(3);
            bytes.extend_from_slice(&core_id.to_le_bytes());
        }
        CounterSubject::Stack {
            stack_id,
            role,
            context_id,
            core_id,
        } => {
            bytes.push(4);
            append_track_string(bytes, stack_id);
            bytes.push(stack_role_tag(*role));
            append_optional_track_string(bytes, context_id.as_deref());
            append_optional_track_u32(bytes, *core_id);
        }
        CounterSubject::MemoryRegion { region_id } => {
            bytes.push(5);
            append_track_string(bytes, region_id);
        }
        CounterSubject::TraceBuffer { buffer_id, core_id } => {
            bytes.push(6);
            append_track_string(bytes, buffer_id);
            append_optional_track_u32(bytes, *core_id);
        }
        CounterSubject::Custom { namespace, id } => {
            bytes.push(7);
            append_track_string(bytes, namespace);
            append_track_string(bytes, id);
        }
    }
}

fn append_track_string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn append_optional_track_string(bytes: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            bytes.push(1);
            append_track_string(bytes, value);
        }
        None => bytes.push(0),
    }
}

fn append_optional_track_u32(bytes: &mut Vec<u8>, value: Option<u32>) {
    match value {
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        None => bytes.push(0),
    }
}

const fn stack_role_tag(role: StackRole) -> u8 {
    match role {
        StackRole::Task => 0,
        StackRole::Isr => 1,
        StackRole::Msp => 2,
        StackRole::Psp => 3,
        StackRole::Custom => 4,
    }
}

const fn stack_role_name(role: StackRole) -> &'static str {
    match role {
        StackRole::Task => "Task",
        StackRole::Isr => "ISR",
        StackRole::Msp => "MSP",
        StackRole::Psp => "PSP",
        StackRole::Custom => "Custom",
    }
}

fn async_trace_id(source_id: &str, correlation_id: &str) -> String {
    format!("{}:{source_id}:{correlation_id}", source_id.len())
}

fn quality_name(quality: Quality) -> &'static str {
    match quality {
        Quality::Exact => "exact",
        Quality::Inferred => "inferred",
        Quality::Statistical => "statistical",
    }
}

fn verdict_name(verdict: HealthVerdict) -> &'static str {
    match verdict {
        HealthVerdict::Valid => "VALID",
        HealthVerdict::Degraded => "DEGRADED",
        HealthVerdict::Invalid => "INVALID",
    }
}

fn write_ns_as_us(output: &mut impl Write, nanoseconds: i128) -> Result<(), std::io::Error> {
    let negative = nanoseconds.is_negative();
    let absolute = nanoseconds.unsigned_abs();
    let whole = absolute / 1000;
    let fractional = absolute % 1000;
    if negative {
        output.write_all(b"-")?;
    }
    if fractional == 0 {
        write!(output, "{whole}")?;
    } else {
        write!(output, "{whole}.{fractional:03}")?;
    }
    Ok(())
}

#[cfg(test)]
mod track_allocator_tests {
    use super::*;

    #[test]
    fn deterministic_linear_probe_resolves_a_forced_hash_collision() {
        let mut writer = ChromeTraceWriter::new(
            Vec::new(),
            TraceConfig::new("allocator", HealthVerdict::Valid),
        )
        .unwrap();
        let target = TrackOwner::Context("target".to_owned());
        let candidate = stable_track_tid(&target);
        let blocker = TrackOwner::Context("blocker".to_owned());
        writer.track_owners.insert(candidate, blocker.clone());
        writer.owner_tracks.insert(blocker, candidate);

        let resolved = writer.dynamic_track_tid(target.clone()).unwrap();
        assert_ne!(resolved, candidate);
        assert_eq!(writer.dynamic_track_tid(target).unwrap(), resolved);
        assert_eq!(writer.track_owners.len(), 2);
    }
}
