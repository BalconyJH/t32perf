//! Synchronous per-observation analyzer state machine.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use t32perf_model::{
    ContextKind, CounterBehavior, CounterSemantic, CounterSubject, DerivedDocument,
    DerivedResourceMetricSummary, DerivedValidationError, DictionaryEntry,
    DictionaryValidationError, DurationNs, FunctionHotspot, FunctionSpan, HealthObservation,
    HealthValidationError, HealthVerdict, HotspotReport, HotspotValidationError,
    MetricSupportEntry, MetricSupportLevel, Observation, ObservationDictionary, ObservationEvent,
    ObservationValidationError, Properties, Quality, ResourceClass, SamplingHotspot, TimestampNs,
};
use thiserror::Error;

use crate::{
    AnalysisResult, AnalysisSummary, AnalyzerConfig, CallDepthSummary, ContextCpuSummary,
    HealthPolicy, ResourceCounterSummary, ResourceSummary,
};

/// Streaming analyzer for one capture session.
#[derive(Debug)]
pub struct Analyzer {
    session_id: String,
    config: AnalyzerConfig,
    cores: BTreeMap<u32, CoreState>,
    contexts: BTreeMap<ExecutionContextKey, ContextState>,
    context_public_ids: BTreeMap<ExecutionContextKey, String>,
    retired_context_cpu: BTreeMap<String, DurationNs>,
    context_kinds: BTreeMap<String, ContextKind>,
    counter_definitions: BTreeMap<String, CounterDefinition>,
    counter_identity_index: BTreeMap<(CounterSemantic, CounterSubject), String>,
    source_progress: BTreeMap<String, SourceProgress>,
    completed_spans: Vec<FunctionSpan>,
    function_hotspots: BTreeMap<String, HotspotAccumulator>,
    function_span_count: u64,
    incomplete_function_span_count: u64,
    samples: BTreeMap<SampleKey, SampleAccumulator>,
    counters: BTreeMap<String, CounterAccumulator>,
    usage_invariants: BTreeMap<CounterSubject, UsageInvariantState>,
    fragmentation: BTreeMap<CounterSubject, FragmentationAccumulator>,
    reported_resource_issues: BTreeSet<ResourceIssueKey>,
    health_observations: Vec<HealthObservation>,
    health_diagnostics_truncated: bool,
    dropped_health_observation_count: u64,
    observation_count: u64,
    max_ts: Option<TimestampNs>,
    max_depth: u32,
    deepest_context: Option<String>,
    deepest_path: Vec<String>,
    next_activation_serial: u64,
    reported_concurrent_tasks: BTreeSet<(String, u32, u32)>,
    open_custom_spans: BTreeMap<CustomSpanKey, OpenCustomSpan>,
    open_async_spans: BTreeMap<AsyncSpanKey, OpenCustomSpan>,
}

impl Analyzer {
    /// Creates an empty analyzer for one session.
    #[must_use]
    pub fn new(session_id: impl Into<String>, config: AnalyzerConfig) -> Self {
        Self {
            session_id: session_id.into(),
            config,
            cores: BTreeMap::new(),
            contexts: BTreeMap::new(),
            context_public_ids: BTreeMap::new(),
            retired_context_cpu: BTreeMap::new(),
            context_kinds: BTreeMap::new(),
            counter_definitions: BTreeMap::new(),
            counter_identity_index: BTreeMap::new(),
            source_progress: BTreeMap::new(),
            completed_spans: Vec::new(),
            function_hotspots: BTreeMap::new(),
            function_span_count: 0,
            incomplete_function_span_count: 0,
            samples: BTreeMap::new(),
            counters: BTreeMap::new(),
            usage_invariants: BTreeMap::new(),
            fragmentation: BTreeMap::new(),
            reported_resource_issues: BTreeSet::new(),
            health_observations: Vec::new(),
            health_diagnostics_truncated: false,
            dropped_health_observation_count: 0,
            observation_count: 0,
            max_ts: None,
            max_depth: 0,
            deepest_context: None,
            deepest_path: Vec::new(),
            next_activation_serial: 0,
            reported_concurrent_tasks: BTreeSet::new(),
            open_custom_spans: BTreeMap::new(),
            open_async_spans: BTreeMap::new(),
        }
    }

    /// Registers context, function, and counter dictionary definitions.
    pub fn register_dictionary(
        &mut self,
        dictionary: &ObservationDictionary,
    ) -> Result<(), AnalysisError> {
        dictionary.validate()?;
        if dictionary.session_id != self.session_id {
            return Err(AnalysisError::SessionMismatch {
                expected: self.session_id.clone(),
                actual: dictionary.session_id.clone(),
            });
        }

        for entry in &dictionary.entries {
            match entry {
                DictionaryEntry::DefineContext { id, kind, .. } => {
                    self.context_kinds.insert(id.clone(), *kind);
                }
                DictionaryEntry::DefineCounter {
                    id,
                    name,
                    unit,
                    description: _,
                    semantic,
                    subject,
                } => {
                    let definition = CounterDefinition {
                        name: name.clone(),
                        unit: unit.clone(),
                        semantic: semantic.clone(),
                        subject: subject.clone(),
                    };
                    if let Some(existing) = self.counter_definitions.get(id)
                        && existing != &definition
                    {
                        return Err(AnalysisError::ConflictingCounterDefinition {
                            counter_id: id.clone(),
                        });
                    }
                    if let (Some(semantic), Some(subject)) = (semantic, subject) {
                        let identity = (semantic.clone(), subject.clone());
                        if let Some(existing) = self.counter_identity_index.get(&identity)
                            && existing != id
                        {
                            return Err(AnalysisError::ConflictingCounterSubject {
                                counter_id: id.clone(),
                                existing_counter_id: existing.clone(),
                                semantic: semantic.clone(),
                            });
                        }
                        self.counter_identity_index.insert(identity, id.clone());
                    }
                    self.counter_definitions.insert(id.clone(), definition);
                }
                DictionaryEntry::DefineFunction { .. } => {}
            }
        }
        Ok(())
    }

    /// Adds a parser- or capture-provided health fact to the policy input.
    pub fn record_health_observation(&mut self, observation: HealthObservation) {
        self.store_health_observation(observation);
    }

    /// Removes and returns all function spans completed since the previous drain.
    ///
    /// Drained spans remain included in final counts and hotspot aggregation, but
    /// are not repeated in [`AnalysisResult::derived`] returned by [`Self::finish`].
    #[must_use]
    pub fn drain_completed_spans(&mut self) -> Vec<FunctionSpan> {
        std::mem::take(&mut self.completed_spans)
    }

    /// Returns the number of completed spans currently retained for a future drain.
    #[must_use]
    pub fn resident_completed_span_count(&self) -> usize {
        self.completed_spans.len()
    }

    /// Returns the number of counter aggregates retained in resident state.
    #[must_use]
    pub fn resident_counter_count(&self) -> usize {
        self.counters.len()
    }

    /// Returns the number of subjects retained for cross-counter resource invariants.
    #[must_use]
    pub fn resident_resource_subject_count(&self) -> usize {
        self.usage_invariants.len() + self.fragmentation.len()
    }

    /// Consumes one normalized observation synchronously.
    pub fn ingest(&mut self, observation: &Observation) -> Result<(), AnalysisError> {
        if let Err(error) = observation.validate() {
            if matches!(observation.event, ObservationEvent::Counter { .. }) {
                self.push_fact(
                    "invalid_resource_counter",
                    &observation.source_id,
                    Some(observation.source_seq),
                    Some(observation.ts_ns()),
                    Some(observation.ts_ns()),
                    Properties::new(),
                );
            }
            return Err(error.into());
        }

        self.observation_count = self.observation_count.checked_add(1).ok_or_else(|| {
            AnalysisError::NumericOverflow {
                field: "observation_count",
                subject: self.session_id.clone(),
            }
        })?;
        self.check_source_order(observation);

        match &observation.event {
            ObservationEvent::FunctionEnter {
                ts_ns,
                core_id,
                context_id,
                function_id,
                frame_id,
            } => self.function_enter(
                observation,
                *ts_ns,
                *core_id,
                context_id,
                function_id,
                frame_id.as_deref(),
            ),
            ObservationEvent::FunctionExit {
                ts_ns,
                core_id,
                context_id,
                function_id,
                frame_id,
            } => self.function_exit(
                observation,
                *ts_ns,
                *core_id,
                context_id,
                function_id,
                frame_id.as_deref(),
            ),
            ObservationEvent::ContextSwitch {
                ts_ns,
                core_id,
                prev_context_id,
                next_context_id,
                reason,
            } => {
                self.context_switch(
                    observation,
                    *ts_ns,
                    *core_id,
                    prev_context_id.as_deref(),
                    next_context_id,
                    reason.as_deref(),
                );
                Ok(())
            }
            ObservationEvent::InterruptEnter {
                ts_ns,
                core_id,
                interrupt_id,
                activation_id,
                ..
            } => {
                self.interrupt_enter(observation, *ts_ns, *core_id, interrupt_id, activation_id)?;
                Ok(())
            }
            ObservationEvent::InterruptExit {
                ts_ns,
                core_id,
                interrupt_id,
                activation_id,
                ..
            } => {
                self.interrupt_exit(observation, *ts_ns, *core_id, interrupt_id, activation_id)?;
                Ok(())
            }
            ObservationEvent::Sample {
                ts_ns,
                core_id,
                context_id,
                function_id,
                address,
                weight_ns,
            } => {
                self.advance_core(*core_id, *ts_ns, observation);
                self.add_sample(
                    function_id.as_deref(),
                    *address,
                    context_id.as_deref(),
                    weight_ns.unwrap_or(1),
                    observation.quality,
                    observation,
                )?;
                Ok(())
            }
            ObservationEvent::Counter {
                ts_ns,
                core_id,
                counter_id,
                value,
                ..
            } => {
                if let Some(core_id) = core_id {
                    self.advance_core(*core_id, *ts_ns, observation);
                } else {
                    self.observe_timestamp(*ts_ns);
                }
                self.add_counter(counter_id, *value, observation.quality, observation)?;
                Ok(())
            }
            ObservationEvent::TraceGap {
                ts_ns,
                duration_ns,
                reason,
            } => {
                self.trace_gap(observation, *ts_ns, *duration_ns, reason);
                Ok(())
            }
            ObservationEvent::Metadata { ts_ns, key, value } => {
                self.observe_timestamp(*ts_ns);
                self.metadata_health(observation, *ts_ns, key, value);
                Ok(())
            }
            ObservationEvent::Instant { ts_ns, core_id, .. } => {
                self.advance_optional_core(*core_id, *ts_ns, observation);
                Ok(())
            }
            ObservationEvent::SpanBegin {
                ts_ns,
                core_id,
                context_id,
                span_id,
                name,
                ..
            } => {
                let effective_ts = self.advance_optional_core(*core_id, *ts_ns, observation);
                self.custom_span_begin(
                    observation,
                    effective_ts,
                    *core_id,
                    context_id.as_deref(),
                    span_id,
                    name,
                );
                Ok(())
            }
            ObservationEvent::SpanEnd {
                ts_ns,
                core_id,
                context_id,
                span_id,
                ..
            } => {
                let effective_ts = self.advance_optional_core(*core_id, *ts_ns, observation);
                self.custom_span_end(
                    observation,
                    effective_ts,
                    *core_id,
                    context_id.as_deref(),
                    span_id,
                );
                Ok(())
            }
            ObservationEvent::AsyncBegin {
                ts_ns,
                core_id,
                correlation_id,
                name,
                ..
            } => {
                let effective_ts = self.advance_optional_core(*core_id, *ts_ns, observation);
                self.async_span_begin(observation, effective_ts, correlation_id, name);
                Ok(())
            }
            ObservationEvent::AsyncEnd {
                ts_ns,
                core_id,
                correlation_id,
                ..
            } => {
                let effective_ts = self.advance_optional_core(*core_id, *ts_ns, observation);
                self.async_span_end(observation, effective_ts, correlation_id);
                Ok(())
            }
        }
    }

    /// Completes analysis, optionally advancing running contexts to an explicit end timestamp.
    pub fn finish(mut self, end_ts: Option<TimestampNs>) -> Result<AnalysisResult, AnalysisError> {
        if self.session_id.trim().is_empty() {
            return Err(AnalysisError::EmptySessionId);
        }
        let finish_ts = end_ts.or(self.max_ts).unwrap_or(0);
        let synthetic = synthetic_observation(finish_ts);
        let core_ids = self.cores.keys().copied().collect::<Vec<_>>();
        for core_id in core_ids {
            self.advance_core(core_id, finish_ts, &synthetic);
        }
        let close_ts = self.max_ts.unwrap_or(finish_ts).max(finish_ts);

        let unclosed_interrupts = self
            .cores
            .iter()
            .flat_map(|(core_id, core)| {
                core.interrupts
                    .iter()
                    .map(|activation| (*core_id, activation.clone()))
            })
            .collect::<Vec<_>>();
        for (core_id, activation) in unclosed_interrupts {
            self.push_fact(
                "unclosed_interrupt",
                "analyzer",
                None,
                Some(activation.entered_ts),
                Some(close_ts),
                Properties::from([
                    ("core_id".to_owned(), json!(core_id)),
                    ("interrupt_id".to_owned(), json!(activation.interrupt_id)),
                    ("activation_id".to_owned(), json!(activation.activation_id)),
                ]),
            );
            self.mark_context_incomplete(&activation.execution_context);
        }

        let context_keys = self.contexts.keys().cloned().collect::<Vec<_>>();
        for context_key in context_keys {
            while self
                .contexts
                .get(&context_key)
                .is_some_and(|context| !context.frames.is_empty())
            {
                let frame = self.contexts[&context_key]
                    .frames
                    .last()
                    .expect("frame existence was checked");
                let function_id = frame.function_id.clone();
                let public_context_id = frame.public_context_id.clone();
                self.push_fact(
                    "unclosed_function",
                    "analyzer",
                    None,
                    Some(close_ts),
                    Some(close_ts),
                    Properties::from([
                        ("context_id".to_owned(), json!(public_context_id)),
                        ("function_id".to_owned(), json!(function_id)),
                    ]),
                );
                self.finalize_top(&context_key, close_ts, None, Quality::Inferred, true)?;
            }
        }

        for (key, span) in std::mem::take(&mut self.open_custom_spans) {
            self.push_fact(
                "unclosed_span",
                &span.source_id,
                Some(span.source_seq),
                Some(span.begin_ts),
                Some(close_ts),
                Properties::from([
                    ("span_id".to_owned(), json!(key.span_id)),
                    ("name".to_owned(), json!(span.name)),
                    ("core_id".to_owned(), json!(key.core_id)),
                    ("context_id".to_owned(), json!(key.context_id)),
                ]),
            );
        }
        for (key, span) in std::mem::take(&mut self.open_async_spans) {
            self.push_fact(
                "unclosed_async",
                &span.source_id,
                Some(span.source_seq),
                Some(span.begin_ts),
                Some(close_ts),
                Properties::from([
                    ("correlation_id".to_owned(), json!(key.correlation_id)),
                    ("name".to_owned(), json!(span.name)),
                ]),
            );
        }

        let policy_version = if self.config.health_policy_version.trim().is_empty() {
            self.push_fact(
                "invalid_health_policy_identity",
                "analyzer",
                None,
                self.max_ts,
                self.max_ts,
                Properties::new(),
            );
            "t32perf.health-policy/invalid".to_owned()
        } else {
            self.config.health_policy_version.clone()
        };
        let mut effective_capabilities = self.config.capabilities.clone();
        effective_capabilities.resource_counters = self.effective_resource_capability();
        let policy = HealthPolicy::new(policy_version);
        let health = policy.evaluate(
            self.session_id.clone(),
            &self.health_observations,
            &effective_capabilities,
        );
        health.validate()?;
        let summary = self.build_summary(&health.metric_support.resource_counters)?;

        let derived = DerivedDocument {
            schema: t32perf_model::DerivedSchemaVersion,
            session_id: self.session_id.clone(),
            input_artifact_ids: Vec::new(),
            function_spans: self.completed_spans,
        };
        derived.validate()?;

        let hotspots = build_hotspots(
            &self.session_id,
            &self.function_hotspots,
            &self.samples,
            health.verdict,
        )?;
        hotspots.validate()?;

        Ok(AnalysisResult {
            derived,
            health,
            hotspots,
            summary,
        })
    }

    fn check_source_order(&mut self, observation: &Observation) {
        let previous = self.source_progress.get(&observation.source_id).copied();
        if let Some(previous) = previous {
            if observation.source_seq <= previous.sequence {
                self.push_fact(
                    "out_of_order_sequence",
                    &observation.source_id,
                    Some(observation.source_seq),
                    Some(observation.ts_ns()),
                    Some(observation.ts_ns()),
                    Properties::from([
                        ("previous".to_owned(), json!(previous.sequence)),
                        ("actual".to_owned(), json!(observation.source_seq)),
                    ]),
                );
                self.mark_all_incomplete();
            } else if previous.sequence != u64::MAX
                && observation.source_seq > previous.sequence + 1
            {
                let interval_start = previous.timestamp.min(observation.ts_ns());
                let interval_end = previous.timestamp.max(observation.ts_ns());
                self.push_fact(
                    "trace_gap",
                    &observation.source_id,
                    Some(observation.source_seq),
                    Some(interval_start),
                    Some(interval_end),
                    Properties::from([
                        ("reason".to_owned(), json!("source_sequence_gap")),
                        (
                            "missing_records".to_owned(),
                            json!(observation.source_seq - previous.sequence - 1),
                        ),
                    ]),
                );
                self.mark_all_incomplete();
            }
            if observation.ts_ns() < previous.timestamp {
                self.push_fact(
                    "out_of_order_timestamp",
                    &observation.source_id,
                    Some(observation.source_seq),
                    Some(observation.ts_ns()),
                    Some(previous.timestamp),
                    Properties::from([
                        ("previous_ns".to_owned(), json!(previous.timestamp)),
                        ("actual_ns".to_owned(), json!(observation.ts_ns())),
                    ]),
                );
                self.mark_all_incomplete();
            }
        }
        self.source_progress
            .entry(observation.source_id.clone())
            .and_modify(|progress| {
                progress.sequence = progress.sequence.max(observation.source_seq);
                progress.timestamp = progress.timestamp.max(observation.ts_ns());
            })
            .or_insert(SourceProgress {
                sequence: observation.source_seq,
                timestamp: observation.ts_ns(),
            });
    }

    fn function_enter(
        &mut self,
        observation: &Observation,
        ts_ns: TimestampNs,
        core_id: u32,
        context_id: &str,
        function_id: &str,
        frame_id: Option<&str>,
    ) -> Result<(), AnalysisError> {
        let effective_ts = self.advance_core(core_id, ts_ns, observation);
        let (context_key, context_matches) =
            self.ensure_function_context(core_id, context_id, observation);
        self.ensure_execution_context(&context_key, context_id);
        let context = self
            .contexts
            .get_mut(&context_key)
            .expect("execution context was ensured");
        let frame = OpenFrame {
            source_id: observation.source_id.clone(),
            source_seq_start: observation.source_seq,
            core_id,
            public_context_id: context_id.to_owned(),
            function_id: function_id.to_owned(),
            frame_id: frame_id.map(str::to_owned),
            start_wall_ns: effective_ts,
            start_virtual_ns: context.virtual_cpu_ns,
            child_active_ns: 0,
            quality: observation.quality,
            incomplete: !context_matches || context.tainted,
        };
        context.frames.push(frame);

        let depth =
            u32::try_from(context.frames.len()).map_err(|_| AnalysisError::NumericOverflow {
                field: "call_depth",
                subject: context_id.to_owned(),
            })?;
        if depth > self.max_depth {
            self.max_depth = depth;
            self.deepest_context = Some(context_id.to_owned());
            self.deepest_path = context
                .frames
                .iter()
                .map(|frame| frame.function_id.clone())
                .collect();
        }
        Ok(())
    }

    fn function_exit(
        &mut self,
        observation: &Observation,
        ts_ns: TimestampNs,
        core_id: u32,
        context_id: &str,
        function_id: &str,
        frame_id: Option<&str>,
    ) -> Result<(), AnalysisError> {
        let effective_ts = self.advance_core(core_id, ts_ns, observation);
        let (context_key, context_matches) =
            self.ensure_function_context(core_id, context_id, observation);
        if !context_matches {
            self.mark_context_incomplete(&context_key);
        }

        let Some(context) = self.contexts.get(&context_key) else {
            self.unmatched_function_exit(observation, effective_ts, context_id, function_id);
            return Ok(());
        };
        let matching_index = context
            .frames
            .iter()
            .rposition(|frame| frame_matches(frame, function_id, frame_id));
        let Some(matching_index) = matching_index else {
            self.unmatched_function_exit(observation, effective_ts, context_id, function_id);
            self.mark_context_incomplete(&context_key);
            return Ok(());
        };

        let top_index = context.frames.len() - 1;
        let source_mismatch = context.frames[matching_index].source_id != observation.source_id;
        let mismatched = matching_index != top_index || source_mismatch;
        if mismatched {
            self.push_fact(
                "mismatched_function_exit",
                &observation.source_id,
                Some(observation.source_seq),
                Some(effective_ts),
                Some(effective_ts),
                Properties::from([
                    ("context_id".to_owned(), json!(context_id)),
                    ("function_id".to_owned(), json!(function_id)),
                ]),
            );
            self.mark_context_incomplete(&context_key);
        }

        while self.contexts[&context_key].frames.len() - 1 > matching_index {
            self.finalize_top(
                &context_key,
                effective_ts,
                Some(observation.source_seq),
                observation.quality,
                true,
            )?;
        }
        self.finalize_top(
            &context_key,
            effective_ts,
            Some(observation.source_seq),
            observation.quality,
            mismatched,
        )
    }

    fn unmatched_function_exit(
        &mut self,
        observation: &Observation,
        ts_ns: TimestampNs,
        context_id: &str,
        function_id: &str,
    ) {
        self.push_fact(
            "unmatched_function_exit",
            &observation.source_id,
            Some(observation.source_seq),
            Some(ts_ns),
            Some(ts_ns),
            Properties::from([
                ("context_id".to_owned(), json!(context_id)),
                ("function_id".to_owned(), json!(function_id)),
            ]),
        );
    }

    fn finalize_top(
        &mut self,
        context_key: &ExecutionContextKey,
        end_wall_ns: TimestampNs,
        source_seq_end: Option<u64>,
        exit_quality: Quality,
        force_incomplete: bool,
    ) -> Result<(), AnalysisError> {
        let context = self
            .contexts
            .get_mut(context_key)
            .expect("finalized context exists");
        let frame = context.frames.pop().expect("finalized frame exists");
        let raw_active_ns = context
            .virtual_cpu_ns
            .saturating_sub(frame.start_virtual_ns);
        let elapsed_ns = duration_between(frame.start_wall_ns, end_wall_ns).unwrap_or(0);
        let mut incomplete = force_incomplete || frame.incomplete;
        let active_ns = raw_active_ns.min(elapsed_ns);
        if raw_active_ns > elapsed_ns || frame.child_active_ns > active_ns {
            incomplete = true;
        }
        let self_active_ns = active_ns.saturating_sub(frame.child_active_ns.min(active_ns));
        let preempted_ns = elapsed_ns.saturating_sub(active_ns);
        let quality = if incomplete {
            worst_quality(
                worst_quality(frame.quality, exit_quality),
                Quality::Inferred,
            )
        } else {
            worst_quality(frame.quality, exit_quality)
        };

        if let Some(parent) = context.frames.last_mut() {
            parent.child_active_ns =
                parent
                    .child_active_ns
                    .checked_add(active_ns)
                    .ok_or_else(|| AnalysisError::NumericOverflow {
                        field: "child_active_ns",
                        subject: frame.public_context_id.clone(),
                    })?;
            if incomplete {
                parent.incomplete = true;
                parent.quality = worst_quality(parent.quality, Quality::Inferred);
            }
        }

        let span = FunctionSpan {
            source_id: frame.source_id,
            source_seq_start: Some(frame.source_seq_start),
            source_seq_end,
            core_id: frame.core_id,
            context_id: frame.public_context_id,
            function_id: frame.function_id,
            frame_id: frame.frame_id,
            start_ns: frame.start_wall_ns,
            end_ns: end_wall_ns.max(frame.start_wall_ns),
            elapsed_ns,
            active_ns,
            self_active_ns,
            preempted_ns,
            quality,
            incomplete,
        };
        self.record_completed_span(span)
    }

    fn record_completed_span(&mut self, span: FunctionSpan) -> Result<(), AnalysisError> {
        span.validate()?;
        let function_span_count = self.function_span_count.checked_add(1).ok_or_else(|| {
            AnalysisError::NumericOverflow {
                field: "function_span_count",
                subject: self.session_id.clone(),
            }
        })?;
        let incomplete_function_span_count = if span.incomplete {
            self.incomplete_function_span_count
                .checked_add(1)
                .ok_or_else(|| AnalysisError::NumericOverflow {
                    field: "incomplete_function_span_count",
                    subject: self.session_id.clone(),
                })?
        } else {
            self.incomplete_function_span_count
        };
        let aggregate = if span.incomplete {
            None
        } else {
            let mut aggregate = self
                .function_hotspots
                .get(&span.function_id)
                .cloned()
                .unwrap_or_default();
            aggregate.add_span(&span)?;
            Some(aggregate)
        };

        self.function_span_count = function_span_count;
        self.incomplete_function_span_count = incomplete_function_span_count;
        if let Some(aggregate) = aggregate {
            self.function_hotspots
                .insert(span.function_id.clone(), aggregate);
        }
        self.completed_spans.push(span);
        Ok(())
    }

    fn context_switch(
        &mut self,
        observation: &Observation,
        ts_ns: TimestampNs,
        core_id: u32,
        prev_context_id: Option<&str>,
        next_context_id: &str,
        reason: Option<&str>,
    ) {
        let effective_ts = self.advance_core(core_id, ts_ns, observation);
        let scheduled = self
            .cores
            .get(&core_id)
            .and_then(|core| core.scheduled_context.as_ref())
            .and_then(ExecutionContextKey::scheduled_id)
            .map(str::to_owned);
        if let Some(expected_previous) = prev_context_id
            && scheduled
                .as_deref()
                .is_some_and(|actual| actual != expected_previous)
        {
            self.push_fact(
                "context_switch_mismatch",
                &observation.source_id,
                Some(observation.source_seq),
                Some(effective_ts),
                Some(effective_ts),
                Properties::from([
                    ("core_id".to_owned(), json!(core_id)),
                    ("expected_previous".to_owned(), json!(expected_previous)),
                    ("actual_previous".to_owned(), json!(scheduled)),
                    ("reason".to_owned(), json!(reason)),
                ]),
            );
            if let Some(scheduled) = scheduled.as_deref() {
                self.mark_context_incomplete(&ExecutionContextKey::scheduled(scheduled));
            }
            self.mark_context_incomplete(&ExecutionContextKey::scheduled(expected_previous));
        }

        let next_context = ExecutionContextKey::scheduled(next_context_id);
        self.ensure_execution_context(&next_context, next_context_id);
        self.schedule_context(core_id, next_context, effective_ts);
        self.context_kinds
            .entry(next_context_id.to_owned())
            .or_insert_with(|| infer_scheduled_context_kind(next_context_id));
    }

    fn interrupt_enter(
        &mut self,
        observation: &Observation,
        ts_ns: TimestampNs,
        core_id: u32,
        interrupt_id: &str,
        activation_id: &str,
    ) -> Result<(), AnalysisError> {
        let effective_ts = self.advance_core(core_id, ts_ns, observation);
        let duplicate_contexts = self
            .cores
            .get(&core_id)
            .map(|core| {
                core.interrupts
                    .iter()
                    .filter(|activation| activation.activation_id == activation_id)
                    .map(|activation| activation.execution_context.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let duplicate = !duplicate_contexts.is_empty();
        if duplicate {
            self.push_fact(
                "duplicate_interrupt_activation",
                &observation.source_id,
                Some(observation.source_seq),
                Some(effective_ts),
                Some(effective_ts),
                Properties::from([("activation_id".to_owned(), json!(activation_id))]),
            );
            for context in duplicate_contexts {
                self.taint_context(&context);
            }
        }
        let serial = self.next_activation_serial;
        self.next_activation_serial =
            self.next_activation_serial.checked_add(1).ok_or_else(|| {
                AnalysisError::NumericOverflow {
                    field: "interrupt_activation_serial",
                    subject: self.session_id.clone(),
                }
            })?;
        let execution_context = ExecutionContextKey::InterruptActivation {
            core_id,
            activation_id: activation_id.to_owned(),
            serial,
        };
        self.ensure_execution_context(&execution_context, interrupt_id);
        if duplicate {
            self.taint_context(&execution_context);
        }
        self.cores
            .entry(core_id)
            .or_default()
            .interrupts
            .push(InterruptActivation {
                interrupt_id: interrupt_id.to_owned(),
                activation_id: activation_id.to_owned(),
                execution_context,
                entered_ts: effective_ts,
            });
        self.context_kinds
            .insert(interrupt_id.to_owned(), ContextKind::Isr);
        Ok(())
    }

    fn interrupt_exit(
        &mut self,
        observation: &Observation,
        ts_ns: TimestampNs,
        core_id: u32,
        interrupt_id: &str,
        activation_id: &str,
    ) -> Result<(), AnalysisError> {
        let effective_ts = self.advance_core(core_id, ts_ns, observation);
        let position = self.cores.get(&core_id).and_then(|core| {
            core.interrupts.iter().rposition(|activation| {
                activation.activation_id == activation_id && activation.interrupt_id == interrupt_id
            })
        });
        let Some(position) = position else {
            self.push_fact(
                "unmatched_interrupt_exit",
                &observation.source_id,
                Some(observation.source_seq),
                Some(effective_ts),
                Some(effective_ts),
                Properties::from([
                    ("core_id".to_owned(), json!(core_id)),
                    ("interrupt_id".to_owned(), json!(interrupt_id)),
                    ("activation_id".to_owned(), json!(activation_id)),
                ]),
            );
            return Ok(());
        };

        let top = self.cores[&core_id].interrupts.len() - 1;
        if position != top {
            self.push_fact(
                "mismatched_interrupt_exit",
                &observation.source_id,
                Some(observation.source_seq),
                Some(effective_ts),
                Some(effective_ts),
                Properties::from([
                    ("core_id".to_owned(), json!(core_id)),
                    ("interrupt_id".to_owned(), json!(interrupt_id)),
                    ("activation_id".to_owned(), json!(activation_id)),
                ]),
            );
            let removed = self.cores[&core_id].interrupts[position + 1..].to_vec();
            for activation in removed {
                self.mark_context_incomplete(&activation.execution_context);
            }
            let target = self.cores[&core_id].interrupts[position]
                .execution_context
                .clone();
            self.mark_context_incomplete(&target);
        }
        let removed = self.cores[&core_id].interrupts[position..].to_vec();
        for activation in &removed {
            self.close_unclosed_frames(
                &activation.execution_context,
                effective_ts,
                &observation.source_id,
                Some(observation.source_seq),
            )?;
        }
        self.cores
            .get_mut(&core_id)
            .expect("interrupt core exists")
            .interrupts
            .truncate(position);
        for activation in removed {
            self.retire_interrupt_context(&activation.execution_context)?;
        }
        Ok(())
    }

    fn retire_interrupt_context(
        &mut self,
        context_key: &ExecutionContextKey,
    ) -> Result<(), AnalysisError> {
        let Some(context) = self.contexts.remove(context_key) else {
            return Ok(());
        };
        debug_assert!(context.frames.is_empty());
        let public_context_id = self
            .context_public_ids
            .remove(context_key)
            .expect("every resident execution context has public attribution");
        let aggregate = self
            .retired_context_cpu
            .entry(public_context_id.clone())
            .or_default();
        *aggregate = aggregate.checked_add(context.virtual_cpu_ns).ok_or(
            AnalysisError::NumericOverflow {
                field: "context_cpu_ns",
                subject: public_context_id,
            },
        )?;
        Ok(())
    }

    fn close_unclosed_frames(
        &mut self,
        context_key: &ExecutionContextKey,
        end_ns: TimestampNs,
        source: &str,
        record: Option<u64>,
    ) -> Result<(), AnalysisError> {
        while self
            .contexts
            .get(context_key)
            .is_some_and(|context| !context.frames.is_empty())
        {
            let frame = self.contexts[context_key]
                .frames
                .last()
                .expect("frame existence was checked");
            let public_context_id = frame.public_context_id.clone();
            let function_id = frame.function_id.clone();
            self.push_fact(
                "unclosed_function",
                source,
                record,
                Some(end_ns),
                Some(end_ns),
                Properties::from([
                    ("context_id".to_owned(), json!(public_context_id)),
                    ("function_id".to_owned(), json!(function_id)),
                ]),
            );
            self.finalize_top(context_key, end_ns, record, Quality::Inferred, true)?;
        }
        Ok(())
    }

    fn ensure_function_context(
        &mut self,
        core_id: u32,
        context_id: &str,
        observation: &Observation,
    ) -> (ExecutionContextKey, bool) {
        let running = self.cores.get(&core_id).and_then(|core| {
            Some((
                core.running_context()?.clone(),
                core.running_public_context()?.to_owned(),
                !core.interrupts.is_empty(),
            ))
        });
        match running {
            Some((running_key, running_public, _)) if running_public == context_id => {
                self.ensure_execution_context(&running_key, context_id);
                (running_key, true)
            }
            None => {
                let context_key = ExecutionContextKey::scheduled(context_id);
                self.ensure_execution_context(&context_key, context_id);
                let scheduled_since = self.cores[&core_id].last_ts.unwrap_or(observation.ts_ns());
                self.schedule_context(core_id, context_key.clone(), scheduled_since);
                self.context_kinds
                    .entry(context_id.to_owned())
                    .or_insert(ContextKind::Unknown);
                (context_key, true)
            }
            Some((_, _, false))
                if self.config.capabilities.context_switches.support
                    == MetricSupportLevel::Unavailable =>
            {
                let context_key = ExecutionContextKey::scheduled(context_id);
                self.ensure_execution_context(&context_key, context_id);
                if self.cores[&core_id].interrupts.is_empty() {
                    let scheduled_since =
                        self.cores[&core_id].last_ts.unwrap_or(observation.ts_ns());
                    self.schedule_context(core_id, context_key.clone(), scheduled_since);
                    self.context_kinds
                        .entry(context_id.to_owned())
                        .or_insert(ContextKind::Unknown);
                    (context_key, true)
                } else {
                    unreachable!("the match arm requires an empty interrupt stack")
                }
            }
            Some((running_key, running_public, _)) => {
                let event_key = self.event_execution_context(core_id, context_id);
                self.ensure_execution_context(&event_key, context_id);
                self.context_mismatch(
                    core_id,
                    &running_key,
                    &running_public,
                    &event_key,
                    context_id,
                    observation,
                );
                (event_key, false)
            }
        }
    }

    fn event_execution_context(&self, core_id: u32, context_id: &str) -> ExecutionContextKey {
        self.cores
            .get(&core_id)
            .and_then(|core| {
                core.interrupts
                    .iter()
                    .rev()
                    .find(|activation| activation.interrupt_id == context_id)
                    .map(|activation| activation.execution_context.clone())
            })
            .unwrap_or_else(|| ExecutionContextKey::scheduled(context_id))
    }

    fn context_mismatch(
        &mut self,
        core_id: u32,
        running_key: &ExecutionContextKey,
        running_public: &str,
        event_key: &ExecutionContextKey,
        event_public: &str,
        observation: &Observation,
    ) {
        self.push_fact(
            "context_mismatch",
            &observation.source_id,
            Some(observation.source_seq),
            Some(observation.ts_ns()),
            Some(observation.ts_ns()),
            Properties::from([
                ("core_id".to_owned(), json!(core_id)),
                ("running_context".to_owned(), json!(running_public)),
                ("event_context".to_owned(), json!(event_public)),
            ]),
        );
        self.mark_context_incomplete(running_key);
        self.mark_context_incomplete(event_key);
    }

    fn ensure_execution_context(&mut self, key: &ExecutionContextKey, public_context_id: &str) {
        self.contexts.entry(key.clone()).or_default();
        self.context_public_ids
            .entry(key.clone())
            .or_insert_with(|| public_context_id.to_owned());
    }

    fn advance_optional_core(
        &mut self,
        core_id: Option<u32>,
        ts_ns: TimestampNs,
        observation: &Observation,
    ) -> TimestampNs {
        if let Some(core_id) = core_id {
            self.advance_core(core_id, ts_ns, observation)
        } else {
            self.observe_timestamp(ts_ns);
            ts_ns
        }
    }

    fn custom_span_begin(
        &mut self,
        observation: &Observation,
        ts_ns: TimestampNs,
        core_id: Option<u32>,
        context_id: Option<&str>,
        span_id: &str,
        name: &str,
    ) {
        let key = CustomSpanKey {
            source_id: observation.source_id.clone(),
            core_id,
            context_id: context_id.map(str::to_owned),
            span_id: span_id.to_owned(),
        };
        if let Some(open) = self.open_custom_spans.get(&key) {
            let prior_begin_ts = open.begin_ts;
            let prior_source_seq = open.source_seq;
            self.push_fact(
                "duplicate_span_begin",
                &observation.source_id,
                Some(observation.source_seq),
                Some(prior_begin_ts),
                Some(ts_ns),
                Properties::from([
                    ("span_id".to_owned(), json!(span_id)),
                    ("prior_source_seq".to_owned(), json!(prior_source_seq)),
                ]),
            );
            return;
        }
        if self.open_custom_span_count() >= self.config.max_open_custom_spans.max(1) {
            self.record_open_custom_span_limit(observation, ts_ns, "span", span_id);
            return;
        }
        self.open_custom_spans.insert(
            key,
            OpenCustomSpan {
                source_id: observation.source_id.clone(),
                source_seq: observation.source_seq,
                begin_ts: ts_ns,
                name: name.to_owned(),
            },
        );
    }

    fn custom_span_end(
        &mut self,
        observation: &Observation,
        ts_ns: TimestampNs,
        core_id: Option<u32>,
        context_id: Option<&str>,
        span_id: &str,
    ) {
        let key = CustomSpanKey {
            source_id: observation.source_id.clone(),
            core_id,
            context_id: context_id.map(str::to_owned),
            span_id: span_id.to_owned(),
        };
        if self.open_custom_spans.remove(&key).is_none() {
            self.push_fact(
                "unmatched_span_end",
                &observation.source_id,
                Some(observation.source_seq),
                Some(ts_ns),
                Some(ts_ns),
                Properties::from([
                    ("span_id".to_owned(), json!(span_id)),
                    ("core_id".to_owned(), json!(core_id)),
                    ("context_id".to_owned(), json!(context_id)),
                ]),
            );
        }
    }

    fn async_span_begin(
        &mut self,
        observation: &Observation,
        ts_ns: TimestampNs,
        correlation_id: &str,
        name: &str,
    ) {
        let key = AsyncSpanKey {
            source_id: observation.source_id.clone(),
            correlation_id: correlation_id.to_owned(),
        };
        if let Some(open) = self.open_async_spans.get(&key) {
            let prior_begin_ts = open.begin_ts;
            let prior_source_seq = open.source_seq;
            self.push_fact(
                "duplicate_async_begin",
                &observation.source_id,
                Some(observation.source_seq),
                Some(prior_begin_ts),
                Some(ts_ns),
                Properties::from([
                    ("correlation_id".to_owned(), json!(correlation_id)),
                    ("prior_source_seq".to_owned(), json!(prior_source_seq)),
                ]),
            );
            return;
        }
        if self.open_custom_span_count() >= self.config.max_open_custom_spans.max(1) {
            self.record_open_custom_span_limit(observation, ts_ns, "async", correlation_id);
            return;
        }
        self.open_async_spans.insert(
            key,
            OpenCustomSpan {
                source_id: observation.source_id.clone(),
                source_seq: observation.source_seq,
                begin_ts: ts_ns,
                name: name.to_owned(),
            },
        );
    }

    fn async_span_end(
        &mut self,
        observation: &Observation,
        ts_ns: TimestampNs,
        correlation_id: &str,
    ) {
        let key = AsyncSpanKey {
            source_id: observation.source_id.clone(),
            correlation_id: correlation_id.to_owned(),
        };
        if self.open_async_spans.remove(&key).is_none() {
            self.push_fact(
                "unmatched_async_end",
                &observation.source_id,
                Some(observation.source_seq),
                Some(ts_ns),
                Some(ts_ns),
                Properties::from([("correlation_id".to_owned(), json!(correlation_id))]),
            );
        }
    }

    fn open_custom_span_count(&self) -> usize {
        self.open_custom_spans
            .len()
            .saturating_add(self.open_async_spans.len())
    }

    fn record_open_custom_span_limit(
        &mut self,
        observation: &Observation,
        ts_ns: TimestampNs,
        kind: &str,
        identifier: &str,
    ) {
        self.push_fact(
            "open_custom_span_limit_exceeded",
            &observation.source_id,
            Some(observation.source_seq),
            Some(ts_ns),
            Some(ts_ns),
            Properties::from([
                ("kind".to_owned(), json!(kind)),
                ("identifier".to_owned(), json!(identifier)),
                (
                    "limit".to_owned(),
                    json!(self.config.max_open_custom_spans.max(1)),
                ),
            ]),
        );
    }

    fn schedule_context(
        &mut self,
        core_id: u32,
        context_key: ExecutionContextKey,
        scheduled_since: TimestampNs,
    ) {
        let core = self.cores.entry(core_id).or_default();
        if core.scheduled_context.as_ref() == Some(&context_key) {
            return;
        }
        core.scheduled_context = Some(context_key);
        core.scheduled_since = Some(scheduled_since);
    }

    fn advance_core(
        &mut self,
        core_id: u32,
        ts_ns: TimestampNs,
        observation: &Observation,
    ) -> TimestampNs {
        let (last_ts, running) = self
            .cores
            .get(&core_id)
            .map(|core| {
                (
                    core.last_ts,
                    core.running_context()
                        .cloned()
                        .zip(core.running_public_context().map(str::to_owned)),
                )
            })
            .unwrap_or((None, None));
        let effective_ts = if let Some(last_ts) = last_ts {
            if ts_ns < last_ts {
                self.push_fact(
                    "out_of_order_timestamp",
                    &observation.source_id,
                    Some(observation.source_seq),
                    Some(ts_ns),
                    Some(last_ts),
                    Properties::from([
                        ("core_id".to_owned(), json!(core_id)),
                        ("previous_ns".to_owned(), json!(last_ts)),
                        ("actual_ns".to_owned(), json!(ts_ns)),
                    ]),
                );
                if let Some((running, _)) = running.as_ref() {
                    self.mark_context_incomplete(running);
                }
                last_ts
            } else {
                let delta = duration_between(last_ts, ts_ns)
                    .expect("ordered i64 timestamps have a representable u64 duration");
                if delta > 0 {
                    self.detect_concurrent_scheduling(core_id, last_ts, ts_ns, observation);
                    if let Some((running, public_context_id)) = running.as_ref() {
                        self.credit_execution_interval(
                            running,
                            public_context_id,
                            core_id,
                            last_ts,
                            ts_ns,
                        );
                    } else {
                        self.push_fact(
                            "missing_scheduled_context",
                            "analyzer",
                            None,
                            Some(last_ts),
                            Some(ts_ns),
                            Properties::from([("core_id".to_owned(), json!(core_id))]),
                        );
                    }
                }
                ts_ns
            }
        } else {
            ts_ns
        };

        self.cores.entry(core_id).or_default().last_ts = Some(effective_ts);
        self.observe_timestamp(effective_ts);
        effective_ts
    }

    fn credit_execution_interval(
        &mut self,
        context_key: &ExecutionContextKey,
        public_context_id: &str,
        core_id: u32,
        start_ns: TimestampNs,
        end_ns: TimestampNs,
    ) {
        self.ensure_execution_context(context_key, public_context_id);
        let credited_ns = if matches!(context_key, ExecutionContextKey::Scheduled(_)) {
            self.credited_scheduled_duration(context_key, core_id, start_ns, end_ns)
        } else {
            duration_between(start_ns, end_ns)
                .expect("ordered timestamps have a representable duration")
        };

        let context = self
            .contexts
            .get_mut(context_key)
            .expect("execution context was ensured");
        if let Some(next) = context.virtual_cpu_ns.checked_add(credited_ns) {
            context.virtual_cpu_ns = next;
        } else {
            context.virtual_cpu_ns = u64::MAX;
            self.push_fact(
                "duration_overflow",
                "analyzer",
                None,
                Some(start_ns),
                Some(end_ns),
                Properties::from([("context_id".to_owned(), json!(public_context_id))]),
            );
            self.mark_context_incomplete(context_key);
        }
    }

    fn detect_concurrent_scheduling(
        &mut self,
        core_id: u32,
        start_ns: TimestampNs,
        end_ns: TimestampNs,
        observation: &Observation,
    ) {
        let Some(context_key) = self
            .cores
            .get(&core_id)
            .and_then(|core| core.scheduled_context.clone())
        else {
            return;
        };
        let Some(public_context_id) = context_key.scheduled_id().map(str::to_owned) else {
            return;
        };
        let conflicts = self.concurrent_scheduled_cores(&context_key, core_id, start_ns, end_ns);
        if conflicts.is_empty() {
            return;
        }
        self.taint_context(&context_key);

        let mut newly_reported = Vec::new();
        let mut overlap_start = end_ns;
        for (other_core, conflict_start) in conflicts {
            let pair = (core_id.min(other_core), core_id.max(other_core));
            if self
                .reported_concurrent_tasks
                .insert((public_context_id.clone(), pair.0, pair.1))
            {
                newly_reported.push(other_core);
                overlap_start = overlap_start.min(conflict_start);
            }
        }
        if newly_reported.is_empty() {
            return;
        }
        self.push_fact(
            "concurrent_context",
            &observation.source_id,
            Some(observation.source_seq),
            Some(overlap_start),
            Some(end_ns),
            Properties::from([
                ("context_id".to_owned(), json!(public_context_id)),
                ("core_id".to_owned(), json!(core_id)),
                ("conflicting_cores".to_owned(), json!(newly_reported)),
            ]),
        );
    }

    fn concurrent_scheduled_cores(
        &self,
        context_key: &ExecutionContextKey,
        core_id: u32,
        start_ns: TimestampNs,
        end_ns: TimestampNs,
    ) -> Vec<(u32, TimestampNs)> {
        let this_since = self.cores[&core_id].scheduled_since.unwrap_or(start_ns);
        self.cores
            .iter()
            .filter_map(|(other_core_id, other_core)| {
                if *other_core_id == core_id
                    || other_core.scheduled_context.as_ref() != Some(context_key)
                {
                    return None;
                }
                let other_since = other_core.scheduled_since.unwrap_or(start_ns);
                let overlap_start = start_ns.max(this_since).max(other_since);
                (overlap_start < end_ns).then_some((*other_core_id, overlap_start))
            })
            .collect()
    }

    fn credited_scheduled_duration(
        &self,
        context_key: &ExecutionContextKey,
        core_id: u32,
        start_ns: TimestampNs,
        end_ns: TimestampNs,
    ) -> DurationNs {
        let first_lower_core_overlap = self
            .concurrent_scheduled_cores(context_key, core_id, start_ns, end_ns)
            .into_iter()
            .filter(|(other_core, _)| *other_core < core_id)
            .map(|(_, overlap_start)| overlap_start)
            .min();
        let credited_end = first_lower_core_overlap.unwrap_or(end_ns);
        duration_between(start_ns, credited_end).expect("credited scheduling bounds are ordered")
    }

    fn trace_gap(
        &mut self,
        observation: &Observation,
        start_ns: TimestampNs,
        duration_ns: DurationNs,
        reason: &str,
    ) {
        let core_ids = self.cores.keys().copied().collect::<Vec<_>>();
        for core_id in &core_ids {
            self.advance_core(*core_id, start_ns, observation);
        }
        self.mark_all_incomplete();

        let end = start_ns as i128 + duration_ns as i128;
        let end_ns = if end > i64::MAX as i128 {
            self.push_fact(
                "timestamp_overflow",
                &observation.source_id,
                Some(observation.source_seq),
                Some(start_ns),
                Some(i64::MAX),
                Properties::from([("duration_ns".to_owned(), json!(duration_ns))]),
            );
            i64::MAX
        } else {
            end as i64
        };
        for core_id in core_ids {
            let core = self.cores.get_mut(&core_id).expect("gap core exists");
            core.last_ts = Some(core.last_ts.unwrap_or(end_ns).max(end_ns));
        }
        self.observe_timestamp(end_ns);
        if let Some(progress) = self.source_progress.get_mut(&observation.source_id) {
            progress.timestamp = progress.timestamp.max(end_ns);
        }

        let evidence = Properties::from([
            ("duration_ns".to_owned(), json!(duration_ns)),
            ("reason".to_owned(), json!(reason)),
        ]);
        self.push_fact(
            "trace_gap",
            &observation.source_id,
            Some(observation.source_seq),
            Some(start_ns),
            Some(end_ns),
            evidence.clone(),
        );
        if let Some(code) = severe_gap_code(reason) {
            self.push_fact(
                code,
                &observation.source_id,
                Some(observation.source_seq),
                Some(start_ns),
                Some(end_ns),
                evidence,
            );
        }
    }

    fn metadata_health(
        &mut self,
        observation: &Observation,
        ts_ns: TimestampNs,
        key: &str,
        value: &Value,
    ) {
        let normalized = key
            .trim()
            .to_ascii_lowercase()
            .replace(['.', '-', ' '], "_");
        let code = match normalized.as_str() {
            "health_trace_overflow" | "trace_overflow" | "overflow" if truthy(value) => {
                Some("trace_overflow")
            }
            "health_flow_error" | "flow_error" if truthy(value) => Some("flow_error"),
            "health_truncated" | "truncated" | "truncation" if truthy(value) => {
                Some("truncated_input")
            }
            "health_elf_mismatch" | "elf_mismatch" if truthy(value) => Some("elf_mismatch"),
            "health_elf_match" | "elf_match" if falsy(value) => Some("elf_mismatch"),
            "health_out_of_order" | "out_of_order" if truthy(value) => {
                Some("out_of_order_timestamp")
            }
            _ => None,
        };
        if let Some(code) = code {
            self.push_fact(
                code,
                &observation.source_id,
                Some(observation.source_seq),
                Some(ts_ns),
                Some(ts_ns),
                Properties::from([
                    ("key".to_owned(), json!(key)),
                    ("value".to_owned(), value.clone()),
                ]),
            );
        }
    }

    fn add_sample(
        &mut self,
        function_id: Option<&str>,
        address: Option<u64>,
        context_id: Option<&str>,
        weight: u64,
        quality: Quality,
        observation: &Observation,
    ) -> Result<(), AnalysisError> {
        if function_id.is_none() && address.is_none() {
            self.push_fact(
                "flow_error",
                &observation.source_id,
                Some(observation.source_seq),
                Some(observation.ts_ns()),
                Some(observation.ts_ns()),
                Properties::from([("reason".to_owned(), json!("sample_without_identity"))]),
            );
            return Ok(());
        }
        let key = SampleKey {
            function_id: function_id.map(str::to_owned),
            address,
            context_id: context_id.map(str::to_owned),
        };
        let subject = sample_subject(&key);
        let accumulator = self.samples.entry(key).or_insert(SampleAccumulator {
            count: 0,
            weight: 0,
            quality,
        });
        accumulator.count =
            accumulator
                .count
                .checked_add(1)
                .ok_or_else(|| AnalysisError::NumericOverflow {
                    field: "sample_count",
                    subject: subject.clone(),
                })?;
        accumulator.weight = accumulator.weight.checked_add(weight as u128).ok_or(
            AnalysisError::NumericOverflow {
                field: "sample_weight",
                subject,
            },
        )?;
        accumulator.quality = worst_quality(accumulator.quality, quality);
        Ok(())
    }

    fn add_counter(
        &mut self,
        counter_id: &str,
        value: f64,
        quality: Quality,
        observation: &Observation,
    ) -> Result<(), AnalysisError> {
        let ts_ns = observation.ts_ns();
        let standard = self
            .counter_definitions
            .get(counter_id)
            .and_then(|definition| definition.semantic.as_ref())
            .and_then(CounterSemantic::standard_spec);

        if standard.is_some_and(|spec| !spec.value_is_valid(value)) {
            let semantic = self
                .counter_definitions
                .get(counter_id)
                .and_then(|definition| definition.semantic.as_ref())
                .map(CounterSemantic::as_str)
                .map(str::to_owned);
            self.push_resource_fact_once(
                "resource_counter_out_of_range",
                counter_id,
                observation,
                Properties::from([
                    ("counter_id".to_owned(), json!(counter_id)),
                    ("value".to_owned(), json!(value)),
                    ("semantic".to_owned(), json!(semantic)),
                ]),
            );
            return Ok(());
        }

        let previous = self
            .counters
            .get(counter_id)
            .map(|accumulator| accumulator.latest);
        let behavior = standard.map(|spec| spec.behavior);
        let monotonic_decrease = previous.is_some_and(|previous| {
            matches!(
                behavior,
                Some(CounterBehavior::Monotonic | CounterBehavior::HighWatermark)
            ) && value < previous
        });
        let capacity_changed = previous.is_some_and(|previous| {
            behavior == Some(CounterBehavior::Capacity) && value != previous
        });

        if let Some(accumulator) = self.counters.get_mut(counter_id) {
            if !accumulator.add(ts_ns, value, quality) {
                self.push_resource_fact_once(
                    "invalid_resource_counter",
                    counter_id,
                    observation,
                    Properties::from([
                        ("counter_id".to_owned(), json!(counter_id)),
                        ("reason".to_owned(), json!("aggregate_overflow")),
                    ]),
                );
                return Ok(());
            }
            if monotonic_decrease || capacity_changed {
                accumulator.window_valid = false;
            }
        } else {
            self.counters.insert(
                counter_id.to_owned(),
                CounterAccumulator::new(ts_ns, value, quality),
            );
        }

        if monotonic_decrease {
            self.push_resource_fact_once(
                "resource_counter_not_monotonic",
                counter_id,
                observation,
                Properties::from([
                    ("counter_id".to_owned(), json!(counter_id)),
                    ("previous".to_owned(), json!(previous)),
                    ("actual".to_owned(), json!(value)),
                ]),
            );
        }
        if capacity_changed {
            self.push_resource_fact_once(
                "resource_counter_invariant_violation",
                &format!("capacity:{counter_id}"),
                observation,
                Properties::from([
                    ("counter_id".to_owned(), json!(counter_id)),
                    ("invariant".to_owned(), json!("capacity_is_stable")),
                    ("previous".to_owned(), json!(previous)),
                    ("actual".to_owned(), json!(value)),
                ]),
            );
        }

        let tracked_identity = self
            .counter_definitions
            .get(counter_id)
            .and_then(|definition| {
                let semantic = definition.semantic.as_ref()?;
                let tracked = matches!(
                    semantic.as_str(),
                    CounterSemantic::HEAP_FREE_BYTES
                        | CounterSemantic::HEAP_LARGEST_FREE_BLOCK_BYTES
                        | CounterSemantic::STACK_CAPACITY_BYTES
                        | CounterSemantic::STACK_CURRENT_USED_BYTES
                        | CounterSemantic::STACK_PEAK_USED_BYTES
                        | CounterSemantic::TRACE_BUFFER_CAPACITY_BYTES
                        | CounterSemantic::TRACE_BUFFER_CURRENT_USED_BYTES
                        | CounterSemantic::TRACE_BUFFER_PEAK_USED_BYTES
                );
                if tracked {
                    Some((semantic.clone(), definition.subject.as_ref()?.clone()))
                } else {
                    None
                }
            });
        if let Some((semantic, subject)) = tracked_identity {
            let point = CounterPoint {
                ts_ns,
                value,
                quality,
            };
            self.update_fragmentation(&semantic, &subject, point, counter_id, observation);
            self.update_usage_invariants(&semantic, &subject, point, counter_id, observation);
        }
        Ok(())
    }

    fn update_fragmentation(
        &mut self,
        semantic: &CounterSemantic,
        subject: &CounterSubject,
        point: CounterPoint,
        counter_id: &str,
        observation: &Observation,
    ) {
        let is_free = semantic.as_str() == CounterSemantic::HEAP_FREE_BYTES;
        let is_largest = semantic.as_str() == CounterSemantic::HEAP_LARGEST_FREE_BLOCK_BYTES;
        if !is_free && !is_largest {
            return;
        }
        let evaluation = {
            let state = self.fragmentation.entry(subject.clone()).or_default();
            if is_free {
                state.free = Some(point);
            } else {
                state.largest = Some(point);
            }
            match (state.free, state.largest) {
                (Some(free), Some(largest)) if free.ts_ns == largest.ts_ns => {
                    let evaluation = if free.value == 0.0 {
                        FragmentationEvaluation {
                            ts_ns: free.ts_ns,
                            value: None,
                            quality: worst_quality(free.quality, largest.quality),
                            reason: Some("free_bytes_zero"),
                        }
                    } else if largest.value > free.value {
                        FragmentationEvaluation {
                            ts_ns: free.ts_ns,
                            value: None,
                            quality: worst_quality(free.quality, largest.quality),
                            reason: Some("largest_free_block_exceeds_free_bytes"),
                        }
                    } else {
                        FragmentationEvaluation {
                            ts_ns: free.ts_ns,
                            value: Some(1.0 - largest.value / free.value),
                            quality: worst_quality(free.quality, largest.quality),
                            reason: None,
                        }
                    };
                    state.latest = Some(evaluation);
                    Some(evaluation)
                }
                _ => None,
            }
        };
        if evaluation.is_some_and(|evaluation| {
            evaluation.reason == Some("largest_free_block_exceeds_free_bytes")
        }) {
            self.push_resource_fact_once(
                "resource_counter_invariant_violation",
                &format!("fragmentation:{}", subject_key(subject)),
                observation,
                Properties::from([
                    ("counter_id".to_owned(), json!(counter_id)),
                    ("subject".to_owned(), json!(subject)),
                    (
                        "invariant".to_owned(),
                        json!("largest_free_block_bytes_lte_free_bytes"),
                    ),
                ]),
            );
        }
    }

    fn update_usage_invariants(
        &mut self,
        semantic: &CounterSemantic,
        subject: &CounterSubject,
        point: CounterPoint,
        counter_id: &str,
        observation: &Observation,
    ) {
        let slot = match semantic.as_str() {
            CounterSemantic::STACK_CAPACITY_BYTES
            | CounterSemantic::TRACE_BUFFER_CAPACITY_BYTES => UsageSlot::Capacity,
            CounterSemantic::STACK_CURRENT_USED_BYTES
            | CounterSemantic::TRACE_BUFFER_CURRENT_USED_BYTES => UsageSlot::Current,
            CounterSemantic::STACK_PEAK_USED_BYTES
            | CounterSemantic::TRACE_BUFFER_PEAK_USED_BYTES => UsageSlot::Peak,
            _ => return,
        };
        let violations = {
            let state = self.usage_invariants.entry(subject.clone()).or_default();
            match slot {
                UsageSlot::Capacity => state.capacity = Some(point),
                UsageSlot::Current => state.current = Some(point),
                UsageSlot::Peak => state.peak = Some(point),
            }
            let mut violations = Vec::new();
            if let (Some(current), Some(peak)) = (state.current, state.peak)
                && current.value > peak.value
            {
                violations.push(("current_lte_peak", current.value, peak.value));
            }
            if let (Some(peak), Some(capacity)) = (state.peak, state.capacity)
                && peak.value > capacity.value
            {
                violations.push(("peak_lte_capacity", peak.value, capacity.value));
            }
            if let (Some(current), Some(capacity)) = (state.current, state.capacity)
                && current.value > capacity.value
            {
                violations.push(("current_lte_capacity", current.value, capacity.value));
            }
            violations
        };
        for (invariant, left, right) in violations {
            self.push_resource_fact_once(
                "resource_counter_invariant_violation",
                &format!("{invariant}:{}", subject_key(subject)),
                observation,
                Properties::from([
                    ("counter_id".to_owned(), json!(counter_id)),
                    ("semantic".to_owned(), json!(semantic)),
                    ("subject".to_owned(), json!(subject)),
                    ("invariant".to_owned(), json!(invariant)),
                    ("left".to_owned(), json!(left)),
                    ("right".to_owned(), json!(right)),
                ]),
            );
        }
    }

    fn push_resource_fact_once(
        &mut self,
        code: &'static str,
        subject: &str,
        observation: &Observation,
        evidence: Properties,
    ) {
        if self.reported_resource_issues.insert(ResourceIssueKey {
            code,
            subject: subject.to_owned(),
        }) {
            self.push_fact(
                code,
                &observation.source_id,
                Some(observation.source_seq),
                Some(observation.ts_ns()),
                Some(observation.ts_ns()),
                evidence,
            );
        }
    }

    fn effective_resource_capability(&self) -> MetricSupportEntry {
        let Some(quality) = self
            .counters
            .values()
            .map(|accumulator| accumulator.quality)
            .max()
        else {
            return MetricSupportEntry::unavailable("no_resource_counters_observed");
        };
        support_with_quality(&self.config.capabilities.resource_counters, quality)
    }

    fn build_summary(
        &self,
        resource_support: &MetricSupportEntry,
    ) -> Result<AnalysisSummary, AnalysisError> {
        let mut context_totals = self.retired_context_cpu.clone();
        for (context_key, context) in &self.contexts {
            let public_context_id = self
                .context_public_ids
                .get(context_key)
                .cloned()
                .or_else(|| context_key.scheduled_id().map(str::to_owned))
                .expect("every execution context has a public attribution");
            let total = context_totals.entry(public_context_id.clone()).or_default();
            *total = total.checked_add(context.virtual_cpu_ns).ok_or(
                AnalysisError::NumericOverflow {
                    field: "context_cpu_ns",
                    subject: public_context_id,
                },
            )?;
        }
        let context_cpu = context_totals
            .into_iter()
            .map(|(context_id, active_ns)| ContextCpuSummary {
                kind: self
                    .context_kinds
                    .get(&context_id)
                    .copied()
                    .unwrap_or(ContextKind::Unknown),
                context_id,
                active_ns,
            })
            .collect::<Vec<_>>();

        let mut task_cpu_ns = 0_u64;
        let mut isr_cpu_ns = 0_u64;
        let mut idle_cpu_ns = 0_u64;
        for context in &context_cpu {
            let total = match context.kind {
                ContextKind::Task => &mut task_cpu_ns,
                ContextKind::Isr => &mut isr_cpu_ns,
                ContextKind::Idle => &mut idle_cpu_ns,
                ContextKind::Core | ContextKind::Unknown => continue,
            };
            *total = total.checked_add(context.active_ns).ok_or_else(|| {
                AnalysisError::NumericOverflow {
                    field: "context_cpu_total",
                    subject: format!("{:?}", context.kind),
                }
            })?;
        }

        let mut counters = self
            .counters
            .iter()
            .map(|(counter_id, accumulator)| {
                let definition = self.counter_definitions.get(counter_id);
                let semantic = definition.and_then(|definition| definition.semantic.clone());
                let subject = definition.and_then(|definition| definition.subject.clone());
                let behavior = semantic
                    .as_ref()
                    .and_then(CounterSemantic::standard_spec)
                    .map(|spec| spec.behavior);
                let trusted_window = accumulator.window_valid
                    || !matches!(
                        behavior,
                        Some(
                            CounterBehavior::Monotonic
                                | CounterBehavior::HighWatermark
                                | CounterBehavior::Capacity
                        )
                    );
                let delta = (accumulator.count >= 2 && trusted_window)
                    .then_some(accumulator.latest - accumulator.first);
                let window_ns = duration_between(accumulator.first_ts_ns, accumulator.last_ts_ns)
                    .filter(|duration| *duration != 0);
                let rate_per_second = if behavior == Some(CounterBehavior::Monotonic) {
                    delta
                        .zip(window_ns)
                        .map(|(delta, window_ns)| delta * 1_000_000_000.0 / window_ns as f64)
                        .filter(|rate| rate.is_finite() && *rate >= 0.0)
                } else {
                    None
                };
                ResourceCounterSummary {
                    counter_id: counter_id.clone(),
                    name: definition.map(|definition| definition.name.clone()),
                    unit: definition.and_then(|definition| definition.unit.clone()),
                    semantic,
                    subject,
                    class: definition
                        .and_then(|definition| definition.semantic.as_ref())
                        .and_then(CounterSemantic::standard_spec)
                        .map_or(ResourceClass::Other, |spec| spec.class),
                    sample_count: accumulator.count,
                    first_ts_ns: Some(accumulator.first_ts_ns),
                    last_ts_ns: Some(accumulator.last_ts_ns),
                    first: Some(accumulator.first),
                    latest: accumulator.latest,
                    min: accumulator.min,
                    max: accumulator.max,
                    mean: accumulator.mean,
                    delta,
                    window_ns,
                    rate_per_second,
                    quality: accumulator.quality,
                    support: support_with_quality(resource_support, accumulator.quality),
                }
            })
            .collect::<Vec<_>>();
        counters.sort_by(|left, right| left.counter_id.cmp(&right.counter_id));
        let derived = self.build_derived_resource_metrics(resource_support);

        Ok(AnalysisSummary {
            observation_count: self.observation_count,
            function_span_count: self.function_span_count,
            incomplete_function_span_count: self.incomplete_function_span_count,
            call_depth: CallDepthSummary {
                max_depth: self.max_depth,
                context_id: self.deepest_context.clone(),
                deepest_path: self.deepest_path.clone(),
            },
            context_cpu,
            task_cpu_ns,
            isr_cpu_ns,
            idle_cpu_ns,
            resources: ResourceSummary { counters, derived },
        })
    }

    fn build_derived_resource_metrics(
        &self,
        resource_support: &MetricSupportEntry,
    ) -> Vec<DerivedResourceMetricSummary> {
        let allocation_count = standard_semantic(CounterSemantic::HEAP_ALLOCATION_COUNT);
        let allocation_rate = standard_semantic(CounterSemantic::HEAP_ALLOCATION_RATE_PER_SECOND);
        let free_bytes = standard_semantic(CounterSemantic::HEAP_FREE_BYTES);
        let largest_free = standard_semantic(CounterSemantic::HEAP_LARGEST_FREE_BLOCK_BYTES);
        let fragmentation = standard_semantic(CounterSemantic::HEAP_EXTERNAL_FRAGMENTATION_RATIO);
        let mut derived = Vec::new();

        for ((semantic, subject), counter_id) in &self.counter_identity_index {
            if semantic != &allocation_count
                || self
                    .counter_identity_index
                    .contains_key(&(allocation_rate.clone(), subject.clone()))
            {
                continue;
            }
            let accumulator = self.counters.get(counter_id);
            let quality = accumulator.map(|accumulator| accumulator.quality);
            let mut support = quality.map_or_else(
                || MetricSupportEntry::unavailable("allocation_count_not_observed"),
                |quality| support_with_quality(resource_support, quality),
            );
            let (value, first_ts_ns, last_ts_ns, window_ns) = match accumulator {
                Some(accumulator) if !accumulator.window_valid => {
                    lower_support(
                        &mut support,
                        MetricSupportLevel::Unavailable,
                        "allocation_count_not_monotonic",
                    );
                    (
                        None,
                        Some(accumulator.first_ts_ns),
                        Some(accumulator.last_ts_ns),
                        None,
                    )
                }
                Some(accumulator) if accumulator.count < 2 => {
                    lower_support(
                        &mut support,
                        MetricSupportLevel::Unavailable,
                        "allocation_rate_requires_two_samples",
                    );
                    (
                        None,
                        Some(accumulator.first_ts_ns),
                        Some(accumulator.last_ts_ns),
                        None,
                    )
                }
                Some(accumulator) => {
                    let window = duration_between(accumulator.first_ts_ns, accumulator.last_ts_ns)
                        .filter(|duration| *duration != 0);
                    let value = window
                        .map(|window| {
                            (accumulator.latest - accumulator.first) * 1_000_000_000.0
                                / window as f64
                        })
                        .filter(|value| value.is_finite() && *value >= 0.0);
                    if value.is_none() {
                        lower_support(
                            &mut support,
                            MetricSupportLevel::Unavailable,
                            "allocation_rate_window_not_positive",
                        );
                    }
                    (
                        support.is_available().then_some(value).flatten(),
                        Some(accumulator.first_ts_ns),
                        Some(accumulator.last_ts_ns),
                        window,
                    )
                }
                None => (None, None, None, None),
            };
            derived.push(DerivedResourceMetricSummary {
                semantic: allocation_rate.clone(),
                subject: subject.clone(),
                unit: "1/s".to_owned(),
                value,
                source_counter_ids: vec![counter_id.clone()],
                first_ts_ns,
                last_ts_ns,
                window_ns,
                quality,
                support,
            });
        }

        let fragmentation_subjects = self
            .counter_identity_index
            .keys()
            .filter(|(semantic, _)| semantic == &free_bytes || semantic == &largest_free)
            .map(|(_, subject)| subject.clone())
            .collect::<BTreeSet<_>>();
        for subject in fragmentation_subjects {
            if self
                .counter_identity_index
                .contains_key(&(fragmentation.clone(), subject.clone()))
            {
                continue;
            }
            let free_id = self
                .counter_identity_index
                .get(&(free_bytes.clone(), subject.clone()));
            let largest_id = self
                .counter_identity_index
                .get(&(largest_free.clone(), subject.clone()));
            let mut source_counter_ids = [free_id, largest_id]
                .into_iter()
                .flatten()
                .cloned()
                .collect::<Vec<_>>();
            source_counter_ids.sort();
            let evaluation = self
                .fragmentation
                .get(&subject)
                .and_then(|state| state.latest);
            let quality = evaluation.map(|evaluation| evaluation.quality);
            let mut support = quality.map_or_else(
                || MetricSupportEntry::unavailable("fragmentation_inputs_not_synchronized"),
                |quality| support_with_quality(resource_support, quality),
            );
            if free_id.is_none() || largest_id.is_none() {
                lower_support(
                    &mut support,
                    MetricSupportLevel::Unavailable,
                    "fragmentation_input_counter_missing",
                );
            }
            if let Some(reason) = evaluation.and_then(|evaluation| evaluation.reason) {
                lower_support(&mut support, MetricSupportLevel::Unavailable, reason);
            }
            let value = evaluation
                .and_then(|evaluation| evaluation.value)
                .filter(|_| support.is_available());
            let timestamp = evaluation.map(|evaluation| evaluation.ts_ns);
            derived.push(DerivedResourceMetricSummary {
                semantic: fragmentation.clone(),
                subject,
                unit: "ratio".to_owned(),
                value,
                source_counter_ids,
                first_ts_ns: timestamp,
                last_ts_ns: timestamp,
                window_ns: None,
                quality,
                support,
            });
        }

        derived.sort_by(|left, right| {
            left.semantic
                .cmp(&right.semantic)
                .then_with(|| left.subject.cmp(&right.subject))
        });
        derived
    }

    fn mark_context_incomplete(&mut self, context_key: &ExecutionContextKey) {
        if let Some(context) = self.contexts.get_mut(context_key) {
            for frame in &mut context.frames {
                frame.incomplete = true;
                frame.quality = worst_quality(frame.quality, Quality::Inferred);
            }
        }
    }

    fn taint_context(&mut self, context_key: &ExecutionContextKey) {
        if let Some(context) = self.contexts.get_mut(context_key) {
            context.tainted = true;
            for frame in &mut context.frames {
                frame.incomplete = true;
                frame.quality = worst_quality(frame.quality, Quality::Inferred);
            }
        }
    }

    fn mark_all_incomplete(&mut self) {
        for context in self.contexts.values_mut() {
            for frame in &mut context.frames {
                frame.incomplete = true;
                frame.quality = worst_quality(frame.quality, Quality::Inferred);
            }
        }
    }

    fn push_fact(
        &mut self,
        code: impl Into<String>,
        source: impl Into<String>,
        record: Option<u64>,
        start_ns: Option<TimestampNs>,
        end_ns: Option<TimestampNs>,
        evidence: Properties,
    ) {
        self.store_health_observation(HealthObservation {
            code: code.into(),
            source: source.into(),
            artifact_id: None,
            record,
            start_ns,
            end_ns,
            evidence,
        });
    }

    fn store_health_observation(&mut self, observation: HealthObservation) {
        let observation =
            if observation.code.trim().is_empty() || observation.source.trim().is_empty() {
                HealthObservation {
                    code: "invalid_health_observation".to_owned(),
                    source: "analyzer".to_owned(),
                    artifact_id: observation.artifact_id,
                    record: observation.record,
                    start_ns: observation.start_ns,
                    end_ns: observation.end_ns,
                    evidence: Properties::from([
                        (
                            "empty_code".to_owned(),
                            json!(observation.code.trim().is_empty()),
                        ),
                        (
                            "empty_source".to_owned(),
                            json!(observation.source.trim().is_empty()),
                        ),
                    ]),
                }
            } else {
                observation
            };
        let limit = self.config.max_health_observations.max(1);
        if !self.health_diagnostics_truncated && self.health_observations.len() < limit {
            self.health_observations.push(observation);
            return;
        }

        if !self.health_diagnostics_truncated {
            self.health_diagnostics_truncated = true;
            self.dropped_health_observation_count = 2;
            if self.health_observations.len() == limit {
                self.health_observations.pop();
            }
            self.health_observations.push(HealthObservation {
                code: "diagnostics_truncated".to_owned(),
                source: "analyzer".to_owned(),
                artifact_id: None,
                record: observation.record,
                start_ns: observation.start_ns,
                end_ns: observation.end_ns,
                evidence: Properties::from([
                    ("limit".to_owned(), json!(limit)),
                    (
                        "dropped_observations".to_owned(),
                        json!(self.dropped_health_observation_count),
                    ),
                ]),
            });
            return;
        }

        self.dropped_health_observation_count = self
            .dropped_health_observation_count
            .checked_add(1)
            .expect("a process cannot supply u64::MAX health observations");

        if let Some(sentinel) = self
            .health_observations
            .iter_mut()
            .find(|observation| observation.code == "diagnostics_truncated")
        {
            sentinel.evidence.insert(
                "dropped_observations".to_owned(),
                json!(self.dropped_health_observation_count),
            );
        }
    }

    fn observe_timestamp(&mut self, ts_ns: TimestampNs) {
        self.max_ts = Some(self.max_ts.map_or(ts_ns, |current| current.max(ts_ns)));
    }
}

/// An analyzer input or output invariant violation.
#[derive(Debug, Error)]
pub enum AnalysisError {
    /// The analyzer was created without a Session identifier.
    #[error("analyzer session_id is empty")]
    EmptySessionId,
    /// A dictionary belongs to another session.
    #[error("dictionary session `{actual}` does not match analyzer session `{expected}`")]
    SessionMismatch {
        /// Analyzer session identifier.
        expected: String,
        /// Dictionary session identifier.
        actual: String,
    },
    /// The observation dictionary is invalid.
    #[error(transparent)]
    InvalidDictionary(#[from] DictionaryValidationError),
    /// A normalized observation is invalid.
    #[error(transparent)]
    InvalidObservation(#[from] ObservationValidationError),
    /// Reconstructed derived data violates the model contract.
    #[error(transparent)]
    InvalidDerived(#[from] DerivedValidationError),
    /// Generated hotspot data violates the model contract.
    #[error(transparent)]
    InvalidHotspots(#[from] HotspotValidationError),
    /// Generated health data violates the model contract.
    #[error(transparent)]
    InvalidHealth(#[from] HealthValidationError),
    /// Two dictionaries define the same counter ID differently.
    #[error("counter `{counter_id}` has conflicting dictionary definitions")]
    ConflictingCounterDefinition {
        /// Conflicting counter identifier.
        counter_id: String,
    },
    /// Two dictionaries assign different counter IDs to one semantic subject.
    #[error(
        "counter `{counter_id}` conflicts with `{existing_counter_id}` for semantic `{semantic}`"
    )]
    ConflictingCounterSubject {
        /// Later counter identifier.
        counter_id: String,
        /// Previously registered counter identifier.
        existing_counter_id: String,
        /// Duplicated semantic identity.
        semantic: CounterSemantic,
    },
    /// An aggregate cannot be represented by its public numeric type.
    #[error("numeric overflow in `{field}` for `{subject}`")]
    NumericOverflow {
        /// Aggregate or field that overflowed.
        field: &'static str,
        /// Context, function, counter, or session associated with the overflow.
        subject: String,
    },
}

#[derive(Debug, Clone, Default)]
struct CoreState {
    scheduled_context: Option<ExecutionContextKey>,
    scheduled_since: Option<TimestampNs>,
    interrupts: Vec<InterruptActivation>,
    last_ts: Option<TimestampNs>,
}

impl CoreState {
    fn running_context(&self) -> Option<&ExecutionContextKey> {
        self.interrupts
            .last()
            .map(|activation| &activation.execution_context)
            .or(self.scheduled_context.as_ref())
    }

    fn running_public_context(&self) -> Option<&str> {
        self.interrupts
            .last()
            .map(|activation| activation.interrupt_id.as_str())
            .or_else(|| {
                self.scheduled_context
                    .as_ref()
                    .and_then(ExecutionContextKey::scheduled_id)
            })
    }
}

#[derive(Debug, Clone)]
struct InterruptActivation {
    interrupt_id: String,
    activation_id: String,
    execution_context: ExecutionContextKey,
    entered_ts: TimestampNs,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ExecutionContextKey {
    Scheduled(String),
    InterruptActivation {
        core_id: u32,
        activation_id: String,
        serial: u64,
    },
}

impl ExecutionContextKey {
    fn scheduled(context_id: impl Into<String>) -> Self {
        Self::Scheduled(context_id.into())
    }

    fn scheduled_id(&self) -> Option<&str> {
        match self {
            Self::Scheduled(context_id) => Some(context_id),
            Self::InterruptActivation { .. } => None,
        }
    }
}

#[derive(Debug, Default)]
struct ContextState {
    virtual_cpu_ns: DurationNs,
    frames: Vec<OpenFrame>,
    tainted: bool,
}

#[derive(Debug)]
struct OpenFrame {
    source_id: String,
    source_seq_start: u64,
    core_id: u32,
    public_context_id: String,
    function_id: String,
    frame_id: Option<String>,
    start_wall_ns: TimestampNs,
    start_virtual_ns: DurationNs,
    child_active_ns: DurationNs,
    quality: Quality,
    incomplete: bool,
}

#[derive(Debug, Clone, Copy)]
struct SourceProgress {
    sequence: u64,
    timestamp: TimestampNs,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CustomSpanKey {
    source_id: String,
    core_id: Option<u32>,
    context_id: Option<String>,
    span_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AsyncSpanKey {
    source_id: String,
    correlation_id: String,
}

#[derive(Debug, Clone)]
struct OpenCustomSpan {
    source_id: String,
    source_seq: u64,
    begin_ts: TimestampNs,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SampleKey {
    function_id: Option<String>,
    address: Option<u64>,
    context_id: Option<String>,
}

#[derive(Debug, Clone)]
struct SampleAccumulator {
    count: u64,
    weight: u128,
    quality: Quality,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CounterDefinition {
    name: String,
    unit: Option<String>,
    semantic: Option<CounterSemantic>,
    subject: Option<CounterSubject>,
}

#[derive(Debug, Clone)]
struct CounterAccumulator {
    count: u64,
    first_ts_ns: TimestampNs,
    last_ts_ns: TimestampNs,
    first: f64,
    latest: f64,
    min: f64,
    max: f64,
    mean: f64,
    quality: Quality,
    window_valid: bool,
}

impl CounterAccumulator {
    fn new(ts_ns: TimestampNs, value: f64, quality: Quality) -> Self {
        Self {
            count: 1,
            first_ts_ns: ts_ns,
            last_ts_ns: ts_ns,
            first: value,
            latest: value,
            min: value,
            max: value,
            mean: value,
            quality,
            window_valid: true,
        }
    }

    fn add(&mut self, ts_ns: TimestampNs, value: f64, quality: Quality) -> bool {
        let Some(count) = self.count.checked_add(1) else {
            return false;
        };
        let mean = self.mean + (value - self.mean) / count as f64;
        if !mean.is_finite() {
            return false;
        }
        self.count = count;
        self.last_ts_ns = ts_ns;
        self.latest = value;
        self.min = self.min.min(value);
        self.max = self.max.max(value);
        self.mean = mean;
        self.quality = worst_quality(self.quality, quality);
        true
    }
}

#[derive(Debug, Clone, Copy)]
struct CounterPoint {
    ts_ns: TimestampNs,
    value: f64,
    quality: Quality,
}

#[derive(Debug, Clone, Copy)]
struct FragmentationEvaluation {
    ts_ns: TimestampNs,
    value: Option<f64>,
    quality: Quality,
    reason: Option<&'static str>,
}

#[derive(Debug, Clone, Default)]
struct FragmentationAccumulator {
    free: Option<CounterPoint>,
    largest: Option<CounterPoint>,
    latest: Option<FragmentationEvaluation>,
}

#[derive(Debug, Clone, Default)]
struct UsageInvariantState {
    capacity: Option<CounterPoint>,
    current: Option<CounterPoint>,
    peak: Option<CounterPoint>,
}

#[derive(Debug, Clone, Copy)]
enum UsageSlot {
    Capacity,
    Current,
    Peak,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ResourceIssueKey {
    code: &'static str,
    subject: String,
}

#[derive(Debug, Clone, Default)]
struct HotspotAccumulator {
    inclusive_active_ns: DurationNs,
    self_active_ns: DurationNs,
    count: u64,
    min_active_ns: DurationNs,
    max_active_ns: DurationNs,
    quality: Option<Quality>,
}

impl HotspotAccumulator {
    fn add_span(&mut self, span: &FunctionSpan) -> Result<(), AnalysisError> {
        self.inclusive_active_ns = self
            .inclusive_active_ns
            .checked_add(span.active_ns)
            .ok_or_else(|| AnalysisError::NumericOverflow {
                field: "hotspot_inclusive_active_ns",
                subject: span.function_id.clone(),
            })?;
        self.self_active_ns = self
            .self_active_ns
            .checked_add(span.self_active_ns)
            .ok_or_else(|| AnalysisError::NumericOverflow {
                field: "hotspot_self_active_ns",
                subject: span.function_id.clone(),
            })?;
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| AnalysisError::NumericOverflow {
                field: "hotspot_count",
                subject: span.function_id.clone(),
            })?;
        self.min_active_ns = if self.count == 1 {
            span.active_ns
        } else {
            self.min_active_ns.min(span.active_ns)
        };
        self.max_active_ns = self.max_active_ns.max(span.active_ns);
        self.quality = Some(
            self.quality
                .map_or(span.quality, |quality| worst_quality(quality, span.quality)),
        );
        Ok(())
    }
}

fn build_hotspots(
    session_id: &str,
    functions: &BTreeMap<String, HotspotAccumulator>,
    samples: &BTreeMap<SampleKey, SampleAccumulator>,
    verdict: HealthVerdict,
) -> Result<HotspotReport, AnalysisError> {
    if verdict == HealthVerdict::Invalid {
        return Ok(HotspotReport::new(session_id, Quality::Inferred));
    }

    let mut function_rows = functions
        .iter()
        .map(|(function_id, aggregate)| FunctionHotspot {
            function_id: function_id.clone(),
            context_id: None,
            inclusive_active_ns: aggregate.inclusive_active_ns,
            self_active_ns: aggregate.self_active_ns,
            count: aggregate.count,
            min_active_ns: aggregate.min_active_ns,
            max_active_ns: aggregate.max_active_ns,
            avg_active_ns: aggregate.inclusive_active_ns / aggregate.count,
            incomplete_count: 0,
            quality: if verdict == HealthVerdict::Degraded {
                Quality::Inferred
            } else {
                aggregate.quality.unwrap_or(Quality::Exact)
            },
        })
        .collect::<Vec<_>>();
    function_rows.sort_by(|left, right| {
        right
            .self_active_ns
            .cmp(&left.self_active_ns)
            .then_with(|| left.function_id.cmp(&right.function_id))
    });

    let total_weight = samples.values().try_fold(0_u128, |total, sample| {
        total
            .checked_add(sample.weight)
            .ok_or_else(|| AnalysisError::NumericOverflow {
                field: "sample_total_weight",
                subject: session_id.to_owned(),
            })
    })?;
    let mut sampling_rows = samples
        .iter()
        .map(|(key, sample)| SamplingHotspot {
            function_id: key.function_id.clone(),
            address: key.address,
            context_id: key.context_id.clone(),
            sample_count: sample.count,
            estimated_share: if total_weight == 0 {
                0.0
            } else {
                sample.weight as f64 / total_weight as f64
            },
            quality: Quality::Statistical,
        })
        .collect::<Vec<_>>();
    sampling_rows.sort_by(|left, right| {
        right
            .estimated_share
            .total_cmp(&left.estimated_share)
            .then_with(|| left.function_id.cmp(&right.function_id))
            .then_with(|| left.address.cmp(&right.address))
    });

    let quality = if verdict == HealthVerdict::Degraded {
        Quality::Inferred
    } else if function_rows.is_empty() && !sampling_rows.is_empty() {
        Quality::Statistical
    } else {
        function_rows
            .iter()
            .map(|row| row.quality)
            .max()
            .unwrap_or(Quality::Exact)
    };
    Ok(HotspotReport {
        schema: t32perf_model::HotspotsSchemaVersion,
        session_id: session_id.to_owned(),
        quality,
        functions: function_rows,
        sampling: sampling_rows,
    })
}

fn sample_subject(key: &SampleKey) -> String {
    key.function_id
        .clone()
        .or_else(|| key.address.map(|address| format!("address:{address:x}")))
        .unwrap_or_else(|| "unknown_sample".to_owned())
}

fn frame_matches(frame: &OpenFrame, function_id: &str, frame_id: Option<&str>) -> bool {
    frame.function_id == function_id
        && frame_id.is_none_or(|frame_id| frame.frame_id.as_deref() == Some(frame_id))
}

fn duration_between(start_ns: TimestampNs, end_ns: TimestampNs) -> Option<DurationNs> {
    u64::try_from(end_ns as i128 - start_ns as i128).ok()
}

fn worst_quality(left: Quality, right: Quality) -> Quality {
    left.max(right)
}

fn standard_semantic(value: &'static str) -> CounterSemantic {
    CounterSemantic::new(value).expect("built-in counter semantics are valid")
}

fn subject_key(subject: &CounterSubject) -> String {
    serde_json::to_string(subject).expect("counter subjects always serialize")
}

fn support_with_quality(base: &MetricSupportEntry, quality: Quality) -> MetricSupportEntry {
    let mut support = base.clone();
    let (level, reason) = match quality {
        Quality::Exact => (MetricSupportLevel::Exact, None),
        Quality::Inferred => (
            MetricSupportLevel::Inferred,
            Some("resource_counter_observation_inferred"),
        ),
        Quality::Statistical => (
            MetricSupportLevel::Statistical,
            Some("resource_counter_observation_statistical"),
        ),
    };
    if let Some(reason) = reason {
        lower_support(&mut support, level, reason);
    }
    support
}

fn lower_support(support: &mut MetricSupportEntry, level: MetricSupportLevel, reason: &str) {
    if metric_support_rank(level) > metric_support_rank(support.support) {
        support.support = level;
    }
    if !support.reasons.iter().any(|existing| existing == reason) {
        support.reasons.push(reason.to_owned());
    }
}

fn metric_support_rank(level: MetricSupportLevel) -> u8 {
    match level {
        MetricSupportLevel::Exact => 0,
        MetricSupportLevel::Inferred => 1,
        MetricSupportLevel::Statistical => 2,
        MetricSupportLevel::Unavailable => 3,
    }
}

fn infer_scheduled_context_kind(context_id: &str) -> ContextKind {
    if context_id.to_ascii_lowercase().contains("idle") {
        ContextKind::Idle
    } else {
        ContextKind::Task
    }
}

fn severe_gap_code(reason: &str) -> Option<&'static str> {
    let reason = reason.to_ascii_lowercase();
    if reason.contains("overflow")
        || (reason.contains("fifo") && reason.contains("full"))
        || (reason.contains("buffer") && reason.contains("full"))
    {
        Some("trace_overflow")
    } else if reason.contains("flow") && reason.contains("error") {
        Some("flow_error")
    } else if reason.contains("truncat") {
        Some("truncated_input")
    } else if reason.contains("elf") && reason.contains("mismatch") {
        Some("elf_mismatch")
    } else if reason.contains("out") && reason.contains("order") {
        Some("out_of_order_timestamp")
    } else {
        None
    }
}

fn truthy(value: &Value) -> bool {
    value.as_bool().unwrap_or(false)
        || value.as_u64().is_some_and(|value| value != 0)
        || value.as_str().is_some_and(|value| {
            matches!(value.to_ascii_lowercase().as_str(), "true" | "yes" | "1")
        })
}

fn falsy(value: &Value) -> bool {
    value.as_bool() == Some(false)
        || value.as_u64() == Some(0)
        || value.as_str().is_some_and(|value| {
            matches!(value.to_ascii_lowercase().as_str(), "false" | "no" | "0")
        })
}

fn synthetic_observation(ts_ns: TimestampNs) -> Observation {
    Observation::new(
        "analyzer",
        u64::MAX,
        Quality::Inferred,
        ObservationEvent::Metadata {
            ts_ns,
            key: "analysis.finish".to_owned(),
            value: Value::Null,
        },
    )
}

#[cfg(test)]
mod resident_state_tests {
    use super::*;
    use crate::AnalysisCapabilities;

    fn exact_config() -> AnalyzerConfig {
        AnalyzerConfig {
            capabilities: AnalysisCapabilities::exact_program_flow(),
            ..AnalyzerConfig::default()
        }
    }

    #[test]
    fn one_million_interrupt_boundaries_keep_activation_state_bounded() {
        const ACTIVATIONS: u64 = 500_000;

        let mut analyzer = Analyzer::new("isr-scale", exact_config());
        analyzer
            .ingest(&Observation::new(
                "scale",
                0,
                Quality::Exact,
                ObservationEvent::ContextSwitch {
                    ts_ns: 0,
                    core_id: 0,
                    prev_context_id: None,
                    next_context_id: "task".to_owned(),
                    reason: None,
                },
            ))
            .unwrap();

        let mut max_resident_contexts = 0_usize;
        let mut max_resident_public_ids = 0_usize;
        for activation in 0..ACTIVATIONS {
            let enter_sequence = activation * 2 + 1;
            let exit_sequence = enter_sequence + 1;
            analyzer
                .ingest(&Observation::new(
                    "scale",
                    enter_sequence,
                    Quality::Exact,
                    ObservationEvent::InterruptEnter {
                        ts_ns: (activation * 2) as i64,
                        core_id: 0,
                        interrupt_id: "irq".to_owned(),
                        priority: Some(1),
                        activation_id: "activation".to_owned(),
                    },
                ))
                .unwrap();
            analyzer
                .ingest(&Observation::new(
                    "scale",
                    exit_sequence,
                    Quality::Exact,
                    ObservationEvent::InterruptExit {
                        ts_ns: (activation * 2 + 1) as i64,
                        core_id: 0,
                        interrupt_id: "irq".to_owned(),
                        priority: Some(1),
                        activation_id: "activation".to_owned(),
                    },
                ))
                .unwrap();
            max_resident_contexts = max_resident_contexts.max(analyzer.contexts.len());
            max_resident_public_ids =
                max_resident_public_ids.max(analyzer.context_public_ids.len());
        }

        assert_eq!(max_resident_contexts, 1);
        assert_eq!(max_resident_public_ids, 1);
        assert!(analyzer.cores[&0].interrupts.is_empty());
        assert_eq!(analyzer.retired_context_cpu.len(), 1);
        assert!(analyzer.health_observations.is_empty());

        let result = analyzer.finish(None).unwrap();
        assert_eq!(result.health.verdict, HealthVerdict::Valid);
        assert_eq!(result.summary.isr_cpu_ns, ACTIVATIONS);
    }

    #[test]
    fn one_million_malicious_begins_respect_open_state_and_health_limits() {
        const BEGINS: u64 = 1_000_000;
        const OPEN_LIMIT: usize = 32;
        const HEALTH_LIMIT: usize = 8;

        let mut analyzer = Analyzer::new(
            "custom-scale",
            AnalyzerConfig {
                capabilities: AnalysisCapabilities::exact_program_flow(),
                max_health_observations: HEALTH_LIMIT,
                max_open_custom_spans: OPEN_LIMIT,
                ..AnalyzerConfig::default()
            },
        );
        for sequence in 0..BEGINS {
            analyzer
                .ingest(&Observation::new(
                    "malicious",
                    sequence,
                    Quality::Exact,
                    ObservationEvent::SpanBegin {
                        ts_ns: sequence as i64,
                        core_id: None,
                        context_id: None,
                        span_id: format!("span-{sequence}"),
                        name: "span".to_owned(),
                        args: Properties::new(),
                    },
                ))
                .unwrap();
        }

        assert_eq!(analyzer.open_custom_span_count(), OPEN_LIMIT);
        assert_eq!(analyzer.health_observations.len(), HEALTH_LIMIT);
        assert!(analyzer.health_diagnostics_truncated);

        let result = analyzer.finish(None).unwrap();
        assert_eq!(result.health.verdict, HealthVerdict::Invalid);
        assert_eq!(result.health.observations.len(), HEALTH_LIMIT);
        assert!(
            result
                .health
                .issues
                .iter()
                .any(|issue| issue.code == "open_custom_span_limit_exceeded")
        );
        assert!(
            result
                .health
                .issues
                .iter()
                .any(|issue| issue.code == "diagnostics_truncated")
        );
    }
}
