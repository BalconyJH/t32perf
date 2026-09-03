//! Strict, versioned adapters for Lauterbach TRACE32 text exports.
//!
//! `Trace.EXPORT.Ascii` is not self-describing: the command-selected columns
//! are written in command order and separated by white space. This module
//! accepts only a fixed, build-qualified SNOOPer PC-sampling profile. The
//! TASKEVENTS adapter accepts only the official no-`/TRaceRecord` semicolon
//! dialect and requires a predeclared ELF/ORTI/marker dictionary.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io::BufRead,
};

use csv::ReaderBuilder;
use object::{BinaryFormat, Object as _, ObjectKind, ObjectSymbol as _, SymbolKind};
use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use t32perf_model::{
    ContextKind, DictionaryEntry, Observation, ObservationDictionary, ObservationEvent, Properties,
    Quality, Sha256Digest, strict_json,
};
use thiserror::Error;

use crate::{
    AdapterDescriptor, AdapterError, AdapterRequest, BoundedLineReader, InputError, InputErrorKind,
    InputLocation, LineLimits, LocatedLine, ObservationAdapter, ObservationOrderError,
    ObservationOrderValidator, ObservationSource, OrderedObservation, SourceDescriptor,
    SourceError,
};

/// Registry ID for Lauterbach `Trace.EXPORT.ASCII` input.
pub const TRACE_ASCII_ADAPTER_ID: &str = "trace32-export-ascii";
/// Registry ID for Lauterbach `Trace.EXPORT.TASKEVENTS` input.
pub const TRACE_TASK_EVENTS_ADAPTER_ID: &str = "trace32-export-taskevents";
/// Fixed SNOOPer PC-sampling ASCII format identity.
pub const TRACE_ASCII_FORMAT_V1: &str =
    "trace32.export-ascii/snooper-single-core-show-record-address-cycle-time-zero-symbol/v1";
/// Official TASKEVENTS format without `/TRaceRecord`.
pub const TRACE_TASK_EVENTS_FORMAT_V1: &str =
    "trace32.export-taskevents/time-name-event-no-trace-record/v1";
/// Command items consumed by [`TraceAsciiSource`]. Symbol is last so spaces are reversible.
pub const TRACE_ASCII_EXPORT_ITEMS_V1: &str =
    "Address CYcle %TimeFixed TIme.Zero sYmbol /ShowRecord";
/// Fixed TC234L SNOOPer ASCII deployment profile identity.
pub const TC234L_SNOOPER_ASCII_PROFILE_V1: &str =
    "t32perf.trace32-ascii-profile/tc234l-build190766-v1";
/// Schema identity for a host-derived immutable TRACE32 ELF symbol map.
pub const TRACE32_SYMBOL_MAPPING_SCHEMA: &str = "t32perf.trace32-symbol-mapping/v1";
/// Schema identity for a deployment-qualified TASKEVENTS mapping.
pub const TRACE32_TASK_EVENTS_MAPPING_SCHEMA: &str = "t32perf.trace32-task-events-mapping/v1";
/// Schema identity for a pre-capture TASKEVENTS dictionary template.
pub const TRACE32_TASK_EVENTS_MAPPING_TEMPLATE_SCHEMA: &str =
    "t32perf.trace32-task-events-mapping-template/v1";
/// Maximum function ranges admitted from one firmware ELF.
pub const MAX_TRACE32_FUNCTION_RANGES: usize = 262_144;
/// Maximum contexts admitted by one TASKEVENTS deployment template.
pub const MAX_TRACE32_TASK_EVENTS_CONTEXTS: usize = 65_536;
/// Maximum runnable bindings admitted by one TASKEVENTS deployment template.
pub const MAX_TRACE32_TASK_EVENTS_RUNNABLES: usize = 262_144;

const TASK_EVENTS_TITLE: &str = "# Task events trace file";
const TASK_EVENTS_COLUMNS: &str = "# time(ns); task name; event;";

/// One function or symbol known before parsing begins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceFunctionMapping {
    /// Exact exported symbol or runnable name.
    pub export_name: String,
    /// Stable normalized identifier.
    pub function_id: String,
    /// Dictionary display name.
    pub display_name: String,
    /// Optional image or module.
    pub module: Option<String>,
    /// Optional function start address.
    pub address: Option<u64>,
    /// Optional exclusive function end address used for PC attribution.
    pub end_address: Option<u64>,
    /// Optional source path.
    pub file: Option<String>,
    /// Optional one-based source line.
    pub line: Option<u32>,
}

impl TraceFunctionMapping {
    fn dictionary_entry(&self) -> DictionaryEntry {
        DictionaryEntry::DefineFunction {
            id: self.function_id.clone(),
            name: self.display_name.clone(),
            module: self.module.clone(),
            address: self.address,
            file: self.file.clone(),
            line: self.line,
        }
    }
}

/// One task, idle context, or ISR known before parsing begins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceContextMapping {
    /// Exact TASKEVENTS `task name` text.
    pub export_name: String,
    /// Stable normalized identifier.
    pub context_id: String,
    /// Kind proved by ELF/ORTI/marker configuration.
    pub kind: ContextKind,
    /// Dictionary display name.
    pub display_name: String,
    /// Optional scheduling or interrupt priority.
    pub priority: Option<i32>,
    /// Function paired with task/ISR start and stop events.
    pub entry_function_id: Option<String>,
}

impl TraceContextMapping {
    fn dictionary_entry(&self, core_id: u32) -> DictionaryEntry {
        DictionaryEntry::DefineContext {
            id: self.context_id.clone(),
            kind: self.kind,
            name: self.display_name.clone(),
            core_id: Some(core_id),
            priority: self.priority,
        }
    }
}

/// Strict syntax configuration for the no-trace-record TASKEVENTS dialect.
///
/// This low-level parser configuration is not a capture-trust token. A host
/// must verify controller health, time origin, qualification, and mapping
/// artifact provenance before registering its output as trusted evidence.
#[derive(Debug, Clone)]
pub struct TraceTaskEventsConfig {
    /// Core selected by the export command.
    pub core_id: u32,
    /// Session-relative clock-domain identity.
    pub clock_domain: String,
    /// Qualified task/idle/ISR mapping.
    pub contexts: Vec<TraceContextMapping>,
    /// Qualified function mapping.
    pub functions: Vec<TraceFunctionMapping>,
    /// Exact runnable-name to function-ID mapping.
    pub runnables: BTreeMap<String, String>,
    /// Context active at the left boundary, when proved.
    pub initial_context_id: Option<String>,
    /// Bounded input limits.
    pub limits: LineLimits,
}

/// Strict syntax configuration for fixed-profile SNOOPer ASCII PC samples.
///
/// This low-level parser configuration is not a capture-trust token. A host
/// must verify the controller runtime, StopV2 time origin, qualification
/// receipt, and ELF mapping provenance before registering normalized output.
#[derive(Debug, Clone)]
pub struct TraceAsciiConfig {
    /// Session-relative clock-domain identity.
    pub clock_domain: String,
    /// Single core selected by the TC234L deployment profile.
    pub core_id: u32,
    /// Exact TRACE32 address classes accepted by this target profile.
    pub address_classes: BTreeSet<String>,
    /// Predeclared symbols eligible for function attribution.
    pub functions: Vec<TraceFunctionMapping>,
    /// Bounded input limits.
    pub limits: LineLimits,
}

/// Versioned host-derived ELF symbol mapping artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Trace32SymbolMappingDocument {
    /// Exact schema identity.
    pub schema: String,
    /// Fixed export profile selected by accepted controller evidence.
    pub profile_id: String,
    /// Exact qualified target-adapter profile digest when this mapping is
    /// used by qualification-bound parsing.  Legacy mapping documents omit
    /// this field and remain parseable, but cannot open a qualified parser.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_sha256: Option<Sha256Digest>,
    /// Canonical TRACE32 release identity.
    pub trace32_release: String,
    /// Exact TRACE32 build.
    pub trace32_build: u64,
    /// Exact architecture package.
    pub architecture_package: String,
    /// Exact deployment target identity.
    pub target_identifier: String,
    /// Firmware ELF artifact identifier.
    pub elf_artifact_id: String,
    /// Firmware ELF digest bound by the authoritative capture config.
    pub elf_sha256: Sha256Digest,
    /// Accepted controller health evidence bound to this mapping.
    pub controller_health: TraceArtifactBinding,
    /// Accepted export/time-origin evidence bound to this mapping.
    pub time_origin_evidence: TraceArtifactBinding,
    /// Deployment qualification receipt admitted by the trusted controller.
    pub qualification_receipt: TraceArtifactBinding,
    /// Exact accepted address classes.
    pub address_classes: Vec<String>,
    /// Nonoverlapping function ranges sorted by start address.
    pub functions: Vec<TraceFunctionMapping>,
}

impl Trace32SymbolMappingDocument {
    /// Validates identity, compatibility, and sorted nonoverlapping ranges.
    pub fn validate(&self) -> Result<(), TraceExportError> {
        if self.schema != TRACE32_SYMBOL_MAPPING_SCHEMA {
            return Err(TraceExportError::config(
                "unsupported symbol mapping schema",
            ));
        }
        for (field, value) in [
            ("profile_id", self.profile_id.as_str()),
            ("trace32_release", self.trace32_release.as_str()),
            ("architecture_package", self.architecture_package.as_str()),
            ("target_identifier", self.target_identifier.as_str()),
            ("elf_artifact_id", self.elf_artifact_id.as_str()),
        ] {
            require_text(field, value)?;
        }
        if self.trace32_build == 0 {
            return Err(TraceExportError::config("TRACE32 build is zero"));
        }
        if self.address_classes.is_empty() {
            return Err(TraceExportError::config("Address class mapping is empty"));
        }
        let classes = self.address_classes.iter().collect::<BTreeSet<_>>();
        if classes.len() != self.address_classes.len() {
            return Err(TraceExportError::config("duplicate Address class"));
        }
        for class in &self.address_classes {
            validate_address_class(class)?;
        }
        if self.functions.is_empty() {
            return Err(TraceExportError::config(
                "symbol mapping contains no ELF function ranges",
            ));
        }
        validate_functions(&self.functions)?;
        validate_sorted_ranges(&self.functions)?;
        self.controller_health.validate("controller health")?;
        self.time_origin_evidence.validate("time-origin evidence")?;
        self.qualification_receipt
            .validate("qualification receipt")?;
        Ok(())
    }
}

/// Immutable Session artifact identity and digest used by a mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceArtifactBinding {
    /// Registered artifact identifier.
    pub artifact_id: String,
    /// Registered artifact digest.
    pub sha256: Sha256Digest,
}

impl TraceArtifactBinding {
    fn validate(&self, label: &str) -> Result<(), TraceExportError> {
        require_text(label, &self.artifact_id)
    }
}

/// Qualified metadata role used to derive TASKEVENTS semantics.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TraceTaskMetadataRole {
    /// ORTI operating-system model.
    Orti,
    /// TRACE32 TASK/ISR/runnable marker qualification.
    Markers,
}

/// One capture-bound ORTI or marker metadata artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceTaskMetadataBinding {
    /// Semantic metadata role.
    pub role: TraceTaskMetadataRole,
    /// Immutable artifact binding.
    pub artifact: TraceArtifactBinding,
}

/// One qualified runnable binding in a TASKEVENTS mapping artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceRunnableMapping {
    /// Exact exported runnable name.
    pub export_name: String,
    /// Function dictionary identifier.
    pub function_id: String,
}

/// Closed, pre-capture TASKEVENTS semantic dictionary for one qualified profile.
///
/// This document deliberately excludes all run-specific identity and evidence.
/// Those values are supplied only by [`TraceTaskEventsRuntimeBinding`] during
/// materialization after the controller completes a capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Trace32TaskEventsMappingTemplateDocument {
    /// Exact schema identity.
    pub schema: String,
    /// Qualified target-adapter profile identity.
    pub profile_id: String,
    /// Single TRACE32 export core.
    pub core_id: u32,
    /// Qualified task, idle, and ISR definitions.
    pub contexts: Vec<TraceContextMapping>,
    /// Qualified task/ISR entry and runnable functions.
    pub functions: Vec<TraceFunctionMapping>,
    /// Qualified runnable bindings.
    pub runnables: Vec<TraceRunnableMapping>,
}

impl Trace32TaskEventsMappingTemplateDocument {
    /// Validates the closed pre-capture dictionary.
    pub fn validate(&self) -> Result<(), TraceExportError> {
        if self.schema != TRACE32_TASK_EVENTS_MAPPING_TEMPLATE_SCHEMA {
            return Err(TraceExportError::config(
                "unsupported TASKEVENTS mapping-template schema",
            ));
        }
        require_text("profile_id", &self.profile_id)?;
        validate_task_events_dictionary(
            self.core_id,
            &self.contexts,
            &self.functions,
            &self.runnables,
        )
    }
}

/// Run-specific TRACE32 identity accepted from completed controller evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceTaskEventsTrace32Identity {
    /// Canonical TRACE32 release identity.
    pub release: String,
    /// Exact TRACE32 build.
    pub build: u64,
    /// Exact architecture package.
    pub architecture_package: String,
}

/// Controller-derived inputs permitted to complete a TASKEVENTS template.
///
/// This is intentionally a typed, closed binding rather than a free-form map:
/// callers cannot substitute arbitrary metadata roles or omit capture evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceTaskEventsRuntimeBinding {
    /// Profile selected by accepted controller evidence.
    pub profile_id: String,
    /// Exact digest of that selected target-adapter profile.
    pub profile_sha256: Sha256Digest,
    /// Single core selected by completed controller evidence.
    pub core_id: u32,
    /// Canonical TRACE32 identity observed for this capture.
    pub trace32: TraceTaskEventsTrace32Identity,
    /// Exact deployment target identity.
    pub target_identifier: String,
    /// Firmware ELF artifact identity and digest.
    pub elf: TraceArtifactBinding,
    /// Capture-bound ORTI and marker artifacts.
    pub metadata_artifacts: Vec<TraceTaskMetadataBinding>,
    /// Accepted controller health evidence.
    pub controller_health: TraceArtifactBinding,
    /// Completed stop evidence proving the export time origin.
    pub stop_time_origin_evidence: TraceArtifactBinding,
    /// Deployment qualification receipt.
    pub qualification_receipt: TraceArtifactBinding,
}

impl TraceTaskEventsRuntimeBinding {
    /// Validates identity and the closed controller-owned binding set.
    pub fn validate(&self) -> Result<(), TraceExportError> {
        for (field, value) in [
            ("profile_id", self.profile_id.as_str()),
            ("trace32 release", self.trace32.release.as_str()),
            (
                "TRACE32 architecture package",
                self.trace32.architecture_package.as_str(),
            ),
            ("target_identifier", self.target_identifier.as_str()),
        ] {
            require_text(field, value)?;
        }
        if self.trace32.build == 0 {
            return Err(TraceExportError::config("TRACE32 build is zero"));
        }
        self.elf.validate("ELF artifact")?;
        validate_task_metadata_bindings(&self.metadata_artifacts)?;
        self.controller_health.validate("controller health")?;
        self.stop_time_origin_evidence
            .validate("stop/time-origin evidence")?;
        self.qualification_receipt
            .validate("qualification receipt")?;
        Ok(())
    }
}

/// Materializes a complete, capture-bound TASKEVENTS mapping from a closed template.
pub fn materialize_trace32_task_events_mapping(
    template: &Trace32TaskEventsMappingTemplateDocument,
    runtime: &TraceTaskEventsRuntimeBinding,
) -> Result<Trace32TaskEventsMappingDocument, TraceExportError> {
    template.validate()?;
    runtime.validate()?;
    if template.profile_id != runtime.profile_id {
        return Err(TraceExportError::config(
            "TASKEVENTS template profile does not match runtime binding",
        ));
    }
    if template.core_id != runtime.core_id {
        return Err(TraceExportError::config(
            "TASKEVENTS template core does not match runtime binding",
        ));
    }
    let document = Trace32TaskEventsMappingDocument {
        schema: TRACE32_TASK_EVENTS_MAPPING_SCHEMA.to_owned(),
        profile_id: template.profile_id.clone(),
        profile_sha256: runtime.profile_sha256.clone(),
        trace32_release: runtime.trace32.release.clone(),
        trace32_build: runtime.trace32.build,
        architecture_package: runtime.trace32.architecture_package.clone(),
        target_identifier: runtime.target_identifier.clone(),
        core_id: template.core_id,
        elf_artifact_id: runtime.elf.artifact_id.clone(),
        elf_sha256: runtime.elf.sha256.clone(),
        metadata_artifacts: runtime.metadata_artifacts.clone(),
        controller_health: runtime.controller_health.clone(),
        time_origin_evidence: runtime.stop_time_origin_evidence.clone(),
        qualification_receipt: runtime.qualification_receipt.clone(),
        contexts: template.contexts.clone(),
        functions: template.functions.clone(),
        runnables: template.runnables.clone(),
    };
    document.validate()?;
    Ok(document)
}

/// Versioned deployment-owned TASKEVENTS dictionary artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Trace32TaskEventsMappingDocument {
    /// Exact schema identity.
    pub schema: String,
    /// Fixed export profile selected by accepted controller evidence.
    pub profile_id: String,
    /// Exact digest of the qualified target-adapter profile selected by the controller.
    pub profile_sha256: Sha256Digest,
    /// Canonical TRACE32 release identity.
    pub trace32_release: String,
    /// Exact TRACE32 build.
    pub trace32_build: u64,
    /// Exact architecture package.
    pub architecture_package: String,
    /// Exact deployment target identity.
    pub target_identifier: String,
    /// Single exported core.
    pub core_id: u32,
    /// Firmware ELF artifact identifier.
    pub elf_artifact_id: String,
    /// Firmware ELF digest used to qualify ORTI and markers.
    pub elf_sha256: Sha256Digest,
    /// Capture-bound ORTI and marker artifacts.
    pub metadata_artifacts: Vec<TraceTaskMetadataBinding>,
    /// Accepted controller health evidence.
    pub controller_health: TraceArtifactBinding,
    /// Accepted time-origin evidence.
    pub time_origin_evidence: TraceArtifactBinding,
    /// Deployment qualification receipt.
    pub qualification_receipt: TraceArtifactBinding,
    /// Qualified Task, idle, and ISR definitions.
    pub contexts: Vec<TraceContextMapping>,
    /// Qualified task/ISR entry and runnable functions.
    pub functions: Vec<TraceFunctionMapping>,
    /// Qualified runnable bindings.
    pub runnables: Vec<TraceRunnableMapping>,
}

impl Trace32TaskEventsMappingDocument {
    /// Validates the closed deployment mapping.
    pub fn validate(&self) -> Result<(), TraceExportError> {
        if self.schema != TRACE32_TASK_EVENTS_MAPPING_SCHEMA {
            return Err(TraceExportError::config(
                "unsupported TASKEVENTS mapping schema",
            ));
        }
        for (field, value) in [
            ("profile_id", self.profile_id.as_str()),
            ("trace32_release", self.trace32_release.as_str()),
            ("architecture_package", self.architecture_package.as_str()),
            ("target_identifier", self.target_identifier.as_str()),
            ("elf_artifact_id", self.elf_artifact_id.as_str()),
        ] {
            require_text(field, value)?;
        }
        if self.trace32_build == 0 {
            return Err(TraceExportError::config("TRACE32 build is zero"));
        }
        validate_task_metadata_bindings(&self.metadata_artifacts)?;
        self.controller_health.validate("controller health")?;
        self.time_origin_evidence.validate("time-origin evidence")?;
        self.qualification_receipt
            .validate("qualification receipt")?;
        validate_task_events_dictionary(
            self.core_id,
            &self.contexts,
            &self.functions,
            &self.runnables,
        )
    }
}

/// Strict TRACE32 text-export failure with physical input location.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{kind} at byte {location_byte}, line {location_line}, record {location_record}")]
pub struct TraceExportError {
    /// Exact physical source location.
    pub location: InputLocation,
    /// Stable error category.
    pub kind: TraceExportErrorKind,
    location_byte: u64,
    location_line: u64,
    location_record: u64,
}

impl TraceExportError {
    fn new(location: InputLocation, kind: TraceExportErrorKind) -> Self {
        Self {
            location,
            kind,
            location_byte: location.byte_offset,
            location_line: location.line,
            location_record: location.record,
        }
    }

    fn config(message: impl Into<String>) -> Self {
        Self::new(
            InputLocation::new(0, 1, 0),
            TraceExportErrorKind::InvalidConfiguration {
                message: message.into(),
            },
        )
    }
}

impl From<InputError> for TraceExportError {
    fn from(error: InputError) -> Self {
        Self::new(error.location, TraceExportErrorKind::Input(error.kind))
    }
}

/// Category of a TRACE32 text-export failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TraceExportErrorKind {
    /// Bounded input failed.
    #[error(transparent)]
    Input(InputErrorKind),
    /// Input is not UTF-8.
    #[error("invalid UTF-8")]
    InvalidUtf8,
    /// Trusted adapter configuration is invalid.
    #[error("invalid adapter configuration: {message}")]
    InvalidConfiguration {
        /// Explanation.
        message: String,
    },
    /// Vendor header is not the versioned dialect.
    #[error("invalid TASKEVENTS header: {message}")]
    InvalidTaskEventsHeader {
        /// Explanation.
        message: String,
    },
    /// TASKEVENTS CSV syntax failed.
    #[error("invalid TASKEVENTS CSV: {message}")]
    InvalidTaskEventsCsv {
        /// Parser text.
        message: String,
    },
    /// Fixed TASKEVENTS row width differs.
    #[error("TASKEVENTS record has {actual} fields; expected 4")]
    TaskEventsRecordWidth {
        /// Actual field count.
        actual: usize,
    },
    /// Required field is empty.
    #[error("required TRACE32 field `{field}` is empty")]
    EmptyField {
        /// Field name.
        field: &'static str,
    },
    /// Timestamp token is invalid.
    #[error("invalid TRACE32 timestamp `{value}`")]
    InvalidTimestamp {
        /// Rejected token.
        value: String,
    },
    /// Timestamp order decreased.
    #[error("TRACE32 timestamp decreased from {previous_ns}ns to {actual_ns}ns")]
    TimestampOrder {
        /// Previous timestamp.
        previous_ns: i64,
        /// Actual timestamp.
        actual_ns: i64,
    },
    /// Event is outside the official closed set.
    #[error("unsupported TASKEVENTS event `{event}`")]
    UnsupportedTaskEvent {
        /// Rejected event.
        event: String,
    },
    /// Exported name has no qualified mapping.
    #[error("unmapped TRACE32 name `{name}` for event `{event}`")]
    UnmappedName {
        /// Rejected name.
        name: String,
        /// Event using it.
        event: String,
    },
    /// Event sequence contradicts the declared model.
    #[error("invalid TRACE32 event state: {message}")]
    InvalidState {
        /// Explanation.
        message: String,
    },
    /// ASCII row differs from the exact profile.
    #[error("invalid ASCII profile row: {message}")]
    InvalidAsciiRow {
        /// Explanation.
        message: String,
    },
    /// ASCII cycle token is not in the qualified mapping.
    #[error("unsupported ASCII cycle token `{cycle}`")]
    UnsupportedAsciiCycle {
        /// Rejected token.
        cycle: String,
    },
    /// Canonical ordering failed.
    #[error(transparent)]
    Ordering(ObservationOrderError),
    /// Canonical model validation failed.
    #[error("invalid normalized observation: {message}")]
    InvalidObservation {
        /// Model error.
        message: String,
    },
}

/// Registry sentinel for raw ASCII; trusted host normalization owns qualification.
#[derive(Debug, Clone, Copy, Default)]
pub struct TraceAsciiAdapter;

impl ObservationAdapter for TraceAsciiAdapter {
    fn id(&self) -> &str {
        TRACE_ASCII_ADAPTER_ID
    }

    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor::unverified(self.id(), TRACE_ASCII_FORMAT_V1)
    }

    fn open(
        &self,
        _request: AdapterRequest,
    ) -> Result<Box<dyn ObservationSource + Send>, AdapterError> {
        Err(AdapterError::UnsupportedNeedsTrace32 {
            adapter: self.id().to_owned(),
            requirement: "trusted host qualification and a capture-bound ELF symbol map",
        })
    }
}

/// Registry sentinel for TASKEVENTS; trusted host normalization owns qualification.
#[derive(Debug, Clone, Copy, Default)]
pub struct TraceTaskEventsAdapter;

impl ObservationAdapter for TraceTaskEventsAdapter {
    fn id(&self) -> &str {
        TRACE_TASK_EVENTS_ADAPTER_ID
    }

    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor::unverified(self.id(), TRACE_TASK_EVENTS_FORMAT_V1)
    }

    fn open(
        &self,
        _request: AdapterRequest,
    ) -> Result<Box<dyn ObservationSource + Send>, AdapterError> {
        Err(AdapterError::UnsupportedNeedsTrace32 {
            adapter: self.id().to_owned(),
            requirement: "trusted host qualification and capture-bound ORTI/marker mappings",
        })
    }
}

#[derive(Debug, Clone)]
struct OpenFrame {
    context_id: String,
    function_id: String,
    frame_id: String,
    interrupt_activation_id: Option<String>,
}

#[derive(Debug, Clone)]
struct OpenInterrupt {
    interrupt_id: String,
    activation_id: String,
    entry_frame: Option<OpenFrame>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TaskLifecycle {
    Ready,
    Running,
    Preempted,
    Waiting,
    Terminated,
}

/// Streaming decoder for the official TASKEVENTS no-trace-record dialect.
pub struct TraceTaskEventsSource<R> {
    descriptor: SourceDescriptor,
    dictionary: ObservationDictionary,
    lines: BoundedLineReader<R>,
    config: TraceTaskEventsConfig,
    contexts: BTreeMap<String, TraceContextMapping>,
    queued: VecDeque<OrderedObservation>,
    order: ObservationOrderValidator,
    next_seq: u64,
    vendor_record: u64,
    last_ts: Option<i64>,
    scheduled: Option<String>,
    pending_previous: Option<String>,
    task_lifecycle: BTreeMap<String, TaskLifecycle>,
    task_frames: BTreeMap<String, OpenFrame>,
    runnable_frames: Vec<OpenFrame>,
    interrupts: Vec<OpenInterrupt>,
    next_activation: u64,
    finished: bool,
}

impl<R: BufRead> TraceTaskEventsSource<R> {
    /// Validates syntax and mapping without buffering data records.
    ///
    /// This constructor does not establish capture trust; see
    /// [`TraceTaskEventsConfig`].
    pub fn new(
        reader: R,
        session_id: impl Into<String>,
        source_id: impl Into<String>,
        config: TraceTaskEventsConfig,
    ) -> Result<Self, TraceExportError> {
        validate_task_config(&config)?;
        let session_id = session_id.into();
        let source_id = source_id.into();
        require_text("session_id", &session_id)?;
        require_text("source_id", &source_id)?;
        let mut lines = BoundedLineReader::vendor_text(reader, config.limits)?;
        read_task_header(&mut lines)?;
        let mut dictionary = ObservationDictionary::new(&session_id);
        validate_dictionary_limits(
            config
                .contexts
                .iter()
                .map(|context| context.dictionary_entry(config.core_id))
                .chain(
                    config
                        .functions
                        .iter()
                        .map(TraceFunctionMapping::dictionary_entry),
                ),
            config.limits,
        )?;
        for context in &config.contexts {
            dictionary
                .entries
                .push(context.dictionary_entry(config.core_id));
        }
        for function in &config.functions {
            dictionary.entries.push(function.dictionary_entry());
        }
        dictionary
            .validate()
            .map_err(|error| TraceExportError::config(error.to_string()))?;
        let contexts = config
            .contexts
            .iter()
            .cloned()
            .map(|mapping| (mapping.export_name.clone(), mapping))
            .collect();
        let mut task_lifecycle = BTreeMap::new();
        if let Some(initial_context_id) = config.initial_context_id.as_deref()
            && config.contexts.iter().any(|context| {
                context.context_id == initial_context_id && context.kind == ContextKind::Task
            })
        {
            task_lifecycle.insert(initial_context_id.to_owned(), TaskLifecycle::Running);
        }
        Ok(Self {
            descriptor: SourceDescriptor::new(&source_id, &config.clock_domain),
            dictionary,
            lines,
            scheduled: config.initial_context_id.clone(),
            config,
            contexts,
            queued: VecDeque::new(),
            order: ObservationOrderValidator::default(),
            next_seq: 0,
            vendor_record: 0,
            last_ts: None,
            pending_previous: None,
            task_lifecycle,
            task_frames: BTreeMap::new(),
            runnable_frames: Vec::new(),
            interrupts: Vec::new(),
            next_activation: 0,
            finished: false,
        })
    }

    fn next_inner(&mut self) -> Result<Option<OrderedObservation>, TraceExportError> {
        if let Some(observation) = self.queued.pop_front() {
            return Ok(Some(observation));
        }
        let Some(line) = self.lines.next_line()? else {
            if !self.task_frames.is_empty()
                || !self.runnable_frames.is_empty()
                || !self.interrupts.is_empty()
                || self.pending_previous.is_some()
            {
                return Err(TraceExportError::new(
                    self.lines.next_location(),
                    TraceExportErrorKind::InvalidState {
                        message:
                            "EOF left an open task, runnable, ISR, or deschedule transition; export is truncated"
                                .to_owned(),
                    },
                ));
            }
            return Ok(None);
        };
        self.vendor_record = self.vendor_record.checked_add(1).ok_or_else(|| {
            TraceExportError::new(
                line.location,
                TraceExportErrorKind::InvalidState {
                    message: "vendor record counter overflow".to_owned(),
                },
            )
        })?;
        let (ts_ns, name, event) = parse_task_record(&line)?;
        if self.last_ts.is_none() && ts_ns != 0 {
            return self.state_error(
                line.location,
                format!("first TASKEVENTS record is {ts_ns}ns; Session-bound time requires 0ns"),
            );
        }
        if let Some(previous) = self.last_ts
            && ts_ns < previous
        {
            return Err(TraceExportError::new(
                line.location,
                TraceExportErrorKind::TimestampOrder {
                    previous_ns: previous,
                    actual_ns: ts_ns,
                },
            ));
        }
        self.last_ts = Some(ts_ns);
        self.map_event(line.location, ts_ns, &name, &event)?;
        self.queued.pop_front().map(Some).ok_or_else(|| {
            TraceExportError::new(
                line.location,
                TraceExportErrorKind::InvalidState {
                    message: "vendor record produced no canonical observation".to_owned(),
                },
            )
        })
    }

    fn map_event(
        &mut self,
        location: InputLocation,
        ts_ns: i64,
        name: &str,
        event: &str,
    ) -> Result<(), TraceExportError> {
        match event {
            "switch" | "schedule" | "resume" | "release" => {
                let context = self.context(location, name, event)?.clone();
                if !matches!(context.kind, ContextKind::Task | ContextKind::Idle) {
                    return self.state_error(
                        location,
                        format!("`{event}` requires a task or idle context"),
                    );
                }
                let lifecycle_verified =
                    self.validate_schedule_lifecycle(location, &context, event)?;
                let previous = self
                    .scheduled
                    .take()
                    .or_else(|| self.pending_previous.take());
                self.scheduled = Some(context.context_id.clone());
                if context.kind == ContextKind::Task {
                    self.task_lifecycle
                        .insert(context.context_id.clone(), TaskLifecycle::Running);
                }
                if event == "switch"
                    && let Some(previous) = previous.as_deref()
                    && previous != context.context_id
                    && self.contexts.values().any(|candidate| {
                        candidate.context_id == previous && candidate.kind == ContextKind::Task
                    })
                {
                    self.task_lifecycle.remove(previous);
                }
                if !lifecycle_verified || previous.as_deref() == Some(context.context_id.as_str()) {
                    let mut args = Properties::new();
                    args.insert("vendor_event".to_owned(), event.into());
                    if !lifecycle_verified {
                        args.insert(
                            "state_validation".to_owned(),
                            "left_boundary_unknown".into(),
                        );
                    }
                    self.push(
                        location,
                        ObservationEvent::Instant {
                            ts_ns,
                            core_id: Some(self.config.core_id),
                            context_id: Some(context.context_id),
                            name: format!("trace32.taskevents.{event}"),
                            args,
                        },
                    )?;
                } else {
                    self.push(
                        location,
                        ObservationEvent::ContextSwitch {
                            ts_ns,
                            core_id: self.config.core_id,
                            prev_context_id: previous,
                            next_context_id: context.context_id,
                            reason: Some(format!("trace32_taskevents_{event}")),
                        },
                    )?;
                }
            }
            "activate" | "preempt" | "wait" | "terminate" => {
                let context_id = if name.is_empty() {
                    if event != "preempt" || self.vendor_record != 1 || self.scheduled.is_some() {
                        return Err(TraceExportError::new(
                            location,
                            TraceExportErrorKind::EmptyField { field: "task name" },
                        ));
                    }
                    None
                } else {
                    let context = self.context(location, name, event)?.clone();
                    if context.kind != ContextKind::Task {
                        return self
                            .state_error(location, format!("`{event}` requires a task context"));
                    }
                    Some(context.context_id)
                };
                let mut args = Properties::new();
                args.insert("vendor_event".to_owned(), event.into());
                self.push(
                    location,
                    ObservationEvent::Instant {
                        ts_ns,
                        core_id: Some(self.config.core_id),
                        context_id: context_id.clone(),
                        name: format!("trace32.taskevents.{event}"),
                        args,
                    },
                )?;
                if let Some(context_id) = context_id {
                    match event {
                        "activate" => {
                            if self.task_lifecycle.contains_key(&context_id) {
                                return self.state_error(
                                    location,
                                    format!("`activate` repeats an unresolved task activation for `{context_id}`"),
                                );
                            }
                            self.task_lifecycle.insert(context_id, TaskLifecycle::Ready);
                        }
                        "preempt" | "wait" | "terminate" => {
                            self.deschedule(location, &context_id, event)?;
                            let state = match event {
                                "preempt" => TaskLifecycle::Preempted,
                                "wait" => TaskLifecycle::Waiting,
                                "terminate" => TaskLifecycle::Terminated,
                                _ => unreachable!(),
                            };
                            self.task_lifecycle.insert(context_id, state);
                        }
                        _ => unreachable!(),
                    }
                }
            }
            "start" => self.task_enter(location, ts_ns, name)?,
            "stop" => self.task_exit(location, ts_ns, name)?,
            "isrstart" => self.isr_enter(location, ts_ns, name)?,
            "isrend" => self.isr_exit(location, ts_ns, name)?,
            "runnablestart" => self.runnable_enter(location, ts_ns, name)?,
            "runnablestop" => self.runnable_exit(location, ts_ns, name)?,
            _ => {
                return Err(TraceExportError::new(
                    location,
                    TraceExportErrorKind::UnsupportedTaskEvent {
                        event: event.to_owned(),
                    },
                ));
            }
        }
        Ok(())
    }

    fn context(
        &self,
        location: InputLocation,
        name: &str,
        event: &str,
    ) -> Result<&TraceContextMapping, TraceExportError> {
        self.contexts.get(name).ok_or_else(|| {
            TraceExportError::new(
                location,
                TraceExportErrorKind::UnmappedName {
                    name: name.to_owned(),
                    event: event.to_owned(),
                },
            )
        })
    }

    fn validate_schedule_lifecycle(
        &self,
        location: InputLocation,
        context: &TraceContextMapping,
        event: &str,
    ) -> Result<bool, TraceExportError> {
        if event == "switch" {
            return Ok(true);
        }
        if context.kind != ContextKind::Task {
            return self.state_error(location, format!("`{event}` requires a task context"));
        }
        let expected = match event {
            "schedule" => TaskLifecycle::Ready,
            "resume" => TaskLifecycle::Preempted,
            "release" => TaskLifecycle::Waiting,
            _ => unreachable!(),
        };
        match self.task_lifecycle.get(&context.context_id).copied() {
            Some(actual) if actual == expected => Ok(true),
            None => Ok(false),
            Some(actual) => self.state_error(
                location,
                format!(
                    "`{event}` requires lifecycle {expected:?} for `{}`; observed {actual:?}",
                    context.context_id
                ),
            ),
        }
    }

    fn deschedule(
        &mut self,
        location: InputLocation,
        context_id: &str,
        event: &str,
    ) -> Result<(), TraceExportError> {
        if self.pending_previous.is_some() {
            return self.state_error(
                location,
                format!("`{event}` occurred before the previous deschedule was resolved"),
            );
        }
        match self.scheduled.take() {
            Some(scheduled) if scheduled == context_id => {
                self.pending_previous = Some(scheduled);
                Ok(())
            }
            Some(scheduled) => {
                self.scheduled = Some(scheduled.clone());
                self.state_error(
                    location,
                    format!("`{event}` references `{context_id}` while `{scheduled}` is scheduled"),
                )
            }
            None => self.state_error(
                location,
                format!("`{event}` references `{context_id}` without a scheduled context"),
            ),
        }
    }

    fn task_enter(
        &mut self,
        location: InputLocation,
        ts_ns: i64,
        name: &str,
    ) -> Result<(), TraceExportError> {
        let context = self.context(location, name, "start")?.clone();
        if context.kind != ContextKind::Task
            || self.scheduled.as_deref() != Some(context.context_id.as_str())
        {
            return self.state_error(location, format!("task `{name}` is not scheduled at start"));
        }
        if self.task_frames.contains_key(&context.context_id) {
            return self.state_error(location, format!("task `{name}` started twice"));
        }
        let function_id = context.entry_function_id.ok_or_else(|| {
            TraceExportError::new(
                location,
                TraceExportErrorKind::InvalidState {
                    message: format!("task `{name}` has no entry-function mapping"),
                },
            )
        })?;
        let frame = self.new_frame(location, context.context_id.clone(), function_id, None)?;
        self.push_frame_event(location, ts_ns, &frame, true)?;
        self.task_frames.insert(context.context_id, frame);
        Ok(())
    }

    fn task_exit(
        &mut self,
        location: InputLocation,
        ts_ns: i64,
        name: &str,
    ) -> Result<(), TraceExportError> {
        let context = self.context(location, name, "stop")?.clone();
        if context.kind != ContextKind::Task
            || self.scheduled.as_deref() != Some(context.context_id.as_str())
            || !self.interrupts.is_empty()
        {
            return self.state_error(location, format!("task `{name}` is not active at stop"));
        }
        if self
            .runnable_frames
            .iter()
            .any(|frame| frame.context_id == context.context_id)
        {
            return self.state_error(
                location,
                format!("task `{name}` stopped with an open runnable frame"),
            );
        }
        let frame = self
            .task_frames
            .remove(&context.context_id)
            .ok_or_else(|| {
                TraceExportError::new(
                    location,
                    TraceExportErrorKind::InvalidState {
                        message: format!("task `{name}` stopped without start"),
                    },
                )
            })?;
        self.push_frame_event(location, ts_ns, &frame, false)
    }

    fn isr_enter(
        &mut self,
        location: InputLocation,
        ts_ns: i64,
        name: &str,
    ) -> Result<(), TraceExportError> {
        let context = self.context(location, name, "isrstart")?.clone();
        if context.kind != ContextKind::Isr {
            return self.state_error(location, format!("`{name}` is not an ISR"));
        }
        let activation_id = format!("{}:{}", context.context_id, self.take_serial(location)?);
        self.push(
            location,
            ObservationEvent::InterruptEnter {
                ts_ns,
                core_id: self.config.core_id,
                interrupt_id: context.context_id.clone(),
                priority: context.priority,
                activation_id: activation_id.clone(),
            },
        )?;
        let entry_frame = context
            .entry_function_id
            .map(|function_id| {
                self.new_frame(
                    location,
                    context.context_id.clone(),
                    function_id,
                    Some(activation_id.clone()),
                )
            })
            .transpose()?;
        if let Some(frame) = &entry_frame {
            self.push_frame_event(location, ts_ns, frame, true)?;
        }
        self.interrupts.push(OpenInterrupt {
            interrupt_id: context.context_id,
            activation_id,
            entry_frame,
        });
        Ok(())
    }

    fn isr_exit(
        &mut self,
        location: InputLocation,
        ts_ns: i64,
        name: &str,
    ) -> Result<(), TraceExportError> {
        let context = self.context(location, name, "isrend")?.clone();
        let interrupt = self.interrupts.pop().ok_or_else(|| {
            TraceExportError::new(
                location,
                TraceExportErrorKind::InvalidState {
                    message: format!("ISR `{name}` ended without start"),
                },
            )
        })?;
        if interrupt.interrupt_id != context.context_id {
            return self.state_error(location, format!("ISR `{name}` ended out of nesting order"));
        }
        if self.runnable_frames.iter().any(|frame| {
            frame.interrupt_activation_id.as_deref() == Some(interrupt.activation_id.as_str())
        }) {
            self.interrupts.push(interrupt);
            return self.state_error(
                location,
                format!("ISR `{name}` ended with an open runnable frame"),
            );
        }
        if let Some(frame) = &interrupt.entry_frame {
            self.push_frame_event(location, ts_ns, frame, false)?;
        }
        self.push(
            location,
            ObservationEvent::InterruptExit {
                ts_ns,
                core_id: self.config.core_id,
                interrupt_id: interrupt.interrupt_id,
                priority: context.priority,
                activation_id: interrupt.activation_id,
            },
        )
    }

    fn runnable_enter(
        &mut self,
        location: InputLocation,
        ts_ns: i64,
        name: &str,
    ) -> Result<(), TraceExportError> {
        let function_id = self.config.runnables.get(name).cloned().ok_or_else(|| {
            TraceExportError::new(
                location,
                TraceExportErrorKind::UnmappedName {
                    name: name.to_owned(),
                    event: "runnablestart".to_owned(),
                },
            )
        })?;
        let (context_id, interrupt_activation_id) = self
            .interrupts
            .last()
            .map(|interrupt| {
                (
                    interrupt.interrupt_id.clone(),
                    Some(interrupt.activation_id.clone()),
                )
            })
            .or_else(|| self.scheduled.clone().map(|context| (context, None)))
            .ok_or_else(|| {
                TraceExportError::new(
                    location,
                    TraceExportErrorKind::InvalidState {
                        message: format!("runnable `{name}` has no active context"),
                    },
                )
            })?;
        let frame = self.new_frame(location, context_id, function_id, interrupt_activation_id)?;
        self.push_frame_event(location, ts_ns, &frame, true)?;
        self.runnable_frames.push(frame);
        Ok(())
    }

    fn runnable_exit(
        &mut self,
        location: InputLocation,
        ts_ns: i64,
        name: &str,
    ) -> Result<(), TraceExportError> {
        let expected = self.config.runnables.get(name).ok_or_else(|| {
            TraceExportError::new(
                location,
                TraceExportErrorKind::UnmappedName {
                    name: name.to_owned(),
                    event: "runnablestop".to_owned(),
                },
            )
        })?;
        let frame = self.runnable_frames.pop().ok_or_else(|| {
            TraceExportError::new(
                location,
                TraceExportErrorKind::InvalidState {
                    message: format!("runnable `{name}` stopped without start"),
                },
            )
        })?;
        if &frame.function_id != expected {
            return self.state_error(
                location,
                format!("runnable `{name}` stopped out of nesting order"),
            );
        }
        let active_context = self
            .interrupts
            .last()
            .map(|interrupt| interrupt.interrupt_id.as_str())
            .or(self.scheduled.as_deref());
        if active_context != Some(frame.context_id.as_str()) {
            return self.state_error(
                location,
                format!("runnable `{name}` stopped outside its active context"),
            );
        }
        let active_activation = self
            .interrupts
            .last()
            .map(|interrupt| interrupt.activation_id.as_str());
        if frame.interrupt_activation_id.as_deref() != active_activation {
            return self.state_error(
                location,
                format!("runnable `{name}` crossed an ISR activation boundary"),
            );
        }
        self.push_frame_event(location, ts_ns, &frame, false)
    }

    fn new_frame(
        &mut self,
        location: InputLocation,
        context_id: String,
        function_id: String,
        interrupt_activation_id: Option<String>,
    ) -> Result<OpenFrame, TraceExportError> {
        let serial = self.take_serial(location)?;
        Ok(OpenFrame {
            context_id,
            function_id,
            frame_id: format!("trace32-frame:{serial}"),
            interrupt_activation_id,
        })
    }

    fn take_serial(&mut self, location: InputLocation) -> Result<u64, TraceExportError> {
        let serial = self.next_activation;
        self.next_activation = self.next_activation.checked_add(1).ok_or_else(|| {
            TraceExportError::new(
                location,
                TraceExportErrorKind::InvalidState {
                    message: "activation counter overflow".to_owned(),
                },
            )
        })?;
        Ok(serial)
    }

    fn push_frame_event(
        &mut self,
        location: InputLocation,
        ts_ns: i64,
        frame: &OpenFrame,
        enter: bool,
    ) -> Result<(), TraceExportError> {
        let event = if enter {
            ObservationEvent::FunctionEnter {
                ts_ns,
                core_id: self.config.core_id,
                context_id: frame.context_id.clone(),
                function_id: frame.function_id.clone(),
                frame_id: Some(frame.frame_id.clone()),
            }
        } else {
            ObservationEvent::FunctionExit {
                ts_ns,
                core_id: self.config.core_id,
                context_id: frame.context_id.clone(),
                function_id: frame.function_id.clone(),
                frame_id: Some(frame.frame_id.clone()),
            }
        };
        self.push(location, event)
    }

    fn push(
        &mut self,
        location: InputLocation,
        event: ObservationEvent,
    ) -> Result<(), TraceExportError> {
        let observation = Observation::new(
            self.descriptor.source_id.clone(),
            self.next_seq,
            Quality::Exact,
            event,
        );
        observation.validate().map_err(|error| {
            TraceExportError::new(
                location,
                TraceExportErrorKind::InvalidObservation {
                    message: error.to_string(),
                },
            )
        })?;
        self.order.observe(&observation).map_err(|error| {
            TraceExportError::new(location, TraceExportErrorKind::Ordering(error))
        })?;
        let order_key = self
            .vendor_record
            .checked_mul(8)
            .and_then(|base| base.checked_add(self.queued.len() as u64))
            .ok_or_else(|| {
                TraceExportError::new(
                    location,
                    TraceExportErrorKind::InvalidState {
                        message: "order key overflow".to_owned(),
                    },
                )
            })?;
        self.next_seq = self.next_seq.checked_add(1).ok_or_else(|| {
            TraceExportError::new(
                location,
                TraceExportErrorKind::InvalidState {
                    message: "source sequence overflow".to_owned(),
                },
            )
        })?;
        self.queued
            .push_back(OrderedObservation::ordered(observation, order_key));
        Ok(())
    }

    fn state_error<T>(
        &self,
        location: InputLocation,
        message: String,
    ) -> Result<T, TraceExportError> {
        Err(TraceExportError::new(
            location,
            TraceExportErrorKind::InvalidState { message },
        ))
    }
}

impl<R: BufRead> ObservationSource for TraceTaskEventsSource<R> {
    fn descriptor(&self) -> &SourceDescriptor {
        &self.descriptor
    }

    fn dictionary(&self) -> Option<&ObservationDictionary> {
        Some(&self.dictionary)
    }

    fn next_observation(&mut self) -> Result<Option<OrderedObservation>, SourceError> {
        if self.finished {
            return Ok(None);
        }
        match self.next_inner() {
            Ok(Some(observation)) => Ok(Some(observation)),
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

/// Streaming decoder for the fixed SNOOPer PC-sampling ASCII profile.
pub struct TraceAsciiSource<R> {
    descriptor: SourceDescriptor,
    dictionary: ObservationDictionary,
    lines: BoundedLineReader<R>,
    config: TraceAsciiConfig,
    function_ranges: Vec<(u64, u64, String)>,
    symbol_functions: BTreeMap<String, String>,
    order: ObservationOrderValidator,
    next_seq: u64,
    last_record: Option<i64>,
    finished: bool,
}

impl<R: BufRead> TraceAsciiSource<R> {
    /// Opens the exact fixed-column profile without consulting TRACE32 defaults.
    ///
    /// This constructor does not establish capture trust; see
    /// [`TraceAsciiConfig`].
    pub fn new(
        reader: R,
        session_id: impl Into<String>,
        source_id: impl Into<String>,
        config: TraceAsciiConfig,
    ) -> Result<Self, TraceExportError> {
        validate_ascii_config(&config)?;
        let session_id = session_id.into();
        let source_id = source_id.into();
        require_text("session_id", &session_id)?;
        require_text("source_id", &source_id)?;
        let mut dictionary = ObservationDictionary::new(session_id);
        validate_dictionary_limits(
            config
                .functions
                .iter()
                .map(TraceFunctionMapping::dictionary_entry),
            config.limits,
        )?;
        for function in &config.functions {
            dictionary.entries.push(function.dictionary_entry());
        }
        dictionary
            .validate()
            .map_err(|error| TraceExportError::config(error.to_string()))?;
        let mut function_ranges = config
            .functions
            .iter()
            .filter_map(|mapping| {
                Some((
                    mapping.address?,
                    mapping.end_address?,
                    mapping.function_id.clone(),
                ))
            })
            .collect::<Vec<_>>();
        function_ranges.sort_unstable_by_key(|(start, _, _)| *start);
        let symbol_functions = config
            .functions
            .iter()
            .map(|mapping| (mapping.export_name.clone(), mapping.function_id.clone()))
            .collect();
        Ok(Self {
            descriptor: SourceDescriptor::new(&source_id, &config.clock_domain),
            dictionary,
            lines: BoundedLineReader::vendor_text(reader, config.limits)?,
            config,
            function_ranges,
            symbol_functions,
            order: ObservationOrderValidator::default(),
            next_seq: 0,
            last_record: None,
            finished: false,
        })
    }

    fn next_inner(&mut self) -> Result<Option<OrderedObservation>, TraceExportError> {
        let Some(line) = self.lines.next_line()? else {
            return Ok(None);
        };
        let row = parse_ascii_record(&line)?;
        if self.last_record.is_none() && row.ts_ns != 0 {
            return Err(TraceExportError::new(
                line.location,
                TraceExportErrorKind::InvalidAsciiRow {
                    message: format!(
                        "first SNOOPer sample is {}ns; Session-bound TIme.Zero requires 0ns",
                        row.ts_ns
                    ),
                },
            ));
        }
        if let Some(previous) = self.last_record
            && previous.checked_add(1) != Some(row.record)
        {
            return Err(TraceExportError::new(
                line.location,
                TraceExportErrorKind::InvalidAsciiRow {
                    message: format!(
                        "record {} is not contiguous after previous record {previous}",
                        row.record
                    ),
                },
            ));
        }
        self.last_record = Some(row.record);
        if row.cycle != "snoop" {
            return Err(TraceExportError::new(
                line.location,
                TraceExportErrorKind::UnsupportedAsciiCycle {
                    cycle: row.cycle.to_owned(),
                },
            ));
        }
        let (address_class, address) = row.address.ok_or_else(|| {
            TraceExportError::new(
                line.location,
                TraceExportErrorKind::InvalidAsciiRow {
                    message: "SNOOPer sample has no Address value".to_owned(),
                },
            )
        })?;
        if !self.config.address_classes.contains(address_class) {
            return Err(TraceExportError::new(
                line.location,
                TraceExportErrorKind::InvalidAsciiRow {
                    message: format!("unsupported Address class `{address_class}`"),
                },
            ));
        }
        let function_id = self.function_for_address(line.location, address, row.symbol)?;
        let event = ObservationEvent::Sample {
            ts_ns: row.ts_ns,
            core_id: self.config.core_id,
            context_id: None,
            function_id,
            address: Some(address),
            weight_ns: None,
        };
        let observation = Observation::new(
            self.descriptor.source_id.clone(),
            self.next_seq,
            Quality::Statistical,
            event,
        );
        observation.validate().map_err(|error| {
            TraceExportError::new(
                line.location,
                TraceExportErrorKind::InvalidObservation {
                    message: error.to_string(),
                },
            )
        })?;
        self.order.observe(&observation).map_err(|error| {
            TraceExportError::new(line.location, TraceExportErrorKind::Ordering(error))
        })?;
        self.next_seq = self.next_seq.checked_add(1).ok_or_else(|| {
            TraceExportError::new(
                line.location,
                TraceExportErrorKind::InvalidState {
                    message: "source sequence overflow".to_owned(),
                },
            )
        })?;
        let order_key = record_order_key(row.record).ok_or_else(|| {
            TraceExportError::new(
                line.location,
                TraceExportErrorKind::InvalidAsciiRow {
                    message: "ShowRecord value cannot be represented as an order key".to_owned(),
                },
            )
        })?;
        Ok(Some(OrderedObservation::ordered(observation, order_key)))
    }

    fn function_for_address(
        &self,
        location: InputLocation,
        address: u64,
        symbol: Option<&str>,
    ) -> Result<Option<String>, TraceExportError> {
        let mapped = self
            .function_ranges
            .partition_point(|(start, _, _)| *start <= address);
        let Some((start, end, function_id)) = mapped
            .checked_sub(1)
            .and_then(|index| self.function_ranges.get(index))
            .filter(|(start, end, _)| (*start..*end).contains(&address))
        else {
            return Ok(None);
        };
        debug_assert!((*start..*end).contains(&address));
        if let Some(symbol) = symbol
            && let Some(symbol_function_id) = self.symbol_functions.get(symbol)
            && symbol_function_id != function_id
        {
            return Err(TraceExportError::new(
                location,
                TraceExportErrorKind::InvalidAsciiRow {
                    message: format!(
                        "Address range maps to `{function_id}` but exact symbol maps to `{symbol_function_id}`"
                    ),
                },
            ));
        }
        Ok(Some(function_id.clone()))
    }
}

impl<R: BufRead> ObservationSource for TraceAsciiSource<R> {
    fn descriptor(&self) -> &SourceDescriptor {
        &self.descriptor
    }

    fn dictionary(&self) -> Option<&ObservationDictionary> {
        Some(&self.dictionary)
    }

    fn next_observation(&mut self) -> Result<Option<OrderedObservation>, SourceError> {
        if self.finished {
            return Ok(None);
        }
        match self.next_inner() {
            Ok(Some(observation)) => Ok(Some(observation)),
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

struct AsciiRecord<'a> {
    record: i64,
    address: Option<(&'a str, u64)>,
    cycle: &'a str,
    ts_ns: i64,
    symbol: Option<&'a str>,
}

fn parse_ascii_record(line: &LocatedLine) -> Result<AsciiRecord<'_>, TraceExportError> {
    let text = line_text(line)?;
    // Exact profile: ShowRecord, Address, CYcle, TIme.Zero, then symbol tail.
    // TRACE32 aligns columns with runs of spaces, while a demangled symbol may
    // itself contain spaces. Consume four tokens with a cursor and retain the
    // remaining tail verbatim as the optional symbol field.
    let fields = split_ascii_profile_fields(text).ok_or_else(|| {
        TraceExportError::new(
            line.location,
            TraceExportErrorKind::InvalidAsciiRow {
                message: "expected ShowRecord Address CYcle TIme.Zero and optional symbol tail"
                    .to_owned(),
            },
        )
    })?;
    if fields[..4].iter().any(|field| field.is_empty()) {
        return Err(TraceExportError::new(
            line.location,
            TraceExportErrorKind::InvalidAsciiRow {
                message: "expected ShowRecord Address CYcle TIme.Zero and optional symbol tail"
                    .to_owned(),
            },
        ));
    }
    let record = parse_record_token(fields[0]).ok_or_else(|| {
        TraceExportError::new(
            line.location,
            TraceExportErrorKind::InvalidAsciiRow {
                message: format!("invalid ShowRecord token `{}`", fields[0]),
            },
        )
    })?;
    let address = if fields[1] == "-" {
        None
    } else {
        Some(parse_address(fields[1]).ok_or_else(|| {
            TraceExportError::new(
                line.location,
                TraceExportErrorKind::InvalidAsciiRow {
                    message: format!("invalid Address token `{}`", fields[1]),
                },
            )
        })?)
    };
    let ts_ns = parse_time_token(fields[3]).ok_or_else(|| {
        TraceExportError::new(
            line.location,
            TraceExportErrorKind::InvalidTimestamp {
                value: fields[3].to_owned(),
            },
        )
    })?;
    let symbol = fields[4].trim();
    Ok(AsciiRecord {
        record,
        address,
        cycle: fields[2],
        ts_ns,
        symbol: (!symbol.is_empty() && symbol != "-").then_some(symbol),
    })
}

fn split_ascii_profile_fields(value: &str) -> Option<[&str; 5]> {
    let bytes = value.as_bytes();
    let mut cursor = 0;
    let mut tokens = [""; 4];
    for token in &mut tokens {
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let start = cursor;
        while cursor < bytes.len() && !bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if start == cursor {
            return None;
        }
        *token = &value[start..cursor];
    }
    while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    let symbol = value[cursor..].trim_end();
    Some([tokens[0], tokens[1], tokens[2], tokens[3], symbol])
}

fn parse_record_token(value: &str) -> Option<i64> {
    (!value.is_empty()
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_digit() || (index == 0 && matches!(byte, b'+' | b'-'))
        }))
    .then(|| value.parse().ok())
    .flatten()
}

fn parse_address(value: &str) -> Option<(&str, u64)> {
    let (class, value) = value.split_once(':')?;
    if class.is_empty()
        || !class
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return None;
    }
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    let address = (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| u64::from_str_radix(value, 16).ok())
        .flatten()?;
    Some((class, address))
}

fn parse_time_token(value: &str) -> Option<i64> {
    for (suffix, numerator, denominator) in [
        ("ps", 1_i128, 1_000_i128),
        ("ns", 1, 1),
        ("us", 1_000, 1),
        ("ms", 1_000_000, 1),
        ("s", 1_000_000_000, 1),
    ] {
        if let Some(number) = value.strip_suffix(suffix) {
            return i64::try_from(parse_decimal(number, numerator, denominator)?).ok();
        }
    }
    None
}

fn parse_decimal(value: &str, numerator: i128, denominator: i128) -> Option<i128> {
    let (negative, unsigned) = value
        .strip_prefix('-')
        .map_or((false, value), |rest| (true, rest));
    let unsigned = unsigned.strip_prefix('+').unwrap_or(unsigned);
    let (whole, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let scale = 10_i128.checked_pow(u32::try_from(fraction.len()).ok()?)?;
    let combined = whole
        .parse::<i128>()
        .ok()?
        .checked_mul(scale)?
        .checked_add(if fraction.is_empty() {
            0
        } else {
            fraction.parse::<i128>().ok()?
        })?;
    let divisor = scale.checked_mul(denominator)?;
    let scaled = combined.checked_mul(numerator)?;
    if scaled % divisor != 0 {
        return None;
    }
    let result = scaled.checked_div(divisor)?;
    if negative {
        result.checked_neg()
    } else {
        Some(result)
    }
}

fn record_order_key(record: i64) -> Option<u64> {
    // Signed TRACE32 record numbering is order-preserving after biasing.
    let biased = i128::from(record).checked_sub(i128::from(i64::MIN))?;
    u64::try_from(biased).ok()
}

fn read_task_header<R: BufRead>(lines: &mut BoundedLineReader<R>) -> Result<(), TraceExportError> {
    let first = required_line(lines, 1)?;
    let title = required_line(lines, 2)?;
    let columns = required_line(lines, 3)?;
    let last = required_line(lines, 4)?;
    let first_text = line_text(&first)?;
    let last_text = line_text(&last)?;
    if first_text.len() < 8 || !first_text.bytes().all(|byte| byte == b'#') {
        return Err(TraceExportError::new(
            first.location,
            TraceExportErrorKind::InvalidTaskEventsHeader {
                message: "opening rule must contain at least eight `#` characters".to_owned(),
            },
        ));
    }
    if first_text.len() != last_text.len() || !last_text.bytes().all(|byte| byte == b'#') {
        return Err(TraceExportError::new(
            last.location,
            TraceExportErrorKind::InvalidTaskEventsHeader {
                message: "closing rule must be an equal-length `#` line".to_owned(),
            },
        ));
    }
    if line_text(&title)?.trim_end() != TASK_EVENTS_TITLE {
        return Err(TraceExportError::new(
            title.location,
            TraceExportErrorKind::InvalidTaskEventsHeader {
                message: format!("expected `{TASK_EVENTS_TITLE}`"),
            },
        ));
    }
    if line_text(&columns)?.trim_end() != TASK_EVENTS_COLUMNS {
        return Err(TraceExportError::new(
            columns.location,
            TraceExportErrorKind::InvalidTaskEventsHeader {
                message: format!("expected `{TASK_EVENTS_COLUMNS}`"),
            },
        ));
    }
    Ok(())
}

fn required_line<R: BufRead>(
    lines: &mut BoundedLineReader<R>,
    number: u64,
) -> Result<LocatedLine, TraceExportError> {
    let eof = lines.next_location();
    lines.next_line()?.ok_or_else(|| {
        TraceExportError::new(
            eof,
            TraceExportErrorKind::InvalidTaskEventsHeader {
                message: format!("missing header line {number}"),
            },
        )
    })
}

fn parse_task_record(line: &LocatedLine) -> Result<(i64, String, String), TraceExportError> {
    let mut reader = ReaderBuilder::new()
        .has_headers(false)
        .delimiter(b';')
        .flexible(false)
        .from_reader(line.bytes.as_slice());
    let record = reader
        .records()
        .next()
        .transpose()
        .map_err(|error| {
            TraceExportError::new(
                line.location,
                TraceExportErrorKind::InvalidTaskEventsCsv {
                    message: error.to_string(),
                },
            )
        })?
        .ok_or_else(|| {
            TraceExportError::new(
                line.location,
                TraceExportErrorKind::InvalidTaskEventsCsv {
                    message: "empty record".to_owned(),
                },
            )
        })?;
    if record.len() != 4 {
        return Err(TraceExportError::new(
            line.location,
            TraceExportErrorKind::TaskEventsRecordWidth {
                actual: record.len(),
            },
        ));
    }
    if !record[3].trim().is_empty() {
        return Err(TraceExportError::new(
            line.location,
            TraceExportErrorKind::InvalidTaskEventsCsv {
                message: "required trailing semicolon is followed by data".to_owned(),
            },
        ));
    }
    let timestamp = record[0].trim();
    let ts_ns = timestamp.parse::<i64>().map_err(|_| {
        TraceExportError::new(
            line.location,
            TraceExportErrorKind::InvalidTimestamp {
                value: timestamp.to_owned(),
            },
        )
    })?;
    let name = record[1].trim().to_owned();
    let event = record[2].trim().to_owned();
    if event.is_empty() {
        return Err(TraceExportError::new(
            line.location,
            TraceExportErrorKind::EmptyField { field: "event" },
        ));
    }
    Ok((ts_ns, name, event))
}

fn line_text(line: &LocatedLine) -> Result<&str, TraceExportError> {
    std::str::from_utf8(&line.bytes)
        .map_err(|_| TraceExportError::new(line.location, TraceExportErrorKind::InvalidUtf8))
}

fn validate_dictionary_limits(
    entries: impl IntoIterator<Item = DictionaryEntry>,
    limits: LineLimits,
) -> Result<(), TraceExportError> {
    let mut physical_bytes = 0_u64;
    for (index, entry) in entries.into_iter().enumerate() {
        let count = u64::try_from(index).unwrap_or(u64::MAX);
        if count >= limits.max_dictionary_entries {
            return Err(TraceExportError::config(format!(
                "dictionary entry count exceeds {}",
                limits.max_dictionary_entries
            )));
        }
        let bytes = serde_json::to_vec(&entry).map_err(|error| {
            TraceExportError::config(format!("dictionary serialization failed: {error}"))
        })?;
        if bytes.len() > limits.max_line_bytes {
            return Err(TraceExportError::config(format!(
                "dictionary entry exceeds {} bytes",
                limits.max_line_bytes
            )));
        }
        let entry_bytes = u64::try_from(bytes.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        physical_bytes = physical_bytes.checked_add(entry_bytes).ok_or_else(|| {
            TraceExportError::config("dictionary physical byte count overflows u64")
        })?;
        if physical_bytes > limits.max_dictionary_bytes {
            return Err(TraceExportError::config(format!(
                "dictionary physical bytes exceed {}",
                limits.max_dictionary_bytes
            )));
        }
    }
    Ok(())
}

fn validate_task_config(config: &TraceTaskEventsConfig) -> Result<(), TraceExportError> {
    require_text("clock_domain", &config.clock_domain)?;
    config.limits.validate().map_err(|kind| {
        TraceExportError::new(
            InputLocation::new(0, 1, 0),
            TraceExportErrorKind::Input(kind),
        )
    })?;
    if config.contexts.is_empty() {
        return Err(TraceExportError::config("context mapping is empty"));
    }
    let mut export_names = BTreeSet::new();
    let mut context_ids = BTreeSet::new();
    for context in &config.contexts {
        require_text("context export name", &context.export_name)?;
        require_text("context ID", &context.context_id)?;
        require_text("context display name", &context.display_name)?;
        if !export_names.insert(context.export_name.as_str()) {
            return Err(TraceExportError::config("duplicate context export name"));
        }
        if !context_ids.insert(context.context_id.as_str()) {
            return Err(TraceExportError::config("duplicate context ID"));
        }
    }
    let function_ids = validate_functions(&config.functions)?;
    for context in &config.contexts {
        if context
            .entry_function_id
            .as_deref()
            .is_some_and(|id| !function_ids.contains(id))
        {
            return Err(TraceExportError::config(
                "context entry function is absent from dictionary",
            ));
        }
    }
    for (name, function_id) in &config.runnables {
        require_text("runnable export name", name)?;
        if !function_ids.contains(function_id.as_str()) {
            return Err(TraceExportError::config(
                "runnable function is absent from dictionary",
            ));
        }
    }
    if config
        .initial_context_id
        .as_deref()
        .is_some_and(|id| !context_ids.contains(id))
    {
        return Err(TraceExportError::config(
            "initial context is absent from dictionary",
        ));
    }
    if let Some(initial) = config.initial_context_id.as_deref()
        && config
            .contexts
            .iter()
            .find(|context| context.context_id == initial)
            .is_some_and(|context| !matches!(context.kind, ContextKind::Task | ContextKind::Idle))
    {
        return Err(TraceExportError::config(
            "initial scheduled context must be a task or idle context",
        ));
    }
    Ok(())
}

fn validate_task_events_dictionary(
    core_id: u32,
    contexts: &[TraceContextMapping],
    functions: &[TraceFunctionMapping],
    runnables: &[TraceRunnableMapping],
) -> Result<(), TraceExportError> {
    if contexts.len() > MAX_TRACE32_TASK_EVENTS_CONTEXTS {
        return Err(TraceExportError::config(format!(
            "TASKEVENTS context count exceeds {MAX_TRACE32_TASK_EVENTS_CONTEXTS}"
        )));
    }
    if functions.len() > MAX_TRACE32_FUNCTION_RANGES {
        return Err(TraceExportError::config(format!(
            "TASKEVENTS function count exceeds {MAX_TRACE32_FUNCTION_RANGES}"
        )));
    }
    if runnables.len() > MAX_TRACE32_TASK_EVENTS_RUNNABLES {
        return Err(TraceExportError::config(format!(
            "TASKEVENTS runnable count exceeds {MAX_TRACE32_TASK_EVENTS_RUNNABLES}"
        )));
    }
    let mut runnable_names = BTreeSet::new();
    let mut runnable_map = BTreeMap::new();
    for runnable in runnables {
        require_text("runnable export name", &runnable.export_name)?;
        require_text("runnable function ID", &runnable.function_id)?;
        if !runnable_names.insert(runnable.export_name.as_str()) {
            return Err(TraceExportError::config(
                "duplicate TASKEVENTS runnable export name",
            ));
        }
        runnable_map.insert(runnable.export_name.clone(), runnable.function_id.clone());
    }
    let config = TraceTaskEventsConfig {
        core_id,
        clock_domain: "validation-only".to_owned(),
        contexts: contexts.to_vec(),
        functions: functions.to_vec(),
        runnables: runnable_map,
        initial_context_id: None,
        limits: LineLimits::default(),
    };
    validate_task_config(&config)
}

fn validate_task_metadata_bindings(
    metadata_artifacts: &[TraceTaskMetadataBinding],
) -> Result<(), TraceExportError> {
    if metadata_artifacts.len() != 2 {
        return Err(TraceExportError::config(
            "TASKEVENTS mapping requires exactly ORTI and marker metadata",
        ));
    }
    let mut roles = BTreeSet::new();
    let mut metadata_ids = BTreeSet::new();
    for binding in metadata_artifacts {
        binding.artifact.validate("task metadata artifact")?;
        if !roles.insert(binding.role) {
            return Err(TraceExportError::config(
                "duplicate TASKEVENTS metadata role",
            ));
        }
        if !metadata_ids.insert(binding.artifact.artifact_id.as_str()) {
            return Err(TraceExportError::config(
                "duplicate TASKEVENTS metadata artifact",
            ));
        }
    }
    if roles != BTreeSet::from([TraceTaskMetadataRole::Orti, TraceTaskMetadataRole::Markers]) {
        return Err(TraceExportError::config(
            "TASKEVENTS mapping requires exactly ORTI and marker metadata",
        ));
    }
    Ok(())
}

fn validate_ascii_config(config: &TraceAsciiConfig) -> Result<(), TraceExportError> {
    require_text("clock_domain", &config.clock_domain)?;
    config.limits.validate().map_err(|kind| {
        TraceExportError::new(
            InputLocation::new(0, 1, 0),
            TraceExportErrorKind::Input(kind),
        )
    })?;
    if config.address_classes.is_empty() {
        return Err(TraceExportError::config("Address class mapping is empty"));
    }
    for class in &config.address_classes {
        require_text("Address class", class)?;
        if !class
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(TraceExportError::config(
                "Address class contains unsupported characters",
            ));
        }
    }
    validate_functions(&config.functions)?;
    let mut ranges = config
        .functions
        .iter()
        .filter_map(|function| {
            Some((
                function.address?,
                function.end_address?,
                &function.function_id,
            ))
        })
        .collect::<Vec<_>>();
    ranges.sort_unstable_by_key(|(start, _, _)| *start);
    for pair in ranges.windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err(TraceExportError::config(format!(
                "function address ranges `{}` and `{}` overlap",
                pair[0].2, pair[1].2
            )));
        }
    }
    Ok(())
}

fn validate_functions(
    functions: &[TraceFunctionMapping],
) -> Result<BTreeSet<&str>, TraceExportError> {
    let mut export_names = BTreeSet::new();
    let mut function_ids = BTreeSet::new();
    for function in functions {
        require_text("function export name", &function.export_name)?;
        require_text("function ID", &function.function_id)?;
        require_text("function display name", &function.display_name)?;
        if function.line == Some(0) {
            return Err(TraceExportError::config(
                "function source line must be one-based",
            ));
        }
        match (function.address, function.end_address) {
            (None, None) => {}
            (Some(start), Some(end)) if start < end => {}
            _ => {
                return Err(TraceExportError::config(
                    "function PC range requires start < exclusive end",
                ));
            }
        }
        if !export_names.insert(function.export_name.as_str()) {
            return Err(TraceExportError::config("duplicate function export name"));
        }
        if !function_ids.insert(function.function_id.as_str()) {
            return Err(TraceExportError::config("duplicate function ID"));
        }
    }
    Ok(function_ids)
}

fn require_text(field: &str, value: &str) -> Result<(), TraceExportError> {
    if value.trim().is_empty() {
        return Err(TraceExportError::config(format!("{field} is empty")));
    }
    Ok(())
}

fn validate_address_class(class: &str) -> Result<(), TraceExportError> {
    require_text("Address class", class)?;
    if !class
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(TraceExportError::config(
            "Address class contains unsupported characters",
        ));
    }
    Ok(())
}

fn validate_sorted_ranges(functions: &[TraceFunctionMapping]) -> Result<(), TraceExportError> {
    let mut previous: Option<(&str, u64, u64)> = None;
    for function in functions {
        let (Some(start), Some(end)) = (function.address, function.end_address) else {
            return Err(TraceExportError::config(
                "symbol mapping functions require complete address ranges",
            ));
        };
        if let Some((previous_id, previous_start, previous_end)) = previous {
            if start < previous_start {
                return Err(TraceExportError::config(
                    "symbol mapping ranges are not sorted by start address",
                ));
            }
            if start < previous_end {
                return Err(TraceExportError::config(format!(
                    "function address ranges `{previous_id}` and `{}` overlap",
                    function.function_id
                )));
            }
        }
        previous = Some((&function.function_id, start, end));
    }
    Ok(())
}

/// Extracts deterministic nonoverlapping function ranges from an executable ELF.
pub fn trace_function_mappings_from_elf(
    bytes: &[u8],
    module: &str,
    maximum_functions: usize,
) -> Result<Vec<TraceFunctionMapping>, TraceExportError> {
    require_text("ELF module", module)?;
    if maximum_functions == 0 || maximum_functions > MAX_TRACE32_FUNCTION_RANGES {
        return Err(TraceExportError::config(format!(
            "ELF function limit must be 1..={MAX_TRACE32_FUNCTION_RANGES}"
        )));
    }
    let file = object::File::parse(bytes)
        .map_err(|error| TraceExportError::config(format!("invalid ELF: {error}")))?;
    if file.format() != BinaryFormat::Elf || file.kind() != ObjectKind::Executable {
        return Err(TraceExportError::config(
            "TRACE32 symbol mapping requires an executable ELF",
        ));
    }

    let mut ranges = Vec::new();
    for symbol in file.symbols() {
        if !symbol.is_definition() || symbol.kind() != SymbolKind::Text || symbol.size() == 0 {
            continue;
        }
        let start = symbol.address();
        let end = start
            .checked_add(symbol.size())
            .ok_or_else(|| TraceExportError::config("ELF function address range overflows u64"))?;
        if start == end {
            continue;
        }
        let name = symbol.name().map_err(|error| {
            TraceExportError::config(format!("invalid ELF symbol name: {error}"))
        })?;
        require_text("ELF function name", name)?;
        ranges.push((start, end, name.to_owned()));
        if ranges.len() > maximum_functions {
            return Err(TraceExportError::config(format!(
                "ELF function count exceeds {maximum_functions}"
            )));
        }
    }
    ranges.sort_unstable();

    let mut functions: Vec<TraceFunctionMapping> = Vec::with_capacity(ranges.len());
    for (start, end, name) in ranges {
        if let Some(previous) = functions.last_mut() {
            let previous_start = previous.address.expect("derived range has start");
            let previous_end = previous.end_address.expect("derived range has end");
            if start == previous_start && end == previous_end {
                if name < previous.export_name {
                    previous.export_name.clone_from(&name);
                    previous.display_name = name;
                }
                continue;
            }
            if start < previous_end {
                return Err(TraceExportError::config(format!(
                    "ELF text symbols `{}` and `{name}` overlap",
                    previous.export_name
                )));
            }
        }
        functions.push(TraceFunctionMapping {
            export_name: name.clone(),
            function_id: format!("elf:{start:016x}-{end:016x}"),
            display_name: name,
            module: Some(module.to_owned()),
            address: Some(start),
            end_address: Some(end),
            file: None,
            line: None,
        });
    }
    validate_functions(&functions)?;
    validate_sorted_ranges(&functions)?;
    if functions.is_empty() {
        return Err(TraceExportError::config(
            "executable ELF contains no defined nonzero-size text functions",
        ));
    }
    Ok(functions)
}

/// Strictly decodes a symbol mapping artifact.
pub fn parse_trace32_symbol_mapping(
    bytes: &[u8],
) -> Result<Trace32SymbolMappingDocument, TraceExportError> {
    let document: Trace32SymbolMappingDocument = strict_json::from_slice(bytes)
        .map_err(|error| TraceExportError::config(error.to_string()))?;
    document.validate()?;
    Ok(document)
}

/// Strictly decodes a deployment TASKEVENTS mapping artifact.
pub fn parse_trace32_task_events_mapping(
    bytes: &[u8],
) -> Result<Trace32TaskEventsMappingDocument, TraceExportError> {
    let document: Trace32TaskEventsMappingDocument = strict_json::from_slice(bytes)
        .map_err(|error| TraceExportError::config(error.to_string()))?;
    document.validate()?;
    Ok(document)
}

/// Strictly decodes a pre-capture TASKEVENTS mapping-template artifact.
pub fn parse_trace32_task_events_mapping_template(
    bytes: &[u8],
) -> Result<Trace32TaskEventsMappingTemplateDocument, TraceExportError> {
    let document: Trace32TaskEventsMappingTemplateDocument = strict_json::from_slice(bytes)
        .map_err(|error| TraceExportError::config(error.to_string()))?;
    document.validate()?;
    Ok(document)
}

/// Generates the public TRACE32 mapping schemas owned by this crate.
#[must_use]
pub fn trace_export_schema_documents() -> BTreeMap<&'static str, Value> {
    BTreeMap::from([
        (
            "trace32-symbol-mapping.schema.json",
            trace_export_schema::<Trace32SymbolMappingDocument>(TRACE32_SYMBOL_MAPPING_SCHEMA),
        ),
        (
            "trace32-task-events-mapping.schema.json",
            trace_export_schema::<Trace32TaskEventsMappingDocument>(
                TRACE32_TASK_EVENTS_MAPPING_SCHEMA,
            ),
        ),
        (
            "trace32-task-events-mapping-template.schema.json",
            trace_export_schema::<Trace32TaskEventsMappingTemplateDocument>(
                TRACE32_TASK_EVENTS_MAPPING_TEMPLATE_SCHEMA,
            ),
        ),
    ])
}

fn trace_export_schema<T: JsonSchema>(id: &'static str) -> Value {
    let mut schema =
        serde_json::to_value(schema_for!(T)).expect("schema serialization is infallible");
    schema
        .as_object_mut()
        .expect("root schemas are objects")
        .insert("$id".to_owned(), Value::String(id.to_owned()));
    schema
}
