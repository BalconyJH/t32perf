//! Structurally validated TRACE32 parser registry.
//!
//! Raw TRACE32 parsers deliberately remain unavailable through the generic
//! [`crate::AdapterRegistry`].  This module is the only adapter boundary that
//! accepts them, and requires mutually consistent caller-supplied profile,
//! receipt, mapping, and runtime facts before it can open a source.  This is
//! not an authorization boundary: callers must establish trusted admission
//! and immutable artifact handles before using this module.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    AdapterError, AdapterRequest, ObservationSource, TargetAdapterCaptureKind,
    TargetAdapterProfile, TargetAdapterQualificationReceipt, Trace32SymbolMappingDocument,
    Trace32TaskEventsMappingDocument, TraceArtifactBinding, TraceAsciiAdapter, TraceAsciiConfig,
    TraceAsciiSource, TraceTaskEventsAdapter, TraceTaskEventsConfig, TraceTaskEventsSource,
    parse_target_adapter_qualification_receipt,
};
use t32perf_model::Sha256Digest;

/// Structurally validated target-adapter profile and receipt bytes.
///
/// Its fields remain opaque after structural validation. This type grants no
/// authorization; callers must establish admission and artifact trust first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedTargetAdapterReceipt {
    profile: TargetAdapterProfile,
    receipt: TargetAdapterQualificationReceipt,
    receipt_binding: TraceArtifactBinding,
}

impl ValidatedTargetAdapterReceipt {
    /// Checks caller-supplied receipt bytes, profile claim, and artifact identity.
    ///
    /// This establishes only structural consistency. It does not authenticate
    /// the inputs or authorize a caller to use them.
    pub fn validate_for(
        profile: TargetAdapterProfile,
        receipt_bytes: &[u8],
        receipt_binding: TraceArtifactBinding,
    ) -> Result<Self, AdapterError> {
        if receipt_binding.artifact_id.trim().is_empty() {
            return Err(invalid("qualification receipt artifact identity is empty"));
        }
        profile.validate().map_err(target_error)?;
        let receipt =
            parse_target_adapter_qualification_receipt(receipt_bytes).map_err(target_error)?;
        receipt
            .validate_for(&profile, receipt_bytes)
            .map_err(target_error)?;
        let expected = profile
            .qualification_sha256
            .as_ref()
            .expect("receipt validation requires profile claim");
        if &receipt_binding.sha256 != expected {
            return Err(invalid(
                "qualification receipt artifact digest does not match profile claim",
            ));
        }
        Ok(Self {
            profile,
            receipt,
            receipt_binding,
        })
    }

    /// Returns the verified profile.
    #[must_use]
    pub fn profile(&self) -> &TargetAdapterProfile {
        &self.profile
    }

    /// Returns the parsed verified receipt.
    #[must_use]
    pub fn receipt(&self) -> &TargetAdapterQualificationReceipt {
        &self.receipt
    }

    /// Returns the immutable qualification artifact binding.
    #[must_use]
    pub fn receipt_binding(&self) -> &TraceArtifactBinding {
        &self.receipt_binding
    }
}

/// Raw capture input identity supplied by the Controller export slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trace32ValidatedRawInputIdentity {
    /// Immutable exported input artifact.
    pub artifact: TraceArtifactBinding,
    /// Exact capture family that emitted it.
    pub capture_kind: Trace32ValidatedCaptureKind,
}

/// Closed parser capture-family discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trace32ValidatedCaptureKind {
    /// Fixed SNOOPer ASCII PC samples.
    AsciiSymbolMapping,
    /// Program-flow TASKEVENTS records.
    TaskEventsMapping,
}

/// Structurally validated parser mapping supplied as a typed immutable document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trace32ValidatedMapping {
    /// Capture-bound ELF symbol mapping for ASCII PC samples.
    AsciiSymbolMapping(Trace32SymbolMappingDocument),
    /// Capture-bound ORTI/marker mapping for TASKEVENTS.
    TaskEventsMapping(Trace32TaskEventsMappingDocument),
}

/// Exact runtime and clock facts asserted by accepted Controller evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trace32ValidatedRuntime {
    /// TRACE32 release.
    pub trace32_release: String,
    /// TRACE32 build.
    pub trace32_build: u64,
    /// TRACE32 architecture package.
    pub architecture_package: String,
    /// Target identity.
    pub target_identifier: String,
    /// Exported core.
    pub core_id: u32,
    /// Session-relative clock domain.
    pub clock_domain: String,
    /// Firmware ELF identity.
    pub elf: TraceArtifactBinding,
    /// Accepted controller health evidence.
    pub controller_health: TraceArtifactBinding,
    /// Accepted export/stop time-origin evidence.
    pub time_origin_evidence: TraceArtifactBinding,
    /// Immutable trace-export input selected by accepted Controller output.
    pub raw_input: TraceArtifactBinding,
}

/// Complete typed context for a caller-authorized structural consistency check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trace32ValidatedAdapterContext {
    /// Structurally validated profile/receipt inputs.
    pub validated_receipt: ValidatedTargetAdapterReceipt,
    /// Immutable raw export identity.
    pub raw_input: Trace32ValidatedRawInputIdentity,
    /// Exact mapping family and immutable content.
    pub mapping: Trace32ValidatedMapping,
    /// Accepted runtime, core, clock, and evidence identities.
    pub runtime: Trace32ValidatedRuntime,
    /// Parser input limits selected by trusted host policy.
    pub limits: crate::LineLimits,
}

/// Structurally validated TRACE32 parser factory; authorization remains caller-owned.
pub trait ValidatedTrace32ObservationAdapter: Send + Sync {
    /// Stable raw adapter identifier.
    fn id(&self) -> &str;
    /// Returns whether this adapter is the one exact candidate for the context.
    fn matches(&self, context: &Trace32ValidatedAdapterContext) -> Result<bool, AdapterError>;
    /// Opens an exact parser source after structurally validated, caller-authorized selection.
    fn open_validated(
        &self,
        context: Trace32ValidatedAdapterContext,
        request: AdapterRequest,
    ) -> Result<Box<dyn ObservationSource + Send>, AdapterError>;
}

/// Deterministic registry for caller-authorized structural parser selection.
#[derive(Default)]
pub struct ValidatedTrace32AdapterRegistry {
    adapters: BTreeMap<String, Box<dyn ValidatedTrace32ObservationAdapter>>,
}

impl ValidatedTrace32AdapterRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates the two strict TRACE32 parser candidates.
    pub fn defaults() -> Result<Self, AdapterError> {
        let mut registry = Self::new();
        registry.register(Box::new(TraceAsciiAdapter))?;
        registry.register(Box::new(TraceTaskEventsAdapter))?;
        Ok(registry)
    }

    /// Registers one structurally validated parser candidate.
    pub fn register(
        &mut self,
        adapter: Box<dyn ValidatedTrace32ObservationAdapter>,
    ) -> Result<(), AdapterError> {
        let id = adapter.id().to_owned();
        if id.is_empty() {
            return Err(AdapterError::EmptyAdapterId);
        }
        if self.adapters.contains_key(&id) {
            return Err(AdapterError::DuplicateAdapter { id });
        }
        self.adapters.insert(id, adapter);
        Ok(())
    }

    /// Selects exactly one parser and opens it with no inline parser options.
    pub fn open(
        &self,
        context: Trace32ValidatedAdapterContext,
        request: AdapterRequest,
    ) -> Result<Box<dyn ObservationSource + Send>, AdapterError> {
        let matches = self
            .adapters
            .values()
            .filter_map(|adapter| match adapter.matches(&context) {
                Ok(true) => Some(Ok(adapter.as_ref())),
                Ok(false) => None,
                Err(error) => Some(Err(error)),
            })
            .collect::<Result<Vec<_>, _>>()?;
        match matches.as_slice() {
            [adapter] => adapter.open_validated(context, request),
            [] => Err(AdapterError::NoValidatedTrace32Adapter),
            _ => Err(AdapterError::AmbiguousValidatedTrace32Adapters {
                adapters: matches
                    .iter()
                    .map(|adapter| adapter.id().to_owned())
                    .collect(),
            }),
        }
    }
}

impl ValidatedTrace32ObservationAdapter for TraceAsciiAdapter {
    fn id(&self) -> &str {
        crate::TRACE_ASCII_ADAPTER_ID
    }
    fn matches(&self, context: &Trace32ValidatedAdapterContext) -> Result<bool, AdapterError> {
        Ok(matches!(
            context.mapping,
            Trace32ValidatedMapping::AsciiSymbolMapping(_)
        ) && context.raw_input.capture_kind == Trace32ValidatedCaptureKind::AsciiSymbolMapping)
    }
    fn open_validated(
        &self,
        context: Trace32ValidatedAdapterContext,
        mut request: AdapterRequest,
    ) -> Result<Box<dyn ObservationSource + Send>, AdapterError> {
        request.reject_options(self.id())?;
        let Trace32ValidatedMapping::AsciiSymbolMapping(mapping) = context.mapping else {
            return Err(invalid("ASCII parser requires an ASCII symbol mapping"));
        };
        validate_ascii_context(
            &context.validated_receipt,
            &context.raw_input,
            &context.runtime,
            &mapping,
        )?;
        let input = request.take_input(self.id())?;
        let config = TraceAsciiConfig {
            clock_domain: context.runtime.clock_domain,
            core_id: context.runtime.core_id,
            address_classes: mapping.address_classes.into_iter().collect::<BTreeSet<_>>(),
            functions: mapping.functions,
            limits: context.limits,
        };
        TraceAsciiSource::new(input, request.session_id, request.source_id, config)
            .map(|source| Box::new(source) as Box<dyn ObservationSource + Send>)
            .map_err(trace_error)
    }
}

impl ValidatedTrace32ObservationAdapter for TraceTaskEventsAdapter {
    fn id(&self) -> &str {
        crate::TRACE_TASK_EVENTS_ADAPTER_ID
    }
    fn matches(&self, context: &Trace32ValidatedAdapterContext) -> Result<bool, AdapterError> {
        Ok(matches!(
            context.mapping,
            Trace32ValidatedMapping::TaskEventsMapping(_)
        ) && context.raw_input.capture_kind == Trace32ValidatedCaptureKind::TaskEventsMapping)
    }
    fn open_validated(
        &self,
        context: Trace32ValidatedAdapterContext,
        mut request: AdapterRequest,
    ) -> Result<Box<dyn ObservationSource + Send>, AdapterError> {
        request.reject_options(self.id())?;
        let Trace32ValidatedMapping::TaskEventsMapping(mapping) = context.mapping else {
            return Err(invalid("TASKEVENTS parser requires a TASKEVENTS mapping"));
        };
        validate_task_context(
            &context.validated_receipt,
            &context.raw_input,
            &context.runtime,
            &mapping,
        )?;
        let input = request.take_input(self.id())?;
        let runnables = mapping
            .runnables
            .into_iter()
            .map(|entry| (entry.export_name, entry.function_id))
            .collect();
        let config = TraceTaskEventsConfig {
            core_id: context.runtime.core_id,
            clock_domain: context.runtime.clock_domain,
            contexts: mapping.contexts,
            functions: mapping.functions,
            runnables,
            initial_context_id: None,
            limits: context.limits,
        };
        TraceTaskEventsSource::new(input, request.session_id, request.source_id, config)
            .map(|source| Box::new(source) as Box<dyn ObservationSource + Send>)
            .map_err(trace_error)
    }
}

fn validate_ascii_context(
    proof: &ValidatedTargetAdapterReceipt,
    raw: &Trace32ValidatedRawInputIdentity,
    runtime: &Trace32ValidatedRuntime,
    mapping: &Trace32SymbolMappingDocument,
) -> Result<(), AdapterError> {
    mapping.validate().map_err(trace_error)?;
    if raw.capture_kind != Trace32ValidatedCaptureKind::AsciiSymbolMapping {
        return Err(invalid("raw input capture kind is not ASCII"));
    }
    validate_common(proof, raw, runtime, MappingIdentity::ascii(mapping))?;
    if mapping.profile_id != crate::TC234L_SNOOPER_ASCII_PROFILE_V1
        || mapping.profile_sha256.as_ref() != Some(&proof.profile().digest().map_err(target_error)?)
    {
        return Err(invalid(
            "ASCII mapping profile identity is not bound to the validated profile",
        ));
    }
    let normal = proof
        .profile()
        .scenario(crate::TargetAdapterScenario::Normal)
        .ok_or_else(|| invalid("validated profile has no normal scenario"))?;
    if !matches!(
        normal.capture.capture_kind,
        TargetAdapterCaptureKind::Sampling { .. }
    ) || !normal.capture.covered_cores.contains(&runtime.core_id)
    {
        return Err(invalid(
            "ASCII mapping does not match the validated sampling capture/core",
        ));
    }
    Ok(())
}

fn validate_task_context(
    proof: &ValidatedTargetAdapterReceipt,
    raw: &Trace32ValidatedRawInputIdentity,
    runtime: &Trace32ValidatedRuntime,
    mapping: &Trace32TaskEventsMappingDocument,
) -> Result<(), AdapterError> {
    mapping.validate().map_err(trace_error)?;
    if raw.capture_kind != Trace32ValidatedCaptureKind::TaskEventsMapping {
        return Err(invalid("raw input capture kind is not TASKEVENTS"));
    }
    validate_common(proof, raw, runtime, MappingIdentity::task(mapping))?;
    let normal = proof
        .profile()
        .scenario(crate::TargetAdapterScenario::Normal)
        .ok_or_else(|| invalid("validated profile has no normal scenario"))?;
    let TargetAdapterCaptureKind::ProgramFlowTaskEvents {
        export_profile_id,
        timestamp_clock_id,
        ..
    } = &normal.capture.capture_kind
    else {
        return Err(invalid(
            "TASKEVENTS mapping does not match the validated capture kind",
        ));
    };
    if mapping.profile_id != *export_profile_id
        || mapping.profile_sha256 != proof.profile().digest().map_err(target_error)?
        || mapping.core_id != runtime.core_id
    {
        return Err(invalid(
            "TASKEVENTS mapping profile digest or core does not match validated runtime",
        ));
    }
    if timestamp_clock_id.as_str() != runtime.clock_domain
        || !normal.capture.covered_cores.contains(&runtime.core_id)
    {
        return Err(invalid(
            "TASKEVENTS clock or core does not match validated capture",
        ));
    }
    Ok(())
}

struct MappingIdentity<'a> {
    release: &'a str,
    build: u64,
    architecture: &'a str,
    target: &'a str,
    elf_id: &'a str,
    elf_sha: &'a Sha256Digest,
    health: &'a TraceArtifactBinding,
    origin: &'a TraceArtifactBinding,
    receipt: &'a TraceArtifactBinding,
}

impl<'a> MappingIdentity<'a> {
    fn ascii(mapping: &'a Trace32SymbolMappingDocument) -> Self {
        Self {
            release: &mapping.trace32_release,
            build: mapping.trace32_build,
            architecture: &mapping.architecture_package,
            target: &mapping.target_identifier,
            elf_id: &mapping.elf_artifact_id,
            elf_sha: &mapping.elf_sha256,
            health: &mapping.controller_health,
            origin: &mapping.time_origin_evidence,
            receipt: &mapping.qualification_receipt,
        }
    }

    fn task(mapping: &'a Trace32TaskEventsMappingDocument) -> Self {
        Self {
            release: &mapping.trace32_release,
            build: mapping.trace32_build,
            architecture: &mapping.architecture_package,
            target: &mapping.target_identifier,
            elf_id: &mapping.elf_artifact_id,
            elf_sha: &mapping.elf_sha256,
            health: &mapping.controller_health,
            origin: &mapping.time_origin_evidence,
            receipt: &mapping.qualification_receipt,
        }
    }
}

fn validate_common(
    proof: &ValidatedTargetAdapterReceipt,
    raw: &Trace32ValidatedRawInputIdentity,
    runtime: &Trace32ValidatedRuntime,
    mapping: MappingIdentity<'_>,
) -> Result<(), AdapterError> {
    if raw.artifact.artifact_id.trim().is_empty() || runtime.clock_domain.trim().is_empty() {
        return Err(invalid("raw input identity or runtime clock is empty"));
    }
    if raw.artifact != runtime.raw_input {
        return Err(invalid(
            "raw input identity does not match accepted runtime export",
        ));
    }
    let profile = proof.profile();
    if mapping.release != profile.build_gate.trace32_release
        || mapping.build < profile.build_gate.minimum_build
        || mapping.build > profile.build_gate.maximum_build
        || mapping.architecture != profile.build_gate.architecture_package
        || mapping.target != profile.target_identifier
    {
        return Err(invalid("mapping does not match validated profile identity"));
    }
    if runtime.trace32_release != mapping.release
        || runtime.trace32_build != mapping.build
        || runtime.architecture_package != mapping.architecture
        || runtime.target_identifier != mapping.target
    {
        return Err(invalid("runtime does not match mapping identity"));
    }
    if runtime.elf.artifact_id != mapping.elf_id
        || runtime.elf.sha256 != *mapping.elf_sha
        || *mapping.elf_sha != profile.firmware_elf_sha256
    {
        return Err(invalid(
            "ELF identity does not match validated profile and mapping",
        ));
    }
    if &runtime.controller_health != mapping.health
        || &runtime.time_origin_evidence != mapping.origin
        || mapping.receipt != proof.receipt_binding()
    {
        return Err(invalid(
            "controller, time-origin, or qualification binding does not match mapping",
        ));
    }
    let receipt = proof.receipt();
    if receipt.trace32_release != runtime.trace32_release
        || receipt.trace32_build != runtime.trace32_build
        || receipt.architecture_package != runtime.architecture_package
        || receipt.target_identifier != runtime.target_identifier
        || receipt.firmware_elf_sha256 != runtime.elf.sha256
    {
        return Err(invalid(
            "qualification receipt does not match accepted runtime or firmware identity",
        ));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> AdapterError {
    AdapterError::InvalidConfiguration {
        adapter: "validated-trace32".to_owned(),
        message: message.into(),
    }
}
fn trace_error(error: crate::TraceExportError) -> AdapterError {
    invalid(error.to_string())
}
fn target_error(error: crate::TargetAdapterError) -> AdapterError {
    invalid(error.to_string())
}
