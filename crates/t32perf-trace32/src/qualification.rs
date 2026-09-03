//! Deployment qualification policy and strict HIL receipt contracts.
//!
//! These contracts deliberately sit below the controller.  They make the
//! deployment trust anchor explicit: a qualification receipt is evidence, and
//! a separately protected policy decides which evidence is admissible.

use std::collections::{BTreeMap, BTreeSet};

use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use t32perf_model::{Sha256Digest, is_portable_artifact_id, strict_json};
use thiserror::Error;

use crate::{
    TargetAdapterFailureKind, TargetAdapterProfile, TargetAdapterQualificationReceipt,
    TargetAdapterRecoveryEvidence, TargetAdapterScenario,
    parse_target_adapter_qualification_receipt,
};

/// Schema identifier for an ACL-protected qualification allowlist snapshot.
pub const TARGET_ADAPTER_QUALIFICATION_POLICY_SCHEMA: &str =
    "t32perf.target-adapter-qualification-policy/v1";
/// Schema identifier for a host-derived immutable admission snapshot.
pub const TARGET_ADAPTER_ADMISSION_SNAPSHOT_SCHEMA: &str =
    "t32perf.target-adapter-admission-snapshot/v1";
/// Schema identifier for the ACL-protected deployment trust-store.
pub const TARGET_ADAPTER_QUALIFICATION_TRUST_STORE_SCHEMA: &str =
    "t32perf.target-adapter-qualification-trust-store/v1";
/// Maximum accepted trust-store size.
pub const MAX_TARGET_ADAPTER_QUALIFICATION_TRUST_STORE_BYTES: usize = 64 * 1024;
/// Schema identifier for a host-reconstructed HIL verification receipt.
pub const HIL_VERIFICATION_RECEIPT_SCHEMA: &str = "t32perf.hil-verification-receipt/v1";
/// Maximum accepted HIL receipt size.
pub const MAX_HIL_VERIFICATION_RECEIPT_BYTES: usize = 4 * 1024 * 1024;
const MAX_POLICY_BYTES: usize = 16 * 1024;
const MAX_TRUST_STORE_ENTRIES: usize = 256;
const MAX_TEXT_BYTES: usize = 4 * 1024;
const MAX_FAILURES: usize = 128;

/// The single supported policy schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum TargetAdapterQualificationPolicySchemaVersion {
    /// Version 1.
    #[serde(rename = "t32perf.target-adapter-qualification-policy/v1")]
    V1,
}

/// The single supported admission-snapshot schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum TargetAdapterAdmissionSnapshotSchemaVersion {
    /// Version 1.
    #[serde(rename = "t32perf.target-adapter-admission-snapshot/v1")]
    V1,
}

/// The single supported deployment trust-store schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum TargetAdapterQualificationTrustStoreSchemaVersion {
    /// Version 1.
    #[serde(rename = "t32perf.target-adapter-qualification-trust-store/v1")]
    V1,
}

/// One exact policy authorization from an ACL-protected deployment store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetAdapterQualificationTrustEntry {
    /// Portable policy identifier, used only to select the fixed policy filename.
    pub policy_id: String,
    /// SHA-256 of the policy's exact raw bytes.
    pub policy_sha256: Sha256Digest,
}

/// ACL-protected exact policy allowlist.
///
/// Entries are sorted by `policy_id` and are unique. This document is an
/// independent deployment trust anchor, not Session evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetAdapterQualificationTrustStore {
    /// Trust-store schema version.
    pub schema: TargetAdapterQualificationTrustStoreSchemaVersion,
    /// Exact authorized policies in canonical ascending `policy_id` order.
    #[schemars(length(min = 1, max = 256))]
    pub entries: Vec<TargetAdapterQualificationTrustEntry>,
}

/// Closed HIL receipt kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HilVerificationKind {
    /// Native timeline verification.
    NativeTimeline,
    /// Resource verification.
    Resources,
    /// Fault injection verification.
    FaultInjection,
}

/// Closed HIL fault scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum HilFaultScenario {
    /// TRACE32 trace-overflow injection.
    #[serde(rename = "trace_overflow", alias = "overflow")]
    TraceOverflow,
    /// Flow-error injection.
    #[serde(rename = "flow_error")]
    FlowError,
    /// SNOOPer Stack reaches the fixed sampling capacity.
    #[serde(rename = "sampling_buffer_full")]
    SamplingBufferFull,
    /// ELF mismatch injection.
    #[serde(rename = "elf_mismatch")]
    ElfMismatch,
    /// TRACE32 disconnect recovery.
    #[serde(rename = "trace32_disconnect_recovery")]
    Trace32DisconnectRecovery,
    /// Driver disconnect recovery.
    #[serde(rename = "driver_disconnect_recovery")]
    DriverDisconnectRecovery,
    /// CMM abort recovery.
    #[serde(rename = "cmm_abort_recovery")]
    CmmAbortRecovery,
}

/// Independently protected exact deployment authorization for one adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetAdapterQualificationPolicy {
    /// Policy document version.
    pub schema: TargetAdapterQualificationPolicySchemaVersion,
    /// Stable ACL snapshot identifier.
    pub policy_id: String,
    /// Stable adapter identity.
    pub adapter_id: String,
    /// Exact adapter version.
    pub adapter_version: String,
    /// Candidate profile digest, with its qualification claim cleared.
    pub candidate_profile_sha256: Sha256Digest,
    /// Complete qualified profile digest after binding the receipt bytes.
    pub qualified_profile_sha256: Sha256Digest,
    /// Deployment-verified expected release-bundle manifest digest.
    ///
    /// Upstream t32mcp does not runtime-attest the installed skill bytes.
    pub implementation_sha256: Sha256Digest,
    /// Exact firmware ELF artifact digest.
    pub firmware_elf_sha256: Sha256Digest,
    /// Exact TRACE32 release.
    pub trace32_release: String,
    /// Exact TRACE32 build.
    #[schemars(range(min = 1))]
    pub trace32_build: u64,
    /// Exact TRACE32 architecture package.
    pub architecture_package: String,
    /// Exact target identity.
    pub target_identifier: String,
    /// Exact debug probe identity.
    pub probe_identifier: String,
    /// Digest of the immutable qualification receipt bytes.
    pub qualification_receipt_sha256: Sha256Digest,
    /// Digest of the immutable HIL receipt bytes.
    pub hil_verification_receipt_sha256: Sha256Digest,
    /// Exact verified board identity.
    pub board_id: String,
    /// Exact qualified t32mcp implementation version.
    pub t32mcp_version: String,
    /// Exact expected HIL kind.
    pub expected_hil_kind: HilVerificationKind,
    /// Exact expected HIL scenario; non-fault kinds require `None`.
    #[schemars(required)]
    pub expected_hil_scenario: Option<HilFaultScenario>,
    /// Canonical deployment scenarios authorized by this exact HIL claim.
    #[schemars(length(min = 1, max = 8))]
    pub allowed_scenarios: Vec<TargetAdapterScenario>,
}

/// Host-derived durable record of the exact evidence admitted for one Session.
///
/// This is not an authorization root.  It records the raw immutable artifacts
/// that were accepted under a separately ACL-protected policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetAdapterAdmissionSnapshot {
    /// Snapshot document version.
    pub schema: TargetAdapterAdmissionSnapshotSchemaVersion,
    /// ACL policy snapshot identifier.
    pub policy_id: String,
    /// SHA-256 of the policy artifact raw bytes.
    pub policy_sha256: Sha256Digest,
    /// SHA-256 of the HIL receipt raw bytes.
    pub hil_verification_receipt_sha256: Sha256Digest,
    /// SHA-256 of the qualification receipt raw bytes.
    pub qualification_receipt_sha256: Sha256Digest,
    /// Candidate profile digest with its qualification claim cleared.
    pub candidate_profile_sha256: Sha256Digest,
    /// Complete qualified profile digest with its receipt claim bound.
    pub qualified_profile_sha256: Sha256Digest,
    /// Deployment-verified expected release-bundle manifest digest.
    ///
    /// Upstream t32mcp does not runtime-attest the installed skill bytes.
    pub implementation_sha256: Sha256Digest,
    /// Exact firmware ELF digest.
    pub firmware_elf_sha256: Sha256Digest,
    /// Exact t32mcp version pin.
    pub t32mcp_version: String,
    /// Canonical authorized adapter scenarios.
    #[schemars(length(min = 1, max = 8))]
    pub allowed_scenarios: Vec<TargetAdapterScenario>,
}

/// Strictly validated HIL receipt facts needed by the deployment boundary.
#[derive(Debug, Clone, PartialEq)]
pub struct HilVerificationReceipt {
    /// Closed receipt kind.
    pub kind: HilVerificationKind,
    /// Fault scenario, if and only if this is fault injection.
    pub scenario: Option<HilFaultScenario>,
    /// Board used for HIL verification.
    pub board_id: String,
    /// Portable Session identifier used by the HIL runner.
    pub session_id: String,
    /// Reference driver digest.
    pub driver_reference_sha256: Sha256Digest,
    /// PASS or FAIL result.
    pub verdict: HilVerificationVerdict,
    /// Immutable target-adapter identity bound to a fault-injection receipt.
    ///
    /// Sampling-buffer-full evidence requires this binding. Other fault
    /// scenarios may carry it when the HIL producer has the same exact
    /// adapter-manifest facts available.
    pub fault_adapter_binding: Option<HilFaultAdapterBinding>,
    /// Digest-bound recovery evidence for recovery scenarios.
    pub recovery_evidence: Option<HilRecoveryEvidenceBinding>,
}

/// Exact adapter identity recorded by a HIL fault-injection receipt.
///
/// `profile_sha256` is the canonical target-adapter candidate-profile digest;
/// `profile_file_sha256` is retained as the independently pinned source-file
/// evidence and is deliberately not substituted for the canonical identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HilFaultAdapterBinding {
    /// Fault scenario bound by the fault-scenarios manifest.
    pub scenario: HilFaultScenario,
    /// Immutable fault-scenarios manifest digest.
    pub fault_scenarios_sha256: Sha256Digest,
    /// Exact target-adapter identifier.
    pub adapter_id: String,
    /// Canonical target-adapter candidate-profile digest.
    pub profile_sha256: Sha256Digest,
    /// Immutable target-adapter profile file digest, retained as evidence.
    pub profile_file_sha256: Sha256Digest,
    /// Exact release-bundle manifest digest.
    pub bundle_sha256: Sha256Digest,
}

/// Closed HIL verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HilVerificationVerdict {
    /// Every check passed.
    Pass,
    /// At least one check failed.
    Fail,
}

/// Strict recovery evidence nested by a recovery HIL receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HilRecoveryEvidenceBinding {
    /// Immutable digest of the recovery-evidence artifact.
    pub sha256: Sha256Digest,
    /// Fully validated target-adapter recovery evidence.
    pub document: TargetAdapterRecoveryEvidence,
}

/// Qualification-policy or HIL-contract failure.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum QualificationError {
    /// A bounded strict JSON document could not be decoded.
    #[error("qualification document is invalid: {message}")]
    InvalidDocument {
        /// Stable parsing detail.
        message: String,
    },
    /// A policy violates its closed semantic contract.
    #[error("qualification policy is invalid: {message}")]
    InvalidPolicy {
        /// Stable validation detail.
        message: String,
    },
    /// HIL evidence violates its closed semantic contract.
    #[error("HIL verification receipt is invalid: {message}")]
    InvalidHilReceipt {
        /// Stable validation detail.
        message: String,
    },
    /// A policy and evidence do not authorize the candidate profile.
    #[error("qualification evidence does not match policy: {message}")]
    BindingMismatch {
        /// Stable cross-binding detail.
        message: String,
    },
}

impl TargetAdapterQualificationPolicy {
    /// Validates all bounded policy fields and kind/scenario semantics.
    pub fn validate(&self) -> Result<(), QualificationError> {
        for (field, value, maximum) in [
            ("policy_id", self.policy_id.as_str(), 256),
            ("adapter_id", self.adapter_id.as_str(), MAX_TEXT_BYTES),
            (
                "adapter_version",
                self.adapter_version.as_str(),
                MAX_TEXT_BYTES,
            ),
            (
                "trace32_release",
                self.trace32_release.as_str(),
                MAX_TEXT_BYTES,
            ),
            (
                "architecture_package",
                self.architecture_package.as_str(),
                MAX_TEXT_BYTES,
            ),
            (
                "target_identifier",
                self.target_identifier.as_str(),
                MAX_TEXT_BYTES,
            ),
            (
                "probe_identifier",
                self.probe_identifier.as_str(),
                MAX_TEXT_BYTES,
            ),
            ("board_id", self.board_id.as_str(), 256),
            (
                "t32mcp_version",
                self.t32mcp_version.as_str(),
                MAX_TEXT_BYTES,
            ),
        ] {
            bounded_text(field, value, maximum).map_err(policy_error)?;
        }
        if self.trace32_build == 0 {
            return Err(QualificationError::InvalidPolicy {
                message: "trace32_build must be nonzero".to_owned(),
            });
        }
        validate_kind_scenario(self.expected_hil_kind, self.expected_hil_scenario)
            .map_err(policy_error)?;
        validate_canonical_scenarios(&self.allowed_scenarios).map_err(policy_error)?;
        Ok(())
    }
}

impl TargetAdapterQualificationTrustStore {
    /// Validates the bounded, canonical allowlist contract.
    pub fn validate(&self) -> Result<(), QualificationError> {
        if self.entries.is_empty() || self.entries.len() > MAX_TRUST_STORE_ENTRIES {
            return Err(QualificationError::InvalidPolicy {
                message: "trust store entries are outside the fixed bound".to_owned(),
            });
        }
        let mut previous = None;
        for entry in &self.entries {
            if !is_portable_artifact_id(&entry.policy_id) {
                return Err(QualificationError::InvalidPolicy {
                    message: "trust store policy_id is not a portable identifier".to_owned(),
                });
            }
            if previous.is_some_and(|value: &str| value >= entry.policy_id.as_str()) {
                return Err(QualificationError::InvalidPolicy {
                    message: "trust store entries must be unique and sorted by policy_id"
                        .to_owned(),
                });
            }
            previous = Some(entry.policy_id.as_str());
        }
        Ok(())
    }

    /// Finds the exact raw policy digest authorized for `policy_id`.
    #[must_use]
    pub fn policy_sha256(&self, policy_id: &str) -> Option<&Sha256Digest> {
        self.entries
            .binary_search_by(|entry| entry.policy_id.as_str().cmp(policy_id))
            .ok()
            .map(|index| &self.entries[index].policy_sha256)
    }
}

impl TargetAdapterAdmissionSnapshot {
    /// Validates the snapshot's bounded, closed semantic fields.
    pub fn validate(&self) -> Result<(), QualificationError> {
        bounded_text("policy_id", &self.policy_id, 256).map_err(policy_error)?;
        bounded_text("t32mcp_version", &self.t32mcp_version, MAX_TEXT_BYTES)
            .map_err(policy_error)?;
        validate_canonical_scenarios(&self.allowed_scenarios).map_err(policy_error)
    }
}

/// Strictly decodes an ACL-protected policy snapshot.
pub fn parse_target_adapter_qualification_policy(
    bytes: &[u8],
) -> Result<TargetAdapterQualificationPolicy, QualificationError> {
    if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
        return Err(QualificationError::InvalidPolicy {
            message: "policy size is outside the fixed bound".to_owned(),
        });
    }
    let value = strict_json::value_from_slice(bytes).map_err(|error| {
        QualificationError::InvalidDocument {
            message: error.to_string(),
        }
    })?;
    exact_policy_fields(object(&value, "policy")?)?;
    let policy: TargetAdapterQualificationPolicy =
        serde_json::from_value(value).map_err(|error| QualificationError::InvalidDocument {
            message: error.to_string(),
        })?;
    policy.validate()?;
    Ok(policy)
}

/// Strictly decodes one ACL-protected deployment trust-store.
pub fn parse_target_adapter_qualification_trust_store(
    bytes: &[u8],
) -> Result<TargetAdapterQualificationTrustStore, QualificationError> {
    if bytes.is_empty() || bytes.len() > MAX_TARGET_ADAPTER_QUALIFICATION_TRUST_STORE_BYTES {
        return Err(QualificationError::InvalidPolicy {
            message: "trust store size is outside the fixed bound".to_owned(),
        });
    }
    let value = strict_json::value_from_slice(bytes).map_err(|error| {
        QualificationError::InvalidDocument {
            message: error.to_string(),
        }
    })?;
    exact_fields(
        object(&value, "qualification trust store")?,
        &["schema", "entries"],
    )?;
    let trust_store: TargetAdapterQualificationTrustStore =
        serde_json::from_value(value).map_err(|error| QualificationError::InvalidDocument {
            message: error.to_string(),
        })?;
    trust_store.validate()?;
    Ok(trust_store)
}

/// Strictly decodes one host-derived target-adapter admission snapshot.
pub fn parse_target_adapter_admission_snapshot(
    bytes: &[u8],
) -> Result<TargetAdapterAdmissionSnapshot, QualificationError> {
    if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
        return Err(QualificationError::InvalidPolicy {
            message: "admission snapshot size is outside the fixed bound".to_owned(),
        });
    }
    let value = strict_json::value_from_slice(bytes).map_err(|error| {
        QualificationError::InvalidDocument {
            message: error.to_string(),
        }
    })?;
    exact_snapshot_fields(object(&value, "admission snapshot")?)?;
    let snapshot: TargetAdapterAdmissionSnapshot =
        serde_json::from_value(value).map_err(|error| QualificationError::InvalidDocument {
            message: error.to_string(),
        })?;
    snapshot.validate()?;
    Ok(snapshot)
}

/// Strictly parses and semantically validates one bounded HIL receipt.
pub fn parse_hil_verification_receipt(
    bytes: &[u8],
) -> Result<HilVerificationReceipt, QualificationError> {
    if bytes.is_empty() || bytes.len() > MAX_HIL_VERIFICATION_RECEIPT_BYTES {
        return Err(hil_error("receipt size is outside the fixed bound"));
    }
    let value = strict_json::value_from_slice(bytes).map_err(|error| {
        QualificationError::InvalidDocument {
            message: error.to_string(),
        }
    })?;
    parse_hil_value(&value)
}

/// Verifies policy, candidate profile, and both immutable receipt byte streams.
///
/// The candidate must not carry a qualification claim.  This avoids confusing
/// its stable candidate digest with the digest of the qualified full profile.
pub fn validate_target_adapter_qualification(
    policy: &TargetAdapterQualificationPolicy,
    candidate: &TargetAdapterProfile,
    qualification_receipt_bytes: &[u8],
    qualification_receipt: &TargetAdapterQualificationReceipt,
    hil_receipt_bytes: &[u8],
    hil_receipt: &HilVerificationReceipt,
) -> Result<(), QualificationError> {
    policy.validate()?;
    candidate
        .validate()
        .map_err(|error| QualificationError::BindingMismatch {
            message: error.to_string(),
        })?;
    if candidate.has_qualification_claim() {
        return Err(binding_error(
            "candidate profile must not carry a qualification claim",
        ));
    }
    let parsed_qualification =
        parse_target_adapter_qualification_receipt(qualification_receipt_bytes)
            .map_err(|error| binding_error(error.to_string()))?;
    if &parsed_qualification != qualification_receipt {
        return Err(binding_error(
            "parsed qualification receipt differs from supplied receipt",
        ));
    }
    let mut qualified_profile = candidate.clone();
    qualified_profile.qualification_sha256 = Some(digest_bytes(qualification_receipt_bytes));
    qualification_receipt
        .validate_for(&qualified_profile, qualification_receipt_bytes)
        .map_err(|error| binding_error(error.to_string()))?;
    let qualified_profile_digest = qualified_profile
        .digest()
        .map_err(|error| binding_error(error.to_string()))?;
    let parsed_hil = parse_hil_verification_receipt(hil_receipt_bytes)?;
    if &parsed_hil != hil_receipt {
        return Err(binding_error(
            "parsed HIL receipt differs from supplied receipt",
        ));
    }
    if hil_receipt.verdict != HilVerificationVerdict::Pass {
        return Err(binding_error("HIL receipt verdict is not PASS"));
    }
    let qualification_sha = digest_bytes(qualification_receipt_bytes);
    let hil_sha = digest_bytes(hil_receipt_bytes);
    same(
        "policy adapter_id",
        &policy.adapter_id,
        &candidate.adapter_id,
    )?;
    same(
        "policy adapter_version",
        &policy.adapter_version,
        &candidate.adapter_version,
    )?;
    same_digest(
        "candidate profile",
        &policy.candidate_profile_sha256,
        &candidate
            .qualification_identity_digest()
            .map_err(|error| binding_error(error.to_string()))?,
    )?;
    same_digest(
        "qualified profile",
        &policy.qualified_profile_sha256,
        &qualified_profile_digest,
    )?;
    same_digest(
        "implementation",
        &policy.implementation_sha256,
        &candidate.implementation_sha256,
    )?;
    same_digest(
        "firmware ELF",
        &policy.firmware_elf_sha256,
        &candidate.firmware_elf_sha256,
    )?;
    same(
        "TRACE32 release",
        &policy.trace32_release,
        &candidate.build_gate.trace32_release,
    )?;
    if policy.trace32_build != candidate.build_gate.minimum_build
        || policy.trace32_build != candidate.build_gate.maximum_build
    {
        return Err(binding_error(
            "policy TRACE32 build does not exactly match candidate gate",
        ));
    }
    same(
        "architecture package",
        &policy.architecture_package,
        &candidate.build_gate.architecture_package,
    )?;
    same(
        "target identifier",
        &policy.target_identifier,
        &candidate.target_identifier,
    )?;
    same(
        "probe identifier",
        &policy.probe_identifier,
        &candidate.probe_identifier,
    )?;
    same_digest(
        "qualification receipt bytes",
        &policy.qualification_receipt_sha256,
        &qualification_sha,
    )?;
    same_digest(
        "HIL receipt bytes",
        &policy.hil_verification_receipt_sha256,
        &hil_sha,
    )?;
    same_digest(
        "qualification receipt HIL",
        &qualification_receipt.hil_verification_receipt_sha256,
        &hil_sha,
    )?;
    same(
        "receipt adapter_id",
        &qualification_receipt.adapter_id,
        &candidate.adapter_id,
    )?;
    same(
        "receipt adapter_version",
        &qualification_receipt.adapter_version,
        &candidate.adapter_version,
    )?;
    same_digest(
        "receipt candidate profile",
        &qualification_receipt.candidate_profile_sha256,
        &candidate
            .qualification_identity_digest()
            .map_err(|error| binding_error(error.to_string()))?,
    )?;
    same_digest(
        "receipt implementation",
        &qualification_receipt.implementation_sha256,
        &candidate.implementation_sha256,
    )?;
    same_digest(
        "receipt firmware ELF",
        &qualification_receipt.firmware_elf_sha256,
        &candidate.firmware_elf_sha256,
    )?;
    same(
        "receipt TRACE32 release",
        &qualification_receipt.trace32_release,
        &candidate.build_gate.trace32_release,
    )?;
    if qualification_receipt.trace32_build != candidate.build_gate.minimum_build
        || candidate.build_gate.minimum_build != candidate.build_gate.maximum_build
    {
        return Err(binding_error(
            "receipt TRACE32 build does not exactly match candidate gate",
        ));
    }
    same(
        "receipt architecture package",
        &qualification_receipt.architecture_package,
        &candidate.build_gate.architecture_package,
    )?;
    same(
        "receipt target identifier",
        &qualification_receipt.target_identifier,
        &candidate.target_identifier,
    )?;
    same(
        "receipt probe identifier",
        &qualification_receipt.probe_identifier,
        &candidate.probe_identifier,
    )?;
    same(
        "receipt t32mcp version",
        &qualification_receipt.t32mcp_version,
        &policy.t32mcp_version,
    )?;
    if hil_receipt.kind != policy.expected_hil_kind
        || hil_receipt.scenario != policy.expected_hil_scenario
    {
        return Err(binding_error("HIL kind or scenario does not match policy"));
    }
    if let Some(recovery) = &hil_receipt.recovery_evidence {
        validate_recovery_cross_binding(&recovery.document, candidate, hil_receipt.scenario)?;
    }
    if let Some(binding) = &hil_receipt.fault_adapter_binding {
        validate_fault_adapter_cross_binding(binding, candidate, hil_receipt.scenario)?;
    }
    let expected_scenarios = scenarios_authorized_by_hil(hil_receipt.kind, hil_receipt.scenario)?;
    if policy.allowed_scenarios != expected_scenarios {
        return Err(binding_error(
            "policy allowed_scenarios do not exactly match its HIL claim",
        ));
    }
    let candidate_scenarios = candidate
        .scenarios
        .iter()
        .map(|contract| contract.scenario)
        .collect::<BTreeSet<_>>();
    if !policy
        .allowed_scenarios
        .iter()
        .all(|scenario| candidate_scenarios.contains(scenario))
    {
        return Err(binding_error(
            "policy authorizes a scenario not implemented by candidate profile",
        ));
    }
    same("HIL board", &hil_receipt.board_id, &policy.board_id)
}

fn validate_fault_adapter_cross_binding(
    binding: &HilFaultAdapterBinding,
    candidate: &TargetAdapterProfile,
    scenario: Option<HilFaultScenario>,
) -> Result<(), QualificationError> {
    if Some(binding.scenario) != scenario {
        return Err(binding_error(
            "fault adapter binding scenario does not match HIL scenario",
        ));
    }
    same(
        "fault adapter adapter_id",
        &binding.adapter_id,
        &candidate.adapter_id,
    )?;
    same_digest(
        "fault adapter canonical profile",
        &binding.profile_sha256,
        &candidate
            .qualification_identity_digest()
            .map_err(|error| binding_error(error.to_string()))?,
    )?;
    // This is evidence of the precisely pinned on-disk profile input. There
    // is no profile-file byte stream in this Rust boundary, so it must not be
    // confused with the canonical profile identity above.
    same_digest(
        "fault adapter release bundle",
        &binding.bundle_sha256,
        &candidate.implementation_sha256,
    )
}

fn scenarios_authorized_by_hil(
    kind: HilVerificationKind,
    scenario: Option<HilFaultScenario>,
) -> Result<Vec<TargetAdapterScenario>, QualificationError> {
    match (kind, scenario) {
        (HilVerificationKind::NativeTimeline | HilVerificationKind::Resources, None) => {
            Ok(vec![TargetAdapterScenario::Normal])
        }
        (HilVerificationKind::FaultInjection, Some(HilFaultScenario::TraceOverflow)) => {
            Ok(vec![TargetAdapterScenario::TraceOverflow])
        }
        (HilVerificationKind::FaultInjection, Some(HilFaultScenario::FlowError)) => {
            Ok(vec![TargetAdapterScenario::FlowError])
        }
        (HilVerificationKind::FaultInjection, Some(HilFaultScenario::SamplingBufferFull)) => {
            Ok(vec![TargetAdapterScenario::SamplingBufferFull])
        }
        (
            HilVerificationKind::FaultInjection,
            Some(HilFaultScenario::Trace32DisconnectRecovery),
        ) => Ok(vec![TargetAdapterScenario::Trace32Disconnect]),
        (HilVerificationKind::FaultInjection, Some(HilFaultScenario::DriverDisconnectRecovery)) => {
            Ok(vec![TargetAdapterScenario::DriverDisconnect])
        }
        (HilVerificationKind::FaultInjection, Some(HilFaultScenario::CmmAbortRecovery)) => {
            Ok(vec![TargetAdapterScenario::CmmAbort])
        }
        (HilVerificationKind::FaultInjection, Some(HilFaultScenario::ElfMismatch)) => Err(
            binding_error("ELF mismatch HIL has no deployable target-adapter scenario"),
        ),
        _ => Err(binding_error("HIL kind and scenario are inconsistent")),
    }
}

/// Returns generated JSON Schema documents for qualification policy artifacts.
#[must_use]
pub fn qualification_schema_documents() -> BTreeMap<&'static str, Value> {
    BTreeMap::from([
        (
            "target-adapter-qualification-policy.schema.json",
            schema_document::<TargetAdapterQualificationPolicy>(
                TARGET_ADAPTER_QUALIFICATION_POLICY_SCHEMA,
            ),
        ),
        (
            "target-adapter-admission-snapshot.schema.json",
            schema_document::<TargetAdapterAdmissionSnapshot>(
                TARGET_ADAPTER_ADMISSION_SNAPSHOT_SCHEMA,
            ),
        ),
        (
            "target-adapter-qualification-trust-store.schema.json",
            schema_document::<TargetAdapterQualificationTrustStore>(
                TARGET_ADAPTER_QUALIFICATION_TRUST_STORE_SCHEMA,
            ),
        ),
    ])
}

fn parse_hil_value(value: &Value) -> Result<HilVerificationReceipt, QualificationError> {
    let root = object(value, "receipt")?;
    exact_fields_allowed(
        root,
        &[
            "schema",
            "source",
            "kind",
            "scenario",
            "board_id",
            "session_id",
            "driver_reference_sha256",
            "recovery_evidence",
            "tolerance",
            "artifact_bindings",
            "checks",
            "check_categories",
            "max_error",
            "failure_count",
            "failures",
            "failures_truncated",
            "verdict",
        ],
        &["recovery_evidence", "fault_adapter_binding"],
    )?;
    string_equals(root, "schema", HIL_VERIFICATION_RECEIPT_SCHEMA)?;
    string_equals(root, "source", "host-reconstructed-session-artifacts")?;
    let kind = parse_kind(string(root, "kind", 64)?)?;
    let scenario = parse_scenario(
        root.get("scenario")
            .ok_or_else(|| hil_error("receipt scenario is missing"))?,
    )?;
    validate_kind_scenario(kind, scenario).map_err(hil_error)?;
    let board_id = bounded_value_string(root, "board_id", 256)?;
    let session_id = bounded_value_string(root, "session_id", 64)?;
    if !portable_session_id(&session_id) {
        return Err(hil_error("receipt session_id is not portable"));
    }
    let driver_reference_sha256 = value_digest(root, "driver_reference_sha256")?;
    validate_tolerance(
        root.get("tolerance")
            .ok_or_else(|| hil_error("receipt tolerance is missing"))?,
    )?;
    validate_bindings(
        kind,
        root.get("artifact_bindings")
            .ok_or_else(|| hil_error("artifact_bindings is missing"))?,
    )?;
    let checks = validate_counts(
        root.get("checks")
            .ok_or_else(|| hil_error("checks is missing"))?,
        "checks",
    )?;
    validate_categories(
        kind,
        scenario,
        root.get("check_categories")
            .ok_or_else(|| hil_error("check_categories is missing"))?,
        checks,
    )?;
    validate_max_error(
        root.get("max_error")
            .ok_or_else(|| hil_error("max_error is missing"))?,
    )?;
    let failure_count = nonnegative_u64(
        root.get("failure_count")
            .ok_or_else(|| hil_error("failure_count is missing"))?,
        "failure_count",
    )?;
    let failures = array(
        root.get("failures")
            .ok_or_else(|| hil_error("failures is missing"))?,
        "failures",
        MAX_FAILURES,
    )?;
    for failure in failures {
        let row = object(failure, "failure")?;
        exact_fields(row, &["check", "reason"])?;
        bounded_value_string(row, "check", 512)?;
        bounded_value_string(row, "reason", 2048)?;
    }
    let truncated = root
        .get("failures_truncated")
        .and_then(Value::as_bool)
        .ok_or_else(|| hil_error("failures_truncated must be boolean"))?;
    if failure_count != checks.failed {
        return Err(hil_error("failure_count does not match failed checks"));
    }
    if truncated != (failure_count > failures.len() as u64) {
        return Err(hil_error("failures_truncated is inconsistent"));
    }
    if !truncated && failure_count != failures.len() as u64 {
        return Err(hil_error("receipt omits untruncated failures"));
    }
    let verdict = match string(root, "verdict", 8)? {
        "PASS" => HilVerificationVerdict::Pass,
        "FAIL" => HilVerificationVerdict::Fail,
        _ => return Err(hil_error("unsupported verdict")),
    };
    if (verdict == HilVerificationVerdict::Pass) != (checks.failed == 0) {
        return Err(hil_error("verdict contradicts failed checks"));
    }
    let fault_adapter_binding = parse_fault_adapter_binding(
        kind,
        scenario,
        root.get("fault_adapter_binding").unwrap_or(&Value::Null),
    )?;
    let recovery_evidence = parse_recovery(
        kind,
        scenario,
        root.get("recovery_evidence").unwrap_or(&Value::Null),
    )?;
    Ok(HilVerificationReceipt {
        kind,
        scenario,
        board_id,
        session_id,
        driver_reference_sha256,
        verdict,
        fault_adapter_binding,
        recovery_evidence,
    })
}

#[derive(Clone, Copy)]
struct Counts {
    total: u64,
    passed: u64,
    failed: u64,
}

fn validate_tolerance(value: &Value) -> Result<(), QualificationError> {
    let row = object(value, "tolerance")?;
    exact_fields(
        row,
        &[
            "timestamp_absolute_ns",
            "timestamp_relative",
            "continuous_relative",
            "continuous_absolute",
            "integer_absolute",
        ],
    )?;
    for key in row.keys() {
        nonnegative_number(row.get(key).expect("iterated key exists"), key)?;
    }
    Ok(())
}

fn validate_bindings(kind: HilVerificationKind, value: &Value) -> Result<(), QualificationError> {
    let rows = array(value, "artifact_bindings", 11)?;
    if rows.len() < 2 {
        return Err(hil_error("artifact_bindings has fewer than two entries"));
    }
    let mut roles = BTreeSet::new();
    for value in rows {
        let row = object(value, "artifact binding")?;
        exact_fields(row, &["role", "artifact_id", "sha256"])?;
        let role = bounded_value_string(row, "role", 64)?;
        if !all_roles().contains(role.as_str()) || !roles.insert(role.clone()) {
            return Err(hil_error(
                "artifact binding role is unsupported or duplicated",
            ));
        }
        if role == "manifest" {
            if !row.get("artifact_id").is_some_and(Value::is_null) {
                return Err(hil_error("manifest artifact_id must be null"));
            }
        } else {
            bounded_value_string(row, "artifact_id", 256)?;
        }
        value_digest(row, "sha256")?;
    }
    let required: BTreeSet<&str> = match kind {
        HilVerificationKind::Resources => resource_roles(),
        HilVerificationKind::NativeTimeline => native_roles(),
        HilVerificationKind::FaultInjection => ["manifest", "health"].into_iter().collect(),
    };
    if !required.iter().all(|role| roles.contains(*role)) {
        return Err(hil_error("artifact binding roles are incomplete"));
    }
    if kind == HilVerificationKind::Resources && roles.len() != required.len()
        || kind == HilVerificationKind::NativeTimeline && roles.len() != required.len()
        || kind == HilVerificationKind::FaultInjection
            && !roles.iter().all(|role| {
                ["manifest", "health", "observations", "analysis_summary"].contains(&role.as_str())
            })
    {
        return Err(hil_error(
            "artifact binding roles do not match receipt kind",
        ));
    }
    Ok(())
}

fn validate_categories(
    kind: HilVerificationKind,
    scenario: Option<HilFaultScenario>,
    value: &Value,
    total: Counts,
) -> Result<(), QualificationError> {
    let rows = array(value, "check_categories", 8)?;
    let expected = category_names(kind);
    if rows.len() != expected.len() {
        return Err(hil_error("check category count is invalid"));
    }
    let mut sum = Counts {
        total: 0,
        passed: 0,
        failed: 0,
    };
    let recovery = matches!(
        scenario,
        Some(
            HilFaultScenario::Trace32DisconnectRecovery
                | HilFaultScenario::DriverDisconnectRecovery
                | HilFaultScenario::CmmAbortRecovery
        )
    );
    for (row_value, &expected_name) in rows.iter().zip(expected.iter()) {
        let row = object(row_value, "check category")?;
        exact_fields(row, &["category", "counts"])?;
        if string(row, "category", 64)? != expected_name {
            return Err(hil_error("check categories are not in canonical order"));
        }
        let counts = validate_counts(
            row.get("counts")
                .ok_or_else(|| hil_error("category counts are missing"))?,
            "category counts",
        )?;
        let required = kind != HilVerificationKind::FaultInjection
            || matches!(
                expected_name,
                "artifact_binding" | "health" | "fault_publication"
            )
            || recovery;
        if required && counts.total == 0 {
            return Err(hil_error("required check category is empty"));
        }
        sum.total = sum
            .total
            .checked_add(counts.total)
            .ok_or_else(|| hil_error("category total count overflows u64"))?;
        sum.passed = sum
            .passed
            .checked_add(counts.passed)
            .ok_or_else(|| hil_error("category passed count overflows u64"))?;
        sum.failed = sum
            .failed
            .checked_add(counts.failed)
            .ok_or_else(|| hil_error("category failed count overflows u64"))?;
    }
    if (sum.total, sum.passed, sum.failed) != (total.total, total.passed, total.failed) {
        return Err(hil_error("category counts do not match checks"));
    }
    Ok(())
}

fn parse_fault_adapter_binding(
    kind: HilVerificationKind,
    scenario: Option<HilFaultScenario>,
    value: &Value,
) -> Result<Option<HilFaultAdapterBinding>, QualificationError> {
    if value.is_null() {
        if kind == HilVerificationKind::FaultInjection
            && scenario == Some(HilFaultScenario::SamplingBufferFull)
        {
            return Err(hil_error(
                "sampling_buffer_full receipt requires fault_adapter_binding",
            ));
        }
        return Ok(None);
    }
    if kind != HilVerificationKind::FaultInjection {
        return Err(hil_error(
            "non-fault receipt cannot bind an adapter fault manifest",
        ));
    }
    let row = object(value, "fault_adapter_binding")?;
    exact_fields(
        row,
        &[
            "scenario",
            "fault_scenarios_sha256",
            "adapter_id",
            "profile_sha256",
            "profile_file_sha256",
            "bundle_sha256",
        ],
    )?;
    let binding_scenario = parse_scenario(
        row.get("scenario")
            .ok_or_else(|| hil_error("fault adapter binding scenario is missing"))?,
    )?
    .ok_or_else(|| hil_error("fault adapter binding scenario must be a fault scenario"))?;
    if Some(binding_scenario) != scenario {
        return Err(hil_error(
            "fault adapter binding scenario does not match receipt",
        ));
    }
    Ok(Some(HilFaultAdapterBinding {
        scenario: binding_scenario,
        fault_scenarios_sha256: value_digest(row, "fault_scenarios_sha256")?,
        adapter_id: bounded_value_string(row, "adapter_id", 256)?,
        profile_sha256: value_digest(row, "profile_sha256")?,
        profile_file_sha256: value_digest(row, "profile_file_sha256")?,
        bundle_sha256: value_digest(row, "bundle_sha256")?,
    }))
}

fn parse_recovery(
    kind: HilVerificationKind,
    scenario: Option<HilFaultScenario>,
    value: &Value,
) -> Result<Option<HilRecoveryEvidenceBinding>, QualificationError> {
    let expected_kind = match scenario {
        Some(HilFaultScenario::Trace32DisconnectRecovery) => {
            Some(TargetAdapterFailureKind::Trace32Disconnect)
        }
        Some(HilFaultScenario::DriverDisconnectRecovery) => {
            Some(TargetAdapterFailureKind::DriverDisconnect)
        }
        Some(HilFaultScenario::CmmAbortRecovery) => Some(TargetAdapterFailureKind::CmmAbort),
        _ => None,
    };
    if kind != HilVerificationKind::FaultInjection || expected_kind.is_none() {
        if !value.is_null() {
            return Err(hil_error(
                "non-recovery receipt must have null recovery_evidence",
            ));
        }
        return Ok(None);
    }
    let row = object(value, "recovery_evidence")?;
    exact_fields(row, &["sha256", "document"])?;
    let sha256 = value_digest(row, "sha256")?;
    let document_value = row
        .get("document")
        .ok_or_else(|| hil_error("recovery document is missing"))?;
    let document: TargetAdapterRecoveryEvidence = serde_json::from_value(document_value.clone())
        .map_err(|error| hil_error(error.to_string()))?;
    validate_recovery_document(&document, expected_kind.expect("checked"))?;
    Ok(Some(HilRecoveryEvidenceBinding { sha256, document }))
}

fn validate_recovery_document(
    value: &TargetAdapterRecoveryEvidence,
    expected_kind: TargetAdapterFailureKind,
) -> Result<(), QualificationError> {
    value
        .validate()
        .map_err(|error| hil_error(error.to_string()))?;
    if value.failure_kind != expected_kind
        || value.initial_target_state != value.restored_target_state
        || !value.adapter_state_restored
        || !value.upstream_abort_confirmed
        || value.upstream_abort_receipt_sha256.is_none()
        || value.files_deleted
        || !value.new_session_required
    {
        return Err(hil_error(
            "recovery evidence does not restore the required canonical target state",
        ));
    }
    if let Some(sampling) = &value.sampling
        && (sampling.method != crate::ControllerSamplingMethod::RealTime
            || sampling.object != crate::ControllerSamplingObject::ProgramCounter
            || sampling.buffer_mode != crate::ControllerSamplingBufferMode::Stack
            || sampling.state != crate::ControllerSamplingState::Off
            || sampling.requested_rate_ns != 1_000_000
            || sampling.capacity_records != 65_536
            || sampling.auto_arm
            || sampling.auto_init
            || !sampling.zero_reset)
    {
        return Err(hil_error("sampling recovery evidence is not canonical"));
    }
    Ok(())
}

fn validate_recovery_cross_binding(
    value: &TargetAdapterRecoveryEvidence,
    candidate: &TargetAdapterProfile,
    scenario: Option<HilFaultScenario>,
) -> Result<(), QualificationError> {
    same_digest(
        "recovery evidence candidate profile",
        &value.profile_sha256,
        &candidate
            .qualification_identity_digest()
            .map_err(|error| binding_error(error.to_string()))?,
    )?;
    let (expected_kind, expected_operation) = match scenario {
        Some(HilFaultScenario::Trace32DisconnectRecovery) => (
            TargetAdapterFailureKind::Trace32Disconnect,
            crate::PerfOperation::Stop,
        ),
        Some(HilFaultScenario::DriverDisconnectRecovery) => (
            TargetAdapterFailureKind::DriverDisconnect,
            crate::PerfOperation::Export,
        ),
        Some(HilFaultScenario::CmmAbortRecovery) => (
            TargetAdapterFailureKind::CmmAbort,
            crate::PerfOperation::Start,
        ),
        _ => return Err(binding_error("unexpected recovery HIL scenario")),
    };
    if value.failure_kind != expected_kind || value.failed_operation != expected_operation {
        return Err(binding_error(
            "recovery evidence failure kind or fault point does not match HIL scenario",
        ));
    }
    if value.sampling.is_none() {
        return Err(binding_error(
            "recovery evidence must include the canonical sampling baseline",
        ));
    }
    Ok(())
}

fn validate_max_error(value: &Value) -> Result<(), QualificationError> {
    let row = object(value, "max_error")?;
    exact_fields(row, &["check", "absolute", "relative"])?;
    if !row.get("check").is_some_and(Value::is_null) {
        bounded_value_string(row, "check", 512)?;
    }
    nonnegative_number(
        row.get("absolute")
            .ok_or_else(|| hil_error("max_error.absolute missing"))?,
        "max_error.absolute",
    )?;
    nonnegative_number(
        row.get("relative")
            .ok_or_else(|| hil_error("max_error.relative missing"))?,
        "max_error.relative",
    )
}
fn validate_counts(value: &Value, label: &str) -> Result<Counts, QualificationError> {
    let row = object(value, label)?;
    exact_fields(row, &["total", "passed", "failed"])?;
    let result = Counts {
        total: nonnegative_u64(
            row.get("total")
                .ok_or_else(|| hil_error("count total missing"))?,
            "total",
        )?,
        passed: nonnegative_u64(
            row.get("passed")
                .ok_or_else(|| hil_error("count passed missing"))?,
            "passed",
        )?,
        failed: nonnegative_u64(
            row.get("failed")
                .ok_or_else(|| hil_error("count failed missing"))?,
            "failed",
        )?,
    };
    if result
        .passed
        .checked_add(result.failed)
        .ok_or_else(|| hil_error("count addition overflows u64"))?
        != result.total
    {
        return Err(hil_error("counts do not add up"));
    }
    Ok(result)
}
fn parse_kind(value: &str) -> Result<HilVerificationKind, QualificationError> {
    match value {
        "native_timeline" => Ok(HilVerificationKind::NativeTimeline),
        "resources" => Ok(HilVerificationKind::Resources),
        "fault_injection" => Ok(HilVerificationKind::FaultInjection),
        _ => Err(hil_error("unsupported HIL kind")),
    }
}
fn parse_scenario(value: &Value) -> Result<Option<HilFaultScenario>, QualificationError> {
    if value.is_null() {
        return Ok(None);
    }
    Ok(Some(
        match value
            .as_str()
            .ok_or_else(|| hil_error("scenario must be a string or null"))?
        {
            // `overflow` was emitted only by the pre-contract Rust parser.
            // Preserve parse compatibility while canonical serialization and
            // generated schemas use the Python/HIL spelling `trace_overflow`.
            "trace_overflow" | "overflow" => HilFaultScenario::TraceOverflow,
            "flow_error" => HilFaultScenario::FlowError,
            "sampling_buffer_full" => HilFaultScenario::SamplingBufferFull,
            "elf_mismatch" => HilFaultScenario::ElfMismatch,
            "trace32_disconnect_recovery" => HilFaultScenario::Trace32DisconnectRecovery,
            "driver_disconnect_recovery" => HilFaultScenario::DriverDisconnectRecovery,
            "cmm_abort_recovery" => HilFaultScenario::CmmAbortRecovery,
            _ => return Err(hil_error("unsupported HIL scenario")),
        },
    ))
}
fn validate_kind_scenario(
    kind: HilVerificationKind,
    scenario: Option<HilFaultScenario>,
) -> Result<(), String> {
    if (kind == HilVerificationKind::FaultInjection) != scenario.is_some() {
        return Err("HIL kind and scenario are inconsistent".to_owned());
    }
    Ok(())
}

fn validate_canonical_scenarios(scenarios: &[TargetAdapterScenario]) -> Result<(), String> {
    if scenarios.is_empty() || scenarios.len() > 8 {
        return Err("allowed_scenarios must contain 1..=8 entries".to_owned());
    }
    if !scenarios.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err("allowed_scenarios must be unique and canonical".to_owned());
    }
    Ok(())
}
fn category_names(kind: HilVerificationKind) -> &'static [&'static str] {
    match kind {
        HilVerificationKind::Resources => &[
            "artifact_binding",
            "allocator",
            "stack",
            "static_ram",
            "trace_buffer",
            "clock_alignment",
            "call_depth",
            "analysis_summary",
        ],
        HilVerificationKind::NativeTimeline => &[
            "artifact_binding",
            "function",
            "task",
            "isr",
            "context_switch",
            "interrupt",
            "function_activation",
        ],
        HilVerificationKind::FaultInjection => &[
            "artifact_binding",
            "health",
            "fault_publication",
            "recovery",
        ],
    }
}
fn all_roles() -> BTreeSet<&'static str> {
    resource_roles().union(&native_roles()).copied().collect()
}
fn resource_roles() -> BTreeSet<&'static str> {
    [
        "manifest",
        "health",
        "observations",
        "analysis_summary",
        "hotspots",
        "static_ram_report",
        "static_ram_config",
        "static_ram_source",
        "resource_source",
        "normalize_config",
    ]
    .into_iter()
    .collect()
}
fn native_roles() -> BTreeSet<&'static str> {
    [
        "manifest",
        "health",
        "observations",
        "analysis_summary",
        "hotspots",
        "derived",
    ]
    .into_iter()
    .collect()
}
fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(hex_encode(&Sha256::digest(bytes))).expect("SHA-256 is valid")
}
fn same(label: &str, actual: &str, expected: &str) -> Result<(), QualificationError> {
    if actual == expected {
        Ok(())
    } else {
        Err(binding_error(format!("{label} does not match")))
    }
}
fn same_digest(
    label: &str,
    actual: &Sha256Digest,
    expected: &Sha256Digest,
) -> Result<(), QualificationError> {
    same(label, actual.as_str(), expected.as_str())
}
fn schema_document<T: JsonSchema>(id: &'static str) -> Value {
    let mut schema =
        serde_json::to_value(schema_for!(T)).expect("schema serialization is infallible");
    schema
        .as_object_mut()
        .expect("schema root is object")
        .insert("$id".to_owned(), Value::String(id.to_owned()));
    schema
}
fn object<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>, QualificationError> {
    value
        .as_object()
        .ok_or_else(|| hil_error(format!("{label} must be an object")))
}
fn array<'a>(
    value: &'a Value,
    label: &str,
    maximum: usize,
) -> Result<&'a Vec<Value>, QualificationError> {
    let result = value
        .as_array()
        .ok_or_else(|| hil_error(format!("{label} must be an array")))?;
    if result.len() > maximum {
        return Err(hil_error(format!("{label} exceeds its fixed bound")));
    }
    Ok(result)
}
fn exact_fields(row: &Map<String, Value>, names: &[&str]) -> Result<(), QualificationError> {
    let actual: BTreeSet<&str> = row.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = names.iter().copied().collect();
    if actual == expected {
        Ok(())
    } else {
        Err(hil_error("object fields are not closed and exact"))
    }
}

fn exact_fields_allowed(
    row: &Map<String, Value>,
    required_names: &[&str],
    optional_names: &[&str],
) -> Result<(), QualificationError> {
    let actual: BTreeSet<&str> = row.keys().map(String::as_str).collect();
    let required: BTreeSet<&str> = required_names.iter().copied().collect();
    let optional: BTreeSet<&str> = optional_names.iter().copied().collect();
    let allowed = required.union(&optional).copied().collect::<BTreeSet<_>>();
    if required.is_subset(&actual) && actual.is_subset(&allowed) {
        Ok(())
    } else {
        Err(hil_error("object fields are not closed and exact"))
    }
}

fn exact_policy_fields(row: &Map<String, Value>) -> Result<(), QualificationError> {
    exact_fields(
        row,
        &[
            "schema",
            "policy_id",
            "adapter_id",
            "adapter_version",
            "candidate_profile_sha256",
            "qualified_profile_sha256",
            "implementation_sha256",
            "firmware_elf_sha256",
            "trace32_release",
            "trace32_build",
            "architecture_package",
            "target_identifier",
            "probe_identifier",
            "qualification_receipt_sha256",
            "hil_verification_receipt_sha256",
            "board_id",
            "t32mcp_version",
            "expected_hil_kind",
            "expected_hil_scenario",
            "allowed_scenarios",
        ],
    )
    .map_err(|error| QualificationError::InvalidPolicy {
        message: error.to_string(),
    })
}

fn exact_snapshot_fields(row: &Map<String, Value>) -> Result<(), QualificationError> {
    exact_fields(
        row,
        &[
            "schema",
            "policy_id",
            "policy_sha256",
            "hil_verification_receipt_sha256",
            "qualification_receipt_sha256",
            "candidate_profile_sha256",
            "qualified_profile_sha256",
            "implementation_sha256",
            "firmware_elf_sha256",
            "t32mcp_version",
            "allowed_scenarios",
        ],
    )
    .map_err(|error| QualificationError::InvalidPolicy {
        message: error.to_string(),
    })
}
fn string<'a>(
    row: &'a Map<String, Value>,
    name: &str,
    maximum: usize,
) -> Result<&'a str, QualificationError> {
    let value = row
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| hil_error(format!("{name} must be a string")))?;
    bounded_text(name, value, maximum).map_err(hil_error)?;
    Ok(value)
}
fn string_equals(
    row: &Map<String, Value>,
    name: &str,
    expected: &str,
) -> Result<(), QualificationError> {
    if string(row, name, MAX_TEXT_BYTES)? == expected {
        Ok(())
    } else {
        Err(hil_error(format!("{name} is not the required value")))
    }
}
fn bounded_value_string(
    row: &Map<String, Value>,
    name: &str,
    maximum: usize,
) -> Result<String, QualificationError> {
    Ok(string(row, name, maximum)?.to_owned())
}
fn value_digest(row: &Map<String, Value>, name: &str) -> Result<Sha256Digest, QualificationError> {
    Sha256Digest::new(string(row, name, 64)?)
        .map_err(|_| hil_error(format!("{name} must be a SHA-256 digest")))
}
fn bounded_text(field: &str, value: &str, maximum: usize) -> Result<(), String> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        Err(format!(
            "{field} is empty, too long, or contains a control character"
        ))
    } else {
        Ok(())
    }
}
fn nonnegative_u64(value: &Value, label: &str) -> Result<u64, QualificationError> {
    value
        .as_u64()
        .ok_or_else(|| hil_error(format!("{label} must be a nonnegative integer")))
}
fn nonnegative_number(value: &Value, label: &str) -> Result<(), QualificationError> {
    value
        .as_f64()
        .filter(|number| number.is_finite() && *number >= 0.0)
        .map(|_| ())
        .ok_or_else(|| hil_error(format!("{label} must be finite and nonnegative")))
}
fn portable_session_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'-')
}
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
fn hil_error(message: impl Into<String>) -> QualificationError {
    QualificationError::InvalidHilReceipt {
        message: message.into(),
    }
}
fn policy_error(message: String) -> QualificationError {
    QualificationError::InvalidPolicy { message }
}
fn binding_error(message: impl Into<String>) -> QualificationError {
    QualificationError::BindingMismatch {
        message: message.into(),
    }
}
