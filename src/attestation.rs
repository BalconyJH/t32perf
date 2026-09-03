use std::{
    collections::BTreeMap,
    error::Error as StdError,
    fmt,
    fs::{self, File, OpenOptions},
    io::Read as _,
    path::Path,
};

use anyhow::{Context as _, Result, bail, ensure};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use t32perf_model::{
    AdapterInfo, Artifact, ArtifactPath, AttestationSigningRequest,
    AttestationSigningRequestSchemaVersion, CaptureAttestation, CaptureAttestationPayload,
    CaptureAttestationSchemaVersion, CaptureCapabilities, CaptureConfigDocument, CaptureReceipt,
    CaptureReceiptSchemaVersion, CaptureTrustKey, CaptureTrustPolicy,
    ControllerHealthArtifactClaim, FirmwareInfo, HealthObservation, MetricSupportEntry,
    MetricSupportLevel, Properties, SessionState, SessionStatus, Sha256Digest, Trace32Info,
    strict_json,
};
use t32perf_session::{ArtifactSpec, IngestIntentClassification, Session, SessionLock};
use t32perf_trace32::{ControllerTargetAdapterBinding, TargetAdapterProfile};

use crate::capture_config::{
    CAPTURE_CONFIG_ID, RegisteredCaptureConfig, capture_config_claim, configuration_sha256,
    registered_capture_config, validate_capture_config_claim, validate_capture_config_receipt,
};

pub const CAPTURE_ATTESTATION_ID: &str = "capture-attestation";
pub const CAPTURE_ATTESTATION_KIND: &str = "capture_attestation";
pub const CAPTURE_ATTESTATION_PATH: &str = "capture/capture-attestation.json";
pub const CAPTURE_ATTESTATION_PRODUCER: &str = "t32perf.external-attestation/untrusted";
pub const CAPTURE_TRUST_POLICY_ID: &str = "capture-trust-policy";
pub const CAPTURE_TRUST_POLICY_KIND: &str = "capture_trust_policy";
pub const CAPTURE_TRUST_POLICY_PATH: &str = "capture/capture-trust-policy.json";
pub const CAPTURE_TRUST_POLICY_PRODUCER: &str = "t32perf.capture-trust-policy/v1";
pub const CAPTURE_RECEIPT_PATH: &str = "capture/capture-receipt.json";
pub const ATTESTATION_SIGNING_REQUEST_ID: &str = "attestation-signing-request";
pub const ATTESTATION_SIGNING_REQUEST_KIND: &str = "attestation_signing_request";
pub const ATTESTATION_SIGNING_REQUEST_PATH: &str = "capture/attestation-signing-request.json";
pub const ATTESTATION_SIGNING_REQUEST_PRODUCER: &str = "t32perf-attestation-signing-request/v1";
pub const ATTESTATION_SIGNER_DISPATCH_INTENT_ID: &str = "attestation-signer-dispatch-intent";
pub const ATTESTATION_SIGNER_DISPATCH_INTENT_KIND: &str = "attestation_signer_dispatch_intent";
pub const ATTESTATION_SIGNER_DISPATCH_INTENT_PATH: &str =
    "logs/performance-run/attestation-signer-dispatch-intent.json";
pub const ATTESTATION_SIGNER_DISPATCH_INTENT_PRODUCER: &str = "t32perf-performance-run-journal/v1";
pub const MAX_CAPTURE_CONTROL_BYTES: u64 = 1024 * 1024;
const CONTROLLER_HEALTH_OBSERVATION_SOURCE: &str = "t32perf.controller-health-evidence/v1";
const ATTESTATION_SIGNING_REQUEST_STAGED_PATH: &str =
    "host-attestation/attestation-signing-request.json";
const ATTESTATION_SIGNER_DISPATCH_INTENT_STAGED_PATH: &str =
    "host-attestation/attestation-signer-dispatch-intent.json";
const CAPTURE_ATTESTATION_HOST_STAGED_PATH: &str = "host-attestation/capture-attestation.json";
const CAPTURE_TRUST_POLICY_STAGED_PATH: &str = "host-attestation/capture-trust-policy.json";
const CAPTURE_RECEIPT_STAGED_PATH: &str = "host-attestation/capture-receipt.json";

#[derive(Clone, Copy)]
struct CaptureAttestationVerificationContext<'a> {
    expected_session_id: &'a str,
    expected_nonce: &'a str,
    expected_request_sha256: &'a Sha256Digest,
    observations: &'a Artifact,
    capture_config: &'a RegisteredCaptureConfig<'a>,
    controller_health: Option<&'a crate::controller::ControllerHealthBinding>,
}

struct CaptureAttestationEnsureContext<'a> {
    artifacts: &'a [Artifact],
    signer_staged_attestation: &'a ArtifactPath,
    signing_request: Option<(&'a Artifact, &'a AttestationSigningRequest)>,
    policy: &'a CaptureTrustPolicy,
    verification: CaptureAttestationVerificationContext<'a>,
}

#[derive(Debug, Clone)]
pub struct VerifiedCaptureAttestation {
    pub receipt: CaptureReceipt,
    pub producer: String,
    pub policy_id: String,
    pub key_id: String,
}

#[derive(Debug, Clone)]
pub struct AttestedCapture {
    pub attestation_artifact: Artifact,
    pub policy_artifact: Artifact,
    pub receipt_artifact: Artifact,
    pub producer: String,
    pub policy_id: String,
    pub key_id: String,
}

#[derive(Debug, Clone)]
pub struct EnsureAttestedResult {
    pub verified: VerifiedCaptureAttestation,
    pub resumed: bool,
}

#[derive(Debug, Clone)]
pub struct EnsureSignerDispatchIntentResult {
    pub resumed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignerDispatchAmbiguousError {
    session_id: String,
    signing_request_sha256: Sha256Digest,
}

impl fmt::Display for SignerDispatchAmbiguousError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "attestation signer dispatch for Session `{}` and signing request `{}` is ambiguous: the durable intent exists but no complete signer output or immutable attestation is available",
            self.session_id, self.signing_request_sha256
        )
    }
}

impl StdError for SignerDispatchAmbiguousError {}

pub(crate) fn is_signer_dispatch_ambiguous(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<SignerDispatchAmbiguousError>()
        .is_some()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum AttestationSignerDispatchIntentSchemaVersion {
    #[serde(rename = "t32perf.attestation-signer-dispatch-intent/v1")]
    V1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestationSignerDispatchIntent {
    schema: AttestationSignerDispatchIntentSchemaVersion,
    session_id: String,
    operation_id: String,
    session_request_sha256: Sha256Digest,
    signing_request_artifact_id: String,
    signing_request_sha256: Sha256Digest,
    policy_artifact_id: String,
    policy_artifact_sha256: Sha256Digest,
    policy_id: String,
    key_id: String,
    performance_run_deployment_sha256: Sha256Digest,
    signer_executable_sha256: Sha256Digest,
}

struct AttestationSigningRequestBuildContext<'a> {
    session: &'a Session,
    state: &'a SessionState,
    artifacts: &'a [Artifact],
    observations: &'a Artifact,
    capture_config: &'a RegisteredCaptureConfig<'a>,
    completed: &'a crate::controller::AcceptedTrace32CompletedBinding,
    controller_health: &'a crate::controller::ControllerHealthBinding,
    policy: &'a CaptureTrustPolicy,
}

struct ExpectedSignerDispatch<'a> {
    policy_sha256: &'a Sha256Digest,
    performance_run_deployment_sha256: &'a Sha256Digest,
    signer_executable_sha256: &'a Sha256Digest,
}

#[cfg(test)]
pub fn ensure_attestation_policy_snapshot(
    session: &Session,
    lock: &SessionLock,
    policy_path: &Path,
    expected_policy_sha256: &Sha256Digest,
    policy_id: &str,
    key_id: &str,
) -> Result<Artifact> {
    captured_attestation_state(session)?;
    let artifacts = session
        .registered_artifacts(true)
        .context("verify Session artifacts before ensuring the capture trust policy")?;
    let (artifact, _, _) = ensure_capture_trust_policy_artifact(
        session,
        lock,
        &artifacts,
        policy_path,
        expected_policy_sha256,
        policy_id,
        key_id,
    )?;
    Ok(artifact)
}

/// Pins the deployment-owned policy before any controller activity so a
/// receipt-bound resume never needs to reopen the external policy source.
pub(crate) fn ensure_deployment_attestation_policy_snapshot(
    session: &Session,
    lock: &SessionLock,
    policy_path: &Path,
    expected_policy_sha256: &Sha256Digest,
    policy_id: &str,
    key_id: &str,
) -> Result<Artifact> {
    ensure!(
        session.read_state()?.status == SessionStatus::Created,
        "deployment capture trust policy can be pinned only while the Session is Created"
    );
    let artifacts = session
        .registered_artifacts(true)
        .context("verify Session artifacts before pinning the deployment capture trust policy")?;
    let (artifact, _, _) = ensure_capture_trust_policy_artifact(
        session,
        lock,
        &artifacts,
        policy_path,
        expected_policy_sha256,
        policy_id,
        key_id,
    )?;
    Ok(artifact)
}

/// Revalidates the immutable policy snapshot without consulting its external
/// deployment source.
pub(crate) fn require_attestation_policy_snapshot(
    session: &Session,
    artifacts: &[Artifact],
    expected_policy_sha256: &Sha256Digest,
    policy_id: &str,
    key_id: &str,
) -> Result<Artifact> {
    validate_registered_capture_policy(
        session,
        artifacts,
        policy_id,
        key_id,
        expected_policy_sha256,
    )
    .map(|(artifact, _)| artifact)
}

pub fn build_attestation_signing_request(
    session: &Session,
    policy_id: &str,
    key_id: &str,
) -> Result<AttestationSigningRequest> {
    let state = captured_attestation_state(session)?;
    let artifacts = session
        .registered_artifacts(true)
        .context("verify Session artifacts before building the signing request")?;
    let observations = required_artifact(&artifacts, "observations")?;
    validate_observation_artifact(observations)?;
    let capture_config = registered_capture_config(session, &artifacts)?;
    let completed = crate::controller::accepted_trace32_completed_binding(session, &artifacts)
        .map_err(|error| anyhow::anyhow!("{}: {}", error.code, error.message))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "attestation signing request requires a fully accepted TRACE32 controller chain"
            )
        })?;
    let controller_health = crate::controller::controller_health_binding(session, &artifacts)
        .map_err(|error| anyhow::anyhow!(error.message))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "attestation signing request requires accepted controller health evidence"
            )
        })?;
    let policy_artifact = required_artifact(&artifacts, CAPTURE_TRUST_POLICY_ID)?;
    validate_catalog_artifact(
        policy_artifact,
        CAPTURE_TRUST_POLICY_ID,
        CAPTURE_TRUST_POLICY_KIND,
        CAPTURE_TRUST_POLICY_PATH,
        CAPTURE_TRUST_POLICY_PRODUCER,
        &[],
    )?;
    let policy: CaptureTrustPolicy =
        read_control_json(session, policy_artifact, "capture trust policy")?;
    policy.validate().context("invalid capture trust policy")?;
    build_attestation_signing_request_from_verified(
        AttestationSigningRequestBuildContext {
            session,
            state: &state,
            artifacts: &artifacts,
            observations,
            capture_config: &capture_config,
            completed: &completed,
            controller_health: &controller_health,
            policy: &policy,
        },
        policy_id,
        key_id,
    )
}

fn build_attestation_signing_request_from_verified(
    context: AttestationSigningRequestBuildContext<'_>,
    policy_id: &str,
    key_id: &str,
) -> Result<AttestationSigningRequest> {
    let control = context.completed.control();
    let (_, admission_catalog, _, _) =
        crate::controller_qualification::load_session_admission(context.session, context.artifacts)
            .map_err(|error| anyhow::anyhow!("{}: {}", error.code, error.message))?;
    let admitted_profile = admission_catalog
        .get(&control.target_adapter.adapter_id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "completed target adapter is absent from the reconstructed admission catalog"
            )
        })?;
    let capture_capabilities = capture_capabilities_for_completed_binding(
        &admitted_profile.profile,
        &control.target_adapter,
    )?;
    ensure!(
        context.controller_health.artifact == control.health_artifact,
        "completed controller binding and accepted health artifact disagree"
    );
    ensure!(
        context.policy.policy_id == policy_id,
        "registered capture trust policy does not match the selected deployment policy"
    );
    let key = context
        .policy
        .key(key_id)
        .ok_or_else(|| anyhow::anyhow!("capture trust policy has no key `{key_id}`"))?;

    ensure!(
        context.capture_config.document.provider == key.provider
            && context.capture_config.document.adapter == key.adapter
            && context.capture_config.document.adapter
                == AdapterInfo {
                    id: control.target_adapter.adapter_id.clone(),
                    version: control.target_adapter.adapter_version.clone(),
                },
        "capture config, trusted key, and completed target-adapter identity disagree"
    );
    let build_suffix = format!("{:09}", control.trace32_build);
    let canonical_release = control
        .trace32_release
        .strip_prefix("R.")
        .unwrap_or(&control.trace32_release);
    let trace32_build = if canonical_release.ends_with(&build_suffix) {
        format!("R.{canonical_release}")
    } else {
        format!("R.{canonical_release}.{build_suffix}")
    };
    let expected_trace32 = Trace32Info {
        build: Some(trace32_build),
        probe: Some(control.probe_identifier.clone()),
        architecture_package: Some(control.architecture_package.clone()),
        properties: Properties::new(),
    };
    ensure!(
        key.trace32.as_ref() == Some(&expected_trace32),
        "trusted key TRACE32 identity disagrees with the completed controller binding"
    );
    ensure!(
        key.target.device.as_deref() == Some(control.target_identifier.as_str()),
        "trusted key target identity disagrees with the completed controller binding"
    );
    ensure!(
        key.target
            .architecture
            .as_deref()
            .is_some_and(|architecture| {
                architecture.eq_ignore_ascii_case(&control.architecture_package)
            }),
        "trusted key target architecture disagrees with the completed controller binding"
    );
    let config_sha256 = configuration_sha256(&context.capture_config.document)?;
    verify_config_constraints(key, &context.capture_config.document, &config_sha256)?;
    verify_capability_ceiling(&key.capability_ceiling, &capture_capabilities)?;
    if context.capture_config.document.timestamp.enabled {
        let clock_id = context
            .capture_config
            .document
            .timestamp
            .clock_id
            .as_deref()
            .context("authoritative capture config enables timestamps without a clock identity")?;
        ensure!(
            key.clocks.iter().any(|clock| clock.id == clock_id),
            "trusted key does not bind the authoritative capture timestamp clock"
        );
    }

    let config_claim = capture_config_claim(
        context.capture_config.artifact,
        &context.capture_config.document,
    )?;
    let health_claim = ControllerHealthArtifactClaim {
        artifact_id: context.controller_health.artifact.id.clone(),
        sha256: context.controller_health.artifact.sha256.clone(),
    };
    let receipt = CaptureReceipt {
        schema: CaptureReceiptSchemaVersion,
        session_id: context.session.id().to_string(),
        provider: context.capture_config.document.provider.clone(),
        mode: context.capture_config.document.mode.clone(),
        adapter: context.capture_config.document.adapter.clone(),
        target: Some(key.target.clone()),
        trace32: key.trace32.clone(),
        firmware: FirmwareInfo {
            elf_path: Some(control.firmware_elf_artifact.relative_path.to_string()),
            elf_sha256: Some(control.firmware_elf_artifact.sha256.clone()),
            build_id: None,
        },
        clocks: key.clocks.clone(),
        covered_cores: context.capture_config.document.covered_cores.clone(),
        capabilities: capture_capabilities,
        health_observations: controller_health_observations(context.controller_health),
        request_sha256: context
            .session
            .request_sha256()
            .context("hash immutable Session request for attestation payload")?,
        capture_config: Some(config_claim.clone()),
        controller_health: Some(health_claim.clone()),
        properties: BTreeMap::new(),
    };
    receipt
        .validate()
        .context("build valid capture receipt for attestation signer")?;
    validate_capture_config_receipt(context.capture_config, &receipt)?;
    verify_key_claims(
        key,
        &receipt,
        &context.capture_config.document,
        &config_claim.configuration_sha256,
    )?;
    let payload = CaptureAttestationPayload {
        schema: CaptureAttestationSchemaVersion,
        key_id: key.key_id.clone(),
        nonce: context.state.operation_id.clone(),
        receipt,
        observation_artifact_id: context.observations.id.clone(),
        observation_sha256: context.observations.sha256.clone(),
        capture_config: Some(config_claim),
        controller_health: Some(health_claim),
    };
    validate_attestation_payload_context(
        &payload,
        &CaptureAttestationVerificationContext {
            expected_session_id: context.session.id().as_str(),
            expected_nonce: &payload.nonce,
            expected_request_sha256: &payload.receipt.request_sha256,
            observations: context.observations,
            capture_config: context.capture_config,
            controller_health: Some(context.controller_health),
        },
    )?;
    let request = AttestationSigningRequest {
        schema: AttestationSigningRequestSchemaVersion,
        policy_id: context.policy.policy_id.clone(),
        key_id: key.key_id.clone(),
        payload,
    };
    request
        .validate()
        .context("validate Host-built attestation signing request")?;
    Ok(request)
}

pub fn ensure_attestation_signing_request(
    session: &Session,
    lock: &SessionLock,
    signing_request: &AttestationSigningRequest,
    expected_policy_sha256: &Sha256Digest,
) -> Result<Artifact> {
    let state = captured_attestation_state(session)?;
    let artifacts = session
        .registered_artifacts(true)
        .context("verify Session artifacts before ensuring the signing request")?;
    let host_built = build_attestation_signing_request(
        session,
        &signing_request.policy_id,
        &signing_request.key_id,
    )?;
    ensure!(
        &host_built == signing_request,
        "attestation signing request contains caller-supplied claims instead of the unique Host-built document"
    );
    validate_signing_request_context(session, &state, &artifacts, signing_request)?;
    let (policy_artifact, _) = validate_registered_capture_policy(
        session,
        &artifacts,
        &signing_request.policy_id,
        &signing_request.key_id,
        expected_policy_sha256,
    )?;
    let controller_health = crate::controller::controller_health_binding(session, &artifacts)
        .map_err(|error| anyhow::anyhow!(error.message))?;
    let bytes = signing_request
        .canonical_bytes()
        .context("serialize canonical attestation signing request")?;
    ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_CAPTURE_CONTROL_BYTES,
        "attestation signing request exceeds the {MAX_CAPTURE_CONTROL_BYTES}-byte limit"
    );
    let mut inputs = external_attestation_inputs(controller_health.as_ref());
    inputs.push(policy_artifact.id.clone());
    let ensured = ensure_exact_ingested_artifact(
        session,
        lock,
        &artifacts,
        &ArtifactPath::new(ATTESTATION_SIGNING_REQUEST_STAGED_PATH)
            .context("construct signing-request staging path")?,
        ArtifactSpec {
            id: ATTESTATION_SIGNING_REQUEST_ID.to_owned(),
            kind: ATTESTATION_SIGNING_REQUEST_KIND.to_owned(),
            relative_path: ArtifactPath::new(ATTESTATION_SIGNING_REQUEST_PATH)
                .context("construct attestation signing-request artifact path")?,
            media_type: "application/json".to_owned(),
            producer: ATTESTATION_SIGNING_REQUEST_PRODUCER.to_owned(),
            input_artifact_ids: inputs,
        },
        &bytes,
        "attestation signing request",
    )?;
    Ok(ensured.artifact)
}

pub fn record_signer_dispatch_intent(
    session: &Session,
    lock: &SessionLock,
    signing_request_artifact: &Artifact,
    signing_request: &AttestationSigningRequest,
    expected_policy_sha256: &Sha256Digest,
    performance_run_deployment_sha256: &Sha256Digest,
    signer_executable_sha256: &Sha256Digest,
) -> Result<EnsureSignerDispatchIntentResult> {
    let state = captured_attestation_state(session)?;
    let artifacts = session
        .registered_artifacts(true)
        .context("verify Session artifacts before recording signer dispatch")?;
    let registered = required_artifact(&artifacts, ATTESTATION_SIGNING_REQUEST_ID)?;
    let policy_artifact = required_artifact(&artifacts, CAPTURE_TRUST_POLICY_ID)?;
    let deployment_binding = artifacts.iter().find(|artifact| {
        artifact.id == crate::target_adapter_provisioning::PERFORMANCE_RUN_DEPLOYMENT_BINDING_ID
    });
    if let Some(binding) = deployment_binding {
        session
            .verify_artifact(binding, true)
            .context("verify performance-run deployment binding before signer dispatch")?;
    }
    ensure!(
        registered == signing_request_artifact,
        "attestation signing-request artifact changed after it was selected for dispatch"
    );
    validate_registered_signing_request(
        session,
        &state,
        &artifacts,
        registered,
        expected_policy_sha256,
        Some(signing_request),
    )?;
    let intent = AttestationSignerDispatchIntent {
        schema: AttestationSignerDispatchIntentSchemaVersion::V1,
        session_id: session.id().to_string(),
        operation_id: state.operation_id,
        session_request_sha256: session
            .request_sha256()
            .context("hash immutable Session request for signer dispatch")?,
        signing_request_artifact_id: registered.id.clone(),
        signing_request_sha256: registered.sha256.clone(),
        policy_artifact_id: policy_artifact.id.clone(),
        policy_artifact_sha256: policy_artifact.sha256.clone(),
        policy_id: signing_request.policy_id.clone(),
        key_id: signing_request.key_id.clone(),
        performance_run_deployment_sha256: performance_run_deployment_sha256.clone(),
        signer_executable_sha256: signer_executable_sha256.clone(),
    };
    let bytes = serde_json::to_vec(&intent).context("serialize signer dispatch intent")?;
    let ensured = ensure_exact_ingested_artifact(
        session,
        lock,
        &artifacts,
        &ArtifactPath::new(ATTESTATION_SIGNER_DISPATCH_INTENT_STAGED_PATH)
            .context("construct signer dispatch-intent staging path")?,
        ArtifactSpec {
            id: ATTESTATION_SIGNER_DISPATCH_INTENT_ID.to_owned(),
            kind: ATTESTATION_SIGNER_DISPATCH_INTENT_KIND.to_owned(),
            relative_path: ArtifactPath::new(ATTESTATION_SIGNER_DISPATCH_INTENT_PATH)
                .context("construct signer dispatch-intent artifact path")?,
            media_type: "application/json".to_owned(),
            producer: ATTESTATION_SIGNER_DISPATCH_INTENT_PRODUCER.to_owned(),
            input_artifact_ids: {
                let mut inputs = vec![registered.id.clone(), policy_artifact.id.clone()];
                if let Some(binding) = deployment_binding {
                    inputs.push(binding.id.clone());
                }
                inputs
            },
        },
        &bytes,
        "attestation signer dispatch intent",
    )?;
    Ok(EnsureSignerDispatchIntentResult {
        resumed: ensured.resumed,
    })
}

pub fn ensure_attested_from_staged(
    session: &Session,
    lock: &SessionLock,
    staged_attestation: &ArtifactPath,
    expected_policy_sha256: &Sha256Digest,
    performance_run_deployment_sha256: &Sha256Digest,
    signer_executable_sha256: &Sha256Digest,
) -> Result<EnsureAttestedResult> {
    ensure_attested_from_staged_inner(
        session,
        lock,
        staged_attestation,
        expected_policy_sha256,
        performance_run_deployment_sha256,
        signer_executable_sha256,
        || Ok(()),
    )
}

fn ensure_attested_from_staged_inner<F>(
    session: &Session,
    lock: &SessionLock,
    staged_attestation: &ArtifactPath,
    expected_policy_sha256: &Sha256Digest,
    performance_run_deployment_sha256: &Sha256Digest,
    signer_executable_sha256: &Sha256Digest,
    after_snapshot_verified: F,
) -> Result<EnsureAttestedResult>
where
    F: FnOnce() -> Result<()>,
{
    let state = captured_attestation_state(session)?;
    let artifacts = session
        .registered_artifacts(true)
        .context("verify Session artifacts before ensuring capture attestation")?;
    let signing_request_artifact = required_artifact(&artifacts, ATTESTATION_SIGNING_REQUEST_ID)?;
    let signing_request = validate_registered_signing_request(
        session,
        &state,
        &artifacts,
        signing_request_artifact,
        expected_policy_sha256,
        None,
    )?;
    validate_registered_signer_dispatch_intent(
        session,
        &state,
        &artifacts,
        signing_request_artifact,
        &signing_request,
        ExpectedSignerDispatch {
            policy_sha256: expected_policy_sha256,
            performance_run_deployment_sha256,
            signer_executable_sha256,
        },
    )?;

    if let Some(receipt_artifact) = artifacts
        .iter()
        .find(|artifact| artifact.id == crate::receipt::CAPTURE_RECEIPT_ID)
    {
        validate_registered_capture_policy(
            session,
            &artifacts,
            &signing_request.policy_id,
            &signing_request.key_id,
            expected_policy_sha256,
        )?;
        let verified = verify_registered_external_capture(session, &artifacts, receipt_artifact)?;
        ensure_registered_attestation_matches_signing_request(
            session,
            &artifacts,
            &signing_request,
        )?;
        ensure!(
            verified.policy_id == signing_request.policy_id
                && verified.key_id == signing_request.key_id,
            "verified capture receipt policy or key does not match the immutable signing request"
        );
        return Ok(EnsureAttestedResult {
            verified,
            resumed: true,
        });
    }

    let (_, policy) = validate_registered_capture_policy(
        session,
        &artifacts,
        &signing_request.policy_id,
        &signing_request.key_id,
        expected_policy_sha256,
    )?;
    let observations = required_artifact(&artifacts, "observations")?;
    validate_observation_artifact(observations)?;
    let capture_config = registered_capture_config(session, &artifacts)?;
    let controller_health = crate::controller::controller_health_binding(session, &artifacts)
        .map_err(|error| anyhow::anyhow!(error.message))?;
    let request_sha256 = session
        .request_sha256()
        .context("hash immutable Session request")?;
    let verification_context = CaptureAttestationVerificationContext {
        expected_session_id: session.id().as_str(),
        expected_nonce: &state.operation_id,
        expected_request_sha256: &request_sha256,
        observations,
        capture_config: &capture_config,
        controller_health: controller_health.as_ref(),
    };
    let (attestation_artifact, _attestation, verified, attestation_resumed) =
        ensure_capture_attestation_artifact(
            session,
            lock,
            CaptureAttestationEnsureContext {
                artifacts: &artifacts,
                signer_staged_attestation: staged_attestation,
                signing_request: Some((signing_request_artifact, &signing_request)),
                policy: &policy,
                verification: verification_context,
            },
            after_snapshot_verified,
        )?;

    let before_receipt = session
        .registered_artifacts(true)
        .context("verify Session artifacts before writing capture receipt")?;
    validate_registered_capture_policy(
        session,
        &before_receipt,
        &signing_request.policy_id,
        &signing_request.key_id,
        expected_policy_sha256,
    )?;
    let mut receipt_bytes =
        serde_json::to_vec_pretty(&verified.receipt).context("serialize capture receipt")?;
    receipt_bytes.push(b'\n');
    let receipt_artifact = ensure_exact_ingested_artifact(
        session,
        lock,
        &before_receipt,
        &ArtifactPath::new(CAPTURE_RECEIPT_STAGED_PATH)
            .context("construct capture receipt staging path")?,
        ArtifactSpec {
            id: crate::receipt::CAPTURE_RECEIPT_ID.to_owned(),
            kind: "capture_receipt".to_owned(),
            relative_path: ArtifactPath::new(CAPTURE_RECEIPT_PATH)
                .context("construct capture receipt artifact path")?,
            media_type: "application/json".to_owned(),
            producer: verified.producer.clone(),
            input_artifact_ids: external_receipt_inputs(controller_health.as_ref()),
        },
        &receipt_bytes,
        "capture receipt",
    )?
    .artifact;

    let complete_catalog = session
        .registered_artifacts(true)
        .context("verify completed capture attestation artifacts")?;
    let reverified = verify_registered_external_capture(
        session,
        &complete_catalog,
        required_artifact(&complete_catalog, &receipt_artifact.id)?,
    )?;
    ensure_registered_attestation_matches_signing_request(
        session,
        &complete_catalog,
        &signing_request,
    )?;
    ensure!(
        reverified.receipt == verified.receipt
            && reverified.producer == verified.producer
            && reverified.policy_id == verified.policy_id
            && reverified.key_id == verified.key_id,
        "capture attestation changed during durable verification"
    );
    ensure!(
        attestation_artifact.id == CAPTURE_ATTESTATION_ID,
        "capture attestation artifact identity changed before receipt publication"
    );

    Ok(EnsureAttestedResult {
        verified: reverified,
        resumed: attestation_resumed,
    })
}

pub fn attest_captured_session(
    session: &Session,
    lock: &SessionLock,
    staged_attestation: &ArtifactPath,
    policy_path: &Path,
) -> Result<AttestedCapture> {
    let state = captured_attestation_state(session)?;
    let artifacts = session
        .registered_artifacts(true)
        .context("verify Session artifact catalog")?;

    if let Some(receipt_artifact) = artifacts
        .iter()
        .find(|artifact| artifact.id == crate::receipt::CAPTURE_RECEIPT_ID)
    {
        let verified = verify_registered_external_capture(session, &artifacts, receipt_artifact)?;
        return Ok(AttestedCapture {
            attestation_artifact: required_artifact(&artifacts, CAPTURE_ATTESTATION_ID)?.clone(),
            policy_artifact: required_artifact(&artifacts, CAPTURE_TRUST_POLICY_ID)?.clone(),
            receipt_artifact: receipt_artifact.clone(),
            producer: verified.producer,
            policy_id: verified.policy_id,
            key_id: verified.key_id,
        });
    }

    let observations = required_artifact(&artifacts, "observations")?;
    validate_observation_artifact(observations)?;
    let capture_config = registered_capture_config(session, &artifacts)?;
    let controller_health = crate::controller::controller_health_binding(session, &artifacts)
        .map_err(|error| anyhow::anyhow!(error.message))?;
    let (policy_bytes, policy) = match artifacts
        .iter()
        .find(|artifact| artifact.id == CAPTURE_TRUST_POLICY_ID)
    {
        Some(policy_artifact) => {
            validate_catalog_artifact(
                policy_artifact,
                CAPTURE_TRUST_POLICY_ID,
                CAPTURE_TRUST_POLICY_KIND,
                CAPTURE_TRUST_POLICY_PATH,
                CAPTURE_TRUST_POLICY_PRODUCER,
                &[],
            )?;
            let bytes = read_artifact_bytes(session, policy_artifact, "capture trust policy")?;
            let policy: CaptureTrustPolicy = decode_control_json(&bytes, "capture trust policy")?;
            policy.validate().context("invalid capture trust policy")?;
            (bytes, policy)
        }
        None => {
            let bytes = read_policy_source_bytes(policy_path)?;
            let policy: CaptureTrustPolicy = decode_control_json(&bytes, "capture trust policy")?;
            policy.validate().context("invalid capture trust policy")?;
            (bytes, policy)
        }
    };
    let request_sha256 = session
        .request_sha256()
        .context("hash immutable Session request")?;
    let verification_context = CaptureAttestationVerificationContext {
        expected_session_id: session.id().as_str(),
        expected_nonce: &state.operation_id,
        expected_request_sha256: &request_sha256,
        observations,
        capture_config: &capture_config,
        controller_health: controller_health.as_ref(),
    };
    let host_staged_attestation = ArtifactPath::new(CAPTURE_ATTESTATION_HOST_STAGED_PATH)
        .context("construct Host capture-attestation staging path")?;
    let existing_attestation = artifacts
        .iter()
        .find(|artifact| artifact.id == CAPTURE_ATTESTATION_ID);
    let attestation_bytes = if let Some(existing) = existing_attestation {
        validate_catalog_artifact(
            existing,
            CAPTURE_ATTESTATION_ID,
            CAPTURE_ATTESTATION_KIND,
            CAPTURE_ATTESTATION_PATH,
            CAPTURE_ATTESTATION_PRODUCER,
            &external_attestation_inputs(controller_health.as_ref()),
        )?;
        read_artifact_bytes(session, existing, "capture attestation")?
    } else if let Some(host_snapshot) = optional_staged_bytes(session, &host_staged_attestation)? {
        host_snapshot
    } else {
        let destination = session.path().join(CAPTURE_ATTESTATION_PATH);
        match fs::symlink_metadata(&destination) {
            Ok(_) => read_plain_bounded_bytes(
                &destination,
                MAX_CAPTURE_CONTROL_BYTES,
                "unregistered capture attestation destination",
            )?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                optional_staged_bytes(session, staged_attestation)?.ok_or_else(|| {
                    anyhow::anyhow!("capture attestation staging output is absent")
                })?
            }
            Err(error) => {
                return Err(error).context("inspect capture attestation destination");
            }
        }
    };
    let (_attestation, memory_verified) = verify_capture_attestation_snapshot(
        &attestation_bytes,
        None,
        &policy,
        verification_context,
    )?;

    let policy_artifact = ensure_exact_ingested_artifact(
        session,
        lock,
        &artifacts,
        &ArtifactPath::new(CAPTURE_TRUST_POLICY_STAGED_PATH)
            .context("construct capture trust policy staging path")?,
        ArtifactSpec {
            id: CAPTURE_TRUST_POLICY_ID.to_owned(),
            kind: CAPTURE_TRUST_POLICY_KIND.to_owned(),
            relative_path: ArtifactPath::new(CAPTURE_TRUST_POLICY_PATH)
                .context("construct capture trust policy artifact path")?,
            media_type: "application/json".to_owned(),
            producer: CAPTURE_TRUST_POLICY_PRODUCER.to_owned(),
            input_artifact_ids: Vec::new(),
        },
        &policy_bytes,
        "capture trust policy",
    )?
    .artifact;

    let after_policy = session
        .registered_artifacts(true)
        .context("verify Session artifacts after snapshotting capture trust policy")?;
    let registered_policy_artifact = required_artifact(&after_policy, CAPTURE_TRUST_POLICY_ID)?;
    let registered_policy_bytes =
        read_artifact_bytes(session, registered_policy_artifact, "capture trust policy")?;
    ensure!(
        registered_policy_bytes == policy_bytes,
        "registered capture trust policy differs from the validated memory snapshot"
    );
    let registered_policy: CaptureTrustPolicy =
        decode_control_json(&registered_policy_bytes, "capture trust policy")?;
    registered_policy
        .validate()
        .context("invalid registered capture trust policy")?;
    let (_attestation, verified) = verify_capture_attestation_snapshot(
        &attestation_bytes,
        None,
        &registered_policy,
        verification_context,
    )?;
    ensure!(
        verified.receipt == memory_verified.receipt
            && verified.producer == memory_verified.producer
            && verified.policy_id == memory_verified.policy_id
            && verified.key_id == memory_verified.key_id,
        "registered capture trust policy changed the validated attestation result"
    );
    let attestation_artifact = ensure_exact_ingested_artifact(
        session,
        lock,
        &after_policy,
        &host_staged_attestation,
        capture_attestation_spec(external_attestation_inputs(controller_health.as_ref()))?,
        &attestation_bytes,
        "capture attestation",
    )?
    .artifact;

    let before_receipt = session
        .registered_artifacts(true)
        .context("verify Session artifacts before writing capture receipt")?;
    let mut receipt_bytes =
        serde_json::to_vec_pretty(&verified.receipt).context("serialize capture receipt")?;
    receipt_bytes.push(b'\n');
    let receipt_artifact = ensure_exact_ingested_artifact(
        session,
        lock,
        &before_receipt,
        &ArtifactPath::new(CAPTURE_RECEIPT_STAGED_PATH)
            .context("construct capture receipt staging path")?,
        ArtifactSpec {
            id: crate::receipt::CAPTURE_RECEIPT_ID.to_owned(),
            kind: "capture_receipt".to_owned(),
            relative_path: ArtifactPath::new(CAPTURE_RECEIPT_PATH)
                .context("construct capture receipt artifact path")?,
            media_type: "application/json".to_owned(),
            producer: verified.producer.clone(),
            input_artifact_ids: external_receipt_inputs(controller_health.as_ref()),
        },
        &receipt_bytes,
        "capture receipt",
    )?
    .artifact;

    let complete_catalog = session
        .registered_artifacts(true)
        .context("verify completed capture attestation artifacts")?;
    let reverified = verify_registered_external_capture(
        session,
        &complete_catalog,
        required_artifact(&complete_catalog, crate::receipt::CAPTURE_RECEIPT_ID)?,
    )?;
    ensure!(
        reverified.receipt == verified.receipt
            && reverified.producer == verified.producer
            && reverified.policy_id == verified.policy_id
            && reverified.key_id == verified.key_id,
        "capture attestation changed during durable verification"
    );

    Ok(AttestedCapture {
        attestation_artifact,
        policy_artifact,
        receipt_artifact,
        producer: verified.producer,
        policy_id: verified.policy_id,
        key_id: verified.key_id,
    })
}

fn verify_capture_attestation_snapshot(
    bytes: &[u8],
    signing_request: Option<&AttestationSigningRequest>,
    policy: &CaptureTrustPolicy,
    context: CaptureAttestationVerificationContext<'_>,
) -> Result<(CaptureAttestation, VerifiedCaptureAttestation)> {
    let attestation: CaptureAttestation = decode_control_json(bytes, "capture attestation")?;
    if let Some(signing_request) = signing_request {
        validate_attestation_matches_signing_request(&attestation, signing_request)?;
    }
    let verified = verify_capture_attestation(policy, &attestation, context)?;
    Ok((attestation, verified))
}

pub fn verify_registered_external_capture(
    session: &Session,
    artifacts: &[Artifact],
    receipt_artifact: &Artifact,
) -> Result<VerifiedCaptureAttestation> {
    let observations = required_artifact(artifacts, "observations")?;
    let capture_config = registered_capture_config(session, artifacts)?;
    let controller_health = crate::controller::controller_health_binding(session, artifacts)
        .map_err(|error| anyhow::anyhow!(error.message))?;
    let attestation_artifact = required_artifact(artifacts, CAPTURE_ATTESTATION_ID)?;
    let policy_artifact = required_artifact(artifacts, CAPTURE_TRUST_POLICY_ID)?;
    validate_observation_artifact(observations)?;
    validate_catalog_artifact(
        attestation_artifact,
        CAPTURE_ATTESTATION_ID,
        CAPTURE_ATTESTATION_KIND,
        CAPTURE_ATTESTATION_PATH,
        CAPTURE_ATTESTATION_PRODUCER,
        &external_attestation_inputs(controller_health.as_ref()),
    )?;
    validate_catalog_artifact(
        policy_artifact,
        CAPTURE_TRUST_POLICY_ID,
        CAPTURE_TRUST_POLICY_KIND,
        CAPTURE_TRUST_POLICY_PATH,
        CAPTURE_TRUST_POLICY_PRODUCER,
        &[],
    )?;
    ensure!(
        receipt_artifact.id == crate::receipt::CAPTURE_RECEIPT_ID
            && receipt_artifact.kind == "capture_receipt"
            && receipt_artifact.relative_path.as_str() == CAPTURE_RECEIPT_PATH
            && receipt_artifact.media_type == "application/json"
            && receipt_artifact.input_artifact_ids
                == external_receipt_inputs(controller_health.as_ref()),
        "external capture receipt catalog identity or provenance is invalid"
    );
    ensure_control_document_size(attestation_artifact, "capture attestation")?;
    ensure_control_document_size(policy_artifact, "capture trust policy")?;
    ensure_control_document_size(receipt_artifact, "capture receipt")?;

    let policy: CaptureTrustPolicy =
        read_control_json(session, policy_artifact, "capture trust policy")?;
    let attestation: CaptureAttestation =
        read_control_json(session, attestation_artifact, "capture attestation")?;
    let receipt: CaptureReceipt = read_control_json(session, receipt_artifact, "capture receipt")?;
    let state = session.read_state().context("read Session state")?;
    let request_sha256 = session
        .request_sha256()
        .context("hash immutable Session request")?;
    let verified = verify_capture_attestation(
        &policy,
        &attestation,
        CaptureAttestationVerificationContext {
            expected_session_id: session.id().as_str(),
            expected_nonce: &state.operation_id,
            expected_request_sha256: &request_sha256,
            observations,
            capture_config: &capture_config,
            controller_health: controller_health.as_ref(),
        },
    )?;
    ensure!(
        verified.receipt == receipt,
        "capture receipt does not equal the signed attestation receipt"
    );
    ensure!(
        receipt_artifact.producer == verified.producer,
        "capture receipt producer does not match the trusted signing key"
    );
    Ok(verified)
}

struct ExactArtifactEnsure {
    artifact: Artifact,
    resumed: bool,
}

fn captured_attestation_state(session: &Session) -> Result<SessionState> {
    let state = session.read_state().context("read Session state")?;
    ensure!(
        state.status != SessionStatus::Failed,
        "failed Session `{}` is terminal; attestation recovery cannot write or repair artifacts",
        session.id()
    );
    ensure!(
        state.status == SessionStatus::Captured,
        "capture attestation is only allowed while the Session is captured"
    );
    Ok(state)
}

fn validate_signing_request_context(
    session: &Session,
    state: &SessionState,
    artifacts: &[Artifact],
    signing_request: &AttestationSigningRequest,
) -> Result<()> {
    signing_request
        .validate()
        .context("invalid attestation signing request")?;
    let observations = required_artifact(artifacts, "observations")?;
    validate_observation_artifact(observations)?;
    let capture_config = registered_capture_config(session, artifacts)?;
    let controller_health = crate::controller::controller_health_binding(session, artifacts)
        .map_err(|error| anyhow::anyhow!(error.message))?;
    let request_sha256 = session
        .request_sha256()
        .context("hash immutable Session request for signing request")?;
    validate_attestation_payload_context(
        &signing_request.payload,
        &CaptureAttestationVerificationContext {
            expected_session_id: session.id().as_str(),
            expected_nonce: &state.operation_id,
            expected_request_sha256: &request_sha256,
            observations,
            capture_config: &capture_config,
            controller_health: controller_health.as_ref(),
        },
    )
    .context("attestation signing request does not match immutable Session facts")
}

fn validate_registered_signing_request(
    session: &Session,
    state: &SessionState,
    artifacts: &[Artifact],
    artifact: &Artifact,
    expected_policy_sha256: &Sha256Digest,
    expected: Option<&AttestationSigningRequest>,
) -> Result<AttestationSigningRequest> {
    let controller_health = crate::controller::controller_health_binding(session, artifacts)
        .map_err(|error| anyhow::anyhow!(error.message))?;
    let request: AttestationSigningRequest = {
        let bytes = read_artifact_bytes(session, artifact, "attestation signing request")?;
        let request: AttestationSigningRequest =
            decode_control_json(&bytes, "attestation signing request")?;
        let canonical = request
            .canonical_bytes()
            .context("serialize registered attestation signing request")?;
        ensure!(
            bytes == canonical,
            "registered attestation signing request is not the exact canonical document"
        );
        request
    };
    let (policy_artifact, _) = validate_registered_capture_policy(
        session,
        artifacts,
        &request.policy_id,
        &request.key_id,
        expected_policy_sha256,
    )?;
    let mut inputs = external_attestation_inputs(controller_health.as_ref());
    inputs.push(policy_artifact.id.clone());
    validate_catalog_artifact(
        artifact,
        ATTESTATION_SIGNING_REQUEST_ID,
        ATTESTATION_SIGNING_REQUEST_KIND,
        ATTESTATION_SIGNING_REQUEST_PATH,
        ATTESTATION_SIGNING_REQUEST_PRODUCER,
        &inputs,
    )?;
    if let Some(expected) = expected {
        ensure!(
            &request == expected,
            "registered attestation signing request conflicts with the exact retry"
        );
    }
    validate_signing_request_context(session, state, artifacts, &request)?;
    Ok(request)
}

fn validate_registered_signer_dispatch_intent(
    session: &Session,
    state: &SessionState,
    artifacts: &[Artifact],
    signing_request_artifact: &Artifact,
    signing_request: &AttestationSigningRequest,
    expected: ExpectedSignerDispatch<'_>,
) -> Result<AttestationSignerDispatchIntent> {
    let artifact = required_artifact(artifacts, ATTESTATION_SIGNER_DISPATCH_INTENT_ID)?;
    let deployment_binding = artifacts.iter().find(|artifact| {
        artifact.id == crate::target_adapter_provisioning::PERFORMANCE_RUN_DEPLOYMENT_BINDING_ID
    });
    if let Some(binding) = deployment_binding {
        session
            .verify_artifact(binding, true)
            .context("verify performance-run deployment binding for signer intent")?;
    }
    let (policy_artifact, _) = validate_registered_capture_policy(
        session,
        artifacts,
        &signing_request.policy_id,
        &signing_request.key_id,
        expected.policy_sha256,
    )?;
    validate_catalog_artifact(
        artifact,
        ATTESTATION_SIGNER_DISPATCH_INTENT_ID,
        ATTESTATION_SIGNER_DISPATCH_INTENT_KIND,
        ATTESTATION_SIGNER_DISPATCH_INTENT_PATH,
        ATTESTATION_SIGNER_DISPATCH_INTENT_PRODUCER,
        &{
            let mut inputs = vec![
                signing_request_artifact.id.clone(),
                policy_artifact.id.clone(),
            ];
            if let Some(binding) = deployment_binding {
                inputs.push(binding.id.clone());
            }
            inputs
        },
    )?;
    let bytes = read_artifact_bytes(session, artifact, "attestation signer dispatch intent")?;
    let intent: AttestationSignerDispatchIntent =
        decode_control_json(&bytes, "attestation signer dispatch intent")?;
    let canonical = serde_json::to_vec(&intent)
        .context("serialize registered attestation signer dispatch intent")?;
    ensure!(
        bytes == canonical,
        "registered attestation signer dispatch intent is not canonical"
    );
    let request_sha256 = session
        .request_sha256()
        .context("hash immutable Session request for signer intent")?;
    ensure!(
        intent.schema == AttestationSignerDispatchIntentSchemaVersion::V1
            && intent.session_id == session.id().as_str()
            && intent.operation_id == state.operation_id
            && intent.session_request_sha256 == request_sha256
            && intent.signing_request_artifact_id == signing_request_artifact.id
            && intent.signing_request_sha256 == signing_request_artifact.sha256
            && intent.policy_artifact_id == policy_artifact.id
            && intent.policy_artifact_sha256 == policy_artifact.sha256
            && intent.policy_id == signing_request.policy_id
            && intent.key_id == signing_request.key_id
            && &intent.performance_run_deployment_sha256
                == expected.performance_run_deployment_sha256
            && &intent.signer_executable_sha256 == expected.signer_executable_sha256,
        "attestation signer dispatch intent does not match the immutable Session or signing request"
    );
    Ok(intent)
}

fn ensure_capture_attestation_artifact<F>(
    session: &Session,
    lock: &SessionLock,
    context: CaptureAttestationEnsureContext<'_>,
    after_snapshot_verified: F,
) -> Result<(
    Artifact,
    CaptureAttestation,
    VerifiedCaptureAttestation,
    bool,
)>
where
    F: FnOnce() -> Result<()>,
{
    let CaptureAttestationEnsureContext {
        artifacts,
        signer_staged_attestation,
        signing_request,
        policy,
        verification: verification_context,
    } = context;
    let controller_health = crate::controller::controller_health_binding(session, artifacts)
        .map_err(|error| anyhow::anyhow!(error.message))?;
    let inputs = external_attestation_inputs(controller_health.as_ref());
    let existing = artifacts
        .iter()
        .find(|artifact| artifact.id == CAPTURE_ATTESTATION_ID);

    if let Some(existing) = existing {
        validate_catalog_artifact(
            existing,
            CAPTURE_ATTESTATION_ID,
            CAPTURE_ATTESTATION_KIND,
            CAPTURE_ATTESTATION_PATH,
            CAPTURE_ATTESTATION_PRODUCER,
            &inputs,
        )?;
        let bytes = read_artifact_bytes(session, existing, "capture attestation")?;
        let (attestation, verified) = verify_capture_attestation_snapshot(
            &bytes,
            signing_request.map(|(_, request)| request),
            policy,
            verification_context,
        )?;
        return Ok((existing.clone(), attestation, verified, true));
    }

    let host_staged_attestation = ArtifactPath::new(CAPTURE_ATTESTATION_HOST_STAGED_PATH)
        .context("construct Host capture-attestation staging path")?;
    let ingest_inspections = session
        .inspect_ingest_intents()
        .context("inspect durable staged-ingest state for capture attestation recovery")?;
    let attestation_intent = ingest_inspections.iter().find(|inspection| {
        inspection.artifact_id.as_deref() == Some(CAPTURE_ATTESTATION_ID)
            || inspection
                .destination_relative_path
                .as_ref()
                .is_some_and(|path| path.as_str() == CAPTURE_ATTESTATION_PATH)
    });
    if attestation_intent.is_none() && !ingest_inspections.is_empty() {
        bail!("an unrelated durable ingest intent blocks capture attestation recovery");
    }
    let destination_path = session.path().join(CAPTURE_ATTESTATION_PATH);
    let destination_exists = match fs::symlink_metadata(&destination_path) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error).context("inspect capture attestation destination"),
    };
    let host_snapshot = optional_staged_bytes(session, &host_staged_attestation)?;
    if attestation_intent.is_some() || destination_exists || host_snapshot.is_some() {
        if let Some(intent) = attestation_intent {
            ensure!(
                intent.staged_relative_path.as_ref() == Some(&host_staged_attestation),
                "capture attestation ingest recovery is bound to a non-Host staging path"
            );
            ensure!(
                matches!(
                    intent.classification,
                    IngestIntentClassification::Pending
                        | IngestIntentClassification::Resumable
                        | IngestIntentClassification::CommittedStale
                ),
                "capture attestation ingest recovery state is conflicting"
            );
        }
        let recovery_snapshot = match host_snapshot {
            Some(snapshot) => snapshot,
            None if destination_exists => read_plain_bounded_bytes(
                &destination_path,
                MAX_CAPTURE_CONTROL_BYTES,
                "unregistered capture attestation destination",
            )?,
            None => {
                return Err(
                    if let Some((signing_request_artifact, _)) = signing_request {
                        anyhow::Error::new(SignerDispatchAmbiguousError {
                            session_id: session.id().to_string(),
                            signing_request_sha256: signing_request_artifact.sha256.clone(),
                        })
                    } else {
                        anyhow::anyhow!(
                            "capture attestation recovery has no readable Host-owned snapshot"
                        )
                    },
                );
            }
        };
        verify_capture_attestation_snapshot(
            &recovery_snapshot,
            signing_request.map(|(_, request)| request),
            policy,
            verification_context,
        )?;
        session
            .ensure_staged_exact(
                lock,
                &host_staged_attestation,
                &recovery_snapshot,
                MAX_CAPTURE_CONTROL_BYTES,
            )
            .context("ensure exact Host capture-attestation recovery snapshot")?;
        let artifact = session
            .ingest_staged_bounded(
                lock,
                &host_staged_attestation,
                capture_attestation_spec(inputs)?,
                MAX_CAPTURE_CONTROL_BYTES,
            )
            .context("recover Host capture-attestation snapshot")?;
        let committed = read_artifact_bytes(session, &artifact, "capture attestation")?;
        ensure!(
            committed == recovery_snapshot,
            "committed capture attestation differs from the validated Host snapshot"
        );
        let (attestation, verified) = verify_capture_attestation_snapshot(
            &committed,
            signing_request.map(|(_, request)| request),
            policy,
            verification_context,
        )?;
        return Ok((artifact, attestation, verified, true));
    }

    let signer_snapshot =
        optional_staged_bytes(session, signer_staged_attestation)?.ok_or_else(|| {
            if let Some((signing_request_artifact, _)) = signing_request {
                anyhow::Error::new(SignerDispatchAmbiguousError {
                    session_id: session.id().to_string(),
                    signing_request_sha256: signing_request_artifact.sha256.clone(),
                })
            } else {
                anyhow::anyhow!("capture attestation staging output is absent")
            }
        })?;
    let (attestation, verified) = match verify_capture_attestation_snapshot(
        &signer_snapshot,
        signing_request.map(|(_, request)| request),
        policy,
        verification_context,
    ) {
        Ok(verified) => verified,
        Err(error)
            if signing_request.is_some()
                && (signer_snapshot.is_empty() || is_truncated_json_error(&error)) =>
        {
            let (signing_request_artifact, _) =
                signing_request.expect("ambiguous signer output has a signing request");
            return Err(anyhow::Error::new(SignerDispatchAmbiguousError {
                session_id: session.id().to_string(),
                signing_request_sha256: signing_request_artifact.sha256.clone(),
            }));
        }
        Err(error) => return Err(error),
    };
    after_snapshot_verified()?;
    let ensured = ensure_exact_ingested_artifact(
        session,
        lock,
        artifacts,
        &host_staged_attestation,
        capture_attestation_spec(inputs)?,
        &signer_snapshot,
        "capture attestation",
    )?;
    Ok((ensured.artifact, attestation, verified, ensured.resumed))
}

fn capture_attestation_spec(input_artifact_ids: Vec<String>) -> Result<ArtifactSpec> {
    Ok(ArtifactSpec {
        id: CAPTURE_ATTESTATION_ID.to_owned(),
        kind: CAPTURE_ATTESTATION_KIND.to_owned(),
        relative_path: ArtifactPath::new(CAPTURE_ATTESTATION_PATH)
            .context("construct capture attestation artifact path")?,
        media_type: "application/json".to_owned(),
        producer: CAPTURE_ATTESTATION_PRODUCER.to_owned(),
        input_artifact_ids,
    })
}

fn is_truncated_json_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<serde_json::Error>()
            .is_some_and(serde_json::Error::is_eof)
    })
}

#[cfg(test)]
fn ensure_attested_from_staged_with_snapshot_hook<F>(
    session: &Session,
    lock: &SessionLock,
    staged_attestation: &ArtifactPath,
    expected_policy_sha256: &Sha256Digest,
    performance_run_deployment_sha256: &Sha256Digest,
    signer_executable_sha256: &Sha256Digest,
    after_snapshot_verified: F,
) -> Result<EnsureAttestedResult>
where
    F: FnOnce() -> Result<()>,
{
    ensure_attested_from_staged_inner(
        session,
        lock,
        staged_attestation,
        expected_policy_sha256,
        performance_run_deployment_sha256,
        signer_executable_sha256,
        after_snapshot_verified,
    )
}

fn ensure_capture_trust_policy_artifact(
    session: &Session,
    lock: &SessionLock,
    artifacts: &[Artifact],
    policy_path: &Path,
    expected_policy_sha256: &Sha256Digest,
    policy_id: &str,
    key_id: &str,
) -> Result<(Artifact, CaptureTrustPolicy, bool)> {
    if artifacts
        .iter()
        .any(|artifact| artifact.id == CAPTURE_TRUST_POLICY_ID)
    {
        let (artifact, policy) = validate_registered_capture_policy(
            session,
            artifacts,
            policy_id,
            key_id,
            expected_policy_sha256,
        )?;
        return Ok((artifact, policy, true));
    }
    let bytes = read_policy_source_bytes(policy_path)?;
    ensure!(
        &sha256_bytes(&bytes)? == expected_policy_sha256,
        "capture trust policy bytes do not match the expected deployment SHA-256"
    );
    let policy: CaptureTrustPolicy = decode_control_json(&bytes, "capture trust policy")?;
    policy.validate().context("invalid capture trust policy")?;
    ensure!(
        policy.policy_id == policy_id,
        "capture trust policy identity does not match the selected deployment policy"
    );
    ensure!(
        policy.key(key_id).is_some(),
        "capture trust policy does not contain the requested signing key"
    );
    let ensured = ensure_exact_ingested_artifact(
        session,
        lock,
        artifacts,
        &ArtifactPath::new(CAPTURE_TRUST_POLICY_STAGED_PATH)
            .context("construct capture trust policy staging path")?,
        ArtifactSpec {
            id: CAPTURE_TRUST_POLICY_ID.to_owned(),
            kind: CAPTURE_TRUST_POLICY_KIND.to_owned(),
            relative_path: ArtifactPath::new(CAPTURE_TRUST_POLICY_PATH)
                .context("construct capture trust policy artifact path")?,
            media_type: "application/json".to_owned(),
            producer: CAPTURE_TRUST_POLICY_PRODUCER.to_owned(),
            input_artifact_ids: Vec::new(),
        },
        &bytes,
        "capture trust policy",
    )?;
    Ok((ensured.artifact, policy, ensured.resumed))
}

fn validate_registered_capture_policy(
    session: &Session,
    artifacts: &[Artifact],
    policy_id: &str,
    key_id: &str,
    expected_policy_sha256: &Sha256Digest,
) -> Result<(Artifact, CaptureTrustPolicy)> {
    let artifact = required_artifact(artifacts, CAPTURE_TRUST_POLICY_ID)?;
    validate_catalog_artifact(
        artifact,
        CAPTURE_TRUST_POLICY_ID,
        CAPTURE_TRUST_POLICY_KIND,
        CAPTURE_TRUST_POLICY_PATH,
        CAPTURE_TRUST_POLICY_PRODUCER,
        &[],
    )?;
    ensure!(
        &artifact.sha256 == expected_policy_sha256,
        "immutable capture trust policy digest does not match the expected deployment policy"
    );
    let policy: CaptureTrustPolicy = read_control_json(session, artifact, "capture trust policy")?;
    policy.validate().context("invalid capture trust policy")?;
    ensure!(
        policy.policy_id == policy_id,
        "capture trust policy identity does not match the selected deployment policy"
    );
    ensure!(
        policy.key(key_id).is_some(),
        "capture trust policy does not contain the requested signing key"
    );
    Ok((artifact.clone(), policy))
}

fn ensure_registered_attestation_matches_signing_request(
    session: &Session,
    artifacts: &[Artifact],
    signing_request: &AttestationSigningRequest,
) -> Result<()> {
    let controller_health = crate::controller::controller_health_binding(session, artifacts)
        .map_err(|error| anyhow::anyhow!(error.message))?;
    let artifact = required_artifact(artifacts, CAPTURE_ATTESTATION_ID)?;
    validate_catalog_artifact(
        artifact,
        CAPTURE_ATTESTATION_ID,
        CAPTURE_ATTESTATION_KIND,
        CAPTURE_ATTESTATION_PATH,
        CAPTURE_ATTESTATION_PRODUCER,
        &external_attestation_inputs(controller_health.as_ref()),
    )?;
    let attestation: CaptureAttestation =
        read_control_json(session, artifact, "capture attestation")?;
    validate_attestation_matches_signing_request(&attestation, signing_request)
}

fn validate_attestation_matches_signing_request(
    attestation: &CaptureAttestation,
    signing_request: &AttestationSigningRequest,
) -> Result<()> {
    attestation
        .validate()
        .context("invalid capture attestation")?;
    ensure!(
        attestation.payload == signing_request.payload,
        "capture attestation payload does not exactly match the immutable signing request payload"
    );
    Ok(())
}

fn ensure_exact_ingested_artifact(
    session: &Session,
    lock: &SessionLock,
    artifacts: &[Artifact],
    staged_relative: &ArtifactPath,
    spec: ArtifactSpec,
    expected_bytes: &[u8],
    document: &str,
) -> Result<ExactArtifactEnsure> {
    ensure!(
        u64::try_from(expected_bytes.len()).unwrap_or(u64::MAX) <= MAX_CAPTURE_CONTROL_BYTES,
        "{document} exceeds the {MAX_CAPTURE_CONTROL_BYTES}-byte limit"
    );
    if let Some(existing) = artifacts.iter().find(|artifact| artifact.id == spec.id) {
        validate_catalog_artifact(
            existing,
            &spec.id,
            &spec.kind,
            spec.relative_path.as_str(),
            &spec.producer,
            &spec.input_artifact_ids,
        )?;
        let actual = read_artifact_bytes(session, existing, document)?;
        ensure!(
            actual == expected_bytes,
            "existing immutable {document} content conflicts with the exact retry"
        );
        return Ok(ExactArtifactEnsure {
            artifact: existing.clone(),
            resumed: true,
        });
    }

    session
        .ensure_staged_exact(
            lock,
            staged_relative,
            expected_bytes,
            MAX_CAPTURE_CONTROL_BYTES,
        )
        .with_context(|| format!("ensure exact staged {document}"))?;
    let artifact = session
        .ingest_staged_bounded(lock, staged_relative, spec, MAX_CAPTURE_CONTROL_BYTES)
        .with_context(|| format!("ingest immutable {document}"))?;
    let actual = read_artifact_bytes(session, &artifact, document)?;
    ensure!(
        actual == expected_bytes,
        "committed immutable {document} differs from its requested bytes"
    );
    Ok(ExactArtifactEnsure {
        artifact,
        resumed: false,
    })
}

fn sha256_bytes(bytes: &[u8]) -> Result<Sha256Digest> {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Sha256Digest::new(encoded).context("construct SHA-256 digest")
}

fn optional_staged_bytes(session: &Session, relative: &ArtifactPath) -> Result<Option<Vec<u8>>> {
    let path = session
        .staging_path(relative)
        .context("resolve capture attestation staging path")?;
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| {
            format!(
                "inspect capture attestation staging path `{}`",
                path.display()
            )
        }),
        Ok(_) => session
            .read_staged_bounded(relative, MAX_CAPTURE_CONTROL_BYTES)
            .map(Some)
            .context("read staged capture attestation"),
    }
}

fn read_policy_source_bytes(policy_path: &Path) -> Result<Vec<u8>> {
    read_plain_bounded_bytes(
        policy_path,
        MAX_CAPTURE_CONTROL_BYTES,
        "capture trust policy",
    )
}

fn read_plain_bounded_bytes(path: &Path, limit: u64, document: &str) -> Result<Vec<u8>> {
    let mut source = open_plain_bounded_file(path, limit, document)?;
    let mut bytes = Vec::new();
    (&mut source)
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {document}"))?;
    ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= limit,
        "{document} exceeds the {limit}-byte limit"
    );
    Ok(bytes)
}

fn read_artifact_bytes(session: &Session, artifact: &Artifact, document: &str) -> Result<Vec<u8>> {
    ensure_control_document_size(artifact, document)?;
    let mut file = session
        .open_artifact(artifact)
        .with_context(|| format!("open immutable {document}"))?;
    let mut bytes = Vec::with_capacity(usize::try_from(artifact.size_bytes).unwrap_or(0));
    (&mut file)
        .take(MAX_CAPTURE_CONTROL_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("read immutable {document}"))?;
    ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_CAPTURE_CONTROL_BYTES,
        "{document} grew beyond the {MAX_CAPTURE_CONTROL_BYTES}-byte limit while reading"
    );
    Ok(bytes)
}

fn open_plain_bounded_file(path: &Path, limit: u64, document: &str) -> Result<File> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {document} `{}`", path.display()))?;
    ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "{document} must be a plain regular file"
    );
    ensure!(
        metadata.len() <= limit,
        "{document} exceeds the {limit}-byte limit"
    );

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .with_context(|| format!("open {document} `{}`", path.display()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("inspect opened {document} `{}`", path.display()))?;
    ensure!(opened.is_file(), "{document} must be a plain regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        let current = fs::symlink_metadata(path)
            .with_context(|| format!("reinspect {document} `{}`", path.display()))?;
        ensure!(
            current.file_type().is_file()
                && !current.file_type().is_symlink()
                && metadata.dev() == opened.dev()
                && metadata.ino() == opened.ino()
                && current.dev() == opened.dev()
                && current.ino() == opened.ino(),
            "{document} changed while it was opened"
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        ensure!(
            opened.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "{document} must not be a reparse point"
        );
    }
    ensure!(
        opened.len() <= limit,
        "{document} exceeds the {limit}-byte limit"
    );
    Ok(file)
}

fn read_control_json<T: serde::de::DeserializeOwned>(
    session: &Session,
    artifact: &Artifact,
    document: &str,
) -> Result<T> {
    ensure_control_document_size(artifact, document)?;
    let mut file = session
        .open_artifact(artifact)
        .with_context(|| format!("open immutable {document}"))?;
    let mut bytes = Vec::with_capacity(usize::try_from(artifact.size_bytes).unwrap_or(0));
    (&mut file)
        .take(MAX_CAPTURE_CONTROL_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("read immutable {document}"))?;
    ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_CAPTURE_CONTROL_BYTES,
        "{document} grew beyond the {MAX_CAPTURE_CONTROL_BYTES}-byte limit while reading"
    );
    decode_control_json(&bytes, document)
}

fn decode_control_json<T: serde::de::DeserializeOwned>(bytes: &[u8], document: &str) -> Result<T> {
    strict_json::from_slice(bytes).with_context(|| format!("parse immutable {document}"))
}

fn ensure_control_document_size(artifact: &Artifact, document: &str) -> Result<()> {
    ensure!(
        artifact.size_bytes <= MAX_CAPTURE_CONTROL_BYTES,
        "{document} exceeds the {MAX_CAPTURE_CONTROL_BYTES}-byte limit"
    );
    Ok(())
}

fn validate_observation_artifact(artifact: &Artifact) -> Result<()> {
    ensure!(
        artifact.id == "observations"
            && artifact.kind == "observations"
            && artifact.relative_path.as_str() == "normalized/observations.ndjson"
            && artifact.media_type == "application/x-ndjson",
        "canonical observation artifact identity, path, or media type is invalid"
    );
    Ok(())
}

fn validate_catalog_artifact(
    artifact: &Artifact,
    id: &str,
    kind: &str,
    path: &str,
    producer: &str,
    inputs: &[String],
) -> Result<()> {
    ensure!(
        artifact.id == id
            && artifact.kind == kind
            && artifact.relative_path.as_str() == path
            && artifact.media_type == "application/json"
            && artifact.producer == producer
            && artifact.input_artifact_ids == inputs,
        "artifact `{id}` catalog identity or provenance is invalid"
    );
    Ok(())
}

fn required_artifact<'a>(artifacts: &'a [Artifact], id: &str) -> Result<&'a Artifact> {
    artifacts
        .iter()
        .find(|artifact| artifact.id == id)
        .ok_or_else(|| anyhow::anyhow!("required artifact `{id}` is not registered"))
}

fn external_attestation_inputs(
    controller_health: Option<&crate::controller::ControllerHealthBinding>,
) -> Vec<String> {
    let mut inputs = vec!["observations".to_owned(), CAPTURE_CONFIG_ID.to_owned()];
    if let Some(controller_health) = controller_health {
        inputs.push(controller_health.artifact.id.clone());
    }
    inputs
}

fn external_receipt_inputs(
    controller_health: Option<&crate::controller::ControllerHealthBinding>,
) -> Vec<String> {
    let mut inputs = external_attestation_inputs(controller_health);
    inputs.extend([
        CAPTURE_ATTESTATION_ID.to_owned(),
        CAPTURE_TRUST_POLICY_ID.to_owned(),
    ]);
    inputs
}

fn verify_capture_attestation(
    policy: &CaptureTrustPolicy,
    attestation: &CaptureAttestation,
    context: CaptureAttestationVerificationContext<'_>,
) -> Result<VerifiedCaptureAttestation> {
    policy.validate().context("invalid capture trust policy")?;
    attestation
        .validate()
        .context("invalid capture attestation")?;
    let payload = &attestation.payload;
    let key = policy.key(&payload.key_id).ok_or_else(|| {
        anyhow::anyhow!(
            "capture attestation key `{}` is not trusted",
            payload.key_id
        )
    })?;
    verify_signature(key, attestation)?;
    validate_attestation_payload_context(payload, &context)?;
    let config_claim = payload
        .capture_config
        .as_ref()
        .expect("validated attestation payload has capture-config provenance");
    verify_key_claims(
        key,
        &payload.receipt,
        &context.capture_config.document,
        &config_claim.configuration_sha256,
    )?;

    Ok(VerifiedCaptureAttestation {
        receipt: payload.receipt.clone(),
        producer: key.producer.clone(),
        policy_id: policy.policy_id.clone(),
        key_id: key.key_id.clone(),
    })
}

fn validate_attestation_payload_context(
    payload: &t32perf_model::CaptureAttestationPayload,
    context: &CaptureAttestationVerificationContext<'_>,
) -> Result<()> {
    ensure!(
        payload.receipt.session_id == context.expected_session_id,
        "capture attestation Session identity does not match"
    );
    ensure!(
        payload.nonce == context.expected_nonce,
        "capture attestation nonce does not match the Session operation"
    );
    ensure!(
        &payload.receipt.request_sha256 == context.expected_request_sha256,
        "capture attestation request digest does not match the immutable Session request"
    );
    ensure!(
        payload.observation_artifact_id == context.observations.id,
        "capture attestation observation artifact ID does not match"
    );
    ensure!(
        payload.observation_sha256 == context.observations.sha256,
        "capture attestation observation digest does not match"
    );
    let config_claim = payload.capture_config.as_ref().ok_or_else(|| {
        anyhow::anyhow!("trusted external capture attestation omits capture-config provenance")
    })?;
    validate_capture_config_claim(context.capture_config, config_claim)?;
    validate_capture_config_receipt(context.capture_config, &payload.receipt)?;
    validate_controller_health_binding(payload, context.controller_health)?;
    Ok(())
}

fn validate_controller_health_binding(
    payload: &t32perf_model::CaptureAttestationPayload,
    controller_health: Option<&crate::controller::ControllerHealthBinding>,
) -> Result<()> {
    match (&payload.controller_health, controller_health) {
        (None, None) => Ok(()),
        (Some(_), None) => bail!(
            "capture attestation claims controller health without an accepted controller health artifact"
        ),
        (None, Some(_)) => {
            bail!("capture attestation omits the accepted controller health artifact")
        }
        (Some(claim), Some(binding)) => {
            ensure!(
                claim
                    == &ControllerHealthArtifactClaim {
                        artifact_id: binding.artifact.id.clone(),
                        sha256: binding.artifact.sha256.clone(),
                    },
                "capture attestation controller-health claim does not match the accepted artifact"
            );
            let expected = controller_health_observations(binding);
            let actual = payload
                .receipt
                .health_observations
                .iter()
                .filter(|observation| observation.source == CONTROLLER_HEALTH_OBSERVATION_SOURCE)
                .cloned()
                .collect::<Vec<_>>();
            ensure!(
                actual == expected,
                "signed controller health observations do not exactly match the accepted typed evidence"
            );
            Ok(())
        }
    }
}

fn controller_health_observations(
    binding: &crate::controller::ControllerHealthBinding,
) -> Vec<HealthObservation> {
    let mut codes = Vec::new();
    let binding_sha256 = match &binding.evidence {
        crate::controller::AcceptedControllerHealthEvidence::ProgramFlow(evidence) => {
            if evidence.trace_overflow {
                codes.push("trace_overflow");
            }
            if evidence.flow_error {
                codes.push("flow_error");
            }
            if evidence.trace_gap {
                codes.push("trace_gap");
            }
            if evidence.truncated {
                codes.push("truncated_input");
            }
            if evidence.timestamp_discontinuity {
                codes.push("timestamp_discontinuity");
            }
            if !evidence.elf_matches_firmware {
                codes.push("elf_mismatch");
            }
            if !evidence.program_flow_closed {
                codes.push("program_flow_unclosed");
            }
            &evidence.binding_sha256
        }
        crate::controller::AcceptedControllerHealthEvidence::Sampling(evidence) => {
            if evidence.sampling.buffer_full {
                codes.push("sampling_buffer_full");
            }
            if evidence.sampling.unexpected_stop {
                codes.push("sampling_unexpected_stop");
            }
            if evidence.elf_matches_firmware == Some(false) {
                codes.push("elf_mismatch");
            }
            &evidence.binding_sha256
        }
    };
    codes
        .into_iter()
        .map(|code| HealthObservation {
            code: code.to_owned(),
            source: CONTROLLER_HEALTH_OBSERVATION_SOURCE.to_owned(),
            artifact_id: Some(binding.artifact.id.clone()),
            record: None,
            start_ns: None,
            end_ns: None,
            evidence: BTreeMap::from([
                (
                    "controller_binding_sha256".to_owned(),
                    json!(binding_sha256),
                ),
                (
                    "controller_evidence_sha256".to_owned(),
                    json!(binding.artifact.sha256),
                ),
            ]),
        })
        .collect()
}

fn verify_signature(key: &CaptureTrustKey, attestation: &CaptureAttestation) -> Result<()> {
    let public_key =
        decode_hex::<32>(&key.public_key_ed25519).context("decode trusted Ed25519 public key")?;
    let signature = decode_hex::<64>(&attestation.signature_ed25519)
        .context("decode capture attestation signature")?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).context("parse trusted Ed25519 public key")?;
    let signature = Signature::from_bytes(&signature);
    let message = attestation
        .payload
        .signing_bytes()
        .context("serialize capture attestation signing payload")?;
    verifying_key
        .verify_strict(&message, &signature)
        .context("verify capture attestation Ed25519 signature")
}

fn verify_key_claims(
    key: &CaptureTrustKey,
    receipt: &CaptureReceipt,
    config: &CaptureConfigDocument,
    config_sha256: &Sha256Digest,
) -> Result<()> {
    ensure!(
        receipt.provider == key.provider,
        "capture provider exceeds trusted key scope"
    );
    ensure!(
        receipt.adapter == key.adapter,
        "capture adapter identity exceeds trusted key scope"
    );
    ensure!(
        key.allowed_modes.iter().any(|mode| mode == &receipt.mode),
        "capture mode is not allowed by the trusted key"
    );
    ensure!(
        receipt.target.as_ref() == Some(&key.target),
        "capture target identity does not match the trusted key"
    );
    ensure!(
        receipt.trace32 == key.trace32,
        "TRACE32 identity does not match the trusted key"
    );
    ensure!(
        receipt.clocks == key.clocks,
        "capture clock identity does not match the trusted key"
    );
    ensure!(
        !receipt.covered_cores.is_empty()
            && receipt
                .covered_cores
                .iter()
                .all(|core| key.allowed_cores.contains(core)),
        "capture claims cores outside the trusted key scope"
    );
    ensure!(
        receipt.firmware.elf_sha256.is_some()
            || receipt
                .firmware
                .build_id
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty()),
        "capture receipt has no immutable firmware identity"
    );
    verify_trace32_firmware_binding(key, receipt, config)?;
    verify_capability_ceiling(&key.capability_ceiling, &receipt.capabilities)?;
    verify_config_constraints(key, config, config_sha256)
}

fn verify_trace32_firmware_binding(
    key: &CaptureTrustKey,
    receipt: &CaptureReceipt,
    config: &CaptureConfigDocument,
) -> Result<()> {
    if key.provider != "trace32" {
        return Ok(());
    }

    let receipt_elf_sha256 = receipt
        .firmware
        .elf_sha256
        .as_ref()
        .context("TRACE32 capture receipt omits firmware.elf_sha256")?;
    ensure!(
        key.allowed_firmware_elf_sha256
            .iter()
            .any(|digest| digest == receipt_elf_sha256),
        "TRACE32 receipt firmware.elf_sha256 is not allowed by the trusted key"
    );
    let config_elf_sha256 = config
        .adapter_parameters
        .get("firmware.elf_sha256")
        .and_then(serde_json::Value::as_str)
        .context(
            "TRACE32 capture-config adapter_parameters.firmware.elf_sha256 must be a string",
        )?;
    let config_elf_sha256 = Sha256Digest::new(config_elf_sha256.to_owned()).context(
        "TRACE32 capture-config firmware.elf_sha256 must be lowercase hexadecimal SHA-256",
    )?;
    ensure!(
        &config_elf_sha256 == receipt_elf_sha256,
        "TRACE32 receipt firmware.elf_sha256 does not match the authoritative capture-config"
    );
    Ok(())
}

fn verify_config_constraints(
    key: &CaptureTrustKey,
    config: &CaptureConfigDocument,
    config_sha256: &Sha256Digest,
) -> Result<()> {
    ensure!(
        config.provider == key.provider && config.adapter == key.adapter,
        "capture config provider or adapter exceeds trusted key scope"
    );
    ensure!(
        key.allowed_modes.iter().any(|mode| mode == &config.mode),
        "capture config mode is not allowed by the trusted key"
    );
    ensure!(
        !config.covered_cores.is_empty()
            && config
                .covered_cores
                .iter()
                .all(|core| key.allowed_cores.contains(core)),
        "capture config claims cores outside the trusted key scope"
    );
    let Some(constraints) = &key.config_constraints else {
        return Ok(());
    };
    if !constraints.allowed_sink_kinds.is_empty() {
        ensure!(
            constraints
                .allowed_sink_kinds
                .iter()
                .any(|kind| kind == &config.sink.kind),
            "capture config sink kind exceeds trusted key scope"
        );
    }
    if !constraints.allowed_sink_ids.is_empty() {
        ensure!(
            constraints
                .allowed_sink_ids
                .iter()
                .any(|id| id == &config.sink.id),
            "capture config sink identity exceeds trusted key scope"
        );
    }
    if !constraints.allowed_initial_target_states.is_empty() {
        ensure!(
            constraints
                .allowed_initial_target_states
                .contains(&config.initial_target_state),
            "capture config initial target state exceeds trusted key scope"
        );
    }
    if !constraints.allowed_rtos_awareness_kinds.is_empty() {
        ensure!(
            constraints
                .allowed_rtos_awareness_kinds
                .iter()
                .any(|kind| kind == &config.rtos_awareness.kind),
            "capture config RTOS-awareness kind exceeds trusted key scope"
        );
    }
    if let Some(maximum) = constraints.max_sink_capacity_bytes {
        ensure!(
            config
                .sink
                .capacity_bytes
                .is_some_and(|capacity| capacity <= maximum),
            "capture config sink capacity exceeds trusted key scope"
        );
    }
    if let Some(required) = constraints.require_timestamp_enabled {
        ensure!(
            config.timestamp.enabled == required,
            "capture config timestamp setting exceeds trusted key scope"
        );
    }
    if !constraints.allowed_config_sha256.is_empty() {
        ensure!(
            constraints.allowed_config_sha256.contains(config_sha256),
            "capture config digest is not allowed by the trusted key"
        );
    }
    Ok(())
}

fn verify_capability_ceiling(
    ceiling: &CaptureCapabilities,
    claimed: &CaptureCapabilities,
) -> Result<()> {
    for (family, ceiling, claimed) in [
        (
            "function_events",
            &ceiling.function_events,
            &claimed.function_events,
        ),
        (
            "context_switches",
            &ceiling.context_switches,
            &claimed.context_switches,
        ),
        (
            "interrupt_events",
            &ceiling.interrupt_events,
            &claimed.interrupt_events,
        ),
        ("samples", &ceiling.samples, &claimed.samples),
        (
            "custom_events",
            &ceiling.custom_events,
            &claimed.custom_events,
        ),
        ("counters", &ceiling.counters, &claimed.counters),
    ] {
        if support_rank(claimed) < support_rank(ceiling) {
            bail!("capture capability `{family}` exceeds trusted key ceiling");
        }
    }
    Ok(())
}

fn capture_capabilities_for_completed_binding(
    profile: &TargetAdapterProfile,
    binding: &ControllerTargetAdapterBinding,
) -> Result<CaptureCapabilities> {
    let scenario = profile.scenario(binding.scenario).ok_or_else(|| {
        anyhow::anyhow!("completed target-adapter scenario is absent from the admission profile")
    })?;
    ensure!(
        profile.adapter_id == binding.adapter_id
            && profile.adapter_version == binding.adapter_version
            && profile
                .digest()
                .context("digest admitted target-adapter profile")?
                == binding.profile_sha256
            && profile.implementation_sha256 == binding.implementation_sha256
            && profile.qualification_sha256 == binding.qualification_sha256
            && profile.build_gate.trace32_release == binding.trace32_release
            && profile.build_gate.minimum_build <= binding.trace32_build
            && binding.trace32_build <= profile.build_gate.maximum_build
            && profile.build_gate.architecture_package == binding.architecture_package
            && profile.target_identifier == binding.target_identifier
            && profile.probe_identifier == binding.probe_identifier
            && scenario.capture.capture_kind == binding.capture_kind,
        "completed target-adapter binding does not exactly select the reconstructed admission profile"
    );
    Ok(profile.capabilities.clone())
}

fn support_rank(entry: &MetricSupportEntry) -> u8 {
    match entry.support {
        MetricSupportLevel::Exact => 0,
        MetricSupportLevel::Inferred => 1,
        MetricSupportLevel::Statistical => 2,
        MetricSupportLevel::Unavailable => 3,
    }
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    ensure!(value.len() == N * 2, "hex value has the wrong length");
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_nibble(pair[0])?;
        let low = decode_nibble(pair[1])?;
        output[index] = high << 4 | low;
    }
    Ok(output)
}

fn decode_nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => bail!("hex value is not lowercase hexadecimal"),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        io::Write as _,
        path::PathBuf,
    };

    use ed25519_dalek::{Signer as _, SigningKey};
    use sha2::{Digest as _, Sha256};
    use t32perf_model::{
        AdapterInfo, ArtifactPath, AttestationSigningRequestSchemaVersion,
        CaptureAttestationPayload, CaptureAttestationSchemaVersion, CaptureConfigArtifactClaim,
        CaptureConfigConstraints, CaptureConfigDocument, CaptureConfigSchemaVersion,
        CaptureDurationConfig, CaptureReceiptSchemaVersion, CaptureRtosAwarenessConfig,
        CaptureSinkConfig, CaptureTimestampConfig, CaptureTriggerConfig,
        CaptureTrustPolicySchemaVersion, ClockInfo, FirmwareInfo, InitialTargetState, Properties,
        SessionError, TargetInfo, Trace32Info,
    };
    use t32perf_session::{
        ArtifactRoot, ArtifactSpec, INGEST_INTENT_SCHEMA, IngestIntentClassification, SessionId,
        SessionLimits,
    };
    use t32perf_trace32::{
        ControllerCaptureCompletionEvidence, ControllerHealthEvidenceV2,
        ControllerHealthEvidenceV2SchemaVersion, ControllerHealthOperation, ControllerHealthSignal,
        ControllerProgramFlowHealthEvidence, ControllerProgramFlowHealthEvidenceSchemaVersion,
        ControllerSamplingBufferMode, ControllerSamplingHealthEvidence, ControllerSamplingMethod,
        ControllerSamplingObject, ControllerSamplingPreStopState, ControllerSamplingState,
        ControllerScriptResponse, ControllerStopEvidenceV2, ControllerStopEvidenceV2SchemaVersion,
        ControllerStopOperation, ControllerTargetState, PROGRAM_FLOW_HEALTH_SIGNALS, PerfOperation,
        PerfStatus, TC234L_SNOOPER_BUILD190766_S3_SHA256, TC234L_SNOOPER_BUILD190766_S3_SIZE_BYTES,
        TargetAdapterScenario, tc234l_build190766_candidate_profile,
        tc234l_snooper_capture_config_for_scenario,
    };
    use tempfile::TempDir;

    use crate::{
        capture_config::{CAPTURE_CONFIG_KIND, CAPTURE_CONFIG_PATH, capture_config_claim},
        controller::{
            AcceptedControllerHealthEvidence, AcceptedTrace32RuntimeBinding,
            ControllerHealthBinding, completed_binding_for_test,
        },
    };

    use super::*;

    struct EnsureFixture {
        _temporary: TempDir,
        session: Session,
        lock: SessionLock,
        policy_path: PathBuf,
        staged_attestation: ArtifactPath,
        signing_request: AttestationSigningRequest,
        attestation: CaptureAttestation,
        signing_key_bytes: [u8; 32],
        policy_sha256: Sha256Digest,
        deployment_sha256: Sha256Digest,
        signer_sha256: Sha256Digest,
    }

    impl EnsureFixture {
        fn new() -> Self {
            let temporary = TempDir::new().unwrap();
            let root =
                ArtifactRoot::open(temporary.path().join("artifacts"), SessionLimits::default())
                    .unwrap();
            let session = root
                .create_session_with_id(
                    SessionId::new("attestation-ensure").unwrap(),
                    &json!({"workload":"attestation-ensure"}),
                )
                .unwrap();
            let lock = session.try_lock().unwrap();

            let mut observation_writer = session
                .create_artifact(
                    &lock,
                    ArtifactSpec {
                        id: "observations".to_owned(),
                        kind: "observations".to_owned(),
                        relative_path: ArtifactPath::new("normalized/observations.ndjson").unwrap(),
                        media_type: "application/x-ndjson".to_owned(),
                        producer: "test-normalizer/v1".to_owned(),
                        input_artifact_ids: Vec::new(),
                    },
                )
                .unwrap();
            observation_writer.write_all(b"{}\n").unwrap();
            let observations = session.commit_artifact(&lock, observation_writer).unwrap();

            let adapter = AdapterInfo {
                id: "test-adapter".to_owned(),
                version: "1".to_owned(),
            };
            let config = CaptureConfigDocument {
                schema: CaptureConfigSchemaVersion,
                session_id: session.id().to_string(),
                provider: "external".to_owned(),
                adapter: adapter.clone(),
                mode: "sampling".to_owned(),
                covered_cores: vec![0],
                sink: CaptureSinkConfig {
                    kind: "host_file".to_owned(),
                    id: "capture-0".to_owned(),
                    capacity_bytes: Some(4096),
                    stream_destination_identity: None,
                },
                timestamp: CaptureTimestampConfig {
                    enabled: false,
                    clock_id: None,
                },
                filters: Vec::new(),
                trigger: CaptureTriggerConfig {
                    kind: "manual".to_owned(),
                    pre_trigger_ns: None,
                    post_trigger_ns: None,
                    condition_identity: None,
                },
                duration: CaptureDurationConfig {
                    duration_ns: Some(1_000_000),
                    observation_limit: None,
                },
                workload_identity: "attestation-workload/v1".to_owned(),
                initial_target_state: InitialTargetState::Halted,
                rtos_awareness: CaptureRtosAwarenessConfig {
                    kind: "none".to_owned(),
                    metadata_artifact_ids: Vec::new(),
                },
                instrumentation: None,
                adapter_parameters: Properties::new(),
            };
            let config_artifact = session
                .write_json_artifact(
                    &lock,
                    ArtifactSpec {
                        id: CAPTURE_CONFIG_ID.to_owned(),
                        kind: CAPTURE_CONFIG_KIND.to_owned(),
                        relative_path: ArtifactPath::new(CAPTURE_CONFIG_PATH).unwrap(),
                        media_type: "application/json".to_owned(),
                        producer: "test-capture-config/v1".to_owned(),
                        input_artifact_ids: Vec::new(),
                    },
                    &config,
                )
                .unwrap();
            session
                .transition(&lock, SessionStatus::Capturing, None)
                .unwrap();
            let state = session
                .transition(&lock, SessionStatus::Captured, None)
                .unwrap();

            let unavailable = MetricSupportEntry::unavailable("not captured");
            let capabilities = CaptureCapabilities {
                function_events: unavailable.clone(),
                context_switches: unavailable.clone(),
                interrupt_events: unavailable.clone(),
                samples: unavailable.clone(),
                custom_events: unavailable.clone(),
                counters: unavailable,
            };
            let target = TargetInfo {
                architecture: Some("test".to_owned()),
                device: Some("test-device".to_owned()),
                board: None,
                core_count: Some(1),
                properties: Properties::new(),
            };
            let clocks = vec![ClockInfo {
                id: "test-clock".to_owned(),
                frequency_hz: Some(1_000_000),
                source: Some("test".to_owned()),
                properties: Properties::new(),
            }];
            let request_sha256 = session.request_sha256().unwrap();
            let config_claim = capture_config_claim(&config_artifact, &config).unwrap();
            let receipt = CaptureReceipt {
                schema: CaptureReceiptSchemaVersion,
                session_id: session.id().to_string(),
                provider: "external".to_owned(),
                mode: "sampling".to_owned(),
                adapter: adapter.clone(),
                target: Some(target.clone()),
                trace32: None,
                firmware: FirmwareInfo {
                    elf_path: None,
                    elf_sha256: None,
                    build_id: Some("test-build".to_owned()),
                },
                clocks: clocks.clone(),
                covered_cores: vec![0],
                capabilities: capabilities.clone(),
                health_observations: Vec::new(),
                request_sha256,
                capture_config: Some(config_claim.clone()),
                controller_health: None,
                properties: BTreeMap::new(),
            };
            let payload = CaptureAttestationPayload {
                schema: CaptureAttestationSchemaVersion,
                key_id: "test-key".to_owned(),
                nonce: state.operation_id,
                receipt,
                observation_artifact_id: observations.id,
                observation_sha256: observations.sha256,
                capture_config: Some(config_claim),
                controller_health: None,
            };
            let signing_request = AttestationSigningRequest {
                schema: AttestationSigningRequestSchemaVersion,
                policy_id: "test-policy".to_owned(),
                key_id: "test-key".to_owned(),
                payload: payload.clone(),
            };
            let signing_key_bytes = [23_u8; 32];
            let signing_key = SigningKey::from_bytes(&signing_key_bytes);
            let attestation = CaptureAttestation {
                signature_ed25519: encode_hex(
                    &signing_key
                        .sign(&payload.signing_bytes().unwrap())
                        .to_bytes(),
                ),
                payload,
            };
            let policy = CaptureTrustPolicy {
                schema: CaptureTrustPolicySchemaVersion,
                policy_id: "test-policy".to_owned(),
                keys: vec![CaptureTrustKey {
                    key_id: "test-key".to_owned(),
                    public_key_ed25519: encode_hex(&signing_key.verifying_key().to_bytes()),
                    producer: "test-signer/v1".to_owned(),
                    provider: "external".to_owned(),
                    adapter,
                    allowed_modes: vec!["sampling".to_owned()],
                    target,
                    trace32: None,
                    clocks,
                    allowed_cores: vec![0],
                    allowed_firmware_elf_sha256: Vec::new(),
                    capability_ceiling: capabilities,
                    config_constraints: None,
                }],
            };
            let policy_path = temporary.path().join("policy.json");
            let mut policy_bytes = serde_json::to_vec_pretty(&policy).unwrap();
            policy_bytes.push(b'\n');
            let policy_sha256 = sha256_bytes(&policy_bytes).unwrap();
            fs::write(&policy_path, policy_bytes).unwrap();

            Self {
                _temporary: temporary,
                session,
                lock,
                policy_path,
                staged_attestation: ArtifactPath::new("capture-attestation.json").unwrap(),
                signing_request,
                attestation,
                signing_key_bytes,
                policy_sha256,
                deployment_sha256: Sha256Digest::new("d".repeat(64)).unwrap(),
                signer_sha256: Sha256Digest::new("e".repeat(64)).unwrap(),
            }
        }

        fn prepare_dispatch(&self) -> EnsureSignerDispatchIntentResult {
            ensure_attestation_policy_snapshot(
                &self.session,
                &self.lock,
                &self.policy_path,
                &self.policy_sha256,
                &self.signing_request.policy_id,
                &self.signing_request.key_id,
            )
            .unwrap();
            let artifacts = self.artifacts();
            let policy = required_artifact(&artifacts, CAPTURE_TRUST_POLICY_ID).unwrap();
            let mut inputs = external_attestation_inputs(None);
            inputs.push(policy.id.clone());
            let request = ensure_exact_ingested_artifact(
                &self.session,
                &self.lock,
                &artifacts,
                &ArtifactPath::new(ATTESTATION_SIGNING_REQUEST_STAGED_PATH).unwrap(),
                ArtifactSpec {
                    id: ATTESTATION_SIGNING_REQUEST_ID.to_owned(),
                    kind: ATTESTATION_SIGNING_REQUEST_KIND.to_owned(),
                    relative_path: ArtifactPath::new(ATTESTATION_SIGNING_REQUEST_PATH).unwrap(),
                    media_type: "application/json".to_owned(),
                    producer: ATTESTATION_SIGNING_REQUEST_PRODUCER.to_owned(),
                    input_artifact_ids: inputs,
                },
                &self.signing_request.canonical_bytes().unwrap(),
                "test attestation signing request",
            )
            .unwrap()
            .artifact;
            record_signer_dispatch_intent(
                &self.session,
                &self.lock,
                &request,
                &self.signing_request,
                &self.policy_sha256,
                &self.deployment_sha256,
                &self.signer_sha256,
            )
            .unwrap()
        }

        fn stage(&self, attestation: &CaptureAttestation) {
            let bytes = Self::attestation_bytes(attestation);
            fs::write(
                self.session.staging_path(&self.staged_attestation).unwrap(),
                bytes,
            )
            .unwrap();
        }

        fn attestation_bytes(attestation: &CaptureAttestation) -> Vec<u8> {
            let mut bytes = serde_json::to_vec_pretty(attestation).unwrap();
            bytes.push(b'\n');
            bytes
        }

        fn stage_bytes(&self, bytes: &[u8]) {
            fs::write(
                self.session.staging_path(&self.staged_attestation).unwrap(),
                bytes,
            )
            .unwrap();
        }

        fn ensure_attestation_only(&self) {
            let state = self.session.read_state().unwrap();
            let artifacts = self.artifacts();
            let request_artifact =
                required_artifact(&artifacts, ATTESTATION_SIGNING_REQUEST_ID).unwrap();
            let (_, policy) = validate_registered_capture_policy(
                &self.session,
                &artifacts,
                &self.signing_request.policy_id,
                &self.signing_request.key_id,
                &self.policy_sha256,
            )
            .unwrap();
            let observations = required_artifact(&artifacts, "observations").unwrap();
            let capture_config = registered_capture_config(&self.session, &artifacts).unwrap();
            let controller_health =
                crate::controller::controller_health_binding(&self.session, &artifacts).unwrap();
            let request_sha256 = self.session.request_sha256().unwrap();
            ensure_capture_attestation_artifact(
                &self.session,
                &self.lock,
                CaptureAttestationEnsureContext {
                    artifacts: &artifacts,
                    signer_staged_attestation: &self.staged_attestation,
                    signing_request: Some((request_artifact, &self.signing_request)),
                    policy: &policy,
                    verification: CaptureAttestationVerificationContext {
                        expected_session_id: self.session.id().as_str(),
                        expected_nonce: &state.operation_id,
                        expected_request_sha256: &request_sha256,
                        observations,
                        capture_config: &capture_config,
                        controller_health: controller_health.as_ref(),
                    },
                },
                || Ok(()),
            )
            .unwrap();
        }

        fn publish_attestation_without_catalog(&self) {
            let bytes = Self::attestation_bytes(&self.attestation);
            let host_staged = ArtifactPath::new(CAPTURE_ATTESTATION_HOST_STAGED_PATH).unwrap();
            self.session
                .ensure_staged_exact(&self.lock, &host_staged, &bytes, MAX_CAPTURE_CONTROL_BYTES)
                .unwrap();
            let staged_path = self.session.staging_path(&host_staged).unwrap();
            let bytes = fs::read(&staged_path).unwrap();
            let artifact = Artifact {
                id: CAPTURE_ATTESTATION_ID.to_owned(),
                kind: CAPTURE_ATTESTATION_KIND.to_owned(),
                relative_path: ArtifactPath::new(CAPTURE_ATTESTATION_PATH).unwrap(),
                media_type: "application/json".to_owned(),
                size_bytes: u64::try_from(bytes.len()).unwrap(),
                sha256: sha256_bytes(&bytes).unwrap(),
                producer: CAPTURE_ATTESTATION_PRODUCER.to_owned(),
                input_artifact_ids: external_attestation_inputs(None),
            };
            let private_path = self
                .session
                .path()
                .join("capture/.ingest-private/capture-attestation.payload");
            fs::create_dir_all(private_path.parent().unwrap()).unwrap();
            fs::copy(&staged_path, &private_path).unwrap();
            let intent = json!({
                "schema": INGEST_INTENT_SCHEMA,
                "session_id": self.session.id().as_str(),
                "operation_id": self.session.read_state().unwrap().operation_id,
                "staged_relative_path": host_staged,
                "private_relative_path": "capture/.ingest-private/capture-attestation.payload",
                "artifact": artifact,
            });
            let mut intent_bytes = serde_json::to_vec_pretty(&intent).unwrap();
            intent_bytes.push(b'\n');
            fs::write(
                self.session
                    .path()
                    .join("ingest-intents/capture-attestation.json"),
                intent_bytes,
            )
            .unwrap();
            fs::rename(
                private_path,
                self.session.path().join(CAPTURE_ATTESTATION_PATH),
            )
            .unwrap();
            fs::remove_file(staged_path).unwrap();
            let inspections = self.session.inspect_ingest_intents().unwrap();
            assert_eq!(inspections.len(), 1);
            assert_eq!(
                inspections[0].classification,
                IngestIntentClassification::Resumable
            );
        }

        fn resign(&self, payload: CaptureAttestationPayload) -> CaptureAttestation {
            let signing_key = SigningKey::from_bytes(&self.signing_key_bytes);
            let signature = signing_key.sign(&payload.signing_bytes().unwrap());
            CaptureAttestation {
                payload,
                signature_ed25519: encode_hex(&signature.to_bytes()),
            }
        }

        fn artifacts(&self) -> Vec<Artifact> {
            self.session.registered_artifacts(true).unwrap()
        }

        fn assert_no_capture_attestation_durable_state(&self, policy_may_exist: bool) {
            let artifacts = self.artifacts();
            assert!(
                artifacts
                    .iter()
                    .all(|artifact| artifact.id != CAPTURE_ATTESTATION_ID)
            );
            assert!(
                artifacts
                    .iter()
                    .all(|artifact| artifact.id != crate::receipt::CAPTURE_RECEIPT_ID)
            );
            if !policy_may_exist {
                assert!(
                    artifacts
                        .iter()
                        .all(|artifact| artifact.id != CAPTURE_TRUST_POLICY_ID)
                );
            }
            assert!(!self.session.path().join(CAPTURE_ATTESTATION_PATH).exists());
            assert!(
                self.session
                    .inspect_ingest_intents()
                    .unwrap()
                    .iter()
                    .all(|inspection| {
                        inspection.artifact_id.as_deref() != Some(CAPTURE_ATTESTATION_ID)
                            && inspection
                                .destination_relative_path
                                .as_ref()
                                .map(|path| path.as_str())
                                != Some(CAPTURE_ATTESTATION_PATH)
                    })
            );
            assert!(
                !self
                    .session
                    .staging_path(&ArtifactPath::new(CAPTURE_ATTESTATION_HOST_STAGED_PATH).unwrap())
                    .unwrap()
                    .exists()
            );
        }
    }

    #[test]
    fn ensure_attested_resumes_a_complete_receipt() {
        let fixture = EnsureFixture::new();
        fixture.prepare_dispatch();
        fixture.stage(&fixture.attestation);
        let first = ensure_attested_from_staged(
            &fixture.session,
            &fixture.lock,
            &fixture.staged_attestation,
            &fixture.policy_sha256,
            &fixture.deployment_sha256,
            &fixture.signer_sha256,
        )
        .unwrap();
        assert!(!first.resumed);
        let durable_ingests = fixture
            .session
            .committed_staging_sources()
            .unwrap()
            .into_iter()
            .map(|source| source.artifact_id)
            .collect::<BTreeSet<_>>();
        assert!(
            [
                CAPTURE_TRUST_POLICY_ID,
                ATTESTATION_SIGNING_REQUEST_ID,
                ATTESTATION_SIGNER_DISPATCH_INTENT_ID,
                crate::receipt::CAPTURE_RECEIPT_ID,
            ]
            .into_iter()
            .all(|id| durable_ingests.contains(id))
        );
        fs::remove_file(
            fixture
                .session
                .staging_path(&fixture.staged_attestation)
                .unwrap(),
        )
        .unwrap();

        let second = ensure_attested_from_staged(
            &fixture.session,
            &fixture.lock,
            &fixture.staged_attestation,
            &fixture.policy_sha256,
            &fixture.deployment_sha256,
            &fixture.signer_sha256,
        )
        .unwrap();
        assert!(second.resumed);
        assert_eq!(second.verified.receipt, first.verified.receipt);
    }

    #[test]
    fn ensure_attested_recovers_attestation_and_policy_without_receipt() {
        let attestation_only = EnsureFixture::new();
        attestation_only.prepare_dispatch();
        attestation_only.stage(&attestation_only.attestation);
        let artifacts = attestation_only.artifacts();
        assert!(required_artifact(&artifacts, ATTESTATION_SIGNING_REQUEST_ID).is_ok());
        attestation_only.ensure_attestation_only();
        fs::remove_file(
            attestation_only
                .session
                .staging_path(&attestation_only.staged_attestation)
                .unwrap(),
        )
        .unwrap();
        let result = ensure_attested_from_staged(
            &attestation_only.session,
            &attestation_only.lock,
            &attestation_only.staged_attestation,
            &attestation_only.policy_sha256,
            &attestation_only.deployment_sha256,
            &attestation_only.signer_sha256,
        )
        .unwrap();
        assert!(result.resumed);

        let tampered_stage = EnsureFixture::new();
        tampered_stage.prepare_dispatch();
        tampered_stage.stage(&tampered_stage.attestation);
        let artifacts = tampered_stage.artifacts();
        assert!(required_artifact(&artifacts, ATTESTATION_SIGNING_REQUEST_ID).is_ok());
        tampered_stage.ensure_attestation_only();
        fs::write(
            tampered_stage
                .session
                .staging_path(&tampered_stage.staged_attestation)
                .unwrap(),
            b"tampered diagnostic staging",
        )
        .unwrap();
        let result = ensure_attested_from_staged(
            &tampered_stage.session,
            &tampered_stage.lock,
            &tampered_stage.staged_attestation,
            &tampered_stage.policy_sha256,
            &tampered_stage.deployment_sha256,
            &tampered_stage.signer_sha256,
        )
        .unwrap();
        assert!(result.resumed);

        let resumable_ingest = EnsureFixture::new();
        resumable_ingest.prepare_dispatch();
        resumable_ingest.publish_attestation_without_catalog();
        let result = ensure_attested_from_staged(
            &resumable_ingest.session,
            &resumable_ingest.lock,
            &resumable_ingest.staged_attestation,
            &resumable_ingest.policy_sha256,
            &resumable_ingest.deployment_sha256,
            &resumable_ingest.signer_sha256,
        )
        .unwrap();
        assert!(result.resumed);
        assert!(
            resumable_ingest
                .session
                .inspect_ingest_intents()
                .unwrap()
                .is_empty()
        );

        let policy_only = EnsureFixture::new();
        policy_only.prepare_dispatch();
        policy_only.stage(&policy_only.attestation);
        let result = ensure_attested_from_staged(
            &policy_only.session,
            &policy_only.lock,
            &policy_only.staged_attestation,
            &policy_only.policy_sha256,
            &policy_only.deployment_sha256,
            &policy_only.signer_sha256,
        )
        .unwrap();
        assert!(!result.resumed);
    }

    #[test]
    fn ensure_attested_rejects_payload_mismatch_before_receipt() {
        let fixture = EnsureFixture::new();
        fixture.prepare_dispatch();
        let mut payload = fixture.attestation.payload.clone();
        payload
            .receipt
            .properties
            .insert("unexpected".to_owned(), json!(true));
        fixture.stage(&fixture.resign(payload));
        let error = ensure_attested_from_staged(
            &fixture.session,
            &fixture.lock,
            &fixture.staged_attestation,
            &fixture.policy_sha256,
            &fixture.deployment_sha256,
            &fixture.signer_sha256,
        )
        .unwrap_err();
        assert!(error.to_string().contains("does not exactly match"));
        fixture.assert_no_capture_attestation_durable_state(true);
    }

    #[test]
    fn ensure_attested_rejects_invalid_signer_snapshots_without_durable_writes() {
        for case in ["empty", "truncated", "wrong_payload", "bad_signature"] {
            let fixture = EnsureFixture::new();
            fixture.prepare_dispatch();
            let bytes = match case {
                "empty" => Vec::new(),
                "truncated" => br#"{"payload":"#.to_vec(),
                "wrong_payload" => {
                    let mut payload = fixture.attestation.payload.clone();
                    payload.receipt.session_id = "wrong-session".to_owned();
                    EnsureFixture::attestation_bytes(&fixture.resign(payload))
                }
                "bad_signature" => {
                    let mut attestation = fixture.attestation.clone();
                    let replacement = if attestation.signature_ed25519.starts_with('0') {
                        "1"
                    } else {
                        "0"
                    };
                    attestation
                        .signature_ed25519
                        .replace_range(0..1, replacement);
                    EnsureFixture::attestation_bytes(&attestation)
                }
                _ => unreachable!(),
            };
            fixture.stage_bytes(&bytes);
            let error = ensure_attested_from_staged(
                &fixture.session,
                &fixture.lock,
                &fixture.staged_attestation,
                &fixture.policy_sha256,
                &fixture.deployment_sha256,
                &fixture.signer_sha256,
            )
            .unwrap_err();
            assert_eq!(
                is_signer_dispatch_ambiguous(&error),
                matches!(case, "empty" | "truncated"),
                "unexpected signer error classification for case {case}: {error:#}"
            );
            fixture.assert_no_capture_attestation_durable_state(true);
            assert_eq!(
                fs::read(
                    fixture
                        .session
                        .staging_path(&fixture.staged_attestation)
                        .unwrap()
                )
                .unwrap(),
                bytes,
                "invalid signer output must remain untouched for case {case}"
            );
        }
    }

    #[test]
    fn validated_signer_snapshot_is_immutable_across_later_signer_mutation() {
        let fixture = EnsureFixture::new();
        fixture.prepare_dispatch();
        let valid_bytes = EnsureFixture::attestation_bytes(&fixture.attestation);
        fixture.stage_bytes(&valid_bytes);
        let signer_path = fixture
            .session
            .staging_path(&fixture.staged_attestation)
            .unwrap();
        let result = ensure_attested_from_staged_with_snapshot_hook(
            &fixture.session,
            &fixture.lock,
            &fixture.staged_attestation,
            &fixture.policy_sha256,
            &fixture.deployment_sha256,
            &fixture.signer_sha256,
            || {
                fs::write(&signer_path, b"mutated after Host snapshot")?;
                Ok(())
            },
        )
        .unwrap();
        assert!(!result.resumed);
        let artifact = required_artifact(&fixture.artifacts(), CAPTURE_ATTESTATION_ID)
            .unwrap()
            .clone();
        assert_eq!(
            read_artifact_bytes(&fixture.session, &artifact, "capture attestation").unwrap(),
            valid_bytes
        );
        assert_eq!(
            fixture
                .session
                .read_staged_bounded(
                    &ArtifactPath::new(CAPTURE_ATTESTATION_HOST_STAGED_PATH).unwrap(),
                    MAX_CAPTURE_CONTROL_BYTES,
                )
                .unwrap(),
            valid_bytes
        );
        assert_eq!(
            fs::read(signer_path).unwrap(),
            b"mutated after Host snapshot"
        );
    }

    #[test]
    fn generic_attest_rejects_invalid_inputs_without_durable_writes() {
        for case in [
            "empty",
            "truncated",
            "wrong_payload",
            "bad_signature",
            "bad_policy",
        ] {
            let fixture = EnsureFixture::new();
            let bytes = match case {
                "empty" => Vec::new(),
                "truncated" => br#"{"payload":"#.to_vec(),
                "wrong_payload" => {
                    let mut payload = fixture.attestation.payload.clone();
                    payload.receipt.session_id = "wrong-session".to_owned();
                    EnsureFixture::attestation_bytes(&fixture.resign(payload))
                }
                "bad_signature" => {
                    let mut attestation = fixture.attestation.clone();
                    let replacement = if attestation.signature_ed25519.starts_with('0') {
                        "1"
                    } else {
                        "0"
                    };
                    attestation
                        .signature_ed25519
                        .replace_range(0..1, replacement);
                    EnsureFixture::attestation_bytes(&attestation)
                }
                "bad_policy" => EnsureFixture::attestation_bytes(&fixture.attestation),
                _ => unreachable!(),
            };
            fixture.stage_bytes(&bytes);
            if case == "bad_policy" {
                fs::write(&fixture.policy_path, br#"{"schema":"#).unwrap();
            }
            attest_captured_session(
                &fixture.session,
                &fixture.lock,
                &fixture.staged_attestation,
                &fixture.policy_path,
            )
            .unwrap_err();
            fixture.assert_no_capture_attestation_durable_state(false);
            assert_eq!(
                fs::read(
                    fixture
                        .session
                        .staging_path(&fixture.staged_attestation)
                        .unwrap()
                )
                .unwrap(),
                bytes,
                "invalid signer output must remain untouched for case {case}"
            );
        }
    }

    #[test]
    fn generic_attest_valid_retry_uses_registered_exact_artifacts() {
        let fixture = EnsureFixture::new();
        fixture.stage(&fixture.attestation);
        let first = attest_captured_session(
            &fixture.session,
            &fixture.lock,
            &fixture.staged_attestation,
            &fixture.policy_path,
        )
        .unwrap();
        let first_catalog = fixture.artifacts();
        fs::remove_file(
            fixture
                .session
                .staging_path(&fixture.staged_attestation)
                .unwrap(),
        )
        .unwrap();
        fs::write(
            &fixture.policy_path,
            b"mutated external policy after completion",
        )
        .unwrap();
        let second = attest_captured_session(
            &fixture.session,
            &fixture.lock,
            &fixture.staged_attestation,
            &fixture.policy_path,
        )
        .unwrap();
        assert_eq!(fixture.artifacts(), first_catalog);
        assert_eq!(second.attestation_artifact, first.attestation_artifact);
        assert_eq!(second.policy_artifact, first.policy_artifact);
        assert_eq!(second.receipt_artifact, first.receipt_artifact);
    }

    #[test]
    fn generic_attest_recovers_policy_first_and_host_snapshot_windows() {
        let policy_only = EnsureFixture::new();
        let artifacts = policy_only.artifacts();
        let (_, _, resumed) = ensure_capture_trust_policy_artifact(
            &policy_only.session,
            &policy_only.lock,
            &artifacts,
            &policy_only.policy_path,
            &policy_only.policy_sha256,
            &policy_only.signing_request.policy_id,
            &policy_only.signing_request.key_id,
        )
        .unwrap();
        assert!(!resumed);
        policy_only.stage(&policy_only.attestation);
        attest_captured_session(
            &policy_only.session,
            &policy_only.lock,
            &policy_only.staged_attestation,
            &policy_only.policy_path,
        )
        .unwrap();

        let host_snapshot_only = EnsureFixture::new();
        let artifacts = host_snapshot_only.artifacts();
        ensure_capture_trust_policy_artifact(
            &host_snapshot_only.session,
            &host_snapshot_only.lock,
            &artifacts,
            &host_snapshot_only.policy_path,
            &host_snapshot_only.policy_sha256,
            &host_snapshot_only.signing_request.policy_id,
            &host_snapshot_only.signing_request.key_id,
        )
        .unwrap();
        host_snapshot_only
            .session
            .ensure_staged_exact(
                &host_snapshot_only.lock,
                &ArtifactPath::new(CAPTURE_ATTESTATION_HOST_STAGED_PATH).unwrap(),
                &EnsureFixture::attestation_bytes(&host_snapshot_only.attestation),
                MAX_CAPTURE_CONTROL_BYTES,
            )
            .unwrap();
        attest_captured_session(
            &host_snapshot_only.session,
            &host_snapshot_only.lock,
            &host_snapshot_only.staged_attestation,
            &host_snapshot_only.policy_path,
        )
        .unwrap();

        let resumable_destination = EnsureFixture::new();
        let artifacts = resumable_destination.artifacts();
        ensure_capture_trust_policy_artifact(
            &resumable_destination.session,
            &resumable_destination.lock,
            &artifacts,
            &resumable_destination.policy_path,
            &resumable_destination.policy_sha256,
            &resumable_destination.signing_request.policy_id,
            &resumable_destination.signing_request.key_id,
        )
        .unwrap();
        resumable_destination.publish_attestation_without_catalog();
        attest_captured_session(
            &resumable_destination.session,
            &resumable_destination.lock,
            &resumable_destination.staged_attestation,
            &resumable_destination.policy_path,
        )
        .unwrap();
        assert!(
            resumable_destination
                .session
                .inspect_ingest_intents()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn signer_intent_without_output_is_explicitly_ambiguous() {
        let fixture = EnsureFixture::new();
        fixture.prepare_dispatch();
        let before = fixture.artifacts();
        let error = ensure_attested_from_staged(
            &fixture.session,
            &fixture.lock,
            &fixture.staged_attestation,
            &fixture.policy_sha256,
            &fixture.deployment_sha256,
            &fixture.signer_sha256,
        )
        .unwrap_err();
        assert!(
            is_signer_dispatch_ambiguous(&error),
            "missing signer output must remain a typed ambiguous result"
        );
        assert_eq!(fixture.artifacts(), before);
    }

    #[test]
    fn failed_session_rejects_attestation_without_writes() {
        let fixture = EnsureFixture::new();
        fixture.prepare_dispatch();
        fixture.stage(&fixture.attestation);
        fixture
            .session
            .transition(
                &fixture.lock,
                SessionStatus::Failed,
                Some(SessionError {
                    code: "TEST_FAILURE".to_owned(),
                    message: "terminal".to_owned(),
                    details: Properties::new(),
                }),
            )
            .unwrap();
        let before = fixture.artifacts();
        let error = ensure_attested_from_staged(
            &fixture.session,
            &fixture.lock,
            &fixture.staged_attestation,
            &fixture.policy_sha256,
            &fixture.deployment_sha256,
            &fixture.signer_sha256,
        )
        .unwrap_err();
        assert!(error.to_string().contains("terminal"));
        assert_eq!(fixture.artifacts(), before);
    }

    #[test]
    fn exact_policy_and_signer_deployment_drift_are_conflicts() {
        let fixture = EnsureFixture::new();
        let first = fixture.prepare_dispatch();
        assert!(!first.resumed);
        let request = required_artifact(&fixture.artifacts(), ATTESTATION_SIGNING_REQUEST_ID)
            .unwrap()
            .clone();
        let same = record_signer_dispatch_intent(
            &fixture.session,
            &fixture.lock,
            &request,
            &fixture.signing_request,
            &fixture.policy_sha256,
            &fixture.deployment_sha256,
            &fixture.signer_sha256,
        )
        .unwrap();
        assert!(same.resumed);
        let drift = Sha256Digest::new("f".repeat(64)).unwrap();
        assert!(
            record_signer_dispatch_intent(
                &fixture.session,
                &fixture.lock,
                &request,
                &fixture.signing_request,
                &fixture.policy_sha256,
                &drift,
                &fixture.signer_sha256,
            )
            .is_err()
        );
        fixture.stage(&fixture.attestation);
        let error = ensure_attested_from_staged(
            &fixture.session,
            &fixture.lock,
            &fixture.staged_attestation,
            &fixture.policy_sha256,
            &drift,
            &fixture.signer_sha256,
        )
        .unwrap_err();
        assert!(error.to_string().contains("signer dispatch intent"));

        let signer_drift = Sha256Digest::new("a".repeat(64)).unwrap();
        assert!(
            record_signer_dispatch_intent(
                &fixture.session,
                &fixture.lock,
                &request,
                &fixture.signing_request,
                &fixture.policy_sha256,
                &fixture.deployment_sha256,
                &signer_drift,
            )
            .is_err()
        );
        let before = fixture.artifacts();
        let error = ensure_attested_from_staged(
            &fixture.session,
            &fixture.lock,
            &fixture.staged_attestation,
            &fixture.policy_sha256,
            &fixture.deployment_sha256,
            &signer_drift,
        )
        .unwrap_err();
        assert!(error.to_string().contains("signer dispatch intent"));
        assert_eq!(fixture.artifacts(), before);

        let policy_drift = Sha256Digest::new("b".repeat(64)).unwrap();
        let before = fixture.artifacts();
        let error = ensure_attested_from_staged(
            &fixture.session,
            &fixture.lock,
            &fixture.staged_attestation,
            &policy_drift,
            &fixture.deployment_sha256,
            &fixture.signer_sha256,
        )
        .unwrap_err();
        assert!(error.to_string().contains("deployment policy"));
        assert_eq!(fixture.artifacts(), before);

        let artifacts = fixture.artifacts();
        ensure_capture_trust_policy_artifact(
            &fixture.session,
            &fixture.lock,
            &artifacts,
            &fixture.policy_path,
            &fixture.policy_sha256,
            &fixture.signing_request.policy_id,
            &fixture.signing_request.key_id,
        )
        .unwrap();
        let mut changed = fs::read(&fixture.policy_path).unwrap();
        changed.push(b' ');
        fs::write(&fixture.policy_path, changed).unwrap();
        let artifacts = fixture.artifacts();
        let (resumed_artifact, _, resumed) = ensure_capture_trust_policy_artifact(
            &fixture.session,
            &fixture.lock,
            &artifacts,
            &fixture.policy_path,
            &fixture.policy_sha256,
            &fixture.signing_request.policy_id,
            &fixture.signing_request.key_id,
        )
        .unwrap();
        assert!(resumed);
        assert_eq!(
            resumed_artifact,
            required_artifact(&artifacts, CAPTURE_TRUST_POLICY_ID)
                .unwrap()
                .clone()
        );
    }

    #[test]
    fn signed_control_documents_reject_duplicate_nested_properties() {
        let error = decode_control_json::<serde_json::Value>(
            br#"{"payload":{"receipt":{"properties":{"probe":"first","probe":"last"}}}}"#,
            "capture attestation",
        )
        .expect_err("duplicate signed control property");

        assert!(
            error
                .root_cause()
                .to_string()
                .contains("duplicate JSON object member name `probe`")
        );
    }

    #[test]
    fn signed_receipt_health_facts_exactly_match_controller_evidence() {
        let artifact = Artifact {
            id: "controller-export-health".to_owned(),
            kind: "trace32_control_evidence".to_owned(),
            relative_path: ArtifactPath::new("capture/control/health.json").unwrap(),
            media_type: "application/json".to_owned(),
            size_bytes: 128,
            sha256: Sha256Digest::new("a".repeat(64)).unwrap(),
            producer: crate::controller::CONTROLLER_PRODUCER.to_owned(),
            input_artifact_ids: vec!["controller-request-health".to_owned()],
        };
        let binding = crate::controller::ControllerHealthBinding {
            artifact: artifact.clone(),
            evidence: crate::controller::AcceptedControllerHealthEvidence::ProgramFlow(
                ControllerProgramFlowHealthEvidence {
                    schema: ControllerProgramFlowHealthEvidenceSchemaVersion::V1,
                    operation: ControllerHealthOperation::V1,
                    binding_sha256: Sha256Digest::new("b".repeat(64)).unwrap(),
                    capture_stopped: true,
                    supported_signals: PROGRAM_FLOW_HEALTH_SIGNALS.to_vec(),
                    stop_evidence_sha256: Sha256Digest::new("c".repeat(64)).unwrap(),
                    trace_overflow: true,
                    flow_error: false,
                    trace_gap: true,
                    truncated: false,
                    timestamp_discontinuity: true,
                    elf_matches_firmware: false,
                    program_flow_closed: false,
                },
            ),
        };
        assert_eq!(
            external_attestation_inputs(Some(&binding)),
            vec![
                "observations".to_owned(),
                CAPTURE_CONFIG_ID.to_owned(),
                artifact.id.clone(),
            ]
        );
        assert_eq!(
            external_receipt_inputs(Some(&binding)),
            vec![
                "observations".to_owned(),
                CAPTURE_CONFIG_ID.to_owned(),
                artifact.id.clone(),
                CAPTURE_ATTESTATION_ID.to_owned(),
                CAPTURE_TRUST_POLICY_ID.to_owned(),
            ]
        );
        let claim = ControllerHealthArtifactClaim {
            artifact_id: artifact.id.clone(),
            sha256: artifact.sha256.clone(),
        };
        let unavailable = MetricSupportEntry {
            support: MetricSupportLevel::Unavailable,
            reasons: vec!["test".to_owned()],
        };
        let mut receipt = CaptureReceipt {
            schema: CaptureReceiptSchemaVersion,
            session_id: "session-health".to_owned(),
            provider: "trace32".to_owned(),
            mode: "etm".to_owned(),
            adapter: AdapterInfo {
                id: "adapter".to_owned(),
                version: "1".to_owned(),
            },
            target: None,
            trace32: None,
            firmware: FirmwareInfo {
                elf_path: None,
                elf_sha256: None,
                build_id: None,
            },
            clocks: Vec::new(),
            covered_cores: vec![0],
            capabilities: CaptureCapabilities {
                function_events: unavailable.clone(),
                context_switches: unavailable.clone(),
                interrupt_events: unavailable.clone(),
                samples: unavailable.clone(),
                custom_events: unavailable.clone(),
                counters: unavailable,
            },
            health_observations: controller_health_observations(&binding),
            request_sha256: Sha256Digest::new("c".repeat(64)).unwrap(),
            capture_config: None,
            controller_health: Some(claim.clone()),
            properties: BTreeMap::new(),
        };
        let mut payload = CaptureAttestationPayload {
            schema: CaptureAttestationSchemaVersion,
            key_id: "key".to_owned(),
            nonce: "nonce".to_owned(),
            receipt: receipt.clone(),
            observation_artifact_id: "observations".to_owned(),
            observation_sha256: Sha256Digest::new("d".repeat(64)).unwrap(),
            capture_config: None,
            controller_health: Some(claim),
        };
        validate_controller_health_binding(&payload, Some(&binding)).unwrap();

        payload.receipt.health_observations.pop();
        assert!(validate_controller_health_binding(&payload, Some(&binding)).is_err());

        receipt.health_observations.push(HealthObservation {
            code: "flow_error".to_owned(),
            source: CONTROLLER_HEALTH_OBSERVATION_SOURCE.to_owned(),
            artifact_id: Some(artifact.id),
            record: None,
            start_ns: None,
            end_ns: None,
            evidence: BTreeMap::new(),
        });
        payload.receipt = receipt;
        assert!(validate_controller_health_binding(&payload, Some(&binding)).is_err());
    }

    #[test]
    fn sampling_buffer_full_health_remains_signable_completed_evidence() {
        let artifact = Artifact {
            id: "controller-sampling-health".to_owned(),
            kind: "trace32_control_evidence".to_owned(),
            relative_path: ArtifactPath::new("capture/control/sampling-health.json").unwrap(),
            media_type: "application/json".to_owned(),
            size_bytes: 128,
            sha256: Sha256Digest::new("a".repeat(64)).unwrap(),
            producer: crate::controller::CONTROLLER_PRODUCER.to_owned(),
            input_artifact_ids: vec!["controller-request-health".to_owned()],
        };
        let binding = crate::controller::ControllerHealthBinding {
            artifact,
            evidence: crate::controller::AcceptedControllerHealthEvidence::Sampling(
                ControllerHealthEvidenceV2 {
                    schema: ControllerHealthEvidenceV2SchemaVersion::V1,
                    operation: ControllerHealthOperation::V1,
                    binding_sha256: Sha256Digest::new("b".repeat(64)).unwrap(),
                    capture_stopped: true,
                    supported_signals: vec![
                        ControllerHealthSignal::SamplingBufferFull,
                        ControllerHealthSignal::SamplingUnexpectedStop,
                        ControllerHealthSignal::ElfMismatch,
                    ],
                    stop_evidence_sha256: Sha256Digest::new("c".repeat(64)).unwrap(),
                    sampling: ControllerSamplingHealthEvidence {
                        method: ControllerSamplingMethod::RealTime,
                        object: ControllerSamplingObject::ProgramCounter,
                        buffer_mode: ControllerSamplingBufferMode::Stack,
                        state: ControllerSamplingState::Off,
                        pre_stop_state: ControllerSamplingPreStopState::Break,
                        requested_rate_ns: 1_000_000,
                        capacity_records: 32,
                        recorded_records: 32,
                        buffer_full: true,
                        unexpected_stop: false,
                    },
                    elf_matches_firmware: Some(true),
                },
            ),
        };
        let observations = controller_health_observations(&binding);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].code, "sampling_buffer_full");
        assert_eq!(
            observations[0].artifact_id.as_deref(),
            Some("controller-sampling-health")
        );
    }

    #[test]
    fn completed_sampling_binding_uses_profile_capabilities_not_policy_ceiling() {
        let profile = tc234l_build190766_candidate_profile();
        let capture_kind = profile
            .scenario(TargetAdapterScenario::Normal)
            .unwrap()
            .capture
            .capture_kind
            .clone();
        let binding = ControllerTargetAdapterBinding {
            adapter_id: profile.adapter_id.clone(),
            adapter_version: profile.adapter_version.clone(),
            trace32_release: profile.build_gate.trace32_release.clone(),
            trace32_build: profile.build_gate.minimum_build,
            architecture_package: profile.build_gate.architecture_package.clone(),
            target_identifier: profile.target_identifier.clone(),
            probe_identifier: profile.probe_identifier.clone(),
            profile_sha256: profile.digest().unwrap(),
            implementation_sha256: profile.implementation_sha256.clone(),
            scenario: TargetAdapterScenario::Normal,
            capture_kind,
            controller_protocol: profile.controller_protocol,
            custom_event_collector: profile.custom_event_collector.clone(),
            qualification_sha256: profile.qualification_sha256.clone(),
        };
        let capabilities = capture_capabilities_for_completed_binding(&profile, &binding).unwrap();
        assert_eq!(
            capabilities.samples.support,
            MetricSupportLevel::Statistical
        );
        assert_eq!(
            capabilities.function_events.support,
            MetricSupportLevel::Unavailable
        );
        let exact = MetricSupportEntry::new(MetricSupportLevel::Exact);
        let permissive_ceiling = CaptureCapabilities {
            function_events: exact.clone(),
            context_switches: exact.clone(),
            interrupt_events: exact.clone(),
            samples: exact.clone(),
            custom_events: exact.clone(),
            counters: exact,
        };
        verify_capability_ceiling(&permissive_ceiling, &capabilities).unwrap();
        assert_ne!(capabilities, permissive_ceiling);
    }

    #[test]
    fn verified_sampling_binding_builds_exact_host_signing_request() {
        let temporary = TempDir::new().unwrap();
        let root = ArtifactRoot::open(
            temporary.path().join("builder-artifacts"),
            SessionLimits::default(),
        )
        .unwrap();
        let session = root
            .create_session_with_id(
                SessionId::new("attestation-builder").unwrap(),
                &json!({"workload":"attestation-builder"}),
            )
            .unwrap();
        let lock = session.try_lock().unwrap();
        session
            .transition(&lock, SessionStatus::Capturing, None)
            .unwrap();
        let state = session
            .transition(&lock, SessionStatus::Captured, None)
            .unwrap();

        let profile = tc234l_build190766_candidate_profile();
        let scenario = TargetAdapterScenario::Normal;
        let capture_contract = profile.scenario(scenario).unwrap().capture.clone();
        let config = tc234l_snooper_capture_config_for_scenario(
            session.id().as_str(),
            ControllerTargetState::Halted,
            scenario,
        );
        config.validate().unwrap();
        let config_bytes = serde_json::to_vec(&config).unwrap();
        let config_artifact = Artifact {
            id: CAPTURE_CONFIG_ID.to_owned(),
            kind: CAPTURE_CONFIG_KIND.to_owned(),
            relative_path: ArtifactPath::new(CAPTURE_CONFIG_PATH).unwrap(),
            media_type: "application/json".to_owned(),
            size_bytes: u64::try_from(config_bytes.len()).unwrap(),
            sha256: sha256_bytes(&config_bytes).unwrap(),
            producer: crate::controller_capture_config::CONTROLLER_CAPTURE_CONFIG_PRODUCER
                .to_owned(),
            input_artifact_ids: Vec::new(),
        };
        let observations = Artifact {
            id: "observations".to_owned(),
            kind: "observations".to_owned(),
            relative_path: ArtifactPath::new("normalized/observations.ndjson").unwrap(),
            media_type: "application/x-ndjson".to_owned(),
            size_bytes: 3,
            sha256: Sha256Digest::new("1".repeat(64)).unwrap(),
            producer: "test-normalizer/v1".to_owned(),
            input_artifact_ids: Vec::new(),
        };
        let firmware_elf = Artifact {
            id: crate::controller_qualification::FIRMWARE_ELF_ARTIFACT_ID.to_owned(),
            kind: crate::controller_qualification::FIRMWARE_ELF_ARTIFACT_KIND.to_owned(),
            relative_path: ArtifactPath::new(
                crate::controller_qualification::FIRMWARE_ELF_ARTIFACT_PATH,
            )
            .unwrap(),
            media_type: "application/x-elf".to_owned(),
            size_bytes: 1,
            sha256: profile.firmware_elf_sha256.clone(),
            producer: crate::controller_qualification::FIRMWARE_ELF_ARTIFACT_PRODUCER.to_owned(),
            input_artifact_ids: Vec::new(),
        };
        let firmware_measurement = Artifact {
            id: crate::controller::FIRMWARE_S3_ARTIFACT_ID.to_owned(),
            kind: crate::controller::FIRMWARE_S3_ARTIFACT_KIND.to_owned(),
            relative_path: ArtifactPath::new(crate::controller::FIRMWARE_S3_ARTIFACT_PATH).unwrap(),
            media_type: "application/vnd.motorola-s-record".to_owned(),
            size_bytes: TC234L_SNOOPER_BUILD190766_S3_SIZE_BYTES,
            sha256: Sha256Digest::new(TC234L_SNOOPER_BUILD190766_S3_SHA256.to_owned()).unwrap(),
            producer: crate::controller::FIRMWARE_S3_PRODUCER.to_owned(),
            input_artifact_ids: vec![firmware_elf.id.clone()],
        };
        let health_artifact = Artifact {
            id: "controller-output-health".to_owned(),
            kind: "trace32_control_evidence".to_owned(),
            relative_path: ArtifactPath::new("capture/control/health.json").unwrap(),
            media_type: "application/json".to_owned(),
            size_bytes: 1,
            sha256: Sha256Digest::new("2".repeat(64)).unwrap(),
            producer: crate::controller::CONTROLLER_PRODUCER.to_owned(),
            input_artifact_ids: vec!["controller-request-health".to_owned()],
        };
        let health = ControllerHealthEvidenceV2 {
            schema: ControllerHealthEvidenceV2SchemaVersion::V1,
            operation: ControllerHealthOperation::V1,
            binding_sha256: Sha256Digest::new("3".repeat(64)).unwrap(),
            capture_stopped: true,
            supported_signals: vec![
                ControllerHealthSignal::SamplingBufferFull,
                ControllerHealthSignal::SamplingUnexpectedStop,
                ControllerHealthSignal::ElfMismatch,
            ],
            stop_evidence_sha256: Sha256Digest::new("4".repeat(64)).unwrap(),
            sampling: ControllerSamplingHealthEvidence {
                method: ControllerSamplingMethod::RealTime,
                object: ControllerSamplingObject::ProgramCounter,
                buffer_mode: ControllerSamplingBufferMode::Stack,
                state: ControllerSamplingState::Off,
                pre_stop_state: ControllerSamplingPreStopState::Break,
                requested_rate_ns: 1_000_000,
                capacity_records: 65_536,
                recorded_records: 64,
                buffer_full: false,
                unexpected_stop: false,
            },
            elf_matches_firmware: Some(true),
        };
        let stop = ControllerStopEvidenceV2 {
            schema: ControllerStopEvidenceV2SchemaVersion::V1,
            operation: ControllerStopOperation::V1,
            binding_sha256: Sha256Digest::new("3".repeat(64)).unwrap(),
            capture_stopped: true,
            workload_identity: config.workload_identity.clone(),
            target_state_after_stop: ControllerTargetState::Halted,
            pre_stop_state: ControllerSamplingPreStopState::Break,
            capacity_records: 65_536,
            recorded_records: 64,
            time_origin_zeroed_to_first_record: true,
        };
        let target_adapter = ControllerTargetAdapterBinding {
            adapter_id: profile.adapter_id.clone(),
            adapter_version: profile.adapter_version.clone(),
            trace32_release: profile.build_gate.trace32_release.clone(),
            trace32_build: profile.build_gate.minimum_build,
            architecture_package: profile.build_gate.architecture_package.clone(),
            target_identifier: profile.target_identifier.clone(),
            probe_identifier: profile.probe_identifier.clone(),
            profile_sha256: profile.digest().unwrap(),
            implementation_sha256: profile.implementation_sha256.clone(),
            scenario,
            capture_kind: capture_contract.capture_kind.clone(),
            controller_protocol: profile.controller_protocol,
            custom_event_collector: profile.custom_event_collector.clone(),
            qualification_sha256: profile.qualification_sha256.clone(),
        };
        let placeholder_artifact = |id: &str| Artifact {
            id: id.to_owned(),
            kind: "test_controller_evidence".to_owned(),
            relative_path: ArtifactPath::new(format!("capture/control/{id}.json")).unwrap(),
            media_type: "application/json".to_owned(),
            size_bytes: 1,
            sha256: sha256_bytes(id.as_bytes()).unwrap(),
            producer: crate::controller::CONTROLLER_PRODUCER.to_owned(),
            input_artifact_ids: Vec::new(),
        };
        let runtime = AcceptedTrace32RuntimeBinding {
            trace32_release: profile.build_gate.trace32_release.clone(),
            trace32_build: profile.build_gate.minimum_build,
            architecture_package: profile.build_gate.architecture_package.clone(),
            target_identifier: profile.target_identifier.clone(),
            probe_identifier: profile.probe_identifier.clone(),
            initial_target_state: ControllerTargetState::Halted,
            target_adapter,
            capture_contract,
            qualification_artifact: None,
            qualification_provenance_artifacts: Vec::new(),
            qualification_receipt: None,
            firmware_elf_artifact: firmware_elf.clone(),
            firmware_measurement_artifact: firmware_measurement.clone(),
            capabilities_artifact: placeholder_artifact("capabilities"),
            configure_artifact: placeholder_artifact("configure"),
            start_artifact: placeholder_artifact("start"),
            health_artifact: health_artifact.clone(),
            stop_artifact: placeholder_artifact("stop"),
            export_artifact: placeholder_artifact("export"),
            custom_event_artifact: None,
            cleanup_artifact: placeholder_artifact("cleanup"),
            export_response: ControllerScriptResponse {
                operation: PerfOperation::Export,
                status: PerfStatus::Ok,
                code: "OK".to_owned(),
                files_deleted: None,
            },
            completion: ControllerCaptureCompletionEvidence::Sampling {
                stop,
                health: health.clone(),
            },
        };
        let completed = completed_binding_for_test(runtime);
        let controller_health = ControllerHealthBinding {
            artifact: health_artifact.clone(),
            evidence: AcceptedControllerHealthEvidence::Sampling(health),
        };
        let registered_config = RegisteredCaptureConfig {
            artifact: &config_artifact,
            document: config,
        };
        let exact = MetricSupportEntry::new(MetricSupportLevel::Exact);
        let capability_ceiling = CaptureCapabilities {
            function_events: exact.clone(),
            context_switches: exact.clone(),
            interrupt_events: exact.clone(),
            samples: exact.clone(),
            custom_events: exact.clone(),
            counters: exact,
        };
        let policy = CaptureTrustPolicy {
            schema: CaptureTrustPolicySchemaVersion,
            policy_id: "sampling-policy".to_owned(),
            keys: vec![CaptureTrustKey {
                key_id: "sampling-key".to_owned(),
                public_key_ed25519: encode_hex(
                    &SigningKey::from_bytes(&[29_u8; 32])
                        .verifying_key()
                        .to_bytes(),
                ),
                producer: "test.capture-signer/v1".to_owned(),
                provider: "trace32".to_owned(),
                adapter: registered_config.document.adapter.clone(),
                allowed_modes: vec![registered_config.document.mode.clone()],
                target: TargetInfo {
                    architecture: Some(profile.build_gate.architecture_package.clone()),
                    device: Some(profile.target_identifier.clone()),
                    board: Some("test-board".to_owned()),
                    core_count: Some(1),
                    properties: Properties::new(),
                },
                trace32: Some(Trace32Info {
                    build: Some("R.2026.02.000190766".to_owned()),
                    probe: Some(profile.probe_identifier.clone()),
                    architecture_package: Some(profile.build_gate.architecture_package.clone()),
                    properties: Properties::new(),
                }),
                clocks: vec![ClockInfo {
                    id: "snooper_host_time".to_owned(),
                    frequency_hz: Some(1_000_000_000),
                    source: Some("trace32".to_owned()),
                    properties: Properties::new(),
                }],
                allowed_cores: vec![0],
                allowed_firmware_elf_sha256: vec![profile.firmware_elf_sha256.clone()],
                capability_ceiling: capability_ceiling.clone(),
                config_constraints: None,
            }],
        };
        policy.validate().unwrap();
        let artifacts = vec![
            observations.clone(),
            config_artifact.clone(),
            firmware_elf,
            firmware_measurement,
            health_artifact,
        ];
        let request = build_attestation_signing_request_from_verified(
            AttestationSigningRequestBuildContext {
                session: &session,
                state: &state,
                artifacts: &artifacts,
                observations: &observations,
                capture_config: &registered_config,
                completed: &completed,
                controller_health: &controller_health,
                policy: &policy,
            },
            "sampling-policy",
            "sampling-key",
        )
        .unwrap();
        assert_eq!(request.payload.receipt.capabilities, profile.capabilities);
        assert_ne!(request.payload.receipt.capabilities, capability_ceiling);
        assert_eq!(
            request
                .payload
                .receipt
                .trace32
                .as_ref()
                .unwrap()
                .build
                .as_deref(),
            Some("R.2026.02.000190766")
        );
        assert_eq!(
            request.payload.receipt.firmware.elf_sha256.as_ref(),
            Some(&profile.firmware_elf_sha256)
        );
        assert!(request.payload.receipt.health_observations.is_empty());
    }

    #[test]
    fn public_signing_request_builder_fails_closed_without_completed_controller_chain() {
        let fixture = EnsureFixture::new();
        let before = fixture.artifacts();
        let error = build_attestation_signing_request(
            &fixture.session,
            &fixture.signing_request.policy_id,
            &fixture.signing_request.key_id,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("fully accepted TRACE32 controller chain")
        );
        assert_eq!(fixture.artifacts(), before);
    }

    #[test]
    fn signed_attestation_binds_session_artifact_and_claim_ceiling() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let exact = MetricSupportEntry::new(MetricSupportLevel::Exact);
        let unavailable = MetricSupportEntry {
            support: MetricSupportLevel::Unavailable,
            reasons: vec!["not_captured".to_owned()],
        };
        let capabilities = CaptureCapabilities {
            function_events: exact.clone(),
            context_switches: exact.clone(),
            interrupt_events: exact.clone(),
            samples: unavailable.clone(),
            custom_events: unavailable.clone(),
            counters: unavailable,
        };
        let target = TargetInfo {
            architecture: Some("armv8-m".to_owned()),
            device: Some("example-mcu".to_owned()),
            board: Some("example-board".to_owned()),
            core_count: Some(1),
            properties: Properties::new(),
        };
        let trace32 = Trace32Info {
            build: Some("R.2026.02".to_owned()),
            probe: Some("PowerTrace".to_owned()),
            architecture_package: Some("ARM".to_owned()),
            properties: Properties::new(),
        };
        let clocks = vec![ClockInfo {
            id: "trace".to_owned(),
            frequency_hz: Some(100_000_000),
            source: Some("target".to_owned()),
            properties: Properties::new(),
        }];
        let request_sha256 = Sha256Digest::new("a".repeat(64)).unwrap();
        let observation_sha256 = Sha256Digest::new("b".repeat(64)).unwrap();
        let config_sha256 = Sha256Digest::new("d".repeat(64)).unwrap();
        let config_artifact = Artifact {
            id: CAPTURE_CONFIG_ID.to_owned(),
            kind: crate::capture_config::CAPTURE_CONFIG_KIND.to_owned(),
            relative_path: ArtifactPath::new(crate::capture_config::CAPTURE_CONFIG_PATH).unwrap(),
            media_type: "application/json".to_owned(),
            size_bytes: 1,
            sha256: config_sha256.clone(),
            producer: "lab-adapter/untrusted".to_owned(),
            input_artifact_ids: Vec::new(),
        };
        let config_document = CaptureConfigDocument {
            schema: CaptureConfigSchemaVersion,
            session_id: "session-a".to_owned(),
            provider: "trace32".to_owned(),
            adapter: AdapterInfo {
                id: "lab-adapter".to_owned(),
                version: "1".to_owned(),
            },
            mode: "etm".to_owned(),
            covered_cores: vec![0],
            sink: CaptureSinkConfig {
                kind: "probe_buffer".to_owned(),
                id: "powertrace-0".to_owned(),
                capacity_bytes: Some(1_048_576),
                stream_destination_identity: None,
            },
            timestamp: CaptureTimestampConfig {
                enabled: true,
                clock_id: Some("trace".to_owned()),
            },
            filters: Vec::new(),
            trigger: CaptureTriggerConfig {
                kind: "manual".to_owned(),
                pre_trigger_ns: None,
                post_trigger_ns: None,
                condition_identity: None,
            },
            duration: CaptureDurationConfig {
                duration_ns: Some(1_000_000),
                observation_limit: None,
            },
            workload_identity: "golden-workload/v1".to_owned(),
            initial_target_state: InitialTargetState::Halted,
            rtos_awareness: CaptureRtosAwarenessConfig {
                kind: "none".to_owned(),
                metadata_artifact_ids: Vec::new(),
            },
            instrumentation: None,
            adapter_parameters: Properties::from([(
                "firmware.elf_sha256".to_owned(),
                json!("c".repeat(64)),
            )]),
        };
        let configuration_digest = Sha256::digest(
            config_document
                .configuration_identity_bytes()
                .expect("serialize config identity"),
        );
        let configuration_sha256 =
            Sha256Digest::new(encode_hex(configuration_digest.as_ref())).unwrap();
        let config_claim = CaptureConfigArtifactClaim {
            artifact_id: CAPTURE_CONFIG_ID.to_owned(),
            sha256: config_sha256.clone(),
            configuration_sha256: configuration_sha256.clone(),
        };
        let registered_config = RegisteredCaptureConfig {
            artifact: &config_artifact,
            document: config_document,
        };
        let receipt = CaptureReceipt {
            schema: CaptureReceiptSchemaVersion,
            session_id: "session-a".to_owned(),
            provider: "trace32".to_owned(),
            mode: "etm".to_owned(),
            adapter: AdapterInfo {
                id: "lab-adapter".to_owned(),
                version: "1".to_owned(),
            },
            target: Some(target.clone()),
            trace32: Some(trace32.clone()),
            firmware: FirmwareInfo {
                elf_path: None,
                elf_sha256: Some(Sha256Digest::new("c".repeat(64)).unwrap()),
                build_id: Some("build-a".to_owned()),
            },
            clocks: clocks.clone(),
            covered_cores: vec![0],
            capabilities: capabilities.clone(),
            health_observations: Vec::new(),
            request_sha256: request_sha256.clone(),
            capture_config: Some(config_claim.clone()),
            controller_health: None,
            properties: BTreeMap::new(),
        };
        let payload = CaptureAttestationPayload {
            schema: CaptureAttestationSchemaVersion,
            key_id: "lab-key".to_owned(),
            nonce: "operation-a".to_owned(),
            receipt,
            observation_artifact_id: "observations".to_owned(),
            observation_sha256: observation_sha256.clone(),
            capture_config: Some(config_claim),
            controller_health: None,
        };
        let signature = signing_key.sign(&payload.signing_bytes().unwrap());
        let attestation = CaptureAttestation {
            payload,
            signature_ed25519: encode_hex(&signature.to_bytes()),
        };
        let policy = CaptureTrustPolicy {
            schema: CaptureTrustPolicySchemaVersion,
            policy_id: "lab-policy".to_owned(),
            keys: vec![CaptureTrustKey {
                key_id: "lab-key".to_owned(),
                public_key_ed25519: encode_hex(&signing_key.verifying_key().to_bytes()),
                producer: "lab.trace32/v1".to_owned(),
                provider: "trace32".to_owned(),
                adapter: AdapterInfo {
                    id: "lab-adapter".to_owned(),
                    version: "1".to_owned(),
                },
                allowed_modes: vec!["etm".to_owned()],
                target,
                trace32: Some(trace32),
                clocks,
                allowed_cores: vec![0],
                allowed_firmware_elf_sha256: vec![Sha256Digest::new("c".repeat(64)).unwrap()],
                capability_ceiling: capabilities,
                config_constraints: Some(CaptureConfigConstraints {
                    allowed_sink_kinds: vec!["probe_buffer".to_owned()],
                    allowed_sink_ids: vec!["powertrace-0".to_owned()],
                    allowed_initial_target_states: vec![InitialTargetState::Halted],
                    allowed_rtos_awareness_kinds: vec!["none".to_owned()],
                    max_sink_capacity_bytes: Some(1_048_576),
                    require_timestamp_enabled: Some(true),
                    allowed_config_sha256: vec![configuration_sha256],
                }),
            }],
        };
        let observations = Artifact {
            id: "observations".to_owned(),
            kind: "observations".to_owned(),
            relative_path: ArtifactPath::new("normalized/observations.ndjson").unwrap(),
            media_type: "application/x-ndjson".to_owned(),
            size_bytes: 1,
            sha256: observation_sha256,
            producer: "normalizer".to_owned(),
            input_artifact_ids: Vec::new(),
        };

        let verified = verify_capture_attestation(
            &policy,
            &attestation,
            CaptureAttestationVerificationContext {
                expected_session_id: "session-a",
                expected_nonce: "operation-a",
                expected_request_sha256: &request_sha256,
                observations: &observations,
                capture_config: &registered_config,
                controller_health: None,
            },
        )
        .unwrap();
        assert_eq!(verified.producer, "lab.trace32/v1");
        assert!(
            verify_trace32_firmware_binding(
                &policy.keys[0],
                &attestation.payload.receipt,
                &registered_config.document,
            )
            .is_ok()
        );

        let mut missing_firmware_config = registered_config.document.clone();
        missing_firmware_config
            .adapter_parameters
            .remove("firmware.elf_sha256");
        assert!(
            verify_trace32_firmware_binding(
                &policy.keys[0],
                &attestation.payload.receipt,
                &missing_firmware_config,
            )
            .is_err()
        );

        let mut wrong_type_firmware_config = registered_config.document.clone();
        wrong_type_firmware_config
            .adapter_parameters
            .insert("firmware.elf_sha256".to_owned(), json!(123));
        assert!(
            verify_trace32_firmware_binding(
                &policy.keys[0],
                &attestation.payload.receipt,
                &wrong_type_firmware_config,
            )
            .is_err()
        );

        let mut mismatched_firmware_config = registered_config.document.clone();
        mismatched_firmware_config
            .adapter_parameters
            .insert("firmware.elf_sha256".to_owned(), json!("e".repeat(64)));
        assert!(
            verify_trace32_firmware_binding(
                &policy.keys[0],
                &attestation.payload.receipt,
                &mismatched_firmware_config,
            )
            .is_err()
        );

        let mut changed_config_document = registered_config.document.clone();
        changed_config_document.sink.id = "different-sink".to_owned();
        let changed_config = RegisteredCaptureConfig {
            artifact: &config_artifact,
            document: changed_config_document,
        };
        assert!(
            verify_capture_attestation(
                &policy,
                &attestation,
                CaptureAttestationVerificationContext {
                    expected_session_id: "session-a",
                    expected_nonce: "operation-a",
                    expected_request_sha256: &request_sha256,
                    observations: &observations,
                    capture_config: &changed_config,
                    controller_health: None,
                },
            )
            .is_err()
        );

        let mut tampered = attestation;
        tampered.payload.receipt.mode = "sampling".to_owned();
        assert!(
            verify_capture_attestation(
                &policy,
                &tampered,
                CaptureAttestationVerificationContext {
                    expected_session_id: "session-a",
                    expected_nonce: "operation-a",
                    expected_request_sha256: &request_sha256,
                    observations: &observations,
                    capture_config: &registered_config,
                    controller_health: None,
                },
            )
            .is_err()
        );
    }

    fn encode_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}
