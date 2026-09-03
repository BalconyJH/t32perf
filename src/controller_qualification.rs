//! Session-scoped deployment qualification admission.
//!
//! The trust-store is deliberately outside a Session and is read-only to this
//! process.  Session artifacts are evidence snapshots, never an enrollment API.

#[cfg(test)]
use std::cell::RefCell;

use std::{
    fs::{self, File, OpenOptions},
    io::Read as _,
    path::Path,
};

use serde_json::json;
use sha2::{Digest as _, Sha256};
use t32perf_model::{Artifact, ArtifactPath, SessionStatus, Sha256Digest, is_portable_artifact_id};
#[cfg(windows)]
use t32perf_session::verify_opened_plain_file_identity;
use t32perf_session::{ArtifactRoot, ArtifactSpec, Session, SessionLock};
use t32perf_trace32::{
    MAX_TARGET_ADAPTER_QUALIFICATION_TRUST_STORE_BYTES, MAX_TRICORE_FIRMWARE_ELF_BYTES,
    TargetAdapterAdmissionCatalog, TargetAdapterAdmissionSnapshot,
    TargetAdapterAdmissionSnapshotSchemaVersion, TargetAdapterProfile,
    TargetAdapterQualificationReceipt, TargetAdapterRecoveryEvidence, TargetAdapterScenario,
    compiled_target_adapter_bundle_catalog, measure_tricore_elf_to_s3,
    parse_hil_verification_receipt, parse_target_adapter_admission_snapshot,
    parse_target_adapter_qualification_policy, parse_target_adapter_qualification_receipt,
    parse_target_adapter_qualification_trust_store, validate_target_adapter_qualification,
};

use crate::{
    app::{AppError, CommandOutcome, EXIT_SUCCESS},
    cli::{
        ControllerProvisionFirmwareArgs, ControllerProvisionQualificationArgs,
        ControllerSelectScenarioArgs,
    },
};

pub const QUALIFICATION_POLICY_ARTIFACT_ID: &str = "target-adapter-qualification-policy";
pub const HIL_VERIFICATION_ARTIFACT_ID: &str = "target-adapter-hil-verification";
pub const HIL_RECOVERY_EVIDENCE_ARTIFACT_ID: &str = "target-adapter-hil-recovery-evidence";
pub const ADMISSION_SNAPSHOT_ARTIFACT_ID: &str = "target-adapter-admission-snapshot";
pub const QUALIFICATION_POLICY_KIND: &str = "target_adapter_qualification_policy";
pub const HIL_VERIFICATION_KIND: &str = "hil_verification_receipt";
pub const HIL_RECOVERY_EVIDENCE_KIND: &str = "target_adapter_recovery_evidence";
pub const ADMISSION_SNAPSHOT_KIND: &str = "target_adapter_admission_snapshot";
pub const DEPLOYMENT_PRODUCER: &str = "t32perf-deployment-qualification/v1";
pub const QUALIFICATION_POLICY_PATH: &str = "capture/deployment/target-adapter-policy.json";
pub const HIL_VERIFICATION_PATH: &str = "capture/deployment/target-adapter-hil.json";
pub const HIL_RECOVERY_EVIDENCE_PATH: &str = "capture/deployment/target-adapter-hil-recovery.json";
pub const QUALIFICATION_PATH: &str = "capture/target-adapter-qualification.json";
pub const ADMISSION_SNAPSHOT_PATH: &str = "capture/deployment/target-adapter-admission.json";
pub const FIRMWARE_ELF_ARTIFACT_ID: &str = "firmware-elf";
pub const FIRMWARE_ELF_ARTIFACT_KIND: &str = "firmware_elf";
pub const FIRMWARE_ELF_ARTIFACT_PATH: &str = "capture/firmware.elf";
pub const FIRMWARE_ELF_ARTIFACT_PRODUCER: &str = "t32perf-deployment-firmware/v1";
const MAX_POLICY_BYTES: u64 = 16 * 1024;
const MAX_QUALIFICATION_BYTES: u64 = 64 * 1024;
const MAX_ADMISSION_BYTES: u64 = 16 * 1024;
const MAX_RECOVERY_EVIDENCE_BYTES: u64 = 64 * 1024;

/// Returns the closed set of compiled deployment profiles.
///
/// This is deliberately the sole production registry seam.  A future
/// TASKEVENTS profile must be added here only after it has its own complete
/// firmware, qualification and deployment selection evidence; it must never
/// be inferred from the TC234L sampling profile.
pub(crate) fn compiled_target_adapter_profiles() -> Vec<TargetAdapterProfile> {
    #[cfg(test)]
    if let Some(profiles) = TEST_COMPILED_PROFILES.with(|slot| slot.borrow().clone()) {
        return profiles;
    }
    compiled_target_adapter_profiles_from_catalog(compiled_target_adapter_bundle_catalog())
        .expect("compiled target-adapter bundle catalog must satisfy its closed contract")
}

/// Builds the deterministic evidence-only catalog used by endpoint discovery.
///
/// This catalog describes every compiled candidate that the Host can recognize;
/// it does not admit the Session firmware or authorize target-side execution.
/// Target operations still reconstruct their exact candidate or qualified
/// Session admission through [`load_session_admission`].
pub(crate) fn compiled_candidate_admission_catalog()
-> Result<TargetAdapterAdmissionCatalog, AppError> {
    let profiles = compiled_target_adapter_profiles();
    if profiles.is_empty() {
        return Err(AppError::operational(
            "compiled target-adapter candidate catalog is empty",
        ));
    }
    let mut catalog = TargetAdapterAdmissionCatalog::new();
    for profile in profiles {
        catalog
            .admit_candidate(profile)
            .map_err(AppError::operational)?;
    }
    Ok(catalog)
}

#[cfg(test)]
thread_local! {
    static TEST_COMPILED_PROFILES: RefCell<Option<Vec<TargetAdapterProfile>>> = const { RefCell::new(None) };
}

/// Runs one test with a thread-local compiled profile catalog override.
///
/// Production code always uses the compiled bundle catalog. The scope is
/// restored during unwinding, so parallel tests cannot observe this fixture.
#[cfg(test)]
pub(crate) fn with_test_compiled_target_adapter_profiles<T>(
    profiles: Vec<TargetAdapterProfile>,
    run: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<Vec<TargetAdapterProfile>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_COMPILED_PROFILES.with(|slot| {
                slot.replace(self.0.take());
            });
        }
    }
    let previous = TEST_COMPILED_PROFILES.with(|slot| slot.replace(Some(profiles)));
    let _restore = Restore(previous);
    run()
}

fn compiled_target_adapter_profiles_from_catalog(
    catalog: Vec<t32perf_trace32::TargetAdapterBundleDescriptor>,
) -> Result<Vec<TargetAdapterProfile>, AppError> {
    validate_compiled_bundle_catalog(&catalog)?;
    Ok(catalog
        .into_iter()
        .map(|descriptor| descriptor.candidate_profile)
        .collect())
}

fn validate_compiled_bundle_catalog(
    catalog: &[t32perf_trace32::TargetAdapterBundleDescriptor],
) -> Result<(), AppError> {
    let mut directories = std::collections::BTreeSet::new();
    let mut adapter_ids = std::collections::BTreeSet::new();
    let mut implementation_digests = std::collections::BTreeSet::new();
    for descriptor in catalog {
        descriptor.validate().map_err(AppError::operational)?;
        if !directories.insert(descriptor.bundle_relative_directory.to_ascii_lowercase()) {
            return Err(AppError::operational(
                "compiled target-adapter bundle catalog contains case-insensitive duplicate directories",
            ));
        }
        if !adapter_ids.insert(descriptor.candidate_profile.adapter_id.as_str()) {
            return Err(AppError::operational(
                "compiled target-adapter bundle catalog contains duplicate adapter IDs",
            ));
        }
        if !implementation_digests
            .insert(descriptor.candidate_profile.implementation_sha256.as_str())
        {
            return Err(AppError::operational(
                "compiled target-adapter bundle catalog contains duplicate implementation digests",
            ));
        }
    }
    let paths = catalog
        .iter()
        .map(|descriptor| descriptor.bundle_relative_directory.to_ascii_lowercase())
        .collect::<Vec<_>>();
    for (index, directory) in paths.iter().enumerate() {
        for other in paths.iter().skip(index + 1) {
            if directory.starts_with(&format!("{other}/"))
                || other.starts_with(&format!("{directory}/"))
            {
                return Err(AppError::operational(
                    "compiled target-adapter bundle catalog contains overlapping adapter directories",
                ));
            }
        }
    }
    Ok(())
}

fn compiled_profile_for_firmware(
    firmware_sha256: &Sha256Digest,
) -> Result<TargetAdapterProfile, AppError> {
    compiled_profile_for_firmware_in(&compiled_target_adapter_profiles(), firmware_sha256)
}

fn compiled_profile_for_firmware_in(
    profiles: &[TargetAdapterProfile],
    firmware_sha256: &Sha256Digest,
) -> Result<TargetAdapterProfile, AppError> {
    let matches = profiles
        .iter()
        .filter(|profile| &profile.firmware_elf_sha256 == firmware_sha256)
        .cloned()
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [profile] => Ok(profile.clone()),
        [] => Err(AppError::operational(
            "firmware ELF SHA-256 is not registered by a compiled target-adapter profile",
        )),
        _ => Err(AppError::operational(
            "firmware ELF matches multiple compiled profiles; an exact adapter/profile discriminator is required",
        )),
    }
}

fn compiled_profile_for_receipt(
    receipt: &TargetAdapterQualificationReceipt,
) -> Result<TargetAdapterProfile, AppError> {
    let mut matches = Vec::new();
    for profile in compiled_target_adapter_profiles() {
        if profile.adapter_id == receipt.adapter_id
            && profile.adapter_version == receipt.adapter_version
            && profile
                .qualification_identity_digest()
                .map_err(AppError::operational)?
                == receipt.candidate_profile_sha256
        {
            matches.push(profile);
        }
    }
    match matches.as_slice() {
        [profile] => Ok(profile.clone()),
        [] => Err(AppError::operational(
            "qualification receipt does not select a compiled adapter/profile",
        )),
        _ => Err(AppError::operational(
            "qualification receipt selects multiple compiled profiles",
        )),
    }
}

pub fn provision(
    root: &ArtifactRoot,
    arguments: ControllerProvisionQualificationArgs,
) -> Result<CommandOutcome, AppError> {
    let session = crate::app::open_session(root, &arguments.session)?;
    let lock = session.try_lock().map_err(AppError::operational)?;
    let state = session.read_state().map_err(AppError::operational)?;
    if !matches!(
        state.status,
        SessionStatus::Created | SessionStatus::Capturing
    ) {
        return Err(AppError::operational(
            "qualification provisioning is only allowed before controller activity",
        ));
    }
    let artifacts = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    if artifacts.iter().any(|artifact| {
        artifact
            .id
            .starts_with(crate::controller::CONTROLLER_ARTIFACT_ID_PREFIX)
    }) {
        return Err(AppError::operational(
            "qualification provisioning is forbidden after any controller request",
        ));
    }
    let policy_bytes = read_trusted_policy(root, &arguments.policy_id)?;
    let qualification_staged =
        ArtifactPath::new(arguments.qualification_staged).map_err(AppError::operational)?;
    let hil_staged = ArtifactPath::new(arguments.hil_staged).map_err(AppError::operational)?;
    let qualification_bytes = session
        .read_staged_bounded(&qualification_staged, MAX_QUALIFICATION_BYTES)
        .map_err(AppError::operational)?;
    let hil_bytes = session
        .read_staged_bounded(
            &hil_staged,
            t32perf_trace32::MAX_HIL_VERIFICATION_RECEIPT_BYTES as u64,
        )
        .map_err(AppError::operational)?;
    let policy =
        parse_target_adapter_qualification_policy(&policy_bytes).map_err(AppError::operational)?;
    if policy.policy_id != arguments.policy_id {
        return Err(AppError::operational(
            "trusted policy ID does not match requested policy ID",
        ));
    }
    let qualification = parse_target_adapter_qualification_receipt(&qualification_bytes)
        .map_err(AppError::operational)?;
    let hil = parse_hil_verification_receipt(&hil_bytes).map_err(AppError::operational)?;
    let recovery = match (&hil.recovery_evidence, arguments.recovery_staged.as_deref()) {
        (None, None) => None,
        (None, Some(_)) => {
            return Err(AppError::operational(
                "non-recovery HIL receipt forbids a recovery-evidence artifact",
            ));
        }
        (Some(_), None) => {
            return Err(AppError::operational(
                "recovery HIL provisioning requires --recovery-staged",
            ));
        }
        (Some(binding), Some(relative)) => {
            let staged = ArtifactPath::new(relative).map_err(AppError::operational)?;
            let bytes = session
                .read_staged_bounded(&staged, MAX_RECOVERY_EVIDENCE_BYTES)
                .map_err(AppError::operational)?;
            let document: TargetAdapterRecoveryEvidence =
                t32perf_model::strict_json::from_slice(&bytes).map_err(AppError::operational)?;
            document.validate().map_err(AppError::operational)?;
            if digest(&bytes) != binding.sha256 || document != binding.document {
                return Err(AppError::operational(
                    "raw recovery-evidence artifact does not exactly match the HIL receipt binding",
                ));
            }
            Some(bytes)
        }
    };
    let candidate = compiled_profile_for_receipt(&qualification)?;
    let firmware = required_firmware(&artifacts)?;
    validate_firmware_identity(firmware)?;
    if firmware.sha256 != candidate.firmware_elf_sha256
        || firmware.sha256 != policy.firmware_elf_sha256
    {
        return Err(AppError::operational(
            "registered firmware ELF does not exactly match candidate/profile policy",
        ));
    }
    validate_target_adapter_qualification(
        &policy,
        &candidate,
        &qualification_bytes,
        &qualification,
        &hil_bytes,
        &hil,
    )
    .map_err(AppError::operational)?;
    let snapshot = admission_snapshot(
        &policy,
        &candidate,
        &policy_bytes,
        &hil_bytes,
        &qualification_bytes,
    )?;
    let snapshot_bytes = canonical_json(&snapshot)?;
    ensure_or_ingest(
        &session,
        &lock,
        QualificationArtifact::new(
            QUALIFICATION_POLICY_ARTIFACT_ID,
            QUALIFICATION_POLICY_KIND,
            QUALIFICATION_POLICY_PATH,
            &policy_bytes,
            vec![],
        ),
    )?;
    let recovery_artifact = if let Some(bytes) = recovery.as_deref() {
        Some(ensure_or_ingest(
            &session,
            &lock,
            QualificationArtifact::new(
                HIL_RECOVERY_EVIDENCE_ARTIFACT_ID,
                HIL_RECOVERY_EVIDENCE_KIND,
                HIL_RECOVERY_EVIDENCE_PATH,
                bytes,
                vec![],
            ),
        )?)
    } else {
        None
    };
    let qualification_inputs = {
        let mut inputs = vec![
            QUALIFICATION_POLICY_ARTIFACT_ID.to_owned(),
            HIL_VERIFICATION_ARTIFACT_ID.to_owned(),
        ];
        if recovery_artifact.is_some() {
            inputs.push(HIL_RECOVERY_EVIDENCE_ARTIFACT_ID.to_owned());
        }
        inputs
    };
    ensure_or_ingest(
        &session,
        &lock,
        QualificationArtifact::new(
            HIL_VERIFICATION_ARTIFACT_ID,
            HIL_VERIFICATION_KIND,
            HIL_VERIFICATION_PATH,
            &hil_bytes,
            vec![],
        ),
    )?;
    ensure_or_ingest(
        &session,
        &lock,
        QualificationArtifact::new(
            crate::controller::TARGET_ADAPTER_QUALIFICATION_ARTIFACT_ID,
            crate::controller::TARGET_ADAPTER_QUALIFICATION_KIND,
            QUALIFICATION_PATH,
            &qualification_bytes,
            qualification_inputs,
        ),
    )?;
    let admission = ensure_or_ingest(
        &session,
        &lock,
        QualificationArtifact::new(
            ADMISSION_SNAPSHOT_ARTIFACT_ID,
            ADMISSION_SNAPSHOT_KIND,
            ADMISSION_SNAPSHOT_PATH,
            &snapshot_bytes,
            {
                let mut inputs = vec![
                    QUALIFICATION_POLICY_ARTIFACT_ID.to_owned(),
                    HIL_VERIFICATION_ARTIFACT_ID.to_owned(),
                    crate::controller::TARGET_ADAPTER_QUALIFICATION_ARTIFACT_ID.to_owned(),
                    firmware.id.clone(),
                ];
                if recovery_artifact.is_some() {
                    inputs.push(HIL_RECOVERY_EVIDENCE_ARTIFACT_ID.to_owned());
                }
                inputs
            },
        ),
    )?;
    let committed = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    let _ = load_session_admission(&session, &committed)?;
    Ok(CommandOutcome {
        command: "controller.provision_qualification",
        result: json!({"session_id": session.id().as_str(), "policy_id": policy.policy_id, "admission_snapshot_artifact": admission}),
        exit_code: EXIT_SUCCESS,
    })
}

/// Publishes the fixed firmware identity through the deployment boundary.
pub fn provision_firmware_command(
    root: &ArtifactRoot,
    arguments: ControllerProvisionFirmwareArgs,
) -> Result<CommandOutcome, AppError> {
    let staged = ArtifactPath::new(arguments.staged).map_err(AppError::operational)?;
    let artifact = provision_firmware(root, &arguments.session, &staged)?;
    Ok(CommandOutcome {
        command: "controller.provision_firmware",
        result: json!({"session_id": arguments.session, "artifact": artifact}),
        exit_code: EXIT_SUCCESS,
    })
}

/// Persists one closed, deployment-owned adapter scenario without admitting any
/// caller-provided script or output path.
pub fn select_scenario(
    root: &ArtifactRoot,
    arguments: ControllerSelectScenarioArgs,
) -> Result<CommandOutcome, AppError> {
    let session = crate::app::open_session(root, &arguments.session)?;
    let lock = session.try_lock().map_err(AppError::operational)?;
    if session.read_state().map_err(AppError::operational)?.status != SessionStatus::Created {
        return Err(AppError::operational(
            "scenario selection is only allowed while the Session is Created",
        ));
    }
    let artifacts = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    if artifacts.iter().any(|artifact| {
        artifact
            .id
            .starts_with(crate::controller::CONTROLLER_ARTIFACT_ID_PREFIX)
    }) {
        return Err(AppError::operational(
            "scenario selection is forbidden after any controller request",
        ));
    }
    let scenario = TargetAdapterScenario::parse(&arguments.scenario).ok_or_else(|| {
        AppError::operational("target-adapter scenario is not in the closed deployment vocabulary")
    })?;
    let firmware = required_firmware(&artifacts)?;
    validate_firmware_identity(firmware)?;
    let (profile, _, provenance, allowed) = load_session_admission(&session, &artifacts)?;
    let (selection, inputs) = crate::controller::provision_target_adapter_scenario(
        scenario,
        &profile,
        &provenance,
        &allowed,
    )?;
    let bytes = canonical_json(&selection)?;
    let spec = ArtifactSpec {
        id: crate::controller::TARGET_ADAPTER_SCENARIO_ARTIFACT_ID.to_owned(),
        kind: crate::controller::TARGET_ADAPTER_SCENARIO_KIND.to_owned(),
        relative_path: ArtifactPath::new(crate::controller::TARGET_ADAPTER_SCENARIO_PATH)
            .map_err(AppError::operational)?,
        media_type: "application/json".to_owned(),
        producer: crate::controller::TARGET_ADAPTER_SCENARIO_PRODUCER.to_owned(),
        input_artifact_ids: inputs,
    };
    let artifact = if let Some(existing) = artifacts.iter().find(|artifact| artifact.id == spec.id)
    {
        session
            .verify_artifact(existing, true)
            .map_err(AppError::operational)?;
        if existing.kind != spec.kind
            || existing.relative_path != spec.relative_path
            || existing.media_type != spec.media_type
            || existing.producer != spec.producer
            || existing.input_artifact_ids != spec.input_artifact_ids
            || existing.sha256 != digest(&bytes)
        {
            return Err(AppError::operational(
                "existing target-adapter scenario conflicts with the requested immutable selection",
            ));
        }
        existing.clone()
    } else {
        let staged = ArtifactPath::new("qualification/target-adapter-scenario.json")
            .map_err(AppError::operational)?;
        let maximum = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        session
            .ensure_staged_exact(&lock, &staged, &bytes, maximum)
            .map_err(AppError::operational)?;
        session
            .ingest_staged_bounded(&lock, &staged, spec, maximum)
            .map_err(AppError::operational)?
    };
    Ok(CommandOutcome {
        command: "controller.select_scenario",
        result: json!({
            "session_id": session.id().as_str(),
            "scenario": scenario.as_str(),
            "artifact": artifact,
        }),
        exit_code: EXIT_SUCCESS,
    })
}

/// Admits the fixed TC234L firmware image before qualification or controller activity.
pub(crate) fn provision_firmware(
    root: &ArtifactRoot,
    session_id: &str,
    staged_relative: &ArtifactPath,
) -> Result<Artifact, AppError> {
    let session = crate::app::open_session(root, session_id)?;
    let lock = session.try_lock().map_err(AppError::operational)?;
    let artifacts = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    let limit = u64::try_from(MAX_TRICORE_FIRMWARE_ELF_BYTES).unwrap_or(u64::MAX);
    if let Some(existing) = artifacts
        .iter()
        .find(|artifact| artifact.id == FIRMWARE_ELF_ARTIFACT_ID)
    {
        // A durable firmware publication is an immutable checkpoint.  Retry
        // must prove that checkpoint before consulting a caller-controlled
        // staging path, including after qualification or controller work has
        // begun.
        validate_firmware_identity(existing)?;
        let published = read_artifact(&session, existing, limit)?;
        if digest(&published) != existing.sha256 {
            return Err(AppError::operational(
                "published firmware ELF bytes do not match its immutable catalog entry",
            ));
        }
        measure_tricore_elf_to_s3(&published).map_err(AppError::operational)?;
        return Ok(existing.clone());
    }
    if session.read_state().map_err(AppError::operational)?.status != SessionStatus::Created {
        return Err(AppError::operational(
            "firmware provisioning is only allowed while the Session is Created",
        ));
    }
    if artifacts.iter().any(|artifact| {
        artifact
            .id
            .starts_with(crate::controller::CONTROLLER_ARTIFACT_ID_PREFIX)
            || matches!(
                artifact.id.as_str(),
                QUALIFICATION_POLICY_ARTIFACT_ID
                    | HIL_VERIFICATION_ARTIFACT_ID
                    | crate::controller::TARGET_ADAPTER_QUALIFICATION_ARTIFACT_ID
                    | ADMISSION_SNAPSHOT_ARTIFACT_ID
            )
    }) {
        return Err(AppError::operational(
            "firmware provisioning is forbidden after qualification or controller activity",
        ));
    }
    let bytes = session
        .read_staged_bounded(staged_relative, limit)
        .map_err(AppError::operational)?;
    let candidate = compiled_profile_for_firmware(&digest(&bytes))?;
    measure_tricore_elf_to_s3(&bytes).map_err(AppError::operational)?;
    let host_staging =
        ArtifactPath::new("qualification/firmware-elf.bin").map_err(AppError::operational)?;
    session
        .ensure_staged_exact(&lock, &host_staging, &bytes, limit)
        .map_err(AppError::operational)?;
    let spec = ArtifactSpec {
        id: FIRMWARE_ELF_ARTIFACT_ID.to_owned(),
        kind: FIRMWARE_ELF_ARTIFACT_KIND.to_owned(),
        relative_path: ArtifactPath::new(FIRMWARE_ELF_ARTIFACT_PATH)
            .map_err(AppError::operational)?,
        media_type: "application/x-elf".to_owned(),
        producer: FIRMWARE_ELF_ARTIFACT_PRODUCER.to_owned(),
        input_artifact_ids: Vec::new(),
    };
    let artifact = session
        .ingest_staged_bounded(&lock, &host_staging, spec, limit)
        .map_err(AppError::operational)?;
    let published = read_artifact(&session, &artifact, limit)?;
    if digest(&published) != candidate.firmware_elf_sha256 {
        return Err(AppError::operational(
            "published firmware ELF does not match the fixed candidate",
        ));
    }
    measure_tricore_elf_to_s3(&published).map_err(AppError::operational)?;
    Ok(artifact)
}

/// Reconstructs an exact candidate or qualified admission from immutable Session evidence.
pub(crate) fn load_session_admission(
    session: &Session,
    artifacts: &[Artifact],
) -> Result<
    (
        TargetAdapterProfile,
        TargetAdapterAdmissionCatalog,
        Vec<Artifact>,
        Vec<TargetAdapterScenario>,
    ),
    AppError,
> {
    let ids = [
        QUALIFICATION_POLICY_ARTIFACT_ID,
        HIL_VERIFICATION_ARTIFACT_ID,
        crate::controller::TARGET_ADAPTER_QUALIFICATION_ARTIFACT_ID,
        ADMISSION_SNAPSHOT_ARTIFACT_ID,
    ];
    let found = ids.map(|id| artifacts.iter().find(|artifact| artifact.id == id));
    if found.iter().all(Option::is_none) {
        if artifacts
            .iter()
            .any(|artifact| artifact.id == HIL_RECOVERY_EVIDENCE_ARTIFACT_ID)
        {
            return Err(AppError::operational(
                "raw recovery evidence without qualification is fail-closed",
            ));
        }
        let firmware = required_firmware(artifacts)?;
        validate_firmware_identity(firmware)?;
        let profile = compiled_profile_for_firmware(&firmware.sha256)?;
        let mut catalog = TargetAdapterAdmissionCatalog::new();
        catalog
            .admit_candidate(profile.clone())
            .map_err(AppError::operational)?;
        return Ok((
            profile,
            catalog,
            Vec::new(),
            vec![TargetAdapterScenario::Normal],
        ));
    }
    if found.iter().any(Option::is_none) {
        return Err(AppError::operational(
            "partial deployment qualification evidence is fail-closed",
        ));
    }
    let policy_artifact = found[0].expect("checked");
    let hil_artifact = found[1].expect("checked");
    let qualification_artifact = found[2].expect("checked");
    let snapshot_artifact = found[3].expect("checked");
    validate_identity(
        policy_artifact,
        QUALIFICATION_POLICY_ARTIFACT_ID,
        QUALIFICATION_POLICY_KIND,
        QUALIFICATION_POLICY_PATH,
    )?;
    validate_identity(
        hil_artifact,
        HIL_VERIFICATION_ARTIFACT_ID,
        HIL_VERIFICATION_KIND,
        HIL_VERIFICATION_PATH,
    )?;
    validate_identity(
        qualification_artifact,
        crate::controller::TARGET_ADAPTER_QUALIFICATION_ARTIFACT_ID,
        crate::controller::TARGET_ADAPTER_QUALIFICATION_KIND,
        QUALIFICATION_PATH,
    )?;
    validate_identity(
        snapshot_artifact,
        ADMISSION_SNAPSHOT_ARTIFACT_ID,
        ADMISSION_SNAPSHOT_KIND,
        ADMISSION_SNAPSHOT_PATH,
    )?;
    if !policy_artifact.input_artifact_ids.is_empty() || !hil_artifact.input_artifact_ids.is_empty()
    {
        return Err(AppError::operational(
            "qualification evidence has non-canonical input provenance",
        ));
    }
    let policy_bytes = read_artifact(session, policy_artifact, MAX_POLICY_BYTES)?;
    let hil_bytes = read_artifact(
        session,
        hil_artifact,
        t32perf_trace32::MAX_HIL_VERIFICATION_RECEIPT_BYTES as u64,
    )?;
    let qualification_bytes =
        read_artifact(session, qualification_artifact, MAX_QUALIFICATION_BYTES)?;
    let snapshot_bytes = read_artifact(session, snapshot_artifact, MAX_ADMISSION_BYTES)?;
    let policy =
        parse_target_adapter_qualification_policy(&policy_bytes).map_err(AppError::operational)?;
    let hil = parse_hil_verification_receipt(&hil_bytes).map_err(AppError::operational)?;
    let qualification = parse_target_adapter_qualification_receipt(&qualification_bytes)
        .map_err(AppError::operational)?;
    let snapshot =
        parse_target_adapter_admission_snapshot(&snapshot_bytes).map_err(AppError::operational)?;
    let candidate = compiled_profile_for_receipt(&qualification)?;
    let firmware = required_firmware(artifacts)?;
    validate_firmware_identity(firmware)?;
    if firmware.sha256 != candidate.firmware_elf_sha256 {
        return Err(AppError::operational(
            "registered firmware ELF does not match the receipt-selected adapter/profile",
        ));
    }
    let recovery_artifact = artifacts
        .iter()
        .find(|artifact| artifact.id == HIL_RECOVERY_EVIDENCE_ARTIFACT_ID);
    let recovery_required = hil.recovery_evidence.is_some();
    if recovery_required != recovery_artifact.is_some() {
        return Err(AppError::operational(
            "recovery HIL evidence and its raw recovery artifact must be present together",
        ));
    }
    if let (Some(binding), Some(artifact)) = (&hil.recovery_evidence, recovery_artifact) {
        validate_identity(
            artifact,
            HIL_RECOVERY_EVIDENCE_ARTIFACT_ID,
            HIL_RECOVERY_EVIDENCE_KIND,
            HIL_RECOVERY_EVIDENCE_PATH,
        )?;
        if !artifact.input_artifact_ids.is_empty() {
            return Err(AppError::operational(
                "recovery-evidence artifact has non-canonical input provenance",
            ));
        }
        let bytes = read_artifact(session, artifact, MAX_RECOVERY_EVIDENCE_BYTES)?;
        let document: TargetAdapterRecoveryEvidence =
            t32perf_model::strict_json::from_slice(&bytes).map_err(AppError::operational)?;
        document.validate().map_err(AppError::operational)?;
        if digest(&bytes) != binding.sha256 || document != binding.document {
            return Err(AppError::operational(
                "recovery-evidence artifact does not exactly match its HIL binding",
            ));
        }
    }
    let mut expected_qualification_inputs = vec![
        QUALIFICATION_POLICY_ARTIFACT_ID.to_owned(),
        HIL_VERIFICATION_ARTIFACT_ID.to_owned(),
    ];
    if recovery_required {
        expected_qualification_inputs.push(HIL_RECOVERY_EVIDENCE_ARTIFACT_ID.to_owned());
    }
    if qualification_artifact.input_artifact_ids != expected_qualification_inputs {
        return Err(AppError::operational(
            "qualification receipt has non-canonical input provenance",
        ));
    }
    let mut expected_snapshot_inputs = vec![
        QUALIFICATION_POLICY_ARTIFACT_ID.to_owned(),
        HIL_VERIFICATION_ARTIFACT_ID.to_owned(),
        crate::controller::TARGET_ADAPTER_QUALIFICATION_ARTIFACT_ID.to_owned(),
        firmware.id.clone(),
    ];
    if recovery_required {
        expected_snapshot_inputs.push(HIL_RECOVERY_EVIDENCE_ARTIFACT_ID.to_owned());
    }
    if snapshot_artifact.input_artifact_ids != expected_snapshot_inputs {
        return Err(AppError::operational(
            "admission snapshot has non-canonical input provenance",
        ));
    }
    validate_target_adapter_qualification(
        &policy,
        &candidate,
        &qualification_bytes,
        &qualification,
        &hil_bytes,
        &hil,
    )
    .map_err(AppError::operational)?;
    if snapshot
        != admission_snapshot(
            &policy,
            &candidate,
            &policy_bytes,
            &hil_bytes,
            &qualification_bytes,
        )?
    {
        return Err(AppError::operational(
            "admission snapshot does not exactly reconstruct from qualification evidence",
        ));
    }
    let mut profile = candidate.clone();
    profile.qualification_sha256 = Some(digest(&qualification_bytes));
    let mut catalog = TargetAdapterAdmissionCatalog::new();
    catalog
        .admit_qualified(profile.clone(), &qualification_bytes)
        .map_err(AppError::operational)?;
    let mut provenance = vec![
        policy_artifact.clone(),
        hil_artifact.clone(),
        qualification_artifact.clone(),
        snapshot_artifact.clone(),
    ];
    if let Some(artifact) = recovery_artifact {
        provenance.push(artifact.clone());
    }
    Ok((profile, catalog, provenance, snapshot.allowed_scenarios))
}

fn required_firmware(artifacts: &[Artifact]) -> Result<&Artifact, AppError> {
    let artifact = artifacts
        .iter()
        .find(|artifact| artifact.id == "firmware-elf")
        .ok_or_else(|| AppError::operational("registered firmware-elf artifact is absent"))?;
    validate_firmware_artifact_envelope(artifact)?;
    Ok(artifact)
}

pub(crate) fn validate_firmware_artifact_envelope(artifact: &Artifact) -> Result<(), AppError> {
    if artifact.id != FIRMWARE_ELF_ARTIFACT_ID
        || artifact.kind != FIRMWARE_ELF_ARTIFACT_KIND
        || artifact.relative_path.as_str() != FIRMWARE_ELF_ARTIFACT_PATH
        || artifact.media_type != "application/x-elf"
        || artifact.producer != FIRMWARE_ELF_ARTIFACT_PRODUCER
        || !artifact.input_artifact_ids.is_empty()
    {
        return Err(AppError::operational(
            "registered firmware-elf artifact has invalid identity",
        ));
    }
    Ok(())
}

fn validate_firmware_identity(artifact: &Artifact) -> Result<(), AppError> {
    validate_firmware_artifact_envelope(artifact)?;
    let _ = compiled_profile_for_firmware(&artifact.sha256)?;
    Ok(())
}

fn admission_snapshot(
    policy: &t32perf_trace32::TargetAdapterQualificationPolicy,
    candidate: &TargetAdapterProfile,
    policy_bytes: &[u8],
    hil_bytes: &[u8],
    qualification_bytes: &[u8],
) -> Result<TargetAdapterAdmissionSnapshot, AppError> {
    let mut qualified = candidate.clone();
    qualified.qualification_sha256 = Some(digest(qualification_bytes));
    Ok(TargetAdapterAdmissionSnapshot {
        schema: TargetAdapterAdmissionSnapshotSchemaVersion::V1,
        policy_id: policy.policy_id.clone(),
        policy_sha256: digest(policy_bytes),
        hil_verification_receipt_sha256: digest(hil_bytes),
        qualification_receipt_sha256: digest(qualification_bytes),
        candidate_profile_sha256: candidate
            .qualification_identity_digest()
            .map_err(AppError::operational)?,
        qualified_profile_sha256: qualified.digest().map_err(AppError::operational)?,
        implementation_sha256: candidate.implementation_sha256.clone(),
        firmware_elf_sha256: candidate.firmware_elf_sha256.clone(),
        t32mcp_version: policy.t32mcp_version.clone(),
        allowed_scenarios: policy.allowed_scenarios.clone(),
    })
}

struct QualificationArtifact<'a> {
    id: &'a str,
    kind: &'a str,
    path: &'a str,
    bytes: &'a [u8],
    inputs: Vec<String>,
}

impl<'a> QualificationArtifact<'a> {
    fn new(
        id: &'a str,
        kind: &'a str,
        path: &'a str,
        bytes: &'a [u8],
        inputs: Vec<String>,
    ) -> Self {
        Self {
            id,
            kind,
            path,
            bytes,
            inputs,
        }
    }
}

fn ensure_or_ingest(
    session: &Session,
    lock: &SessionLock,
    entry: QualificationArtifact<'_>,
) -> Result<Artifact, AppError> {
    let spec = ArtifactSpec {
        id: entry.id.to_owned(),
        kind: entry.kind.to_owned(),
        relative_path: ArtifactPath::new(entry.path).map_err(AppError::operational)?,
        media_type: "application/json".to_owned(),
        producer: DEPLOYMENT_PRODUCER.to_owned(),
        input_artifact_ids: entry.inputs,
    };
    let artifacts = session
        .registered_artifacts(true)
        .map_err(AppError::operational)?;
    if let Some(existing) = artifacts.iter().find(|artifact| artifact.id == entry.id) {
        session
            .verify_artifact(existing, true)
            .map_err(AppError::operational)?;
        if existing.kind != entry.kind
            || existing.relative_path != spec.relative_path
            || existing.media_type != spec.media_type
            || existing.producer != spec.producer
            || existing.input_artifact_ids != spec.input_artifact_ids
            || existing.sha256 != digest(entry.bytes)
        {
            return Err(AppError::operational(format!(
                "immutable qualification artifact `{}` conflicts with this admission",
                entry.id
            )));
        }
        return Ok(existing.clone());
    }
    let staged = ArtifactPath::new(format!("qualification/{}.json", entry.id))
        .map_err(AppError::operational)?;
    let maximum = u64::try_from(entry.bytes.len()).unwrap_or(u64::MAX);
    session
        .ensure_staged_exact(lock, &staged, entry.bytes, maximum)
        .map_err(AppError::operational)?;
    session
        .ingest_staged_bounded(lock, &staged, spec, maximum)
        .map_err(AppError::operational)
}

fn read_trusted_policy(root: &ArtifactRoot, policy_id: &str) -> Result<Vec<u8>, AppError> {
    if !is_portable_artifact_id(policy_id) {
        return Err(AppError::operational(
            "policy ID is not a portable identifier",
        ));
    }
    let control = root.path().join(".t32perf-control");
    let deployment = control.join("deployment");
    let policies = deployment.join("target-adapter-policies");
    ensure_plain_directory(&control)?;
    ensure_plain_directory(&deployment)?;
    let trust_bytes = read_plain_bounded(
        &deployment.join("target-adapter-qualification-trust-store.json"),
        u64::try_from(MAX_TARGET_ADAPTER_QUALIFICATION_TRUST_STORE_BYTES).unwrap_or(u64::MAX),
    )?;
    ensure_plain_directory(&control)?;
    ensure_plain_directory(&deployment)?;
    let trust = parse_target_adapter_qualification_trust_store(&trust_bytes)
        .map_err(AppError::operational)?;
    let expected = trust.policy_sha256(policy_id).ok_or_else(|| {
        AppError::operational("qualification trust store has no entry for policy ID")
    })?;
    ensure_plain_directory(&policies)?;
    let bytes = read_plain_bounded(
        &policies.join(format!("{policy_id}.json")),
        MAX_POLICY_BYTES,
    )?;
    ensure_plain_directory(&control)?;
    ensure_plain_directory(&deployment)?;
    ensure_plain_directory(&policies)?;
    if digest(&bytes) != *expected {
        return Err(AppError::operational(
            "trusted policy raw SHA-256 does not match trust store",
        ));
    }
    Ok(bytes)
}

fn ensure_plain_directory(path: &Path) -> Result<(), AppError> {
    let metadata = fs::symlink_metadata(path).map_err(AppError::operational)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(AppError::operational(
            "trusted deployment path component is not a plain directory",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(AppError::operational(
                "trusted deployment path component must not be a reparse point",
            ));
        }
    }
    Ok(())
}

fn read_plain_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, AppError> {
    let metadata = fs::symlink_metadata(path).map_err(AppError::operational)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > limit
    {
        return Err(AppError::operational(
            "trusted deployment file is not a bounded plain file",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(AppError::operational(
                "trusted deployment file must not be a reparse point",
            ));
        }
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options.open(path).map_err(AppError::operational)?;
    validate_opened_plain_file(path, &metadata, &file, limit)?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.read_to_end(&mut bytes)
        .map_err(AppError::operational)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(AppError::operational(
            "trusted deployment file exceeds its fixed limit",
        ));
    }
    validate_opened_plain_file(path, &metadata, &file, limit)?;
    Ok(bytes)
}

#[cfg_attr(not(unix), allow(unused_variables))]
fn validate_opened_plain_file(
    path: &Path,
    before: &fs::Metadata,
    file: &File,
    limit: u64,
) -> Result<(), AppError> {
    let opened = file.metadata().map_err(AppError::operational)?;
    if !opened.is_file() || opened.len() > limit {
        return Err(AppError::operational(
            "trusted deployment file changed or exceeds its fixed limit",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let current = fs::symlink_metadata(path).map_err(AppError::operational)?;
        if !current.file_type().is_file()
            || current.file_type().is_symlink()
            || before.dev() != opened.dev()
            || before.ino() != opened.ino()
            || current.dev() != opened.dev()
            || current.ino() != opened.ino()
        {
            return Err(AppError::operational(
                "trusted deployment file changed while it was opened",
            ));
        }
    }
    #[cfg(windows)]
    verify_opened_plain_file_identity(path, file).map_err(AppError::operational)?;
    Ok(())
}
fn read_artifact(session: &Session, artifact: &Artifact, limit: u64) -> Result<Vec<u8>, AppError> {
    if artifact.size_bytes > limit {
        return Err(AppError::operational(
            "qualification artifact exceeds its fixed limit",
        ));
    }
    let mut file = session
        .open_artifact(artifact)
        .map_err(AppError::operational)?;
    let mut bytes = Vec::with_capacity(usize::try_from(artifact.size_bytes).unwrap_or(0));
    file.read_to_end(&mut bytes)
        .map_err(AppError::operational)?;
    let actual_size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual_size > limit || actual_size != artifact.size_bytes {
        return Err(AppError::operational(
            "qualification artifact changed while it was read or exceeds its fixed limit",
        ));
    }
    if digest(&bytes) != artifact.sha256 {
        return Err(AppError::operational(
            "qualification artifact raw SHA-256 does not match its immutable catalog",
        ));
    }
    Ok(bytes)
}
fn validate_identity(
    artifact: &Artifact,
    id: &str,
    kind: &str,
    path: &str,
) -> Result<(), AppError> {
    if artifact.id != id
        || artifact.kind != kind
        || artifact.relative_path.as_str() != path
        || artifact.media_type != "application/json"
        || artifact.producer != DEPLOYMENT_PRODUCER
    {
        return Err(AppError::operational(
            "qualification artifact identity/provenance is invalid",
        ));
    }
    Ok(())
}
fn canonical_json<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, AppError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(AppError::operational)?;
    bytes.push(b'\n');
    Ok(bytes)
}
fn digest(bytes: &[u8]) -> Sha256Digest {
    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("String write cannot fail");
    }
    Sha256Digest::new(encoded).expect("SHA-256 is canonical")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use t32perf_model::ArtifactPath;
    use t32perf_session::{ArtifactRoot, SessionLimits};
    use tempfile::tempdir;

    use super::{
        QUALIFICATION_POLICY_ARTIFACT_ID, QUALIFICATION_POLICY_KIND, QUALIFICATION_POLICY_PATH,
        QualificationArtifact, compiled_candidate_admission_catalog, compiled_profile_for_firmware,
        compiled_profile_for_firmware_in, compiled_target_adapter_profiles,
        compiled_target_adapter_profiles_from_catalog, digest, ensure_or_ingest,
        read_trusted_policy, with_test_compiled_target_adapter_profiles,
    };
    use t32perf_trace32::TargetAdapterBundleDescriptor;

    fn root() -> (tempfile::TempDir, ArtifactRoot) {
        let directory = tempdir().expect("temporary root");
        let root = ArtifactRoot::open(directory.path(), SessionLimits::default()).expect("root");
        (directory, root)
    }

    #[test]
    fn trust_store_missing_is_deny_all() {
        let (_directory, root) = root();
        assert!(read_trusted_policy(&root, "policy-a").is_err());
    }

    #[test]
    fn trust_store_rejects_unknown_and_traversal_ids() {
        let (_directory, root) = root();
        let deployment = root.path().join(".t32perf-control/deployment");
        fs::create_dir_all(&deployment).expect("deployment directory");
        fs::write(
            deployment.join("target-adapter-qualification-trust-store.json"),
            r#"{"schema":"t32perf.target-adapter-qualification-trust-store/v1","entries":[{"policy_id":"policy-a","policy_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}"#,
        ).expect("trust store");
        assert!(read_trusted_policy(&root, "unknown").is_err());
        assert!(read_trusted_policy(&root, "../policy-a").is_err());
    }

    #[test]
    fn trust_store_rejects_policy_sha_mismatch() {
        let (_directory, root) = root();
        let deployment = root.path().join(".t32perf-control/deployment");
        let policies = deployment.join("target-adapter-policies");
        fs::create_dir_all(&policies).expect("policy directory");
        fs::write(policies.join("policy-a.json"), b"not-the-authorized-policy").expect("policy");
        fs::write(
            deployment.join("target-adapter-qualification-trust-store.json"),
            r#"{"schema":"t32perf.target-adapter-qualification-trust-store/v1","entries":[{"policy_id":"policy-a","policy_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}"#,
        ).expect("trust store");
        assert!(read_trusted_policy(&root, "policy-a").is_err());
    }

    #[test]
    fn trust_store_accepts_only_hash_anchored_bytes() {
        let (_directory, root) = root();
        let deployment = root.path().join(".t32perf-control/deployment");
        let policies = deployment.join("target-adapter-policies");
        fs::create_dir_all(&policies).expect("policy directory");
        let bytes = b"policy bytes";
        fs::write(policies.join("policy-a.json"), bytes).expect("policy");
        fs::write(
            deployment.join("target-adapter-qualification-trust-store.json"),
            format!(r#"{{"schema":"t32perf.target-adapter-qualification-trust-store/v1","entries":[{{"policy_id":"policy-a","policy_sha256":"{}"}}]}}"#, digest(bytes)),
        ).expect("trust store");
        assert_eq!(
            read_trusted_policy(&root, "policy-a").expect("trusted bytes"),
            bytes
        );
    }

    #[test]
    fn truncated_host_staging_is_never_overwritten_during_retry() {
        let (_directory, root) = root();
        let session = root.create_session(&serde_json::json!({})).unwrap();
        let lock = session.try_lock().unwrap();
        let staged = ArtifactPath::new(format!(
            "qualification/{QUALIFICATION_POLICY_ARTIFACT_ID}.json"
        ))
        .unwrap();
        let path = session.prepare_staging_path(&lock, &staged).unwrap();
        fs::write(&path, b"truncated").unwrap();

        assert!(
            ensure_or_ingest(
                &session,
                &lock,
                QualificationArtifact::new(
                    QUALIFICATION_POLICY_ARTIFACT_ID,
                    QUALIFICATION_POLICY_KIND,
                    QUALIFICATION_POLICY_PATH,
                    br#"{"policy":"authoritative"}"#,
                    Vec::new(),
                ),
            )
            .is_err()
        );
        assert_eq!(fs::read(path).unwrap(), b"truncated");
    }

    #[test]
    fn compiled_registry_is_the_single_firmware_admission_seam() {
        let profiles = compiled_target_adapter_profiles();
        assert_eq!(profiles.len(), 1);
        let profile = profiles[0].clone();
        assert_eq!(profile, profiles[0]);
        assert_eq!(
            compiled_profile_for_firmware(&profile.firmware_elf_sha256).unwrap(),
            profile
        );
        assert!(
            compiled_profile_for_firmware(
                &t32perf_model::Sha256Digest::new("0".repeat(64)).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn fixture_catalog_rejects_ambiguous_firmware_admission() {
        let profile = compiled_target_adapter_profiles()[0].clone();
        let mut second = profile.clone();
        second.adapter_id = "fixture-second-adapter".to_owned();
        second.implementation_sha256 = t32perf_model::Sha256Digest::new("0".repeat(64)).unwrap();
        let profiles = compiled_target_adapter_profiles_from_catalog(vec![
            TargetAdapterBundleDescriptor {
                bundle_relative_directory: "scripts/adapters/tc234l-build190766",
                candidate_profile: profile.clone(),
            },
            TargetAdapterBundleDescriptor {
                bundle_relative_directory: "scripts/adapters/fixture-second",
                candidate_profile: second,
            },
        ])
        .unwrap();
        assert!(compiled_profile_for_firmware_in(&profiles, &profile.firmware_elf_sha256).is_err());
        with_test_compiled_target_adapter_profiles(profiles.clone(), || {
            assert!(compiled_profile_for_firmware(&profile.firmware_elf_sha256).is_err());
        });
    }

    #[test]
    fn endpoint_candidate_catalog_contains_every_profile_with_a_stable_digest() {
        let first = compiled_target_adapter_profiles()[0].clone();
        let mut second = first.clone();
        second.adapter_id = "fixture-second-adapter".to_owned();
        second.implementation_sha256 = t32perf_model::Sha256Digest::new("0".repeat(64)).unwrap();

        let forward =
            with_test_compiled_target_adapter_profiles(vec![first.clone(), second.clone()], || {
                let catalog = compiled_candidate_admission_catalog().unwrap();
                assert!(catalog.get(&first.adapter_id).is_some());
                assert!(catalog.get(&second.adapter_id).is_some());
                catalog.digest().unwrap()
            });
        let reverse = with_test_compiled_target_adapter_profiles(vec![second, first], || {
            compiled_candidate_admission_catalog()
                .unwrap()
                .digest()
                .unwrap()
        });
        assert_eq!(forward, reverse);
    }
}
