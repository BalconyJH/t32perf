//! Durable root-wide quarantine and typed recovery for interrupted target control.
//!
//! Active records live outside failed Sessions. Recovery validates strict
//! harness evidence, preserves the failed Session as terminal, and moves the
//! active record into immutable recovery history instead of deleting it.

use std::{
    fs::{self, File},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

use atomic_write_file::AtomicWriteFile;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use t32perf_model::{Artifact, Sha256Digest, strict_json};
use t32perf_session::{ArtifactRoot, SessionId};
use t32perf_trace32::{
    ControllerAbortReason, ControllerAbortRequest, ControllerTargetAdapterBinding, PerfOperation,
    TargetAdapterFailureKind, TargetAdapterRecoveryEvidence, TargetAdapterScenario,
};
use uuid::Uuid;

use crate::{
    app::{AppError, CommandOutcome, EXIT_OPERATIONAL, EXIT_SUCCESS},
    controller::{
        ControllerRequestEnvelope, QuarantinedTargetRecoveryClaims, admitted_profile_for_binding,
    },
};

const CONTROL_DIRECTORY: &str = ".t32perf-control";
const CONTROLLER_DIRECTORY: &str = "controller";
const QUARANTINE_DIRECTORY: &str = "quarantine";
const RECOVERY_STAGING_DIRECTORY: &str = "recovery-staging";
const RECOVERY_HISTORY_DIRECTORY: &str = "recovery-history";
const RECOVERY_EVIDENCE_FILE: &str = "target-adapter-recovery-evidence.json";
const RESERVATION_FILE: &str = "reservation.json";
const HISTORY_EVIDENCE_FILE: &str = "evidence.json";
const HISTORY_QUARANTINE_FILE: &str = "quarantine.json";
const HISTORY_RECEIPT_FILE: &str = "receipt.json";
const QUARANTINE_SCHEMA: &str = "t32perf.controller-target-quarantine/v1";
const RESERVATION_SCHEMA: &str = "t32perf.controller-recovery-reservation/v1";
const RECOVERY_RECEIPT_SCHEMA: &str = "t32perf.controller-recovery-receipt/v1";
const MAX_RECOVERY_BYTES: u64 = 64 * 1024;
const MAX_ACTIVE_QUARANTINES: usize = 128;
const ROOT_ENDPOINT_SCOPE: &str = "artifact_root_single_tenant";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RecoveryScopeArgument {
    Endpoint,
    Target,
}

impl RecoveryScopeArgument {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Endpoint => "endpoint",
            Self::Target => "target",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum QuarantineKey {
    Endpoint {
        endpoint_scope: String,
    },
    Target {
        adapter_id: String,
        adapter_version: String,
        trace32_release: String,
        trace32_build: u64,
        architecture_package: String,
        target_identifier: String,
        profile_sha256: Sha256Digest,
        implementation_sha256: Sha256Digest,
        probe_identifier: String,
    },
}

impl QuarantineKey {
    fn scope(&self) -> RecoveryScopeArgument {
        match self {
            Self::Endpoint { .. } => RecoveryScopeArgument::Endpoint,
            Self::Target { .. } => RecoveryScopeArgument::Target,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuarantineRecord {
    schema: String,
    quarantine_id: String,
    key_id: String,
    key: QuarantineKey,
    failed_session_id: String,
    failed_session_operation_id: String,
    failed_transaction_id: String,
    failed_operation: PerfOperation,
    abort_reason: ControllerAbortReason,
    adapter_catalog_sha256: Sha256Digest,
    binding_sha256: Sha256Digest,
    request_artifact_id: String,
    request_artifact_sha256: Sha256Digest,
    abort_request_artifact_id: String,
    abort_request_artifact_sha256: Sha256Digest,
    abort_receipt_artifact_id: String,
    abort_receipt_artifact_sha256: Sha256Digest,
    target_adapter: Option<ControllerTargetAdapterBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryReservation {
    schema: String,
    reservation_id: String,
    quarantine_id: String,
    key_id: String,
    scope: RecoveryScopeArgument,
    quarantine_record_sha256: Sha256Digest,
    evidence_filename: String,
    max_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryHistoryReceipt {
    schema: String,
    receipt_id: String,
    quarantine_id: String,
    key_id: String,
    reservation_id: String,
    scope: RecoveryScopeArgument,
    failed_session_id: String,
    failed_transaction_id: String,
    quarantine_record_sha256: Sha256Digest,
    evidence_sha256: Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    linked_quarantine_id: Option<String>,
    files_deleted: bool,
    new_session_required: bool,
}

struct LoadedQuarantine {
    record: QuarantineRecord,
    bytes: Vec<u8>,
}

struct ConfirmedAbortClaims<'a> {
    request: &'a ControllerRequestEnvelope,
    request_artifact: &'a Artifact,
    abort: &'a ControllerAbortRequest,
    abort_request_artifact: &'a Artifact,
    abort_receipt_artifact: &'a Artifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointRecoveryEvidence {
    schema: String,
    adapter_catalog_sha256: Sha256Digest,
    binding_sha256: Sha256Digest,
    failed_operation: PerfOperation,
    upstream_abort_confirmed: bool,
    upstream_abort_receipt_sha256: Sha256Digest,
    adapter_mutation: bool,
    files_deleted: bool,
    new_session_required: bool,
}

/// Adds durable endpoint and, when selected, exact adapter/profile/probe quarantine.
///
/// The caller invokes this only after the immutable abort receipt exists and
/// has been validated against the immutable request and abort plan.
pub(crate) fn quarantine_confirmed_abort(
    root: &ArtifactRoot,
    request: &ControllerRequestEnvelope,
    request_artifact: &Artifact,
    abort: &ControllerAbortRequest,
    abort_request_artifact: &Artifact,
    abort_receipt_artifact: &Artifact,
) -> Result<(), AppError> {
    let claims = ConfirmedAbortClaims {
        request,
        request_artifact,
        abort,
        abort_request_artifact,
        abort_receipt_artifact,
    };
    validate_failure_claims(&claims)?;

    create_or_verify_quarantine(
        root,
        &claims,
        QuarantineKey::Endpoint {
            endpoint_scope: ROOT_ENDPOINT_SCOPE.to_owned(),
        },
    )?;

    if request.operation() != PerfOperation::GetHotspots
        && let Some(binding) = request.target_adapter()
    {
        create_or_verify_quarantine(root, &claims, target_key(binding)?)?;
    }
    Ok(())
}

/// Refuses a new request while the root endpoint or selected target is unsafe.
///
/// The endpoint key deliberately excludes the catalog digest. Otherwise a
/// software/catalog upgrade could bypass an unrecovered physical endpoint.
pub(crate) fn ensure_not_quarantined(
    root: &ArtifactRoot,
    requested_catalog_sha256: &Sha256Digest,
    binding: Option<&ControllerTargetAdapterBinding>,
) -> Result<(), AppError> {
    ensure_key_clear(
        root,
        &QuarantineKey::Endpoint {
            endpoint_scope: ROOT_ENDPOINT_SCOPE.to_owned(),
        },
        requested_catalog_sha256,
    )?;
    if let Some(binding) = binding {
        ensure_key_clear(root, &target_key(binding)?, requested_catalog_sha256)?;
    }
    Ok(())
}

/// Returns whether a confirmed abort has a durable endpoint quarantine record.
///
/// Callers must additionally require that the failed Session is terminal
/// before treating an abort receipt as a closed controller transaction.
pub(crate) fn has_durable_abort_quarantine(
    root: &ArtifactRoot,
    session_id: &str,
    transaction_id: &str,
) -> Result<bool, AppError> {
    if list_active_quarantines(root)?.into_iter().any(|loaded| {
        matches!(loaded.record.key, QuarantineKey::Endpoint { .. })
            && loaded.record.failed_session_id == session_id
            && loaded.record.failed_transaction_id == transaction_id
    }) {
        return Ok(true);
    }
    let history = recovery_history_directory(root)?;
    for entry in fs::read_dir(history).map_err(AppError::operational)? {
        let directory = entry.map_err(AppError::operational)?.path();
        ensure_plain_directory(&directory)?;
        let quarantine_path = directory.join(HISTORY_QUARANTINE_FILE);
        let receipt_path = directory.join(HISTORY_RECEIPT_FILE);
        if !filesystem_entry_exists(&quarantine_path)? || !filesystem_entry_exists(&receipt_path)? {
            continue;
        }
        let loaded = read_quarantine(&quarantine_path)?;
        if !matches!(loaded.record.key, QuarantineKey::Endpoint { .. })
            || loaded.record.failed_session_id != session_id
            || loaded.record.failed_transaction_id != transaction_id
        {
            continue;
        }
        let receipt: RecoveryHistoryReceipt = read_strict_json(&receipt_path, MAX_RECOVERY_BYTES)?;
        if receipt.schema == RECOVERY_RECEIPT_SCHEMA
            && receipt.quarantine_id == loaded.record.quarantine_id
            && receipt.key_id == loaded.record.key_id
            && receipt.failed_session_id == session_id
            && receipt.failed_transaction_id == transaction_id
            && receipt.quarantine_record_sha256 == digest_bytes(&loaded.bytes)
            && !receipt.files_deleted
            && receipt.new_session_required
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn prepare_recovery(
    root: &ArtifactRoot,
    failed_session_id: &str,
    transaction_id: &str,
    scope: RecoveryScopeArgument,
) -> Result<CommandOutcome, AppError> {
    SessionId::new(failed_session_id.to_owned()).map_err(AppError::operational)?;
    validate_identifier(transaction_id, "controller transaction")?;
    let _namespace = root.try_namespace_lock().map_err(AppError::operational)?;
    let loaded = find_active_quarantine(root, failed_session_id, transaction_id, scope)?;

    let reservation_id = new_identifier();
    let staging_root = recovery_staging_directory(root)?;
    let staging = staging_root.join(&reservation_id);
    fs::create_dir(&staging).map_err(AppError::operational)?;
    ensure_plain_directory(&staging)?;
    sync_control_directory(&staging_root)?;
    let reservation = RecoveryReservation {
        schema: RESERVATION_SCHEMA.to_owned(),
        reservation_id: reservation_id.clone(),
        quarantine_id: loaded.record.quarantine_id.clone(),
        key_id: loaded.record.key_id.clone(),
        scope,
        quarantine_record_sha256: digest_bytes(&loaded.bytes),
        evidence_filename: RECOVERY_EVIDENCE_FILE.to_owned(),
        max_bytes: MAX_RECOVERY_BYTES,
    };
    write_new_json(&staging.join(RESERVATION_FILE), &reservation)?;
    let evidence_path = staging.join(RECOVERY_EVIDENCE_FILE);

    success(
        "controller.recover.prepare",
        json!({
            "failed_session_id": failed_session_id,
            "failed_transaction_id": transaction_id,
            "quarantine_id": loaded.record.quarantine_id,
            "scope": scope.as_str(),
            "reservation_id": reservation_id,
            "evidence_handoff_path": evidence_path,
            "max_evidence_bytes": MAX_RECOVERY_BYTES,
            "evidence_expectation": recovery_expectation(root, &loaded.record, scope)?,
        }),
    )
}

/// Validates recovery identifiers before app acquires a performance-run lease.
/// `prepare_recovery` repeats this check before it mutates control state.
pub(crate) fn preflight_prepare_recovery(
    failed_session_id: &str,
    transaction_id: &str,
) -> Result<(), AppError> {
    SessionId::new(failed_session_id.to_owned()).map_err(AppError::operational)?;
    validate_identifier(transaction_id, "controller transaction")
}

/// Validates a recovery reservation identifier without inspecting control files.
pub(crate) fn preflight_accept_recovery(reservation_id: &str) -> Result<(), AppError> {
    validate_identifier(reservation_id, "controller recovery reservation")
}

pub(crate) fn accept_recovery(
    root: &ArtifactRoot,
    reservation_id: &str,
) -> Result<CommandOutcome, AppError> {
    validate_identifier(reservation_id, "controller recovery reservation")?;
    let _namespace = root.try_namespace_lock().map_err(AppError::operational)?;
    let staging = recovery_staging_directory(root)?.join(reservation_id);
    ensure_plain_directory(&staging)?;
    let reservation: RecoveryReservation =
        read_strict_json(&staging.join(RESERVATION_FILE), MAX_RECOVERY_BYTES)?;
    validate_reservation(&reservation, reservation_id)?;

    let active_path = quarantine_directory(root)?.join(format!("{}.json", reservation.key_id));
    let history_directory = recovery_history_directory(root)?.join(&reservation.quarantine_id);
    ensure_or_create_directory(&history_directory)?;
    let moved_path = history_directory.join(HISTORY_QUARANTINE_FILE);
    let evidence_history_path = history_directory.join(HISTORY_EVIDENCE_FILE);
    let receipt_path = history_directory.join(HISTORY_RECEIPT_FILE);

    let active_exists = filesystem_entry_exists(&active_path)?;
    let moved_exists = filesystem_entry_exists(&moved_path)?;
    if active_exists && moved_exists {
        return Err(AppError::operational(
            "controller quarantine exists in both active and recovered history",
        ));
    }
    let loaded = if active_exists {
        read_quarantine(&active_path)?
    } else if moved_exists {
        read_quarantine(&moved_path)?
    } else {
        return Err(AppError::operational(
            "controller recovery reservation no longer names a quarantine record",
        ));
    };
    validate_reserved_record(&reservation, &loaded)?;
    let linked_endpoint = if reservation.scope == RecoveryScopeArgument::Target && active_exists {
        Some(find_linked_endpoint_quarantine(root, &loaded.record)?)
    } else {
        None
    };

    let existing_receipt = if filesystem_entry_exists(&receipt_path)? {
        Some(read_strict_json::<RecoveryHistoryReceipt>(
            &receipt_path,
            MAX_RECOVERY_BYTES,
        )?)
    } else {
        None
    };
    if moved_exists && existing_receipt.is_none() {
        return Err(AppError::operational(
            "recovered quarantine is missing its recovery receipt",
        ));
    }

    let (receipt, already_recovered) = if let Some(receipt) = existing_receipt {
        let evidence_bytes = read_plain_file(&evidence_history_path, MAX_RECOVERY_BYTES)?;
        validate_history_receipt(
            &receipt,
            &reservation,
            &loaded,
            &digest_bytes(&evidence_bytes),
        )?;
        validate_recovery_evidence(root, &loaded.record, reservation.scope, &evidence_bytes)?;
        (receipt, moved_exists)
    } else {
        let evidence_path = staging.join(RECOVERY_EVIDENCE_FILE);
        let evidence_bytes = read_plain_file(&evidence_path, MAX_RECOVERY_BYTES)?;
        validate_recovery_evidence(root, &loaded.record, reservation.scope, &evidence_bytes)?;
        publish_or_verify_bytes(&evidence_history_path, &evidence_bytes)?;

        let receipt = RecoveryHistoryReceipt {
            schema: RECOVERY_RECEIPT_SCHEMA.to_owned(),
            receipt_id: new_identifier(),
            quarantine_id: loaded.record.quarantine_id.clone(),
            key_id: loaded.record.key_id.clone(),
            reservation_id: reservation_id.to_owned(),
            scope: reservation.scope,
            failed_session_id: loaded.record.failed_session_id.clone(),
            failed_transaction_id: loaded.record.failed_transaction_id.clone(),
            quarantine_record_sha256: reservation.quarantine_record_sha256.clone(),
            evidence_sha256: digest_bytes(&evidence_bytes),
            linked_quarantine_id: linked_endpoint
                .as_ref()
                .map(|endpoint| endpoint.record.quarantine_id.clone()),
            files_deleted: false,
            new_session_required: true,
        };
        write_new_json(&receipt_path, &receipt)?;
        (receipt, false)
    };

    if active_exists {
        if filesystem_entry_exists(&moved_path)? {
            return Err(AppError::operational(
                "recovered quarantine destination already exists",
            ));
        }
        fs::rename(&active_path, &moved_path).map_err(AppError::operational)?;
        sync_rename_parents(&active_path, &moved_path)?;
    }

    if reservation.scope == RecoveryScopeArgument::Target {
        complete_linked_endpoint_recovery(
            root,
            &loaded.record,
            &receipt,
            &evidence_history_path,
            linked_endpoint.as_ref(),
        )?;
    }

    success(
        "controller.recover.accept",
        json!({
            "quarantine_id": loaded.record.quarantine_id,
            "scope": reservation.scope.as_str(),
            "reservation_id": reservation_id,
            "recovery_receipt_id": receipt.receipt_id,
            "already_recovered": already_recovered,
            "failed_session_remains_terminal": true,
            "active_quarantine_moved_to_history": true,
        }),
    )
}

pub(crate) fn quarantine_status(root: &ArtifactRoot, session_id: &str) -> Result<Value, AppError> {
    let records = list_active_quarantines(root)?;
    let active = records
        .into_iter()
        .filter(|loaded| loaded.record.failed_session_id == session_id)
        .map(|loaded| {
            let record = loaded.record;
            json!({
                "quarantine_id": record.quarantine_id,
                "scope": record.key.scope().as_str(),
                "failed_transaction_id": record.failed_transaction_id,
                "failed_operation": record.failed_operation,
                "key": record.key,
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({"active_quarantine_count": active.len(), "active_quarantines": active}))
}

pub(crate) fn root_quarantine_status(root: &ArtifactRoot) -> Result<Value, AppError> {
    let active = list_active_quarantines(root)?
        .into_iter()
        .map(|loaded| {
            let record = loaded.record;
            json!({
                "quarantine_id": record.quarantine_id,
                "scope": record.key.scope().as_str(),
                "failed_session_id": record.failed_session_id,
                "failed_transaction_id": record.failed_transaction_id,
                "failed_operation": record.failed_operation,
                "key": record.key,
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({"active_quarantine_count": active.len(), "active_quarantines": active}))
}

fn validate_failure_claims(claims: &ConfirmedAbortClaims<'_>) -> Result<(), AppError> {
    let transaction = &claims.request.binding().transaction_id;
    if claims.abort.binding != *claims.request.binding()
        || claims.abort.request_artifact_id != claims.request_artifact.id
        || claims.abort.request_artifact_sha256 != claims.request_artifact.sha256
        || claims.request_artifact.id != format!("controller-request-{transaction}")
        || claims.abort_request_artifact.id != format!("controller-abort-{transaction}")
        || claims.abort_receipt_artifact.id != format!("controller-abort-receipt-{transaction}")
    {
        return Err(AppError::operational(
            "controller quarantine claims are not bound to the confirmed abort",
        ));
    }
    Ok(())
}

fn create_or_verify_quarantine(
    root: &ArtifactRoot,
    claims: &ConfirmedAbortClaims<'_>,
    key: QuarantineKey,
) -> Result<(), AppError> {
    let key_id = key_digest(&key);
    let path = quarantine_directory(root)?.join(format!("{key_id}.json"));
    if filesystem_entry_exists(&path)? {
        let existing = read_quarantine(&path)?.record;
        let expected = quarantine_record(claims, key, existing.quarantine_id.clone());
        if existing != expected {
            return Err(AppError::operational(
                "active controller quarantine conflicts with another failed request",
            ));
        }
        return Ok(());
    }
    let record = quarantine_record(claims, key, new_identifier());
    validate_quarantine_record(&record)?;
    write_new_json(&path, &record)
}

fn quarantine_record(
    claims: &ConfirmedAbortClaims<'_>,
    key: QuarantineKey,
    quarantine_id: String,
) -> QuarantineRecord {
    QuarantineRecord {
        schema: QUARANTINE_SCHEMA.to_owned(),
        quarantine_id,
        key_id: key_digest(&key),
        key,
        failed_session_id: claims.request.binding().session_id.clone(),
        failed_session_operation_id: claims.request.binding().session_operation_id.clone(),
        failed_transaction_id: claims.request.binding().transaction_id.clone(),
        failed_operation: claims.request.operation(),
        abort_reason: claims.abort.reason,
        adapter_catalog_sha256: claims.request.adapter_catalog_sha256().clone(),
        binding_sha256: claims.request.binding().binding_sha256.clone(),
        request_artifact_id: claims.request_artifact.id.clone(),
        request_artifact_sha256: claims.request_artifact.sha256.clone(),
        abort_request_artifact_id: claims.abort_request_artifact.id.clone(),
        abort_request_artifact_sha256: claims.abort_request_artifact.sha256.clone(),
        abort_receipt_artifact_id: claims.abort_receipt_artifact.id.clone(),
        abort_receipt_artifact_sha256: claims.abort_receipt_artifact.sha256.clone(),
        target_adapter: if claims.request.operation() == PerfOperation::GetHotspots {
            None
        } else {
            claims.request.target_adapter().cloned()
        },
    }
}

fn target_key(binding: &ControllerTargetAdapterBinding) -> Result<QuarantineKey, AppError> {
    if binding.adapter_id.is_empty()
        || binding.adapter_version.is_empty()
        || binding.trace32_release.is_empty()
        || binding.trace32_build == 0
        || binding.architecture_package.is_empty()
        || binding.target_identifier.is_empty()
        || binding.probe_identifier.is_empty()
    {
        return Err(AppError::operational(
            "controller quarantine target binding is incomplete",
        ));
    }
    Ok(QuarantineKey::Target {
        adapter_id: binding.adapter_id.clone(),
        adapter_version: binding.adapter_version.clone(),
        trace32_release: binding.trace32_release.clone(),
        trace32_build: binding.trace32_build,
        architecture_package: binding.architecture_package.clone(),
        target_identifier: binding.target_identifier.clone(),
        profile_sha256: binding.profile_sha256.clone(),
        implementation_sha256: binding.implementation_sha256.clone(),
        probe_identifier: binding.probe_identifier.clone(),
    })
}

fn ensure_key_clear(
    root: &ArtifactRoot,
    key: &QuarantineKey,
    requested_catalog_sha256: &Sha256Digest,
) -> Result<(), AppError> {
    let key_id = key_digest(key);
    let path = quarantine_directory(root)?.join(format!("{key_id}.json"));
    if !filesystem_entry_exists(&path)? {
        return Ok(());
    }
    let record = read_quarantine(&path)?.record;
    if record.key != *key {
        return Err(AppError::operational(
            "active controller quarantine key does not match its storage key",
        ));
    }
    Err(AppError {
        code: "TARGET_QUARANTINED",
        message:
            "TRACE32 endpoint or target is quarantined until typed recovery evidence is accepted"
                .to_owned(),
        details: json!({
            "quarantine_id": record.quarantine_id,
            "scope": key.scope().as_str(),
            "failed_session_id": record.failed_session_id,
            "failed_transaction_id": record.failed_transaction_id,
            "quarantined_adapter_catalog_sha256": record.adapter_catalog_sha256,
            "requested_adapter_catalog_sha256": requested_catalog_sha256,
        }),
        exit_code: EXIT_OPERATIONAL,
    })
}

fn find_active_quarantine(
    root: &ArtifactRoot,
    session_id: &str,
    transaction_id: &str,
    scope: RecoveryScopeArgument,
) -> Result<LoadedQuarantine, AppError> {
    let mut matches = list_active_quarantines(root)?
        .into_iter()
        .filter(|loaded| {
            loaded.record.failed_session_id == session_id
                && loaded.record.failed_transaction_id == transaction_id
                && loaded.record.key.scope() == scope
        })
        .collect::<Vec<_>>();
    match matches.len() {
        1 => Ok(matches.pop().expect("one matching quarantine")),
        0 => Err(AppError::operational(
            "no active controller quarantine matches the failed Session, transaction, and scope",
        )),
        _ => Err(AppError::operational(
            "ambiguous active controller quarantine",
        )),
    }
}

fn find_linked_endpoint_quarantine(
    root: &ArtifactRoot,
    target: &QuarantineRecord,
) -> Result<LoadedQuarantine, AppError> {
    let mut matches = list_active_quarantines(root)?
        .into_iter()
        .filter(|loaded| {
            matches!(loaded.record.key, QuarantineKey::Endpoint { .. })
                && loaded.record.failed_session_id == target.failed_session_id
                && loaded.record.failed_session_operation_id == target.failed_session_operation_id
                && loaded.record.failed_transaction_id == target.failed_transaction_id
                && loaded.record.binding_sha256 == target.binding_sha256
                && loaded.record.request_artifact_sha256 == target.request_artifact_sha256
                && loaded.record.abort_receipt_artifact_sha256
                    == target.abort_receipt_artifact_sha256
        })
        .collect::<Vec<_>>();
    match matches.len() {
        1 => Ok(matches.pop().expect("one linked endpoint quarantine")),
        0 => Err(AppError::operational(
            "target recovery has no linked active endpoint quarantine",
        )),
        _ => Err(AppError::operational(
            "target recovery has ambiguous linked endpoint quarantines",
        )),
    }
}

fn complete_linked_endpoint_recovery(
    root: &ArtifactRoot,
    target: &QuarantineRecord,
    target_receipt: &RecoveryHistoryReceipt,
    target_evidence_path: &Path,
    initial_endpoint: Option<&LoadedQuarantine>,
) -> Result<(), AppError> {
    let Some(endpoint_id) = target_receipt.linked_quarantine_id.as_deref() else {
        return Err(AppError::operational(
            "target recovery receipt does not bind its endpoint quarantine",
        ));
    };
    let discovered_endpoint = if initial_endpoint.is_none() {
        find_linked_endpoint_quarantine(root, target).ok()
    } else {
        None
    };
    let endpoint = match initial_endpoint.or(discovered_endpoint.as_ref()) {
        Some(endpoint) => {
            if endpoint.record.quarantine_id != endpoint_id {
                return Err(AppError::operational(
                    "target recovery endpoint quarantine identity changed",
                ));
            }
            endpoint
        }
        None => {
            let history = recovery_history_directory(root)?.join(endpoint_id);
            let receipt: RecoveryHistoryReceipt =
                read_strict_json(&history.join(HISTORY_RECEIPT_FILE), MAX_RECOVERY_BYTES)?;
            if receipt.linked_quarantine_id.as_deref() != Some(&target.quarantine_id)
                || receipt.scope != RecoveryScopeArgument::Target
            {
                return Err(AppError::operational(
                    "linked endpoint recovery history is not bound to target recovery",
                ));
            }
            return Ok(());
        }
    };
    let history = recovery_history_directory(root)?.join(&endpoint.record.quarantine_id);
    ensure_or_create_directory(&history)?;
    let evidence = read_plain_file(target_evidence_path, MAX_RECOVERY_BYTES)?;
    publish_or_verify_bytes(&history.join(HISTORY_EVIDENCE_FILE), &evidence)?;
    let receipt_path = history.join(HISTORY_RECEIPT_FILE);
    let receipt = RecoveryHistoryReceipt {
        schema: RECOVERY_RECEIPT_SCHEMA.to_owned(),
        receipt_id: target_receipt.receipt_id.clone(),
        quarantine_id: endpoint.record.quarantine_id.clone(),
        key_id: endpoint.record.key_id.clone(),
        reservation_id: target_receipt.reservation_id.clone(),
        scope: RecoveryScopeArgument::Target,
        failed_session_id: endpoint.record.failed_session_id.clone(),
        failed_transaction_id: endpoint.record.failed_transaction_id.clone(),
        quarantine_record_sha256: digest_bytes(&endpoint.bytes),
        evidence_sha256: digest_bytes(&evidence),
        linked_quarantine_id: Some(target.quarantine_id.clone()),
        files_deleted: false,
        new_session_required: true,
    };
    if filesystem_entry_exists(&receipt_path)? {
        let existing: RecoveryHistoryReceipt = read_strict_json(&receipt_path, MAX_RECOVERY_BYTES)?;
        if existing != receipt {
            return Err(AppError::operational(
                "linked endpoint recovery history conflicts with target receipt",
            ));
        }
    } else {
        write_new_json(&receipt_path, &receipt)?;
    }
    let active = quarantine_directory(root)?.join(format!("{}.json", endpoint.record.key_id));
    let moved = history.join(HISTORY_QUARANTINE_FILE);
    if filesystem_entry_exists(&active)? {
        fs::rename(&active, &moved).map_err(AppError::operational)?;
        sync_rename_parents(&active, &moved)?;
    } else if !filesystem_entry_exists(&moved)? {
        return Err(AppError::operational(
            "linked endpoint quarantine disappeared during target recovery",
        ));
    }
    Ok(())
}

fn list_active_quarantines(root: &ArtifactRoot) -> Result<Vec<LoadedQuarantine>, AppError> {
    let directory = quarantine_directory(root)?;
    let mut records = Vec::new();
    for entry in fs::read_dir(&directory).map_err(AppError::operational)? {
        if records.len() >= MAX_ACTIVE_QUARANTINES {
            return Err(AppError::operational(
                "controller active-quarantine record limit exceeded",
            ));
        }
        let entry = entry.map_err(AppError::operational)?;
        let path = entry.path();
        let filename = entry.file_name();
        let filename = filename
            .to_str()
            .ok_or_else(|| AppError::operational("controller quarantine filename is not UTF-8"))?;
        let Some(key_id) = filename.strip_suffix(".json") else {
            return Err(AppError::operational(
                "controller quarantine directory contains an unexpected entry",
            ));
        };
        validate_sha256_text(key_id, "controller quarantine key")?;
        let loaded = read_quarantine(&path)?;
        if loaded.record.key_id != key_id {
            return Err(AppError::operational(
                "controller quarantine filename does not match its key",
            ));
        }
        records.push(loaded);
    }
    Ok(records)
}

fn read_quarantine(path: &Path) -> Result<LoadedQuarantine, AppError> {
    let bytes = read_plain_file(path, MAX_RECOVERY_BYTES)?;
    let record: QuarantineRecord =
        strict_json::from_slice(&bytes).map_err(AppError::operational)?;
    validate_quarantine_record(&record)?;
    Ok(LoadedQuarantine { record, bytes })
}

fn validate_quarantine_record(record: &QuarantineRecord) -> Result<(), AppError> {
    if record.schema != QUARANTINE_SCHEMA {
        return Err(AppError::operational(
            "unsupported controller quarantine schema",
        ));
    }
    validate_identifier(&record.quarantine_id, "controller quarantine")?;
    validate_sha256_text(&record.key_id, "controller quarantine key")?;
    if record.key_id != key_digest(&record.key) {
        return Err(AppError::operational(
            "controller quarantine key digest is invalid",
        ));
    }
    SessionId::new(record.failed_session_id.clone()).map_err(AppError::operational)?;
    validate_identifier(
        &record.failed_session_operation_id,
        "failed Session operation",
    )?;
    validate_identifier(
        &record.failed_transaction_id,
        "failed controller transaction",
    )?;
    if record.request_artifact_id != format!("controller-request-{}", record.failed_transaction_id)
        || record.abort_request_artifact_id
            != format!("controller-abort-{}", record.failed_transaction_id)
        || record.abort_receipt_artifact_id
            != format!("controller-abort-receipt-{}", record.failed_transaction_id)
    {
        return Err(AppError::operational(
            "controller quarantine artifact identity is invalid",
        ));
    }
    match (&record.key, &record.target_adapter) {
        (QuarantineKey::Endpoint { endpoint_scope }, _)
            if endpoint_scope == ROOT_ENDPOINT_SCOPE => {}
        (QuarantineKey::Target { .. }, Some(binding)) if target_key(binding)? == record.key => {}
        _ => {
            return Err(AppError::operational(
                "controller quarantine scope is not bound to its target adapter",
            ));
        }
    }
    Ok(())
}

fn failure_kind(scenario: TargetAdapterScenario) -> Result<TargetAdapterFailureKind, AppError> {
    match scenario {
        TargetAdapterScenario::Normal => Ok(TargetAdapterFailureKind::OperationFailure),
        TargetAdapterScenario::CmmAbort => Ok(TargetAdapterFailureKind::CmmAbort),
        TargetAdapterScenario::Trace32Disconnect => Ok(TargetAdapterFailureKind::Trace32Disconnect),
        TargetAdapterScenario::DriverDisconnect => Ok(TargetAdapterFailureKind::DriverDisconnect),
        _ => Err(unsupported_recovery(
            "selected target-adapter scenario does not define interrupted-operation recovery",
        )),
    }
}

fn recovery_scenario(
    record: &QuarantineRecord,
    evidence: &TargetAdapterRecoveryEvidence,
) -> Result<TargetAdapterScenario, AppError> {
    let binding = record.target_adapter.as_ref().ok_or_else(|| {
        unsupported_recovery(
            "target recovery requires an immutable selected target-adapter binding",
        )
    })?;
    if evidence.failure_kind != failure_kind(binding.scenario)? {
        return Err(AppError::operational(
            "target recovery failure kind does not match the deployment-owned scenario",
        ));
    }
    Ok(binding.scenario)
}

fn recovery_expectation(
    root: &ArtifactRoot,
    record: &QuarantineRecord,
    scope: RecoveryScopeArgument,
) -> Result<Value, AppError> {
    match scope {
        RecoveryScopeArgument::Endpoint => {
            if record.target_adapter.is_some() {
                return Err(unsupported_recovery(
                    "selected-target failures require target recovery to restore adapter state",
                ));
            }
            Ok(json!({
                "schema": "t32perf.controller-endpoint-recovery-evidence/v1",
                "adapter_catalog_sha256": record.adapter_catalog_sha256,
                "binding_sha256": record.binding_sha256,
                "failed_operation": record.failed_operation,
                "upstream_abort_receipt_sha256": record.abort_receipt_artifact_sha256,
                "adapter_mutation": false,
                "files_deleted": false,
                "new_session_required": true,
            }))
        }
        RecoveryScopeArgument::Target => {
            let binding = record.target_adapter.as_ref().ok_or_else(|| {
                unsupported_recovery(
                    "target recovery requires an immutable selected target-adapter binding",
                )
            })?;
            let profile = admitted_profile_for_recovery(root, record, binding)?;
            Ok(json!({
                "schema": "t32perf.target-adapter-recovery-evidence/v1",
                "profile_sha256": profile
                    .qualification_identity_digest()
                    .map_err(AppError::operational)?,
                "binding_sha256": record.binding_sha256,
                "failed_operation": record.failed_operation,
                "failure_kind": failure_kind(binding.scenario)?,
                "upstream_abort_receipt_sha256": record.abort_receipt_artifact_sha256,
                "files_deleted": false,
                "new_session_required": true,
            }))
        }
    }
}

fn admitted_profile_for_recovery(
    root: &ArtifactRoot,
    record: &QuarantineRecord,
    binding: &ControllerTargetAdapterBinding,
) -> Result<t32perf_trace32::TargetAdapterProfile, AppError> {
    let session = root
        .session(&SessionId::new(record.failed_session_id.clone()).map_err(AppError::operational)?)
        .map_err(AppError::operational)?;
    let artifacts = session
        .registered_artifacts(false)
        .map_err(AppError::operational)?;
    admitted_profile_for_binding(&session, &artifacts, binding)
}

fn validate_target_recovery(
    root: &ArtifactRoot,
    record: &QuarantineRecord,
    evidence: &TargetAdapterRecoveryEvidence,
) -> Result<(), AppError> {
    let target_adapter = record.target_adapter.as_ref().ok_or_else(|| {
        unsupported_recovery("recovery requires an immutable selected target-adapter binding")
    })?;
    let recovery_scenario = recovery_scenario(record, evidence)?;
    crate::controller::validate_quarantined_target_recovery(
        root,
        QuarantinedTargetRecoveryClaims {
            failed_session_id: &record.failed_session_id,
            failed_session_operation_id: &record.failed_session_operation_id,
            failed_transaction_id: &record.failed_transaction_id,
            failed_operation: record.failed_operation,
            failed_binding_sha256: &record.binding_sha256,
            request_artifact_id: &record.request_artifact_id,
            request_artifact_sha256: &record.request_artifact_sha256,
            abort_request_artifact_id: &record.abort_request_artifact_id,
            abort_request_artifact_sha256: &record.abort_request_artifact_sha256,
            abort_receipt_artifact_id: &record.abort_receipt_artifact_id,
            abort_receipt_artifact_sha256: &record.abort_receipt_artifact_sha256,
            target_adapter,
            recovery_scenario,
        },
        evidence,
    )
}

fn validate_recovery_evidence(
    root: &ArtifactRoot,
    record: &QuarantineRecord,
    scope: RecoveryScopeArgument,
    bytes: &[u8],
) -> Result<(), AppError> {
    match scope {
        RecoveryScopeArgument::Endpoint => {
            if record.target_adapter.is_some() {
                return Err(unsupported_recovery(
                    "selected-target failures require target recovery evidence",
                ));
            }
            let evidence: EndpointRecoveryEvidence =
                strict_json::from_slice(bytes).map_err(AppError::operational)?;
            if evidence.schema != "t32perf.controller-endpoint-recovery-evidence/v1"
                || evidence.adapter_catalog_sha256 != record.adapter_catalog_sha256
                || evidence.binding_sha256 != record.binding_sha256
                || evidence.failed_operation != record.failed_operation
                || !evidence.upstream_abort_confirmed
                || evidence.upstream_abort_receipt_sha256 != record.abort_receipt_artifact_sha256
                || evidence.adapter_mutation
                || evidence.files_deleted
                || !evidence.new_session_required
            {
                return Err(AppError::operational(
                    "endpoint recovery evidence is not bound to the quarantined abort",
                ));
            }
            Ok(())
        }
        RecoveryScopeArgument::Target => {
            let evidence: TargetAdapterRecoveryEvidence =
                strict_json::from_slice(bytes).map_err(AppError::operational)?;
            validate_target_recovery(root, record, &evidence)
        }
    }
}

fn validate_reservation(
    reservation: &RecoveryReservation,
    reservation_id: &str,
) -> Result<(), AppError> {
    if reservation.schema != RESERVATION_SCHEMA
        || reservation.reservation_id != reservation_id
        || reservation.evidence_filename != RECOVERY_EVIDENCE_FILE
        || reservation.max_bytes != MAX_RECOVERY_BYTES
    {
        return Err(AppError::operational(
            "invalid controller recovery reservation",
        ));
    }
    validate_identifier(&reservation.quarantine_id, "controller quarantine")?;
    validate_sha256_text(&reservation.key_id, "controller quarantine key")
}

fn validate_reserved_record(
    reservation: &RecoveryReservation,
    loaded: &LoadedQuarantine,
) -> Result<(), AppError> {
    if loaded.record.quarantine_id != reservation.quarantine_id
        || loaded.record.key_id != reservation.key_id
        || loaded.record.key.scope() != reservation.scope
        || digest_bytes(&loaded.bytes) != reservation.quarantine_record_sha256
    {
        return Err(AppError::operational(
            "controller recovery reservation does not match its quarantine record",
        ));
    }
    Ok(())
}

fn validate_history_receipt(
    receipt: &RecoveryHistoryReceipt,
    reservation: &RecoveryReservation,
    loaded: &LoadedQuarantine,
    evidence_sha256: &Sha256Digest,
) -> Result<(), AppError> {
    if receipt.schema != RECOVERY_RECEIPT_SCHEMA
        || receipt.quarantine_id != reservation.quarantine_id
        || receipt.key_id != reservation.key_id
        || receipt.reservation_id != reservation.reservation_id
        || receipt.scope != reservation.scope
        || receipt.failed_session_id != loaded.record.failed_session_id
        || receipt.failed_transaction_id != loaded.record.failed_transaction_id
        || receipt.quarantine_record_sha256 != reservation.quarantine_record_sha256
        || &receipt.evidence_sha256 != evidence_sha256
        || receipt.files_deleted
        || !receipt.new_session_required
    {
        return Err(AppError::operational(
            "controller recovery history receipt is not bound to the accepted recovery",
        ));
    }
    validate_identifier(&receipt.receipt_id, "controller recovery receipt")
}

fn unsupported_recovery(message: impl Into<String>) -> AppError {
    AppError {
        code: "UNSUPPORTED",
        message: message.into(),
        details: json!({"feature": "controller.target_recovery"}),
        exit_code: crate::app::EXIT_UNSUPPORTED,
    }
}

fn quarantine_directory(root: &ArtifactRoot) -> Result<PathBuf, AppError> {
    control_subdirectory(root, QUARANTINE_DIRECTORY)
}

fn recovery_staging_directory(root: &ArtifactRoot) -> Result<PathBuf, AppError> {
    control_subdirectory(root, RECOVERY_STAGING_DIRECTORY)
}

fn recovery_history_directory(root: &ArtifactRoot) -> Result<PathBuf, AppError> {
    control_subdirectory(root, RECOVERY_HISTORY_DIRECTORY)
}

fn control_subdirectory(root: &ArtifactRoot, leaf: &str) -> Result<PathBuf, AppError> {
    let control = root.path().join(CONTROL_DIRECTORY);
    ensure_or_create_directory(&control)?;
    let controller = control.join(CONTROLLER_DIRECTORY);
    ensure_or_create_directory(&controller)?;
    let result = controller.join(leaf);
    ensure_or_create_directory(&result)?;
    Ok(result)
}

fn ensure_or_create_directory(path: &Path) -> Result<(), AppError> {
    match fs::symlink_metadata(path) {
        Ok(_) => ensure_plain_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(AppError::operational)?;
            ensure_plain_directory(path)?;
            if let Some(parent) = path.parent() {
                sync_control_directory(parent)?;
            }
            Ok(())
        }
        Err(error) => Err(AppError::operational(error)),
    }
}

fn ensure_plain_directory(path: &Path) -> Result<(), AppError> {
    let metadata = fs::symlink_metadata(path).map_err(AppError::operational)?;
    if metadata.is_dir() && !unsafe_file_type(&metadata) {
        Ok(())
    } else {
        Err(AppError::operational(format!(
            "controller recovery path is not a plain directory: `{}`",
            path.display()
        )))
    }
}

fn write_new_json<T: Serialize>(path: &Path, value: &T) -> Result<(), AppError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(AppError::operational)?;
    bytes.push(b'\n');
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_RECOVERY_BYTES {
        return Err(AppError::operational(
            "controller recovery record exceeds its byte limit",
        ));
    }
    write_new_bytes(path, &bytes)
}

fn write_new_bytes(path: &Path, bytes: &[u8]) -> Result<(), AppError> {
    if filesystem_entry_exists(path)? {
        return Err(AppError::operational(format!(
            "controller recovery file already exists: `{}`",
            path.display()
        )));
    }
    let mut file = AtomicWriteFile::open(path).map_err(AppError::operational)?;
    file.write_all(bytes).map_err(AppError::operational)?;
    if filesystem_entry_exists(path)? {
        file.discard().map_err(AppError::operational)?;
        return Err(AppError::operational(format!(
            "controller recovery file appeared during atomic publish: `{}`",
            path.display()
        )));
    }
    file.commit().map_err(AppError::operational)?;
    sync_control_directory(
        path.parent()
            .expect("controller recovery file always has a parent"),
    )
}

fn publish_or_verify_bytes(path: &Path, bytes: &[u8]) -> Result<(), AppError> {
    if filesystem_entry_exists(path)? {
        if read_plain_file(path, MAX_RECOVERY_BYTES)? == bytes {
            return Ok(());
        }
        return Err(AppError::operational(
            "controller recovery history conflicts with accepted evidence",
        ));
    }
    write_new_bytes(path, bytes)
}

fn read_strict_json<T: for<'a> Deserialize<'a>>(path: &Path, maximum: u64) -> Result<T, AppError> {
    let bytes = read_plain_file(path, maximum)?;
    strict_json::from_slice(&bytes).map_err(AppError::operational)
}

fn read_plain_file(path: &Path, maximum: u64) -> Result<Vec<u8>, AppError> {
    let path_metadata = fs::symlink_metadata(path).map_err(AppError::operational)?;
    validate_plain_file_metadata(path, &path_metadata, maximum)?;
    let mut file = open_read(path).map_err(AppError::operational)?;
    let opened_metadata = file.metadata().map_err(AppError::operational)?;
    validate_plain_file_metadata(path, &opened_metadata, maximum)?;
    ensure_single_link(&file, &opened_metadata)?;
    verify_opened_identity(path, &file, &opened_metadata, maximum)?;

    let mut bytes = Vec::with_capacity(usize::try_from(opened_metadata.len()).unwrap_or(0));
    std::io::Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(AppError::operational)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(AppError::operational(
            "controller recovery input grew beyond its byte limit",
        ));
    }
    Ok(bytes)
}

fn open_read(path: &Path) -> std::io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;

        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn validate_plain_file_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    maximum: u64,
) -> Result<(), AppError> {
    if !metadata.is_file() || unsafe_file_type(metadata) || metadata.len() > maximum {
        return Err(AppError::operational(format!(
            "controller recovery input is not a bounded plain file: `{}`",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_single_link(_file: &File, metadata: &fs::Metadata) -> Result<(), AppError> {
    use std::os::unix::fs::MetadataExt as _;

    if metadata.nlink() == 1 {
        Ok(())
    } else {
        Err(AppError::operational(
            "controller recovery input must have exactly one hard link",
        ))
    }
}

#[cfg(windows)]
fn ensure_single_link(file: &File, _metadata: &fs::Metadata) -> Result<(), AppError> {
    if windows_file_information(file)?.2 == 1 {
        Ok(())
    } else {
        Err(AppError::operational(
            "controller recovery input must have exactly one hard link",
        ))
    }
}

#[cfg(not(any(unix, windows)))]
fn ensure_single_link(_file: &File, _metadata: &fs::Metadata) -> Result<(), AppError> {
    Ok(())
}

#[cfg(unix)]
fn verify_opened_identity(
    path: &Path,
    _file: &File,
    opened: &fs::Metadata,
    maximum: u64,
) -> Result<(), AppError> {
    use std::os::unix::fs::MetadataExt as _;

    let current = fs::symlink_metadata(path).map_err(AppError::operational)?;
    validate_plain_file_metadata(path, &current, maximum)?;
    if opened.dev() == current.dev() && opened.ino() == current.ino() {
        Ok(())
    } else {
        Err(AppError::operational(
            "controller recovery input identity changed while opening",
        ))
    }
}

#[cfg(windows)]
fn verify_opened_identity(
    path: &Path,
    file: &File,
    _opened: &fs::Metadata,
    maximum: u64,
) -> Result<(), AppError> {
    let current_metadata = fs::symlink_metadata(path).map_err(AppError::operational)?;
    validate_plain_file_metadata(path, &current_metadata, maximum)?;
    let current = open_read(path).map_err(AppError::operational)?;
    if windows_file_information(file)? == windows_file_information(&current)? {
        Ok(())
    } else {
        Err(AppError::operational(
            "controller recovery input identity changed while opening",
        ))
    }
}

#[cfg(not(any(unix, windows)))]
fn verify_opened_identity(
    path: &Path,
    _file: &File,
    opened: &fs::Metadata,
    maximum: u64,
) -> Result<(), AppError> {
    let current = fs::symlink_metadata(path).map_err(AppError::operational)?;
    validate_plain_file_metadata(path, &current, maximum)?;
    if opened.len() == current.len() {
        Ok(())
    } else {
        Err(AppError::operational(
            "controller recovery input identity changed while opening",
        ))
    }
}

#[cfg(windows)]
fn windows_file_information(file: &File) -> Result<(u32, u64, u32), AppError> {
    use std::{ffi::c_void, os::windows::io::AsRawHandle as _};

    #[repr(C)]
    struct ByHandleFileInformation {
        file_attributes: u32,
        creation_time_low: u32,
        creation_time_high: u32,
        last_access_time_low: u32,
        last_access_time_high: u32,
        last_write_time_low: u32,
        last_write_time_high: u32,
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }

    #[link(name = "Kernel32")]
    unsafe extern "system" {
        #[link_name = "GetFileInformationByHandle"]
        fn get_file_information_by_handle(
            file: *mut c_void,
            information: *mut ByHandleFileInformation,
        ) -> i32;
    }

    let mut information = std::mem::MaybeUninit::<ByHandleFileInformation>::uninit();
    // SAFETY: `file` owns a valid handle and `information` points to writable storage.
    if unsafe { get_file_information_by_handle(file.as_raw_handle(), information.as_mut_ptr()) }
        == 0
    {
        return Err(AppError::operational(std::io::Error::last_os_error()));
    }
    // SAFETY: a successful call initialized the complete C structure.
    let information = unsafe { information.assume_init() };
    let file_index =
        u64::from(information.file_index_low) | (u64::from(information.file_index_high) << 32);
    Ok((
        information.volume_serial_number,
        file_index,
        information.number_of_links,
    ))
}

fn unsafe_file_type(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    false
}

fn filesystem_entry_exists(path: &Path) -> Result<bool, AppError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(AppError::operational(error)),
    }
}

#[cfg(unix)]
fn sync_control_directory(path: &Path) -> Result<(), AppError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(AppError::operational)
}

#[cfg(not(unix))]
fn sync_control_directory(_path: &Path) -> Result<(), AppError> {
    Ok(())
}

fn sync_rename_parents(source: &Path, destination: &Path) -> Result<(), AppError> {
    let source_parent = source
        .parent()
        .ok_or_else(|| AppError::operational("quarantine source has no parent directory"))?;
    let destination_parent = destination
        .parent()
        .ok_or_else(|| AppError::operational("quarantine destination has no parent directory"))?;
    sync_control_directory(source_parent)?;
    if destination_parent != source_parent {
        sync_control_directory(destination_parent)?;
    }
    Ok(())
}

fn key_digest(key: &QuarantineKey) -> String {
    hex_encode(&Sha256::digest(
        serde_json::to_vec(key).expect("quarantine key serialization is infallible"),
    ))
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(hex_encode(&Sha256::digest(bytes))).expect("SHA-256 syntax is valid")
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}

fn new_identifier() -> String {
    Uuid::now_v7().simple().to_string()
}

fn validate_identifier(value: &str, label: &str) -> Result<(), AppError> {
    if value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(AppError::operational(format!(
            "{label} identifier must be 32 lowercase hexadecimal characters"
        )))
    }
}

fn validate_sha256_text(value: &str, label: &str) -> Result<(), AppError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(AppError::operational(format!(
            "{label} digest must be 64 lowercase hexadecimal characters"
        )))
    }
}

fn success(command: &'static str, result: Value) -> Result<CommandOutcome, AppError> {
    Ok(CommandOutcome {
        command,
        result,
        exit_code: EXIT_SUCCESS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use t32perf_session::SessionLimits;
    use t32perf_trace32::TargetAdapterCaptureKind;

    fn digest(character: char) -> Sha256Digest {
        Sha256Digest::new(character.to_string().repeat(64)).expect("digest")
    }

    fn record(operation: PerfOperation, reason: ControllerAbortReason) -> QuarantineRecord {
        let key = QuarantineKey::Endpoint {
            endpoint_scope: ROOT_ENDPOINT_SCOPE.to_owned(),
        };
        QuarantineRecord {
            schema: QUARANTINE_SCHEMA.to_owned(),
            quarantine_id: "0123456789abcdef0123456789abcdef".to_owned(),
            key_id: key_digest(&key),
            key,
            failed_session_id: "failed-session".to_owned(),
            failed_session_operation_id: "1123456789abcdef0123456789abcdef".to_owned(),
            failed_transaction_id: "2123456789abcdef0123456789abcdef".to_owned(),
            failed_operation: operation,
            abort_reason: reason,
            adapter_catalog_sha256: digest('a'),
            binding_sha256: digest('b'),
            request_artifact_id: "controller-request-2123456789abcdef0123456789abcdef".to_owned(),
            request_artifact_sha256: digest('c'),
            abort_request_artifact_id: "controller-abort-2123456789abcdef0123456789abcdef"
                .to_owned(),
            abort_request_artifact_sha256: digest('d'),
            abort_receipt_artifact_id: "controller-abort-receipt-2123456789abcdef0123456789abcdef"
                .to_owned(),
            abort_receipt_artifact_sha256: digest('e'),
            target_adapter: None,
        }
    }

    fn binding() -> ControllerTargetAdapterBinding {
        ControllerTargetAdapterBinding {
            adapter_id: "adapter".to_owned(),
            adapter_version: "1".to_owned(),
            trace32_release: "2026.02".to_owned(),
            trace32_build: 190766,
            architecture_package: "tricore".to_owned(),
            target_identifier: "target".to_owned(),
            probe_identifier: "probe".to_owned(),
            profile_sha256: digest('1'),
            implementation_sha256: digest('2'),
            scenario: TargetAdapterScenario::Normal,
            capture_kind: TargetAdapterCaptureKind::Sampling {
                capacity_records: 65_536,
            },
            controller_protocol: t32perf_trace32::TargetAdapterControllerProtocol::V1,
            custom_event_collector: None,
            qualification_sha256: None,
        }
    }

    #[test]
    fn endpoint_key_is_stable_across_catalog_upgrades() {
        let before = QuarantineKey::Endpoint {
            endpoint_scope: ROOT_ENDPOINT_SCOPE.to_owned(),
        };
        let after = QuarantineKey::Endpoint {
            endpoint_scope: ROOT_ENDPOINT_SCOPE.to_owned(),
        };
        assert_eq!(key_digest(&before), key_digest(&after));
    }

    #[test]
    fn normal_scenario_uses_generic_operation_failure() {
        let record = record(PerfOperation::Start, ControllerAbortReason::OperatorRequest);
        assert!(record.target_adapter.is_none());
        assert_eq!(
            failure_kind(TargetAdapterScenario::Normal).expect("normal failure kind"),
            TargetAdapterFailureKind::OperationFailure
        );
    }

    #[test]
    fn capabilities_abort_endpoint_recovery_prepares_and_accepts_without_adapter_binding() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let root = ArtifactRoot::open(temporary.path(), SessionLimits::default()).expect("root");
        let record = record(
            PerfOperation::GetCapabilities,
            ControllerAbortReason::Timeout,
        );
        let active = quarantine_directory(&root)
            .expect("quarantine directory")
            .join(format!("{}.json", record.key_id));
        write_new_json(&active, &record).expect("active endpoint quarantine");

        let prepared = prepare_recovery(
            &root,
            &record.failed_session_id,
            &record.failed_transaction_id,
            RecoveryScopeArgument::Endpoint,
        )
        .expect("endpoint recovery preparation");
        assert_eq!(
            prepared.result["evidence_expectation"]["schema"],
            "t32perf.controller-endpoint-recovery-evidence/v1"
        );
        let evidence = EndpointRecoveryEvidence {
            schema: "t32perf.controller-endpoint-recovery-evidence/v1".to_owned(),
            adapter_catalog_sha256: record.adapter_catalog_sha256.clone(),
            binding_sha256: record.binding_sha256.clone(),
            failed_operation: record.failed_operation,
            upstream_abort_confirmed: true,
            upstream_abort_receipt_sha256: record.abort_receipt_artifact_sha256.clone(),
            adapter_mutation: false,
            files_deleted: false,
            new_session_required: true,
        };
        let handoff = prepared.result["evidence_handoff_path"]
            .as_str()
            .expect("handoff path");
        fs::write(
            handoff,
            serde_json::to_vec(&evidence).expect("endpoint evidence"),
        )
        .expect("write endpoint evidence");
        let reservation = prepared.result["reservation_id"]
            .as_str()
            .expect("reservation id");
        accept_recovery(&root, reservation).expect("endpoint recovery acceptance");
        assert!(!filesystem_entry_exists(&active).expect("active state"));
        assert!(
            recovery_history_directory(&root)
                .expect("history directory")
                .join(&record.quarantine_id)
                .join(HISTORY_RECEIPT_FILE)
                .is_file()
        );
    }

    #[test]
    fn recovered_history_does_not_consume_active_quarantine_capacity() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let root = ArtifactRoot::open(temporary.path(), SessionLimits::default()).expect("root");
        let history = recovery_history_directory(&root).expect("history directory");
        for index in 0..=MAX_ACTIVE_QUARANTINES {
            fs::create_dir(history.join(format!("{index:032x}"))).expect("history shard");
        }
        let record = record(
            PerfOperation::GetCapabilities,
            ControllerAbortReason::Timeout,
        );
        write_new_json(
            &quarantine_directory(&root)
                .expect("quarantine directory")
                .join(format!("{}.json", record.key_id)),
            &record,
        )
        .expect("active quarantine");
        assert_eq!(
            list_active_quarantines(&root)
                .expect("active quarantines")
                .len(),
            1
        );
    }

    #[test]
    fn target_recovery_moves_the_linked_endpoint_quarantine() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let root = ArtifactRoot::open(temporary.path(), SessionLimits::default()).expect("root");
        let endpoint = record(PerfOperation::Start, ControllerAbortReason::OperatorRequest);
        let binding = binding();
        let target_key = target_key(&binding).expect("target key");
        let target = QuarantineRecord {
            quarantine_id: "3123456789abcdef0123456789abcdef".to_owned(),
            key_id: key_digest(&target_key),
            key: target_key,
            target_adapter: Some(binding.clone()),
            ..endpoint.clone()
        };
        let active_directory = quarantine_directory(&root).expect("quarantine directory");
        let endpoint_active = active_directory.join(format!("{}.json", endpoint.key_id));
        let target_active = active_directory.join(format!("{}.json", target.key_id));
        write_new_json(&endpoint_active, &endpoint).expect("endpoint active");
        write_new_json(&target_active, &target).expect("target active");
        let endpoint_loaded = read_quarantine(&endpoint_active).expect("endpoint loaded");
        let target_history = recovery_history_directory(&root)
            .expect("history directory")
            .join(&target.quarantine_id);
        ensure_or_create_directory(&target_history).expect("target history");
        let evidence_path = target_history.join(HISTORY_EVIDENCE_FILE);
        write_new_bytes(&evidence_path, b"{\"accepted\":true}").expect("target evidence");
        let receipt = RecoveryHistoryReceipt {
            schema: RECOVERY_RECEIPT_SCHEMA.to_owned(),
            receipt_id: "4123456789abcdef0123456789abcdef".to_owned(),
            quarantine_id: target.quarantine_id.clone(),
            key_id: target.key_id.clone(),
            reservation_id: "5123456789abcdef0123456789abcdef".to_owned(),
            scope: RecoveryScopeArgument::Target,
            failed_session_id: target.failed_session_id.clone(),
            failed_transaction_id: target.failed_transaction_id.clone(),
            quarantine_record_sha256: digest_bytes(
                &read_quarantine(&target_active)
                    .expect("target loaded")
                    .bytes,
            ),
            evidence_sha256: digest_bytes(b"{\"accepted\":true}"),
            linked_quarantine_id: Some(endpoint.quarantine_id.clone()),
            files_deleted: false,
            new_session_required: true,
        };
        write_new_json(&target_history.join(HISTORY_RECEIPT_FILE), &receipt)
            .expect("target receipt");
        fs::rename(&target_active, target_history.join(HISTORY_QUARANTINE_FILE))
            .expect("move target");
        complete_linked_endpoint_recovery(
            &root,
            &target,
            &receipt,
            &evidence_path,
            Some(&endpoint_loaded),
        )
        .expect("complete linked endpoint");
        assert!(!filesystem_entry_exists(&endpoint_active).expect("endpoint moved"));
        assert!(
            recovery_history_directory(&root)
                .expect("history directory")
                .join(&endpoint.quarantine_id)
                .join(HISTORY_RECEIPT_FILE)
                .is_file()
        );
        ensure_not_quarantined(&root, &digest('a'), Some(&binding))
            .expect("both quarantine scopes released");
    }
}
