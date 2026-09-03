use std::{
    collections::BTreeSet,
    fs::{self, File, Metadata, OpenOptions},
    io,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

use fs2::FileExt as _;
use t32perf_session::{ArtifactRoot, verify_opened_plain_file_identity};

use crate::app::AppError;

const CONTROL_DIRECTORY: &str = ".t32perf-control";
const CONTROLLER_DIRECTORY: &str = "controller";
const DRIVER_EXECUTION_LEASE_FILE: &str = "trace32-driver-execution.lock";

static ACTIVE_DRIVER_EXECUTIONS: OnceLock<Mutex<BTreeSet<PathBuf>>> = OnceLock::new();

/// Exclusive root-wide ownership of the deployment's single-tenant TRACE32 endpoint.
#[derive(Debug)]
pub(crate) struct DriverExecutionLease {
    file: File,
    root_path: PathBuf,
}

/// Acquires the root/endpoint execution lease without waiting.
///
/// The fixed deployment contract assigns one single-tenant t32mcp endpoint to
/// one canonical artifact root. The process registry closes same-process file
/// locking differences, while the file lock excludes other host processes.
pub(crate) fn try_acquire(root: &ArtifactRoot) -> Result<DriverExecutionLease, AppError> {
    try_acquire_with_gate(root, || {
        crate::sampling::ensure_endpoint_not_quarantined(root)
    })
}

fn try_acquire_with_gate(
    root: &ArtifactRoot,
    gate: impl FnOnce() -> Result<(), AppError>,
) -> Result<DriverExecutionLease, AppError> {
    let root_path = root.path().to_path_buf();
    let lease_path = ensure_lease_path(root)?;
    reserve_process_execution(&root_path)?;

    let lease = match open_and_lock(&lease_path, &root_path) {
        Ok(lease) => lease,
        Err(error) => {
            release_process_execution(&root_path);
            return Err(error);
        }
    };
    gate()?;
    Ok(lease)
}

fn open_and_lock(path: &Path, root_path: &Path) -> Result<DriverExecutionLease, AppError> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| {
            AppError::operational(format!(
                "open TRACE32 driver execution lease `{}`: {error}",
                path.display()
            ))
        })?;
    verify_empty_plain_lease(path, &file)?;
    if let Err(error) = file.try_lock_exclusive() {
        return Err(if lock_is_contended(&error) {
            controller_driver_busy(root_path, "another process")
        } else {
            AppError::operational(format!(
                "lock TRACE32 driver execution lease `{}`: {error}",
                path.display()
            ))
        });
    }
    if let Err(error) = verify_empty_plain_lease(path, &file) {
        let _ = fs2::FileExt::unlock(&file);
        return Err(error);
    }
    Ok(DriverExecutionLease {
        file,
        root_path: root_path.to_path_buf(),
    })
}

fn lock_is_contended(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(windows)]
    {
        // Windows reports LockFileEx contention as ERROR_LOCK_VIOLATION.
        const ERROR_LOCK_VIOLATION: i32 = 33;
        if error.raw_os_error() == Some(ERROR_LOCK_VIOLATION) {
            return true;
        }
    }
    false
}

fn ensure_lease_path(root: &ArtifactRoot) -> Result<PathBuf, AppError> {
    let control = root.path().join(CONTROL_DIRECTORY);
    ensure_or_create_plain_directory(&control, "control-plane directory")?;
    let controller = control.join(CONTROLLER_DIRECTORY);
    ensure_or_create_plain_directory(&controller, "controller directory")?;
    Ok(controller.join(DRIVER_EXECUTION_LEASE_FILE))
}

fn ensure_or_create_plain_directory(path: &Path, description: &str) -> Result<(), AppError> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(AppError::operational(format!(
                "create TRACE32 driver {description} `{}`: {error}",
                path.display()
            )));
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AppError::operational(format!(
            "inspect TRACE32 driver {description} `{}`: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_dir() || is_link_like(&metadata) {
        return Err(AppError::operational(format!(
            "TRACE32 driver {description} `{}` is not a plain directory",
            path.display()
        )));
    }
    Ok(())
}

fn verify_empty_plain_lease(path: &Path, file: &File) -> Result<(), AppError> {
    verify_opened_plain_file_identity(path, file).map_err(|error| {
        AppError::operational(format!(
            "verify TRACE32 driver execution lease `{}`: {error}",
            path.display()
        ))
    })?;
    let metadata = file.metadata().map_err(|error| {
        AppError::operational(format!(
            "inspect TRACE32 driver execution lease `{}`: {error}",
            path.display()
        ))
    })?;
    if metadata.len() != 0 {
        return Err(AppError::operational(format!(
            "TRACE32 driver execution lease `{}` must remain empty",
            path.display()
        )));
    }
    Ok(())
}

fn active_driver_executions() -> &'static Mutex<BTreeSet<PathBuf>> {
    ACTIVE_DRIVER_EXECUTIONS.get_or_init(|| Mutex::new(BTreeSet::new()))
}

fn reserve_process_execution(root_path: &Path) -> Result<(), AppError> {
    let mut active = active_driver_executions().lock().map_err(|_| {
        AppError::operational("TRACE32 driver execution lease process registry is poisoned")
    })?;
    if !active.insert(root_path.to_path_buf()) {
        return Err(controller_driver_busy(root_path, "this process"));
    }
    Ok(())
}

fn controller_driver_busy(root_path: &Path, owner: &str) -> AppError {
    AppError {
        code: "CONTROLLER_DRIVER_BUSY",
        message: format!(
            "TRACE32 driver execution lease for artifact root `{}` is already active in {owner}",
            root_path.display()
        ),
        details: serde_json::json!({
            "artifact_root": root_path.display().to_string(),
            "owner": owner
        }),
        exit_code: crate::app::EXIT_OPERATIONAL,
    }
}

fn release_process_execution(root_path: &Path) {
    if let Ok(mut active) = active_driver_executions().lock() {
        active.remove(root_path);
    }
}

fn is_link_like(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

impl Drop for DriverExecutionLease {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
        release_process_execution(&self.root_path);
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Write as _};

    use fs2::FileExt as _;
    use t32perf_session::{ArtifactRoot, SessionLimits};
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn excludes_same_process_and_releases_on_drop() {
        let temporary = TempDir::new().unwrap();
        let root = artifact_root(&temporary);
        let first = try_acquire(&root).unwrap();
        let error = try_acquire(&root).unwrap_err();
        assert_eq!(error.code, "CONTROLLER_DRIVER_BUSY");
        assert!(error.message.contains("already active in this process"));
        drop(first);
        try_acquire(&root).unwrap();
    }

    #[test]
    fn rejects_an_existing_operating_system_lock() {
        let temporary = TempDir::new().unwrap();
        let root = artifact_root(&temporary);
        drop(try_acquire(&root).unwrap());
        let path = ensure_lease_path(&root).unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.try_lock_exclusive().unwrap();
        let error = try_acquire(&root).unwrap_err();
        assert_eq!(error.code, "CONTROLLER_DRIVER_BUSY");
        assert!(error.message.contains("execution lease"));
        fs2::FileExt::unlock(&file).unwrap();
    }

    #[test]
    fn gate_failure_releases_exactly_its_own_process_reservation() {
        let temporary = TempDir::new().unwrap();
        let root = artifact_root(&temporary);
        let error = try_acquire_with_gate(&root, || {
            Err(AppError::operational("injected gate failure"))
        })
        .unwrap_err();
        assert!(error.message.contains("injected gate failure"));

        let lease = try_acquire(&root).unwrap();
        let contention = try_acquire(&root).unwrap_err();
        assert_eq!(contention.code, "CONTROLLER_DRIVER_BUSY");
        drop(lease);
        drop(try_acquire(&root).unwrap());
    }

    #[test]
    fn rejects_nonempty_or_linked_lease_objects() {
        let temporary = TempDir::new().unwrap();
        let root = artifact_root(&temporary);
        drop(try_acquire(&root).unwrap());
        let path = ensure_lease_path(&root).unwrap();
        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.write_all(b"not a lease").unwrap();
        drop(file);
        let error = try_acquire(&root).unwrap_err();
        assert!(error.message.contains("must remain empty"));

        fs::remove_file(&path).unwrap();
        let target = temporary.path().join("target.lock");
        fs::write(&target, b"").unwrap();
        if create_file_symlink(&target, &path).is_ok() {
            let error = try_acquire(&root).unwrap_err();
            assert!(
                error
                    .message
                    .contains("verify TRACE32 driver execution lease")
            );
        }
    }

    #[test]
    fn sampling_quarantine_blocks_every_cooperating_driver_until_cleanup_is_observed() {
        let temporary = TempDir::new().unwrap();
        let root = artifact_root(&temporary);
        let transaction = "123e4567-e89b-42d3-a456-426614174000";

        write_sampling_event(
            &root,
            transaction,
            1,
            "configure_intent",
            serde_json::json!({"method": "realtime"}),
        );
        let error = try_acquire(&root).unwrap_err();
        assert_eq!(error.code, "SAMPLING_ENDPOINT_QUARANTINED");

        write_sampling_event(
            &root,
            transaction,
            2,
            "configure_observed",
            serde_json::json!({"method": "realtime"}),
        );
        write_sampling_event(
            &root,
            transaction,
            3,
            "cleanup_intent",
            serde_json::json!({}),
        );
        write_sampling_event(
            &root,
            transaction,
            4,
            "cleanup_observed",
            serde_json::json!({}),
        );
        drop(try_acquire(&root).unwrap());
    }

    #[test]
    fn failed_sampling_cleanup_requires_an_explicit_recovery_observation() {
        let temporary = TempDir::new().unwrap();
        let root = artifact_root(&temporary);
        let transaction = "123e4567-e89b-42d3-a456-426614174001";
        let events = [
            (
                "configure_intent",
                serde_json::json!({"method": "stop_and_go"}),
            ),
            ("cleanup_intent", serde_json::json!({})),
            (
                "cleanup_failed",
                serde_json::json!({"error": "RuntimeError"}),
            ),
        ];
        for (index, (event, details)) in events.into_iter().enumerate() {
            write_sampling_event(&root, transaction, index + 1, event, details);
        }
        let error = try_acquire(&root).unwrap_err();
        assert_eq!(error.code, "SAMPLING_ENDPOINT_QUARANTINED");
        assert_eq!(error.details["reason"], "cleanup_failed");

        write_sampling_event(
            &root,
            transaction,
            4,
            "cleanup_intent",
            serde_json::json!({"recovery": true}),
        );
        write_sampling_event(
            &root,
            transaction,
            5,
            "recovery_observed",
            serde_json::json!({"recovery": true}),
        );
        drop(try_acquire(&root).unwrap());
    }

    #[test]
    fn rejects_endpoint_mismatch_and_mutation_after_cleanup() {
        let temporary = TempDir::new().unwrap();
        let root = artifact_root(&temporary);
        let transaction = "123e4567-e89b-42d3-a456-426614174002";
        let events = [
            (
                "configure_intent",
                serde_json::json!({"method": "realtime"}),
            ),
            ("cleanup_intent", serde_json::json!({})),
            ("cleanup_observed", serde_json::json!({})),
            (
                "configure_intent",
                serde_json::json!({"method": "realtime"}),
            ),
        ];
        for (index, (event, details)) in events.into_iter().enumerate() {
            write_sampling_event(&root, transaction, index + 1, event, details);
        }
        let error = try_acquire(&root).unwrap_err();
        assert_eq!(error.code, "SAMPLING_ENDPOINT_QUARANTINED");
        assert_eq!(error.details["reason"], "journal event order is invalid");

        let second_temporary = TempDir::new().unwrap();
        let second = artifact_root(&second_temporary);
        write_sampling_event(
            &second,
            transaction,
            1,
            "configure_intent",
            serde_json::json!({"method": "realtime"}),
        );
        fs::write(
            second
                .path()
                .join(".t32perf-control")
                .join("sampling-endpoint-binding.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema": "t32perf.sampling-endpoint-binding/v1",
                "endpoint_fingerprint": "b".repeat(64),
                "endpoint_fingerprint_scheme": "t32perf.endpoint-fingerprint/v2",
            }))
            .unwrap(),
        )
        .unwrap();
        let error = try_acquire(&second).unwrap_err();
        assert_eq!(error.code, "SAMPLING_ENDPOINT_QUARANTINED");
        assert_eq!(
            error.details["reason"],
            "journal endpoint does not match the root binding"
        );
    }

    fn write_sampling_event(
        root: &ArtifactRoot,
        transaction: &str,
        sequence: usize,
        event: &str,
        details: serde_json::Value,
    ) {
        let directory = root
            .path()
            .join(".t32perf-control")
            .join("sampling-driver-events");
        fs::create_dir_all(&directory).unwrap();
        let binding = root
            .path()
            .join(".t32perf-control")
            .join("sampling-endpoint-binding.json");
        if !binding.exists() {
            fs::write(
                &binding,
                serde_json::to_vec(&serde_json::json!({
                    "schema": "t32perf.sampling-endpoint-binding/v1",
                    "endpoint_fingerprint": "a".repeat(64),
                    "endpoint_fingerprint_scheme": "t32perf.endpoint-fingerprint/v2",
                }))
                .unwrap(),
            )
            .unwrap();
        }
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema": "t32perf.sampling-driver-event/v1",
            "transaction_id": transaction,
            "endpoint_fingerprint": "a".repeat(64),
            "endpoint_fingerprint_scheme": "t32perf.endpoint-fingerprint/v2",
            "owner": "lauterbach-sampling-mcp/v1",
            "event": event,
            "sequence": sequence,
            "observed_at": format!("2026-08-30T00:00:{sequence:02}Z"),
            "details": details,
        }))
        .unwrap();
        fs::write(
            directory.join(format!("{transaction}-{sequence:08}.json")),
            bytes,
        )
        .unwrap();
    }

    fn artifact_root(temporary: &TempDir) -> ArtifactRoot {
        ArtifactRoot::open(temporary.path().join("sessions"), SessionLimits::default()).unwrap()
    }

    #[cfg(unix)]
    fn create_file_symlink(target: &Path, link: &Path) -> io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn create_file_symlink(target: &Path, link: &Path) -> io::Result<()> {
        std::os::windows::fs::symlink_file(target, link)
    }
}
