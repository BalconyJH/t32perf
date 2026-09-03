//! Artifact-root ownership, session creation, locking, state, and manifest commit.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Read as _, Write as _},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

use atomic_write_file::AtomicWriteFile;
use fs2::FileExt as _;
use jiff::Timestamp;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use t32perf_model::{
    ArtifactPath, MAX_MANIFEST_ARTIFACTS, Manifest, SessionError, SessionState, SessionStatus,
    StateSchemaVersion, is_portable_session_id, portable_name_key, strict_json,
};
use uuid::Uuid;

use crate::{
    SessionStoreError,
    error::io_error,
    path::{
        canonical_root, directory_size, ensure_opened_file_identity, ensure_plain_directory,
        ensure_plain_file, is_link_like, open_existing_plain_file, open_or_create_plain_file,
        resolve_artifact, resolve_existing_session,
    },
};

const LOCK_FILE: &str = ".session.lock";
const ROOT_NAMESPACE_LOCK_FILE: &str = ".artifact-root.lock";
/// Maximum number of direct artifact-root entries inspected by one listing operation.
pub const MAX_ARTIFACT_ROOT_ENTRIES: usize = 100_000;
const REQUEST_FILE: &str = "request.json";
const STATE_FILE: &str = "state.json";
const MANIFEST_FILE: &str = "manifest.json";
pub(crate) const ARTIFACT_INDEX_DIRECTORY: &str = "artifact-index";
pub(crate) const INGEST_INTENT_DIRECTORY: &str = "ingest-intents";
pub(crate) const COMMITTED_STAGING_SOURCE_DIRECTORY: &str = "committed-staging-sources";
pub(crate) const MAX_JSON_DOCUMENT_BYTES: u64 = 16 * 1024 * 1024;

static PROCESS_LOCKS: OnceLock<Mutex<BTreeSet<PathBuf>>> = OnceLock::new();
static ROOT_NAMESPACE_LOCKS: OnceLock<Mutex<BTreeMap<PathBuf, NamespaceProcessState>>> =
    OnceLock::new();

#[derive(Debug, Default)]
struct NamespaceProcessState {
    shared: usize,
    exclusive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NamespaceLockMode {
    Shared,
    Exclusive,
}

#[derive(Debug)]
struct NamespaceLease {
    file: File,
    root_path: PathBuf,
    mode: NamespaceLockMode,
}

const STANDARD_DIRECTORIES: &[&str] = &[
    "capture",
    "capture/raw",
    "capture/staging",
    "normalized",
    "analysis",
    "report",
    "logs",
    ARTIFACT_INDEX_DIRECTORY,
    INGEST_INTENT_DIRECTORY,
    COMMITTED_STAGING_SOURCE_DIRECTORY,
];

/// File-payload limits enforced before data becomes durable Session state.
///
/// `max_session_bytes` covers every regular-file payload below the Session,
/// including requests, state, artifacts, catalog records, manifests, the lock
/// file, and atomic-write temporary payloads. Directory-entry and allocation-
/// unit overhead is platform-specific and is intentionally outside this
/// portable byte quota; standard directories and the empty lock file therefore
/// consume zero payload bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLimits {
    /// Maximum size of one artifact file.
    pub max_file_bytes: u64,
    /// Maximum aggregate size of one Session directory.
    pub max_session_bytes: u64,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: 64 * 1024 * 1024 * 1024,
            max_session_bytes: 256 * 1024 * 1024 * 1024,
        }
    }
}

impl SessionLimits {
    fn validate(self) -> Result<Self, SessionStoreError> {
        if self.max_file_bytes == 0 {
            return Err(SessionStoreError::FileLimitExceeded {
                limit_bytes: 0,
                actual_bytes: 1,
            });
        }
        if self.max_session_bytes < self.max_file_bytes {
            return Err(SessionStoreError::SessionLimitExceeded {
                limit_bytes: self.max_session_bytes,
                actual_bytes: self.max_file_bytes,
            });
        }
        Ok(self)
    }
}

/// A validated portable Session identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(String);

impl SessionId {
    /// Validates an existing identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, SessionStoreError> {
        let value = value.into();
        if !is_portable_session_id(&value) {
            return Err(SessionStoreError::InvalidSessionId { value });
        }
        Ok(Self(value))
    }

    /// Generates a time-sortable UUIDv7 identifier.
    #[must_use]
    pub fn generate() -> Self {
        Self(format!("session-{}", Uuid::now_v7().simple()))
    }

    /// Returns the portable identifier string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A canonical whitelist root containing only T32Perf-managed Sessions.
#[derive(Debug, Clone)]
pub struct ArtifactRoot {
    path: PathBuf,
    limits: SessionLimits,
}

impl ArtifactRoot {
    /// Creates or opens an artifact root and resolves it to a canonical directory.
    pub fn open(path: impl AsRef<Path>, limits: SessionLimits) -> Result<Self, SessionStoreError> {
        Ok(Self {
            path: canonical_root(path.as_ref())?,
            limits: limits.validate()?,
        })
    }

    /// Returns the canonical artifact-root path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the configured per-Session artifact limits.
    #[must_use]
    pub const fn limits(&self) -> SessionLimits {
        self.limits
    }

    /// Creates a new Session with a generated identifier.
    pub fn create_session(&self, request: &Value) -> Result<Session, SessionStoreError> {
        self.create_session_with_id(SessionId::generate(), request)
    }

    /// Creates a new Session with an explicit identifier, primarily for deterministic automation.
    pub fn create_session_with_id(
        &self,
        session_id: SessionId,
        request: &Value,
    ) -> Result<Session, SessionStoreError> {
        let _namespace_lock = self.try_namespace_lock()?;
        if let Some(existing) = find_session_name_conflict(&self.path, &session_id)? {
            return Err(if existing == session_id {
                SessionStoreError::SessionExists {
                    session_id: session_id.to_string(),
                }
            } else {
                SessionStoreError::SessionNameConflict {
                    requested: session_id.to_string(),
                    existing: existing.to_string(),
                }
            });
        }
        let created_at = now_rfc3339();
        let state = SessionState {
            schema: StateSchemaVersion,
            created_at: created_at.clone(),
            status: SessionStatus::Created,
            operation_id: Uuid::now_v7().simple().to_string(),
            revision: 0,
            updated_at: created_at,
            error: None,
        };
        state
            .validate()
            .map_err(|error| SessionStoreError::InvalidDocument {
                document: "session state",
                message: error.to_string(),
            })?;
        let path = self.path.join(session_id.as_str());
        let request_bytes =
            serialize_json_document(&path.join(REQUEST_FILE), "session request", request)?;
        let state_bytes = serialize_json_document(&path.join(STATE_FILE), "session state", &state)?;
        ensure_peak_capacity(
            self.limits.max_session_bytes,
            0,
            bytes_len(&request_bytes)?
                .checked_add(bytes_len(&state_bytes)?)
                .ok_or(SessionStoreError::SessionLimitExceeded {
                    limit_bytes: self.limits.max_session_bytes,
                    actual_bytes: u64::MAX,
                })?,
        )?;
        if path_entry_exists(&path)? {
            return Err(SessionStoreError::SessionExists {
                session_id: session_id.to_string(),
            });
        }

        let private_path = self
            .path
            .join(format!(".session-create-{}", Uuid::now_v7().simple()));
        fs::create_dir(&private_path)
            .map_err(|error| io_error("create private Session directory", &private_path, error))?;
        ensure_plain_directory(&private_path)?;
        if let Err(error) = self.initialize_session(&private_path, &request_bytes, &state_bytes) {
            return Err(cleanup_private_session_directory(&private_path, error));
        }
        if path_entry_exists(&path)? {
            let error = SessionStoreError::SessionExists {
                session_id: session_id.to_string(),
            };
            return Err(cleanup_private_session_directory(&private_path, error));
        }
        if let Err(error) = fs::rename(&private_path, &path) {
            let publish_error = if error.kind() == io::ErrorKind::AlreadyExists {
                SessionStoreError::SessionExists {
                    session_id: session_id.to_string(),
                }
            } else {
                io_error("publish Session directory", &path, error)
            };
            return Err(cleanup_private_session_directory(
                &private_path,
                publish_error,
            ));
        }
        ensure_plain_directory(&path)?;
        Ok(Session {
            id: session_id,
            path,
            limits: self.limits,
        })
    }

    fn initialize_session(
        &self,
        path: &Path,
        request_bytes: &[u8],
        state_bytes: &[u8],
    ) -> Result<(), SessionStoreError> {
        for relative in STANDARD_DIRECTORIES {
            let directory = path.join(relative.replace('/', std::path::MAIN_SEPARATOR_STR));
            fs::create_dir(&directory)
                .map_err(|error| io_error("create session directory", &directory, error))?;
            ensure_plain_directory(&directory)?;
        }
        let lock_path = path.join(LOCK_FILE);
        File::options()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|error| io_error("create session lock", &lock_path, error))?;

        let request_path = path.join(REQUEST_FILE);
        write_serialized_json_atomic(&request_path, request_bytes, true)?;
        write_serialized_json_atomic(&path.join(STATE_FILE), state_bytes, false)?;
        Ok(())
    }

    /// Attempts to acquire exclusive ownership of top-level Session namespace changes.
    ///
    /// Session creation and whole-Session retention moves use this lease so a
    /// published Session directory cannot be replaced or removed by a concurrent
    /// namespace operation.
    pub fn try_namespace_lock(&self) -> Result<ArtifactRootNamespaceLock, SessionStoreError> {
        Ok(ArtifactRootNamespaceLock {
            lease: acquire_namespace_lease(&self.path, NamespaceLockMode::Exclusive)?,
        })
    }

    /// Opens an existing Session without acquiring its operation lock.
    pub fn session(&self, session_id: &SessionId) -> Result<Session, SessionStoreError> {
        let path = resolve_existing_session(&self.path, session_id.as_str())?;
        Ok(Session {
            id: session_id.clone(),
            path,
            limits: self.limits,
        })
    }

    /// Lists valid Session identifiers without following links or reparse points.
    pub fn list_sessions(&self) -> Result<Vec<SessionId>, SessionStoreError> {
        self.list_sessions_bounded(MAX_ARTIFACT_ROOT_ENTRIES)
    }

    fn list_sessions_bounded(
        &self,
        max_root_entries: usize,
    ) -> Result<Vec<SessionId>, SessionStoreError> {
        let mut sessions = Vec::new();
        let mut portable_ids = BTreeMap::new();
        let entries = fs::read_dir(&self.path)
            .map_err(|error| io_error("list artifact root", &self.path, error))?;
        let mut entry_count = 0_usize;
        for entry in entries {
            entry_count = entry_count.saturating_add(1);
            if entry_count > max_root_entries {
                return Err(SessionStoreError::DirectoryEntryLimitExceeded {
                    limit: max_root_entries,
                    actual: entry_count,
                });
            }
            let entry =
                entry.map_err(|error| io_error("read artifact-root entry", &self.path, error))?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| io_error("inspect artifact-root entry", &path, error))?;
            if !metadata.is_dir() || is_link_like(&metadata) {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if let Ok(session_id) = SessionId::new(name) {
                let key = portable_name_key(session_id.as_str());
                if let Some(existing) = portable_ids.insert(key, session_id.clone()) {
                    return Err(SessionStoreError::SessionNameConflict {
                        requested: session_id.to_string(),
                        existing: existing.to_string(),
                    });
                }
                sessions.push(session_id);
            }
        }
        sessions.sort();
        Ok(sessions)
    }
}

/// One existing T32Perf Session below a canonical artifact root.
#[derive(Debug, Clone)]
pub struct Session {
    id: SessionId,
    path: PathBuf,
    limits: SessionLimits,
}

impl Session {
    /// Returns the Session identifier.
    #[must_use]
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// Returns the canonical Session directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the configured artifact limits.
    #[must_use]
    pub const fn limits(&self) -> SessionLimits {
        self.limits
    }

    /// Returns the only directory in which an external capture process may write.
    #[must_use]
    pub fn staging_root(&self) -> PathBuf {
        self.path.join("capture").join("staging")
    }

    /// Resolves a validated path below `capture/staging` for a capture process.
    pub fn staging_path(&self, relative: &ArtifactPath) -> Result<PathBuf, SessionStoreError> {
        let combined =
            ArtifactPath::new(format!("capture/staging/{relative}")).map_err(|error| {
                SessionStoreError::InvalidStagingPath {
                    path: error.to_string(),
                }
            })?;
        resolve_artifact(&self.path, &combined, false)
    }

    /// Reads one plain staging file through the Session path boundary with an
    /// independent byte limit.
    ///
    /// The returned bytes are a snapshot of the opened file handle. Callers
    /// that later ingest the path must compare the immutable artifact bytes to
    /// this snapshot before trusting any pre-ingest parse result.
    pub fn read_staged_bounded(
        &self,
        relative: &ArtifactPath,
        max_bytes: u64,
    ) -> Result<Vec<u8>, SessionStoreError> {
        let path = self.staging_path(relative)?;
        let (mut file, metadata) = open_existing_plain_file(&path, false)?;
        if metadata.len() > max_bytes {
            return Err(SessionStoreError::MetadataLimitExceeded {
                document: "staged control file",
                limit_bytes: max_bytes,
                actual_bytes: metadata.len(),
            });
        }
        let capacity = usize::try_from(metadata.len()).map_err(|_| {
            SessionStoreError::MetadataLimitExceeded {
                document: "staged control file",
                limit_bytes: max_bytes,
                actual_bytes: metadata.len(),
            }
        })?;
        let mut bytes = Vec::with_capacity(capacity);
        file.read_to_end(&mut bytes)
            .map_err(|error| io_error("read staged control file", &path, error))?;
        let actual_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if actual_bytes > max_bytes {
            return Err(SessionStoreError::MetadataLimitExceeded {
                document: "staged control file",
                limit_bytes: max_bytes,
                actual_bytes,
            });
        }
        Ok(bytes)
    }

    /// Prepares parent directories for a validated path below `capture/staging`.
    ///
    /// This mutation requires the Session operation lock and is unavailable
    /// after the Session reaches a terminal state.
    pub fn prepare_staging_path(
        &self,
        lock: &SessionLock,
        relative: &ArtifactPath,
    ) -> Result<PathBuf, SessionStoreError> {
        self.ensure_lock(lock)?;
        self.ensure_lifecycle_mutation_allowed()?;
        let combined =
            ArtifactPath::new(format!("capture/staging/{relative}")).map_err(|error| {
                SessionStoreError::InvalidStagingPath {
                    path: error.to_string(),
                }
            })?;
        resolve_artifact(&self.path, &combined, true)
    }

    /// Attempts to acquire exclusive operation ownership for this Session.
    pub fn try_lock(&self) -> Result<SessionLock, SessionStoreError> {
        let root_path = self
            .path
            .parent()
            .ok_or_else(|| SessionStoreError::InvalidRoot {
                path: self.path.clone(),
            })?;
        let namespace_lease = acquire_namespace_lease(root_path, NamespaceLockMode::Shared)?;
        self.try_lock_with_lease(namespace_lease)
    }

    /// Acquires the Session lock while an exclusive root namespace lease is held.
    ///
    /// Retention operations use this form to preserve the global root-then-
    /// Session lock order without trying to acquire a conflicting shared lease.
    pub fn try_lock_in_namespace(
        &self,
        namespace: &ArtifactRootNamespaceLock,
    ) -> Result<SessionLock, SessionStoreError> {
        let root_path = self
            .path
            .parent()
            .ok_or_else(|| SessionStoreError::InvalidRoot {
                path: self.path.clone(),
            })?;
        if namespace.lease.root_path != root_path
            || namespace.lease.mode != NamespaceLockMode::Exclusive
        {
            return Err(SessionStoreError::NamespaceLockMismatch {
                root: root_path.to_path_buf(),
            });
        }
        self.try_lock_with_lease(Arc::clone(&namespace.lease))
    }

    fn try_lock_with_lease(
        &self,
        namespace_lease: Arc<NamespaceLease>,
    ) -> Result<SessionLock, SessionStoreError> {
        let path = self.path.join(LOCK_FILE);
        {
            let mut locks = process_locks()
                .lock()
                .expect("process lock registry poisoned");
            if !locks.insert(self.path.clone()) {
                return Err(SessionStoreError::SessionLocked {
                    session_id: self.id.to_string(),
                });
            }
        }
        let (file, _) = open_existing_plain_file(&path, true).inspect_err(|_| {
            remove_process_lock(&self.path);
        })?;
        if let Err(error) = file.try_lock_exclusive() {
            remove_process_lock(&self.path);
            return Err(if lock_is_contended(&error) {
                SessionStoreError::SessionLocked {
                    session_id: self.id.to_string(),
                }
            } else {
                io_error("lock session", &path, error)
            });
        }
        if let Err(error) = ensure_opened_file_identity(&path, &file) {
            let _ = fs2::FileExt::unlock(&file);
            remove_process_lock(&self.path);
            return Err(error);
        }
        Ok(SessionLock {
            file,
            session_path: self.path.clone(),
            _namespace_lease: namespace_lease,
        })
    }

    pub(crate) fn ensure_lock(&self, lock: &SessionLock) -> Result<(), SessionStoreError> {
        if lock.session_path == self.path {
            Ok(())
        } else {
            Err(SessionStoreError::LockMismatch {
                session_id: self.id.to_string(),
            })
        }
    }

    /// Reads and semantically validates the current durable state.
    pub fn read_state(&self) -> Result<SessionState, SessionStoreError> {
        let path = self.path.join(STATE_FILE);
        let state: SessionState =
            read_bounded_json(&path, "session state", MAX_JSON_DOCUMENT_BYTES)?;
        state
            .validate()
            .map_err(|error| SessionStoreError::InvalidDocument {
                document: "session state",
                message: error.to_string(),
            })?;
        Ok(state)
    }

    /// Reads the immutable Session request through the Session-owned path boundary.
    pub fn request(&self) -> Result<Value, SessionStoreError> {
        let path = self.path.join(REQUEST_FILE);
        read_bounded_json(&path, "session request", MAX_JSON_DOCUMENT_BYTES)
    }

    /// Computes the SHA-256 digest of the exact immutable request file.
    pub fn request_sha256(&self) -> Result<t32perf_model::Sha256Digest, SessionStoreError> {
        let path = self.path.join(REQUEST_FILE);
        let metadata = ensure_plain_file(&path)?;
        ensure_metadata_size("session request", metadata.len(), MAX_JSON_DOCUMENT_BYTES)?;
        let (size, digest) = crate::artifact::hash_file(&path)?;
        ensure_metadata_size("session request", size, MAX_JSON_DOCUMENT_BYTES)?;
        Ok(digest)
    }

    /// Atomically advances durable lifecycle state while preserving operation ownership.
    pub fn transition(
        &self,
        lock: &SessionLock,
        status: SessionStatus,
        error: Option<SessionError>,
    ) -> Result<SessionState, SessionStoreError> {
        self.ensure_lock(lock)?;
        let current = self.read_state()?;
        if status == SessionStatus::Complete {
            return Err(SessionStoreError::InvalidTransition {
                from: current.status,
                to: status,
            });
        }
        if matches!(
            current.status,
            SessionStatus::Complete | SessionStatus::Failed
        ) {
            if current.status == SessionStatus::Failed
                && status == SessionStatus::Failed
                && current.error == error
            {
                return Ok(current);
            }
            return Err(SessionStoreError::InvalidTransition {
                from: current.status,
                to: status,
            });
        }
        crate::artifact::ensure_no_active_writer(self)?;
        if status != SessionStatus::Failed {
            self.ensure_no_ingest_intents()?;
        }
        let next = self.next_state(&current, status, error)?;
        let path = self.path.join(STATE_FILE);
        let bytes = serialize_json_document(&path, "session state", &next)?;
        self.ensure_additional_capacity(bytes_len(&bytes)?)?;
        write_serialized_json_atomic(&path, &bytes, false)?;
        Ok(next)
    }

    pub(crate) fn ensure_lifecycle_mutation_allowed(
        &self,
    ) -> Result<SessionState, SessionStoreError> {
        let state = self.read_state()?;
        if matches!(
            state.status,
            SessionStatus::Complete | SessionStatus::Failed
        ) {
            return Err(SessionStoreError::TerminalSessionMutation {
                status: state.status,
            });
        }
        Ok(state)
    }

    fn next_state(
        &self,
        current: &SessionState,
        status: SessionStatus,
        error: Option<SessionError>,
    ) -> Result<SessionState, SessionStoreError> {
        if !current.status.can_transition_to(status) {
            return Err(SessionStoreError::InvalidTransition {
                from: current.status,
                to: status,
            });
        }
        self.build_next_state(current, status, error)
    }

    fn next_completed_state(
        &self,
        current: &SessionState,
    ) -> Result<SessionState, SessionStoreError> {
        if !matches!(
            current.status,
            SessionStatus::Captured | SessionStatus::Processing
        ) {
            return Err(SessionStoreError::InvalidTransition {
                from: current.status,
                to: SessionStatus::Complete,
            });
        }
        self.build_next_state(current, SessionStatus::Complete, None)
    }

    fn build_next_state(
        &self,
        current: &SessionState,
        status: SessionStatus,
        error: Option<SessionError>,
    ) -> Result<SessionState, SessionStoreError> {
        let next = SessionState {
            schema: StateSchemaVersion,
            created_at: current.created_at.clone(),
            status,
            operation_id: current.operation_id.clone(),
            revision: current.revision.checked_add(1).ok_or_else(|| {
                SessionStoreError::InvalidDocument {
                    document: "session state",
                    message: "state revision overflow".to_owned(),
                }
            })?,
            updated_at: now_rfc3339(),
            error,
        };
        next.validate()
            .map_err(|error| SessionStoreError::InvalidDocument {
                document: "session state",
                message: error.to_string(),
            })?;
        Ok(next)
    }

    pub(crate) fn ensure_additional_capacity(
        &self,
        additional_bytes: u64,
    ) -> Result<(), SessionStoreError> {
        let baseline = directory_size(&self.path)?;
        ensure_peak_capacity(self.limits.max_session_bytes, baseline, additional_bytes)
    }

    pub(crate) fn ensure_artifact_catalog_slot(
        &self,
        artifact_id: &str,
        relative_path: &ArtifactPath,
    ) -> Result<(), SessionStoreError> {
        let artifacts = self.registered_artifacts(false)?;
        ensure_artifact_catalog_slot(&artifacts, artifact_id, relative_path)
    }

    pub(crate) fn catalog_records_unverified(
        &self,
    ) -> Result<Vec<t32perf_model::Artifact>, SessionStoreError> {
        let directory = self.path.join(ARTIFACT_INDEX_DIRECTORY);
        ensure_plain_directory(&directory)?;
        let mut entries = read_directory_entries_bounded(&directory, MAX_MANIFEST_ARTIFACTS)?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        let mut artifacts = Vec::with_capacity(entries.len());
        let mut identifiers = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for entry in entries {
            let path = entry.path();
            ensure_plain_file(&path)?;
            if path.extension() != Some(std::ffi::OsStr::new("json")) {
                return Err(SessionStoreError::InvalidDocument {
                    document: "artifact catalog",
                    message: format!("unexpected catalog entry `{}`", path.display()),
                });
            }
            let artifact: t32perf_model::Artifact =
                read_bounded_json(&path, "artifact catalog record", MAX_JSON_DOCUMENT_BYTES)?;
            artifact
                .validate()
                .map_err(|error| SessionStoreError::InvalidDocument {
                    document: "artifact catalog",
                    message: error.to_string(),
                })?;
            if path.file_stem().and_then(std::ffi::OsStr::to_str) != Some(artifact.id.as_str()) {
                return Err(SessionStoreError::InvalidDocument {
                    document: "artifact catalog",
                    message: format!("catalog filename does not match artifact `{}`", artifact.id),
                });
            }
            if !identifiers.insert(portable_name_key(&artifact.id)) {
                return Err(SessionStoreError::InvalidDocument {
                    document: "artifact catalog",
                    message: format!(
                        "artifact id `{}` has a portable-name collision",
                        artifact.id
                    ),
                });
            }
            if !paths.insert(artifact.relative_path.portable_key()) {
                return Err(SessionStoreError::InvalidDocument {
                    document: "artifact catalog",
                    message: format!(
                        "multiple artifacts use the portable path `{}`",
                        artifact.relative_path
                    ),
                });
            }
            artifacts.push(artifact);
        }
        artifacts.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(artifacts)
    }

    /// Reads the immutable manifest, if it has already been committed.
    pub fn manifest(&self) -> Result<Option<Manifest>, SessionStoreError> {
        let path = self.path.join(MANIFEST_FILE);
        if !path_entry_exists(&path)? {
            return Ok(None);
        }
        let manifest: Manifest = read_bounded_json(&path, "manifest", MAX_JSON_DOCUMENT_BYTES)?;
        self.validate_manifest(&manifest, false)?;
        Ok(Some(manifest))
    }

    /// Registers immutable artifact metadata in the append-only durable catalog.
    ///
    /// Re-registering byte-for-byte equivalent metadata is idempotent. The
    /// artifact file is deeply verified before its record becomes visible.
    pub fn register_artifact(
        &self,
        lock: &SessionLock,
        artifact: &t32perf_model::Artifact,
    ) -> Result<(), SessionStoreError> {
        self.ensure_lock(lock)?;
        crate::artifact::ensure_no_active_writer(self)?;
        artifact
            .validate()
            .map_err(|error| SessionStoreError::InvalidArtifactSpec {
                message: error.to_string(),
            })?;
        let artifacts = self.registered_artifacts(false)?;
        let artifact_key = portable_name_key(&artifact.id);
        if let Some(existing) = artifacts
            .iter()
            .find(|existing| portable_name_key(&existing.id) == artifact_key)
        {
            return if existing == artifact {
                self.verify_artifact(artifact, true)?;
                Ok(())
            } else {
                Err(SessionStoreError::ArtifactRecordConflict {
                    artifact_id: artifact.id.clone(),
                })
            };
        }
        self.ensure_lifecycle_mutation_allowed()?;
        ensure_artifact_catalog_slot(&artifacts, &artifact.id, &artifact.relative_path)?;
        let path = self
            .path
            .join(ARTIFACT_INDEX_DIRECTORY)
            .join(format!("{}.json", artifact.id));
        let bytes = serialize_json_document(&path, "artifact catalog record", artifact)?;
        self.ensure_additional_capacity(bytes_len(&bytes)?)?;
        self.verify_artifact(artifact, true)?;
        write_serialized_json_atomic(&path, &bytes, true)
    }

    /// Reads the append-only artifact catalog in stable identifier order.
    pub fn registered_artifacts(
        &self,
        deep: bool,
    ) -> Result<Vec<t32perf_model::Artifact>, SessionStoreError> {
        let artifacts = self.catalog_records_unverified()?;
        for artifact in &artifacts {
            self.verify_artifact(artifact, deep)?;
        }
        Ok(artifacts)
    }

    /// Verifies manifest semantics and all referenced artifacts.
    pub fn validate_manifest(
        &self,
        manifest: &Manifest,
        deep: bool,
    ) -> Result<(), SessionStoreError> {
        if manifest.session_id != self.id.as_str() {
            return Err(SessionStoreError::ManifestSessionMismatch {
                expected: self.id.to_string(),
                actual: manifest.session_id.clone(),
            });
        }
        manifest
            .validate()
            .map_err(|error| SessionStoreError::InvalidDocument {
                document: "manifest",
                message: error.to_string(),
            })?;
        let mut registered = self.registered_artifacts(deep)?;
        let mut declared = manifest.artifacts.clone();
        registered.sort_by(|left, right| left.id.cmp(&right.id));
        declared.sort_by(|left, right| left.id.cmp(&right.id));
        if registered != declared {
            return Err(SessionStoreError::ArtifactCatalogMismatch);
        }
        for artifact in &manifest.artifacts {
            self.verify_artifact(artifact, deep)?;
        }
        let total = directory_size(&self.path)?;
        if total > self.limits.max_session_bytes {
            return Err(SessionStoreError::SessionLimitExceeded {
                limit_bytes: self.limits.max_session_bytes,
                actual_bytes: total,
            });
        }
        Ok(())
    }

    /// Commits the immutable manifest and then atomically marks the Session complete.
    ///
    /// The operation is retry-safe: after a crash between the two commits, the same
    /// manifest may be supplied again and the state transition will finish.
    pub fn finalize(
        &self,
        lock: &SessionLock,
        manifest: &Manifest,
    ) -> Result<SessionState, SessionStoreError> {
        self.ensure_lock(lock)?;
        crate::artifact::ensure_no_active_writer(self)?;
        let state = self.read_state()?;
        if !state.status.can_finalize() {
            return Err(SessionStoreError::InvalidTransition {
                from: state.status,
                to: SessionStatus::Complete,
            });
        }
        self.ensure_no_ingest_intents()?;
        self.validate_manifest(manifest, true)?;

        let path = self.path.join(MANIFEST_FILE);
        let manifest_exists = path_entry_exists(&path)?;
        if manifest_exists {
            let existing: Manifest = read_bounded_json(&path, "manifest", MAX_JSON_DOCUMENT_BYTES)?;
            if existing != *manifest {
                return Err(SessionStoreError::ManifestConflict);
            }
        }
        if state.status == SessionStatus::Complete {
            if !manifest_exists {
                return Err(SessionStoreError::InvalidDocument {
                    document: "manifest",
                    message: "complete Session is missing its immutable manifest".to_owned(),
                });
            }
            return Ok(state);
        }

        let next = self.next_completed_state(&state)?;
        let state_path = self.path.join(STATE_FILE);
        let state_bytes = serialize_json_document(&state_path, "session state", &next)?;
        let manifest_bytes = if manifest_exists {
            None
        } else {
            Some(serialize_json_document(&path, "manifest", manifest)?)
        };
        let additional = bytes_len(&state_bytes)?
            .checked_add(
                manifest_bytes
                    .as_ref()
                    .map_or(Ok(0), |bytes| bytes_len(bytes))?,
            )
            .ok_or(SessionStoreError::SessionLimitExceeded {
                limit_bytes: self.limits.max_session_bytes,
                actual_bytes: u64::MAX,
            })?;
        self.ensure_additional_capacity(additional)?;

        if let Some(bytes) = manifest_bytes {
            write_serialized_json_atomic(&path, &bytes, true)?;
        }
        write_serialized_json_atomic(&state_path, &state_bytes, false)?;
        Ok(next)
    }
}

fn ensure_artifact_catalog_slot(
    artifacts: &[t32perf_model::Artifact],
    artifact_id: &str,
    relative_path: &ArtifactPath,
) -> Result<(), SessionStoreError> {
    let attempted =
        artifacts
            .len()
            .checked_add(1)
            .ok_or(SessionStoreError::ArtifactCountExceeded {
                limit: MAX_MANIFEST_ARTIFACTS,
                actual: usize::MAX,
            })?;
    if attempted > MAX_MANIFEST_ARTIFACTS {
        return Err(SessionStoreError::ArtifactCountExceeded {
            limit: MAX_MANIFEST_ARTIFACTS,
            actual: attempted,
        });
    }
    let artifact_key = portable_name_key(artifact_id);
    if artifacts
        .iter()
        .any(|artifact| portable_name_key(&artifact.id) == artifact_key)
    {
        return Err(SessionStoreError::ArtifactRecordConflict {
            artifact_id: artifact_id.to_owned(),
        });
    }
    let path_key = relative_path.portable_key();
    if artifacts
        .iter()
        .any(|artifact| artifact.relative_path.portable_key() == path_key)
    {
        return Err(SessionStoreError::InvalidArtifactSpec {
            message: format!("artifact path `{relative_path}` is already registered"),
        });
    }
    Ok(())
}

/// RAII guard proving exclusive ownership of one Session operation.
#[derive(Debug)]
pub struct SessionLock {
    file: File,
    session_path: PathBuf,
    _namespace_lease: Arc<NamespaceLease>,
}

/// RAII guard proving exclusive ownership of top-level Session namespace changes.
#[derive(Debug, Clone)]
pub struct ArtifactRootNamespaceLock {
    lease: Arc<NamespaceLease>,
}

impl Drop for SessionLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
        remove_process_lock(&self.session_path);
    }
}

impl Drop for NamespaceLease {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
        release_root_namespace_process_lock(&self.root_path, self.mode);
    }
}

fn process_locks() -> &'static Mutex<BTreeSet<PathBuf>> {
    PROCESS_LOCKS.get_or_init(|| Mutex::new(BTreeSet::new()))
}

fn remove_process_lock(path: &Path) {
    process_locks()
        .lock()
        .expect("process lock registry poisoned")
        .remove(path);
}

fn root_namespace_process_locks() -> &'static Mutex<BTreeMap<PathBuf, NamespaceProcessState>> {
    ROOT_NAMESPACE_LOCKS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn reserve_root_namespace_process_lock(
    path: &Path,
    mode: NamespaceLockMode,
) -> Result<(), SessionStoreError> {
    let mut locks = root_namespace_process_locks()
        .lock()
        .expect("artifact-root namespace lock registry poisoned");
    let state = locks.entry(path.to_path_buf()).or_default();
    let conflicted = match mode {
        NamespaceLockMode::Shared => state.exclusive,
        NamespaceLockMode::Exclusive => state.exclusive || state.shared != 0,
    };
    if conflicted {
        return Err(SessionStoreError::ArtifactRootNamespaceLocked {
            path: path.to_path_buf(),
        });
    }
    match mode {
        NamespaceLockMode::Shared => {
            state.shared = state.shared.checked_add(1).ok_or_else(|| {
                SessionStoreError::ArtifactRootNamespaceLocked {
                    path: path.to_path_buf(),
                }
            })?;
        }
        NamespaceLockMode::Exclusive => state.exclusive = true,
    }
    Ok(())
}

fn release_root_namespace_process_lock(path: &Path, mode: NamespaceLockMode) {
    let mut locks = root_namespace_process_locks()
        .lock()
        .expect("artifact-root namespace lock registry poisoned");
    let Some(state) = locks.get_mut(path) else {
        return;
    };
    match mode {
        NamespaceLockMode::Shared => state.shared = state.shared.saturating_sub(1),
        NamespaceLockMode::Exclusive => state.exclusive = false,
    }
    if state.shared == 0 && !state.exclusive {
        locks.remove(path);
    }
}

fn acquire_namespace_lease(
    root_path: &Path,
    mode: NamespaceLockMode,
) -> Result<Arc<NamespaceLease>, SessionStoreError> {
    reserve_root_namespace_process_lock(root_path, mode)?;
    let path = root_path.join(ROOT_NAMESPACE_LOCK_FILE);
    let (file, _) = match open_or_create_plain_file(&path, true) {
        Ok(opened) => opened,
        Err(error) => {
            release_root_namespace_process_lock(root_path, mode);
            return Err(error);
        }
    };
    let lock_result = match mode {
        NamespaceLockMode::Shared => fs2::FileExt::try_lock_shared(&file),
        NamespaceLockMode::Exclusive => file.try_lock_exclusive(),
    };
    if let Err(error) = lock_result {
        release_root_namespace_process_lock(root_path, mode);
        return Err(if lock_is_contended(&error) {
            SessionStoreError::ArtifactRootNamespaceLocked {
                path: root_path.to_path_buf(),
            }
        } else {
            io_error("lock artifact-root Session namespace", &path, error)
        });
    }
    if let Err(error) = ensure_opened_file_identity(&path, &file) {
        let _ = fs2::FileExt::unlock(&file);
        release_root_namespace_process_lock(root_path, mode);
        return Err(error);
    }
    Ok(Arc::new(NamespaceLease {
        file,
        root_path: root_path.to_path_buf(),
        mode,
    }))
}

fn lock_is_contended(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(windows)]
    {
        const ERROR_LOCK_VIOLATION: i32 = 33;
        if error.raw_os_error() == Some(ERROR_LOCK_VIOLATION) {
            return true;
        }
    }
    false
}

fn cleanup_private_session_directory(
    path: &Path,
    initialization: SessionStoreError,
) -> SessionStoreError {
    if let Err(cleanup) = ensure_plain_directory(path).and_then(|_| {
        fs::remove_dir_all(path)
            .map_err(|error| io_error("remove private Session directory", path, error))
    }) {
        let cleanup = match cleanup {
            SessionStoreError::Io { source, .. } => source,
            other => io::Error::other(other.to_string()),
        };
        return SessionStoreError::SessionInitializationCleanupFailed {
            path: path.to_path_buf(),
            initialization: initialization.to_string(),
            cleanup,
        };
    }
    initialization
}

pub(crate) fn path_entry_exists(path: &Path) -> Result<bool, SessionStoreError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error("inspect filesystem entry", path, error)),
    }
}

fn find_session_name_conflict(
    root: &Path,
    requested: &SessionId,
) -> Result<Option<SessionId>, SessionStoreError> {
    let requested_key = portable_name_key(requested.as_str());
    let entries =
        fs::read_dir(root).map_err(|error| io_error("list artifact root", root, error))?;
    for entry in entries {
        let entry = entry.map_err(|error| io_error("read artifact-root entry", root, error))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(existing) = SessionId::new(name) else {
            continue;
        };
        if portable_name_key(existing.as_str()) == requested_key {
            return Ok(Some(existing));
        }
    }
    Ok(None)
}

pub(crate) fn read_directory_entries_bounded(
    directory: &Path,
    limit: usize,
) -> Result<Vec<fs::DirEntry>, SessionStoreError> {
    let entries = fs::read_dir(directory)
        .map_err(|error| io_error("list bounded directory", directory, error))?;
    let mut bounded = Vec::with_capacity(limit.min(256));
    for entry in entries {
        let entry =
            entry.map_err(|error| io_error("read bounded directory entry", directory, error))?;
        if bounded.len() == limit {
            return Err(SessionStoreError::ArtifactCountExceeded {
                limit,
                actual: limit.saturating_add(1),
            });
        }
        bounded.push(entry);
    }
    Ok(bounded)
}

pub(crate) fn read_bounded_json<T: DeserializeOwned>(
    path: &Path,
    document: &'static str,
    limit_bytes: u64,
) -> Result<T, SessionStoreError> {
    let (mut file, metadata) = open_existing_plain_file(path, false)?;
    ensure_metadata_size(document, metadata.len(), limit_bytes)?;
    let capacity = usize::try_from(metadata.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take(limit_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| io_error("read bounded JSON document", path, error))?;
    let actual_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    ensure_metadata_size(document, actual_bytes, limit_bytes)?;
    ensure_opened_file_identity(path, &file)?;
    strict_json::from_slice(&bytes).map_err(|source| SessionStoreError::Json {
        path: path.to_path_buf(),
        source,
    })
}

fn ensure_metadata_size(
    document: &'static str,
    actual_bytes: u64,
    limit_bytes: u64,
) -> Result<(), SessionStoreError> {
    if actual_bytes > limit_bytes {
        return Err(SessionStoreError::MetadataLimitExceeded {
            document,
            limit_bytes,
            actual_bytes,
        });
    }
    Ok(())
}

pub(crate) fn serialize_json_document<T: Serialize>(
    path: &Path,
    document: &'static str,
    value: &T,
) -> Result<Vec<u8>, SessionStoreError> {
    serialize_json_document_with_limit(path, document, value, MAX_JSON_DOCUMENT_BYTES)
}

fn serialize_json_document_with_limit<T: Serialize>(
    path: &Path,
    document: &'static str,
    value: &T,
    limit_bytes: u64,
) -> Result<Vec<u8>, SessionStoreError> {
    let mut buffer = BoundedJsonBuffer::new(limit_bytes);
    if let Err(source) = serde_json::to_writer_pretty(&mut buffer, value) {
        if let Some(actual_bytes) = buffer.exceeded_at {
            return Err(SessionStoreError::MetadataLimitExceeded {
                document,
                limit_bytes,
                actual_bytes,
            });
        }
        return Err(SessionStoreError::Json {
            path: path.to_path_buf(),
            source,
        });
    }
    if let Err(error) = buffer.write_all(b"\n") {
        if let Some(actual_bytes) = buffer.exceeded_at {
            return Err(SessionStoreError::MetadataLimitExceeded {
                document,
                limit_bytes,
                actual_bytes,
            });
        }
        return Err(io_error("serialize JSON document", path, error));
    }
    Ok(buffer.bytes)
}

pub(crate) fn write_serialized_json_atomic(
    path: &Path,
    bytes: &[u8],
    must_not_exist: bool,
) -> Result<(), SessionStoreError> {
    if !must_not_exist && path_entry_exists(path)? {
        ensure_plain_file(path)?;
    }
    if must_not_exist && path_entry_exists(path)? {
        return Err(SessionStoreError::ArtifactExists {
            path: path.to_path_buf(),
        });
    }
    let mut file = AtomicWriteFile::open(path)
        .map_err(|error| io_error("open atomic JSON document", path, error))?;
    file.write_all(bytes)
        .map_err(|error| io_error("write atomic JSON document", path, error))?;
    if must_not_exist && path_entry_exists(path)? {
        file.discard()
            .map_err(|error| io_error("discard atomic JSON document", path, error))?;
        return Err(SessionStoreError::ArtifactExists {
            path: path.to_path_buf(),
        });
    }
    file.commit()
        .map_err(|error| io_error("commit atomic JSON document", path, error))
}

struct BoundedJsonBuffer {
    bytes: Vec<u8>,
    limit_bytes: u64,
    exceeded_at: Option<u64>,
}

impl BoundedJsonBuffer {
    fn new(limit_bytes: u64) -> Self {
        Self {
            bytes: Vec::new(),
            limit_bytes,
            exceeded_at: None,
        }
    }
}

impl io::Write for BoundedJsonBuffer {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let current = u64::try_from(self.bytes.len()).unwrap_or(u64::MAX);
        let requested = u64::try_from(buffer.len()).unwrap_or(u64::MAX);
        let attempted = current.saturating_add(requested);
        if attempted > self.limit_bytes {
            self.exceeded_at = Some(attempted);
            return Err(io::Error::other("JSON document exceeds its byte limit"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bytes_len(bytes: &[u8]) -> Result<u64, SessionStoreError> {
    u64::try_from(bytes.len()).map_err(|_| SessionStoreError::SessionLimitExceeded {
        limit_bytes: u64::MAX,
        actual_bytes: u64::MAX,
    })
}

fn ensure_peak_capacity(
    limit_bytes: u64,
    baseline_bytes: u64,
    additional_bytes: u64,
) -> Result<(), SessionStoreError> {
    let actual_bytes = baseline_bytes.checked_add(additional_bytes).ok_or(
        SessionStoreError::SessionLimitExceeded {
            limit_bytes,
            actual_bytes: u64::MAX,
        },
    )?;
    if actual_bytes > limit_bytes {
        return Err(SessionStoreError::SessionLimitExceeded {
            limit_bytes,
            actual_bytes,
        });
    }
    Ok(())
}

fn now_rfc3339() -> String {
    Timestamp::now().to_string()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::{ArtifactRoot, SessionLimits, read_directory_entries_bounded};
    use crate::{SessionId, SessionStoreError};

    #[test]
    fn bounded_directory_iteration_stops_at_limit_plus_one() {
        let temp = TempDir::new().unwrap();
        for name in ["a", "b", "c"] {
            fs::write(temp.path().join(name), b"").unwrap();
        }
        assert!(matches!(
            read_directory_entries_bounded(temp.path(), 2),
            Err(SessionStoreError::ArtifactCountExceeded {
                limit: 2,
                actual: 3
            })
        ));
    }

    #[test]
    fn artifact_root_listing_fails_closed_at_its_entry_bound() {
        let temp = TempDir::new().unwrap();
        let root = ArtifactRoot::open(temp.path(), SessionLimits::default()).unwrap();
        for id in ["session-a", "session-b", "session-c"] {
            root.create_session_with_id(SessionId::new(id).unwrap(), &serde_json::json!({}))
                .unwrap();
        }
        assert!(matches!(
            root.list_sessions_bounded(2),
            Err(SessionStoreError::DirectoryEntryLimitExceeded {
                limit: 2,
                actual: 3
            })
        ));
    }
}
