//! Session filesystem and lifecycle errors.

use std::{io, path::PathBuf};

use t32perf_model::SessionStatus;
use thiserror::Error;

/// A failure while managing a session or one of its artifacts.
#[derive(Debug, Error)]
pub enum SessionStoreError {
    /// A filesystem operation failed.
    #[error("failed to {operation} `{path}`: {source}")]
    Io {
        /// Short operation description.
        operation: &'static str,
        /// Path involved in the operation.
        path: PathBuf,
        /// Operating-system error.
        #[source]
        source: io::Error,
    },
    /// A JSON document could not be encoded or decoded.
    #[error("invalid JSON document `{path}`: {source}")]
    Json {
        /// JSON document path.
        path: PathBuf,
        /// Serialization error.
        #[source]
        source: serde_json::Error,
    },
    /// The artifact root is not a plain directory.
    #[error("artifact root is not a plain directory: `{path}`")]
    InvalidRoot {
        /// Rejected root path.
        path: PathBuf,
    },
    /// A symbolic link, junction, or other reparse point crossed the trust boundary.
    #[error("links and reparse points are not permitted in session paths: `{path}`")]
    LinkNotAllowed {
        /// Rejected path.
        path: PathBuf,
    },
    /// The filesystem entry changed between opening it and checking its path.
    #[error("filesystem entry identity changed while opening `{path}`")]
    FileIdentityChanged {
        /// Path whose current entry no longer names the opened handle.
        path: PathBuf,
    },
    /// A resolved path escaped the configured artifact root.
    #[error("resolved path escapes the artifact root: `{path}`")]
    OutsideArtifactRoot {
        /// Rejected resolved path.
        path: PathBuf,
    },
    /// A session identifier did not match the stable portable format.
    #[error("invalid session id `{value}`")]
    InvalidSessionId {
        /// Rejected identifier.
        value: String,
    },
    /// A session already exists and cannot be overwritten.
    #[error("session already exists: `{session_id}`")]
    SessionExists {
        /// Existing session identifier.
        session_id: String,
    },
    /// A requested session does not exist.
    #[error("session does not exist: `{session_id}`")]
    SessionNotFound {
        /// Missing session identifier.
        session_id: String,
    },
    /// Another process or operation owns the session lock.
    #[error("session is locked by another operation: `{session_id}`")]
    SessionLocked {
        /// Locked session identifier.
        session_id: String,
    },
    /// Another process or operation owns the artifact-root Session namespace lock.
    #[error("artifact-root Session namespace is locked: `{path}`")]
    ArtifactRootNamespaceLocked {
        /// Canonical artifact root whose namespace is locked.
        path: PathBuf,
    },
    /// Cleaning a private, unpublished Session directory failed after initialization failed.
    #[error(
        "Session initialization failed for `{path}`: {initialization}; cleanup also failed: {cleanup}"
    )]
    SessionInitializationCleanupFailed {
        /// Private unpublished directory created by this operation.
        path: PathBuf,
        /// Original initialization or publication failure.
        initialization: String,
        /// Cleanup failure.
        #[source]
        cleanup: io::Error,
    },
    /// A lock from another session was supplied to an operation.
    #[error("session lock does not belong to `{session_id}`")]
    LockMismatch {
        /// Expected session identifier.
        session_id: String,
    },
    /// An exclusive namespace lease belongs to another artifact root.
    #[error("artifact-root namespace lease does not belong to `{root}`")]
    NamespaceLockMismatch {
        /// Expected canonical artifact root.
        root: PathBuf,
    },
    /// The requested lifecycle transition is not permitted.
    #[error("invalid session state transition from {from:?} to {to:?}")]
    InvalidTransition {
        /// Current status.
        from: SessionStatus,
        /// Requested status.
        to: SessionStatus,
    },
    /// A terminal Session cannot accept a new lifecycle mutation.
    #[error("session is terminal in state {status:?}; no new mutation is permitted")]
    TerminalSessionMutation {
        /// Durable terminal status that rejected the mutation.
        status: SessionStatus,
    },
    /// A model document failed its semantic validation.
    #[error("invalid {document}: {message}")]
    InvalidDocument {
        /// Document family.
        document: &'static str,
        /// Validation detail.
        message: String,
    },
    /// A manifest belongs to another session.
    #[error("manifest session `{actual}` does not match `{expected}`")]
    ManifestSessionMismatch {
        /// Expected session identifier.
        expected: String,
        /// Manifest session identifier.
        actual: String,
    },
    /// An immutable manifest already exists with different content.
    #[error("an immutable manifest with different content already exists")]
    ManifestConflict,
    /// The manifest does not match the append-only artifact catalog.
    #[error("manifest artifact list does not match the durable artifact catalog")]
    ArtifactCatalogMismatch,
    /// An artifact identifier is already registered with different metadata.
    #[error("artifact `{artifact_id}` is already registered with different metadata")]
    ArtifactRecordConflict {
        /// Conflicting artifact identifier.
        artifact_id: String,
    },
    /// Durable staged-ingest metadata or filesystem state conflicts with the requested ingest.
    #[error("staged ingest for artifact `{artifact_id}` is conflicted: {message}")]
    IngestIntentConflict {
        /// Artifact identifier named by the attempted ingest.
        artifact_id: String,
        /// Exact inconsistency that prevented safe recovery.
        message: String,
    },
    /// An artifact destination already exists and cannot be overwritten.
    #[error("artifact already exists: `{path}`")]
    ArtifactExists {
        /// Existing artifact path.
        path: PathBuf,
    },
    /// A required artifact does not exist.
    #[error("artifact does not exist: `{path}`")]
    ArtifactNotFound {
        /// Missing artifact path.
        path: PathBuf,
    },
    /// A staged file is outside the capture staging directory.
    #[error("staged input must be below capture/staging: `{path}`")]
    InvalidStagingPath {
        /// Rejected staging path.
        path: String,
    },
    /// An artifact is not a plain regular file.
    #[error("artifact is not a plain regular file: `{path}`")]
    NotRegularFile {
        /// Rejected path.
        path: PathBuf,
    },
    /// One artifact exceeds the configured file-size limit.
    #[error("artifact size {actual_bytes} exceeds limit {limit_bytes}")]
    FileLimitExceeded {
        /// Configured limit.
        limit_bytes: u64,
        /// Attempted size.
        actual_bytes: u64,
    },
    /// A Session exceeds its configured total-size limit.
    #[error("session size {actual_bytes} exceeds limit {limit_bytes}")]
    SessionLimitExceeded {
        /// Configured limit.
        limit_bytes: u64,
        /// Attempted total size.
        actual_bytes: u64,
    },
    /// One managed JSON metadata document exceeds its independent safety bound.
    #[error("{document} metadata size {actual_bytes} exceeds limit {limit_bytes}")]
    MetadataLimitExceeded {
        /// Document family being serialized.
        document: &'static str,
        /// Independent metadata-document limit.
        limit_bytes: u64,
        /// Attempted serialized size.
        actual_bytes: u64,
    },
    /// The durable catalog already contains the maximum number of artifacts.
    #[error("artifact catalog has {actual} records; maximum is {limit}")]
    ArtifactCountExceeded {
        /// Maximum permitted catalog record count.
        limit: usize,
        /// Attempted catalog record count.
        actual: usize,
    },
    /// Recursive Session accounting encountered too many filesystem entries.
    #[error("session directory has {actual} entries; traversal maximum is {limit}")]
    DirectoryEntryLimitExceeded {
        /// Maximum filesystem entry count visited by one traversal.
        limit: usize,
        /// Attempted entry count.
        actual: usize,
    },
    /// Recursive Session accounting exceeded its bounded directory depth.
    #[error("session directory depth exceeds {limit} at `{path}`")]
    DirectoryDepthLimitExceeded {
        /// Maximum permitted directory nesting below the Session root.
        limit: usize,
        /// First directory beyond the depth limit.
        path: PathBuf,
    },
    /// A portable case-folded Session identifier collides with an existing entry.
    #[error("session id `{requested}` conflicts with existing Session `{existing}`")]
    SessionNameConflict {
        /// Requested identifier.
        requested: String,
        /// Existing identifier with the same portable key.
        existing: String,
    },
    /// A Session already has an unfinished bounded artifact writer.
    #[error("session already has an active artifact writer: `{session_id}`")]
    ArtifactWriterActive {
        /// Session whose writer reservation is active.
        session_id: String,
    },
    /// An artifact writer was supplied to a different Session.
    #[error("artifact writer does not belong to session `{session_id}`")]
    ArtifactWriterSessionMismatch {
        /// Session receiving the foreign writer.
        session_id: String,
    },
    /// An artifact's size differs from the manifest.
    #[error("artifact `{artifact_id}` size mismatch: expected {expected}, found {actual}")]
    ArtifactSizeMismatch {
        /// Artifact identifier.
        artifact_id: String,
        /// Manifest size.
        expected: u64,
        /// Observed size.
        actual: u64,
    },
    /// An artifact's digest differs from the manifest.
    #[error("artifact `{artifact_id}` SHA-256 mismatch")]
    ArtifactDigestMismatch {
        /// Artifact identifier.
        artifact_id: String,
    },
    /// An artifact specification contains an invalid identifier or field.
    #[error("invalid artifact specification: {message}")]
    InvalidArtifactSpec {
        /// Validation detail.
        message: String,
    },
}

pub(crate) fn io_error(
    operation: &'static str,
    path: impl Into<PathBuf>,
    source: io::Error,
) -> SessionStoreError {
    SessionStoreError::Io {
        operation,
        path: path.into(),
        source,
    }
}
