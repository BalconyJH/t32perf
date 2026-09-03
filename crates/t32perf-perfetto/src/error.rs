use std::{io, path::PathBuf};

use t32perf_model::{DerivedValidationError, ObservationValidationError};
use thiserror::Error;

/// An error produced while converting model events to Chrome Trace JSON.
#[derive(Debug, Error)]
pub enum ExportError {
    /// The configured session identifier is empty.
    #[error("trace export session_id is empty")]
    EmptySessionId,
    /// A dictionary belongs to a different session.
    #[error(
        "dictionary session `{dictionary_session_id}` does not match export session `{export_session_id}`"
    )]
    DictionarySessionMismatch {
        /// Session declared by the dictionary.
        dictionary_session_id: String,
        /// Session configured for the export.
        export_session_id: String,
    },
    /// A dictionary entry redefines an existing identifier of the same kind.
    #[error("duplicate {entity_kind} dictionary identifier `{id}`")]
    DuplicateDictionaryEntry {
        /// Dictionary entity kind.
        entity_kind: &'static str,
        /// Duplicated identifier.
        id: String,
    },
    /// A dictionary was registered after trace events had started.
    #[error("dictionaries must be registered before the first trace event")]
    DictionaryAfterEvents,
    /// The reserved dynamic track identifier space is exhausted.
    #[error("the Chrome Trace dynamic track identifier space is exhausted")]
    TrackIdSpaceExhausted,
    /// A core identifier cannot fit in the reserved scheduling-track range.
    #[error("core id {core_id} exceeds the Chrome Trace scheduling-track range")]
    CoreIdOutOfRange {
        /// Rejected core identifier.
        core_id: u32,
    },
    /// A synchronous custom span identifier is already active on its track.
    #[error("custom span `{span_id}` is already active on pid {pid}, tid {tid}")]
    DuplicateOpenSpan {
        /// Chrome Trace process identifier.
        pid: u64,
        /// Chrome Trace thread identifier.
        tid: u32,
        /// Duplicated source span identifier.
        span_id: String,
    },
    /// An asynchronous correlation identifier is already active for its source.
    #[error("async correlation `{correlation_id}` is already active for source `{source_id}`")]
    DuplicateOpenAsync {
        /// Source stream identifier.
        source_id: String,
        /// Duplicated correlation identifier.
        correlation_id: String,
    },
    /// A synchronous custom span end has no matching open begin on its track.
    #[error("custom span `{span_id}` has no matching begin on pid {pid}, tid {tid}")]
    UnmatchedSpanEnd {
        /// Chrome Trace process identifier.
        pid: u64,
        /// Chrome Trace thread identifier.
        tid: u32,
        /// Unmatched source span identifier.
        span_id: String,
    },
    /// An asynchronous end has no matching open begin for its source.
    #[error("async correlation `{correlation_id}` has no matching begin for source `{source_id}`")]
    UnmatchedAsyncEnd {
        /// Source stream identifier.
        source_id: String,
        /// Unmatched correlation identifier.
        correlation_id: String,
    },
    /// The writer was finished while custom spans remained open.
    #[error(
        "trace export has {sync_count} unclosed synchronous and {async_count} unclosed asynchronous spans"
    )]
    UnclosedCustomSpans {
        /// Number of synchronous spans still open.
        sync_count: usize,
        /// Number of asynchronous spans still open.
        async_count: usize,
    },
    /// The configured resident-state limit for open custom spans was reached.
    #[error("open custom span limit {limit} exceeded")]
    OpenCustomSpanLimitExceeded {
        /// Configured combined synchronous and asynchronous limit.
        limit: usize,
    },
    /// A derived function span violates the model invariants.
    #[error("invalid derived function span: {0}")]
    InvalidSpan(#[from] DerivedValidationError),
    /// A normalized observation violates the model invariants.
    #[error("invalid normalized observation: {0}")]
    InvalidObservation(#[from] ObservationValidationError),
    /// JSON serialization or self-validation failed.
    #[error("JSON processing failed: {0}")]
    Json(#[from] serde_json::Error),
    /// Reading, writing, flushing, syncing, or renaming a file failed.
    #[error("I/O operation failed: {0}")]
    Io(#[from] io::Error),
    /// Atomic export requires a target path with a file name.
    #[error("atomic export target has no file name: `{0}`")]
    MissingTargetFileName(PathBuf),
    /// Atomic export does not replace an existing artifact.
    #[error("atomic export target already exists: `{0}`")]
    TargetExists(PathBuf),
    /// No unique sibling temporary path could be reserved.
    #[error("could not reserve a temporary file beside `{0}`")]
    TemporaryPathExhausted(PathBuf),
}
