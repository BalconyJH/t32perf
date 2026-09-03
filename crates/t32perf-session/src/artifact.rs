//! Immutable artifact creation, staging ingest, hashing, and verification.

use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{self, Read, Seek, Write},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

use atomic_write_file::AtomicWriteFile;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use t32perf_model::{
    Artifact, ArtifactPath, MAX_ARTIFACT_INPUTS, MAX_MANIFEST_ARTIFACTS, Sha256Digest,
    is_portable_artifact_id, portable_name_key,
};
use uuid::Uuid;

use crate::{
    SessionLock, SessionStoreError,
    error::io_error,
    path::{
        create_new_plain_file, directory_size, ensure_opened_file_identity, ensure_plain_directory,
        ensure_plain_file, open_existing_plain_file, resolve_artifact,
    },
    session::{
        ARTIFACT_INDEX_DIRECTORY, COMMITTED_STAGING_SOURCE_DIRECTORY, INGEST_INTENT_DIRECTORY,
        Session, path_entry_exists, read_bounded_json, read_directory_entries_bounded,
        serialize_json_document, write_serialized_json_atomic,
    },
};

const MAX_SHORT_METADATA_BYTES: usize = 256;
const MAX_INGEST_INTENT_BYTES: u64 = 64 * 1024;
static ACTIVE_WRITERS: OnceLock<Mutex<BTreeSet<PathBuf>>> = OnceLock::new();

/// Schema identifier for durable staged-ingest recovery metadata.
pub const INGEST_INTENT_SCHEMA: &str = "t32perf.ingest-intent/v2";
const LEGACY_INGEST_INTENT_SCHEMA: &str = "t32perf.ingest-intent/v1";
const COMMITTED_STAGING_SOURCE_SCHEMA: &str = "t32perf.committed-staging-source/v1";

/// Read-only classification of one durable staged-ingest intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IngestIntentClassification {
    /// The host-owned private copy is intact and can be atomically published.
    Pending,
    /// The destination is intact and only its append-only catalog record is missing.
    Resumable,
    /// The destination and catalog are committed, but the exact intent still needs deletion.
    CommittedStale,
    /// Metadata or filesystem evidence is inconsistent and must not be changed automatically.
    Conflict,
}

/// Read-only evidence for one entry in the Session ingest-intent directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IngestIntentInspection {
    /// Session-relative path of the inspected control entry.
    pub intent_relative_path: String,
    /// Artifact identifier, when a valid intent could be decoded.
    pub artifact_id: Option<String>,
    /// Staging path relative to `capture/staging`, when available.
    pub staged_relative_path: Option<ArtifactPath>,
    /// Immutable artifact destination, when available.
    pub destination_relative_path: Option<ArtifactPath>,
    /// Recovery classification derived without changing the Session.
    pub classification: IngestIntentClassification,
    /// Bounded human-readable reason for the classification.
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct IngestIntent {
    schema: String,
    session_id: String,
    operation_id: String,
    staged_relative_path: ArtifactPath,
    #[serde(default)]
    private_relative_path: Option<ArtifactPath>,
    #[serde(default)]
    phase: IngestIntentPhase,
    artifact: Artifact,
}

/// Durable evidence that a committed artifact retains an exact staging source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedStagingSource {
    /// Stable committed artifact identifier.
    pub artifact_id: String,
    /// Session-relative path below `capture/staging`.
    pub staged_relative_path: ArtifactPath,
    /// Exact size of the retained source bytes.
    pub size_bytes: u64,
    /// Exact SHA-256 digest of the retained source bytes.
    pub sha256: Sha256Digest,
    /// Destination path of the bound committed artifact.
    pub artifact_relative_path: ArtifactPath,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommittedStagingSourceRecord {
    schema: String,
    session_id: String,
    source: CommittedStagingSource,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "schema", deny_unknown_fields)]
enum IngestIntentDocument {
    #[serde(rename = "t32perf.ingest-intent/v1")]
    V1 {
        session_id: String,
        operation_id: String,
        staged_relative_path: ArtifactPath,
        artifact: Artifact,
    },
    #[serde(rename = "t32perf.ingest-intent/v2")]
    V2 {
        session_id: String,
        operation_id: String,
        staged_relative_path: ArtifactPath,
        #[serde(default)]
        private_relative_path: Option<ArtifactPath>,
        #[serde(default)]
        phase: IngestIntentPhase,
        artifact: Artifact,
    },
}

impl From<IngestIntentDocument> for IngestIntent {
    fn from(document: IngestIntentDocument) -> Self {
        match document {
            IngestIntentDocument::V1 {
                session_id,
                operation_id,
                staged_relative_path,
                artifact,
            } => Self {
                schema: LEGACY_INGEST_INTENT_SCHEMA.to_owned(),
                session_id,
                operation_id,
                staged_relative_path,
                private_relative_path: None,
                phase: IngestIntentPhase::Ready,
                artifact,
            },
            IngestIntentDocument::V2 {
                session_id,
                operation_id,
                staged_relative_path,
                private_relative_path,
                phase,
                artifact,
            } => Self {
                schema: INGEST_INTENT_SCHEMA.to_owned(),
                session_id,
                operation_id,
                staged_relative_path,
                private_relative_path,
                phase,
                artifact,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum IngestIntentPhase {
    Preparing,
    #[default]
    Ready,
}

/// Metadata supplied before an immutable artifact is written or ingested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactSpec {
    /// Stable identifier unique in the future manifest.
    pub id: String,
    /// Extensible artifact kind, such as `raw_trace` or `perfetto`.
    pub kind: String,
    /// Destination path relative to the Session directory.
    pub relative_path: ArtifactPath,
    /// IANA media type.
    pub media_type: String,
    /// Tool or stage producing the artifact.
    pub producer: String,
    /// Input artifact identifiers used to produce this artifact.
    pub input_artifact_ids: Vec<String>,
}

impl ArtifactSpec {
    /// Validates portable identifiers, bounded metadata, media type syntax,
    /// and the closed direct-provenance list without consulting Session state.
    pub fn validate(&self) -> Result<(), SessionStoreError> {
        validate_artifact_identifier(&self.id, "artifact id")?;
        validate_text(&self.kind, "artifact kind", MAX_SHORT_METADATA_BYTES)?;
        validate_text(
            &self.media_type,
            "artifact media type",
            MAX_SHORT_METADATA_BYTES,
        )?;
        if !self.media_type.contains('/') {
            return Err(invalid_spec("media type must be a non-empty type/subtype"));
        }
        validate_text(
            &self.producer,
            "artifact producer",
            MAX_SHORT_METADATA_BYTES,
        )?;
        if self.input_artifact_ids.len() > MAX_ARTIFACT_INPUTS {
            return Err(invalid_spec(format!(
                "artifact has {} input ids; maximum is {MAX_ARTIFACT_INPUTS}",
                self.input_artifact_ids.len()
            )));
        }
        let mut inputs = BTreeSet::new();
        let self_key = portable_name_key(&self.id);
        for input in &self.input_artifact_ids {
            validate_artifact_identifier(input, "input artifact id")?;
            let input_key = portable_name_key(input);
            if input_key == self_key {
                return Err(invalid_spec("artifact directly references itself"));
            }
            if !inputs.insert(input_key) {
                return Err(invalid_spec(format!(
                    "input artifact id `{input}` is duplicated"
                )));
            }
        }
        Ok(())
    }

    fn catalog_reservation(&self) -> Result<Artifact, SessionStoreError> {
        let sha256 = Sha256Digest::new("0".repeat(64)).map_err(|error| {
            SessionStoreError::InvalidDocument {
                document: "artifact catalog reservation",
                message: error.to_string(),
            }
        })?;
        Ok(self.clone().into_artifact(u64::MAX, sha256))
    }

    fn into_artifact(self, size_bytes: u64, sha256: Sha256Digest) -> Artifact {
        Artifact {
            id: self.id,
            kind: self.kind,
            relative_path: self.relative_path,
            media_type: self.media_type,
            size_bytes,
            sha256,
            producer: self.producer,
            input_artifact_ids: self.input_artifact_ids,
        }
    }
}

/// A bounded, atomic writer for one immutable Session artifact.
#[derive(Debug)]
pub struct ArtifactWriter {
    destination: PathBuf,
    file: Option<AtomicWriteFile>,
    spec: Option<ArtifactSpec>,
    hasher: Sha256,
    size_bytes: u64,
    baseline_session_bytes: u64,
    max_file_bytes: u64,
    max_session_bytes: u64,
    catalog_reservation_bytes: u64,
    session_path: PathBuf,
}

impl ArtifactWriter {
    pub(crate) fn new(
        destination: PathBuf,
        spec: ArtifactSpec,
        baseline_session_bytes: u64,
        max_file_bytes: u64,
        max_session_bytes: u64,
        catalog_reservation_bytes: u64,
        session_path: PathBuf,
    ) -> Result<Self, SessionStoreError> {
        spec.validate()?;
        if path_entry_exists(&destination)? {
            return Err(SessionStoreError::ArtifactExists { path: destination });
        }
        reserve_active_writer(&session_path)?;
        let file = match AtomicWriteFile::open(&destination) {
            Ok(file) => file,
            Err(error) => {
                release_active_writer(&session_path);
                return Err(io_error("open atomic artifact", &destination, error));
            }
        };
        Ok(Self {
            destination,
            file: Some(file),
            spec: Some(spec),
            hasher: Sha256::new(),
            size_bytes: 0,
            baseline_session_bytes,
            max_file_bytes,
            max_session_bytes,
            catalog_reservation_bytes,
            session_path,
        })
    }

    /// Commits the complete file and returns its immutable manifest entry.
    fn finish(mut self, session: &Session) -> Result<Artifact, SessionStoreError> {
        if self.session_path != session.path() {
            return Err(SessionStoreError::ArtifactWriterSessionMismatch {
                session_id: session.id().to_string(),
            });
        }
        let observed_session_bytes = directory_size(session.path())?;
        let expected_session_bytes = self
            .baseline_session_bytes
            .checked_add(self.size_bytes)
            .ok_or(SessionStoreError::SessionLimitExceeded {
                limit_bytes: self.max_session_bytes,
                actual_bytes: u64::MAX,
            })?;
        let commit_peak = observed_session_bytes
            .max(expected_session_bytes)
            .checked_add(self.catalog_reservation_bytes)
            .ok_or(SessionStoreError::SessionLimitExceeded {
                limit_bytes: self.max_session_bytes,
                actual_bytes: u64::MAX,
            })?;
        if commit_peak > self.max_session_bytes {
            return Err(SessionStoreError::SessionLimitExceeded {
                limit_bytes: self.max_session_bytes,
                actual_bytes: commit_peak,
            });
        }
        if path_entry_exists(&self.destination)? {
            if let Some(file) = self.file.take() {
                file.discard().map_err(|error| {
                    io_error("discard atomic artifact", &self.destination, error)
                })?;
            }
            return Err(SessionStoreError::ArtifactExists {
                path: self.destination.clone(),
            });
        }
        let file = self.file.take().expect("artifact writer is finalized once");
        file.commit()
            .map_err(|error| io_error("commit atomic artifact", &self.destination, error))?;
        let output = std::mem::take(&mut self.hasher).finalize();
        let digest = Sha256Digest::new(encode_hex(&output)).map_err(|error| {
            SessionStoreError::InvalidDocument {
                document: "artifact digest",
                message: error.to_string(),
            }
        })?;
        Ok(self
            .spec
            .take()
            .expect("artifact specification is consumed once")
            .into_artifact(self.size_bytes, digest))
    }

    fn remaining_capacity(&self) -> Result<u64, SessionStoreError> {
        let file_remaining = self.max_file_bytes.saturating_sub(self.size_bytes);
        let session_used = self
            .baseline_session_bytes
            .saturating_add(self.catalog_reservation_bytes)
            .saturating_add(self.size_bytes);
        if session_used > self.max_session_bytes {
            return Err(SessionStoreError::SessionLimitExceeded {
                limit_bytes: self.max_session_bytes,
                actual_bytes: session_used,
            });
        }
        Ok(file_remaining.min(self.max_session_bytes - session_used))
    }
}

impl Drop for ArtifactWriter {
    fn drop(&mut self) {
        release_active_writer(&self.session_path);
    }
}

impl Write for ArtifactWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let requested = u64::try_from(buffer.len()).unwrap_or(u64::MAX);
        let remaining = self.remaining_capacity().map_err(io::Error::other)?;
        if requested > remaining {
            let attempted_file = self.size_bytes.saturating_add(requested);
            let attempted_session = self
                .baseline_session_bytes
                .saturating_add(self.catalog_reservation_bytes)
                .saturating_add(attempted_file);
            let error = if attempted_file > self.max_file_bytes {
                SessionStoreError::FileLimitExceeded {
                    limit_bytes: self.max_file_bytes,
                    actual_bytes: attempted_file,
                }
            } else {
                SessionStoreError::SessionLimitExceeded {
                    limit_bytes: self.max_session_bytes,
                    actual_bytes: attempted_session,
                }
            };
            return Err(io::Error::other(error));
        }
        let written = self
            .file
            .as_mut()
            .expect("artifact writer is open")
            .write(buffer)?;
        self.hasher.update(&buffer[..written]);
        self.size_bytes += u64::try_from(written).unwrap_or(u64::MAX);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.as_mut().expect("artifact writer is open").flush()
    }
}

impl Session {
    /// Creates one host-owned staging file exactly once, or verifies an exact retry.
    ///
    /// The path remains below `capture/staging`, is opened without following
    /// links or reparse points, and is never overwritten. A failed write leaves
    /// its bytes in place for diagnosis; retry succeeds only when those bytes
    /// are exactly the requested value.
    pub fn ensure_staged_exact(
        &self,
        lock: &SessionLock,
        staged_relative: &ArtifactPath,
        bytes: &[u8],
        max_bytes: u64,
    ) -> Result<(), SessionStoreError> {
        self.ensure_lock(lock)?;
        self.ensure_lifecycle_mutation_allowed()?;
        let limit = max_bytes.min(self.limits().max_file_bytes);
        let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if bytes.is_empty() || actual > limit {
            return Err(SessionStoreError::FileLimitExceeded {
                limit_bytes: limit,
                actual_bytes: actual,
            });
        }
        let path = self.prepare_staging_path(lock, staged_relative)?;
        match plain_file_metadata(&path)? {
            Some(_) => {
                let existing = self.read_staged_bounded(staged_relative, limit)?;
                if existing == bytes {
                    Ok(())
                } else {
                    Err(SessionStoreError::IngestIntentConflict {
                        artifact_id: staged_relative.to_string(),
                        message: "host-owned staging file contains conflicting bytes".to_owned(),
                    })
                }
            }
            None => {
                let temporary = exact_staging_temporary_path(&path);
                let (mut file, metadata) = create_new_plain_file(&temporary)?;
                if metadata.len() != 0 {
                    return Err(SessionStoreError::IngestIntentConflict {
                        artifact_id: staged_relative.to_string(),
                        message: "new host-owned staging temporary file is unexpectedly nonempty"
                            .to_owned(),
                    });
                }
                file.write_all(bytes).map_err(|error| {
                    io_error("write exact staged temporary bytes", &temporary, error)
                })?;
                file.sync_all().map_err(|error| {
                    io_error("sync exact staged temporary bytes", &temporary, error)
                })?;
                ensure_opened_file_identity(&temporary, &file)?;
                drop(file);
                match fs::hard_link(&temporary, &path) {
                    Ok(()) => {
                        let parent = path
                            .parent()
                            .ok_or_else(|| SessionStoreError::InvalidRoot { path: path.clone() })?;
                        sync_directory(parent)?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(io_error(
                            "publish exact staged bytes without replacement",
                            &path,
                            error,
                        ));
                    }
                }
                let existing = self.read_staged_bounded(staged_relative, limit)?;
                if existing == bytes {
                    let _ = fs::remove_file(&temporary);
                    Ok(())
                } else {
                    Err(SessionStoreError::IngestIntentConflict {
                        artifact_id: staged_relative.to_string(),
                        message: "host-owned staging file conflicts with exact temporary bytes"
                            .to_owned(),
                    })
                }
            }
        }
    }

    /// Opens and deeply verifies an immutable artifact with leaf no-follow checks.
    ///
    /// The digest is computed from the opened handle before it is rewound and returned,
    /// preventing verify-then-reopen races from changing the bytes consumed by callers.
    /// The configured artifact root must not be concurrently writable by an
    /// untrusted principal.
    pub fn open_artifact(&self, artifact: &Artifact) -> Result<File, SessionStoreError> {
        let path = resolve_artifact(self.path(), &artifact.relative_path, false)?;
        if !path_entry_exists(&path)? {
            return Err(SessionStoreError::ArtifactNotFound { path });
        }
        let (mut file, opened_metadata) = open_existing_plain_file(&path, false)?;
        if opened_metadata.len() != artifact.size_bytes {
            return Err(SessionStoreError::ArtifactSizeMismatch {
                artifact_id: artifact.id.clone(),
                expected: artifact.size_bytes,
                actual: opened_metadata.len(),
            });
        }

        let (size, digest) = hash_reader(&mut file, &path)?;
        if size != artifact.size_bytes {
            return Err(SessionStoreError::ArtifactSizeMismatch {
                artifact_id: artifact.id.clone(),
                expected: artifact.size_bytes,
                actual: size,
            });
        }
        if digest != artifact.sha256 {
            return Err(SessionStoreError::ArtifactDigestMismatch {
                artifact_id: artifact.id.clone(),
            });
        }
        ensure_opened_file_identity(&path, &file)?;

        let canonical = fs::canonicalize(&path)
            .map_err(|error| io_error("canonicalize opened artifact", &path, error))?;
        if !canonical.starts_with(self.path()) {
            return Err(SessionStoreError::OutsideArtifactRoot { path: canonical });
        }
        file.rewind()
            .map_err(|error| io_error("rewind verified artifact", &path, error))?;
        Ok(file)
    }

    /// Opens an atomic writer for a new immutable artifact.
    pub fn create_artifact(
        &self,
        lock: &SessionLock,
        spec: ArtifactSpec,
    ) -> Result<ArtifactWriter, SessionStoreError> {
        self.ensure_lock(lock)?;
        spec.validate()?;
        self.ensure_lifecycle_mutation_allowed()?;
        self.ensure_artifact_catalog_slot(&spec.id, &spec.relative_path)?;
        let destination = resolve_artifact(self.path(), &spec.relative_path, true)?;
        let catalog_path = self
            .path()
            .join(ARTIFACT_INDEX_DIRECTORY)
            .join(format!("{}.json", spec.id));
        let reservation = spec.catalog_reservation()?;
        let catalog_bytes =
            serialize_json_document(&catalog_path, "artifact catalog record", &reservation)?;
        let catalog_reservation_bytes = u64::try_from(catalog_bytes.len()).map_err(|_| {
            SessionStoreError::SessionLimitExceeded {
                limit_bytes: self.limits().max_session_bytes,
                actual_bytes: u64::MAX,
            }
        })?;
        let baseline = directory_size(self.path())?;
        let reserved = baseline.checked_add(catalog_reservation_bytes).ok_or(
            SessionStoreError::SessionLimitExceeded {
                limit_bytes: self.limits().max_session_bytes,
                actual_bytes: u64::MAX,
            },
        )?;
        if reserved > self.limits().max_session_bytes {
            return Err(SessionStoreError::SessionLimitExceeded {
                limit_bytes: self.limits().max_session_bytes,
                actual_bytes: reserved,
            });
        }
        ArtifactWriter::new(
            destination,
            spec,
            baseline,
            self.limits().max_file_bytes,
            self.limits().max_session_bytes,
            catalog_reservation_bytes,
            self.path().to_path_buf(),
        )
    }

    /// Commits a completed writer and durably registers its artifact metadata.
    pub fn commit_artifact(
        &self,
        lock: &SessionLock,
        writer: ArtifactWriter,
    ) -> Result<Artifact, SessionStoreError> {
        self.ensure_lock(lock)?;
        self.ensure_lifecycle_mutation_allowed()?;
        let artifact = writer.finish(self)?;
        self.register_artifact(lock, &artifact)?;
        Ok(artifact)
    }

    /// Atomically serializes one JSON artifact with a trailing newline.
    pub fn write_json_artifact<T: serde::Serialize>(
        &self,
        lock: &SessionLock,
        spec: ArtifactSpec,
        value: &T,
    ) -> Result<Artifact, SessionStoreError> {
        let mut writer = self.create_artifact(lock, spec)?;
        serde_json::to_writer_pretty(&mut writer, value).map_err(|source| {
            SessionStoreError::Json {
                path: writer.destination.clone(),
                source,
            }
        })?;
        writer
            .write_all(b"\n")
            .map_err(|error| io_error("write JSON artifact", &writer.destination, error))?;
        self.commit_artifact(lock, writer)
    }

    /// Copies a completed staging file into a host-owned immutable destination.
    ///
    /// A strict, versioned intent is committed before publication. The external
    /// staging inode is never renamed into the artifact namespace.
    pub fn ingest_staged(
        &self,
        lock: &SessionLock,
        staged_relative: &ArtifactPath,
        spec: ArtifactSpec,
    ) -> Result<Artifact, SessionStoreError> {
        self.ingest_staged_bounded(lock, staged_relative, spec, self.limits().max_file_bytes)
    }

    /// Moves a completed staging file into an immutable destination with an
    /// independent source-size limit.
    ///
    /// This is the control-plane counterpart to [`Self::ingest_staged`]. It
    /// preserves the same durable recovery protocol while preventing a small
    /// protocol document from consuming the Session's much larger raw-trace
    /// allowance.
    pub fn ingest_staged_bounded(
        &self,
        lock: &SessionLock,
        staged_relative: &ArtifactPath,
        spec: ArtifactSpec,
        max_source_bytes: u64,
    ) -> Result<Artifact, SessionStoreError> {
        self.ensure_lock(lock)?;
        ensure_no_active_writer(self)?;
        spec.validate()?;
        let source_limit = max_source_bytes.min(self.limits().max_file_bytes);
        if spec.relative_path.as_str().starts_with("capture/staging/") {
            return Err(SessionStoreError::InvalidStagingPath {
                path: spec.relative_path.to_string(),
            });
        }
        let intent_directory = self.path().join(INGEST_INTENT_DIRECTORY);
        ensure_plain_directory(&intent_directory)?;
        let intent_path = intent_directory.join(format!("{}.json", spec.id));
        ensure_only_requested_intent(&intent_directory, &intent_path, &spec.id)?;

        let staged_path = self.staging_path(staged_relative)?;
        for source in self.committed_staging_sources()? {
            if source.staged_relative_path.portable_key() == staged_relative.portable_key()
                && source.artifact_id != spec.id
            {
                return Err(ingest_conflict(
                    &spec.id,
                    format!(
                        "staging path `{staged_relative}` is already bound to committed artifact `{}`",
                        source.artifact_id
                    ),
                ));
            }
        }
        let destination = resolve_artifact(self.path(), &spec.relative_path, false)?;
        let catalogs = self.catalog_records_unverified()?;
        let intent_exists = plain_file_exists(&intent_path)?;

        if !intent_exists && let Some(committed) = find_catalog_for_request(&catalogs, &spec)? {
            if committed.size_bytes > source_limit {
                return Err(SessionStoreError::FileLimitExceeded {
                    limit_bytes: source_limit,
                    actual_bytes: committed.size_bytes,
                });
            }
            ensure_matching_artifact_file(&destination, committed, "destination")?;
            return Ok(committed.clone());
        }

        let state = self.ensure_lifecycle_mutation_allowed()?;
        let destination = resolve_artifact(self.path(), &spec.relative_path, true)?;

        let intent = if intent_exists {
            let intent = read_ingest_intent(&intent_path)
                .map_err(|error| ingest_conflict(&spec.id, error.to_string()))?;
            validate_intent(self, &state.operation_id, &intent_path, &intent)?;
            ensure_intent_matches_request(&intent, staged_relative, &spec)?;
            if intent.artifact.size_bytes > source_limit {
                return Err(SessionStoreError::FileLimitExceeded {
                    limit_bytes: source_limit,
                    actual_bytes: intent.artifact.size_bytes,
                });
            }
            intent
        } else {
            ensure_catalog_slot_for_request(&catalogs, &spec)?;
            if plain_file_exists(&destination)? {
                return Err(ingest_conflict(
                    &spec.id,
                    "the destination exists without a matching durable intent or catalog record",
                ));
            }
            let (source_size, source_sha256) = hash_staged_bounded(&staged_path, source_limit)?;
            let private_path = private_copy_path(self, &spec.id, true)?;
            if plain_file_exists(&private_path)? {
                return Err(ingest_conflict(
                    &spec.id,
                    "a prepared private copy already exists without a durable intent",
                ));
            }
            let private_relative_path = private_copy_relative_path(&spec.id)?;
            let provisional = IngestIntent {
                schema: INGEST_INTENT_SCHEMA.to_owned(),
                session_id: self.id().to_string(),
                operation_id: state.operation_id.clone(),
                staged_relative_path: staged_relative.clone(),
                private_relative_path: Some(private_relative_path.clone()),
                phase: IngestIntentPhase::Preparing,
                artifact: spec.clone().into_artifact(source_size, source_sha256),
            };
            let provisional_intent_bytes = serialize_ingest_intent(&intent_path, &provisional)?;
            let provisional_catalog_bytes =
                serialize_catalog_reservation(self, &provisional.artifact)?;
            let provisional_source_record_bytes =
                committed_staging_source_bytes(self, &provisional)?;
            let private_copy_and_intent = source_size
                .checked_add(usize_to_u64(self, provisional_intent_bytes.len())?)
                .ok_or(SessionStoreError::SessionLimitExceeded {
                    limit_bytes: self.limits().max_session_bytes,
                    actual_bytes: u64::MAX,
                })?;
            self.ensure_additional_capacity(
                private_copy_and_intent
                    .checked_add(usize_to_u64(self, provisional_catalog_bytes.len())?)
                    .and_then(|total| {
                        total.checked_add(
                            usize_to_u64(self, provisional_source_record_bytes.len()).ok()?,
                        )
                    })
                    .ok_or(SessionStoreError::SessionLimitExceeded {
                        limit_bytes: self.limits().max_session_bytes,
                        actual_bytes: u64::MAX,
                    })?,
            )?;
            write_serialized_json_atomic(&intent_path, &provisional_intent_bytes, true)?;
            sync_directory(&intent_directory)?;
            complete_prepared_intent(self, &intent_path, provisional, source_limit)?
        };

        let intent = complete_prepared_intent(self, &intent_path, intent, source_limit)?;

        let catalogs = self.catalog_records_unverified()?;
        let assessment = assess_intent(self, &intent, &catalogs);
        if intent.private_relative_path.is_none()
            && matches!(
                assessment.classification,
                IngestIntentClassification::Resumable | IngestIntentClassification::CommittedStale
            )
        {
            migrate_legacy_destination(
                self,
                &intent,
                source_limit,
                assessment.classification == IngestIntentClassification::Resumable,
            )?;
        }
        match assessment.classification {
            IngestIntentClassification::Pending => {
                let catalog_bytes = serialize_catalog_reservation(self, &intent.artifact)?;
                let record_bytes = committed_staging_source_bytes(self, &intent)?;
                let private_path = intent_private_copy_path(self, &intent, true)?;
                let private_exists = plain_file_exists(&private_path)?;
                let additional = if private_exists {
                    usize_to_u64(self, catalog_bytes.len())?
                        .checked_add(usize_to_u64(self, record_bytes.len())?)
                        .ok_or(SessionStoreError::SessionLimitExceeded {
                            limit_bytes: self.limits().max_session_bytes,
                            actual_bytes: u64::MAX,
                        })?
                } else {
                    intent
                        .artifact
                        .size_bytes
                        .checked_add(usize_to_u64(self, catalog_bytes.len())?)
                        .and_then(|total| {
                            total.checked_add(usize_to_u64(self, record_bytes.len()).ok()?)
                        })
                        .ok_or(SessionStoreError::SessionLimitExceeded {
                            limit_bytes: self.limits().max_session_bytes,
                            actual_bytes: u64::MAX,
                        })?
                };
                self.ensure_additional_capacity(additional)?;
                if !private_exists {
                    let copied = replace_private_copy_from_staged(
                        &staged_path,
                        &private_path,
                        source_limit,
                    )?;
                    if copied != (intent.artifact.size_bytes, intent.artifact.sha256.clone()) {
                        return Err(ingest_conflict(
                            &intent.artifact.id,
                            "staged bytes do not match the durable intent",
                        ));
                    }
                }
                ensure_matching_artifact_file(&private_path, &intent.artifact, "private copy")?;
                fs::rename(&private_path, &destination).map_err(|error| {
                    io_error("publish private artifact copy", &destination, error)
                })?;
                sync_rename_directories(&private_path, &destination)?;
                ensure_matching_artifact_file(&destination, &intent.artifact, "destination")?;
                self.register_artifact(lock, &intent.artifact)?;
            }
            IngestIntentClassification::Resumable => {
                let catalog_bytes = serialize_catalog_reservation(self, &intent.artifact)?;
                let record_bytes = committed_staging_source_bytes(self, &intent)?;
                self.ensure_additional_capacity(
                    usize_to_u64(self, catalog_bytes.len())?
                        .checked_add(usize_to_u64(self, record_bytes.len())?)
                        .ok_or(SessionStoreError::SessionLimitExceeded {
                            limit_bytes: self.limits().max_session_bytes,
                            actual_bytes: u64::MAX,
                        })?,
                )?;
                self.register_artifact(lock, &intent.artifact)?;
            }
            IngestIntentClassification::CommittedStale => {}
            IngestIntentClassification::Conflict => {
                return Err(ingest_conflict(&intent.artifact.id, assessment.detail));
            }
        }

        remove_exact_committed_intent(self, &intent_path, &intent)?;
        Ok(intent.artifact)
    }

    /// Inspects every durable ingest intent without changing Session contents.
    ///
    /// Callers that require a stable snapshot should hold the Session operation
    /// lock. Unknown, malformed, linked, or inconsistent entries are reported as
    /// [`IngestIntentClassification::Conflict`] and are never removed.
    pub fn inspect_ingest_intents(&self) -> Result<Vec<IngestIntentInspection>, SessionStoreError> {
        let state = self.read_state()?;
        let (catalogs, catalog_error) = match self.catalog_records_unverified() {
            Ok(catalogs) => (catalogs, None),
            Err(error) => (Vec::new(), Some(bounded_detail(error.to_string()))),
        };
        let directory = self.path().join(INGEST_INTENT_DIRECTORY);
        ensure_plain_directory(&directory)?;
        let mut entries_bounded =
            read_directory_entries_bounded(&directory, MAX_MANIFEST_ARTIFACTS)?;
        entries_bounded.sort_by_key(std::fs::DirEntry::file_name);

        let mut inspections = Vec::with_capacity(entries_bounded.len());
        for entry in entries_bounded {
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().into_owned();
            let relative_path = format!("{INGEST_INTENT_DIRECTORY}/{file_name}");
            let parsed = read_ingest_intent(&path).and_then(|intent| {
                validate_intent(self, &state.operation_id, &path, &intent)?;
                Ok(intent)
            });
            match parsed {
                Ok(intent) => {
                    let assessment = catalog_error.as_ref().map_or_else(
                        || assess_intent(self, &intent, &catalogs),
                        |error| {
                            conflicted_assessment(format!(
                                "artifact catalog cannot be validated: {error}"
                            ))
                        },
                    );
                    inspections.push(IngestIntentInspection {
                        intent_relative_path: relative_path,
                        artifact_id: Some(intent.artifact.id.clone()),
                        staged_relative_path: Some(intent.staged_relative_path.clone()),
                        destination_relative_path: Some(intent.artifact.relative_path.clone()),
                        classification: assessment.classification,
                        detail: assessment.detail,
                    });
                }
                Err(error) => inspections.push(IngestIntentInspection {
                    intent_relative_path: relative_path,
                    artifact_id: None,
                    staged_relative_path: None,
                    destination_relative_path: None,
                    classification: IngestIntentClassification::Conflict,
                    detail: bounded_detail(error.to_string()),
                }),
            }
        }
        Ok(inspections)
    }

    /// Reads committed staging-source records without opening retained payloads.
    ///
    /// Ingest uses this metadata-only view so historical retained-source changes
    /// cannot block an idempotent request for an already committed artifact.
    pub fn committed_staging_sources(
        &self,
    ) -> Result<Vec<CommittedStagingSource>, SessionStoreError> {
        let directory = self.path().join(COMMITTED_STAGING_SOURCE_DIRECTORY);
        ensure_plain_directory(&directory)?;
        let mut entries = read_directory_entries_bounded(&directory, MAX_MANIFEST_ARTIFACTS)?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        let catalogs = self.catalog_records_unverified()?;
        let mut sources = Vec::with_capacity(entries.len());
        let mut paths = BTreeSet::new();
        for entry in entries {
            let path = entry.path();
            ensure_plain_file(&path)?;
            let record: CommittedStagingSourceRecord =
                read_bounded_json(&path, "committed staging source", MAX_INGEST_INTENT_BYTES)?;
            validate_committed_staging_source_record(self, &path, &record)?;
            if !paths.insert(record.source.staged_relative_path.portable_key()) {
                return Err(ingest_conflict(
                    &record.source.artifact_id,
                    "multiple committed source records use the same staging path",
                ));
            }
            let artifact = catalogs
                .iter()
                .find(|artifact| artifact.id == record.source.artifact_id)
                .ok_or_else(|| {
                    ingest_conflict(
                        &record.source.artifact_id,
                        "committed source record has no cataloged artifact",
                    )
                })?;
            if artifact.relative_path != record.source.artifact_relative_path
                || artifact.size_bytes != record.source.size_bytes
                || artifact.sha256 != record.source.sha256
            {
                return Err(ingest_conflict(
                    &record.source.artifact_id,
                    "committed source record does not match its cataloged artifact",
                ));
            }
            sources.push(record.source);
        }
        Ok(sources)
    }

    /// Verifies retained staging-source presence, type, and size without hashing payloads.
    pub fn verify_committed_staging_sources_shallow(
        &self,
    ) -> Result<Vec<CommittedStagingSource>, SessionStoreError> {
        let sources = self.committed_staging_sources()?;
        for source in &sources {
            let path = self.staging_path(&source.staged_relative_path)?;
            let metadata = ensure_plain_file(&path)?;
            if metadata.len() != source.size_bytes {
                return Err(SessionStoreError::ArtifactSizeMismatch {
                    artifact_id: source.artifact_id.clone(),
                    expected: source.size_bytes,
                    actual: metadata.len(),
                });
            }
        }
        Ok(sources)
    }

    /// Deeply verifies retained staging-source payloads and their artifact bindings.
    pub fn verify_committed_staging_sources(
        &self,
    ) -> Result<Vec<CommittedStagingSource>, SessionStoreError> {
        let sources = self.verify_committed_staging_sources_shallow()?;
        let catalogs = self.catalog_records_unverified()?;
        for source in &sources {
            let artifact = catalogs
                .iter()
                .find(|artifact| artifact.id == source.artifact_id)
                .expect("shallow source validation requires a cataloged artifact");
            ensure_matching_artifact_file(
                &resolve_artifact(self.path(), &artifact.relative_path, false)?,
                artifact,
                "committed artifact destination",
            )?;
            let expected = Artifact {
                id: source.artifact_id.clone(),
                kind: artifact.kind.clone(),
                relative_path: source.staged_relative_path.clone(),
                media_type: artifact.media_type.clone(),
                size_bytes: source.size_bytes,
                sha256: source.sha256.clone(),
                producer: artifact.producer.clone(),
                input_artifact_ids: Vec::new(),
            };
            ensure_matching_artifact_file(
                &self.staging_path(&source.staged_relative_path)?,
                &expected,
                "retained staging source",
            )?;
        }
        Ok(sources)
    }

    pub(crate) fn ensure_no_ingest_intents(&self) -> Result<(), SessionStoreError> {
        if let Some(inspection) = self.inspect_ingest_intents()?.into_iter().next() {
            return Err(ingest_conflict(
                inspection.artifact_id.as_deref().unwrap_or("<unknown>"),
                format!(
                    "Session lifecycle cannot advance while `{}` is {:?}: {}",
                    inspection.intent_relative_path, inspection.classification, inspection.detail
                ),
            ));
        }
        Ok(())
    }

    /// Verifies one manifest artifact's type, size, and optionally its digest.
    pub fn verify_artifact(
        &self,
        artifact: &Artifact,
        deep: bool,
    ) -> Result<(), SessionStoreError> {
        if deep {
            drop(self.open_artifact(artifact)?);
            return Ok(());
        }
        let path = resolve_artifact(self.path(), &artifact.relative_path, false)?;
        if !path_entry_exists(&path)? {
            return Err(SessionStoreError::ArtifactNotFound { path });
        }
        let metadata = ensure_plain_file(&path)?;
        if metadata.len() != artifact.size_bytes {
            return Err(SessionStoreError::ArtifactSizeMismatch {
                artifact_id: artifact.id.clone(),
                expected: artifact.size_bytes,
                actual: metadata.len(),
            });
        }
        Ok(())
    }
}

fn exact_staging_temporary_path(destination: &Path) -> PathBuf {
    let name = destination
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("staged");
    destination.with_file_name(format!(".{name}.{}.partial", Uuid::now_v7().simple()))
}

struct IntentAssessment {
    classification: IngestIntentClassification,
    detail: String,
}

enum ArtifactFileEvidence {
    Missing,
    Matching,
    Conflict(String),
}

fn validate_intent(
    session: &Session,
    operation_id: &str,
    path: &Path,
    intent: &IngestIntent,
) -> Result<(), SessionStoreError> {
    if intent.schema != INGEST_INTENT_SCHEMA && intent.schema != LEGACY_INGEST_INTENT_SCHEMA {
        return Err(ingest_conflict(
            &intent.artifact.id,
            format!("unsupported intent schema `{}`", intent.schema),
        ));
    }
    if intent.session_id != session.id().as_str() {
        return Err(ingest_conflict(
            &intent.artifact.id,
            format!(
                "intent Session `{}` does not match `{}`",
                intent.session_id,
                session.id()
            ),
        ));
    }
    if intent.operation_id != operation_id {
        return Err(ingest_conflict(
            &intent.artifact.id,
            "intent operation id does not match the current Session operation",
        ));
    }
    intent
        .artifact
        .validate()
        .map_err(|error| ingest_conflict(&intent.artifact.id, error.to_string()))?;
    if intent.artifact.size_bytes > session.limits().max_file_bytes {
        return Err(SessionStoreError::FileLimitExceeded {
            limit_bytes: session.limits().max_file_bytes,
            actual_bytes: intent.artifact.size_bytes,
        });
    }
    if intent
        .artifact
        .relative_path
        .as_str()
        .starts_with("capture/staging/")
    {
        return Err(ingest_conflict(
            &intent.artifact.id,
            "intent destination is inside capture/staging",
        ));
    }
    let expected_name = format!("{}.json", intent.artifact.id);
    if path.file_name().and_then(std::ffi::OsStr::to_str) != Some(expected_name.as_str()) {
        return Err(ingest_conflict(
            &intent.artifact.id,
            "intent filename does not match its artifact id",
        ));
    }
    session.staging_path(&intent.staged_relative_path)?;
    if let Some(private_relative_path) = &intent.private_relative_path {
        if private_relative_path != &private_copy_relative_path(&intent.artifact.id)? {
            return Err(ingest_conflict(
                &intent.artifact.id,
                "intent private copy path does not match its artifact id",
            ));
        }
        resolve_artifact(session.path(), private_relative_path, false)?;
    }
    resolve_artifact(session.path(), &intent.artifact.relative_path, false)?;
    Ok(())
}

fn validate_committed_staging_source_record(
    session: &Session,
    path: &Path,
    record: &CommittedStagingSourceRecord,
) -> Result<(), SessionStoreError> {
    if record.schema != COMMITTED_STAGING_SOURCE_SCHEMA {
        return Err(ingest_conflict(
            &record.source.artifact_id,
            format!("unsupported committed source schema `{}`", record.schema),
        ));
    }
    if record.session_id != session.id().as_str() {
        return Err(ingest_conflict(
            &record.source.artifact_id,
            "committed source record belongs to another Session",
        ));
    }
    validate_artifact_identifier(&record.source.artifact_id, "committed source artifact id")?;
    let expected_name = format!("{}.json", record.source.artifact_id);
    if path.file_name().and_then(std::ffi::OsStr::to_str) != Some(expected_name.as_str()) {
        return Err(ingest_conflict(
            &record.source.artifact_id,
            "committed source record filename does not match its artifact id",
        ));
    }
    session.staging_path(&record.source.staged_relative_path)?;
    resolve_artifact(session.path(), &record.source.artifact_relative_path, false)?;
    Ok(())
}

fn private_copy_relative_path(artifact_id: &str) -> Result<ArtifactPath, SessionStoreError> {
    ArtifactPath::new(format!("capture/.ingest-private/{artifact_id}.payload")).map_err(|error| {
        SessionStoreError::InvalidDocument {
            document: "ingest private copy path",
            message: error.to_string(),
        }
    })
}

fn private_copy_path(
    session: &Session,
    artifact_id: &str,
    create_parents: bool,
) -> Result<PathBuf, SessionStoreError> {
    let relative = private_copy_relative_path(artifact_id)?;
    resolve_artifact(session.path(), &relative, create_parents)
}

fn intent_private_copy_path(
    session: &Session,
    intent: &IngestIntent,
    create_parents: bool,
) -> Result<PathBuf, SessionStoreError> {
    match &intent.private_relative_path {
        Some(relative) => resolve_artifact(session.path(), relative, create_parents),
        None => private_copy_path(session, &intent.artifact.id, create_parents),
    }
}

fn complete_prepared_intent(
    session: &Session,
    intent_path: &Path,
    mut intent: IngestIntent,
    source_limit: u64,
) -> Result<IngestIntent, SessionStoreError> {
    if intent.phase == IngestIntentPhase::Ready {
        return Ok(intent);
    }
    let private_path = intent_private_copy_path(session, &intent, true)?;
    let private_ready = matches!(
        artifact_file_evidence(&private_path, &intent.artifact, "private copy"),
        ArtifactFileEvidence::Matching
    );
    if !private_ready {
        let catalog_bytes = serialize_catalog_reservation(session, &intent.artifact)?;
        let record_bytes = committed_staging_source_bytes(session, &intent)?;
        let private_and_catalog = intent
            .artifact
            .size_bytes
            .checked_add(usize_to_u64(session, catalog_bytes.len())?)
            .and_then(|total| total.checked_add(usize_to_u64(session, record_bytes.len()).ok()?))
            .ok_or(SessionStoreError::SessionLimitExceeded {
                limit_bytes: session.limits().max_session_bytes,
                actual_bytes: u64::MAX,
            })?;
        session.ensure_additional_capacity(private_and_catalog)?;
        let staged_path = session.staging_path(&intent.staged_relative_path)?;
        let copied = replace_private_copy_from_staged(&staged_path, &private_path, source_limit)?;
        if copied != (intent.artifact.size_bytes, intent.artifact.sha256.clone()) {
            return Err(ingest_conflict(
                &intent.artifact.id,
                "staged bytes changed after the durable prepare intent",
            ));
        }
    }
    intent.phase = IngestIntentPhase::Ready;
    let bytes = serialize_ingest_intent(intent_path, &intent)?;
    write_serialized_json_atomic(intent_path, &bytes, false)?;
    sync_directory(
        intent_path
            .parent()
            .expect("ingest intent always has a parent directory"),
    )?;
    Ok(intent)
}

fn migrate_legacy_destination(
    session: &Session,
    intent: &IngestIntent,
    source_limit: u64,
    catalog_is_absent: bool,
) -> Result<(), SessionStoreError> {
    let destination = resolve_artifact(session.path(), &intent.artifact.relative_path, false)?;
    let catalog_bytes = if catalog_is_absent {
        usize_to_u64(
            session,
            serialize_catalog_reservation(session, &intent.artifact)?.len(),
        )?
    } else {
        0
    };
    let record_bytes = if plain_file_exists(&session.staging_path(&intent.staged_relative_path)?)? {
        usize_to_u64(
            session,
            committed_staging_source_bytes(session, intent)?.len(),
        )?
    } else {
        0
    };
    let replacement_peak =
        intent
            .artifact
            .size_bytes
            .max(catalog_bytes.checked_add(record_bytes).ok_or(
                SessionStoreError::SessionLimitExceeded {
                    limit_bytes: session.limits().max_session_bytes,
                    actual_bytes: u64::MAX,
                },
            )?);
    session.ensure_additional_capacity(replacement_peak)?;
    let (mut source, source_metadata) = open_existing_plain_file(&destination, false)?;
    if source_metadata.len() != intent.artifact.size_bytes || source_metadata.len() > source_limit {
        return Err(ingest_conflict(
            &intent.artifact.id,
            "legacy destination no longer matches the durable intent",
        ));
    }
    let mut replacement = AtomicWriteFile::open(&destination)
        .map_err(|error| io_error("open legacy artifact replacement", &destination, error))?;
    let copied = copy_and_hash_bounded(&mut source, &mut replacement, &destination, source_limit)?;
    source
        .rewind()
        .map_err(|error| io_error("rewind legacy artifact", &destination, error))?;
    let verified = hash_reader_bounded(&mut source, &destination, source_limit)?;
    ensure_opened_file_identity(&destination, &source)?;
    if copied != (intent.artifact.size_bytes, intent.artifact.sha256.clone()) || verified != copied
    {
        return Err(ingest_conflict(
            &intent.artifact.id,
            "legacy destination changed during host-owned migration",
        ));
    }
    replacement
        .commit()
        .map_err(|error| io_error("publish legacy artifact replacement", &destination, error))?;
    sync_directory(
        destination
            .parent()
            .expect("artifact destinations always have a parent directory"),
    )?;
    ensure_matching_artifact_file(&destination, &intent.artifact, "migrated destination")
}

fn replace_private_copy_from_staged(
    staged_path: &Path,
    private_path: &Path,
    source_limit: u64,
) -> Result<(u64, Sha256Digest), SessionStoreError> {
    let (mut source, initial_metadata) = open_existing_plain_file(staged_path, false)?;
    if initial_metadata.len() > source_limit {
        return Err(SessionStoreError::FileLimitExceeded {
            limit_bytes: source_limit,
            actual_bytes: initial_metadata.len(),
        });
    }
    let mut replacement = AtomicWriteFile::open(private_path)
        .map_err(|error| io_error("open private ingest copy replacement", private_path, error))?;
    let copied = copy_and_hash_bounded(&mut source, &mut replacement, staged_path, source_limit)?;
    source
        .rewind()
        .map_err(|error| io_error("rewind staged source", staged_path, error))?;
    let verified = hash_reader_bounded(&mut source, staged_path, source_limit)?;
    let current_metadata = source
        .metadata()
        .map_err(|error| io_error("inspect staged source after copy", staged_path, error))?;
    ensure_opened_file_identity(staged_path, &source)?;
    if current_metadata.len() != initial_metadata.len() || verified != copied {
        return Err(SessionStoreError::FileIdentityChanged {
            path: staged_path.to_path_buf(),
        });
    }
    replacement.commit().map_err(|error| {
        io_error(
            "publish private ingest copy replacement",
            private_path,
            error,
        )
    })?;
    sync_directory(
        private_path
            .parent()
            .expect("private ingest copies always have a parent directory"),
    )?;
    Ok(copied)
}

fn ensure_intent_matches_request(
    intent: &IngestIntent,
    staged_relative: &ArtifactPath,
    spec: &ArtifactSpec,
) -> Result<(), SessionStoreError> {
    if &intent.staged_relative_path != staged_relative {
        return Err(ingest_conflict(
            &spec.id,
            format!(
                "requested staging path `{staged_relative}` does not match intent `{}`",
                intent.staged_relative_path
            ),
        ));
    }
    if !spec_matches_artifact(spec, &intent.artifact) {
        return Err(ingest_conflict(
            &spec.id,
            "requested artifact specification does not match the durable intent",
        ));
    }
    Ok(())
}

fn spec_matches_artifact(spec: &ArtifactSpec, artifact: &Artifact) -> bool {
    spec.id == artifact.id
        && spec.kind == artifact.kind
        && spec.relative_path == artifact.relative_path
        && spec.media_type == artifact.media_type
        && spec.producer == artifact.producer
        && spec.input_artifact_ids == artifact.input_artifact_ids
}

fn ensure_only_requested_intent(
    directory: &Path,
    requested_path: &Path,
    artifact_id: &str,
) -> Result<(), SessionStoreError> {
    let entries = fs::read_dir(directory)
        .map_err(|error| io_error("list ingest intents", directory, error))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| io_error("read ingest intent entry", directory, error))?;
        if entry.path() != requested_path {
            return Err(ingest_conflict(
                artifact_id,
                format!(
                    "unresolved or unknown ingest control entry `{}` must be inspected first",
                    entry.file_name().to_string_lossy()
                ),
            ));
        }
    }
    Ok(())
}

fn find_catalog_for_request<'a>(
    catalogs: &'a [Artifact],
    spec: &ArtifactSpec,
) -> Result<Option<&'a Artifact>, SessionStoreError> {
    let id_key = portable_name_key(&spec.id);
    if let Some(existing) = catalogs
        .iter()
        .find(|artifact| portable_name_key(&artifact.id) == id_key)
    {
        if !spec_matches_artifact(spec, existing) {
            return Err(ingest_conflict(
                &spec.id,
                "artifact id is cataloged with a different specification",
            ));
        }
        return Ok(Some(existing));
    }
    let path_key = spec.relative_path.portable_key();
    if let Some(existing) = catalogs
        .iter()
        .find(|artifact| artifact.relative_path.portable_key() == path_key)
    {
        return Err(ingest_conflict(
            &spec.id,
            format!(
                "destination `{}` is cataloged by artifact `{}`",
                spec.relative_path, existing.id
            ),
        ));
    }
    Ok(None)
}

fn ensure_catalog_slot_for_request(
    catalogs: &[Artifact],
    spec: &ArtifactSpec,
) -> Result<(), SessionStoreError> {
    if find_catalog_for_request(catalogs, spec)?.is_some() {
        return Err(ingest_conflict(&spec.id, "artifact is already cataloged"));
    }
    let attempted =
        catalogs
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
    Ok(())
}

fn exact_catalog_state(catalogs: &[Artifact], expected: &Artifact) -> Result<bool, String> {
    let id_key = portable_name_key(&expected.id);
    if let Some(existing) = catalogs
        .iter()
        .find(|artifact| portable_name_key(&artifact.id) == id_key)
    {
        if existing != expected {
            return Err("artifact id has a different catalog record".to_owned());
        }
        return Ok(true);
    }
    let path_key = expected.relative_path.portable_key();
    if let Some(existing) = catalogs
        .iter()
        .find(|artifact| artifact.relative_path.portable_key() == path_key)
    {
        return Err(format!(
            "destination is cataloged by artifact `{}`",
            existing.id
        ));
    }
    Ok(false)
}

fn assess_intent(
    session: &Session,
    intent: &IngestIntent,
    catalogs: &[Artifact],
) -> IntentAssessment {
    let cataloged = match exact_catalog_state(catalogs, &intent.artifact) {
        Ok(cataloged) => cataloged,
        Err(detail) => return conflicted_assessment(detail),
    };
    let staged_path = match session.staging_path(&intent.staged_relative_path) {
        Ok(path) => path,
        Err(error) => return conflicted_assessment(error.to_string()),
    };
    let destination = match resolve_artifact(session.path(), &intent.artifact.relative_path, false)
    {
        Ok(path) => path,
        Err(error) => return conflicted_assessment(error.to_string()),
    };
    let private_path = match intent_private_copy_path(session, intent, false) {
        Ok(path) => path,
        Err(error) => return conflicted_assessment(error.to_string()),
    };
    let staged = artifact_file_evidence(&staged_path, &intent.artifact, "staged file");
    let private = artifact_file_evidence(&private_path, &intent.artifact, "private copy");
    let destination = artifact_file_evidence(&destination, &intent.artifact, "destination");
    if matches!(destination, ArtifactFileEvidence::Matching) {
        return IntentAssessment {
            classification: if cataloged {
                IngestIntentClassification::CommittedStale
            } else {
                IngestIntentClassification::Resumable
            },
            detail: if cataloged {
                "destination and catalog match; the exact intent is stale".to_owned()
            } else {
                "destination bytes match the intent; catalog is absent".to_owned()
            },
        };
    }
    if let ArtifactFileEvidence::Conflict(detail) = staged {
        return conflicted_assessment(detail);
    }
    if let ArtifactFileEvidence::Conflict(detail) = destination {
        return conflicted_assessment(detail);
    }
    if let ArtifactFileEvidence::Conflict(detail) = private {
        return conflicted_assessment(detail);
    }

    match (staged, private, destination, cataloged) {
        (
            ArtifactFileEvidence::Matching | ArtifactFileEvidence::Missing,
            ArtifactFileEvidence::Matching,
            ArtifactFileEvidence::Missing,
            false,
        )
        | (
            ArtifactFileEvidence::Matching,
            ArtifactFileEvidence::Missing,
            ArtifactFileEvidence::Missing,
            false,
        ) => IntentAssessment {
            classification: IngestIntentClassification::Pending,
            detail: "host-owned private copy can be published; destination and catalog are absent"
                .to_owned(),
        },
        (_, _, ArtifactFileEvidence::Missing, true) => {
            conflicted_assessment("catalog exists while staged and destination files are absent")
        }
        (
            ArtifactFileEvidence::Missing,
            ArtifactFileEvidence::Missing,
            ArtifactFileEvidence::Missing,
            false,
        ) => conflicted_assessment("staged and private copy files are both absent"),
        (ArtifactFileEvidence::Conflict(_), _, _, _)
        | (_, ArtifactFileEvidence::Conflict(_), _, _)
        | (_, _, ArtifactFileEvidence::Conflict(_), _) => {
            unreachable!("file conflicts are handled before state classification")
        }
        (_, _, ArtifactFileEvidence::Matching, _) => {
            unreachable!("matching destinations are handled before state classification")
        }
    }
}

fn conflicted_assessment(detail: impl Into<String>) -> IntentAssessment {
    IntentAssessment {
        classification: IngestIntentClassification::Conflict,
        detail: bounded_detail(detail.into()),
    }
}

fn artifact_file_evidence(
    path: &Path,
    expected: &Artifact,
    label: &'static str,
) -> ArtifactFileEvidence {
    match plain_file_metadata(path) {
        Ok(None) => ArtifactFileEvidence::Missing,
        Ok(Some(metadata)) if metadata.len() != expected.size_bytes => {
            ArtifactFileEvidence::Conflict(format!(
                "{label} does not match intent: expected {} bytes, found {} bytes",
                expected.size_bytes,
                metadata.len()
            ))
        }
        Ok(Some(_)) => match hash_file(path) {
            Ok((size, digest)) if size == expected.size_bytes && digest == expected.sha256 => {
                ArtifactFileEvidence::Matching
            }
            Ok((size, digest)) => ArtifactFileEvidence::Conflict(format!(
                "{label} does not match intent: expected {} bytes/{}, found {size}/{digest}",
                expected.size_bytes, expected.sha256
            )),
            Err(error) => ArtifactFileEvidence::Conflict(format!(
                "cannot verify {label} `{}`: {error}",
                path.display()
            )),
        },
        Err(error) => ArtifactFileEvidence::Conflict(format!(
            "cannot inspect {label} `{}`: {error}",
            path.display()
        )),
    }
}

fn ensure_matching_artifact_file(
    path: &Path,
    expected: &Artifact,
    label: &'static str,
) -> Result<(), SessionStoreError> {
    match artifact_file_evidence(path, expected, label) {
        ArtifactFileEvidence::Matching => Ok(()),
        ArtifactFileEvidence::Missing => {
            Err(ingest_conflict(&expected.id, format!("{label} is absent")))
        }
        ArtifactFileEvidence::Conflict(detail) => Err(ingest_conflict(&expected.id, detail)),
    }
}

fn serialize_ingest_intent(
    path: &Path,
    intent: &IngestIntent,
) -> Result<Vec<u8>, SessionStoreError> {
    let bytes = serialize_json_document(path, "ingest intent", intent)?;
    let actual_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual_bytes > MAX_INGEST_INTENT_BYTES {
        return Err(SessionStoreError::MetadataLimitExceeded {
            document: "ingest intent",
            limit_bytes: MAX_INGEST_INTENT_BYTES,
            actual_bytes,
        });
    }
    Ok(bytes)
}

fn read_ingest_intent(path: &Path) -> Result<IngestIntent, SessionStoreError> {
    let document: IngestIntentDocument =
        read_bounded_json(path, "ingest intent", MAX_INGEST_INTENT_BYTES)?;
    Ok(document.into())
}

fn serialize_catalog_reservation(
    session: &Session,
    artifact: &Artifact,
) -> Result<Vec<u8>, SessionStoreError> {
    let path = session
        .path()
        .join(ARTIFACT_INDEX_DIRECTORY)
        .join(format!("{}.json", artifact.id));
    serialize_json_document(&path, "artifact catalog record", artifact)
}

fn usize_to_u64(session: &Session, value: usize) -> Result<u64, SessionStoreError> {
    u64::try_from(value).map_err(|_| SessionStoreError::SessionLimitExceeded {
        limit_bytes: session.limits().max_session_bytes,
        actual_bytes: u64::MAX,
    })
}

fn plain_file_exists(path: &Path) -> Result<bool, SessionStoreError> {
    plain_file_metadata(path).map(|metadata| metadata.is_some())
}

fn plain_file_metadata(path: &Path) -> Result<Option<fs::Metadata>, SessionStoreError> {
    match fs::symlink_metadata(path) {
        Ok(_) => ensure_plain_file(path).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error("inspect file", path, error)),
    }
}

fn remove_exact_committed_intent(
    session: &Session,
    intent_path: &Path,
    expected: &IngestIntent,
) -> Result<(), SessionStoreError> {
    let current = read_ingest_intent(intent_path)?;
    if current != *expected {
        return Err(ingest_conflict(
            &expected.artifact.id,
            "intent changed before committed cleanup",
        ));
    }
    let catalogs = session.catalog_records_unverified()?;
    match exact_catalog_state(&catalogs, &expected.artifact) {
        Ok(true) => {}
        Ok(false) => {
            return Err(ingest_conflict(
                &expected.artifact.id,
                "catalog record is absent before intent cleanup",
            ));
        }
        Err(detail) => return Err(ingest_conflict(&expected.artifact.id, detail)),
    }
    session.verify_artifact(&expected.artifact, true)?;
    let source_path = session.staging_path(&expected.staged_relative_path)?;
    if matches!(
        artifact_file_evidence(&source_path, &expected.artifact, "staged source"),
        ArtifactFileEvidence::Matching
    ) {
        write_committed_staging_source_record(session, expected)?;
    }
    fs::remove_file(intent_path)
        .map_err(|error| io_error("remove committed ingest intent", intent_path, error))?;
    sync_directory(
        intent_path
            .parent()
            .expect("ingest intent always has a parent directory"),
    )?;
    Ok(())
}

fn write_committed_staging_source_record(
    session: &Session,
    intent: &IngestIntent,
) -> Result<(), SessionStoreError> {
    let source_path = session.staging_path(&intent.staged_relative_path)?;
    if !plain_file_exists(&source_path)? {
        return Ok(());
    }
    let source = CommittedStagingSource {
        artifact_id: intent.artifact.id.clone(),
        staged_relative_path: intent.staged_relative_path.clone(),
        size_bytes: intent.artifact.size_bytes,
        sha256: intent.artifact.sha256.clone(),
        artifact_relative_path: intent.artifact.relative_path.clone(),
    };
    let record = CommittedStagingSourceRecord {
        schema: COMMITTED_STAGING_SOURCE_SCHEMA.to_owned(),
        session_id: session.id().to_string(),
        source,
    };
    let directory = session.path().join(COMMITTED_STAGING_SOURCE_DIRECTORY);
    ensure_plain_directory(&directory)?;
    let path = directory.join(format!("{}.json", intent.artifact.id));
    let bytes = serialize_json_document(&path, "committed staging source", &record)?;
    match plain_file_exists(&path)? {
        true => {
            let existing: CommittedStagingSourceRecord =
                read_bounded_json(&path, "committed staging source", MAX_INGEST_INTENT_BYTES)?;
            if existing != record {
                return Err(ingest_conflict(
                    &intent.artifact.id,
                    "existing committed source record differs from the ingest binding",
                ));
            }
        }
        false => {
            session.ensure_additional_capacity(usize_to_u64(session, bytes.len())?)?;
            write_serialized_json_atomic(&path, &bytes, true)?;
            sync_directory(&directory)?;
        }
    }
    Ok(())
}

fn committed_staging_source_bytes(
    session: &Session,
    intent: &IngestIntent,
) -> Result<Vec<u8>, SessionStoreError> {
    let source = CommittedStagingSource {
        artifact_id: intent.artifact.id.clone(),
        staged_relative_path: intent.staged_relative_path.clone(),
        size_bytes: intent.artifact.size_bytes,
        sha256: intent.artifact.sha256.clone(),
        artifact_relative_path: intent.artifact.relative_path.clone(),
    };
    let record = CommittedStagingSourceRecord {
        schema: COMMITTED_STAGING_SOURCE_SCHEMA.to_owned(),
        session_id: session.id().to_string(),
        source,
    };
    let path = session
        .path()
        .join(COMMITTED_STAGING_SOURCE_DIRECTORY)
        .join(format!("{}.json", intent.artifact.id));
    serialize_json_document(&path, "committed staging source", &record)
}

fn sync_rename_directories(source: &Path, destination: &Path) -> Result<(), SessionStoreError> {
    let source_parent = source
        .parent()
        .expect("staged artifact always has a parent directory");
    let destination_parent = destination
        .parent()
        .expect("artifact destination always has a parent directory");
    sync_directory(destination_parent)?;
    if source_parent != destination_parent {
        sync_directory(source_parent)?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), SessionStoreError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_error("sync directory", path, error))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), SessionStoreError> {
    Ok(())
}

fn ingest_conflict(artifact_id: &str, message: impl Into<String>) -> SessionStoreError {
    SessionStoreError::IngestIntentConflict {
        artifact_id: artifact_id.to_owned(),
        message: bounded_detail(message.into()),
    }
}

fn bounded_detail(value: String) -> String {
    const MAX_DETAIL_CHARS: usize = 512;
    value.chars().take(MAX_DETAIL_CHARS).collect()
}

pub(crate) fn hash_file(path: &Path) -> Result<(u64, Sha256Digest), SessionStoreError> {
    let (mut file, _) = open_existing_plain_file(path, false)?;
    let result = hash_reader(&mut file, path)?;
    ensure_opened_file_identity(path, &file)?;
    Ok(result)
}

fn hash_staged_bounded(
    path: &Path,
    source_limit: u64,
) -> Result<(u64, Sha256Digest), SessionStoreError> {
    let (mut file, initial_metadata) = open_existing_plain_file(path, false)?;
    if initial_metadata.len() > source_limit {
        return Err(SessionStoreError::FileLimitExceeded {
            limit_bytes: source_limit,
            actual_bytes: initial_metadata.len(),
        });
    }
    let result = hash_reader_bounded(&mut file, path, source_limit)?;
    let current_metadata = file
        .metadata()
        .map_err(|error| io_error("inspect staged source after hashing", path, error))?;
    ensure_opened_file_identity(path, &file)?;
    if current_metadata.len() != initial_metadata.len() {
        return Err(SessionStoreError::FileIdentityChanged {
            path: path.to_path_buf(),
        });
    }
    Ok(result)
}

fn copy_and_hash_bounded<W: Write>(
    source: &mut File,
    destination: &mut W,
    source_path: &Path,
    source_limit: u64,
) -> Result<(u64, Sha256Digest), SessionStoreError> {
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = source
            .read(&mut buffer[..bounded_read_len(size, source_limit)])
            .map_err(|error| io_error("read staged source", source_path, error))?;
        if count == 0 {
            break;
        }
        size = checked_bounded_size(size, count, source_limit)?;
        destination
            .write_all(&buffer[..count])
            .map_err(|error| io_error("write private ingest copy", source_path, error))?;
        hasher.update(&buffer[..count]);
        invoke_copy_test_hook();
    }
    digest_from_hasher(hasher).map(|digest| (size, digest))
}

#[cfg(test)]
type CopyTestHook = Box<dyn FnOnce() + Send>;

#[cfg(test)]
static COPY_TEST_HOOK: OnceLock<Mutex<Option<CopyTestHook>>> = OnceLock::new();

#[cfg(test)]
fn invoke_copy_test_hook() {
    let hook = COPY_TEST_HOOK
        .get_or_init(|| Mutex::new(None))
        .lock()
        .expect("copy test hook mutex is not poisoned")
        .take();
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(not(test))]
fn invoke_copy_test_hook() {}

fn hash_reader_bounded(
    mut reader: impl Read,
    path: &Path,
    source_limit: u64,
) -> Result<(u64, Sha256Digest), SessionStoreError> {
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader
            .read(&mut buffer[..bounded_read_len(size, source_limit)])
            .map_err(|error| io_error("read artifact", path, error))?;
        if count == 0 {
            break;
        }
        size = checked_bounded_size(size, count, source_limit)?;
        hasher.update(&buffer[..count]);
    }
    digest_from_hasher(hasher).map(|digest| (size, digest))
}

fn bounded_read_len(size: u64, source_limit: u64) -> usize {
    let remaining_plus_one = source_limit.saturating_sub(size).saturating_add(1);
    usize::try_from(remaining_plus_one)
        .unwrap_or(usize::MAX)
        .min(64 * 1024)
}

fn checked_bounded_size(
    size: u64,
    count: usize,
    source_limit: u64,
) -> Result<u64, SessionStoreError> {
    let next = size
        .checked_add(u64::try_from(count).unwrap_or(u64::MAX))
        .ok_or(SessionStoreError::FileLimitExceeded {
            limit_bytes: source_limit,
            actual_bytes: u64::MAX,
        })?;
    if next > source_limit {
        return Err(SessionStoreError::FileLimitExceeded {
            limit_bytes: source_limit,
            actual_bytes: next,
        });
    }
    Ok(next)
}

fn digest_from_hasher(hasher: Sha256) -> Result<Sha256Digest, SessionStoreError> {
    let output = hasher.finalize();
    Sha256Digest::new(encode_hex(&output)).map_err(|error| SessionStoreError::InvalidDocument {
        document: "artifact digest",
        message: error.to_string(),
    })
}

fn hash_reader(
    mut reader: impl Read,
    path: &Path,
) -> Result<(u64, Sha256Digest), SessionStoreError> {
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| io_error("read artifact", path, error))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        size = size
            .checked_add(u64::try_from(count).unwrap_or(u64::MAX))
            .ok_or(SessionStoreError::FileLimitExceeded {
                limit_bytes: u64::MAX,
                actual_bytes: u64::MAX,
            })?;
    }
    let digest = digest_from_hasher(hasher)?;
    Ok((size, digest))
}

fn validate_artifact_identifier(value: &str, field: &'static str) -> Result<(), SessionStoreError> {
    if is_portable_artifact_id(value) {
        Ok(())
    } else {
        Err(invalid_spec(format!("{field} `{value}` is invalid")))
    }
}

fn validate_text(
    value: &str,
    field: &'static str,
    max_len: usize,
) -> Result<(), SessionStoreError> {
    if value.trim().is_empty() {
        return Err(invalid_spec(format!("{field} is empty or whitespace")));
    }
    if value.len() > max_len {
        return Err(invalid_spec(format!(
            "{field} is {} bytes; maximum is {max_len}",
            value.len()
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid_spec(format!(
            "{field} contains a control character"
        )));
    }
    Ok(())
}

fn active_writers() -> &'static Mutex<BTreeSet<PathBuf>> {
    ACTIVE_WRITERS.get_or_init(|| Mutex::new(BTreeSet::new()))
}

fn reserve_active_writer(session_path: &Path) -> Result<(), SessionStoreError> {
    let mut writers = active_writers()
        .lock()
        .expect("active artifact writer registry poisoned");
    if !writers.insert(session_path.to_path_buf()) {
        let session_id = session_path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or("<unknown>")
            .to_owned();
        return Err(SessionStoreError::ArtifactWriterActive { session_id });
    }
    Ok(())
}

fn release_active_writer(session_path: &Path) {
    active_writers()
        .lock()
        .expect("active artifact writer registry poisoned")
        .remove(session_path);
}

pub(crate) fn ensure_no_active_writer(session: &Session) -> Result<(), SessionStoreError> {
    let writers = active_writers()
        .lock()
        .expect("active artifact writer registry poisoned");
    if writers.contains(session.path()) {
        return Err(SessionStoreError::ArtifactWriterActive {
            session_id: session.id().to_string(),
        });
    }
    Ok(())
}

fn invalid_spec(message: impl Into<String>) -> SessionStoreError {
    SessionStoreError::InvalidArtifactSpec {
        message: message.into(),
    }
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

#[cfg(test)]
mod tests {
    use std::{fs, sync::Mutex};

    use tempfile::TempDir;

    use super::{COPY_TEST_HOOK, SessionStoreError, replace_private_copy_from_staged};

    #[test]
    fn private_copy_rejects_source_mutation_during_copy() {
        let temp = TempDir::new().unwrap();
        let staged = temp.path().join("staged.bin");
        let private = temp.path().join("private.bin");
        fs::write(&staged, vec![b'A'; 128 * 1024]).unwrap();

        let mutation_path = staged.clone();
        *COPY_TEST_HOOK
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap() = Some(Box::new(move || {
            fs::write(mutation_path, vec![b'B'; 128 * 1024]).unwrap();
        }));

        assert!(matches!(
            replace_private_copy_from_staged(&staged, &private, 128 * 1024),
            Err(SessionStoreError::FileIdentityChanged { .. })
        ));
    }
}
