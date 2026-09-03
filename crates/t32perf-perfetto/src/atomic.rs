use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde::Deserialize;
use serde::de::IgnoredAny;
use t32perf_model::{FunctionSpan, Observation, ObservationDictionary};

use crate::{ExportError, TraceConfig, write_trace};

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const TEMPORARY_ATTEMPTS: u64 = 128;

/// Streams a trace to a sibling temporary file, validates it, and atomically renames it.
///
/// The destination must not already exist. The temporary file is created in the
/// destination directory so the final rename remains on one filesystem. Any
/// conversion, flush, sync, validation, or rename failure removes the temporary file.
pub fn export_atomic<'dictionary, 'span, 'observation, D, S, O>(
    target: impl AsRef<Path>,
    config: TraceConfig,
    dictionaries: D,
    spans: S,
    observations: O,
) -> Result<(), ExportError>
where
    D: IntoIterator<Item = &'dictionary ObservationDictionary>,
    S: IntoIterator<Item = &'span FunctionSpan>,
    O: IntoIterator<Item = &'observation Observation>,
{
    let target = target.as_ref();
    if target.exists() {
        return Err(ExportError::TargetExists(target.to_path_buf()));
    }
    let (temporary_path, temporary_file) = create_temporary_file(target)?;
    let mut temporary = TemporaryGuard::new(temporary_path);

    let buffered = BufWriter::new(temporary_file);
    let mut buffered = write_trace(buffered, config, dictionaries, spans, observations)?;
    buffered.flush()?;
    let file = buffered.into_inner().map_err(|error| error.into_error())?;
    file.sync_all()?;
    drop(file);

    validate_json(temporary.path())?;
    if target.exists() {
        return Err(ExportError::TargetExists(target.to_path_buf()));
    }
    fs::rename(temporary.path(), target)?;
    temporary.commit();
    Ok(())
}

fn create_temporary_file(target: &Path) -> Result<(PathBuf, File), ExportError> {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let file_name = target
        .file_name()
        .ok_or_else(|| ExportError::MissingTargetFileName(target.to_path_buf()))?;
    let process_id = std::process::id();

    for _ in 0..TEMPORARY_ATTEMPTS {
        let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut temporary_name = OsString::from(file_name);
        temporary_name.push(format!(".tmp-{process_id}-{sequence}"));
        let path = parent.join(temporary_name);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(ExportError::TemporaryPathExhausted(target.to_path_buf()))
}

fn validate_json(path: &Path) -> Result<(), ExportError> {
    let file = File::open(path)?;
    let mut deserializer = serde_json::Deserializer::from_reader(BufReader::new(file));
    IgnoredAny::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(())
}

struct TemporaryGuard {
    path: PathBuf,
    committed: bool,
}

impl TemporaryGuard {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for TemporaryGuard {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}
