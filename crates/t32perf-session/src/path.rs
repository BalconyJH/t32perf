//! Link-rejecting path traversal inside one canonical artifact root.
//!
//! The artifact root must not be concurrently writable by an untrusted
//! principal. These checks reject links and reparse points observed by the
//! process; they are not a handle-relative defense against malicious parent
//! directory replacement races.

use std::{
    fs::{self, File, Metadata, OpenOptions},
    io,
    path::{Path, PathBuf},
};

use t32perf_model::ArtifactPath;

use crate::{SessionStoreError, error::io_error};

const MAX_SESSION_DIRECTORY_ENTRIES: usize = 65_536;
const MAX_SESSION_DIRECTORY_DEPTH: usize = 512;

pub(crate) fn canonical_root(path: &Path) -> Result<PathBuf, SessionStoreError> {
    match fs::symlink_metadata(path) {
        Ok(_) => reject_link(path)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)
                .map_err(|error| io_error("create artifact root", path, error))?;
        }
        Err(error) => return Err(io_error("inspect artifact root", path, error)),
    }
    let root = fs::canonicalize(path)
        .map_err(|error| io_error("canonicalize artifact root", path, error))?;
    let metadata = fs::symlink_metadata(&root)
        .map_err(|error| io_error("inspect artifact root", &root, error))?;
    if !metadata.is_dir() || is_link_like(&metadata) {
        return Err(SessionStoreError::InvalidRoot { path: root });
    }
    Ok(root)
}

pub(crate) fn ensure_plain_directory(path: &Path) -> Result<(), SessionStoreError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| io_error("inspect directory", path, error))?;
    if is_link_like(&metadata) {
        return Err(SessionStoreError::LinkNotAllowed {
            path: path.to_path_buf(),
        });
    }
    if !metadata.is_dir() {
        return Err(SessionStoreError::InvalidRoot {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

pub(crate) fn ensure_plain_file(path: &Path) -> Result<Metadata, SessionStoreError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| io_error("inspect file", path, error))?;
    if is_link_like(&metadata) {
        return Err(SessionStoreError::LinkNotAllowed {
            path: path.to_path_buf(),
        });
    }
    if !metadata.is_file() {
        return Err(SessionStoreError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    Ok(metadata)
}

pub(crate) fn open_existing_plain_file(
    path: &Path,
    writable: bool,
) -> Result<(File, Metadata), SessionStoreError> {
    open_plain_file(path, writable, false)
}

pub(crate) fn open_or_create_plain_file(
    path: &Path,
    writable: bool,
) -> Result<(File, Metadata), SessionStoreError> {
    open_plain_file(path, writable, true)
}

/// Creates one previously absent plain file without following links.
///
/// Unlike [`open_or_create_plain_file`], this never opens an existing entry.
/// Callers use it for host-owned staging materialization where an incomplete
/// prior write must remain observable rather than being overwritten.
pub(crate) fn create_new_plain_file(path: &Path) -> Result<(File, Metadata), SessionStoreError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            return Err(SessionStoreError::ArtifactExists {
                path: path.to_path_buf(),
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error("inspect new plain file", path, error)),
    }

    let file =
        open_new_nofollow(path).map_err(|error| io_error("create new plain file", path, error))?;
    let metadata = ensure_opened_file_identity(path, &file)?;
    Ok((file, metadata))
}

fn open_plain_file(
    path: &Path,
    writable: bool,
    create: bool,
) -> Result<(File, Metadata), SessionStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_plain_metadata(path, &metadata)?,
        Err(error) if create && error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error("inspect file before open", path, error)),
    }

    let file = open_nofollow(path, writable, create)
        .map_err(|error| io_error("open plain file", path, error))?;
    let opened_metadata = ensure_opened_file_identity(path, &file)?;
    Ok((file, opened_metadata))
}

pub(crate) fn ensure_opened_file_identity(
    path: &Path,
    file: &File,
) -> Result<Metadata, SessionStoreError> {
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect opened file", path, error))?;
    validate_plain_metadata(path, &metadata)?;
    verify_opened_identity(path, file, &metadata)?;
    Ok(metadata)
}

fn open_nofollow(path: &Path, writable: bool, create: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(writable)
        .create(create)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;

        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn open_new_nofollow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;

        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn validate_plain_metadata(path: &Path, metadata: &Metadata) -> Result<(), SessionStoreError> {
    if is_link_like(metadata) {
        return Err(SessionStoreError::LinkNotAllowed {
            path: path.to_path_buf(),
        });
    }
    if !metadata.is_file() {
        return Err(SessionStoreError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

/// Verifies that `file` remains the plain filesystem object currently named by
/// `path`, without following links or reparse points.
///
/// This is the narrow read-only primitive for deployment control files that
/// live outside a Session artifact namespace.
pub fn verify_opened_plain_file_identity(
    path: &Path,
    file: &File,
) -> Result<(), SessionStoreError> {
    let opened = file
        .metadata()
        .map_err(|error| io_error("inspect opened plain file", path, error))?;
    validate_plain_metadata(path, &opened)?;
    verify_opened_identity(path, file, &opened)
}

#[cfg(unix)]
fn verify_opened_identity(
    path: &Path,
    _file: &File,
    opened_metadata: &Metadata,
) -> Result<(), SessionStoreError> {
    use std::os::unix::fs::MetadataExt as _;

    let current = ensure_plain_file(path)?;
    if opened_metadata.dev() != current.dev() || opened_metadata.ino() != current.ino() {
        return Err(SessionStoreError::FileIdentityChanged {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(windows)]
fn verify_opened_identity(
    path: &Path,
    file: &File,
    _opened_metadata: &Metadata,
) -> Result<(), SessionStoreError> {
    let current = open_nofollow(path, false, false)
        .map_err(|error| io_error("reopen plain file for identity check", path, error))?;
    let current_metadata = current
        .metadata()
        .map_err(|error| io_error("inspect reopened file", path, error))?;
    validate_plain_metadata(path, &current_metadata)?;
    if windows_file_identity(file).map_err(|error| io_error("identify opened file", path, error))?
        != windows_file_identity(&current)
            .map_err(|error| io_error("identify current file", path, error))?
    {
        return Err(SessionStoreError::FileIdentityChanged {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(windows)]
fn windows_file_identity(file: &File) -> io::Result<(u32, u64)> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `file` owns a valid handle and `information` is writable for the call.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let index =
        u64::from(information.nFileIndexLow) | (u64::from(information.nFileIndexHigh) << 32);
    Ok((information.dwVolumeSerialNumber, index))
}

#[cfg(not(any(unix, windows)))]
fn verify_opened_identity(
    path: &Path,
    _file: &File,
    opened_metadata: &Metadata,
) -> Result<(), SessionStoreError> {
    let current = ensure_plain_file(path)?;
    if opened_metadata.len() != current.len() {
        return Err(SessionStoreError::FileIdentityChanged {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

pub(crate) fn resolve_existing_session(
    root: &Path,
    session_id: &str,
) -> Result<PathBuf, SessionStoreError> {
    let path = root.join(session_id);
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(SessionStoreError::SessionNotFound {
                session_id: session_id.to_owned(),
            });
        }
        Err(error) => return Err(io_error("inspect Session entry", &path, error)),
    }
    ensure_plain_directory(&path)?;
    let resolved =
        fs::canonicalize(&path).map_err(|error| io_error("canonicalize session", &path, error))?;
    if !resolved.starts_with(root) {
        return Err(SessionStoreError::OutsideArtifactRoot { path: resolved });
    }
    Ok(resolved)
}

pub(crate) fn resolve_artifact(
    session: &Path,
    relative: &ArtifactPath,
    create_parents: bool,
) -> Result<PathBuf, SessionStoreError> {
    let segments: Vec<_> = relative.as_str().split('/').collect();
    let mut current = session.to_path_buf();
    for (index, segment) in segments.iter().enumerate() {
        current.push(segment);
        let is_leaf = index + 1 == segments.len();
        match fs::symlink_metadata(&current) {
            Ok(_) => {
                reject_link(&current)?;
                if !is_leaf {
                    ensure_plain_directory(&current)?;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if !is_leaf && create_parents {
                    fs::create_dir(&current)
                        .map_err(|error| io_error("create artifact directory", &current, error))?;
                    ensure_plain_directory(&current)?;
                }
            }
            Err(error) => return Err(io_error("inspect artifact path", &current, error)),
        }
    }
    if !current.starts_with(session) {
        return Err(SessionStoreError::OutsideArtifactRoot { path: current });
    }
    Ok(current)
}

pub(crate) fn directory_size(path: &Path) -> Result<u64, SessionStoreError> {
    directory_size_with_limits(
        path,
        MAX_SESSION_DIRECTORY_ENTRIES,
        MAX_SESSION_DIRECTORY_DEPTH,
    )
}

fn directory_size_with_limits(
    path: &Path,
    entry_limit: usize,
    depth_limit: usize,
) -> Result<u64, SessionStoreError> {
    let mut total = 0_u64;
    let mut entry_count = 0_usize;
    let mut pending = vec![(path.to_path_buf(), 0_usize)];
    while let Some((directory, depth)) = pending.pop() {
        if depth > depth_limit {
            return Err(SessionStoreError::DirectoryDepthLimitExceeded {
                limit: depth_limit,
                path: directory,
            });
        }
        ensure_plain_directory(&directory)?;
        let entries = fs::read_dir(&directory)
            .map_err(|error| io_error("read session directory", &directory, error))?;
        for entry in entries {
            let entry = entry.map_err(|error| io_error("read session entry", &directory, error))?;
            entry_count = entry_count.checked_add(1).ok_or(
                SessionStoreError::DirectoryEntryLimitExceeded {
                    limit: entry_limit,
                    actual: usize::MAX,
                },
            )?;
            if entry_count > entry_limit {
                return Err(SessionStoreError::DirectoryEntryLimitExceeded {
                    limit: entry_limit,
                    actual: entry_count,
                });
            }
            let entry_path = entry.path();
            let metadata = fs::symlink_metadata(&entry_path)
                .map_err(|error| io_error("inspect session entry", &entry_path, error))?;
            if is_link_like(&metadata) {
                return Err(SessionStoreError::LinkNotAllowed { path: entry_path });
            }
            if metadata.is_dir() {
                pending.push((entry_path, depth.saturating_add(1)));
            } else if metadata.is_file() {
                total = total.checked_add(metadata.len()).ok_or(
                    SessionStoreError::SessionLimitExceeded {
                        limit_bytes: u64::MAX,
                        actual_bytes: u64::MAX,
                    },
                )?;
            } else {
                return Err(SessionStoreError::NotRegularFile { path: entry_path });
            }
        }
    }
    Ok(total)
}

fn reject_link(path: &Path) -> Result<(), SessionStoreError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| io_error("inspect path", path, error))?;
    if is_link_like(&metadata) {
        return Err(SessionStoreError::LinkNotAllowed {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

pub(crate) fn is_link_like(metadata: &Metadata) -> bool {
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

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::directory_size_with_limits;
    use crate::SessionStoreError;

    #[test]
    fn directory_size_stops_at_entry_and_depth_limits() {
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join("a"), b"a").unwrap();
        fs::write(temp.path().join("b"), b"bb").unwrap();
        assert!(matches!(
            directory_size_with_limits(temp.path(), 1, 8),
            Err(SessionStoreError::DirectoryEntryLimitExceeded { .. })
        ));

        let nested = temp.path().join("nested");
        fs::create_dir(&nested).unwrap();
        fs::create_dir(nested.join("deeper")).unwrap();
        assert!(matches!(
            directory_size_with_limits(temp.path(), 16, 1),
            Err(SessionStoreError::DirectoryDepthLimitExceeded { .. })
        ));
    }
}
