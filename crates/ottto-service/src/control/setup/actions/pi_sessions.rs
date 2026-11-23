//! setup actions pi sessions for local control.

use crate::control::fs;
use crate::control::home_path;
#[cfg(unix)]
use crate::control::AsRawFd;
use crate::control::BTreeSet;
#[cfg(unix)]
use crate::control::Component;
#[cfg(unix)]
use crate::control::FromRawFd;
use crate::control::LocalApiError;
#[cfg(unix)]
use crate::control::MetadataExt;
#[cfg(unix)]
use crate::control::OpenOptionsExt;
#[cfg(unix)]
use crate::control::OsStrExt;
use crate::control::Path;
use crate::control::PathBuf;
use crate::control::SystemTime;
use crate::control::PI_SESSION_IMPORT_UNSUPPORTED_PLATFORM_REASON;

pub(in crate::control) struct PiSessionCensus {
    pub(in crate::control) root: OpenPiSessionRoot,
    pub(in crate::control) files: BTreeSet<PathBuf>,
}

pub(in crate::control) fn prepare_pi_live_session_census() -> Result<PiSessionCensus, LocalApiError>
{
    let root = open_or_create_pi_session_root()?;
    let files = pi_session_files_for_root(&root)?;
    Ok(PiSessionCensus { root, files })
}

#[cfg(test)]
pub(in crate::control) fn pi_session_files_in(
    root: &Path,
) -> Result<BTreeSet<PathBuf>, LocalApiError> {
    let Some(root) = open_pi_session_root_direct(root)? else {
        return Ok(BTreeSet::new());
    };
    pi_session_files_for_root(&root)
}

/// Every Pi session file under `root`, as a complete set or a refusal. The
/// walk never follows a symlink, so it cannot loop; the tree's own size is
/// the only bound.
pub(in crate::control) fn pi_session_files_for_root(
    root: &OpenPiSessionRoot,
) -> Result<BTreeSet<PathBuf>, LocalApiError> {
    verify_pi_session_root_path_identity(root)?;
    let mut files = BTreeSet::new();
    collect_pi_session_files(&root.path, &mut files)?;
    verify_pi_session_root_path_identity(root)?;
    validate_discovered_pi_session_files(root, files)
}

fn validate_discovered_pi_session_files(
    root: &OpenPiSessionRoot,
    files: BTreeSet<PathBuf>,
) -> Result<BTreeSet<PathBuf>, LocalApiError> {
    let mut validated = BTreeSet::new();
    for path in files {
        let file = open_pi_session_file_beneath_root(root, &path).map_err(|_| {
            pi_session_import_refused("session tree changed during bounded discovery")
        })?;
        let metadata = file.metadata().map_err(|_| {
            pi_session_import_refused("session tree changed during bounded discovery")
        })?;
        if !metadata.is_file() {
            return Err(pi_session_import_refused(
                "session tree changed during bounded discovery",
            ));
        }
        validated.insert(path);
    }
    verify_pi_session_root_path_identity(root)?;
    Ok(validated)
}

#[cfg(unix)]
fn verify_pi_session_root_path_identity(root: &OpenPiSessionRoot) -> Result<(), LocalApiError> {
    let opened = root
        .directory
        .metadata()
        .map_err(|_| pi_session_import_refused("session root identity could not be verified"))?;
    let current = fs::metadata(&root.path)
        .map_err(|_| pi_session_import_refused("session root changed during bounded discovery"))?;
    if !current.is_dir() || opened.dev() != current.dev() || opened.ino() != current.ino() {
        return Err(pi_session_import_refused(
            "session root changed during bounded discovery",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_pi_session_root_path_identity(root: &OpenPiSessionRoot) -> Result<(), LocalApiError> {
    let _ = root;
    require_pi_session_import_platform_support()
}

fn collect_pi_session_files(
    path: &Path,
    files: &mut BTreeSet<PathBuf>,
) -> Result<(), LocalApiError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        pi_session_import_refused("session traversal could not inspect a directory entry")
    })?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    };
    if metadata.is_file() {
        if path.extension().and_then(|extension| extension.to_str()) == Some("jsonl") {
            files.insert(path.to_path_buf());
        }
        return Ok(());
    }
    if !metadata.is_dir() {
        return Ok(());
    }
    let entries = fs::read_dir(path)
        .map_err(|_| pi_session_import_refused("session traversal could not open a directory"))?;
    for entry in entries {
        let entry = entry.map_err(|_| {
            pi_session_import_refused("session traversal could not read a directory entry")
        })?;
        collect_pi_session_files(&entry.path(), files)?;
    }
    Ok(())
}

pub(in crate::control) fn new_pi_route_session_files(
    before: &PiSessionCensus,
) -> Result<Vec<PathBuf>, LocalApiError> {
    Ok(pi_session_files_for_root(&before.root)?
        .difference(&before.files)
        .cloned()
        .collect())
}

/// Local Pi session files modified at or after `since`. The passive
/// (no-live-smoke) subscription-OAuth verify path uses only their presence as
/// local evidence; it never runs `pi` and never uploads or reads transcript
/// contents (the direct Pi import endpoint is retired).
pub(in crate::control) fn recent_pi_session_files(
    since: SystemTime,
) -> Result<Option<Vec<PathBuf>>, LocalApiError> {
    let Some(root) = open_pi_session_root()? else {
        return Ok(None);
    };
    let files = pi_session_files_for_root(&root)?;
    pi_session_files_modified_since(&root, files, since).map(Some)
}

/// Keep only session files whose on-disk mtime is at or after `since`. Files
/// whose metadata can't be read are dropped (treated as not-recent), matching
/// the conservative behavior of the live census. Pure helper so the mtime
/// bound used by the passive Pi route verifier is unit-testable without the
/// network calls.
pub(in crate::control) fn pi_session_files_modified_since(
    root: &OpenPiSessionRoot,
    files: impl IntoIterator<Item = PathBuf>,
    since: SystemTime,
) -> Result<Vec<PathBuf>, LocalApiError> {
    let mut recent = Vec::new();
    for path in files {
        let file = match open_pi_session_file_beneath_root(root, &path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                return Err(pi_session_import_refused(
                    "session tree changed during recent-file selection",
                ))
            }
        };
        let modified = file
            .metadata()
            .and_then(|metadata| metadata.modified())
            .map_err(|_| {
                pi_session_import_refused("session tree changed during recent-file selection")
            })?;
        if modified >= since {
            recent.push(path);
        }
    }
    verify_pi_session_root_path_identity(root)?;
    Ok(recent)
}

fn pi_session_import_refused(reason: &str) -> LocalApiError {
    LocalApiError::LocalOperationFailed(format!("Pi session import refused: {reason}"))
}

const fn pi_session_import_supported_on_target() -> bool {
    cfg!(unix)
}

fn require_pi_session_import_platform_support() -> Result<(), LocalApiError> {
    if pi_session_import_supported_on_target() {
        Ok(())
    } else {
        Err(pi_session_import_refused(
            PI_SESSION_IMPORT_UNSUPPORTED_PLATFORM_REASON,
        ))
    }
}

pub(in crate::control) struct OpenPiSessionRoot {
    pub(in crate::control) path: PathBuf,
    pub(in crate::control) directory: fs::File,
}

fn open_pi_session_root() -> Result<Option<OpenPiSessionRoot>, LocalApiError> {
    let home = home_path("");
    open_pi_session_root_from_home(&home, &crate::agent_status::pi_sessions_dir(&home))
}

fn open_or_create_pi_session_root() -> Result<OpenPiSessionRoot, LocalApiError> {
    require_pi_session_import_platform_support()?;
    let home = home_path("");
    open_or_create_pi_session_root_from_home_io(&home, &crate::agent_status::pi_sessions_dir(&home))
        .map_err(|_| pi_session_import_refused("session root could not be safely established"))
}

#[cfg(test)]
pub(in crate::control) fn open_pi_session_root_direct(
    root: &Path,
) -> Result<Option<OpenPiSessionRoot>, LocalApiError> {
    require_pi_session_import_platform_support()?;
    match open_pi_session_root_direct_io(root) {
        Ok(root) => Ok(Some(root)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(LocalApiError::LocalOperationFailed(error.to_string())),
    }
}

pub(in crate::control) fn open_pi_session_root_from_home(
    home: &Path,
    sessions: &Path,
) -> Result<Option<OpenPiSessionRoot>, LocalApiError> {
    require_pi_session_import_platform_support()?;
    match open_pi_session_root_from_home_io(home, sessions) {
        Ok(root) => Ok(Some(root)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(LocalApiError::LocalOperationFailed(error.to_string())),
    }
}

#[cfg(unix)]
pub(in crate::control) fn open_pi_session_root_direct_io(
    root: &Path,
) -> std::io::Result<OpenPiSessionRoot> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let directory = options.open(root)?;
    Ok(OpenPiSessionRoot {
        path: root.to_path_buf(),
        directory,
    })
}

/// The components of `sessions` below `home`, walked one by one from the
/// trusted home directory. A sessions directory outside `home`, relative, or
/// with `..` is refused, and never as NotFound, so neither open path reports
/// it as "no root". (`Path` drops interior `.` components.)
#[cfg(unix)]
fn pi_session_components<'a>(
    home: &Path,
    sessions: &'a Path,
) -> std::io::Result<Vec<&'a std::ffi::OsStr>> {
    let outside = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Pi session directory is not below the home directory",
        )
    };
    sessions
        .strip_prefix(home)
        .map_err(|_| outside())?
        .components()
        .map(|component| match component {
            std::path::Component::Normal(name) => Ok(name),
            _ => Err(outside()),
        })
        .collect()
}

#[cfg(unix)]
fn open_pi_session_root_from_home_io(
    home: &Path,
    sessions: &Path,
) -> std::io::Result<OpenPiSessionRoot> {
    walk_pi_session_root_from_home(home, sessions, open_pi_directory_component)
}

#[cfg(unix)]
pub(in crate::control) fn open_or_create_pi_session_root_from_home_io(
    home: &Path,
    sessions: &Path,
) -> std::io::Result<OpenPiSessionRoot> {
    walk_pi_session_root_from_home(home, sessions, open_or_create_pi_directory_component)
}

/// Walks `sessions` one component at a time from the trusted home directory,
/// each opened by `open`.
#[cfg(unix)]
fn walk_pi_session_root_from_home(
    home: &Path,
    sessions: &Path,
    open: fn(&fs::File, &std::ffi::OsStr) -> std::io::Result<fs::File>,
) -> std::io::Result<OpenPiSessionRoot> {
    let components = pi_session_components(home, sessions)?;
    let trusted_home = open_pi_session_root_direct_io(home)?;
    let mut directory = trusted_home.directory;
    let mut path = home.to_path_buf();
    for component in components {
        directory = open(&directory, component)?;
        path.push(component);
    }
    Ok(OpenPiSessionRoot { path, directory })
}

#[cfg(unix)]
fn open_pi_directory_component(
    directory: &fs::File,
    name: &std::ffi::OsStr,
) -> std::io::Result<fs::File> {
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Pi session directory contains a NUL byte",
        )
    })?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn open_or_create_pi_directory_component(
    directory: &fs::File,
    name: &std::ffi::OsStr,
) -> std::io::Result<fs::File> {
    open_or_create_pi_directory_component_with(directory, name, mkdir_pi_directory_component)
}

#[cfg(unix)]
pub(in crate::control) fn open_or_create_pi_directory_component_with<Mkdir>(
    directory: &fs::File,
    name: &std::ffi::OsStr,
    mkdir: Mkdir,
) -> std::io::Result<fs::File>
where
    Mkdir: FnOnce(&fs::File, &std::ffi::OsStr) -> std::io::Result<()>,
{
    match open_pi_directory_component(directory, name) {
        Ok(opened) => Ok(opened),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Err(create_error) = mkdir(directory, name) {
                if create_error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(create_error);
                }
            }
            // Always reopen through the held parent descriptor. This accepts a
            // benign EEXIST race only when the winner created a real directory;
            // O_NOFOLLOW refuses a symlink or other replacement.
            open_pi_directory_component(directory, name)
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn mkdir_pi_directory_component(
    directory: &fs::File,
    name: &std::ffi::OsStr,
) -> std::io::Result<()> {
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Pi session directory contains a NUL byte",
        )
    })?;
    let created = unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) };
    if created < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
pub(in crate::control) fn open_pi_session_root_direct_io(
    _root: &Path,
) -> std::io::Result<OpenPiSessionRoot> {
    Err(pi_session_import_unsupported_io_error())
}

#[cfg(not(unix))]
fn open_pi_session_root_from_home_io(
    _home: &Path,
    _sessions: &Path,
) -> std::io::Result<OpenPiSessionRoot> {
    Err(pi_session_import_unsupported_io_error())
}

#[cfg(not(unix))]
pub(in crate::control) fn open_or_create_pi_session_root_from_home_io(
    _home: &Path,
    _sessions: &Path,
) -> std::io::Result<OpenPiSessionRoot> {
    Err(pi_session_import_unsupported_io_error())
}

#[cfg(unix)]
pub(in crate::control) fn open_pi_session_file_beneath_root(
    root: &OpenPiSessionRoot,
    path: &Path,
) -> std::io::Result<fs::File> {
    let relative = path.strip_prefix(&root.path).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Pi session file escaped its session root",
        )
    })?;
    let components = relative.components().collect::<Vec<_>>();
    if components.is_empty()
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Pi session file is not root-relative",
        ));
    }

    let mut directory = root.directory.try_clone()?;
    for (position, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            unreachable!("components validated above")
        };
        let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Pi session file contains a NUL byte",
            )
        })?;
        let is_final = position + 1 == components.len();
        let flags = if is_final {
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK
        } else {
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
        };
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let opened = unsafe { fs::File::from_raw_fd(fd) };
        if is_final {
            return Ok(opened);
        }
        directory = opened;
    }
    unreachable!("non-empty component list returns its final object")
}

#[cfg(not(unix))]
pub(in crate::control) fn open_pi_session_file_beneath_root(
    _root: &OpenPiSessionRoot,
    _path: &Path,
) -> std::io::Result<fs::File> {
    Err(pi_session_import_unsupported_io_error())
}

#[cfg(not(unix))]
fn pi_session_import_unsupported_io_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        PI_SESSION_IMPORT_UNSUPPORTED_PLATFORM_REASON,
    )
}
