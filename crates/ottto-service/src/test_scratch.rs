//! Shared scratch-directory helpers for this crate's unit tests.
//!
//! Scratch paths used to be keyed on `<pid>-<counter>` and created with
//! `create_dir_all`, which adopts whatever already sits at the path. Pids are
//! reused across runs, so a directory that a panicking test left behind was
//! handed straight to a later run, carrying whatever mode and whatever files it
//! happened to hold. That is how a directory poisoned to `0o600` - readable but
//! with no execute bit, so untraversable - reached a later run and failed every
//! write inside it with EACCES.
//!
//! Everything here is built so a leftover can never be adopted: names carry 64
//! random bits, creation refuses an existing path, and the mode is pinned
//! rather than inherited from a umask another thread can move.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(1);

/// Builds a scratch name from `prefix`. The pid and a per-process counter keep
/// a failing run's directories greppable; the random suffix is what makes the
/// name unreusable by any later run.
pub(crate) fn unique_name(prefix: &str) -> String {
    let mut suffix = [0_u8; 8];
    getrandom::fill(&mut suffix).expect("random scratch name");
    format!(
        "{prefix}-{}-{}-{:016x}",
        std::process::id(),
        NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed),
        u64::from_ne_bytes(suffix)
    )
}

/// An unused scratch path directly under `$TMPDIR`. The directory is not
/// created; callers that want one should use [`private_dir`].
pub(crate) fn unique_path(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(unique_name(prefix))
}

/// Creates `path` as an owner-only directory and refuses to adopt anything
/// already there: `create_dir` (unlike `create_dir_all`) fails with
/// `AlreadyExists`. The mode is pinned explicitly because `mkdir` masks its
/// requested mode with the process umask, which another thread can move.
pub(crate) fn create_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::create_dir(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// A fresh owner-only scratch directory under `$TMPDIR`.
pub(crate) fn private_dir(prefix: &str) -> PathBuf {
    for _ in 0..16 {
        let path = unique_path(prefix);
        match create_private_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create scratch directory {}: {error}", path.display()),
        }
    }
    panic!("no unique scratch directory name after 16 attempts");
}

/// Owner-only scratch directory that is removed when it goes out of scope,
/// including while a failing test unwinds, so a panicking test cannot leave
/// anything behind for a later run.
pub(crate) struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    pub(crate) fn new(prefix: &str) -> Self {
        Self {
            path: private_dir(prefix),
        }
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;

        // Restore traversal first so cleanup still works for a test that
        // narrowed the directory on purpose.
        let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

impl std::ops::Deref for ScratchDir {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<Path> for ScratchDir {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}
