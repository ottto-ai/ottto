//! The daemon's held state-directory lock, reachable from the library.
//!
//! `serve` and `serve-xpc` take #801's `StateDirLock` before anything else
//! and hand it here, where it stays for the life of the process. Writers of
//! daemon-owned caches that must never have a second writer (the M1
//! durable-tail store) ask for it with [`held_for`]; a process that does not
//! hold it (a CLI command, a test) gets `None` and writes nothing.
//!
//! #801's lock is close-only: it never calls `LOCK_UN`, and the kernel
//! releases it when its descriptor closes. Nothing here relies on when that
//! happens. The holder is a process static, never dropped, so the lock is
//! released at process exit (or crash) and not before.

use crate::state_dir_lock::{StateDirLock, StateDirLockError};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// #801's lock together with the directory it locks.
#[derive(Debug)]
pub struct LockedStateDir {
    dir: PathBuf,
    _lock: StateDirLock,
}

impl LockedStateDir {
    /// `StateDirLock::acquire` on `dir`, unchanged; the directory is kept so
    /// a writer can check its files live inside the locked directory.
    pub fn acquire(dir: &Path) -> Result<Self, StateDirLockError> {
        StateDirLock::acquire(dir).map(|lock| Self {
            dir: dir.to_path_buf(),
            _lock: lock,
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

static PROCESS: OnceLock<LockedStateDir> = OnceLock::new();

/// Keeps `locked` for the rest of the process. A daemon takes the lock once,
/// first; a later call keeps the first holder.
pub fn hold_for_process(locked: LockedStateDir) -> &'static LockedStateDir {
    PROCESS.get_or_init(|| locked)
}

/// The lock this process holds on the state directory containing `path`,
/// if it is the daemon and `path` is inside the directory it locked.
pub(crate) fn held_for(path: &Path) -> Option<&'static LockedStateDir> {
    if let Some(locked) = PROCESS.get().filter(|locked| path.starts_with(&locked.dir)) {
        return Some(locked);
    }
    #[cfg(test)]
    if let Some(locked) = test_locks::held_for(path) {
        return Some(locked);
    }
    None
}

/// Tests stand in for the daemon on their own scratch state directory. The
/// lock is taken with #801's real `acquire` and kept until the test process
/// exits (it is never dropped), like the daemon's.
#[cfg(test)]
pub(crate) mod test_locks {
    use super::LockedStateDir;
    use std::path::Path;
    use std::sync::Mutex;

    static HELD: Mutex<Vec<&'static LockedStateDir>> = Mutex::new(Vec::new());

    pub(crate) fn hold(dir: &Path) -> &'static LockedStateDir {
        let locked: &'static LockedStateDir = Box::leak(Box::new(
            LockedStateDir::acquire(dir).expect("scratch state dir lock"),
        ));
        HELD.lock().unwrap().push(locked);
        locked
    }

    pub(super) fn held_for(path: &Path) -> Option<&'static LockedStateDir> {
        HELD.lock()
            .unwrap()
            .iter()
            .copied()
            .find(|locked| path.starts_with(&locked.dir))
    }
}
