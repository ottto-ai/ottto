//! The daemon's held state-directory lock, reachable from the library.
//!
//! `serve` and `serve-xpc` take #801's `StateDirLock` before anything else
//! and hand it here, where it stays for the life of the process. Writers of
//! daemon-owned caches that must never have a second writer (the M1
//! durable-tail store) ask for it with [`held_for`]; a process that does not
//! hold it (a CLI command, a test) gets `None` and writes nothing.
//!
//! Dropping #801's lock unlocks it (#812). The holder here is a process
//! static, never dropped (like `StateDirLock::hold_until_exit`), so the lock
//! is released at process exit (or crash) and not before. Nothing here
//! relies on when that happens.
//!
//! It also owns the low-level file primitives state writers share: an
//! exclusive `flock` guard and the temp-then-rename writers. Each caller
//! keeps its own lock order, transaction and error text.

use crate::state_dir_lock::{StateDirLock, StateDirLockError};
use anyhow::Context;
use serde::Serialize;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

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

/// An exclusive `flock` on an open file, unlocked (`LOCK_UN`) on drop before
/// the file closes.
#[derive(Debug)]
pub(crate) struct FileLock(File);

impl FileLock {
    /// Waits for the lock.
    pub(crate) fn exclusive(file: File) -> io::Result<Self> {
        Self::lock(file, libc::LOCK_EX)
    }

    /// Fails with `EWOULDBLOCK` when another open file holds the lock.
    pub(crate) fn try_exclusive(file: File) -> io::Result<Self> {
        Self::lock(file, libc::LOCK_EX | libc::LOCK_NB)
    }

    fn lock(file: File, operation: libc::c_int) -> io::Result<Self> {
        // SAFETY: flock on the live descriptor `file` owns.
        if unsafe { libc::flock(file.as_raw_fd(), operation) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(file))
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // SAFETY: flock on the live descriptor this guard owns.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Opens `path` read-write for locking: created 0600, never through a
/// symlink, closed on exec.
pub(crate) fn open_private_lock_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

/// `<stem>.<kind>.<pid>.<nanos>.json` beside `path`, for a temp, tombstone or
/// quarantine name no other writer uses.
pub(crate) fn unique_sibling(path: &Path, kind: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    path.with_extension(format!("{kind}.{}.{nanos}.json", std::process::id()))
}

/// Best-effort cache write: create the parent, write `<stem>.json.tmp`, rename
/// it over `path`. No fsync; any failure leaves the old file and is ignored.
pub(crate) fn write_json_atomic(path: &Path, value: &impl Serialize) {
    let Some(dir) = path.parent() else {
        return;
    };
    if fs::create_dir_all(dir).is_err() {
        return;
    }
    let Ok(payload) = serde_json::to_vec(value) else {
        return;
    };
    let temp = path.with_extension("json.tmp");
    if fs::write(&temp, &payload).is_ok() {
        let _ = fs::rename(&temp, path);
    }
}

/// Replaces `path` with `payload` through `<stem>.json.tmp`: create
/// (truncating), write, best-effort fsync, rename while the temp is open. No
/// directory fsync. Errors read `create|write <temp_label> temp <temp path>`
/// and `rename <cache_label> into place <path>`.
pub(crate) fn replace_json_cache(
    path: &Path,
    payload: &[u8],
    temp_label: &str,
    cache_label: &str,
) -> anyhow::Result<()> {
    let temp_path = path.with_extension("json.tmp");
    let mut temp = File::create(&temp_path)
        .with_context(|| format!("create {temp_label} temp {}", temp_path.display()))?;
    temp.write_all(payload)
        .with_context(|| format!("write {temp_label} temp {}", temp_path.display()))?;
    temp.sync_all().ok();
    fs::rename(&temp_path, path)
        .with_context(|| format!("rename {cache_label} into place {}", path.display()))
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
