//! The daemon's held state-directory lock, reachable from the library.
//!
//! `serve` and `serve-xpc` take the `StateDirLock` before anything else
//! and hand it here, where it stays for the life of the process. Writers of
//! daemon-owned caches that must never have a second writer (the
//! durable-tail store) ask for it with [`held_for`]; a process that does not
//! hold it (a CLI command, a test) gets `None` and writes nothing.
//!
//! Dropping the state-directory lock unlocks it. The holder here is a process
//! static, never dropped (like `StateDirLock::hold_until_exit`), so the lock
//! is released at process exit (or crash) and not before. Nothing here
//! relies on when that happens.
//!
//! It also owns the low-level file primitives state writers share: an
//! exclusive `flock` guard and the temp-then-rename writers. Each caller
//! keeps its own lock order, transaction and error text.

pub(crate) use crate::local_resource_diagnostics::cache_lifecycle::JsonCacheKind;
use crate::local_resource_diagnostics::cache_lifecycle::{add, json_cache, Event};
use crate::state_dir_lock::{StateDirLock, StateDirLockError};
use anyhow::Context;
use serde::Serialize;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The lock together with the directory it protects.
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

/// Best-effort cache write: create the parent, write `<stem>.json.tmp`, rename
/// it over `path`. No fsync; any failure leaves the old file and is ignored.
/// Best-effort cache writes only; not for durable custody state.
pub(crate) fn write_json_atomic(path: &Path, value: &impl Serialize, kind: JsonCacheKind) {
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
        count_cache_bytes(kind, payload.len());
        let _ = fs::rename(&temp, path);
    }
}

/// Diagnostics only: the total and the per-kind byte counters.
fn count_cache_bytes(kind: JsonCacheKind, bytes: usize) {
    add(Event::SharedCacheBytes, bytes as u64);
    json_cache::add(kind, bytes as u64);
}

/// Replaces `path` with `payload` through `<stem>.json.tmp`: create
/// (truncating), write, best-effort fsync, rename while the temp is open. No
/// directory fsync. Errors read `create|write <temp_label> temp <temp path>`
/// and `rename <cache_label> into place <path>`.
/// Best-effort cache writes only; not for durable custody state.
pub(crate) fn replace_json_cache(
    path: &Path,
    payload: &[u8],
    temp_label: &str,
    cache_label: &str,
    kind: JsonCacheKind,
) -> anyhow::Result<()> {
    let temp_path = path.with_extension("json.tmp");
    let mut temp = File::create(&temp_path)
        .with_context(|| format!("create {temp_label} temp {}", temp_path.display()))?;
    temp.write_all(payload)
        .with_context(|| format!("write {temp_label} temp {}", temp_path.display()))?;
    count_cache_bytes(kind, payload.len());
    temp.sync_all().ok();
    fs::rename(&temp_path, path)
        .with_context(|| format!("rename {cache_label} into place {}", path.display()))
}

/// How much a small status file replaced whole is relied on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SmallFileClass {
    /// A restart, an account decision, an upload, a usage path or a security
    /// decision reads it back. Its writer keeps its own durability.
    Durable,
    /// Rebuilt from other state when missing or stale; a crash may lose it.
    PureCache,
}

/// Counts one small whole-file write that either wrote `bytes` or was skipped
/// because the file already held them.
fn count_small_file_write(class: SmallFileClass, written: bool, bytes: usize) {
    let (writes, skipped, payload) = match class {
        SmallFileClass::Durable => (
            Event::SmallFileWritesDurable,
            Event::SmallFileSkippedDurable,
            Event::SmallFileBytesDurable,
        ),
        SmallFileClass::PureCache => (
            Event::SmallFileWritesPureCache,
            Event::SmallFileSkippedPureCache,
            Event::SmallFileBytesPureCache,
        ),
    };
    if written {
        add(writes, 1);
        add(payload, bytes as u64);
    } else {
        add(skipped, 1);
    }
}

/// [`ottto_core::replace_owner_only_file_if_changed`] with its outcome counted
/// under `class`. The caller's `fsync` choice is passed through unchanged.
pub(crate) fn replace_owner_only_file_counted(
    path: &Path,
    bytes: &[u8],
    fsync: bool,
    class: SmallFileClass,
) -> io::Result<()> {
    #[cfg(test)]
    small_file_mode::note(class, fsync);
    let written = ottto_core::replace_owner_only_file_if_changed(path, bytes, fsync)?;
    count_small_file_write(class, written, bytes.len());
    Ok(())
}

/// One small-file writer at a time in this process, so two writers of one
/// path never share its temp file.
static SMALL_FILE_WRITER: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Replaces the small file `path` with `payload` unless it already holds
/// exactly those bytes. The check opens `path` without following a symlink,
/// takes one `fstat` (a regular file of the same length) and compares the
/// bytes, so a missing, truncated or changed file is written again. A write
/// goes through `<file name>.tmp` and a rename, so readers never see a torn
/// file. `Durable` fsyncs the temp file before the rename; `PureCache` does
/// not. No directory fsync. Returns whether it wrote.
pub(crate) fn replace_small_file_if_changed(
    path: &Path,
    payload: &[u8],
    class: SmallFileClass,
) -> io::Result<bool> {
    let fsync = class == SmallFileClass::Durable;
    let _writer = SMALL_FILE_WRITER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    #[cfg(test)]
    small_file_mode::note(class, fsync);
    let written = !holds_bytes(path, payload);
    if written {
        let mut name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?
            .to_os_string();
        name.push(".tmp");
        let temp_path = path.with_file_name(name);
        let mut temp = File::create(&temp_path)?;
        temp.write_all(payload)?;
        if fsync {
            temp.sync_all()?;
        }
        fs::rename(&temp_path, path)?;
    }
    count_small_file_write(class, written, payload.len());
    Ok(written)
}

fn holds_bytes(path: &Path, payload: &[u8]) -> bool {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let Ok(file) = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    else {
        return false;
    };
    let same_length = file
        .metadata()
        .is_ok_and(|meta| meta.is_file() && meta.len() == payload.len() as u64);
    let mut held = Vec::with_capacity(payload.len());
    same_length
        && file
            .take(payload.len() as u64 + 1)
            .read_to_end(&mut held)
            .is_ok()
        && held == payload
}

/// The class and fsync choice of the last small-file write on this test
/// thread, so tests can check a writer's durability through its mode.
#[cfg(test)]
pub(crate) mod small_file_mode {
    use super::SmallFileClass;
    use std::cell::Cell;

    thread_local! {
        static LAST: Cell<Option<(SmallFileClass, bool)>> = const { Cell::new(None) };
    }

    pub(super) fn note(class: SmallFileClass, fsync: bool) {
        LAST.with(|last| last.set(Some((class, fsync))));
    }

    /// Takes the last noted `(class, fsync)`.
    pub(crate) fn take() -> Option<(SmallFileClass, bool)> {
        LAST.with(Cell::take)
    }
}

/// Tests stand in for the daemon on their own scratch state directory. The
/// lock is taken with the real `StateDirLock::acquire` and kept until the test process
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

#[cfg(test)]
mod small_file_tests {
    use super::{replace_small_file_if_changed, small_file_mode, SmallFileClass};
    use crate::local_resource_diagnostics::cache_lifecycle;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    fn inode(path: &Path) -> u64 {
        std::fs::symlink_metadata(path).unwrap().ino()
    }

    /// [regress] Identical bytes are not written again; changed bytes land.
    #[test]
    fn unchanged_small_file_is_skipped_and_a_change_lands() {
        let scratch = crate::test_scratch::ScratchDir::new("small-file-skip");
        let path = scratch.join("status.json");
        let (outcomes, counts) = cache_lifecycle::observe(|| {
            let first = replace_small_file_if_changed(&path, b"one", SmallFileClass::PureCache);
            let written = inode(&path);
            let same = replace_small_file_if_changed(&path, b"one", SmallFileClass::PureCache);
            assert_eq!(
                inode(&path),
                written,
                "a skipped write leaves the file as is"
            );
            let changed = replace_small_file_if_changed(&path, b"two", SmallFileClass::PureCache);
            [first.unwrap(), same.unwrap(), changed.unwrap()]
        });
        assert_eq!(outcomes, [true, false, true]);
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        assert!(!scratch.join("status.json.tmp").exists());
        assert_eq!(counts.small_file_writes_pure_cache, 2);
        assert_eq!(counts.small_file_writes_skipped_unchanged_pure_cache, 1);
        assert_eq!(counts.small_file_write_bytes_pure_cache, 6);
    }

    /// [regress] A deleted, truncated or same-length edited file is written again.
    #[test]
    fn deleted_truncated_or_edited_small_file_is_rewritten() {
        let scratch = crate::test_scratch::ScratchDir::new("small-file-repair");
        let path = scratch.join("status.json");
        let write = || replace_small_file_if_changed(&path, b"payload", SmallFileClass::PureCache);
        assert!(write().unwrap());
        std::fs::remove_file(&path).unwrap();
        assert!(write().unwrap(), "deleted");
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(3)
            .unwrap();
        assert!(write().unwrap(), "truncated");
        std::fs::write(&path, b"PAYLOAD").unwrap();
        assert!(write().unwrap(), "same length, other bytes");
        let target = scratch.join("target");
        std::fs::write(&target, b"payload").unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(write().unwrap(), "symlink");
        assert!(std::fs::symlink_metadata(&path).unwrap().is_file());
        assert!(!write().unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), b"payload");
    }

    /// [regress] Durable writes keep the fsync; pure caches drop it.
    #[test]
    fn small_file_durability_follows_its_class() {
        let scratch = crate::test_scratch::ScratchDir::new("small-file-mode");
        let path = scratch.join("status.json");
        replace_small_file_if_changed(&path, b"a", SmallFileClass::Durable).unwrap();
        assert_eq!(
            small_file_mode::take(),
            Some((SmallFileClass::Durable, true))
        );
        replace_small_file_if_changed(&path, b"b", SmallFileClass::PureCache).unwrap();
        assert_eq!(
            small_file_mode::take(),
            Some((SmallFileClass::PureCache, false))
        );
    }
}
