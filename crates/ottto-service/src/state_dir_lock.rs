//! One daemon per local state directory.
//!
//! `serve` and `serve-xpc` take an exclusive `flock` on
//! `<support>/ottto-service.lock` before any startup step, relay or
//! listener can read or write local state, and hold it until the process
//! exits. A second daemon on the same directory, whatever its entry point,
//! socket path, launchd label or binary, fails here and exits without
//! writing anything.
//!
//! The per-save locks next to the scan index and upload progress only guard
//! one read-modify-write. They make a second writer's save fail its
//! generation check instead of clobbering, but nothing stopped that writer
//! from scanning, uploading and restarting traversals on the same state.
//! Process-local mutexes (backfill state, upload receipts) do not see
//! another process at all.
//!
//! The kernel drops the lock when its holder exits, crashes or is killed, so
//! a lock is never stale and there is nothing to clean up; the file stays.
//! The descriptor is close-on-exec, so a child process (Claude, Codex, the
//! composition worker) never keeps the lock past the daemon's own exit.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub const STATE_DIR_LOCK_FILE_NAME: &str = "ottto-service.lock";

/// `EX_TEMPFAIL`: another daemon owns the state directory.
pub const STATE_DIR_HELD_EXIT_CODE: i32 = 75;

/// `EX_IOERR`: the lock could not be taken, so this process cannot show it
/// is the only writer.
pub const STATE_DIR_LOCK_FAILED_EXIT_CODE: i32 = 74;

/// Holds the state directory until dropped.
#[derive(Debug)]
pub struct StateDirLock {
    _file: File,
}

#[derive(Debug)]
pub enum StateDirLockError {
    /// Another process holds the lock. `holder_pid` is what that process
    /// recorded, when it could be read.
    Held {
        dir: PathBuf,
        holder_pid: Option<u32>,
    },
    Failed {
        dir: PathBuf,
        error: std::io::Error,
    },
}

impl StateDirLockError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Held { .. } => STATE_DIR_HELD_EXIT_CODE,
            Self::Failed { .. } => STATE_DIR_LOCK_FAILED_EXIT_CODE,
        }
    }
}

impl std::fmt::Display for StateDirLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Held { dir, holder_pid } => {
                write!(f, "another ottto-service")?;
                if let Some(pid) = holder_pid {
                    write!(f, " (pid {pid})")?;
                }
                write!(
                    f,
                    " already owns local state at {}; exiting without touching it",
                    dir.display()
                )
            }
            Self::Failed { dir, error } => write!(
                f,
                "cannot lock local state at {}: {error}; exiting without touching it",
                dir.display()
            ),
        }
    }
}

impl std::error::Error for StateDirLockError {}

impl StateDirLock {
    /// Takes the lock without waiting. Creates `support_dir` (0700) and the
    /// lock file (0600) when missing; writes nothing else, and nothing at
    /// all when another process holds the lock.
    pub fn acquire(support_dir: &Path) -> Result<Self, StateDirLockError> {
        let failed = |error| StateDirLockError::Failed {
            dir: support_dir.to_path_buf(),
            error,
        };
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(support_dir)
            .map_err(failed)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(support_dir.join(STATE_DIR_LOCK_FILE_NAME))
            .map_err(failed)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Err(StateDirLockError::Held {
                    dir: support_dir.to_path_buf(),
                    holder_pid: read_holder_pid(&mut file),
                });
            }
            return Err(failed(error));
        }
        // Best effort: the pid only names the holder in a later refusal.
        let _ = record_holder_pid(&mut file);
        Ok(Self { _file: file })
    }
}

fn record_holder_pid(file: &mut File) -> std::io::Result<()> {
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    writeln!(file, "{}", std::process::id())
}

fn read_holder_pid(file: &mut File) -> Option<u32> {
    let mut text = String::new();
    Read::by_ref(file).take(32).read_to_string(&mut text).ok()?;
    text.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("read support dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .into_string()
                    .expect("utf-8")
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn second_holder_is_refused_without_writing_and_lock_returns_on_drop() {
        let root = crate::test_scratch::private_dir("state-dir-lock");
        let support = root.join("Ottto");
        let first = StateDirLock::acquire(&support).expect("first daemon takes the lock");
        let lock_path = support.join(STATE_DIR_LOCK_FILE_NAME);
        let recorded = std::fs::read(&lock_path).expect("read lock file");
        assert_eq!(recorded, format!("{}\n", std::process::id()).into_bytes());

        // flock is per open file description, so a second open in this
        // process contends exactly like a second process would.
        let refusal = StateDirLock::acquire(&support).expect_err("second writer refused");
        assert!(
            matches!(
                &refusal,
                StateDirLockError::Held { dir, holder_pid }
                    if dir == &support && *holder_pid == Some(std::process::id())
            ),
            "{refusal:?}"
        );
        assert_eq!(refusal.exit_code(), STATE_DIR_HELD_EXIT_CODE);
        assert!(refusal.to_string().contains("already owns local state"));
        assert_eq!(
            entries(&support),
            vec![STATE_DIR_LOCK_FILE_NAME.to_string()]
        );
        assert_eq!(
            std::fs::read(&lock_path).expect("reread lock file"),
            recorded
        );

        drop(first);
        let restarted = StateDirLock::acquire(&support).expect("restart takes the lock");
        drop(restarted);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn lock_creates_a_private_support_dir_and_file() {
        use std::os::unix::fs::PermissionsExt;
        let root = crate::test_scratch::private_dir("state-dir-lock-mode");
        let support = root.join("nested").join("Ottto");
        let lock = StateDirLock::acquire(&support).expect("take lock");
        // A umask only removes bits, so check that none reach group or other.
        let shared_bits = |path: &Path| {
            std::fs::metadata(path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o077
        };
        assert_eq!(shared_bits(&support), 0);
        assert_eq!(shared_bits(&support.join(STATE_DIR_LOCK_FILE_NAME)), 0);
        drop(lock);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn unusable_support_dir_fails_closed() {
        let root = crate::test_scratch::private_dir("state-dir-lock-file");
        let not_a_dir = root.join("Ottto");
        std::fs::write(&not_a_dir, b"").expect("plant a file");
        let error = StateDirLock::acquire(&not_a_dir).expect_err("cannot lock");
        assert!(
            matches!(error, StateDirLockError::Failed { .. }),
            "{error:?}"
        );
        assert_eq!(error.exit_code(), STATE_DIR_LOCK_FAILED_EXIT_CODE);
        let _ = std::fs::remove_dir_all(root);
    }
}
