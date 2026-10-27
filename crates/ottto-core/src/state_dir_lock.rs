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
//! The kernel drops the lock when the last descriptor of its open file
//! closes, so a lock is never stale and there is nothing to clean up; the
//! file stays. The descriptor is close-on-exec, so a child process (Claude,
//! Codex, the composition worker) drops its copy when it execs. Until then a
//! child forked from the daemon shares the lock: if the daemon exits, crashes
//! or is killed in that window, the lock stays held until the child execs or
//! exits, and a restart may be refused (exit 75) or uninstall wait meanwhile.
//! Dropping the guard unlocks explicitly, which frees the lock for every copy
//! at once. Only the process that took the lock unlocks it: a forked child
//! that did would free it under the daemon that still runs.
//!
//! Two other writers of daemon-owned state respect it without holding it for
//! long: the CLI creates a missing control token only while it holds the
//! lock (`load_or_create_control_token_unless_daemon_owns`), and uninstall
//! keeps the lock file's inode in place, and after stopping the daemon holds
//! the lock while it deletes state, so a restarted daemon can never take a
//! fresh lock while the old one still runs. Delegated workers and input
//! producers (statusline caches) write their own files and never take it.

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
    file: File,
    /// The process that took the lock.
    owner: u32,
}

impl Drop for StateDirLock {
    fn drop(&mut self) {
        // A forked child that drops its copy of the guard shares the lock's
        // open file description; unlocking there would free the holder's
        // lock while the holder still runs.
        if std::process::id() != self.owner {
            return;
        }
        // If the unlock fails, closing the file below still releases this
        // descriptor's share, as it would without the unlock.
        while unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) } != 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
        {}
    }
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
                write!(f, " already owns local state at {}", dir.display())
            }
            Self::Failed { dir, error } => {
                write!(f, "cannot lock local state at {}: {error}", dir.display())
            }
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
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(support_dir.join(STATE_DIR_LOCK_FILE_NAME))
            .map_err(failed)?;
        Self::lock(file, support_dir)
    }

    /// Like [`Self::acquire`], but never creates `support_dir`: `Ok(None)`
    /// when it does not exist. In an existing directory the lock file is
    /// created when missing, so the caller owns the directory even if no
    /// daemon ever ran there, and its inode stays for any later daemon.
    pub fn acquire_in_existing_dir(support_dir: &Path) -> Result<Option<Self>, StateDirLockError> {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(support_dir.join(STATE_DIR_LOCK_FILE_NAME))
        {
            Ok(file) => Self::lock(file, support_dir).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(StateDirLockError::Failed {
                dir: support_dir.to_path_buf(),
                error,
            }),
        }
    }

    fn lock(mut file: File, support_dir: &Path) -> Result<Self, StateDirLockError> {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Err(StateDirLockError::Held {
                    dir: support_dir.to_path_buf(),
                    holder_pid: read_holder_pid(&mut file),
                });
            }
            return Err(StateDirLockError::Failed {
                dir: support_dir.to_path_buf(),
                error,
            });
        }
        // Best effort: the pid only names the holder in a later refusal.
        let _ = record_holder_pid(&mut file);
        Ok(Self {
            file,
            owner: std::process::id(),
        })
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
/// A fresh private directory under `$TMPDIR`; never adopts a leftover.
pub(crate) fn scratch(prefix: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "ottto-core-{prefix}-{}-{}-{nanos}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .expect("fresh scratch dir");
    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    /// Whether the calling test runs its body in this process: true in a
    /// child test process that runs only that test. Otherwise runs it there,
    /// panics unless exactly that test passed, and returns false. Other
    /// tests of this binary spawn processes at any moment, and each child
    /// shares every descriptor open at its fork until it execs.
    fn run_isolated() -> bool {
        const ISOLATED_TEST_ENV: &str = "OTTTO_CORE_ISOLATED_UNIT_TEST";
        let current = std::thread::current();
        let test = current
            .name()
            .expect("the test harness names a test's thread after the test");
        if std::env::var_os(ISOLATED_TEST_ENV).is_some_and(|isolated| isolated == test) {
            return true;
        }
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([test, "--exact", "--test-threads=1"])
            .env(ISOLATED_TEST_ENV, test)
            .output()
            .expect("run the isolated test");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("test result: ok. 1 passed;"),
            "isolated run of {test} failed ({}):\n--- stdout\n{stdout}\n--- stderr\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        false
    }

    /// Forks a child that runs `child` and exits 0. `child` must only make
    /// async-signal-safe calls: it runs in a copy of this process.
    fn fork_child(child: impl FnOnce()) -> libc::pid_t {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
        if pid == 0 {
            child();
            unsafe { libc::_exit(0) };
        }
        pid
    }

    fn reap(pid: libc::pid_t) -> std::process::ExitStatus {
        let mut status = 0;
        loop {
            if unsafe { libc::waitpid(pid, &mut status, 0) } == pid {
                return std::process::ExitStatus::from_raw(status);
            }
            let error = std::io::Error::last_os_error();
            assert_eq!(error.raw_os_error(), Some(libc::EINTR), "waitpid: {error}");
        }
    }

    /// Kills and reaps a forked child, also when an assertion fails first.
    struct ForkedChild(libc::pid_t);

    impl Drop for ForkedChild {
        fn drop(&mut self) {
            unsafe { libc::kill(self.0, libc::SIGKILL) };
            // No assertion here: a panic while unwinding would abort.
            let mut status = 0;
            while unsafe { libc::waitpid(self.0, &mut status, 0) } == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
            {}
        }
    }

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
        let root = super::scratch("state-dir-lock");
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
        let restarted = StateDirLock::acquire(&support).expect("released at drop");
        drop(restarted);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn lock_creates_a_private_support_dir_and_file() {
        use std::os::unix::fs::PermissionsExt;
        let root = super::scratch("state-dir-lock-mode");
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
        let root = super::scratch("state-dir-lock-file");
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

    #[test]
    fn acquire_in_existing_dir_never_creates_the_dir_and_contends_like_acquire() {
        let root = super::scratch("state-dir-lock-existing");
        let support = root.join("Ottto");
        assert!(StateDirLock::acquire_in_existing_dir(&support)
            .expect("absent directory")
            .is_none());
        assert!(!support.exists(), "an absent directory must not be created");

        // An existing directory without a lock file gets one and is owned.
        std::fs::create_dir(&support).expect("support dir without a lock");
        let owner = StateDirLock::acquire_in_existing_dir(&support)
            .expect("lock an unlocked dir")
            .expect("directory exists");
        assert!(support.join(STATE_DIR_LOCK_FILE_NAME).is_file());
        let refused = StateDirLock::acquire(&support).expect_err("owned");
        assert!(
            matches!(refused, StateDirLockError::Held { .. }),
            "{refused:?}"
        );
        drop(owner);

        let holder = StateDirLock::acquire(&support).expect("released at drop");
        let refusal = StateDirLock::acquire_in_existing_dir(&support).expect_err("held");
        assert!(
            matches!(refusal, StateDirLockError::Held { .. }),
            "{refusal:?}"
        );
        drop(holder);
        drop(StateDirLock::acquire(&support).expect("released at drop"));
        let claimed = StateDirLock::acquire_in_existing_dir(&support).expect("free lock");
        assert!(claimed.is_some());
        let _ = std::fs::remove_dir_all(root);
    }

    /// A child forked from the holder shares the lock until it execs or
    /// exits. The holder dropping its guard frees the lock at once all the
    /// same, and only the holder's drop does: a child dropping its copy of
    /// the guard leaves the lock with the holder. Runs alone, so no other
    /// test's child shares a descriptor of this lock.
    #[test]
    fn dropped_guard_frees_the_lock_a_forked_child_still_shares() {
        if !run_isolated() {
            return;
        }
        let root = super::scratch("state-dir-lock-fork");
        let support = root.join("Ottto");
        let holder = StateDirLock::acquire(&support).expect("daemon takes the lock");

        let dropper = fork_child(|| drop(unsafe { std::ptr::read(&holder) }));
        let dropped = reap(dropper);
        assert!(dropped.success(), "{dropped:?}");
        let refusal = StateDirLock::acquire(&support).expect_err("holder keeps the lock");
        assert!(
            matches!(refusal, StateDirLockError::Held { .. }),
            "{refusal:?}"
        );

        // Never execs or exits on its own: it shares the lock until killed.
        let sharer = ForkedChild(fork_child(|| loop {
            unsafe { libc::pause() };
        }));
        let refusal = StateDirLock::acquire(&support).expect_err("still held");
        assert!(
            matches!(refusal, StateDirLockError::Held { .. }),
            "{refusal:?}"
        );
        drop(holder);
        let restarted = StateDirLock::acquire(&support)
            .expect("the lock is free once its guard drops, though a fork child shares it");
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(sharer.0, &mut status, libc::WNOHANG) },
            0,
            "the forked child still runs"
        );
        drop(restarted);
        drop(sharer);
        let _ = std::fs::remove_dir_all(root);
    }
}
