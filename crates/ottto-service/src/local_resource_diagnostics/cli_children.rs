//! Fixed argv classes only; no paths, arguments, output or account identifiers.
use serde::Serialize;
use std::io;
use std::ops::{Deref, DerefMut};
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

const ARGV: [&str; 5] = [
    "codex login status",
    "codex models",
    "claude version",
    "other codex",
    "other",
];
super::process_static!(fn with_totals: [[AtomicU64; 5]; 2] =
    [const { [const { AtomicU64::new(0) }; 5] }; 2]);

#[derive(Debug, Serialize)]
pub(super) struct Counts {
    argv: &'static str,
    starts: u64,
    cpu_us: u64,
}
pub(super) fn snapshot() -> Vec<Counts> {
    ARGV.iter()
        .enumerate()
        .map(|(i, argv)| Counts {
            argv,
            starts: with_totals(|totals| totals[0][i].load(Relaxed)),
            cpu_us: with_totals(|totals| totals[1][i].load(Relaxed)),
        })
        .filter(|counts| counts.starts != 0)
        .collect()
}

/// Fixed-kind counters including observed zeros, without sparse log omission.
#[cfg(all(test, unix))]
pub(crate) fn starts_for_test() -> std::collections::BTreeMap<&'static str, u64> {
    with_totals(|totals| {
        ARGV.iter()
            .enumerate()
            .map(|(i, kind)| (*kind, totals[0][i].load(Relaxed)))
            .collect()
    })
}

/// Preserve Child's cached exit-status behavior while wait4 obtains exact CPU
/// for this PID, rather than subtracting process-wide RUSAGE_CHILDREN samples.
/// Ownership, signals, process groups and pipe handling remain with the caller.
pub(crate) struct MeasuredChild {
    inner: Child,
    class: usize,
    status: Option<ExitStatus>,
}
impl Deref for MeasuredChild {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.inner
    }
}
impl DerefMut for MeasuredChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.inner
    }
}

pub(crate) fn spawn(command: &mut Command) -> io::Result<MeasuredChild> {
    let binary = std::path::Path::new(command.get_program())
        .file_name()
        .and_then(|s| s.to_str());
    let has = |value: &str| command.get_args().any(|arg| arg == value);
    let class = match binary {
        Some("codex") if has("login") && has("status") => 0,
        Some("codex") if has("debug") && has("models") && has("--bundled") => 1,
        Some("claude") if has("--version") => 2,
        Some("codex") => 3,
        _ => 4,
    };
    let inner = command.spawn()?;
    with_totals(|totals| totals[0][class].fetch_add(1, Relaxed));
    Ok(MeasuredChild {
        inner,
        class,
        status: None,
    })
}
impl MeasuredChild {
    pub(crate) fn into_inner(self) -> Child {
        self.inner
    }

    pub(crate) fn kill(&mut self) -> io::Result<()> {
        // wait4 reaped the PID without filling std::Child's private cache.
        // Preserve Child::kill's already-exited guard before delegating.
        if self.status.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "process already exited",
            ));
        }
        self.inner.kill()
    }

    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.reap(false)
    }
    pub(crate) fn wait(&mut self) -> io::Result<ExitStatus> {
        self.inner.stdin.take();
        self.reap(true)?
            .ok_or_else(|| io::Error::other("child not exited"))
    }
    fn reap(&mut self, blocking: bool) -> io::Result<Option<ExitStatus>> {
        if self.status.is_some() {
            return Ok(self.status);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            let mut status = 0;
            let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
            loop {
                // This wrapper is the sole reaper for its owned child.
                let pid = unsafe {
                    libc::wait4(
                        self.inner.id() as libc::pid_t,
                        &mut status,
                        if blocking { 0 } else { libc::WNOHANG },
                        usage.as_mut_ptr(),
                    )
                };
                if pid < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error);
                }
                if pid == 0 {
                    return Ok(None);
                }
                let usage = unsafe { usage.assume_init() };
                let micros = |v: libc::timeval| {
                    (v.tv_sec as u64)
                        .saturating_mul(1_000_000)
                        .saturating_add(v.tv_usec as u64)
                };
                with_totals(|totals| {
                    totals[1][self.class].fetch_add(
                        micros(usage.ru_utime).saturating_add(micros(usage.ru_stime)),
                        Relaxed,
                    )
                });
                self.status = Some(ExitStatus::from_raw(status));
                return Ok(self.status);
            }
        }
        #[cfg(not(unix))]
        {
            self.status = if blocking {
                Some(self.inner.wait()?)
            } else {
                self.inner.try_wait()?
            };
            Ok(self.status)
        }
    }
}
