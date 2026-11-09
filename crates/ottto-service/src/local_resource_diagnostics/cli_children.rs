//! Fixed argv classes only; no paths, arguments, output or account identifiers.
use serde::Serialize;
use std::io::{self, Read};
use std::ops::{Deref, DerefMut};
use std::process::{Child, Command, ExitStatus, Output};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

const ARGV: [&str; 8] = [
    "codex login status",
    "codex debug models --bundled",
    "claude --version",
    "codex app-server",
    "codex cloud list",
    "codex login",
    "codex --version",
    "codex verify",
];
super::process_static!(fn with_totals: [[AtomicU64; 8]; 2] =
    [const { [const { AtomicU64::new(0) }; 8] }; 2]);

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

/// Preserve Child's cached exit-status behavior while wait4 obtains exact CPU
/// for this PID, rather than subtracting process-wide RUSAGE_CHILDREN samples.
/// Ownership, signals, process groups and pipe handling remain with the caller.
pub(crate) struct MeasuredChild {
    inner: Child,
    class: Option<usize>,
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
        Some("codex") if has("login") && has("status") => Some(0),
        Some("codex") if has("debug") && has("models") && has("--bundled") => Some(1),
        Some("claude") if has("--version") => Some(2),
        Some("codex") if has("app-server") => Some(3),
        Some("codex") if has("cloud") && has("list") => Some(4),
        Some("codex") if has("login") => Some(5),
        Some("codex") if has("--version") => Some(6),
        Some("codex") => Some(7),
        _ => None,
    };
    let inner = command.spawn()?;
    if let Some(i) = class {
        with_totals(|totals| totals[0][i].fetch_add(1, Relaxed));
    }
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
        if self.class.is_none() {
            self.status = if blocking {
                Some(self.inner.wait()?)
            } else {
                self.inner.try_wait()?
            };
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
                if let Some(i) = self.class {
                    with_totals(|totals| {
                        totals[1][i].fetch_add(
                            micros(usage.ru_utime).saturating_add(micros(usage.ru_stime)),
                            Relaxed,
                        )
                    });
                }
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
    pub(crate) fn wait_with_output(mut self) -> io::Result<Output> {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        if let Some(mut pipe) = self.inner.stdout.take() {
            pipe.read_to_end(&mut stdout)?;
        }
        if let Some(mut pipe) = self.inner.stderr.take() {
            pipe.read_to_end(&mut stderr)?;
        }
        let status = self.wait()?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }
}
