//! Shared ownership and bounded subprocess lifetime for the per-user job.
//! A child retains the flock if its caller dies. Never unlink or explicitly
//! unlock this file; only the last close releases transaction ownership.
use anyhow::{Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(10);
const OUTPUT_LIMIT: usize = 1024 * 1024;

/// No lifecycle transaction was entered, so this result is safe to retry.
#[derive(Debug, thiserror::Error)]
#[error("service lifecycle transaction busy; current job unchanged")]
pub struct ServiceLifecycleBusy;

pub struct ServiceLifecycleTransaction(File);

impl ServiceLifecycleTransaction {
    /// The path is fixed by user home and the single job label, for every caller.
    pub fn acquire(home: &Path, timeout: Duration) -> Result<Self> {
        let directory = home.join("Library/LaunchAgents");
        fs::create_dir_all(&directory)?;
        Self::acquire_path(
            &directory.join(format!(
                ".{}.lifecycle.lock",
                crate::MACOS_LAUNCH_AGENT_LABEL
            )),
            timeout,
        )
    }

    fn acquire_path(path: &Path, timeout: Duration) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .context("open service lifecycle lock")?;
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.nlink() == 1
                && metadata.mode() & 0o077 == 0,
            "unsafe service lifecycle lock"
        );
        let start = Instant::now();
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(Self(file));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::WouldBlock
                && error.kind() != io::ErrorKind::Interrupted
            {
                return Err(error).context("lock service lifecycle transaction");
            }
            if start.elapsed() >= timeout {
                return Err(ServiceLifecycleBusy.into());
            }
            std::thread::sleep(POLL);
        }
    }

    fn spawn(&self, command: &mut Command) -> io::Result<Child> {
        let fd = self.0.as_raw_fd();
        // Only this child's copy loses CLOEXEC. Other children of this process
        // do not inherit the lock, and no allocator or lock runs after fork.
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command.spawn()
    }
}

impl ServiceLifecycleTransaction {
    /// Inherit transaction ownership, bound output/wait, kill and reap on error.
    pub fn run(&self, command: &mut Command, timeout: Duration) -> Result<(ExitStatus, Vec<u8>)> {
        run(self, command, timeout)
    }
}

fn run(
    lock: &ServiceLifecycleTransaction,
    command: &mut Command,
    timeout: Duration,
) -> Result<(ExitStatus, Vec<u8>)> {
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null());
    let mut child = lock
        .spawn(command)
        .context("spawn service lifecycle command")?;
    complete(&mut child, timeout)
}

fn complete(child: &mut Child, timeout: Duration) -> Result<(ExitStatus, Vec<u8>)> {
    let outcome = collect(child, timeout);
    if outcome.is_err() {
        // Kill before wait, and reap even on polling/output errors. The lock
        // stays held throughout. SIGKILL of this helper instead leaves the lock
        // with the live child; a later helper waits boundedly and fails closed.
        let killed = child.kill();
        child
            .wait()
            .context("reap failed service lifecycle command")?;
        if let Err(error) = killed {
            // ESRCH/InvalidInput just means the child exited at the deadline.
            if error.raw_os_error() != Some(libc::ESRCH)
                && error.kind() != io::ErrorKind::InvalidInput
            {
                return Err(error).context("kill failed service lifecycle command");
            }
        }
    }
    outcome.context("service lifecycle command did not complete; installation may be partial; reconcile launchd state before retrying")
}

fn collect(child: &mut Child, timeout: Duration) -> Result<(ExitStatus, Vec<u8>)> {
    let mut stdout = child
        .stdout
        .take()
        .context("missing service command stdout")?;
    let fd = stdout.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    anyhow::ensure!(
        flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0,
        "configure service command output"
    );
    let start = Instant::now();
    let mut output = Vec::new();
    loop {
        let mut buffer = [0; 8192];
        match stdout.read(&mut buffer) {
            Ok(size) => {
                anyhow::ensure!(
                    output.len() + size <= OUTPUT_LIMIT,
                    "service command output too large"
                );
                output.extend_from_slice(&buffer[..size]);
                // Check time and exit on every read, including continuously
                // writable peers. Never wait for EOF from an inherited pipe.
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error.into()),
        }
        if let Some(status) = child.try_wait()? {
            // Drain currently available bytes, capped above; no wait on EOF.
            loop {
                match stdout.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(size) => {
                        anyhow::ensure!(
                            output.len() + size <= OUTPUT_LIMIT,
                            "service command output too large"
                        );
                        output.extend_from_slice(&buffer[..size]);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.into()),
                }
                anyhow::ensure!(start.elapsed() < timeout, "service command timed out");
            }
            return Ok((status, output));
        }
        anyhow::ensure!(start.elapsed() < timeout, "service command timed out");
        std::thread::sleep(POLL);
    }
}

#[cfg(test)]
mod tests;
