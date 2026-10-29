//! Ownership of the current per-user LaunchAgent, independent of app lifetime.
//!
//! Never unlink or explicitly unlock the lock file: a mutating child inherits
//! the same open file description and must keep ownership if this helper dies.
//! This serializes Ottto callers, not external installers or requests launchd
//! has already accepted. A failed mutation is an indeterminate partial install,
//! never proof that the previous daemon is still running or that a new one is ready.
use anyhow::{Context, Result};
use ottto_service::macos_service::{self, LaunchAgentConfig, LaunchAgentInstallPlan};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(10);
const OUTPUT_LIMIT: usize = 1024 * 1024;

struct TransactionLock(File);

impl TransactionLock {
    fn acquire(path: &Path, timeout: Duration) -> Result<Self> {
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
            anyhow::ensure!(
                start.elapsed() < timeout,
                "service lifecycle transaction busy; no changes made"
            );
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

pub(super) fn install(
    home: &Path,
    config: &LaunchAgentConfig,
    plist: &Path,
    migrate_owner: bool,
    execute: bool,
) -> Result<LaunchAgentInstallPlan> {
    // Fixed per-user/label path, never derived from the requested executable,
    // socket or owner. write-launch-agent participates in the same transaction.
    let directory = home.join("Library/LaunchAgents");
    fs::create_dir_all(&directory)?;
    let lock = TransactionLock::acquire(
        &directory.join(format!(
            ".{}.lifecycle.lock",
            macos_service::LAUNCH_AGENT_LABEL
        )),
        LOCK_TIMEOUT,
    )?;
    install_with(
        config,
        plist,
        migrate_owner,
        execute,
        || loaded_program(&lock),
        |args| {
            let (program, rest) = args.split_first().context("empty service command")?;
            // Plans retain their existing CLI strings; execution uses a fixed path.
            anyhow::ensure!(program == "launchctl", "unexpected service command");
            let mut command = Command::new("/bin/launchctl");
            command.args(rest);
            let (status, _) = run(&lock, &mut command, COMMAND_TIMEOUT)?;
            anyhow::ensure!(
                status.success(),
                "service lifecycle command failed ({status}); installation may be partial: {}",
                args.join(" ")
            );
            Ok(())
        },
    )
}

fn install_with(
    config: &LaunchAgentConfig,
    plist: &Path,
    migrate_owner: bool,
    execute: bool,
    inspect: impl FnOnce() -> Result<Option<std::path::PathBuf>>,
    mut mutate: impl FnMut(&[String]) -> Result<()>,
) -> Result<LaunchAgentInstallPlan> {
    let loaded = inspect()?;
    let (exists, program, error) = macos_service::read_launch_agent_program_path(plist);
    let state = macos_service::inspect_launch_agent_owner_with_loaded_program(
        plist,
        Some(&config.executable_path),
        exists,
        program,
        error,
        loaded,
    );
    // Keep the same installer migration/refusal policy as the public owner
    // check, but use the bounded, fail-closed probe from this transaction.
    anyhow::ensure!(migrate_owner || !state.owner_drift,
        "refusing to replace {}: existing LaunchAgent owner conflicts with requested owner {}. Inspect ownership or pass --migrate-owner for an intentional owner switch.",
        macos_service::LAUNCH_AGENT_LABEL, macos_service::install_owner_label(state.expected_owner));
    let plan = macos_service::write_launch_agent(config, plist)?;
    if execute {
        for args in super::service_bootstrap_commands(&plan, state.loaded) {
            mutate(&args).with_context(|| {
                format!(
                    "service lifecycle stage {} failed; installation may be partial",
                    args[1]
                )
            })?;
        }
    }
    Ok(plan)
}

fn loaded_program(lock: &TransactionLock) -> Result<Option<std::path::PathBuf>> {
    if !cfg!(target_os = "macos") {
        return Ok(None);
    }
    let mut command = Command::new("/bin/launchctl");
    command.args(["print", &ottto_core::macos_launch_agent_target()]);
    let (status, output) = run(lock, &mut command, COMMAND_TIMEOUT)?;
    parse_loaded_program(status.code(), &output)
}

fn parse_loaded_program(code: Option<i32>, output: &[u8]) -> Result<Option<std::path::PathBuf>> {
    // ESRCH and launchctl's service-not-found status (113) mean the exact
    // job is absent. A missing domain (112), permissions, signals, and
    // unparseable successful queries are unknown ownership, never absence.
    if matches!(code, Some(libc::ESRCH | 113)) {
        return Ok(None);
    }
    anyhow::ensure!(
        code == Some(0),
        "cannot establish loaded LaunchAgent ownership"
    );
    let body = std::str::from_utf8(output).context("invalid launchctl output")?;
    macos_service::parse_launchctl_program_path(
        &body
            .lines()
            .filter(|line| line.trim().starts_with("program = "))
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .map(Some)
    .context("loaded LaunchAgent has no identifiable program; refusing changes")
}

fn run(
    lock: &TransactionLock,
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
