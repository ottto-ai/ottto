//! Locked bootstrap decision; process ownership is shared with CLI autostart.
use anyhow::{Context, Result};
use ottto_core::service_lifecycle::{
    ServiceLifecyclePrincipal, ServiceLifecycleTransaction, COMMAND_TIMEOUT,
};
use ottto_service::macos_service::{self, LaunchAgentConfig, LaunchAgentInstallPlan};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
/// Total time, including probes, for launchd to remove a booted-out job.
const REMOVAL_BUDGET: Duration = Duration::from_secs(5);
const REMOVAL_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Shortest probe timeout, so the last probe near the deadline can still answer.
const MIN_PROBE_TIMEOUT: Duration = Duration::from_millis(100);

pub(super) fn install(
    home: &Path,
    config: &LaunchAgentConfig,
    plist: &Path,
    migrate_owner: bool,
    execute: bool,
) -> Result<LaunchAgentInstallPlan> {
    let principal = ServiceLifecyclePrincipal::current()?;
    install_transaction(
        &principal.home,
        LOCK_TIMEOUT,
        || {
            ottto_service::legacy_service::cleanup_legacy_services(home);
        },
        |lock| {
            install_with(
                config,
                plist,
                migrate_owner,
                execute,
                || loaded_program(lock, COMMAND_TIMEOUT),
                |args| {
                    let (program, rest) = args.split_first().context("empty service command")?;
                    // Plans retain their existing CLI strings; execution uses a fixed path.
                    anyhow::ensure!(program == "launchctl", "unexpected service command");
                    let mut command = Command::new("/bin/launchctl");
                    command.args(rest);
                    let (status, _) = lock.run(&mut command, COMMAND_TIMEOUT)?;
                    anyhow::ensure!(
                status.success(),
                "service lifecycle command failed ({status}); installation may be partial: {}",
                args.join(" ")
            );
                    // `bootout` can return before launchd removes the job, and a
                    // bootstrap that arrives first fails. Wait for removal.
                    if rest.first().map(String::as_str) == Some("bootout") {
                        wait_until_job_absent(
                            |timeout| loaded_program(lock, timeout),
                            REMOVAL_BUDGET,
                            REMOVAL_POLL_INTERVAL,
                        )?;
                    }
                    Ok(())
                },
            )
        },
    )
}

fn install_transaction<T>(
    lock_home: &Path,
    timeout: Duration,
    cleanup: impl FnOnce(),
    install: impl FnOnce(&ServiceLifecycleTransaction) -> Result<T>,
) -> Result<T> {
    let lock = ServiceLifecycleTransaction::acquire(lock_home, timeout)?;
    cleanup();
    install(&lock)
}

fn install_with(
    config: &LaunchAgentConfig,
    plist: &Path,
    migrate_owner: bool,
    execute: bool,
    inspect: impl FnOnce() -> Result<Option<std::path::PathBuf>>,
    mut mutate: impl FnMut(&[String]) -> Result<()>,
) -> Result<LaunchAgentInstallPlan> {
    let loaded = inspect().map_err(macos_service::LaunchAgentLifecycleFailure)?;
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
    if !migrate_owner && state.owner_drift {
        return Err(macos_service::owner_conflict_error(&state));
    }
    // Same program and same plist bytes: the loaded job needs a new process,
    // not a new definition.
    let plist_unchanged = state.loaded_executable_path.as_deref()
        == Some(config.executable_path.as_path())
        && std::fs::read(plist).is_ok_and(|current| {
            macos_service::render_launch_agent_plist(config)
                .is_ok_and(|rendered| rendered == current)
        });
    let plan = macos_service::write_launch_agent(config, plist)
        .map_err(macos_service::LaunchAgentLifecycleFailure)?;
    if execute {
        for args in super::service_bootstrap_commands(&plan, state.loaded, plist_unchanged) {
            mutate(&args)
                .with_context(|| {
                    format!(
                        "service lifecycle stage {} failed; installation may be partial",
                        args[1]
                    )
                })
                .map_err(macos_service::LaunchAgentLifecycleFailure)?;
        }
    }
    Ok(plan)
}

/// Polls `probe` until the job is absent, within one `budget` measured from
/// the first probe. Each probe gets the time left (at least 100 ms) as its
/// timeout. A probe error (unknown state) or a job still present at the
/// deadline is an error, so bootstrap never runs against a job that may still
/// be loaded.
fn wait_until_job_absent(
    mut probe: impl FnMut(Duration) -> Result<Option<std::path::PathBuf>>,
    budget: Duration,
    interval: Duration,
) -> Result<()> {
    let deadline = Instant::now() + budget;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if probe(left.max(MIN_PROBE_TIMEOUT))?.is_none() {
            return Ok(());
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            anyhow::bail!("LaunchAgent is still loaded after bootout; installation may be partial");
        }
        std::thread::sleep(interval.min(left));
    }
}

fn loaded_program(
    lock: &ServiceLifecycleTransaction,
    timeout: Duration,
) -> Result<Option<std::path::PathBuf>> {
    if !cfg!(target_os = "macos") {
        return Ok(None);
    }
    let mut command = Command::new("/bin/launchctl");
    command.args(["print", &ottto_core::macos_launch_agent_target()]);
    let (status, output) = lock.run(&mut command, timeout)?;
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

#[cfg(test)]
mod tests;
