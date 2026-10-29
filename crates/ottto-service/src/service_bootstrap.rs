//! Locked bootstrap decision; process ownership is shared with CLI autostart.
use anyhow::{Context, Result};
use ottto_core::service_lifecycle::{ServiceLifecycleTransaction, COMMAND_TIMEOUT};
use ottto_service::macos_service::{self, LaunchAgentConfig, LaunchAgentInstallPlan};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const LOCK_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) fn install(
    home: &Path,
    config: &LaunchAgentConfig,
    plist: &Path,
    migrate_owner: bool,
    execute: bool,
) -> Result<LaunchAgentInstallPlan> {
    // Fixed per-user/label path, never derived from the requested executable,
    // socket or owner. write-launch-agent participates in the same transaction.
    let lock = ServiceLifecycleTransaction::acquire(home, LOCK_TIMEOUT)?;
    ottto_service::legacy_service::cleanup_legacy_services(home);
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
            let (status, _) = lock.run(&mut command, COMMAND_TIMEOUT)?;
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
    let plan = macos_service::write_launch_agent(config, plist)
        .map_err(macos_service::LaunchAgentLifecycleFailure)?;
    if execute {
        for args in super::service_bootstrap_commands(&plan, state.loaded) {
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

fn loaded_program(lock: &ServiceLifecycleTransaction) -> Result<Option<std::path::PathBuf>> {
    if !cfg!(target_os = "macos") {
        return Ok(None);
    }
    let mut command = Command::new("/bin/launchctl");
    command.args(["print", &ottto_core::macos_launch_agent_target()]);
    let (status, output) = lock.run(&mut command, COMMAND_TIMEOUT)?;
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
