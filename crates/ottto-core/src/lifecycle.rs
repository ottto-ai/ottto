use crate::local_service::{
    user_launchctl_domain, MACOS_LAUNCH_AGENT_LABEL, MACOS_LEGACY_LAUNCH_AGENT_LABEL,
    OTTTO_LEGACY_SERVICE_BINARY_NAME, OTTTO_SERVICE_BINARY_NAME,
};
#[cfg(target_os = "macos")]
use crate::token_store::{ControlTokenStore, KeychainSecretStore};
use crate::{
    OTTTO_KEYCHAIN_ACCOUNT, OTTTO_KEYCHAIN_SERVICE, OTTTO_LEGACY_KEYCHAIN_SERVICE,
    OTTTO_RELAY_DEVICE_SECRET_ACCOUNT, OTTTO_SETUP_RUN_TOKEN_ACCOUNT,
};
use ottto_protocol::{UninstallAction, UninstallExecutionResult, UninstallPlan};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use thiserror::Error;

const LAUNCHCTL: &str = "/bin/launchctl";
const PKILL: &str = "/usr/bin/pkill";

#[derive(Debug, Error)]
pub enum LifecycleError {
    #[error("HOME is required for Ottto local lifecycle operations")]
    HomeRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UninstallExecutionOptions {
    pub stop_companion_process: bool,
    pub stop_daemon_process: bool,
}

impl UninstallExecutionOptions {
    pub const CLI: Self = Self {
        stop_companion_process: true,
        stop_daemon_process: true,
    };

    pub const DAEMON: Self = Self {
        stop_companion_process: false,
        stop_daemon_process: false,
    };
}

#[derive(Debug, Default)]
struct CleanupReport {
    credential_status: String,
    removed_paths: Vec<String>,
    missing_paths: Vec<String>,
    warnings: Vec<String>,
    failed_operations: Vec<String>,
}

impl CleanupReport {
    fn new() -> Self {
        Self {
            credential_status: "not_checked".to_string(),
            ..Self::default()
        }
    }

    fn warn(&mut self, message: impl Into<String>) {
        self.warnings.push(message.into());
    }

    fn fail(&mut self, message: impl Into<String>) {
        self.failed_operations.push(message.into());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupTargetKind {
    File,
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CleanupTarget {
    path: PathBuf,
    kind: CleanupTargetKind,
}

pub fn local_lifecycle_home_dir() -> Result<PathBuf, LifecycleError> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or(LifecycleError::HomeRequired)
}

pub fn plan_local_uninstall(home: &Path) -> UninstallPlan {
    let mut actions = vec![
        UninstallAction {
            action: "stop_process".to_string(),
            target: "Ottto".to_string(),
            kind: "process".to_string(),
            requires_confirmation: true,
            destructive: false,
        },
        UninstallAction {
            action: "stop_process".to_string(),
            target: "OtttoCompanion".to_string(),
            kind: "process".to_string(),
            requires_confirmation: true,
            destructive: false,
        },
        UninstallAction {
            action: "unload_launch_agent".to_string(),
            target: launchd_target(),
            kind: "launch_agent".to_string(),
            requires_confirmation: true,
            destructive: false,
        },
        UninstallAction {
            action: "unload_legacy_launch_agent".to_string(),
            target: launchd_target_for_label(MACOS_LEGACY_LAUNCH_AGENT_LABEL),
            kind: "legacy_launch_agent".to_string(),
            requires_confirmation: true,
            destructive: false,
        },
        UninstallAction {
            action: "stop_process".to_string(),
            target: OTTTO_SERVICE_BINARY_NAME.to_string(),
            kind: "process".to_string(),
            requires_confirmation: true,
            destructive: false,
        },
        UninstallAction {
            action: "stop_process".to_string(),
            target: OTTTO_LEGACY_SERVICE_BINARY_NAME.to_string(),
            kind: "process".to_string(),
            requires_confirmation: true,
            destructive: false,
        },
        UninstallAction {
            action: "remove_local_control_credential".to_string(),
            target: format!("{OTTTO_KEYCHAIN_SERVICE}/{OTTTO_KEYCHAIN_ACCOUNT}"),
            kind: "local_keychain_item".to_string(),
            requires_confirmation: true,
            destructive: true,
        },
        UninstallAction {
            action: "remove_setup_run_credential".to_string(),
            target: format!("{OTTTO_KEYCHAIN_SERVICE}/{OTTTO_SETUP_RUN_TOKEN_ACCOUNT}"),
            kind: "local_keychain_item".to_string(),
            requires_confirmation: true,
            destructive: true,
        },
        UninstallAction {
            action: "remove_relay_device_credential".to_string(),
            target: format!("{OTTTO_KEYCHAIN_SERVICE}/{OTTTO_RELAY_DEVICE_SECRET_ACCOUNT}"),
            kind: "local_keychain_item".to_string(),
            requires_confirmation: true,
            destructive: true,
        },
    ];

    actions.extend(
        [
            OTTTO_KEYCHAIN_ACCOUNT,
            OTTTO_SETUP_RUN_TOKEN_ACCOUNT,
            OTTTO_RELAY_DEVICE_SECRET_ACCOUNT,
        ]
        .into_iter()
        .map(|account| UninstallAction {
            action: "remove_legacy_local_credential".to_string(),
            target: format!("{OTTTO_LEGACY_KEYCHAIN_SERVICE}/{account}"),
            kind: "legacy_local_keychain_item".to_string(),
            requires_confirmation: true,
            destructive: true,
        }),
    );

    actions.extend(uninstall_cleanup_targets(home).into_iter().map(|target| {
        UninstallAction {
            action: "remove_path".to_string(),
            target: target.path.display().to_string(),
            kind: match target.kind {
                CleanupTargetKind::File => "file",
                CleanupTargetKind::Directory => "directory",
            }
            .to_string(),
            requires_confirmation: true,
            destructive: true,
        }
    }));

    UninstallPlan {
        plan_id: "local_uninstall_macos_user_v1".to_string(),
        service_label: MACOS_LAUNCH_AGENT_LABEL.to_string(),
        launchd_target: launchd_target(),
        actions,
        warnings: vec![
            "Cloud provider credentials, provider CLI logins, and remote Ottto data are not revoked or removed by this local uninstall.".to_string(),
        ],
        requires_confirmation: true,
        cloud_credentials_untouched: true,
    }
}

pub fn execute_local_uninstall(
    home: &Path,
    options: UninstallExecutionOptions,
) -> UninstallExecutionResult {
    let plan = plan_local_uninstall(home);
    let mut report = CleanupReport::new();

    if std::env::consts::OS != "macos" {
        report.fail("Ottto local uninstall is currently implemented for macOS packages");
        return execution_result(plan, report);
    }

    if options.stop_companion_process {
        stop_process("Ottto", &mut report);
        stop_process("OtttoCompanion", &mut report);
    } else {
        report.warn("Companion process stop was deferred because uninstall was invoked through ottto-service");
    }

    unload_launch_agent(&mut report, home, MACOS_LAUNCH_AGENT_LABEL);
    unload_launch_agent(&mut report, home, MACOS_LEGACY_LAUNCH_AGENT_LABEL);

    if options.stop_daemon_process {
        stop_process(OTTTO_SERVICE_BINARY_NAME, &mut report);
        stop_process(OTTTO_LEGACY_SERVICE_BINARY_NAME, &mut report);
    } else {
        report.warn("Daemon process stop was deferred until after the typed uninstall response");
    }

    remove_keychain_tokens(&mut report);

    for target in uninstall_cleanup_targets(home) {
        remove_cleanup_target(target, &mut report);
    }

    execution_result(plan, report)
}

pub fn launch_agent_path(home: &Path) -> PathBuf {
    launch_agent_path_for_label(home, MACOS_LAUNCH_AGENT_LABEL)
}

fn launch_agent_path_for_label(home: &Path, label: &str) -> PathBuf {
    home.join("Library")
        .join("LaunchAgents")
        .join(format!("{label}.plist"))
}

pub fn launchd_target() -> String {
    launchd_target_for_label(MACOS_LAUNCH_AGENT_LABEL)
}

fn launchd_target_for_label(label: &str) -> String {
    format!("{}/{}", user_launchctl_domain(), label)
}

fn execution_result(plan: UninstallPlan, mut report: CleanupReport) -> UninstallExecutionResult {
    report.warnings.extend(plan.warnings.iter().cloned());
    UninstallExecutionResult {
        status: if report.failed_operations.is_empty() {
            "uninstalled".to_string()
        } else {
            "uninstall_incomplete".to_string()
        },
        plan,
        credential_status: report.credential_status,
        removed_paths: report.removed_paths,
        missing_paths: report.missing_paths,
        warnings: report.warnings,
        failed_operations: report.failed_operations,
        cloud_credentials_untouched: true,
    }
}

fn uninstall_cleanup_targets(home: &Path) -> Vec<CleanupTarget> {
    vec![
        CleanupTarget {
            path: launch_agent_path(home),
            kind: CleanupTargetKind::File,
        },
        CleanupTarget {
            path: launch_agent_path_for_label(home, MACOS_LEGACY_LAUNCH_AGENT_LABEL),
            kind: CleanupTargetKind::File,
        },
        CleanupTarget {
            path: home.join("Applications").join("Ottto.app"),
            kind: CleanupTargetKind::Directory,
        },
        CleanupTarget {
            path: home.join("Applications").join("Ottto Companion.app"),
            kind: CleanupTargetKind::Directory,
        },
        CleanupTarget {
            path: home
                .join("Library")
                .join("Application Support")
                .join("Ottto"),
            kind: CleanupTargetKind::Directory,
        },
        CleanupTarget {
            path: home.join("Library").join("Logs").join("Ottto"),
            kind: CleanupTargetKind::Directory,
        },
        CleanupTarget {
            path: home.join(".ottto"),
            kind: CleanupTargetKind::Directory,
        },
    ]
}

fn stop_process(process_name: &str, report: &mut CleanupReport) {
    match Command::new(PKILL)
        .arg("-x")
        .arg(process_name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(status) if status.success() || status.code() == Some(1) => {}
        Ok(status) => report.warn(format!("pkill -x {process_name} exited with {status}")),
        Err(error) => report.warn(format!("pkill -x {process_name} failed: {error}")),
    }
}

fn unload_launch_agent(report: &mut CleanupReport, home: &Path, label: &str) {
    let target = launchd_target_for_label(label);
    let domain = user_launchctl_domain();
    let plist_path = launch_agent_path_for_label(home, label);

    if let Err(error) = run_command(LAUNCHCTL, &["disable", &target]) {
        report.warn(format!("launchctl disable {target} failed: {error}"));
    }

    if launchd_service_loaded(&target) {
        let bootout_target = run_command(LAUNCHCTL, &["bootout", &target]);
        if bootout_target.is_err() && plist_path.exists() {
            let plist = plist_path.display().to_string();
            let _ = run_command(LAUNCHCTL, &["bootout", &domain, &plist]);
        }

        if !wait_until_launchd_unloaded(&target) {
            report.fail(format!("launchctl bootout did not unload {target}"));
        }
    }
}

fn launchd_service_loaded(target: &str) -> bool {
    Command::new(LAUNCHCTL)
        .arg("print")
        .arg(target)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn wait_until_launchd_unloaded(target: &str) -> bool {
    for _ in 0..20 {
        if !launchd_service_loaded(target) {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

fn run_command(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.is_empty() {
            Err(output.status.to_string())
        } else {
            Err(format!("{}: {stderr}", output.status))
        }
    }
}

#[cfg(target_os = "macos")]
fn remove_keychain_tokens(report: &mut CleanupReport) {
    let mut failures = 0usize;
    for account in [
        OTTTO_KEYCHAIN_ACCOUNT,
        OTTTO_SETUP_RUN_TOKEN_ACCOUNT,
        OTTTO_RELAY_DEVICE_SECRET_ACCOUNT,
    ] {
        match KeychainSecretStore::new(account).delete() {
            Ok(()) => {}
            Err(error) => {
                failures += 1;
                report.fail(format!(
                    "delete keychain item {OTTTO_KEYCHAIN_SERVICE}/{account}: {error}"
                ));
            }
        }
    }
    for account in [
        OTTTO_KEYCHAIN_ACCOUNT,
        OTTTO_SETUP_RUN_TOKEN_ACCOUNT,
        OTTTO_RELAY_DEVICE_SECRET_ACCOUNT,
    ] {
        if let Err(error) = delete_legacy_keychain_item(account) {
            failures += 1;
            report.fail(format!(
                "delete legacy keychain item {OTTTO_LEGACY_KEYCHAIN_SERVICE}/{account}: {error}"
            ));
        }
    }
    report.credential_status = if failures == 0 {
        "removed_or_absent".to_string()
    } else {
        "failed".to_string()
    };
}

#[cfg(target_os = "macos")]
fn delete_legacy_keychain_item(account: &'static str) -> Result<(), String> {
    let output = Command::new("/usr/bin/security")
        .args([
            "delete-generic-password",
            "-s",
            OTTTO_LEGACY_KEYCHAIN_SERVICE,
            "-a",
            account,
        ])
        .output()
        .map_err(|error| error.to_string())?;
    if output.status.success()
        || keychain_delete_reports_missing(output.status.code(), &output.stderr)
    {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let message = if stderr.is_empty() { stdout } else { stderr };
    Err(if message.is_empty() {
        format!("security exited with status {}", output.status)
    } else {
        message
    })
}

#[cfg(target_os = "macos")]
fn keychain_delete_reports_missing(exit_code: Option<i32>, stderr: &[u8]) -> bool {
    if exit_code == Some(44) {
        return true;
    }
    let stderr = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    stderr.contains("could not be found") || stderr.contains("item not found")
}

#[cfg(not(target_os = "macos"))]
fn remove_keychain_tokens(report: &mut CleanupReport) {
    report.credential_status = "not_supported".to_string();
    report.warn("local credential removal is only implemented for macOS");
}

fn remove_cleanup_target(target: CleanupTarget, report: &mut CleanupReport) {
    let result = match target.kind {
        CleanupTargetKind::File => fs::remove_file(&target.path),
        CleanupTargetKind::Directory => fs::remove_dir_all(&target.path),
    };

    match result {
        Ok(()) => report.removed_paths.push(target.path.display().to_string()),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            report.missing_paths.push(target.path.display().to_string())
        }
        Err(error) => report.fail(format!("remove {}: {error}", target.path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uninstall_plan_is_user_scoped_and_cloud_safe() {
        let plan = plan_local_uninstall(Path::new("/Users/test"));
        let targets = plan
            .actions
            .iter()
            .filter(|action| action.action == "remove_path")
            .map(|action| action.target.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            targets,
            vec![
                "/Users/test/Library/LaunchAgents/net.ottto.service.plist",
                "/Users/test/Library/LaunchAgents/net.ottto.locald.plist",
                "/Users/test/Applications/Ottto.app",
                "/Users/test/Applications/Ottto Companion.app",
                "/Users/test/Library/Application Support/Ottto",
                "/Users/test/Library/Logs/Ottto",
                "/Users/test/.ottto",
            ]
        );
        assert!(plan.requires_confirmation);
        assert!(plan.cloud_credentials_untouched);
        assert!(plan.actions.iter().any(|action| {
            action.action == "unload_legacy_launch_agent"
                && action.target.ends_with("net.ottto.locald")
        }));
        assert!(plan.actions.iter().any(|action| {
            action.action == "stop_process" && action.target == OTTTO_LEGACY_SERVICE_BINARY_NAME
        }));
        let credentials = plan
            .actions
            .iter()
            .filter(|action| action.kind == "local_keychain_item")
            .map(|action| (action.action.as_str(), action.target.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            credentials,
            vec![
                (
                    "remove_local_control_credential",
                    "net.ottto.service/control-token"
                ),
                (
                    "remove_setup_run_credential",
                    "net.ottto.service/setup-run-token"
                ),
                (
                    "remove_relay_device_credential",
                    "net.ottto.service/relay-device-secret"
                ),
            ]
        );
        let legacy_credentials = plan
            .actions
            .iter()
            .filter(|action| action.kind == "legacy_local_keychain_item")
            .map(|action| action.target.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            legacy_credentials,
            vec![
                "net.ottto.locald/control-token",
                "net.ottto.locald/setup-run-token",
                "net.ottto.locald/relay-device-secret",
            ]
        );
        assert!(plan
            .warnings
            .iter()
            .any(|warning| warning.contains("Cloud provider credentials")));
    }

    #[test]
    fn execution_result_marks_failures_incomplete() {
        let plan = plan_local_uninstall(Path::new("/Users/test"));
        let mut report = CleanupReport::new();
        report.credential_status = "removed_or_absent".to_string();
        report
            .failed_operations
            .push("launchctl bootout did not unload gui/501/net.ottto.service".to_string());

        let result = execution_result(plan, report);

        assert_eq!(result.status, "uninstall_incomplete");
        assert_eq!(result.failed_operations.len(), 1);
        assert!(result.cloud_credentials_untouched);
    }
}
