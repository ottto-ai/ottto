#[cfg(unix)]
use crate::service_lifecycle::{
    ServiceLifecycleBusy, ServiceLifecycleTransaction, COMMAND_TIMEOUT,
};
use anyhow::{Context, Result};
use ottto_protocol::InstallOwner;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(unix)]
use std::process::ExitStatus;
#[cfg(unix)]
use std::time::{Duration, Instant};

pub const MACOS_LAUNCH_AGENT_LABEL: &str = "net.ottto.service";
pub const MACOS_LEGACY_LAUNCH_AGENT_LABEL: &str = "net.ottto.locald";
pub const OTTTO_SERVICE_BINARY_NAME: &str = "ottto-service";
pub const OTTTO_LEGACY_SERVICE_BINARY_NAME: &str = "ottto-locald";
pub const OTTTO_SOCKET_ENV: &str = "OTTTO_SERVICE_SOCKET";
pub const OTTTO_CONTROL_TOKEN_ENV: &str = "OTTTO_SERVICE_CONTROL_TOKEN";
pub const OTTTO_SECRET_FALLBACK_DIR_ENV: &str = "OTTTO_SERVICE_SECRET_FALLBACK_DIR";
pub const OTTTO_SERVICE_SOCKET_NAME: &str = "ottto-service.sock";
pub const OTTTO_LEGACY_SOCKET_NAME: &str = "locald.sock";
pub const OTTTO_CLIENT_NAME: &str = "ottto-service";

pub fn user_launchctl_domain() -> String {
    format!("gui/{}", current_uid())
}

pub fn macos_launch_agent_target() -> String {
    format!("{}/{}", user_launchctl_domain(), MACOS_LAUNCH_AGENT_LABEL)
}

pub fn install_owner_for_path(path: &Path) -> InstallOwner {
    let value = path.to_string_lossy();
    if value.contains(".app/Contents/") {
        return InstallOwner::AppBundle;
    }
    if value.contains("/.ottto/bin/") {
        return InstallOwner::HostedInstaller;
    }
    if value.contains("/Cellar/")
        || value.contains("/opt/homebrew/")
        || value.contains("/usr/local/Homebrew/")
    {
        return InstallOwner::Homebrew;
    }
    InstallOwner::Unknown
}

pub fn kickstart_macos_launch_agent() -> Result<()> {
    if std::env::consts::OS != "macos" {
        anyhow::bail!("ottto-service autostart is only implemented for macOS");
    }
    #[cfg(unix)]
    {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .context("HOME is not set")?;
        let deadline = Instant::now() + Duration::from_secs(30);
        kickstart_with(&home, |transaction, args| {
            let remaining = deadline.saturating_duration_since(Instant::now());
            anyhow::ensure!(
                !remaining.is_zero(),
                "autostart lifecycle deadline expired; state may be partial"
            );
            let mut command = Command::new("/bin/launchctl");
            command.args(args);
            transaction
                .run(&mut command, remaining.min(COMMAND_TIMEOUT))
                .map(|(status, _)| status)
        })
    }
    #[cfg(not(unix))]
    anyhow::bail!("ottto-service autostart requires Unix");
}

#[cfg(unix)]
#[derive(Debug, thiserror::Error)]
#[error("launchctl command failed with {0}")]
struct LaunchctlExitFailure(ExitStatus);

#[cfg(unix)]
fn kickstart_with(
    home: &Path,
    mut execute: impl FnMut(&ServiceLifecycleTransaction, &[&str]) -> Result<ExitStatus>,
) -> Result<()> {
    let transaction = match ServiceLifecycleTransaction::acquire(home, Duration::ZERO) {
        Ok(transaction) => transaction,
        // An upgrade owns this label. The CLI's existing socket retry handles
        // readiness without entering another launchd transaction.
        Err(error) if error.downcast_ref::<ServiceLifecycleBusy>().is_some() => return Ok(()),
        Err(error) => return Err(error),
    };
    let mut run = |args: &[&str]| execute(&transaction, args);
    let domain = user_launchctl_domain();
    let target = macos_launch_agent_target();
    let plist = launch_agent_path_from_home(home);
    run_launchctl(&mut run, &["enable", &target])?;
    ensure_launch_agent_loaded(&mut run, &plist, &domain, &target)?;
    // A connected listener may still be starting after bootstrap released the
    // transaction. Ensure it runs without killing the newly loaded instance.
    // A failed automatic start never escalates to bootout/replacement.
    run_launchctl(&mut run, &["kickstart", &target])
}

#[cfg(unix)]
fn ensure_launch_agent_loaded(
    run: &mut impl FnMut(&[&str]) -> Result<ExitStatus>,
    plist_path: &Path,
    domain: &str,
    target: &str,
) -> Result<()> {
    if launch_agent_is_loaded(run, target)? || !plist_path.exists() {
        return Ok(());
    }
    bootstrap_launch_agent(run, plist_path, domain, target)
}

#[cfg(unix)]
fn bootstrap_launch_agent(
    run: &mut impl FnMut(&[&str]) -> Result<ExitStatus>,
    plist_path: &Path,
    domain: &str,
    target: &str,
) -> Result<()> {
    let plist = plist_path.display().to_string();
    match run_launchctl(run, &["bootstrap", domain, &plist]) {
        Ok(()) => Ok(()),
        // Preserve the existing reconciliation of a conclusive bootstrap exit.
        // Indeterminate command errors never proceed as successful autostart.
        Err(error)
            if error.downcast_ref::<LaunchctlExitFailure>().is_some()
                && wait_for_launch_agent_loaded(run, target)? =>
        {
            Ok(())
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "bootstrap LaunchAgent {} into {domain}",
                plist_path.display()
            )
        }),
    }
}

#[cfg(unix)]
fn launch_agent_is_loaded(
    run: &mut impl FnMut(&[&str]) -> Result<ExitStatus>,
    target: &str,
) -> Result<bool> {
    let status = run(&["print", target])?;
    match status.code() {
        Some(0) => Ok(true),
        Some(libc::ESRCH | 113) => Ok(false),
        _ => anyhow::bail!(
            "cannot establish LaunchAgent state ({status}); refusing further autostart changes"
        ),
    }
}

#[cfg(unix)]
fn wait_for_launch_agent_loaded(
    run: &mut impl FnMut(&[&str]) -> Result<ExitStatus>,
    target: &str,
) -> Result<bool> {
    for _ in 0..20 {
        if launch_agent_is_loaded(run, target)? {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(false)
}

fn launch_agent_path_from_home(home: &Path) -> PathBuf {
    home.join("Library")
        .join("LaunchAgents")
        .join(format!("{MACOS_LAUNCH_AGENT_LABEL}.plist"))
}

#[cfg(unix)]
fn run_launchctl(run: &mut impl FnMut(&[&str]) -> Result<ExitStatus>, args: &[&str]) -> Result<()> {
    let status = run(args)?;
    if status.success() {
        Ok(())
    } else {
        Err(LaunchctlExitFailure(status).into())
    }
}

fn current_uid() -> u32 {
    if let Some(uid) = std::env::var("UID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
    {
        return uid;
    }
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_agent_target_uses_current_user_domain() {
        let target = macos_launch_agent_target();
        assert!(target.starts_with("gui/"));
        assert!(target.ends_with(MACOS_LAUNCH_AGENT_LABEL));
    }

    #[test]
    fn launch_agent_path_uses_user_library() {
        assert_eq!(
            launch_agent_path_from_home(Path::new("/Users/test")),
            PathBuf::from("/Users/test/Library/LaunchAgents/net.ottto.service.plist")
        );
    }

    #[test]
    fn install_owner_detection_routes_known_install_paths() {
        assert_eq!(
            install_owner_for_path(Path::new(
                "/opt/homebrew/Cellar/ottto/0.1.0/bin/ottto-service"
            )),
            InstallOwner::Homebrew
        );
        assert_eq!(
            install_owner_for_path(Path::new(
                "/usr/local/Homebrew/Cellar/ottto/0.1.0/bin/ottto-service"
            )),
            InstallOwner::Homebrew
        );
        assert_eq!(
            install_owner_for_path(Path::new("/Users/test/.ottto/bin/ottto-service")),
            InstallOwner::HostedInstaller
        );
        assert_eq!(
            install_owner_for_path(Path::new(
                "/Applications/Ottto.app/Contents/Helpers/ottto-service"
            )),
            InstallOwner::AppBundle
        );
        assert_eq!(
            install_owner_for_path(Path::new("/tmp/Ottto.app-helper/ottto-service")),
            InstallOwner::Unknown
        );
    }
}

#[cfg(all(test, unix))]
mod autostart_tests {
    use super::*;
    use std::fs;
    use std::os::unix::process::ExitStatusExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let home = std::env::temp_dir().join(format!(
                "ottto-autostart-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&home).unwrap();
            fs::create_dir_all(home.join("Library/LaunchAgents")).unwrap();
            fs::write(
                launch_agent_path_from_home(&home),
                b"external install plist unchanged",
            )
            .unwrap();
            Self(home)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn status(code: i32) -> ExitStatus {
        ExitStatus::from_raw(code << 8)
    }

    #[test]
    fn cli_contention_enters_socket_retry_without_launchd_mutation() {
        let fixture = Fixture::new();
        let transaction = ServiceLifecycleTransaction::acquire(&fixture.0, Duration::ZERO).unwrap();
        let original = fs::read(launch_agent_path_from_home(&fixture.0)).unwrap();
        kickstart_with(&fixture.0, |_, _| {
            panic!("CLI issued launchctl while bootstrap owned the label")
        })
        .unwrap();
        assert_eq!(
            fs::read(launch_agent_path_from_home(&fixture.0)).unwrap(),
            original
        );
        drop(transaction);
        let mut commands = Vec::new();
        kickstart_with(&fixture.0, |_, args| {
            commands.push(args.iter().map(|s| s.to_string()).collect::<Vec<_>>());
            Ok(status(0))
        })
        .unwrap();
        assert_eq!(
            commands
                .iter()
                .map(|args| args[0].as_str())
                .collect::<Vec<_>>(),
            ["enable", "print", "kickstart"]
        );
        assert_eq!(commands[0][1], macos_launch_agent_target());
        assert_eq!(commands[2], ["kickstart", &macos_launch_agent_target()]);
        assert_eq!(
            fs::read(launch_agent_path_from_home(&fixture.0)).unwrap(),
            original
        );
    }

    #[test]
    fn cli_missing_job_bootstraps_the_existing_plist_under_ownership() {
        let fixture = Fixture::new();
        let mut seen = Vec::new();
        kickstart_with(&fixture.0, |_, args| {
            seen.push(args[0].to_owned());
            if args[0] == "print" {
                Ok(status(113))
            } else {
                Ok(status(0))
            }
        })
        .unwrap();
        assert_eq!(seen, ["enable", "print", "bootstrap", "kickstart"]);
        assert_eq!(
            fs::read(launch_agent_path_from_home(&fixture.0)).unwrap(),
            b"external install plist unchanged"
        );
    }

    #[test]
    fn cli_indeterminate_kickstart_never_boots_out_or_rebootstraps() {
        let fixture = Fixture::new();
        let mut seen = Vec::new();
        assert!(kickstart_with(&fixture.0, |_, args| {
            seen.push(args[0].to_owned());
            if args[0] == "kickstart" {
                anyhow::bail!("injected command timeout");
            }
            Ok(status(0))
        })
        .is_err());
        assert_eq!(seen, ["enable", "print", "kickstart"]);
    }

    #[test]
    fn cli_unknown_query_and_failed_enable_stop_without_further_mutation() {
        for failing in ["enable", "print"] {
            let fixture = Fixture::new();
            let mut seen = Vec::new();
            assert!(kickstart_with(&fixture.0, |_, args| {
                seen.push(args[0].to_owned());
                Ok(status(if args[0] == failing { 1 } else { 0 }))
            })
            .is_err());
            assert_eq!(
                seen,
                if failing == "enable" {
                    vec!["enable"]
                } else {
                    vec!["enable", "print"]
                }
            );
        }
    }

    #[test]
    fn serialized_cli_requests_keep_the_just_bootstrapped_generation_while_listener_starts() {
        let fixture = Fixture::new();
        // The helper has loaded generation 1 and returned, releasing its lock.
        // No listener is ready yet, so multiple CLI requests enter autostart.
        let helper = ServiceLifecycleTransaction::acquire(&fixture.0, Duration::ZERO).unwrap();
        let mut generation = 1;
        let mut loaded = true;
        let listener_ready = false;
        drop(helper);
        let mut seen = Vec::new();
        for _ in 0..3 {
            assert!(!listener_ready);
            kickstart_with(&fixture.0, |_, args| {
                seen.push(args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>());
                match args[0] {
                    "print" => return Ok(status(if loaded { 0 } else { 113 })),
                    "bootout" => loaded = false,
                    "bootstrap" => {
                        loaded = true;
                        generation += 1;
                    }
                    "kickstart" if args.contains(&"-k") => generation += 1,
                    _ => {}
                }
                Ok(status(0))
            })
            .unwrap();
        }
        assert!(loaded);
        assert_eq!(generation, 1, "CLI replaced the helper's starting daemon");
        assert!(seen.iter().all(|args| !args
            .iter()
            .any(|arg| matches!(arg.as_str(), "-k" | "bootout" | "bootstrap"))));
        assert_eq!(seen.iter().filter(|args| args[0] == "kickstart").count(), 3);
    }

    #[test]
    fn failed_automatic_kickstart_never_destroys_a_loaded_starting_job() {
        for kickoff_status in [7, 113] {
            let fixture = Fixture::new();
            let mut seen = Vec::new();
            assert!(kickstart_with(&fixture.0, |_, args| {
                seen.push(args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>());
                Ok(status(if args[0] == "kickstart" {
                    kickoff_status
                } else {
                    0
                }))
            })
            .is_err());
            assert_eq!(
                seen.iter().map(|args| args[0].as_str()).collect::<Vec<_>>(),
                ["enable", "print", "kickstart"]
            );
            assert!(seen.iter().all(|args| !args
                .iter()
                .any(|arg| matches!(arg.as_str(), "-k" | "bootout" | "bootstrap"))));
        }
    }
}
