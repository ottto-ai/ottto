use anyhow::{Context, Result};
use ottto_protocol::InstallOwner;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

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

    let domain = user_launchctl_domain();
    let target = macos_launch_agent_target();
    run_launchctl(&["enable", &target])?;
    ensure_launch_agent_loaded(&domain, &target)?;
    run_launchctl(&["kickstart", "-k", &target])
}

fn ensure_launch_agent_loaded(domain: &str, target: &str) -> Result<()> {
    if launch_agent_is_loaded(target) {
        return Ok(());
    }

    let Some(plist_path) = user_launch_agent_path() else {
        return Ok(());
    };
    if !plist_path.exists() {
        return Ok(());
    }

    let plist = plist_path.display().to_string();
    match run_launchctl(&["bootstrap", domain, &plist]) {
        Ok(()) => Ok(()),
        Err(_error) if wait_for_launch_agent_loaded(target) => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "bootstrap LaunchAgent {} into {domain}",
                plist_path.display()
            )
        }),
    }
}

fn launch_agent_is_loaded(target: &str) -> bool {
    Command::new("launchctl")
        .arg("print")
        .arg(target)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn wait_for_launch_agent_loaded(target: &str) -> bool {
    for _ in 0..20 {
        if launch_agent_is_loaded(target) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn user_launch_agent_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| launch_agent_path_from_home(&home))
}

fn launch_agent_path_from_home(home: &Path) -> PathBuf {
    home.join("Library")
        .join("LaunchAgents")
        .join(format!("{MACOS_LAUNCH_AGENT_LABEL}.plist"))
}

fn run_launchctl(args: &[&str]) -> Result<()> {
    let status = Command::new("launchctl")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("run launchctl {}", args.join(" ")))?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("launchctl {} failed with {status}", args.join(" "))
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
