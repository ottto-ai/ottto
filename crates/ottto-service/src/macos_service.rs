use anyhow::{Context, Result};
use ottto_core::{
    install_owner_for_path, macos_launch_agent_target, user_launchctl_domain,
    MACOS_LAUNCH_AGENT_LABEL, OTTTO_CONTROL_TOKEN_ENV, OTTTO_SERVICE_SOCKET_NAME, OTTTO_SOCKET_ENV,
};
use ottto_protocol::InstallOwner;
use plist::{Dictionary, Value};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const LAUNCH_AGENT_LABEL: &str = MACOS_LAUNCH_AGENT_LABEL;
pub const MACH_SERVICE_NAME: &str = "net.ottto.service.xpc";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LaunchAgentConfig {
    pub label: String,
    pub executable_path: PathBuf,
    pub socket_path: PathBuf,
    pub mach_service_name: String,
    pub stdout_path: PathBuf,
    pub stderr_path: PathBuf,
    pub control_token_env_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LaunchAgentInstallPlan {
    pub plist_path: PathBuf,
    pub bootstrap_command: Vec<String>,
    pub enable_command: Vec<String>,
    pub kickstart_command: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LaunchAgentOwnerState {
    pub plist_path: PathBuf,
    pub plist_exists: bool,
    pub plist_owner: InstallOwner,
    pub loaded: bool,
    pub loaded_owner: InstallOwner,
    pub expected_owner: InstallOwner,
    pub owner_drift: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plist_executable_path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loaded_executable_path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plist_error: Option<String>,
}

impl LaunchAgentConfig {
    pub fn local_user_default(home: &Path, executable_path: PathBuf) -> Self {
        let support_dir = home
            .join("Library")
            .join("Application Support")
            .join("Ottto");
        let log_dir = home.join("Library").join("Logs").join("Ottto");

        Self {
            label: LAUNCH_AGENT_LABEL.to_string(),
            executable_path,
            socket_path: support_dir.join(OTTTO_SERVICE_SOCKET_NAME),
            mach_service_name: MACH_SERVICE_NAME.to_string(),
            stdout_path: log_dir.join("ottto-service.out.log"),
            stderr_path: log_dir.join("ottto-service.err.log"),
            control_token_env_name: OTTTO_CONTROL_TOKEN_ENV.to_string(),
        }
    }
}

pub fn launch_agent_path(home: &Path) -> PathBuf {
    home.join("Library")
        .join("LaunchAgents")
        .join(format!("{LAUNCH_AGENT_LABEL}.plist"))
}

pub fn write_launch_agent(
    config: &LaunchAgentConfig,
    plist_path: &Path,
) -> Result<LaunchAgentInstallPlan> {
    if let Some(parent) = plist_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create launch agent dir {}", parent.display()))?;
    }
    for path in [
        &config.socket_path,
        &config.stdout_path,
        &config.stderr_path,
    ] {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create ottto-service dir {}", parent.display()))?;
        }
    }

    let plist = render_launch_agent_plist(config)?;
    fs::write(plist_path, plist)
        .with_context(|| format!("write launch agent {}", plist_path.display()))?;

    Ok(install_plan(config, plist_path))
}

pub fn ensure_launch_agent_write_allowed(
    config: &LaunchAgentConfig,
    plist_path: &Path,
    allow_owner_migration: bool,
) -> Result<LaunchAgentOwnerState> {
    let state = inspect_launch_agent_owner(plist_path, Some(&config.executable_path));
    if allow_owner_migration || !state.owner_drift {
        return Ok(state);
    }

    let current_owner = conflicting_owner(&state);
    anyhow::bail!(
        "refusing to replace {LAUNCH_AGENT_LABEL}: existing owner is {}, requested owner is {}. {}",
        install_owner_label(current_owner),
        install_owner_label(state.expected_owner),
        install_owner_repair_hint(current_owner)
    )
}

pub fn inspect_launch_agent_owner(
    plist_path: &Path,
    expected_executable_path: Option<&Path>,
) -> LaunchAgentOwnerState {
    let (plist_exists, plist_executable_path, plist_error) =
        read_launch_agent_program_path(plist_path);
    inspect_launch_agent_owner_with_loaded_program(
        plist_path,
        expected_executable_path,
        plist_exists,
        plist_executable_path,
        plist_error,
        loaded_launch_agent_program_path(),
    )
}

pub fn inspect_launch_agent_owner_with_loaded_program(
    plist_path: &Path,
    expected_executable_path: Option<&Path>,
    plist_exists: bool,
    plist_executable_path: Option<PathBuf>,
    plist_error: Option<String>,
    loaded_executable_path: Option<PathBuf>,
) -> LaunchAgentOwnerState {
    let expected_owner = expected_executable_path
        .map(install_owner_for_path)
        .unwrap_or(InstallOwner::Unknown);
    let plist_owner = plist_executable_path
        .as_deref()
        .map(install_owner_for_path)
        .unwrap_or(InstallOwner::Unknown);
    let loaded_owner = loaded_executable_path
        .as_deref()
        .map(install_owner_for_path)
        .unwrap_or(InstallOwner::Unknown);
    let loaded = loaded_executable_path.is_some();
    let owner_drift = owner_state_drift(
        expected_executable_path,
        plist_executable_path.as_deref(),
        expected_owner,
        plist_owner,
        loaded_owner,
        plist_exists,
        loaded,
    );

    LaunchAgentOwnerState {
        plist_path: plist_path.to_path_buf(),
        plist_exists,
        plist_owner,
        loaded,
        loaded_owner,
        expected_owner,
        owner_drift,
        plist_executable_path,
        loaded_executable_path,
        plist_error,
    }
}

pub fn read_launch_agent_program_path(
    plist_path: &Path,
) -> (bool, Option<PathBuf>, Option<String>) {
    if !plist_path.exists() {
        return (false, None, None);
    }
    let parsed = match Value::from_file(plist_path) {
        Ok(parsed) => parsed,
        Err(error) => return (true, None, Some(format!("malformed plist: {error}"))),
    };
    let Some(root) = parsed.as_dictionary() else {
        return (
            true,
            None,
            Some("plist root is not a dictionary".to_string()),
        );
    };
    let executable = root
        .get("ProgramArguments")
        .and_then(Value::as_array)
        .and_then(|arguments| arguments.first())
        .and_then(Value::as_string)
        .map(PathBuf::from);
    if executable.is_none() {
        return (
            true,
            None,
            Some("plist is missing ProgramArguments[0]".to_string()),
        );
    }
    (true, executable, None)
}

pub fn parse_launchctl_program_path(output: &str) -> Option<PathBuf> {
    parse_launchctl_prefixed_path(output, "program = ")
        .or_else(|| parse_launchctl_prefixed_path(output, "path = "))
}

fn parse_launchctl_prefixed_path(output: &str, prefix: &str) -> Option<PathBuf> {
    output.lines().find_map(|line| {
        line.trim().strip_prefix(prefix).and_then(|value| {
            let value = value.trim().trim_matches('"');
            if value.is_empty() || value == "(null)" {
                None
            } else {
                Some(PathBuf::from(value))
            }
        })
    })
}

pub fn loaded_launch_agent_program_path() -> Option<PathBuf> {
    if std::env::consts::OS != "macos" {
        return None;
    }
    let output = Command::new("launchctl")
        .arg("print")
        .arg(macos_launch_agent_target())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let body = String::from_utf8(output.stdout).ok()?;
    parse_launchctl_program_path(&body)
}

pub fn install_owner_label(owner: InstallOwner) -> &'static str {
    match owner {
        InstallOwner::Homebrew => "Homebrew",
        InstallOwner::HostedInstaller => "hosted-installer",
        InstallOwner::AppBundle => "app-bundle",
        InstallOwner::Unknown => "unknown-owner",
    }
}

pub fn install_owner_repair_hint(owner: InstallOwner) -> &'static str {
    match owner {
        InstallOwner::Homebrew => {
            "Use brew services restart ottto, or stop Homebrew and pass --migrate-owner for an intentional owner switch."
        }
        InstallOwner::AppBundle => {
            "Relaunch the Ottto app for app-bundle ownership, or quit the app and pass --migrate-owner for an intentional owner switch."
        }
        InstallOwner::HostedInstaller => {
            "Rerun the hosted installer for hosted-installer ownership, or pass --migrate-owner for an intentional owner switch."
        }
        InstallOwner::Unknown => {
            "Inspect the existing LaunchAgent, then pass --migrate-owner only if replacing it is intentional."
        }
    }
}

pub fn render_launch_agent_plist(config: &LaunchAgentConfig) -> Result<Vec<u8>> {
    let mut root = Dictionary::new();
    root.insert("Label".to_string(), Value::String(config.label.clone()));
    root.insert(
        "ProgramArguments".to_string(),
        Value::Array(vec![
            Value::String(config.executable_path.display().to_string()),
            Value::String("serve-xpc".to_string()),
            Value::String("--mach-service".to_string()),
            Value::String(config.mach_service_name.clone()),
            Value::String("--socket".to_string()),
            Value::String(config.socket_path.display().to_string()),
        ]),
    );
    let mut mach_services = Dictionary::new();
    mach_services.insert(config.mach_service_name.clone(), Value::Boolean(true));
    root.insert("MachServices".to_string(), Value::Dictionary(mach_services));
    root.insert("RunAtLoad".to_string(), Value::Boolean(true));
    root.insert("KeepAlive".to_string(), Value::Boolean(true));
    root.insert(
        "StandardOutPath".to_string(),
        Value::String(config.stdout_path.display().to_string()),
    );
    root.insert(
        "StandardErrorPath".to_string(),
        Value::String(config.stderr_path.display().to_string()),
    );

    let mut env = Dictionary::new();
    env.insert(
        OTTTO_SOCKET_ENV.to_string(),
        Value::String(config.socket_path.display().to_string()),
    );
    root.insert("EnvironmentVariables".to_string(), Value::Dictionary(env));

    let mut body = Vec::new();
    Value::Dictionary(root).to_writer_xml(&mut body)?;
    Ok(body)
}

pub fn install_plan(config: &LaunchAgentConfig, plist_path: &Path) -> LaunchAgentInstallPlan {
    let domain = user_launchctl_domain();
    LaunchAgentInstallPlan {
        plist_path: plist_path.to_path_buf(),
        bootstrap_command: vec![
            "launchctl".to_string(),
            "bootstrap".to_string(),
            domain.clone(),
            plist_path.display().to_string(),
        ],
        enable_command: vec![
            "launchctl".to_string(),
            "enable".to_string(),
            format!("{domain}/{}", config.label),
        ],
        kickstart_command: vec![
            "launchctl".to_string(),
            "kickstart".to_string(),
            "-k".to_string(),
            format!("{domain}/{}", config.label),
        ],
    }
}

fn owner_state_drift(
    expected_executable_path: Option<&Path>,
    plist_executable_path: Option<&Path>,
    expected_owner: InstallOwner,
    plist_owner: InstallOwner,
    loaded_owner: InstallOwner,
    plist_exists: bool,
    loaded: bool,
) -> bool {
    if plist_exists && plist_executable_path.is_none() {
        return true;
    }
    if let (Some(expected), Some(plist)) = (expected_executable_path, plist_executable_path) {
        if expected_owner == InstallOwner::Unknown
            && plist_owner == InstallOwner::Unknown
            && expected != plist
        {
            return true;
        }
    }
    (plist_exists && owner_conflict(expected_owner, plist_owner))
        || (loaded && owner_conflict(expected_owner, loaded_owner))
        || (plist_exists && loaded && owner_conflict(plist_owner, loaded_owner))
}

fn owner_conflict(left: InstallOwner, right: InstallOwner) -> bool {
    left != right && (left != InstallOwner::Unknown || right != InstallOwner::Unknown)
}

fn conflicting_owner(state: &LaunchAgentOwnerState) -> InstallOwner {
    if state.plist_owner != InstallOwner::Unknown && state.plist_owner != state.expected_owner {
        return state.plist_owner;
    }
    if state.loaded_owner != InstallOwner::Unknown && state.loaded_owner != state.expected_owner {
        return state.loaded_owner;
    }
    if state.plist_exists {
        return state.plist_owner;
    }
    state.loaded_owner
}

#[cfg(test)]
mod tests {
    use super::*;
    use ottto_core::OTTTO_SERVICE_BINARY_NAME;

    #[test]
    fn renders_valid_launch_agent_plist() {
        let config = config();
        let bytes = render_launch_agent_plist(&config).expect("plist should render");
        let parsed = Value::from_reader_xml(bytes.as_slice()).expect("plist should parse");
        let root = parsed
            .as_dictionary()
            .expect("launch agent should be dictionary");

        assert_eq!(
            root.get("Label").and_then(Value::as_string),
            Some(LAUNCH_AGENT_LABEL)
        );
        assert_eq!(
            root.get("RunAtLoad").and_then(Value::as_boolean),
            Some(true)
        );
        assert_eq!(
            root.get("KeepAlive").and_then(Value::as_boolean),
            Some(true)
        );

        let args = root
            .get("ProgramArguments")
            .and_then(Value::as_array)
            .expect("program args");
        assert_eq!(args[1].as_string(), Some("serve-xpc"));
        assert_eq!(args[2].as_string(), Some("--mach-service"));
        assert_eq!(args[3].as_string(), Some(MACH_SERVICE_NAME));
        assert_eq!(args[4].as_string(), Some("--socket"));
        assert_eq!(
            args[5].as_string(),
            Some("/Users/test/Library/Application Support/Ottto/ottto-service.sock")
        );
        assert_eq!(
            root.get("MachServices")
                .and_then(Value::as_dictionary)
                .and_then(|services| services.get(MACH_SERVICE_NAME))
                .and_then(Value::as_boolean),
            Some(true)
        );
    }

    #[test]
    fn launchctl_plan_targets_current_user_domain() {
        let config = config();
        let plan = install_plan(
            &config,
            Path::new("/Users/test/Library/LaunchAgents/net.ottto.service.plist"),
        );

        assert_eq!(plan.bootstrap_command[0], "launchctl");
        assert_eq!(plan.bootstrap_command[1], "bootstrap");
        assert!(plan.bootstrap_command[2].starts_with("gui/"));
        assert!(plan.enable_command[2].ends_with(LAUNCH_AGENT_LABEL));
        assert!(plan.kickstart_command[3].ends_with(LAUNCH_AGENT_LABEL));
    }

    #[test]
    fn classifies_launch_agent_program_arguments_owner() {
        let path = test_plist_path("homebrew-owner");
        write_test_plist(&path, "/opt/homebrew/Cellar/ottto/0.1.0/bin/ottto-service");

        let state = inspect_launch_agent_owner_with_loaded_program(
            &path,
            Some(Path::new(
                "/Applications/Ottto.app/Contents/Helpers/ottto-service",
            )),
            true,
            Some(PathBuf::from(
                "/opt/homebrew/Cellar/ottto/0.1.0/bin/ottto-service",
            )),
            None,
            None,
        );

        assert_eq!(state.plist_owner, InstallOwner::Homebrew);
        assert_eq!(state.expected_owner, InstallOwner::AppBundle);
        assert!(state.owner_drift);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn app_bundle_paths_require_app_contents_boundary() {
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

    #[test]
    fn parses_loaded_launchd_program_path() {
        let output = r#"
            path = /Users/test/Library/LaunchAgents/net.ottto.service.plist
            program = /opt/homebrew/opt/ottto/bin/ottto-service
        "#;

        assert_eq!(
            parse_launchctl_program_path(output),
            Some(PathBuf::from("/opt/homebrew/opt/ottto/bin/ottto-service"))
        );
    }

    #[test]
    fn malformed_plist_is_unknown_and_drifted() {
        let path = test_plist_path("malformed-owner");
        fs::write(&path, "not a plist").expect("write malformed plist");

        let (exists, executable, error) = read_launch_agent_program_path(&path);

        assert!(exists);
        assert_eq!(executable, None);
        assert!(error.expect("error").contains("malformed plist"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn app_bundle_owner_can_repair_stale_app_bundle_path() {
        let state = inspect_launch_agent_owner_with_loaded_program(
            Path::new("/Users/test/Library/LaunchAgents/net.ottto.service.plist"),
            Some(Path::new(
                "/Applications/Ottto.app/Contents/Helpers/ottto-service",
            )),
            true,
            Some(PathBuf::from(
                "/Users/test/Applications/Ottto.app/Contents/Helpers/ottto-service",
            )),
            None,
            None,
        );

        assert_eq!(state.plist_owner, InstallOwner::AppBundle);
        assert_eq!(state.expected_owner, InstallOwner::AppBundle);
        assert!(!state.owner_drift);
    }

    #[test]
    fn unknown_existing_path_blocks_unknown_rewrite_when_path_differs() {
        let state = inspect_launch_agent_owner_with_loaded_program(
            Path::new("/Users/test/Library/LaunchAgents/net.ottto.service.plist"),
            Some(Path::new("/tmp/new/ottto-service")),
            true,
            Some(PathBuf::from("/tmp/old/ottto-service")),
            None,
            None,
        );

        assert_eq!(state.plist_owner, InstallOwner::Unknown);
        assert_eq!(state.expected_owner, InstallOwner::Unknown);
        assert!(state.owner_drift);
    }

    #[test]
    fn known_existing_owner_blocks_unknown_rewrite() {
        let path = test_plist_path("known-owner-unknown-rewrite");
        write_test_plist(&path, "/opt/homebrew/bin/ottto-service");
        let config = LaunchAgentConfig::local_user_default(
            Path::new("/Users/tester"),
            PathBuf::from("/tmp/ottto-service"),
        );

        let error = ensure_launch_agent_write_allowed(&config, &path, false)
            .expect_err("unknown writer should not replace Homebrew ownership");

        assert!(error.to_string().contains("existing owner is Homebrew"));
        let _ = fs::remove_file(path);
    }

    fn config() -> LaunchAgentConfig {
        LaunchAgentConfig::local_user_default(
            Path::new("/Users/test"),
            PathBuf::from(format!(
                "/Applications/Ottto.app/Contents/MacOS/{OTTTO_SERVICE_BINARY_NAME}"
            )),
        )
    }

    fn test_plist_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ottto-service-{name}-{}.plist", std::process::id()))
    }

    fn write_test_plist(path: &Path, executable: &str) {
        let mut root = Dictionary::new();
        root.insert(
            "ProgramArguments".to_string(),
            Value::Array(vec![Value::String(executable.to_string())]),
        );
        let mut body = Vec::new();
        Value::Dictionary(root)
            .to_writer_xml(&mut body)
            .expect("write plist");
        fs::write(path, body).expect("write test plist");
    }
}
