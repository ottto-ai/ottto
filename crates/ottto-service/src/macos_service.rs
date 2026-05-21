use anyhow::{Context, Result};
use ottto_core::{
    user_launchctl_domain, MACOS_LAUNCH_AGENT_LABEL, OTTTO_CONTROL_TOKEN_ENV,
    OTTTO_SERVICE_SOCKET_NAME, OTTTO_SOCKET_ENV,
};
use plist::{Dictionary, Value};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

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

    fn config() -> LaunchAgentConfig {
        LaunchAgentConfig::local_user_default(
            Path::new("/Users/test"),
            PathBuf::from(format!(
                "/Applications/Ottto.app/Contents/MacOS/{OTTTO_SERVICE_BINARY_NAME}"
            )),
        )
    }
}
