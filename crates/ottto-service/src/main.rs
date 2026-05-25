use anyhow::Result;
use clap::{Parser, Subcommand};
use ottto_core::{
    compiled_release_version, generate_control_token, load_or_create_control_token,
    FileAccountStore, FileConnectionStore, FileMachineStore, LocalMachineBinding,
    OTTTO_SERVICE_BINARY_NAME,
};
use ottto_protocol::{MachineIdentity, OperatingSystem};
use ottto_service::{current_rfc3339_timestamp, macos_service, ControlToken, LocalDaemon};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio};

#[derive(Debug, Parser)]
#[command(name = "ottto-service")]
#[command(about = "Ottto per-user local service")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Status {
        #[arg(long)]
        json: bool,
    },
    Serve {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        once: bool,
    },
    ServeXpc {
        #[arg(long, default_value = "net.ottto.service.xpc")]
        mach_service: String,
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ServiceCommand {
    InstallPlan {
        #[arg(long)]
        executable: PathBuf,
        #[arg(long)]
        json: bool,
    },
    WriteLaunchAgent {
        #[arg(long)]
        executable: PathBuf,
        #[arg(
            long,
            help = "Deliberately replace a LaunchAgent owned by another install method"
        )]
        migrate_owner: bool,
        #[arg(long)]
        json: bool,
    },
    Bootstrap {
        #[arg(long)]
        executable: PathBuf,
        #[arg(
            long,
            help = "Deliberately replace a LaunchAgent owned by another install method"
        )]
        migrate_owner: bool,
        #[arg(long)]
        json: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command.unwrap_or(Command::Status { json: true }) {
        Command::Status { json } => {
            let token = load_or_create_control_token()?;
            let daemon = LocalDaemon::new(
                local_machine(),
                ControlToken::new(token.clone())?,
                current_rfc3339_timestamp(),
            )
            .with_account(FileAccountStore::default().load()?)
            .with_connection(FileConnectionStore::default().load()?);
            let status = daemon.status(&token)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!(
                    "{OTTTO_SERVICE_BINARY_NAME} running for {}",
                    status.machine.display_name
                );
            }
        }
        Command::Serve { socket, once } => {
            #[cfg(unix)]
            {
                let token = load_or_create_control_token()?;
                let daemon = LocalDaemon::new(
                    local_machine(),
                    ControlToken::new(token)?,
                    current_rfc3339_timestamp(),
                )
                .with_account(FileAccountStore::default().load()?)
                .with_connection(FileConnectionStore::default().load()?);
                if !once {
                    start_builtin_relays(&daemon);
                }
                if once {
                    ottto_service::unix_socket::serve_unix_socket_once(&socket, daemon)?;
                } else {
                    ottto_service::unix_socket::serve_unix_socket(&socket, daemon)?;
                }
            }
            #[cfg(not(unix))]
            {
                let _ = socket;
                anyhow::bail!("unix socket transport is not supported on this platform yet");
            }
        }
        Command::ServeXpc {
            mach_service,
            socket,
        } => {
            let token = load_or_create_control_token()?;
            let daemon = LocalDaemon::new(
                local_machine(),
                ControlToken::new(token)?,
                current_rfc3339_timestamp(),
            )
            .with_account(FileAccountStore::default().load()?)
            .with_connection(FileConnectionStore::default().load()?);
            start_builtin_relays(&daemon);
            #[cfg(all(target_os = "macos", unix))]
            {
                let socket = socket.unwrap_or_else(ottto_core::default_socket_path);
                let socket_daemon = daemon.clone();
                let socket_for_thread = socket.clone();
                std::thread::spawn(move || {
                    if let Err(error) = ottto_service::unix_socket::serve_unix_socket(
                        &socket_for_thread,
                        socket_daemon,
                    ) {
                        eprintln!(
                            "debug socket listener {} stopped: {error}",
                            socket_for_thread.display()
                        );
                    }
                });
                eprintln!(
                    "serving XPC Mach service {mach_service} with debug socket {}",
                    socket.display()
                );
            }

            #[cfg(all(not(target_os = "macos"), unix))]
            if let Some(socket) = socket {
                eprintln!(
                    "serving debug local app control at {} without XPC on this platform",
                    socket.display()
                );
                ottto_service::unix_socket::serve_unix_socket(&socket, daemon)?;
                return Ok(());
            }

            #[cfg(target_os = "macos")]
            {
                ottto_service::xpc_mach::serve_xpc_mach_service(&mach_service, daemon)?;
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = mach_service;
                let _ = socket;
                anyhow::bail!("XPC transport is not supported on this platform");
            }
            #[cfg(not(any(unix, target_os = "macos")))]
            {
                let _ = daemon;
            }
        }
        Command::Service { command } => {
            let json = command.json_enabled();
            if let Err(error) = handle_service_command(command) {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "ok": false,
                            "error": {
                                "code": "launch_agent_owner_conflict",
                                "message": error.to_string(),
                                "retryable": false
                            }
                        }))?
                    );
                    std::process::exit(2);
                }
                return Err(error);
            }
        }
    }

    Ok(())
}

fn handle_service_command(command: ServiceCommand) -> Result<()> {
    let home = home_dir()?;
    let (executable, write, execute, json, migrate_owner) = match command {
        ServiceCommand::InstallPlan { executable, json } => (executable, false, false, json, false),
        ServiceCommand::WriteLaunchAgent {
            executable,
            migrate_owner,
            json,
        } => (executable, true, false, json, migrate_owner),
        ServiceCommand::Bootstrap {
            executable,
            migrate_owner,
            json,
        } => (executable, true, true, json, migrate_owner),
    };
    let config = macos_service::LaunchAgentConfig::local_user_default(&home, executable);
    let plist_path = macos_service::launch_agent_path(&home);
    let plan = if write {
        macos_service::ensure_launch_agent_write_allowed(&config, &plist_path, migrate_owner)?;
        macos_service::write_launch_agent(&config, &plist_path)?
    } else {
        macos_service::install_plan(&config, &plist_path)
    };

    if execute {
        for command in service_bootstrap_commands(&plan, service_loaded(&plan)) {
            run_command(&command)?;
        }
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&plan)?);
    } else {
        println!("LaunchAgent plist: {}", plan.plist_path.display());
        println!("Bootstrap: {}", plan.bootstrap_command.join(" "));
        println!("Enable: {}", plan.enable_command.join(" "));
        println!("Kickstart: {}", plan.kickstart_command.join(" "));
    }

    Ok(())
}

impl ServiceCommand {
    fn json_enabled(&self) -> bool {
        match self {
            ServiceCommand::InstallPlan { json, .. }
            | ServiceCommand::WriteLaunchAgent { json, .. }
            | ServiceCommand::Bootstrap { json, .. } => *json,
        }
    }
}

fn start_builtin_relays(daemon: &LocalDaemon) {
    match ottto_service::otlp_relay::spawn_local_otlp_relay(daemon.clone()) {
        Ok(addr) => eprintln!("serving local OTLP relay at http://{addr}"),
        Err(error) => eprintln!("local OTLP relay unavailable: {error}"),
    }
    match ottto_service::snapshot_sync::spawn_local_snapshot_sync() {
        Ok(()) => eprintln!("serving local snapshot sync"),
        Err(error) => eprintln!("local snapshot sync unavailable: {error}"),
    }
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("HOME is not set"))
}

fn run_command(args: &[String]) -> Result<()> {
    let Some((program, rest)) = args.split_first() else {
        anyhow::bail!("empty command");
    };
    let status = ProcessCommand::new(program).args(rest).status()?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("command failed with status {status}: {}", args.join(" "))
    }
}

fn service_loaded(plan: &macos_service::LaunchAgentInstallPlan) -> bool {
    let Some(service_target) = plan.enable_command.last() else {
        return false;
    };
    ProcessCommand::new("launchctl")
        .arg("print")
        .arg(service_target)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn service_bootstrap_commands(
    plan: &macos_service::LaunchAgentInstallPlan,
    loaded: bool,
) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    if loaded {
        if let Some(service_target) = plan.enable_command.last() {
            commands.push(vec![
                "launchctl".to_string(),
                "bootout".to_string(),
                service_target.clone(),
            ]);
        }
    }
    commands.push(plan.enable_command.clone());
    commands.push(plan.bootstrap_command.clone());
    commands.push(plan.kickstart_command.clone());
    commands
}

fn local_machine() -> MachineIdentity {
    let hostname = local_hostname();
    let mut binding = persistent_machine_binding().unwrap_or_else(|_| LocalMachineBinding {
        machine_id: fallback_machine_id(&hostname),
        installation_id: fallback_installation_id(),
        hardware_uuid: platform_hardware_uuid(),
    });
    if binding.hardware_uuid.is_none() {
        if let Some(uuid) = platform_hardware_uuid() {
            binding.hardware_uuid = Some(uuid);
            let _ = FileMachineStore::default().save(&binding);
        }
    }
    MachineIdentity {
        machine_id: binding.machine_id,
        installation_id: binding.installation_id,
        hardware_uuid: binding.hardware_uuid,
        display_name: hostname.clone(),
        hostname,
        os: current_os(),
        arch: current_arch(),
        local_platform_version: compiled_release_version(),
    }
}

fn persistent_machine_binding() -> Result<LocalMachineBinding> {
    let hostname = local_hostname();
    FileMachineStore::default().load_or_create(|| {
        Ok(LocalMachineBinding {
            machine_id: platform_machine_id().unwrap_or_else(|| fallback_machine_id(&hostname)),
            installation_id: fallback_installation_id(),
            hardware_uuid: platform_hardware_uuid(),
        })
    })
}

fn platform_hardware_uuid() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        ioplatform_uuid()
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

fn fallback_machine_id(hostname: &str) -> String {
    stable_machine_id_from_seed(&format!(
        "{}:{}:{}",
        current_os_slug(),
        current_arch(),
        hostname
    ))
}

fn fallback_installation_id() -> String {
    match generate_control_token() {
        Ok(token) => format!("oti_{}", &token[..32]),
        Err(_) => "oti_local_generation_failed".to_string(),
    }
}

fn stable_machine_id_from_seed(seed: &str) -> String {
    let digest = Sha256::digest(seed.as_bytes());
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("otm_{}", &hex[..32])
}

fn platform_machine_id() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        ioplatform_uuid().map(|uuid| stable_machine_id_from_seed(&format!("macos:{uuid}")))
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

#[cfg(target_os = "macos")]
fn ioplatform_uuid() -> Option<String> {
    let output = ProcessCommand::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let body = String::from_utf8(output.stdout).ok()?;
    body.lines().find_map(|line| {
        let trimmed = line.trim();
        if !trimmed.contains("IOPlatformUUID") {
            return None;
        }
        trimmed
            .split_once('=')
            .map(|(_, value)| value.trim().trim_matches('"').to_string())
            .filter(|value| !value.is_empty())
    })
}

fn local_hostname() -> String {
    if let Ok(hostname) = std::env::var("HOSTNAME") {
        if !hostname.trim().is_empty() {
            return hostname;
        }
    }
    ProcessCommand::new("hostname")
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .map(|hostname| hostname.trim().to_string())
        .filter(|hostname| !hostname.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
}

fn current_os_slug() -> &'static str {
    match current_os() {
        OperatingSystem::Macos => "macos",
        OperatingSystem::Windows => "windows",
        OperatingSystem::Linux => "linux",
        OperatingSystem::Unknown => "unknown",
    }
}

fn current_arch() -> String {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        other => other,
    }
    .to_string()
}

fn current_os() -> OperatingSystem {
    match std::env::consts::OS {
        "macos" => OperatingSystem::Macos,
        "windows" => OperatingSystem::Windows,
        "linux" => OperatingSystem::Linux,
        _ => OperatingSystem::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_bootstrap_clears_disabled_state_before_bootstrap() {
        let plan = macos_service::LaunchAgentInstallPlan {
            plist_path: PathBuf::from("/Users/test/Library/LaunchAgents/net.ottto.service.plist"),
            bootstrap_command: vec![
                "launchctl".to_string(),
                "bootstrap".to_string(),
                "gui/501".to_string(),
                "/Users/test/Library/LaunchAgents/net.ottto.service.plist".to_string(),
            ],
            enable_command: vec![
                "launchctl".to_string(),
                "enable".to_string(),
                "gui/501/net.ottto.service".to_string(),
            ],
            kickstart_command: vec![
                "launchctl".to_string(),
                "kickstart".to_string(),
                "-k".to_string(),
                "gui/501/net.ottto.service".to_string(),
            ],
        };

        let commands = service_bootstrap_commands(&plan, false);

        assert_eq!(commands[0], plan.enable_command);
        assert_eq!(commands[1], plan.bootstrap_command);
        assert_eq!(commands[2], plan.kickstart_command);
    }

    #[test]
    fn service_bootstrap_replaces_loaded_service() {
        let plan = macos_service::LaunchAgentInstallPlan {
            plist_path: PathBuf::from("/Users/test/Library/LaunchAgents/net.ottto.service.plist"),
            bootstrap_command: vec!["bootstrap".to_string()],
            enable_command: vec![
                "enable".to_string(),
                "gui/501/net.ottto.service".to_string(),
            ],
            kickstart_command: vec!["kickstart".to_string()],
        };

        assert_eq!(
            service_bootstrap_commands(&plan, true),
            vec![
                vec![
                    "launchctl".to_string(),
                    "bootout".to_string(),
                    "gui/501/net.ottto.service".to_string(),
                ],
                plan.enable_command,
                plan.bootstrap_command,
                plan.kickstart_command,
            ],
        );
    }
}
