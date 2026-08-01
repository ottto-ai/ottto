use anyhow::Result;
use clap::{Parser, Subcommand};
use ottto_core::{
    compiled_release_version, generate_control_token, load_or_create_control_token,
    FileAccountStore, FileConnectionStore, FileDeviceStore, FileMachineStore, LocalDeviceBinding,
    LocalMachineBinding, OTTTO_SERVICE_BINARY_NAME,
};
use ottto_protocol::{MachineIdentity, OperatingSystem};
use ottto_service::{current_rfc3339_timestamp, macos_service, ControlToken, LocalDaemon};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio};
use std::time::Duration;

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
    /// Print this machine's configured-MCP inventory (the always-on schema
    /// footprint) as JSON, WITHOUT uploading. List-only: runs `initialize` +
    /// `tools/list` against each configured server and never executes a tool.
    /// For local inspection and the cross-tool validation harness.
    McpInventory {
        /// `claude-code` or `codex`; omit to dump both as a JSON array.
        #[arg(long)]
        agent: Option<String>,
    },
    /// Print the Codex cloud-session collector state without invoking Codex.
    CloudSessionsStatus {
        #[arg(long)]
        json: bool,
    },
    /// Run the production local-session scanner and print a privacy-safe audit.
    SnapshotAudit {
        /// `codex`, `claude_code`, or `pi`.
        #[arg(long)]
        source: String,
        /// Source transcript root. Repeat for multiple roots.
        #[arg(long = "root", required = true)]
        roots: Vec<PathBuf>,
        /// Dedicated private audit-state directory; production index files are rejected.
        #[arg(long)]
        audit_state_dir: PathBuf,
        /// File containing at least 32 bytes used to blind audit identifiers.
        #[arg(long)]
        audit_key_file: PathBuf,
        /// Private file containing the exact URL-safe no-pad attribution HMAC key
        /// from the activity hint. Required to reconstruct every legacy policy.
        #[arg(long)]
        session_attribution_hmac_key_file: PathBuf,
        /// Home used to resolve local scheduler attribution inputs.
        #[arg(long)]
        attribution_home: Option<PathBuf>,
        /// Machine id used by the normal upload contract; never printed raw.
        #[arg(long)]
        machine_id: String,
        /// Deterministic collection timestamp. Defaults to the current time.
        #[arg(long)]
        collected_at: Option<String>,
        /// Requested lookback, capped by the production scanner.
        #[arg(long, default_value_t = ottto_service::snapshots::BACKFILL_WINDOW_DAYS)]
        backfill_window_days: u64,
        /// Optional private 0600 file containing the normal stripped upload payload.
        #[arg(long = "private-upload-payload-out")]
        private_upload_payload_out: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum ServiceCommand {
    /// Remove retired Ottto login items and LaunchAgents.
    CleanupLegacy {
        #[arg(long)]
        json: bool,
    },
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
    // This is a background service: it must never block on an interactive
    // keychain modal (e.g. "Keychain Not Found"). Disable Security UI for the
    // whole process up front so a transient keychain failure logs and retries
    // instead of stalling behind a dialog no user is present to answer.
    ottto_core::disable_keychain_user_interaction();

    let cli = Cli::parse();

    match cli.command.unwrap_or(Command::Status { json: true }) {
        Command::McpInventory { agent } => {
            let value = match agent.as_deref() {
                Some(agent) => ottto_service::mcp_inventory::dump_inventory(agent)?,
                None => ottto_service::mcp_inventory::dump_all_inventories()?,
            };
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
        Command::CloudSessionsStatus { json } => {
            let status = ottto_service::cloud_sessions::default_cloud_session_collector_status();
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!(
                    "cloud_sessions {} ({})",
                    serde_json::to_value(&status.runtime_state)?
                        .as_str()
                        .unwrap_or("unknown"),
                    status.reason_code
                );
            }
        }
        Command::SnapshotAudit {
            source,
            roots,
            audit_state_dir,
            audit_key_file,
            session_attribution_hmac_key_file,
            attribution_home,
            machine_id,
            collected_at,
            backfill_window_days,
            private_upload_payload_out,
        } => {
            let source = ottto_service::snapshot_audit::snapshot_source_from_slug(&source)?;
            let stdout = std::io::stdout();
            let mut output = stdout.lock();
            ottto_service::snapshot_audit::run_snapshot_audit(
                ottto_service::snapshot_audit::SnapshotAuditOptions {
                    source,
                    roots,
                    audit_state_dir,
                    audit_key_path: audit_key_file,
                    session_attribution_hmac_key_path: session_attribution_hmac_key_file,
                    attribution_home,
                    machine_id,
                    collected_at: collected_at
                        .unwrap_or_else(ottto_service::current_rfc3339_timestamp),
                    backfill_window_days,
                    private_upload_payload_out,
                },
                &mut output,
            )?;
        }
        Command::Status { json } => {
            let token = load_or_create_control_token()?;
            let daemon = LocalDaemon::new(
                local_machine(),
                ControlToken::new(token.clone())?,
                current_rfc3339_timestamp(),
            )
            .with_account(FileAccountStore::default().load()?)
            .with_connection(FileConnectionStore::default().load()?)
            .with_source_state_dir(ottto_core::default_sources_dir())
            .with_registered_device_sources(load_registered_device_sources());
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
                cleanup_legacy_services_at_startup();
                if ottto_service::control::recover_pending_device_credential_at_startup().is_err() {
                    eprintln!("pending relay credential recovery deferred");
                }
                let token = load_or_create_control_token()?;
                let daemon = LocalDaemon::new(
                    local_machine(),
                    ControlToken::new(token)?,
                    current_rfc3339_timestamp(),
                )
                .with_account(FileAccountStore::default().load()?)
                .with_connection(FileConnectionStore::default().load()?)
                .with_source_state_dir(ottto_core::default_sources_dir())
                .with_registered_device_sources(load_registered_device_sources());
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
            cleanup_legacy_services_at_startup();
            if ottto_service::control::recover_pending_device_credential_at_startup().is_err() {
                eprintln!("pending relay credential recovery deferred");
            }
            let token = load_or_create_control_token()?;
            let daemon = LocalDaemon::new(
                local_machine(),
                ControlToken::new(token)?,
                current_rfc3339_timestamp(),
            )
            .with_account(FileAccountStore::default().load()?)
            .with_connection(FileConnectionStore::default().load()?)
            .with_source_state_dir(ottto_core::default_sources_dir())
            .with_registered_device_sources(load_registered_device_sources());
            start_builtin_relays(&daemon);
            #[cfg(all(target_os = "macos", unix))]
            {
                let socket = socket.unwrap_or_else(ottto_core::default_socket_path);
                let socket_daemon = daemon.clone();
                let socket_for_thread = socket.clone();
                std::thread::spawn(move || loop {
                    match ottto_service::unix_socket::serve_unix_socket(
                        &socket_for_thread,
                        socket_daemon.clone(),
                    ) {
                        Ok(()) => eprintln!(
                            "debug socket listener {} exited; restarting",
                            socket_for_thread.display()
                        ),
                        Err(error) => eprintln!(
                            "debug socket listener {} stopped: {error}; restarting",
                            socket_for_thread.display()
                        ),
                    }
                    std::thread::sleep(Duration::from_secs(1));
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

fn load_registered_device_sources() -> Option<LocalDeviceBinding> {
    match FileDeviceStore::default().load() {
        Ok(device) => device,
        Err(error) => {
            eprintln!("warning: failed to load relay device source cache: {error:#}");
            None
        }
    }
}

fn handle_service_command(command: ServiceCommand) -> Result<()> {
    let home = home_dir()?;
    let (executable, write, execute, json, migrate_owner) = match command {
        ServiceCommand::CleanupLegacy { json } => {
            let report = ottto_service::legacy_service::cleanup_legacy_services(&home);
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            return Ok(());
        }
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
        // Install, repair, and app-update registration paths all pass here.
        // Remove the retired locald registration before touching the current
        // single-owner LaunchAgent.
        ottto_service::legacy_service::cleanup_legacy_services(&home);
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
            ServiceCommand::CleanupLegacy { json }
            | ServiceCommand::InstallPlan { json, .. }
            | ServiceCommand::WriteLaunchAgent { json, .. }
            | ServiceCommand::Bootstrap { json, .. } => *json,
        }
    }
}

#[cfg(target_os = "macos")]
fn cleanup_legacy_services_at_startup() {
    match home_dir() {
        Ok(home) => {
            ottto_service::legacy_service::cleanup_legacy_services(&home);
        }
        Err(error) => {
            eprintln!("legacy_service_cleanup unavailable: {error}");
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn cleanup_legacy_services_at_startup() {}

fn start_builtin_relays(daemon: &LocalDaemon) {
    // Proactively rebuild upstream HTTP pools on macOS network transitions so
    // pooled sockets bound to a dead local IP never stall uploads (2026-07-17).
    match ottto_service::net_transition::spawn_network_transition_observer() {
        Ok(()) => eprintln!("serving network transition observer"),
        Err(error) => eprintln!("network transition observer unavailable: {error}"),
    }
    match ottto_service::otlp_relay::spawn_local_otlp_relay(daemon.clone()) {
        Ok(addr) => eprintln!("serving local OTLP relay at http://{addr}"),
        Err(error) => eprintln!("local OTLP relay unavailable: {error}"),
    }
    match ottto_service::snapshot_sync::spawn_local_snapshot_sync(daemon.clone()) {
        Ok(()) => eprintln!("serving local snapshot sync"),
        Err(error) => eprintln!("local snapshot sync unavailable: {error}"),
    }
    match ottto_service::snapshot_sync::spawn_collector_checkin_heartbeat() {
        Ok(()) => eprintln!("serving collector check-in heartbeat"),
        Err(error) => eprintln!("collector check-in heartbeat unavailable: {error}"),
    }
    match ottto_service::mcp_inventory::spawn_mcp_inventory_sync() {
        Ok(()) => eprintln!("serving mcp inventory harvest"),
        Err(error) => eprintln!("mcp inventory harvest unavailable: {error}"),
    }
    match ottto_service::context_footprint::spawn_context_footprint_sync() {
        Ok(()) => eprintln!("serving context footprint harvest"),
        Err(error) => eprintln!("context footprint harvest unavailable: {error}"),
    }
    match ottto_service::context_composition::spawn_context_composition_sync() {
        Ok(()) => eprintln!("serving context composition harvest"),
        Err(error) => eprintln!("context composition harvest unavailable: {error}"),
    }
    match ottto_service::cloud_sessions::spawn_cloud_session_collector() {
        Ok(ottto_service::cloud_sessions::CloudSessionCollectorStartup::Started) => {
            eprintln!("serving Codex cloud-session collector")
        }
        Ok(ottto_service::cloud_sessions::CloudSessionCollectorStartup::DeferredTransport) => {
            eprintln!("Codex cloud-session collector deferred")
        }
        Err(error) => eprintln!("Codex cloud-session collector unavailable: {error}"),
    }
    match ottto_service::provider_daily_reference::spawn_codex_daily_aggregate_collector() {
        Ok(ottto_service::provider_daily_reference::CollectorStartup::Started) => {
            eprintln!("serving Codex daily aggregates collector")
        }
        Err(error) => eprintln!("Codex daily aggregates collector unavailable: {error}"),
    }
    match ottto_service::snapshot_sync::spawn_local_health_projection_sync(daemon.clone()) {
        Ok(()) => eprintln!("serving local health projection sync"),
        Err(error) => eprintln!("local health projection sync unavailable: {error}"),
    }
    // Reconfirm sources seeded `verifying` by the restart so they settle to real
    // health in seconds instead of dwelling until the next client poll/session.
    ottto_service::snapshot_sync::spawn_startup_source_reverify(daemon.clone());
    // Retry sources stuck in a blocking verification failure with exponential
    // backoff so transient smoke failures heal without a manual Verify.
    match ottto_service::snapshot_sync::spawn_failed_verification_reverify(daemon.clone()) {
        Ok(()) => eprintln!("serving failed-verification re-verify loop"),
        Err(error) => eprintln!("failed-verification re-verify loop unavailable: {error}"),
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
    let account_scope = local_account_scope(&binding.machine_id);
    MachineIdentity {
        machine_id: binding.machine_id,
        installation_id: binding.installation_id,
        hardware_uuid: binding.hardware_uuid,
        account_scope,
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
    prefixed_sha256_id("otm", seed)
}

/// Privacy-safe discriminator for the OS account this install runs under; see
/// `MachineIdentity::account_scope` for the contract. Derived from the POSIX
/// uid on every call, so it survives daemon restarts and reinstalls without
/// persisting anything about the account.
fn local_account_scope(machine_id: &str) -> Option<String> {
    account_scope_from_uid(machine_id, current_account_uid())
}

/// Hash-only half of `local_account_scope`, split out so tests can pin the
/// stability and distinctness guarantees without depending on whichever account
/// runs them. The uid is digest input only; it never appears in the output, and
/// neither does the username, the home directory, nor any path.
fn account_scope_from_uid(machine_id: &str, uid: Option<u32>) -> Option<String> {
    let uid = uid?;
    Some(prefixed_sha256_id(
        "otu",
        &format!("account:{machine_id}:{uid}"),
    ))
}

/// The POSIX uid the daemon runs as. `getuid` cannot fail on unix. Non-unix
/// targets have no POSIX uid, so they report `None` instead of a placeholder
/// that would collapse distinct accounts onto one scope.
fn current_account_uid() -> Option<u32> {
    #[cfg(unix)]
    {
        // `libc::uid_t` is `u32` on every supported unix target.
        Some(unsafe { libc::getuid() })
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// `<prefix>_` + the first 32 hex characters of the seed's SHA-256 digest. The
/// shared shape behind `machine_id` (`otm_`) and `account_scope` (`otu_`); each
/// caller owns its own prefix so the two can never be confused for each other
/// or for the randomly minted `installation_id` (`oti_`).
fn prefixed_sha256_id(prefix: &str, seed: &str) -> String {
    let digest = Sha256::digest(seed.as_bytes());
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{prefix}_{}", &hex[..32])
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
    use std::ffi::OsString;
    use std::fs;

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
        assert_eq!(commands.len(), 2);
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
            ],
        );
    }

    /// Fixed derivation vectors for `account_scope`. Recomputed from
    /// `sha256("account:<machine_id>:<uid>")`, so a change here is a change to
    /// the wire contract: the backend keys sibling installs off these values,
    /// and re-deriving them differently would orphan every existing install.
    const ALPHA_UID_501: &str = "otu_d8b0c573acd0c2b5f822065edfd4ec58";
    const ALPHA_UID_502: &str = "otu_2bc221830d52dafb982c36c3450123b8";
    const BETA_UID_501: &str = "otu_94a43be990de1c2d7e47cfc8b23bb612";

    #[test]
    fn account_scope_is_identical_for_the_same_account_on_the_same_machine() {
        // Two independent computations with nothing persisted in between: this
        // is the "survives daemon restarts and reinstalls" guarantee, since a
        // reinstall re-derives `machine_id` from the same IOPlatformUUID.
        let first = account_scope_from_uid("otm_machine_alpha", Some(501));
        let second = account_scope_from_uid("otm_machine_alpha", Some(501));

        assert_eq!(first, second);
        assert_eq!(first.as_deref(), Some(ALPHA_UID_501));
    }

    #[test]
    fn account_scope_differs_between_accounts_on_one_machine() {
        // The whole point of the field: two macOS user accounts on one Mac share
        // a `machine_id` but must not share an `account_scope`.
        assert_ne!(ALPHA_UID_501, ALPHA_UID_502);
        assert_eq!(
            account_scope_from_uid("otm_machine_alpha", Some(502)).as_deref(),
            Some(ALPHA_UID_502)
        );
    }

    #[test]
    fn account_scope_differs_for_the_same_account_on_another_machine() {
        assert_ne!(ALPHA_UID_501, BETA_UID_501);
        assert_eq!(
            account_scope_from_uid("otm_machine_beta", Some(501)).as_deref(),
            Some(BETA_UID_501)
        );
    }

    #[test]
    fn account_scope_is_a_bare_prefixed_digest() {
        let scope = account_scope_from_uid("otm_machine_alpha", Some(501)).expect("scope");
        let digest = scope.strip_prefix("otu_").expect("otu_ prefix");

        assert_eq!(scope.len(), 36);
        assert_eq!(digest.len(), 32);
        assert!(digest
            .chars()
            .all(|ch| ch.is_ascii_digit() || matches!(ch, 'a'..='f')));
        // Nothing but the digest is emitted: no uid, no seed material, no path.
        assert!(!scope.contains("501"));
        assert!(!scope.contains("machine_alpha"));
        assert!(!scope.contains('/'));
    }

    #[test]
    fn account_scope_never_collides_with_the_machine_id_namespace() {
        let scope = account_scope_from_uid("otm_machine_alpha", Some(501)).expect("scope");
        let machine_style = stable_machine_id_from_seed("account:otm_machine_alpha:501");

        assert!(scope.starts_with("otu_"));
        assert!(machine_style.starts_with("otm_"));
        assert_ne!(scope, machine_style);
    }

    #[test]
    fn account_scope_is_absent_when_no_posix_uid_is_available() {
        assert_eq!(account_scope_from_uid("otm_machine_alpha", None), None);
    }

    #[test]
    fn local_account_scope_leaks_no_account_identifying_text() {
        let Some(scope) = local_account_scope("otm_machine_alpha") else {
            // Non-unix targets have no POSIX uid; `None` is the correct answer.
            assert!(current_account_uid().is_none());
            return;
        };

        assert!(scope.starts_with("otu_"));
        assert_eq!(scope.len(), 36);
        assert!(scope[4..]
            .chars()
            .all(|ch| ch.is_ascii_digit() || matches!(ch, 'a'..='f')));
        for key in ["USER", "LOGNAME", "HOME"] {
            let value = std::env::var(key).unwrap_or_default();
            if value.len() >= 3 {
                assert!(
                    !scope.contains(&value),
                    "account scope must not carry ${key}"
                );
            }
        }
    }

    #[test]
    fn malformed_registered_device_cache_is_ignored() {
        let root = std::env::temp_dir().join(format!(
            "ottto-service-device-cache-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create support dir");
        fs::write(root.join("device.json"), b"{not valid json").expect("write invalid device");
        let _guard = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);

        assert_eq!(load_registered_device_sources(), None);

        let _ = fs::remove_dir_all(&root);
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set_path(key: &'static str, value: &std::path::Path) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }
}
