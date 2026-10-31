//! Claude Code `/context` footprint harvest.
//!
//! This is a low-cadence, per-workspace collector for the static context
//! footprint Claude Code reports from `/context`: category totals plus memory
//! files, skills, custom agents, and a bounded sample of MCP tool token costs.
//! It is intentionally separate from
//! `AgentContextStatus`/`context_live`, which reflects active session load from
//! statusLine `context_window`.

use crate::context_file_counts::{load_or_create_salt, measure_file, FileCounts};
use crate::instruction_inventory::{
    build_instruction_inventory, default_login_claude_mode, InstructionInventory, InventoryPaths,
};
use crate::snapshot_client::{
    load_snapshot_device_credentials, workspace_labels_allowed, ActivityHintResponse,
    SnapshotApiClient,
};
use crate::snapshots::line_delivery::{
    DeliveryEnd, DeliveryMode, FileView, LineObserver, PhysicalLine, Want,
};
use crate::snapshots::SnapshotSource;
use crate::transcript_acquisition::FileObject;
use anyhow::{anyhow, Result};
use ottto_core::{compiled_release_version, default_support_dir, LocalDeviceBinding};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const CONTEXT_FOOTPRINT_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const CONTEXT_COMMAND_TIMEOUT_SECS: u64 = 25;
const CONTEXT_MCP_COMMAND_TIMEOUT_SECS: u64 = 120;
const CONTEXT_COMMAND_TIMEOUT: Duration = Duration::from_secs(CONTEXT_COMMAND_TIMEOUT_SECS);
const CONTEXT_MCP_COMMAND_TIMEOUT: Duration = Duration::from_secs(CONTEXT_MCP_COMMAND_TIMEOUT_SECS);
const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
const GIT_STDOUT_MAX_BYTES: usize = 1024 * 1024;
const CONTEXT_MAX_STALENESS_SECS: i64 = 7 * 24 * 60 * 60;
const RECENT_WORKSPACE_WINDOW: Duration = Duration::from_secs(14 * 24 * 60 * 60);
const MAX_WORKSPACES_PER_CYCLE: usize = 12;
const MAX_MCP_TOOLS_PER_CAPTURE: usize = 500;
// One MCP-enabled capture may use its full cold-start allowance while every
// other workspace uses the existing strict allowance. Thirty seconds covers
// bounded git identity checks and uploads without pretending all 12 commands
// still fit inside the old five-minute budget.
const CONTEXT_CYCLE_BUDGET: Duration = Duration::from_secs(
    CONTEXT_MCP_COMMAND_TIMEOUT_SECS
        + ((MAX_WORKSPACES_PER_CYCLE as u64 - 1) * CONTEXT_COMMAND_TIMEOUT_SECS)
        + 30,
);

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct ContextFootprintCategoryInput {
    pub(crate) name: String,
    pub(crate) tokens: u64,
    pub(crate) pct: f64,
    pub(crate) loading_mode: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct ContextFootprintItemInput {
    pub(crate) kind: String,
    pub(crate) name: String,
    pub(crate) tokens: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) relative_path: Option<String>,
    pub(crate) loading_mode: String,
    #[serde(flatten)]
    pub(crate) file_counts: FileCounts,
    // Preserve the original /context path only until measurement. Never upload it.
    #[serde(skip)]
    pub(crate) local_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct ContextFootprintMcpToolInput {
    name: String,
    server: String,
    tokens: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct ContextFootprintIngestRequest {
    pub(crate) agent_source: String,
    pub(crate) machine_id: String,
    pub(crate) workspace_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) workspace_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) workspace_label_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) repository_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) repository_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) repository_label_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) repository_identity_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) workspace_kind: Option<String>,
    pub(crate) config_hash: String,
    pub(crate) captured_at: String,
    pub(crate) collector_version: String,
    pub(crate) counter_source: String,
    pub(crate) model: String,
    pub(crate) used_tokens: u64,
    pub(crate) context_window_tokens: u64,
    pub(crate) pct_context: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) free_space_tokens: Option<u64>,
    pub(crate) categories: Vec<ContextFootprintCategoryInput>,
    pub(crate) memory_files: Vec<ContextFootprintItemInput>,
    pub(crate) skills: Vec<ContextFootprintItemInput>,
    pub(crate) custom_agents: Vec<ContextFootprintItemInput>,
    pub(crate) mcp_tools: Vec<ContextFootprintMcpToolInput>,
    /// Claude Code only; see `instruction_inventory`. Absent means unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) instruction_inventory: Option<InstructionInventory>,
}

#[derive(Debug, Clone, PartialEq)]
struct ParsedContextFootprint {
    model: String,
    used_tokens: u64,
    context_window_tokens: u64,
    pct_context: f64,
    free_space_tokens: Option<u64>,
    categories: Vec<ContextFootprintCategoryInput>,
    memory_files: Vec<ContextFootprintItemInput>,
    skills: Vec<ContextFootprintItemInput>,
    custom_agents: Vec<ContextFootprintItemInput>,
    mcp_tools: Vec<ContextFootprintMcpToolInput>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkspaceCandidate {
    path: PathBuf,
    last_seen: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepositoryIdentity {
    pub(crate) repository_hash: Option<String>,
    pub(crate) repository_label: Option<String>,
    pub(crate) repository_label_source: Option<String>,
    pub(crate) repository_identity_source: Option<String>,
    pub(crate) workspace_kind: Option<String>,
}

#[derive(Clone)]
struct SpawnEnv {
    path: Option<OsString>,
    provider: BTreeMap<String, OsString>,
}

impl SpawnEnv {
    fn resolve() -> Self {
        Self {
            path: crate::command_env::path_env(),
            provider: crate::command_env::provider_env(),
        }
    }

    fn claude_command(&self) -> Result<Command> {
        let Some(program) = crate::command_env::executable_path("claude") else {
            return Err(anyhow!("Claude Code CLI was not found"));
        };
        let mut command = Command::new(program);
        if let Some(path) = self.path.as_ref() {
            command.env("PATH", path);
        }
        for (key, value) in &self.provider {
            command.env(key, value);
        }
        Ok(command)
    }
}

/// The quiet window refused a `/context` run: the default login is within 15
/// minutes of its access token's expiry (or expired) and not yet refreshed.
#[derive(Debug)]
struct ClaudeContextRefused(crate::claude_spawn_gate::ClaudeSpawnRefusal);

impl std::fmt::Display for ClaudeContextRefused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Claude Code /context was not started: {}",
            self.0.code()
        )
    }
}

impl std::error::Error for ClaudeContextRefused {}

/// A `/context` run whose process never started: not a provider call.
#[cfg(unix)]
#[derive(Debug)]
struct ClaudeContextNotStarted(&'static str);

#[cfg(unix)]
impl std::fmt::Display for ClaudeContextNotStarted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

#[cfg(unix)]
impl std::error::Error for ClaudeContextNotStarted {}

/// After a refusal the next cycle starts sooner, once the login is refreshed.
const CONTEXT_REFUSED_RETRY_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// One harvest cycle's outcome: how many workspaces the quiet window skipped.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ContextHarvestOutcome {
    refused: usize,
}

fn next_context_cycle_delay(refused: bool) -> Duration {
    if refused {
        CONTEXT_REFUSED_RETRY_INTERVAL
    } else {
        CONTEXT_FOOTPRINT_INTERVAL
    }
}

/// Workspaces come from `daemon`'s projection of snapshot sync's Claude reads.
pub fn spawn_context_footprint_sync(daemon: &crate::LocalDaemon) -> Result<()> {
    let home = crate::snapshot_sync::home_dir()?;
    let support_dir = default_support_dir();
    let projection = Arc::clone(&daemon.footprint_cwds);
    let codex_preludes = Arc::clone(&daemon.codex_preludes);
    std::thread::Builder::new()
        .name("ottto-context-footprint-sync".to_string())
        .spawn(move || loop {
            let refused = match harvest_all_once(&home, &support_dir, &projection) {
                Ok(outcome) => outcome.refused > 0,
                Err(error) => {
                    eprintln!(
                        "context footprint harvest skipped: {}",
                        crate::snapshot_sync::safe_error(&error)
                    );
                    false
                }
            };
            // Codex session starts share this thread: no extra background job.
            if let Err(error) =
                crate::codex_prelude_footprint::harvest_once(&home, &support_dir, &codex_preludes)
            {
                eprintln!(
                    "codex session start harvest skipped: {}",
                    crate::snapshot_sync::safe_error(&error)
                );
            }
            std::thread::sleep(next_context_cycle_delay(refused));
        })
        .map_err(|error| anyhow!("spawn context footprint sync: {error}"))?;
    Ok(())
}

fn harvest_all_once(
    home: &Path,
    support_dir: &Path,
    projection: &CwdProjection,
) -> Result<ContextHarvestOutcome> {
    if local_harvest_disabled(support_dir) {
        return Ok(ContextHarvestOutcome::default());
    }
    let (device, device_secret) = load_snapshot_device_credentials()?;
    if !crate::snapshot_sync::enabled_snapshot_sources(&device)
        .into_iter()
        .any(|source| matches!(source, SnapshotSource::ClaudeCode))
    {
        return Ok(ContextHarvestOutcome::default());
    }
    let Some(machine_id) = crate::snapshot_sync::snapshot_machine_id(&device)? else {
        return Err(anyhow!("machine identity is missing"));
    };
    let api_base_url = crate::snapshot_sync::snapshot_api_base_url()?;
    let client = SnapshotApiClient::new(api_base_url.clone());
    harvest_source(
        &client,
        &device,
        &device_secret,
        &machine_id,
        &api_base_url,
        home,
        support_dir,
        projection,
    )
}

#[allow(clippy::too_many_arguments)]
fn harvest_source(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    machine_id: &str,
    api_base_url: &str,
    home: &Path,
    support_dir: &Path,
    projection: &CwdProjection,
) -> Result<ContextHarvestOutcome> {
    let relay_token =
        client.issue_relay_token(device, device_secret, SnapshotSource::ClaudeCode)?;
    let identity = destination_identity(device, machine_id, api_base_url);
    let marker = org_disabled_marker_path(support_dir);
    match client.get_activity_hint(&relay_token) {
        Ok(hint) => {
            let workspace_labels_enabled = workspace_labels_allowed(Some(&hint));
            if !hint.context_footprint_harvest_enabled {
                write_marker(&marker, &identity);
                return Ok(ContextHarvestOutcome::default());
            }
            let _ = fs::remove_file(&marker);
            return harvest_recent_workspaces(
                client,
                &relay_token,
                support_dir,
                &identity,
                home,
                machine_id,
                workspace_labels_enabled,
                inventory_paths(Some(&hint)),
                projection,
            );
        }
        Err(_) if read_marker(&marker).as_deref() == Some(identity.as_str()) => {
            return Ok(ContextHarvestOutcome::default())
        }
        Err(_) => {}
    }

    harvest_recent_workspaces(
        client,
        &relay_token,
        support_dir,
        &identity,
        home,
        machine_id,
        workspace_labels_allowed(None),
        inventory_paths(None),
        projection,
    )
}

/// Instruction paths leave the machine only when the hint explicitly sent
/// `workspace_labels_enabled: true`. Without a hint, or without that field,
/// the policy is unknown, so no inventory block is built at all.
fn inventory_paths(hint: Option<&ActivityHintResponse>) -> Option<InventoryPaths> {
    match hint?.workspace_labels_explicit? {
        true => Some(InventoryPaths::Collect),
        false => Some(InventoryPaths::Withhold),
    }
}

#[allow(clippy::too_many_arguments)]
fn harvest_recent_workspaces(
    client: &SnapshotApiClient,
    relay_token: &str,
    support_dir: &Path,
    identity: &str,
    home: &Path,
    machine_id: &str,
    workspace_labels_enabled: bool,
    inventory_paths: Option<InventoryPaths>,
    projection: &CwdProjection,
) -> Result<ContextHarvestOutcome> {
    let now = SystemTime::now();
    let mut path_scopes = 0;
    let cwds = projection.recent_cwds(now);
    let mut workspaces = discover_workspaces(cwds, &mut path_scopes, repository_scope);
    workspaces.truncate(MAX_WORKSPACES_PER_CYCLE);
    if workspaces.is_empty() {
        eprintln!(
            "context_footprint_harvest_metrics discovered=0 uploaded=0 skipped=0 failed=0 discovery_path_scopes={path_scopes} {}",
            projection.metrics()
        );
        return Ok(ContextHarvestOutcome::default());
    }

    let env = SpawnEnv::resolve();
    let salt = load_or_create_salt(support_dir);
    let deadline = Instant::now() + CONTEXT_CYCLE_BUDGET;
    let mut uploaded = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;
    let mut refused = 0usize;
    for (workspace_index, workspace) in workspaces.into_iter().enumerate() {
        if Instant::now() >= deadline {
            break;
        }
        // Discovery is sorted newest-first, so index zero is the deterministic
        // most-recently-active workspace selected for the cycle's sole MCP run.
        let include_mcp_servers = should_include_mcp_servers(workspace_index);
        match build_request_for_workspace(
            &workspace.path,
            machine_id,
            &env,
            workspace_labels_enabled,
            inventory_paths,
            include_mcp_servers,
            home,
            salt.as_ref(),
        ) {
            Ok(request) => {
                match upload_if_changed(client, relay_token, support_dir, identity, &request) {
                    Ok(true) => uploaded += 1,
                    Ok(false) => skipped += 1,
                    Err(error) => {
                        failed += 1;
                        eprintln!(
                            "context footprint upload skipped for workspace_hash={}: {}",
                            request.workspace_hash,
                            crate::snapshot_sync::safe_error(&error)
                        );
                    }
                }
            }
            Err(error) if error.downcast_ref::<ClaudeContextRefused>().is_some() => {
                refused += 1;
            }
            Err(error) => {
                failed += 1;
                eprintln!(
                    "context footprint harvest skipped for a workspace: {}",
                    crate::snapshot_sync::safe_error(&error)
                );
            }
        }
    }
    eprintln!(
        "context_footprint_harvest_metrics discovered={} uploaded={} skipped={} failed={} discovery_path_scopes={} {}",
        uploaded + skipped + failed,
        uploaded,
        skipped,
        failed,
        path_scopes,
        projection.metrics()
    );
    if failed > 0 && uploaded == 0 && skipped == 0 {
        return Err(anyhow!(
            "context footprint harvest failed for all workspaces"
        ));
    }
    Ok(ContextHarvestOutcome { refused })
}

fn should_include_mcp_servers(workspace_index: usize) -> bool {
    workspace_index == 0
}

#[allow(clippy::too_many_arguments)]
fn build_request_for_workspace(
    workspace: &Path,
    machine_id: &str,
    env: &SpawnEnv,
    workspace_labels_enabled: bool,
    inventory_paths: Option<InventoryPaths>,
    include_mcp_servers: bool,
    home: &Path,
    salt: Option<&[u8; 32]>,
) -> Result<ContextFootprintIngestRequest> {
    let stdout = run_claude_context(workspace, env, include_mcp_servers)?;
    let value: Value = serde_json::from_str(&stdout)
        .map_err(|_| anyhow!("Claude Code /context JSON was invalid"))?;
    if value
        .get("is_error")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err(anyhow!("Claude Code /context returned an error"));
    }
    let result = value
        .get("result")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Claude Code /context result was missing"))?;
    let fallback_model = value.get("model").and_then(Value::as_str);
    let mut parsed = parse_context_markdown(result)?;
    if parsed.model.is_empty() {
        parsed.model = fallback_model.unwrap_or("unknown").to_string();
    }
    let workspace_text = workspace.to_string_lossy();
    let workspace_hash = sha256_hex(&[workspace_text.as_ref()]);
    let repository_identity = resolve_repository_identity(workspace, workspace_labels_enabled);
    let observed = measure_memory_files(&mut parsed, workspace, home, salt);
    let instruction_inventory = inventory_paths.and_then(|paths| {
        build_instruction_inventory(workspace, &observed, default_login_claude_mode(home), paths)
    });
    let config_hash = request_content_hash(&parsed)?;
    Ok(ContextFootprintIngestRequest {
        agent_source: "claude-code".to_string(),
        machine_id: machine_id.to_string(),
        workspace_hash,
        workspace_label: workspace_labels_enabled
            .then(|| workspace_label(workspace))
            .flatten(),
        workspace_label_source: workspace_labels_enabled.then(|| "directory_name".to_string()),
        repository_hash: repository_identity.repository_hash,
        repository_label: repository_identity.repository_label,
        repository_label_source: repository_identity.repository_label_source,
        repository_identity_source: repository_identity.repository_identity_source,
        workspace_kind: repository_identity.workspace_kind,
        config_hash,
        captured_at: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()),
        collector_version: compiled_release_version(),
        counter_source: "claude_code_context_v1".to_string(),
        model: parsed.model,
        used_tokens: parsed.used_tokens,
        context_window_tokens: parsed.context_window_tokens,
        pct_context: parsed.pct_context,
        free_space_tokens: parsed.free_space_tokens,
        categories: parsed.categories,
        memory_files: parsed.memory_files,
        skills: parsed.skills,
        custom_agents: parsed.custom_agents,
        mcp_tools: parsed.mcp_tools,
        instruction_inventory,
    })
}

fn run_claude_context(
    workspace: &Path,
    env: &SpawnEnv,
    include_mcp_servers: bool,
) -> Result<String> {
    // Quiet window: never start Claude Code from 15 minutes before the
    // default login's access expiry until the refresher confirmed a new one.
    let login = ottto_core::ClaudeConfigDirSlot::Default;
    crate::claude_spawn_gate::check_short_claude_run(&login)
        .map_err(|refusal| anyhow::Error::new(ClaudeContextRefused(refusal)))?;
    let mut command = env.claude_command()?;
    crate::claude_spawn_gate::pin_claude_login(&mut command, &login);
    command
        .current_dir(workspace)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let command_timeout = configure_claude_context_command(&mut command, include_mcp_servers);
    #[cfg(unix)]
    {
        let started = Instant::now();
        let result = capture_claude_context(command, &login, command_timeout);
        record_claude_context_run(&result, &login, started);
        result
    }
    #[cfg(not(unix))]
    {
        let mut child = command
            .spawn()
            .map_err(|_| anyhow!("Claude Code /context could not be started"))?;
        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    let output = child
                        .wait_with_output()
                        .map_err(|_| anyhow!("Claude Code /context output could not be read"))?;
                    if !output.status.success() {
                        return Err(anyhow!("Claude Code /context exited unsuccessfully"));
                    }
                    return String::from_utf8(output.stdout)
                        .map_err(|_| anyhow!("Claude Code /context stdout was not UTF-8"));
                }
                Ok(None) if started.elapsed() >= command_timeout => {
                    crate::claude_spawn_gate::stop_claude_child(child, &login, "context");
                    return Err(anyhow!("Claude Code /context timed out"));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                Err(_) => return Err(anyhow!("Claude Code /context status could not be read")),
            }
        }
    }
}

/// One provider-call log line per `/context` run that started. `/context`
/// itself is local, but Claude Code may contact Anthropic while starting:
/// counted as at least zero requests.
#[cfg(unix)]
fn record_claude_context_run(
    result: &Result<String>,
    login: &ottto_core::ClaudeConfigDirSlot,
    started: Instant,
) {
    use crate::provider_calls::{CallKind, CallResult, Provider, ProviderCall, Trigger};
    let result = match result {
        Ok(_) => CallResult::Ok,
        Err(error)
            if error.downcast_ref::<ClaudeContextRefused>().is_some()
                || error.downcast_ref::<ClaudeContextNotStarted>().is_some() =>
        {
            return
        }
        Err(error) if error.to_string().ends_with("timed out") => CallResult::Timeout,
        Err(error) if error.to_string().ends_with("exited unsuccessfully") => {
            CallResult::Error("exited")
        }
        Err(_) => CallResult::Error("error"),
    };
    crate::provider_calls::record(ProviderCall::subprocess(
        Provider::Anthropic,
        CallKind::ClaudeContextProbe,
        crate::provider_calls::trigger_or(Trigger::Schedule),
        crate::provider_calls::claude_slot_account_hash(login).as_deref(),
        result,
        started.elapsed(),
        0,
    ));
}

#[cfg(unix)]
fn capture_claude_context(
    command: Command,
    login: &ottto_core::ClaudeConfigDirSlot,
    timeout: Duration,
) -> Result<String> {
    use crate::claude_spawn_gate::probe::{check_deadline, ChildProbe, Origin, Reader, StartError};
    use std::io::Read;
    let deadline = Instant::now() + timeout;
    let mut child =
        ChildProbe::spawn(command, Some(login), Origin::Context, deadline).map_err(|error| {
            match error {
                StartError::Refused(refusal) => anyhow::Error::new(ClaudeContextRefused(refusal)),
                StartError::Io(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                    anyhow::Error::new(ClaudeContextNotStarted("Claude Code /context timed out"))
                }
                StartError::Io(_) => anyhow::Error::new(ClaudeContextNotStarted(
                    "Claude Code /context could not be started",
                )),
            }
        })?;
    // Accepted output remains complete and uncapped. Drain concurrently with
    // execution; only the cleanup owner's discard scratch has a fixed size.
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut eof = false;
    loop {
        check_deadline(deadline).map_err(|_| anyhow!("Claude Code /context timed out"))?;
        let status = child
            .try_wait()
            .map_err(|_| anyhow!("Claude Code /context status could not be read"))?;
        if !eof {
            match Reader(child.stdout(), deadline).read(&mut buffer) {
                Ok(0) => eof = true,
                Ok(read) => bytes.extend_from_slice(&buffer[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                    return Err(anyhow!("Claude Code /context timed out"))
                }
                Err(_) => return Err(anyhow!("Claude Code /context output could not be read")),
            }
        }
        if let Some(status) = status.filter(|_| eof) {
            child.finish(deadline);
            if !status.success() {
                return Err(anyhow!("Claude Code /context exited unsuccessfully"));
            }
            return String::from_utf8(bytes)
                .map_err(|_| anyhow!("Claude Code /context stdout was not UTF-8"));
        }
        if eof {
            std::thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(50)),
            );
        }
    }
}

fn configure_claude_context_command(command: &mut Command, include_mcp_servers: bool) -> Duration {
    command.args(["-p", "/context", "--output-format", "json"]);
    if !include_mcp_servers {
        // Keep strict mode everywhere except the single sampled workspace.
        // Dropping it globally would double-count MCP across the context and
        // inventory spines, multiply unattended user-server spawns by 12 per
        // cycle, and put every capture behind a timeout one cold server blows.
        command.arg("--strict-mcp-config");
    }
    if include_mcp_servers {
        CONTEXT_MCP_COMMAND_TIMEOUT
    } else {
        CONTEXT_COMMAND_TIMEOUT
    }
}

pub(crate) fn resolve_repository_identity(
    workspace: &Path,
    labels_enabled: bool,
) -> RepositoryIdentity {
    let Some(toplevel) = git_toplevel(workspace) else {
        return RepositoryIdentity {
            repository_hash: None,
            repository_label: None,
            repository_label_source: None,
            repository_identity_source: None,
            workspace_kind: Some("non_git".to_string()),
        };
    };
    let Some(common_dir_raw) = git_stdout(workspace, &["rev-parse", "--git-common-dir"]) else {
        return RepositoryIdentity {
            repository_hash: None,
            repository_label: labels_enabled
                .then(|| toplevel.file_name()?.to_str())
                .flatten()
                .and_then(|name| safe_text(name, 255)),
            repository_label_source: labels_enabled.then(|| "git_root".to_string()),
            repository_identity_source: None,
            workspace_kind: Some("unknown".to_string()),
        };
    };
    let common_dir = absolutize_git_path(workspace, &common_dir_raw);
    let git_dir = git_stdout(workspace, &["rev-parse", "--git-dir"])
        .map(|raw| absolutize_git_path(workspace, &raw));
    let common_text = common_dir.to_string_lossy();
    let linked_worktree = git_dir
        .as_ref()
        .map(|git_dir| canonical_or_self(git_dir) != canonical_or_self(&common_dir))
        .unwrap_or(false);
    let workspace_kind = if linked_worktree {
        "linked_worktree"
    } else if same_path(workspace, &toplevel) {
        "repository_root"
    } else {
        "repository_subdir"
    };
    // For linked worktrees, `--show-toplevel` is the throwaway worktree
    // directory, so labels would surface names like "gallant-albattani-9baa0b".
    // Use the main checkout directory (the parent of the shared `.git` common
    // dir) instead, falling back to the toplevel for layouts where the common
    // dir does not end in `.git` (e.g. bare-ish repositories).
    let label_basis: &Path = if linked_worktree {
        main_checkout_dir(&common_dir).unwrap_or(&toplevel)
    } else {
        &toplevel
    };
    RepositoryIdentity {
        repository_hash: Some(sha256_hex(&[common_text.as_ref()])),
        repository_label: labels_enabled
            .then(|| label_basis.file_name()?.to_str())
            .flatten()
            .and_then(|name| safe_text(name, 255)),
        repository_label_source: labels_enabled.then(|| "git_root".to_string()),
        repository_identity_source: Some(
            if linked_worktree {
                "git_worktree"
            } else {
                "git_common_dir"
            }
            .to_string(),
        ),
        workspace_kind: Some(workspace_kind.to_string()),
    }
}

/// The main checkout folder of the repository holding `workspace` (the
/// parent of its shared `.git` folder), else the workspace's top level for
/// layouts without one. `None` outside git.
pub(crate) fn repository_main_checkout(workspace: &Path) -> Option<PathBuf> {
    let toplevel = git_stdout(workspace, &["rev-parse", "--show-toplevel"])?;
    let toplevel = absolutize_git_path(workspace, &toplevel);
    let Some(common_dir) = git_stdout(workspace, &["rev-parse", "--git-common-dir"]) else {
        return Some(toplevel);
    };
    let common_dir = absolutize_git_path(workspace, &common_dir);
    Some(
        main_checkout_dir(&common_dir)
            .map(Path::to_path_buf)
            .unwrap_or(toplevel),
    )
}

pub(crate) fn git_toplevel(workspace: &Path) -> Option<PathBuf> {
    git_stdout(workspace, &["rev-parse", "--show-toplevel"])
        .map(|raw| absolutize_git_path(workspace, &raw))
}

fn git_stdout(workspace: &Path, args: &[&str]) -> Option<String> {
    let bytes = git_stdout_capped(workspace, args, GIT_STDOUT_MAX_BYTES).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.chars().take(4096).collect())
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GitOutputError {
    Failed,
    TooLarge,
    TimedOut,
}

/// Successful git stdout, read while git runs so output over the pipe buffer
/// cannot stall it. Reading stops past `max_bytes` (git then gets SIGPIPE).
/// On timeout the child is killed and reaped; a reader still held open by a
/// descendant is left to finish on its own thread.
pub(crate) fn git_stdout_capped(
    dir: &Path,
    args: &[&str],
    max_bytes: usize,
) -> Result<Vec<u8>, GitOutputError> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| GitOutputError::Failed)?;
    let deadline = Instant::now() + GIT_COMMAND_TIMEOUT;
    fn stop(
        mut child: std::process::Child,
        error: GitOutputError,
    ) -> Result<Vec<u8>, GitOutputError> {
        let _ = child.kill();
        let _ = child.wait();
        Err(error)
    }
    let Some(stdout) = child.stdout.take() else {
        return stop(child, GitOutputError::Failed);
    };
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let spawned = std::thread::Builder::new()
        .name("ottto-git-stdout".to_string())
        .spawn(move || {
            let mut bytes = Vec::new();
            let read = stdout
                .take(max_bytes as u64 + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = sender.send(read);
        });
    if spawned.is_err() {
        return stop(child, GitOutputError::Failed);
    }
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => return stop(child, GitOutputError::TimedOut),
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => return stop(child, GitOutputError::Failed),
        }
    };
    let bytes = match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => return Err(GitOutputError::Failed),
        Err(_) => return Err(GitOutputError::TimedOut),
    };
    if bytes.len() > max_bytes {
        return Err(GitOutputError::TooLarge);
    }
    if !status.success() {
        return Err(GitOutputError::Failed);
    }
    Ok(bytes)
}

/// The directory holding the main checkout of a repository whose shared git
/// common dir is `common_dir`. For the standard layout the common dir is
/// `<main-checkout>/.git`, so this is its parent. Returns `None` when the
/// common dir does not end in `.git` (bare or unusual layouts), signalling the
/// caller to fall back to the workspace toplevel.
fn main_checkout_dir(common_dir: &Path) -> Option<&Path> {
    (common_dir.file_name()? == ".git")
        .then(|| common_dir.parent())
        .flatten()
}

fn absolutize_git_path(workspace: &Path, raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    let absolute = if path.is_absolute() {
        path
    } else {
        workspace.join(path)
    };
    canonical_or_self(&absolute)
}

fn canonical_or_self(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn same_path(left: &Path, right: &Path) -> bool {
    canonical_or_self(left) == canonical_or_self(right)
}

fn parse_context_markdown(markdown: &str) -> Result<ParsedContextFootprint> {
    let mut model = String::new();
    let mut used_tokens = None;
    let mut context_window_tokens = None;
    let mut pct_context = None;
    let mut categories = Vec::new();
    let mut memory_files = Vec::new();
    let mut skills = Vec::new();
    let mut custom_agents = Vec::new();
    let mut mcp_tools = Vec::new();
    let mut section = String::new();

    for line in markdown.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("**Model:**") {
            model = clean_inline_markup(rest).unwrap_or_default();
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("**Tokens:**") {
            if let Some((used, max, pct)) = parse_tokens_headline(rest) {
                used_tokens = Some(used);
                context_window_tokens = Some(max);
                pct_context = Some(pct);
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("### ") {
            section = rest.trim().to_ascii_lowercase();
            continue;
        }
        if !trimmed.starts_with('|') {
            continue;
        }
        let cells = markdown_cells(trimmed);
        if cells.is_empty() || is_separator_row(&cells) || is_header_row(&cells) {
            continue;
        }
        match section.as_str() {
            "estimated usage by category" => {
                if let Some(category) = parse_category_row(&cells) {
                    categories.push(category);
                }
            }
            "memory files" => {
                if let Some(item) = parse_memory_file_row(&cells) {
                    memory_files.push(item);
                }
            }
            "skills" => {
                if let Some(item) = parse_named_item_row(&cells, "skill") {
                    skills.push(item);
                }
            }
            "custom agents" => {
                if let Some(item) = parse_named_item_row(&cells, "custom_agent") {
                    custom_agents.push(item);
                }
            }
            "mcp tools" if mcp_tools.len() < MAX_MCP_TOOLS_PER_CAPTURE => {
                if let Some(item) = parse_mcp_tool_row(&cells) {
                    mcp_tools.push(item);
                }
            }
            _ => {}
        }
    }

    let used_tokens = used_tokens.ok_or_else(|| anyhow!("Claude Code /context tokens missing"))?;
    let context_window_tokens =
        context_window_tokens.ok_or_else(|| anyhow!("Claude Code /context window missing"))?;
    let pct_context = pct_context
        .unwrap_or_else(|| used_tokens as f64 * 100.0 / context_window_tokens.max(1) as f64);
    let free_space_tokens = categories
        .iter()
        .find(|category| category.name.eq_ignore_ascii_case("Free space"))
        .map(|category| category.tokens);

    Ok(ParsedContextFootprint {
        model,
        used_tokens,
        context_window_tokens,
        pct_context,
        free_space_tokens,
        categories,
        memory_files,
        skills,
        custom_agents,
        mcp_tools,
    })
}

fn parse_tokens_headline(raw: &str) -> Option<(u64, u64, f64)> {
    let cleaned = raw.replace("**", "");
    let (used_raw, rest) = cleaned.split_once('/')?;
    let used = parse_token_count(used_raw)?;
    let (window_raw, pct_raw) = rest.split_once('(')?;
    let context_window = parse_token_count(window_raw)?;
    let pct = parse_percent(pct_raw.trim_end_matches(')').trim())?;
    Some((used, context_window, pct))
}

fn parse_category_row(cells: &[String]) -> Option<ContextFootprintCategoryInput> {
    if cells.len() < 3 {
        return None;
    }
    let name = clean_inline_markup(&cells[0])?;
    let tokens = parse_token_count(&cells[1])?;
    let pct = parse_percent(&cells[2]).unwrap_or(0.0);
    let loading_mode = if name.to_ascii_lowercase().contains("deferred") {
        "on_demand"
    } else if name.eq_ignore_ascii_case("Free space") {
        "unknown"
    } else {
        "always_on"
    };
    Some(ContextFootprintCategoryInput {
        name,
        tokens,
        pct,
        loading_mode: loading_mode.to_string(),
    })
}

fn parse_memory_file_row(cells: &[String]) -> Option<ContextFootprintItemInput> {
    if cells.len() < 3 {
        return None;
    }
    let source = safe_text(&cells[0], 128);
    let raw_path = cells[1].trim();
    let relative_path = sanitize_relative_path(raw_path);
    let name = name_from_path_or_text(raw_path)?;
    let tokens = parse_token_count(&cells[2])?;
    Some(ContextFootprintItemInput {
        kind: "memory_file".to_string(),
        name,
        tokens,
        pct: None,
        source,
        relative_path,
        loading_mode: "always_on".to_string(),
        file_counts: FileCounts::default(),
        local_path: Some(PathBuf::from(raw_path.trim_matches('`'))),
    })
}

/// Measures each loaded memory file and returns the symlink-resolved paths
/// of the Project/Local rows, which the instruction inventory compares with.
fn measure_memory_files(
    parsed: &mut ParsedContextFootprint,
    workspace: &Path,
    home: &Path,
    salt: Option<&[u8; 32]>,
) -> BTreeSet<PathBuf> {
    let mut observed = BTreeSet::new();
    for item in &mut parsed.memory_files {
        let Some(raw_path) = item.local_path.take() else {
            continue;
        };
        let path = if let Ok(relative) = raw_path.strip_prefix("~") {
            home.join(relative)
        } else if raw_path.is_absolute() {
            raw_path
        } else {
            workspace.join(raw_path)
        };
        if item.source.as_deref().is_some_and(|source| {
            source.eq_ignore_ascii_case("Project") || source.eq_ignore_ascii_case("Local")
        }) {
            observed.insert(canonical_or_self(&path));
        }
        let auto_memory = item
            .source
            .as_deref()
            .is_some_and(|source| source.eq_ignore_ascii_case("AutoMem"))
            && path.file_name().is_some_and(|name| name == "MEMORY.md");
        if let Some(counts) = measure_file(&path, auto_memory, salt) {
            item.file_counts = counts;
        }
    }
    observed
}

fn parse_named_item_row(cells: &[String], kind: &str) -> Option<ContextFootprintItemInput> {
    if cells.len() < 3 {
        return None;
    }
    let name = name_from_path_or_text(&cells[0])?;
    let source = safe_text(&cells[1], 128);
    let tokens = parse_token_count(&cells[2])?;
    Some(ContextFootprintItemInput {
        kind: kind.to_string(),
        name,
        tokens,
        pct: None,
        source,
        relative_path: None,
        loading_mode: "always_on".to_string(),
        file_counts: FileCounts::default(),
        local_path: None,
    })
}

fn parse_mcp_tool_row(cells: &[String]) -> Option<ContextFootprintMcpToolInput> {
    if cells.len() < 3 {
        return None;
    }
    Some(ContextFootprintMcpToolInput {
        name: safe_mcp_identity(&cells[0])?,
        server: safe_mcp_identity(&cells[1])?,
        tokens: parse_token_count(&cells[2])?,
    })
}

fn safe_mcp_identity(raw: &str) -> Option<String> {
    let value = safe_text(raw, 256)?;
    if value.starts_with('/')
        || value.starts_with('\\')
        || value.starts_with('~')
        || value.contains('/')
        || value.contains('\\')
        || value.contains("://")
    {
        return None;
    }
    Some(value)
}

fn parse_token_count(raw: &str) -> Option<u64> {
    let mut value = raw
        .trim()
        .trim_matches('*')
        .trim_start_matches('~')
        .trim_start_matches('<')
        .replace(',', "")
        .replace("tokens", "")
        .to_ascii_lowercase();
    value = value.trim().to_string();
    let multiplier = if let Some(stripped) = value.strip_suffix('k') {
        value = stripped.trim().to_string();
        1_000.0
    } else if let Some(stripped) = value.strip_suffix('m') {
        value = stripped.trim().to_string();
        1_000_000.0
    } else if let Some(stripped) = value.strip_suffix('b') {
        value = stripped.trim().to_string();
        1_000_000_000.0
    } else {
        1.0
    };
    let parsed = value.parse::<f64>().ok()?;
    if !parsed.is_finite() || parsed < 0.0 {
        return None;
    }
    Some((parsed * multiplier).round() as u64)
}

fn parse_percent(raw: &str) -> Option<f64> {
    let cleaned = raw
        .trim()
        .trim_matches('*')
        .trim_end_matches('%')
        .trim()
        .replace(',', "");
    let parsed = cleaned.parse::<f64>().ok()?;
    parsed.is_finite().then_some(parsed.max(0.0))
}

fn markdown_cells(line: &str) -> Vec<String> {
    line.trim()
        .trim_matches('|')
        .split('|')
        .map(|cell| cell.trim().to_string())
        .collect()
}

fn is_separator_row(cells: &[String]) -> bool {
    cells.iter().all(|cell| {
        let trimmed = cell.trim();
        !trimmed.is_empty() && trimmed.chars().all(|ch| matches!(ch, '-' | ':' | ' '))
    })
}

fn is_header_row(cells: &[String]) -> bool {
    cells
        .iter()
        .any(|cell| matches!(cell.to_ascii_lowercase().as_str(), "tokens" | "percentage"))
}

fn clean_inline_markup(raw: &str) -> Option<String> {
    safe_text(&raw.replace("**", ""), 256)
}

fn name_from_path_or_text(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_matches('`');
    if trimmed.is_empty() {
        return None;
    }
    let looks_pathy = trimmed.starts_with('/')
        || trimmed.starts_with('~')
        || trimmed.contains("\\")
        || trimmed.to_ascii_lowercase().contains("/users/")
        || trimmed.to_ascii_lowercase().contains("/home/");
    if looks_pathy {
        let path = Path::new(trimmed);
        if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
            return safe_text(name, 256);
        }
        return None;
    }
    safe_text(trimmed, 256)
}

fn sanitize_relative_path(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_matches('`');
    if trimmed.is_empty() {
        return None;
    }
    let path = Path::new(trimmed);
    let candidate = if path.is_absolute() || trimmed.starts_with('~') {
        path.file_name()
            .and_then(|name| name.to_str())
            .map(str::to_string)
    } else {
        Some(trimmed.replace('\\', "/"))
    }?;
    if candidate.starts_with('/')
        || candidate.starts_with('~')
        || candidate.contains("..")
        || candidate.to_ascii_lowercase().contains("/users/")
        || candidate.to_ascii_lowercase().contains("/home/")
        || candidate.contains(":/")
        || candidate.contains(":\\")
    {
        return None;
    }
    safe_text(&candidate, 512)
}

pub(crate) fn safe_text(raw: &str, max_len: usize) -> Option<String> {
    let normalized = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return None;
    }
    let lowered = normalized.to_ascii_lowercase();
    if lowered.contains("/users/")
        || lowered.contains("\\users\\")
        || lowered.contains("/home/")
        || lowered.contains("\\home\\")
        || lowered.contains("file://")
        || lowered.contains("transcript_path")
        || lowered.contains("workspace_path")
        || lowered.contains("authorization:")
        || lowered.contains("bearer ")
        || lowered.contains("otdev_")
        || lowered.contains("otsi_")
        || lowered.contains("otsr_")
        || lowered.contains("otel_")
        || lowered.contains("otrelay_")
    {
        return None;
    }
    Some(normalized.chars().take(max_len).collect())
}

const OBSERVED_CWDS_PER_FILE: usize = 8;
const OBSERVED_CWD_MAX_BYTES: usize = 4 * 1024;
const PROJECTION_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Charged per projected file for its map slots, on top of its cwd
/// allocations: `merge` keeps the table's slots within twice its files plus
/// eight, and one slot (entry and control byte at 7/8 load) is under 128 bytes.
const PROJECTED_FILE_BYTES: usize = 256;

/// Raw cwds of Claude transcripts, filled by snapshot sync's one read through
/// its line delivery and read by each footprint cycle; footprint opens no
/// transcript. RAM only, keyed by the opened object, never a transcript path,
/// and nothing is persisted: after a daemon restart only files read since
/// then are known, and nothing is known while snapshot sync does not read
/// Claude.
#[derive(Debug, Default)]
pub(crate) struct CwdProjection(Mutex<Projection>);

/// Counters are since daemon start, for the cycle metrics line.
#[derive(Debug, Default)]
struct Projection {
    files: HashMap<FileObject, ProjectedFile>,
    /// The most `files` has reported it can hold since it was last rebuilt.
    /// Removal frees no slot and its tombstones lower `capacity()`, so only
    /// this bounds the table's allocation.
    table_slots: usize,
    bytes: usize,
    passes: u64,
    evicted_files: u64,
    cwd_dropped: u64,
    incomplete_files: u64,
}

#[derive(Debug)]
struct ProjectedFile {
    mtime: SystemTime,
    /// Distinct cwds by last occurrence, newest last.
    cwds: Vec<String>,
}

fn projected_bytes(file: &ProjectedFile) -> usize {
    let slots = file.cwds.capacity() * std::mem::size_of::<String>();
    PROJECTED_FILE_BYTES + slots + file.cwds.iter().map(String::capacity).sum::<usize>()
}

/// Moves `cwd` to the newest position, keeping at most one file's worth.
fn remember_cwd(cwds: &mut Vec<String>, cwd: &str) {
    if cwds.last().is_some_and(|last| last == cwd) {
        return;
    }
    cwds.retain(|seen| seen != cwd);
    if cwds.len() == OBSERVED_CWDS_PER_FILE {
        cwds.remove(0);
    }
    cwds.push(cwd.to_string());
}

impl Projection {
    /// Moves the files into a table sized for them, free of tombstones.
    fn rebuild(&mut self) {
        self.files = std::mem::take(&mut self.files).into_iter().collect();
        self.table_slots = self.files.capacity();
    }
}

impl CwdProjection {
    fn lock(&self) -> std::sync::MutexGuard<'_, Projection> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// One snapshot-sync pass's observer.
    pub(crate) fn observer(self: &Arc<Self>) -> Box<CwdObserver> {
        self.lock().passes += 1;
        Box::new(CwdObserver {
            projection: Arc::clone(self),
            cwds: Vec::new(),
            dropped: 0,
        })
    }

    fn merge(&self, file: &FileView, cwds: Vec<String>, dropped: u64, incomplete: bool) {
        let mut projection = self.lock();
        projection.cwd_dropped += dropped;
        let old = projection.files.remove(&file.object);
        // A Tail or Unchanged read of an unknown file follows a prefix this
        // process never saw (restart, durable restore or eviction): partial,
        // like an interrupted read, and counted once since the file is then
        // remembered even with no cwds.
        let unseen_prefix = old.is_none() && file.mode != DeliveryMode::Full;
        projection.incomplete_files += u64::from(incomplete || unseen_prefix);
        let mut known = Vec::new();
        if let Some(old) = old {
            projection.bytes -= projected_bytes(&old);
            // A Full read starts at offset 0 and replaces what was known.
            if file.mode != DeliveryMode::Full {
                known = old.cwds;
            }
        }
        for cwd in &cwds {
            remember_cwd(&mut known, cwd);
        }
        if let Some(mtime) = file.mtime {
            let entry = ProjectedFile { mtime, cwds: known };
            projection.bytes += projected_bytes(&entry);
            projection.files.insert(file.object, entry);
            projection.table_slots = projection.table_slots.max(projection.files.capacity());
        }
        while projection.bytes > PROJECTION_MAX_BYTES {
            let oldest = projection.files.iter().min_by_key(|(_, file)| file.mtime);
            let Some(oldest) = oldest.map(|(object, _)| *object) else {
                break;
            };
            let evicted = projection
                .files
                .remove(&oldest)
                .map_or(0, |file| projected_bytes(&file));
            projection.bytes -= evicted;
            projection.evicted_files += 1;
        }
        if projection.table_slots > 2 * projection.files.len() + 8 {
            projection.rebuild();
        }
    }

    /// Forgets files outside the window, then answers each cwd with the
    /// newest mtime of a file naming it.
    fn recent_cwds(&self, now: SystemTime) -> BTreeMap<String, SystemTime> {
        let mut projection = self.lock();
        projection.files.retain(|_, file| {
            now.duration_since(file.mtime).unwrap_or(Duration::ZERO) <= RECENT_WORKSPACE_WINDOW
        });
        projection.rebuild();
        projection.bytes = projection.files.values().map(projected_bytes).sum();
        let mut out: BTreeMap<String, SystemTime> = BTreeMap::new();
        for file in projection.files.values() {
            for cwd in &file.cwds {
                let last_seen = out.entry(cwd.clone()).or_insert(file.mtime);
                *last_seen = (*last_seen).max(file.mtime);
            }
        }
        out
    }

    fn metrics(&self) -> String {
        let p = self.lock();
        format!(
            "footprint_observer_passes={} footprint_observer_files={} footprint_observer_bytes={} footprint_observer_evicted_files={} footprint_observer_cwd_dropped={} footprint_observer_incomplete_files={}",
            p.passes, p.files.len(), p.bytes, p.evicted_files, p.cwd_dropped, p.incomplete_files
        )
    }
}

/// One snapshot-sync pass's view of the current file's cwds, merged into the
/// projection once at `end`. Its pass state is at most one file's cwds.
pub(crate) struct CwdObserver {
    projection: Arc<CwdProjection>,
    cwds: Vec<String>,
    dropped: u64,
}

impl LineObserver for CwdObserver {
    fn begin(&mut self, file: &FileView) -> Want {
        self.cwds.clear();
        self.dropped = 0;
        if file.source == SnapshotSource::ClaudeCode {
            Want::Lines
        } else {
            Want::Skip
        }
    }

    fn line(&mut self, _: &FileView, line: &PhysicalLine<'_>) {
        let Some(value) = line.value else {
            return;
        };
        let Some(cwd) = string_at(value, &["cwd"])
            .or_else(|| string_at(value, &["payload", "cwd"]))
            .or_else(|| string_at(value, &["turn_context", "payload", "cwd"]))
        else {
            return;
        };
        if cwd.len() > OBSERVED_CWD_MAX_BYTES {
            self.dropped += 1;
        } else {
            remember_cwd(&mut self.cwds, cwd);
        }
    }

    fn end(&mut self, file: &FileView, end: &DeliveryEnd) {
        if file.source == SnapshotSource::ClaudeCode {
            let cwds = std::mem::take(&mut self.cwds);
            let incomplete = *end == DeliveryEnd::Incomplete;
            self.projection.merge(file, cwds, self.dropped, incomplete);
        }
    }
}

/// `cwds` holds each raw cwd's newest mtime. `scope_of` answers a
/// workspace's repository scope and whether it fell back to the path itself.
fn discover_workspaces(
    cwds: BTreeMap<String, SystemTime>,
    path_scopes: &mut usize,
    mut scope_of: impl FnMut(&Path) -> (String, bool),
) -> Vec<WorkspaceCandidate> {
    let mut scope_by_path: BTreeMap<String, String> = BTreeMap::new();
    let mut candidates = Vec::new();
    for (cwd, last_seen) in cwds {
        let path = PathBuf::from(&cwd);
        if !path.is_dir() {
            continue;
        }
        let (scope, path_scope) = scope_of(&path);
        *path_scopes += usize::from(path_scope);
        scope_by_path.insert(path.to_string_lossy().to_string(), scope);
        candidates.push(WorkspaceCandidate { path, last_seen });
    }
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.last_seen));
    dedupe_workspace_candidates_by_repository(candidates, |candidate| {
        scope_by_path
            .get(candidate.path.to_string_lossy().as_ref())
            .cloned()
            .unwrap_or_default()
    })
}

/// Workspaces of one repository share a scope; a workspace without a
/// repository hash is its own scope (`true`).
fn repository_scope(path: &Path) -> (String, bool) {
    match resolve_repository_identity(path, false).repository_hash {
        Some(hash) => (hash, false),
        None => (sha256_hex(&[path.to_string_lossy().as_ref()]), true),
    }
}

fn dedupe_workspace_candidates_by_repository(
    candidates: Vec<WorkspaceCandidate>,
    scope_of: impl Fn(&WorkspaceCandidate) -> String,
) -> Vec<WorkspaceCandidate> {
    let mut by_scope: BTreeMap<String, WorkspaceCandidate> = BTreeMap::new();
    for candidate in candidates {
        by_scope
            .entry(scope_of(&candidate))
            .and_modify(|existing| {
                if existing.last_seen < candidate.last_seen {
                    *existing = candidate.clone();
                }
            })
            .or_insert(candidate);
    }
    let mut out: Vec<_> = by_scope.into_values().collect();
    out.sort_by_key(|candidate| std::cmp::Reverse(candidate.last_seen));
    out
}

fn string_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FootprintCacheEntry {
    identity: String,
    footprint_sha256: String,
    posted_at: String,
}

fn upload_if_changed(
    client: &SnapshotApiClient,
    relay_token: &str,
    support_dir: &Path,
    identity: &str,
    request: &ContextFootprintIngestRequest,
) -> Result<bool> {
    let hash = request_content_hash_for_request(request)?;
    let path = cache_path(support_dir, &request.workspace_hash);
    let now = OffsetDateTime::now_utc();
    if let Some(entry) = read_cache(&path) {
        if entry.identity == identity
            && entry.footprint_sha256 == hash
            && !cache_is_stale(&entry, now)
        {
            return Ok(false);
        }
    }
    let payload = serde_json::to_value(request)
        .map_err(|error| anyhow!("encode context footprint: {error}"))?;
    client.upload_context_footprint(relay_token, &payload)?;
    write_cache(
        &path,
        &FootprintCacheEntry {
            identity: identity.to_string(),
            footprint_sha256: hash,
            posted_at: now.format(&Rfc3339).unwrap_or_default(),
        },
    );
    Ok(true)
}

fn request_content_hash(parsed: &ParsedContextFootprint) -> Result<String> {
    let canonical = serde_json::to_vec(&json!({
        "model": &parsed.model,
        "used_tokens": parsed.used_tokens,
        "context_window_tokens": parsed.context_window_tokens,
        "pct_context": parsed.pct_context,
        "free_space_tokens": parsed.free_space_tokens,
        "categories": &parsed.categories,
        "memory_files": &parsed.memory_files,
        "skills": &parsed.skills,
        "custom_agents": &parsed.custom_agents,
        "mcp_tools": &parsed.mcp_tools,
    }))
    .map_err(|error| anyhow!("hash encode failed: {error}"))?;
    Ok(sha256_bytes(&canonical))
}

pub(crate) fn request_content_hash_for_request(
    request: &ContextFootprintIngestRequest,
) -> Result<String> {
    let mut canonical = json!({
        "cache_schema": "context_footprint_request_v3",
        "agent_source": &request.agent_source,
        "machine_id": &request.machine_id,
        "workspace_hash": &request.workspace_hash,
        "workspace_label": &request.workspace_label,
        "workspace_label_source": &request.workspace_label_source,
        "repository_hash": &request.repository_hash,
        "repository_label": &request.repository_label,
        "repository_label_source": &request.repository_label_source,
        "repository_identity_source": &request.repository_identity_source,
        "workspace_kind": &request.workspace_kind,
        "config_hash": &request.config_hash,
        "collector_version": &request.collector_version,
        "counter_source": &request.counter_source,
        "model": &request.model,
        "used_tokens": request.used_tokens,
        "context_window_tokens": request.context_window_tokens,
        "pct_context": request.pct_context,
        "free_space_tokens": request.free_space_tokens,
        "categories": &request.categories,
        "memory_files": &request.memory_files,
        "skills": &request.skills,
        "custom_agents": &request.custom_agents,
        "mcp_tools": &request.mcp_tools,
    });
    // Only when present, so requests without a block keep their digest
    // (Codex footprints included) and a new block alone forces one upload.
    if let Some(inventory) = &request.instruction_inventory {
        canonical["instruction_inventory"] = serde_json::to_value(inventory)
            .map_err(|error| anyhow!("hash encode failed: {error}"))?;
    }
    let canonical =
        serde_json::to_vec(&canonical).map_err(|error| anyhow!("hash encode failed: {error}"))?;
    Ok(sha256_bytes(&canonical))
}

pub(crate) fn sha256_hex(parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.as_bytes());
        digest.update([0]);
    }
    format!("{:x}", digest.finalize())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn destination_identity(
    device: &LocalDeviceBinding,
    machine_id: &str,
    api_base_url: &str,
) -> String {
    format!("{}|{}|{}", device.device_id, machine_id, api_base_url)
}

fn cache_path(support_dir: &Path, workspace_hash: &str) -> PathBuf {
    support_dir
        .join("context_footprint")
        .join(format!("{workspace_hash}.json"))
}

fn read_cache(path: &Path) -> Option<FootprintCacheEntry> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_cache(path: &Path, entry: &FootprintCacheEntry) {
    let Some(dir) = path.parent() else {
        return;
    };
    if fs::create_dir_all(dir).is_err() {
        return;
    }
    let Ok(payload) = serde_json::to_vec(entry) else {
        return;
    };
    let temp = path.with_extension("json.tmp");
    if fs::write(&temp, &payload).is_ok() {
        let _ = fs::rename(&temp, path);
    }
}

fn cache_is_stale(entry: &FootprintCacheEntry, now: OffsetDateTime) -> bool {
    let Ok(posted) = OffsetDateTime::parse(&entry.posted_at, &Rfc3339) else {
        return true;
    };
    (now - posted).whole_seconds() >= CONTEXT_MAX_STALENESS_SECS
}

const LOCAL_DISABLE_ENV: &str = "OTTTO_CONTEXT_FOOTPRINT_HARVEST_DISABLED";

fn local_harvest_disabled(support_dir: &Path) -> bool {
    if std::env::var(LOCAL_DISABLE_ENV)
        .map(|value| is_truthy(&value))
        .unwrap_or(false)
    {
        return true;
    }
    support_dir
        .join("context_footprint")
        .join("disabled")
        .exists()
}

fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn org_disabled_marker_path(support_dir: &Path) -> PathBuf {
    support_dir.join("context_footprint").join("org_disabled")
}

fn read_marker(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn write_marker(path: &Path, identity: &str) {
    if let Some(dir) = path.parent() {
        if fs::create_dir_all(dir).is_err() {
            return;
        }
    }
    let _ = fs::write(path, identity.as_bytes());
}

pub(crate) fn workspace_label(workspace: &Path) -> Option<String> {
    workspace
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| safe_text(name, 255))
        .or_else(|| Some("workspace".to_string()))
}

#[cfg(test)]
mod tests {
    /// Recent plain `.jsonl` transcripts under `dir`. Recent `.jsonl.zst` archives
    /// are counted in `compressed` and never opened.
    fn collect_recent_jsonl_files(
        dir: &Path,
        now: SystemTime,
        out: &mut Vec<(PathBuf, SystemTime)>,
        compressed: &mut usize,
    ) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.is_dir() {
                collect_recent_jsonl_files(&path, now, out, compressed);
                continue;
            }
            let plain = path.extension().and_then(|value| value.to_str()) == Some("jsonl");
            let archive = !plain
                && path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .is_some_and(|name| name.ends_with(".jsonl.zst"));
            if !plain && !archive {
                continue;
            }
            let mtime = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            if now.duration_since(mtime).unwrap_or(Duration::ZERO) <= RECENT_WORKSPACE_WINDOW {
                if plain {
                    out.push((path, mtime));
                } else {
                    *compressed += 1;
                }
            }
        }
    }

    use super::*;
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    /// Every cwd a transcript names, read whole: the oracle footprint's own
    /// reader used before it took cwds from snapshot sync's read.
    fn cwd_values_from_jsonl(path: &Path) -> Vec<String> {
        let Ok(file) = File::open(path) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for line in BufReader::new(file)
            .lines()
            .map_while(std::result::Result::ok)
        {
            let Ok(value) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if let Some(cwd) = string_at(&value, &["cwd"])
                .or_else(|| string_at(&value, &["payload", "cwd"]))
                .or_else(|| string_at(&value, &["turn_context", "payload", "cwd"]))
            {
                out.push(cwd.to_string());
            }
        }
        out
    }

    #[cfg(unix)]
    use crate::claude_spawn_gate::test_support::{set_probe_fault, ProbeFault, ProbeFixture};

    #[cfg(unix)]
    fn probe_context(fixture: &ProbeFixture, timeout: Duration) -> Result<String> {
        let mut command = fixture.command();
        configure_claude_context_command(&mut command, false);
        capture_claude_context(command, &ottto_core::ClaudeConfigDirSlot::Default, timeout)
    }

    #[cfg(unix)]
    #[test]
    #[serial_test::serial]
    fn probe_context_drains_large_complete_output_and_preserves_modes() {
        let payload = json!({"result":"λ".repeat(600_000),"is_error":false}).to_string();
        let fixture = ProbeFixture::new("probe-context-fidelity", "output", payload.as_bytes(), 0);
        for sampled in [false, true] {
            let mut command = fixture.command();
            configure_claude_context_command(&mut command, sampled);
            assert_eq!(
                capture_claude_context(
                    command,
                    &ottto_core::ClaudeConfigDirSlot::Default,
                    Duration::from_secs(3)
                )
                .unwrap(),
                payload
            );
            let arguments = fs::read_to_string(fixture.fake.root.join("arguments")).unwrap();
            assert!(arguments.starts_with("\n-p\n/context\n--output-format\njson\n"));
            assert_eq!(arguments.contains("--strict-mcp-config"), !sampled);
            assert_eq!(crate::claude_spawn_gate::probe::active_count(), 0);
        }
        fixture.wait_settled();
    }

    #[cfg(unix)]
    #[test]
    #[serial_test::serial]
    fn probe_context_preserves_exit_utf8_and_expired_launch_errors() {
        for (output, exit, error) in [
            (b"{}".as_slice(), 7, "exited unsuccessfully"),
            ([0xff].as_slice(), 0, "stdout was not UTF-8"),
        ] {
            let fixture = ProbeFixture::new("probe-context-errors", "output", output, exit);
            assert!(probe_context(&fixture, Duration::from_secs(2))
                .err()
                .unwrap()
                .to_string()
                .contains(error));
            fixture.wait_settled();
        }
        let fixture = ProbeFixture::new("probe-context-expired", "output", b"{}", 0);
        assert!(probe_context(&fixture, Duration::ZERO)
            .err()
            .unwrap()
            .to_string()
            .contains("timed out"));
        assert!(!fixture.fake.root.join("direct").exists());
        assert_eq!(crate::claude_spawn_gate::probe::active_count(), 0);
    }

    #[cfg(unix)]
    #[test]
    #[serial_test::serial]
    fn probe_context_prelaunch_failures_and_postlaunch_errors_keep_ownership() {
        for fault in [ProbeFault::Prepare, ProbeFault::WorkerStart] {
            let fixture = ProbeFixture::new("probe-context-no-launch", "protected", &[], 0);
            set_probe_fault(fault);
            assert!(probe_context(&fixture, Duration::from_secs(1)).is_err());
            assert!(!fixture.fake.root.join("direct").exists());
            assert_eq!(crate::claude_spawn_gate::probe::active_count(), 0);
        }
        for fault in [ProbeFault::Read, ProbeFault::Status] {
            let fixture = ProbeFixture::new("probe-context-owned-error", "protected", &[], 0);
            set_probe_fault(fault);
            assert!(probe_context(&fixture, Duration::from_secs(1)).is_err());
            fixture.wait_started();
            assert!(ProbeFixture::alive(fixture.pid("direct")));
            assert_eq!(crate::claude_spawn_gate::probe::active_count(), 1);
            for _ in 0..10 {
                assert!(probe_context(&fixture, Duration::from_secs(1))
                    .err()
                    .unwrap()
                    .downcast_ref::<ClaudeContextRefused>()
                    .is_some());
            }
            fixture.release();
            fixture.wait_settled();
        }
        let fixture = ProbeFixture::new("probe-context-spawn-error", "output", b"{}", 0);
        fs::remove_file(&fixture.script).unwrap();
        assert!(probe_context(&fixture, Duration::from_secs(1)).is_err());
        assert_eq!(crate::claude_spawn_gate::probe::active_count(), 0);
    }

    #[cfg(unix)]
    #[test]
    #[serial_test::serial]
    fn probe_context_held_writers_cannot_hold_active_deadline() {
        for mode in ["hold-exit", "protected", "escaped"] {
            let fixture = ProbeFixture::new("probe-context-held-writer", mode, &[], 0);
            let budget = if mode == "escaped" {
                Duration::from_secs(2)
            } else {
                Duration::from_millis(500)
            };
            let started = Instant::now();
            assert!(probe_context(&fixture, budget)
                .err()
                .unwrap()
                .to_string()
                .contains("timed out"));
            assert!(started.elapsed() < budget + Duration::from_secs(1));
            fixture.wait_started();
            if mode != "hold-exit" {
                assert_eq!(crate::claude_spawn_gate::probe::active_count(), 1);
                if mode == "protected" {
                    assert!(ProbeFixture::alive(fixture.pid("direct")));
                }
                for _ in 0..20 {
                    assert!(probe_context(&fixture, Duration::from_secs(1))
                        .err()
                        .unwrap()
                        .downcast_ref::<ClaudeContextRefused>()
                        .is_some());
                }
            }
            fixture.release();
            fixture.wait_settled();
            if mode == "escaped" {
                assert!(ProbeFixture::alive(fixture.pid("descendant")));
                fs::write(fixture.fake.root.join("release"), []).unwrap();
                fixture.wait_until(|| !ProbeFixture::alive(fixture.pid("descendant")));
            }
            assert_eq!(crate::claude_spawn_gate::probe::active_count(), 0);
        }
    }

    use crate::test_scratch;

    fn temp_dir(name: &str) -> PathBuf {
        test_scratch::private_dir(&format!("ottto-context-footprint-{name}"))
    }

    #[test]
    fn recent_archives_are_counted_and_never_listed() {
        let root = temp_dir("collector-archives");
        let day = root.join("2026/10/28");
        fs::create_dir_all(&day).unwrap();
        fs::write(day.join("rollout-a.jsonl"), b"{}\n").unwrap();
        fs::write(day.join("rollout-b.jsonl.zst"), b"not zstd").unwrap();
        fs::write(day.join("notes.zst"), b"other").unwrap();
        let (mut files, mut compressed) = (Vec::new(), 0);
        collect_recent_jsonl_files(&root, SystemTime::now(), &mut files, &mut compressed);
        let names: Vec<_> = files
            .iter()
            .map(|(path, _)| path.file_name().unwrap().to_owned())
            .collect();
        assert_eq!(names, [std::ffi::OsString::from("rollout-a.jsonl")]);
        assert_eq!(compressed, 1);
        fs::remove_dir_all(root).unwrap();
    }

    fn run_git(repo: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    fn init_git_repo(name: &str) -> PathBuf {
        let repo = temp_dir(name);
        run_git(&repo, &["init"]);
        run_git(&repo, &["config", "user.email", "test@example.com"]);
        run_git(&repo, &["config", "user.name", "Test User"]);
        fs::write(repo.join("README.md"), "test\n").unwrap();
        run_git(&repo, &["add", "README.md"]);
        run_git(&repo, &["commit", "-m", "initial"]);
        repo
    }

    #[test]
    fn parses_claude_context_markdown_tables() {
        let parsed = parse_context_markdown(
            r#"# Context Usage

**Model:** claude-opus-4-8
**Tokens:** 42.2k / 1m (4%)

### Estimated usage by category
| Category | Tokens | Percentage |
|---|---:|---:|
| System prompt | 2.5k | 0.2% |
| System tools (deferred) | 13.9k | 1.4% |
| MCP tools (deferred) | 1.75k | 0.2% |
| Memory files | 22.2k | 2.2% |
| Free space | 957.8k | 95.8% |

### Memory Files
| Type | Path | Tokens |
|---|---|---:|
| Project | /Users/example/private/repo/CLAUDE.md | 22.2k |

### Skills
| Skill | Source | Tokens |
|---|---|---:|
| frontend-flow-change | project | 4.2k |

### Custom Agents
| Agent Type | Source | Tokens |
|---|---|---:|
| reviewer | global | 3.6k |

### MCP Tools
| Tool | Server | Tokens |
|---|---|---:|
| leaks_path | /Users/example/private/server | 999 |
| create_artifact | claude_design | 1.25k |
| read_artifact | claude_design | 500 |
"#,
        )
        .expect("parse");

        assert_eq!(parsed.model, "claude-opus-4-8");
        assert_eq!(parsed.used_tokens, 42_200);
        assert_eq!(parsed.context_window_tokens, 1_000_000);
        assert_eq!(parsed.free_space_tokens, Some(957_800));
        assert_eq!(parsed.categories.len(), 5);
        assert_eq!(parsed.categories[1].loading_mode, "on_demand");
        assert_eq!(parsed.categories[2].name, "MCP tools (deferred)");
        assert_eq!(parsed.categories[2].loading_mode, "on_demand");
        assert_eq!(parsed.memory_files[0].name, "CLAUDE.md");
        assert_eq!(
            parsed.memory_files[0].relative_path.as_deref(),
            Some("CLAUDE.md")
        );
        assert_eq!(parsed.skills[0].name, "frontend-flow-change");
        assert_eq!(parsed.custom_agents[0].name, "reviewer");
        assert_eq!(parsed.mcp_tools.len(), 2);
        assert_eq!(parsed.mcp_tools[0].name, "create_artifact");
        assert_eq!(parsed.mcp_tools[0].server, "claude_design");
        assert_eq!(parsed.mcp_tools[0].tokens, 1_250);
        assert_eq!(parsed.mcp_tools[1].tokens, 500);
        let encoded = serde_json::to_string(&parsed.memory_files).unwrap();
        assert!(!encoded.contains("/Users/example"));
        let encoded_mcp = serde_json::to_string(&parsed.mcp_tools).unwrap();
        assert!(!encoded_mcp.contains("description"));
    }

    #[test]
    fn file_counts_resolve_original_paths_and_trigger_upload_after_token_plateau() {
        let dir = temp_dir("context-footprint-counts");
        let home = dir.join("home");
        let workspace = dir.join("repo");
        fs::create_dir_all(home.join(".claude")).unwrap();
        fs::create_dir_all(&workspace).unwrap();
        let memory_path = home.join("MEMORY.md");
        fs::write(&memory_path, "x\n".repeat(201)).unwrap();
        fs::write(workspace.join("AGENTS.md"), "synthetic private instruction").unwrap();
        fs::write(home.join(".claude/CLAUDE.md"), "synthetic user instruction").unwrap();
        let markdown = format!("**Tokens:** 10k / 200k (5%)\n### Memory Files\n| AutoMem | {} | 6k |\n| Project | AGENTS.md | 1k |\n| User | ~/.claude/CLAUDE.md | 1k |", memory_path.display());
        let mut parsed = parse_context_markdown(&markdown).unwrap();
        let observed = measure_memory_files(&mut parsed, &workspace, &home, Some(&[7; 32]));
        // Only Project/Local rows, symlink-resolved, feed the inventory.
        assert_eq!(
            observed,
            BTreeSet::from([workspace.join("AGENTS.md").canonicalize().unwrap()])
        );
        assert_eq!(parsed.memory_files[0].file_counts.loaded_lines, Some(200));
        assert_eq!(
            parsed.memory_files[0].file_counts.truncated_by_limit,
            Some(true)
        );
        assert_eq!(parsed.memory_files[1].file_counts.file_bytes, Some(29));
        assert_eq!(parsed.memory_files[2].file_counts.file_bytes, Some(26));
        let before = request_content_hash(&parsed).unwrap();
        let mut request = sample_request();
        request.memory_files = parsed.memory_files.clone();
        let before_upload = request_content_hash_for_request(&request).unwrap();
        fs::write(&memory_path, "x\n".repeat(202)).unwrap();
        let mut changed = parse_context_markdown(&markdown).unwrap();
        measure_memory_files(&mut changed, &workspace, &home, Some(&[7; 32]));
        assert_ne!(before, request_content_hash(&changed).unwrap());
        request.memory_files = changed.memory_files.clone();
        assert_ne!(
            before_upload,
            request_content_hash_for_request(&request).unwrap()
        );
        let encoded = serde_json::to_string(&changed.memory_files).unwrap();
        assert!(!encoded.contains("synthetic"));
        assert!(!encoded.contains(&dir.to_string_lossy().to_string()));
        assert!(!encoded.contains("local_path"));
        assert!(encoded.contains("file_chars"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn context_file_counts_generated_wire_fixture() {
        let dir = temp_dir("context-counts-wire");
        let path = dir.join("MEMORY.md");
        fs::write(&path, "x\n".repeat(300)).unwrap();
        let mut parsed = parse_context_markdown(
            "**Tokens:** 10k / 200k (5%)\n### Memory Files\n| AutoMem | MEMORY.md | 6k |",
        )
        .unwrap();
        measure_memory_files(&mut parsed, &dir, &dir, Some(&[7; 32]));
        let actual = json!({
            "contract_version": "context_footprint_file_counts:v1",
            "max_file_bytes": crate::context_file_counts::MAX_FILE_BYTES,
            "character_unit": "utf16",
            "auto_memory_limit": {"lines": crate::context_file_counts::AUTO_MEMORY_LIMIT.0,
                "chars": crate::context_file_counts::AUTO_MEMORY_LIMIT.1},
            "hash_scheme": "sha256(ottto-context-file-v1\\0 || device_salt_32_bytes || file_bytes):hex64",
            "item": &parsed.memory_files[0],
        });
        if let Some(output) = std::env::var_os("OTTTO_CONTEXT_COUNTS_FIXTURE_OUTPUT") {
            fs::write(
                output,
                serde_json::to_string_pretty(&actual).unwrap() + "\n",
            )
            .unwrap();
        }
        let expected: Value = serde_json::from_str(include_str!(
            "../../../fixtures/context-footprint/file-counts-v1.json"
        ))
        .unwrap();
        assert_eq!(actual, expected);
        fs::remove_dir_all(dir).unwrap();
    }

    /// The `/context` read runs an hour before expiry and is refused ten
    /// minutes before it (never started), with a 30-minute retry.
    #[test]
    #[serial_test::serial]
    fn context_run_waits_inside_the_quiet_window() {
        use crate::provider_calls::CallKind;
        let fake = crate::claude_spawn_gate::test_support::FakeClaudeEnv::new("context");
        let account = fake.default_account("context-account-uuid");
        let workspace = temp_dir("context-gate-workspace");
        let env = SpawnEnv {
            path: crate::command_env::path_env(),
            provider: BTreeMap::new(),
        };
        fake.default_login_expires_in(time::Duration::hours(1));
        run_claude_context(&workspace, &env, false).expect("admitted an hour out");
        assert_eq!(fake.spawns().len(), 1);
        fake.default_login_expires_in(time::Duration::minutes(10));
        let error = run_claude_context(&workspace, &env, false).expect_err("refused");
        assert!(error.downcast_ref::<ClaudeContextRefused>().is_some());
        assert_eq!(fake.spawns().len(), 1, "the refused run never started");
        // The started run is logged as a possible Anthropic contact (at
        // least zero requests); the refused one is not logged.
        let lines = crate::provider_calls::test_lines(CallKind::ClaudeContextProbe, &account);
        assert_eq!(lines.len(), 1);
        assert_eq!(
            (
                lines[0].provider.as_str(),
                lines[0].trigger.as_str(),
                lines[0].result.as_str(),
                lines[0].requests_at_least
            ),
            ("anthropic", "schedule", "ok", 0)
        );
        assert_eq!(next_context_cycle_delay(true), Duration::from_secs(30 * 60));
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn only_newest_workspace_enables_mcp_with_the_long_timeout() {
        assert!(should_include_mcp_servers(0));
        assert!((1..MAX_WORKSPACES_PER_CYCLE).all(|index| !should_include_mcp_servers(index)));

        let mut sampled = Command::new("claude");
        let sampled_timeout = configure_claude_context_command(&mut sampled, true);
        let sampled_args: Vec<_> = sampled.get_args().collect();
        assert!(!sampled_args.iter().any(|arg| *arg == "--strict-mcp-config"));
        assert_eq!(sampled_timeout, CONTEXT_MCP_COMMAND_TIMEOUT);

        let mut strict = Command::new("claude");
        let strict_timeout = configure_claude_context_command(&mut strict, false);
        let strict_args: Vec<_> = strict.get_args().collect();
        assert!(strict_args.iter().any(|arg| *arg == "--strict-mcp-config"));
        assert_eq!(strict_timeout, CONTEXT_COMMAND_TIMEOUT);
        assert!(
            CONTEXT_CYCLE_BUDGET
                >= CONTEXT_MCP_COMMAND_TIMEOUT
                    + CONTEXT_COMMAND_TIMEOUT * (MAX_WORKSPACES_PER_CYCLE as u32 - 1)
        );
    }

    #[test]
    fn discovers_recent_workspace_from_claude_jsonl() {
        let home = temp_dir("discover");
        let workspace = home.join("work").join("repo");
        fs::create_dir_all(&workspace).unwrap();
        let project = home.join(".claude").join("projects").join("-work-repo");
        fs::create_dir_all(&project).unwrap();
        fs::write(
            project.join("session.jsonl"),
            format!(
                "{{\"type\":\"session\",\"cwd\":\"{}\",\"timestamp\":\"2026-06-29T00:00:00Z\"}}\n",
                workspace.to_string_lossy()
            ),
        )
        .unwrap();

        let (discovered, path_scopes) = discover_with_counts(&home, SystemTime::now());

        assert_eq!(discovered.len(), 1);
        assert_eq!(path_scopes, 1);
        assert_eq!(discovered[0].path, workspace);
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn repository_identity_groups_root_and_subdir_without_raw_paths() {
        let repo = init_git_repo("repo-identity-root");
        let subdir = repo.join("backend");
        fs::create_dir_all(&subdir).unwrap();

        let root_identity = resolve_repository_identity(&repo, true);
        let subdir_identity = resolve_repository_identity(&subdir, true);

        assert_eq!(
            root_identity.repository_hash,
            subdir_identity.repository_hash
        );
        assert_eq!(root_identity.repository_hash.as_ref().unwrap().len(), 64);
        assert_eq!(
            root_identity.repository_label.as_deref(),
            repo.file_name().and_then(|name| name.to_str())
        );
        assert_eq!(
            root_identity.repository_label_source.as_deref(),
            Some("git_root")
        );
        assert_eq!(
            root_identity.repository_identity_source.as_deref(),
            Some("git_common_dir")
        );
        assert_eq!(
            root_identity.workspace_kind.as_deref(),
            Some("repository_root")
        );
        assert_eq!(
            subdir_identity.workspace_kind.as_deref(),
            Some("repository_subdir")
        );
        let encoded = serde_json::to_string(&root_identity.repository_label).unwrap();
        assert!(!encoded.contains("/Users/"));
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn repository_identity_withholds_labels_unless_a_hint_allows_them() {
        let repo = init_git_repo("repo-identity-hint-policy");
        let hint = |labels: bool| {
            crate::snapshot_client::decode_activity_hint(serde_json::json!({
                "source": "claude_code", "server_time": "2026-10-25T10:00:00Z",
                "record_count_15m": 0, "record_count_24h": 0,
                "local_usage_reconciliation_enabled": true, "backfill_window_days": 183,
                "workspace_labels_enabled": labels,
                "recommended_scan_after": "2026-10-25T10:05:00Z",
            }))
            .unwrap()
        };
        let identity = |hint: Option<&ActivityHintResponse>| {
            resolve_repository_identity(&repo, workspace_labels_allowed(hint))
        };

        // Policy ON keeps today's labelled identity.
        let on = identity(Some(&hint(true)));
        assert_eq!(on, resolve_repository_identity(&repo, true));
        assert!(on.repository_label.is_some());
        // Policy OFF and a failed hint fetch both withhold the labels.
        let withheld = resolve_repository_identity(&repo, false);
        assert_eq!(identity(Some(&hint(false))), withheld);
        assert_eq!(identity(None), withheld);
        assert!(withheld.repository_label.is_none());
        assert!(withheld.repository_label_source.is_none());
        assert_eq!(withheld.repository_hash, on.repository_hash);
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn repository_identity_marks_non_git_without_repository_hash() {
        let dir = temp_dir("repo-identity-non-git");

        let identity = resolve_repository_identity(&dir, true);

        assert!(identity.repository_hash.is_none());
        assert!(identity.repository_label.is_none());
        assert!(identity.repository_label_source.is_none());
        assert!(identity.repository_identity_source.is_none());
        assert_eq!(identity.workspace_kind.as_deref(), Some("non_git"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn repository_identity_groups_linked_worktree_to_common_repo() {
        let repo = init_git_repo("repo-identity-worktree");
        let worktree = temp_dir("repo-identity-worktree-linked");
        fs::remove_dir_all(&worktree).unwrap();
        let worktree_text = worktree.to_string_lossy().to_string();
        run_git(
            &repo,
            &["worktree", "add", "-b", "context-test", &worktree_text],
        );

        let root_identity = resolve_repository_identity(&repo, true);
        let worktree_identity = resolve_repository_identity(&worktree, true);

        assert_eq!(
            root_identity.repository_hash,
            worktree_identity.repository_hash
        );
        assert_eq!(
            worktree_identity.repository_identity_source.as_deref(),
            Some("git_worktree")
        );
        assert_eq!(
            worktree_identity.workspace_kind.as_deref(),
            Some("linked_worktree")
        );
        // The label must name the main checkout, not the throwaway worktree
        // directory the user happens to be working from.
        assert_eq!(
            worktree_identity.repository_label,
            root_identity.repository_label
        );
        let worktree_dir_name = worktree.file_name().unwrap().to_str().unwrap();
        assert_ne!(
            worktree_identity.repository_label.as_deref(),
            Some(worktree_dir_name)
        );
        let _ = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["worktree", "remove", "--force", &worktree_text])
            .status();
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn repository_identity_labels_worktree_subdir_after_main_checkout() {
        let repo = init_git_repo("repo-identity-worktree-subdir");
        let worktree = temp_dir("repo-identity-worktree-subdir-linked");
        fs::remove_dir_all(&worktree).unwrap();
        let worktree_text = worktree.to_string_lossy().to_string();
        run_git(
            &repo,
            &[
                "worktree",
                "add",
                "-b",
                "context-subdir-test",
                &worktree_text,
            ],
        );
        let subdir = worktree.join("nested");
        fs::create_dir_all(&subdir).unwrap();

        let root_identity = resolve_repository_identity(&repo, true);
        let subdir_identity = resolve_repository_identity(&subdir, true);

        assert_eq!(
            root_identity.repository_hash,
            subdir_identity.repository_hash
        );
        assert_eq!(
            subdir_identity.workspace_kind.as_deref(),
            Some("linked_worktree")
        );
        assert_eq!(
            subdir_identity.repository_label,
            root_identity.repository_label
        );
        let _ = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["worktree", "remove", "--force", &worktree_text])
            .status();
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn dedupes_recent_candidates_by_repository_hash() {
        let repo = init_git_repo("repo-identity-dedupe");
        let subdir = repo.join("frontend");
        fs::create_dir_all(&subdir).unwrap();
        let older = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let newer = SystemTime::UNIX_EPOCH + Duration::from_secs(200);

        let out = dedupe_workspace_candidates_by_repository(
            vec![
                WorkspaceCandidate {
                    path: repo.clone(),
                    last_seen: older,
                },
                WorkspaceCandidate {
                    path: subdir.clone(),
                    last_seen: newer,
                },
            ],
            |candidate| repository_scope(&candidate.path).0,
        );

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].path, subdir);
        let _ = fs::remove_dir_all(&repo);
    }

    /// Discovery before the projection: every recent file is parsed whole,
    /// then deduplicated by repository and truncated to one cycle.
    fn discover_all_files_oracle(home: &Path, now: SystemTime) -> Vec<WorkspaceCandidate> {
        let mut files = Vec::new();
        collect_recent_jsonl_files(
            &home.join(".claude").join("projects"),
            now,
            &mut files,
            &mut 0,
        );
        files.sort_by_key(|item| std::cmp::Reverse(item.1));
        let mut by_path: BTreeMap<String, WorkspaceCandidate> = BTreeMap::new();
        for (file, mtime) in files {
            for cwd in cwd_values_from_jsonl(&file) {
                let path = PathBuf::from(&cwd);
                if !path.is_dir() {
                    continue;
                }
                by_path
                    .entry(path.to_string_lossy().to_string())
                    .and_modify(|candidate| {
                        if candidate.last_seen < mtime {
                            candidate.last_seen = mtime;
                        }
                    })
                    .or_insert(WorkspaceCandidate {
                        path,
                        last_seen: mtime,
                    });
            }
        }
        let mut candidates: Vec<_> = by_path.into_values().collect();
        candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.last_seen));
        let mut by_scope: BTreeMap<String, WorkspaceCandidate> = BTreeMap::new();
        for candidate in candidates {
            let scope = resolve_repository_identity(&candidate.path, false)
                .repository_hash
                .unwrap_or_else(|| frozen_path_scope(&candidate.path));
            by_scope
                .entry(scope)
                .and_modify(|existing| {
                    if existing.last_seen < candidate.last_seen {
                        *existing = candidate.clone();
                    }
                })
                .or_insert(candidate);
        }
        let mut out: Vec<_> = by_scope.into_values().collect();
        out.sort_by_key(|candidate| std::cmp::Reverse(candidate.last_seen));
        out.truncate(MAX_WORKSPACES_PER_CYCLE);
        out
    }

    /// The path scope bytes as shipped before the projection: SHA-256 of the
    /// lossy path text followed by one NUL byte, lowercase hex.
    fn frozen_path_scope(path: &Path) -> String {
        let mut hasher = Sha256::new();
        hasher.update(path.to_string_lossy().as_bytes());
        hasher.update([0u8]);
        format!("{:x}", hasher.finalize())
    }

    /// Writes one transcript per entry, naming its cwds, with the given age.
    fn write_discovery_transcripts(home: &Path, now: SystemTime, files: &[(u64, Vec<&Path>)]) {
        let project = home.join(".claude").join("projects").join("-early-stop");
        fs::create_dir_all(&project).unwrap();
        for (index, (age_secs, cwds)) in files.iter().enumerate() {
            let path = project.join(format!("session-{index:03}.jsonl"));
            let text: String = cwds
                .iter()
                .map(|cwd| format!("{}\n", json!({"type": "user", "cwd": cwd})))
                .collect();
            fs::write(&path, text).unwrap();
            File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(now - Duration::from_secs(*age_secs))
                .unwrap();
        }
    }

    /// Feeds each transcript's lines to one pass observer, as a Full read of
    /// snapshot sync delivers them.
    fn project_transcripts(projection: &Arc<CwdProjection>, files: &[(PathBuf, SystemTime)]) {
        let mut observer = projection.observer();
        for (path, mtime) in files {
            let view = claude_view(path, *mtime, DeliveryMode::Full);
            assert_eq!(observer.begin(&view), Want::Lines);
            for line in fs::read_to_string(path).unwrap().lines() {
                let value = serde_json::from_str::<Value>(line).ok();
                observer.line(
                    &view,
                    &PhysicalLine {
                        end: 0,
                        value: value.as_ref(),
                    },
                );
            }
            observer.end(&view, &DeliveryEnd::Complete);
        }
    }

    fn claude_view(path: &Path, mtime: SystemTime, mode: DeliveryMode) -> FileView {
        let (object, _) = FileObject::of(&File::open(path).unwrap()).unwrap();
        FileView {
            source: SnapshotSource::ClaudeCode,
            root: Some(0),
            start: 0,
            object,
            mtime: Some(mtime),
            mode,
        }
    }

    fn discover_with_counts(home: &Path, now: SystemTime) -> (Vec<WorkspaceCandidate>, usize) {
        let mut files = Vec::new();
        collect_recent_jsonl_files(
            &home.join(".claude").join("projects"),
            now,
            &mut files,
            &mut 0,
        );
        let projection = Arc::new(CwdProjection::default());
        project_transcripts(&projection, &files);
        let mut path_scopes = 0;
        let cwds = projection.recent_cwds(now);
        let mut found = discover_workspaces(cwds, &mut path_scopes, repository_scope);
        found.truncate(MAX_WORKSPACES_PER_CYCLE);
        (found, path_scopes)
    }

    #[test]
    fn projected_discovery_matches_reading_every_file() {
        let home = temp_dir("early-stop");
        let now = SystemTime::now();
        let dirs: Vec<PathBuf> = (0..15)
            .map(|index| {
                let dir = home.join("work").join(format!("dir-{index:02}"));
                fs::create_dir_all(&dir).unwrap();
                dir
            })
            .collect();
        let missing = home.join("work").join("missing");
        let mut files: Vec<(u64, Vec<&Path>)> = dirs
            .iter()
            .enumerate()
            .map(|(index, dir)| (60 * (index as u64 + 1), vec![dir.as_path()]))
            .collect();
        // A cwd that no longer exists is not a workspace.
        files[0].1.insert(0, missing.as_path());
        // The oldest file also names a newer workspace; it cannot move it.
        files[14].1.push(dirs[0].as_path());
        write_discovery_transcripts(&home, now, &files);

        let (found, path_scopes) = discover_with_counts(&home, now);

        assert_eq!(found, discover_all_files_oracle(&home, now));
        assert_eq!(
            found.iter().map(|c| c.path.clone()).collect::<Vec<_>>(),
            dirs[..MAX_WORKSPACES_PER_CYCLE].to_vec()
        );
        assert_eq!(path_scopes, 15);
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn discovery_counts_repository_scopes_not_directories() {
        let repo = init_git_repo("early-stop-scopes");
        let now = SystemTime::now();
        let mut subdirs: Vec<PathBuf> = (0..11)
            .map(|index| {
                let dir = repo.join(format!("pkg-{index:02}"));
                fs::create_dir_all(&dir).unwrap();
                dir
            })
            .collect();
        // A linked worktree is the same repository scope as its main checkout.
        let worktree = temp_dir("early-stop-scopes-worktree");
        fs::remove_dir_all(&worktree).unwrap();
        run_git(
            &repo,
            &[
                "worktree",
                "add",
                "-b",
                "early-stop",
                worktree.to_string_lossy().as_ref(),
            ],
        );
        subdirs.push(worktree.clone());
        let others: Vec<PathBuf> = (0..13)
            .map(|index| {
                let dir = repo.join("..").join(format!(
                    "{}-plain-{index:02}",
                    repo.file_name().unwrap().to_string_lossy()
                ));
                fs::create_dir_all(&dir).unwrap();
                fs::canonicalize(dir).unwrap()
            })
            .collect();
        let home = temp_dir("early-stop-scopes-home");
        // Twelve newest files name twelve directories of one repository: one
        // scope, so the plain directories fill the cycle.
        let mut files: Vec<(u64, Vec<&Path>)> = subdirs
            .iter()
            .enumerate()
            .map(|(index, dir)| (60 * (index as u64 + 1), vec![dir.as_path()]))
            .collect();
        for (index, dir) in others.iter().enumerate() {
            files.push((6_000 + 60 * index as u64, vec![dir.as_path()]));
        }
        // An old file names the repository root: the newest subdirectory
        // still represents the repository.
        files.push((90_000, vec![repo.as_path()]));
        write_discovery_transcripts(&home, now, &files);

        let (found, path_scopes) = discover_with_counts(&home, now);

        assert_eq!(found, discover_all_files_oracle(&home, now));
        assert_eq!(found[0].path, subdirs[0]);
        assert_eq!(found.len(), MAX_WORKSPACES_PER_CYCLE);
        assert_eq!(path_scopes, 13);
        for dir in others {
            let _ = fs::remove_dir_all(dir);
        }
        let _ = fs::remove_dir_all(&worktree);
        let _ = fs::remove_dir_all(&repo);
        let _ = fs::remove_dir_all(&home);
    }

    /// One transcript per entry naming `cwd`, projected with the captured
    /// mtime; the file's real mtime is left as written.
    fn captured_cwds(root: &Path, entries: &[(&Path, SystemTime)]) -> BTreeMap<String, SystemTime> {
        let files: Vec<(PathBuf, SystemTime)> = entries
            .iter()
            .enumerate()
            .map(|(index, (cwd, mtime))| {
                let path = root.join(format!("captured-{index:03}.jsonl"));
                fs::write(&path, format!("{}\n", json!({"cwd": cwd}))).unwrap();
                (path, *mtime)
            })
            .collect();
        let projection = Arc::new(CwdProjection::default());
        project_transcripts(&projection, &files);
        let all = projection
            .lock()
            .files
            .values()
            .map(|file| file.mtime)
            .min();
        projection.recent_cwds(all.unwrap() + RECENT_WORKSPACE_WINDOW)
    }

    #[test]
    fn discovery_counts_path_scopes_when_repository_probes_fail() {
        let root = temp_dir("early-stop-probe-fails");
        let dirs: Vec<PathBuf> = (0..14)
            .map(|index| {
                let dir = root.join(format!("pkg-{index:02}"));
                fs::create_dir_all(&dir).unwrap();
                dir
            })
            .collect();
        let entries: Vec<(&Path, SystemTime)> = dirs
            .iter()
            .enumerate()
            .map(|(index, dir)| {
                (
                    dir.as_path(),
                    SystemTime::UNIX_EPOCH + Duration::from_secs(100 - index as u64),
                )
            })
            .collect();
        // If every probe fails, directories of one repository look like
        // separate scopes; the path-scope counter makes that visible.
        let failing = |path: &Path| (frozen_path_scope(path), true);
        let mut path_scopes = 0;
        let found = discover_workspaces(captured_cwds(&root, &entries), &mut path_scopes, failing);
        assert_eq!((found.len(), path_scopes), (14, 14));

        // With the probe answering, they are one repository.
        let answering = |_: &Path| ("repository".to_string(), false);
        let mut path_scopes = 0;
        let found =
            discover_workspaces(captured_cwds(&root, &entries), &mut path_scopes, answering);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path, dirs[0]);
        assert_eq!(path_scopes, 0);
        fs::remove_dir_all(root).unwrap();
    }

    fn deliver(observer: &mut CwdObserver, view: &FileView, lines: &[Value], end: DeliveryEnd) {
        let want = observer.begin(view);
        if want == Want::Lines {
            for value in lines {
                observer.line(
                    view,
                    &PhysicalLine {
                        end: 0,
                        value: Some(value),
                    },
                );
            }
            observer.line(
                view,
                &PhysicalLine {
                    end: 0,
                    value: None,
                },
            );
        }
        observer.end(view, &end);
    }

    fn projected(projection: &CwdProjection, view: &FileView) -> Option<Vec<String>> {
        let projection = projection.lock();
        let file = projection.files.get(&view.object)?;
        Some(file.cwds.clone())
    }

    #[test]
    fn observer_full_replaces_tail_adds_in_last_occurrence_order() {
        let root = temp_dir("cwd-observer-modes");
        let path = root.join("session.jsonl");
        fs::write(&path, "").unwrap();
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let projection = Arc::new(CwdProjection::default());
        let full = claude_view(&path, at, DeliveryMode::Full);
        let tail = FileView {
            mode: DeliveryMode::Tail,
            ..full
        };
        // Field precedence as footprint's reader had it; repeats move to the end.
        let lines = [
            json!({"cwd": "/a"}),
            json!({"payload": {"cwd": "/b"}}),
            json!({"turn_context": {"payload": {"cwd": "/c"}}}),
            json!({"cwd": "/a", "payload": {"cwd": "/ignored"}}),
            json!({"cwd": 17}),
        ];
        deliver(
            &mut projection.observer(),
            &full,
            &lines,
            DeliveryEnd::Complete,
        );
        assert_eq!(projected(&projection, &full).unwrap(), ["/b", "/c", "/a"]);

        let more: Vec<Value> = (0..7).map(|i| json!({"cwd": format!("/t{i}")})).collect();
        deliver(
            &mut projection.observer(),
            &tail,
            &more,
            DeliveryEnd::Complete,
        );
        let mut expected = vec!["/a".to_string()];
        expected.extend((0..7).map(|i| format!("/t{i}")));
        assert_eq!(projected(&projection, &full).unwrap(), expected);

        let unchanged = FileView {
            mode: DeliveryMode::Unchanged,
            ..full
        };
        deliver(
            &mut projection.observer(),
            &unchanged,
            &[],
            DeliveryEnd::Complete,
        );
        assert_eq!(projected(&projection, &full).unwrap(), expected);

        deliver(
            &mut projection.observer(),
            &full,
            &[json!({"cwd": "/z"})],
            DeliveryEnd::Complete,
        );
        assert_eq!(projected(&projection, &full).unwrap(), ["/z"]);
        assert_eq!(projection.lock().passes, 4);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn observer_drops_long_cwds_skips_other_sources_and_counts_incomplete() {
        let root = temp_dir("cwd-observer-limits");
        let path = root.join("session.jsonl");
        fs::write(&path, "").unwrap();
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let projection = Arc::new(CwdProjection::default());
        let view = claude_view(&path, at, DeliveryMode::Full);
        let long = format!("/{}", "x".repeat(OBSERVED_CWD_MAX_BYTES));
        let at_cap = format!("/{}", "y".repeat(OBSERVED_CWD_MAX_BYTES - 1));
        deliver(
            &mut projection.observer(),
            &view,
            &[json!({"cwd": long}), json!({"cwd": at_cap})],
            DeliveryEnd::Incomplete,
        );
        assert_eq!(projected(&projection, &view).unwrap(), [at_cap]);
        let state = projection.lock();
        assert_eq!((state.cwd_dropped, state.incomplete_files), (1, 1));
        drop(state);

        let codex = FileView {
            source: SnapshotSource::Codex,
            ..view
        };
        let mut observer = projection.observer();
        assert_eq!(observer.begin(&codex), Want::Skip);
        observer.end(&codex, &DeliveryEnd::Incomplete);
        assert_eq!(projection.lock().incomplete_files, 1);

        // A Tail of a file this process never projected missed its prefix.
        let tail = root.join("tail.jsonl");
        fs::write(&tail, "").unwrap();
        let tail = claude_view(&tail, at, DeliveryMode::Tail);
        deliver(
            &mut projection.observer(),
            &tail,
            &[json!({"cwd": "/short"})],
            DeliveryEnd::Complete,
        );
        assert_eq!(projection.lock().incomplete_files, 2);
        // Short cwds are charged their slots and capacity, not only text.
        let state = projection.lock();
        let entry = &state.files[&tail.object];
        assert!(projected_bytes(entry) >= PROJECTED_FILE_BYTES + std::mem::size_of::<String>() + 6);
        drop(state);

        // A file whose read named no cwd is still remembered, so its later
        // Unchanged reads are no missed prefix.
        let empty = root.join("empty.jsonl");
        fs::write(&empty, "").unwrap();
        let empty = claude_view(&empty, at, DeliveryMode::Full);
        deliver(
            &mut projection.observer(),
            &empty,
            &[json!({})],
            DeliveryEnd::Complete,
        );
        assert_eq!(
            projected(&projection, &empty).unwrap(),
            Vec::<String>::new()
        );
        let unchanged = FileView {
            mode: DeliveryMode::Unchanged,
            ..empty
        };
        deliver(
            &mut projection.observer(),
            &unchanged,
            &[],
            DeliveryEnd::Complete,
        );
        assert_eq!(projection.lock().incomplete_files, 2);

        // An Unchanged read of a file this process never saw (a durable
        // restore after restart) missed its lines: counted once.
        let restored = root.join("restored.jsonl");
        fs::write(&restored, "").unwrap();
        let restored = claude_view(&restored, at, DeliveryMode::Unchanged);
        for _ in 0..2 {
            deliver(
                &mut projection.observer(),
                &restored,
                &[],
                DeliveryEnd::Complete,
            );
        }
        assert_eq!(projection.lock().incomplete_files, 3);
        assert_eq!(
            projected(&projection, &restored).unwrap(),
            Vec::<String>::new()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn projection_rebuilds_its_map_after_evictions_and_pruning() {
        // The per-file charge covers a map of twice its files plus eight only
        // while one slot (entry and control byte at 7/8 load) is under 128 bytes.
        const _: () =
            assert!((std::mem::size_of::<(FileObject, ProjectedFile)>() + 1) * 8 / 7 < 128);
        let within_charge = |state: &Projection| {
            state.files.capacity() <= state.table_slots
                && state.table_slots <= 2 * state.files.len() + 8
                && state.bytes <= PROJECTION_MAX_BYTES
        };
        let root = temp_dir("cwd-projection-churn");
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let projection = Arc::new(CwdProjection::default());
        let mut observer = projection.observer();
        let short = [json!({"cwd": "/s"})];
        for index in 0..2_000 {
            let path = root.join(format!("short-{index:04}.jsonl"));
            fs::write(&path, "").unwrap();
            let view = claude_view(&path, start, DeliveryMode::Full);
            deliver(&mut observer, &view, &short, DeliveryEnd::Complete);
            assert!(within_charge(&projection.lock()));
        }
        assert_eq!(projection.lock().files.len(), 2_000);

        // Newer large files evict the short ones, whose tombstones lower the
        // reported capacity; the table's slots stay bounded throughout.
        let large: Vec<Value> = (0..OBSERVED_CWDS_PER_FILE)
            .map(|i| json!({"cwd": format!("/{i}{}", "c".repeat(OBSERVED_CWD_MAX_BYTES - 2))}))
            .collect();
        for index in 0..130u64 {
            let path = root.join(format!("large-{index:03}.jsonl"));
            fs::write(&path, "").unwrap();
            let view = claude_view(
                &path,
                start + Duration::from_secs(index + 1),
                DeliveryMode::Full,
            );
            deliver(&mut observer, &view, &large, DeliveryEnd::Complete);
            assert!(within_charge(&projection.lock()));
        }
        let state = projection.lock();
        assert_eq!((state.files.len(), state.evicted_files), (126, 2_004));
        drop(state);

        // A cycle that forgets every file releases the table.
        let later = start + RECENT_WORKSPACE_WINDOW * 2;
        assert!(projection.recent_cwds(later).is_empty());
        let state = projection.lock();
        assert_eq!(
            (state.bytes, state.table_slots, state.files.capacity()),
            (0, 0, 0)
        );
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn request_hash_ignores_machine_and_workspace_metadata() {
        let parsed = parse_context_markdown(
            r#"**Model:** claude
**Tokens:** 10 / 100 (10%)
### Estimated usage by category
| Category | Tokens | Percentage |
|---|---:|---:|
| Free space | 90 | 90% |
"#,
        )
        .unwrap();
        let hash = request_content_hash(&parsed).unwrap();
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, request_content_hash(&parsed).unwrap());
    }

    fn sample_request() -> ContextFootprintIngestRequest {
        ContextFootprintIngestRequest {
            agent_source: "claude-code".to_string(),
            machine_id: "machine-a".to_string(),
            workspace_hash: "workspace-a".to_string(),
            workspace_label: Some("coding-agents-observability".to_string()),
            workspace_label_source: Some("directory_name".to_string()),
            repository_hash: Some("repo-a".to_string()),
            repository_label: Some("coding-agents-observability".to_string()),
            repository_label_source: Some("git_root".to_string()),
            repository_identity_source: Some("git_common_dir".to_string()),
            workspace_kind: Some("repository_root".to_string()),
            config_hash: "config-a".to_string(),
            captured_at: "2026-07-05T00:00:00Z".to_string(),
            collector_version: "0.1.69".to_string(),
            counter_source: "claude_code_context_v1".to_string(),
            model: "claude".to_string(),
            used_tokens: 10,
            context_window_tokens: 100,
            pct_context: 10.0,
            free_space_tokens: Some(90),
            categories: vec![ContextFootprintCategoryInput {
                name: "Free space".to_string(),
                tokens: 90,
                pct: 90.0,
                loading_mode: "unknown".to_string(),
            }],
            memory_files: Vec::new(),
            skills: Vec::new(),
            custom_agents: Vec::new(),
            mcp_tools: Vec::new(),
            instruction_inventory: None,
        }
    }

    #[test]
    fn request_upload_cache_hash_tracks_repository_identity_and_label_policy() {
        let base = sample_request();
        let mut legacy_shape = base.clone();
        legacy_shape.repository_hash = None;
        legacy_shape.repository_label = None;
        legacy_shape.repository_label_source = None;
        legacy_shape.repository_identity_source = None;
        legacy_shape.workspace_kind = None;
        let mut labels_disabled = base.clone();
        labels_disabled.workspace_label = None;
        labels_disabled.workspace_label_source = None;
        labels_disabled.repository_label = None;
        labels_disabled.repository_label_source = None;

        let base_hash = request_content_hash_for_request(&base).unwrap();
        assert_eq!(base_hash.len(), 64);
        assert_ne!(
            base_hash,
            request_content_hash_for_request(&legacy_shape).unwrap()
        );
        assert_ne!(
            base_hash,
            request_content_hash_for_request(&labels_disabled).unwrap()
        );
    }

    #[test]
    fn instruction_inventory_rides_upload_digest_only_when_present() {
        let without = sample_request();
        // Without a block the digest is the previous algorithm's, unchanged.
        let previous = serde_json::to_vec(&json!({
            "cache_schema": "context_footprint_request_v3",
            "agent_source": &without.agent_source,
            "machine_id": &without.machine_id,
            "workspace_hash": &without.workspace_hash,
            "workspace_label": &without.workspace_label,
            "workspace_label_source": &without.workspace_label_source,
            "repository_hash": &without.repository_hash,
            "repository_label": &without.repository_label,
            "repository_label_source": &without.repository_label_source,
            "repository_identity_source": &without.repository_identity_source,
            "workspace_kind": &without.workspace_kind,
            "config_hash": &without.config_hash,
            "collector_version": &without.collector_version,
            "counter_source": &without.counter_source,
            "model": &without.model,
            "used_tokens": without.used_tokens,
            "context_window_tokens": without.context_window_tokens,
            "pct_context": without.pct_context,
            "free_space_tokens": without.free_space_tokens,
            "categories": &without.categories,
            "memory_files": &without.memory_files,
            "skills": &without.skills,
            "custom_agents": &without.custom_agents,
            "mcp_tools": &without.mcp_tools,
        }))
        .unwrap();
        assert_eq!(
            request_content_hash_for_request(&without).unwrap(),
            sha256_bytes(&previous)
        );
        let encoded = serde_json::to_value(&without).unwrap();
        assert!(encoded.get("instruction_inventory").is_none());
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../fixtures/context-footprint/instruction-inventory-v1.json"
        ))
        .unwrap();
        let inventory: InstructionInventory = serde_json::from_value(
            fixture["variants"]["default_mode"]["instruction_inventory"].clone(),
        )
        .unwrap();
        let mut with = without.clone();
        with.instruction_inventory = Some(inventory.clone());
        assert_eq!(
            serde_json::to_value(&with).unwrap()["instruction_inventory"],
            fixture["variants"]["default_mode"]["instruction_inventory"]
        );
        let mut resized = with.clone();
        resized
            .instruction_inventory
            .as_mut()
            .unwrap()
            .files
            .entries[3]
            .file_bytes += 1;
        let hashes = [&without, &with, &resized]
            .map(|request| request_content_hash_for_request(request).unwrap());
        assert_ne!(hashes[0], hashes[1]);
        assert_ne!(hashes[1], hashes[2]);
        // Identical captures keep one digest; each state change uploads once.
        assert_eq!(hashes[1], request_content_hash_for_request(&with).unwrap());
        let mut withheld = without.clone();
        withheld.instruction_inventory = Some(
            serde_json::from_value(
                fixture["variants"]["labels_off"]["instruction_inventory"].clone(),
            )
            .unwrap(),
        );
        let withheld_hash = request_content_hash_for_request(&withheld).unwrap();
        assert_eq!(
            withheld_hash,
            request_content_hash_for_request(&withheld).unwrap()
        );
        assert!(!hashes.contains(&withheld_hash));
    }

    #[test]
    fn instruction_paths_need_an_explicit_labels_on_hint() {
        let hint = |extra: &str| {
            crate::snapshot_client::decode_activity_hint(
                serde_json::from_str(&format!(
                    r#"{{"source":"claude_code","server_time":"2026-10-22T10:00:00Z","last_data_at":null,
                    "record_count_15m":0,"record_count_24h":0,"local_usage_reconciliation_enabled":true,
                    "backfill_window_days":183,"recommended_scan_after":"2026-10-22T10:05:00Z"{extra}}}"#
                ))
                .unwrap(),
            )
            .unwrap()
        };
        let omitted = hint("");
        // Labels keep their legacy default; the inventory does not.
        assert!(omitted.workspace_labels_enabled);
        assert_eq!(inventory_paths(Some(&omitted)), None);
        assert_eq!(
            inventory_paths(Some(&hint(r#","workspace_labels_enabled":false"#))),
            Some(InventoryPaths::Withhold)
        );
        assert_eq!(
            inventory_paths(Some(&hint(r#","workspace_labels_enabled":true"#))),
            Some(InventoryPaths::Collect)
        );
        assert_eq!(inventory_paths(None), None);
    }

    #[test]
    fn capped_git_output_drains_large_output_and_refuses_over_cap() {
        let repo = init_git_repo("git-capped");
        let blob = repo.join("blob");
        fs::write(&blob, "x".repeat(300_000)).unwrap();
        let output = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["hash-object", "-w", "blob"])
            .output()
            .unwrap();
        let id = String::from_utf8(output.stdout).unwrap().trim().to_string();
        let args = ["cat-file", "-p", id.as_str()];
        assert_eq!(
            git_stdout_capped(&repo, &args, GIT_STDOUT_MAX_BYTES)
                .unwrap()
                .len(),
            300_000
        );
        assert_eq!(
            git_stdout_capped(&repo, &args, 100_000),
            Err(GitOutputError::TooLarge)
        );
        assert_eq!(
            git_stdout_capped(&repo, &["cat-file", "-p", "missing"], 1024),
            Err(GitOutputError::Failed)
        );
        // A descendant still holding stdout cannot hold the caller past the
        // timeout; the reader thread finishes once the pipe closes.
        let started = Instant::now();
        assert_eq!(
            git_stdout_capped(&repo, &["-c", "alias.slow=!sleep 4", "slow"], 1024),
            Err(GitOutputError::TimedOut)
        );
        assert!(started.elapsed() < GIT_COMMAND_TIMEOUT + Duration::from_secs(1));
        // Non-ASCII output keeps the 4,096-character (not byte) result.
        fs::write(repo.join("wide"), "\u{e9}".repeat(5000)).unwrap();
        let output = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["hash-object", "-w", "wide"])
            .output()
            .unwrap();
        let wide = String::from_utf8(output.stdout).unwrap().trim().to_string();
        assert_eq!(
            git_stdout(&repo, &["cat-file", "-p", wide.as_str()]),
            Some("\u{e9}".repeat(4096))
        );
        fs::remove_dir_all(repo).unwrap();
    }
}
