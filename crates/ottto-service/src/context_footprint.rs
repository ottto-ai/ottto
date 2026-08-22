//! Claude Code `/context` footprint harvest.
//!
//! This is a low-cadence, per-workspace collector for the static context
//! footprint Claude Code reports from `/context`: category totals plus memory
//! files, skills, custom agents, and a bounded sample of MCP tool token costs.
//! It is intentionally separate from
//! `AgentContextStatus`/`context_live`, which reflects active session load from
//! statusLine `context_window`.

use crate::snapshot_client::{load_snapshot_device_credentials, SnapshotApiClient};
use crate::snapshots::SnapshotSource;
use anyhow::{anyhow, Result};
use ottto_core::{compiled_release_version, default_support_dir, LocalDeviceBinding};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const CONTEXT_FOOTPRINT_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const CONTEXT_COMMAND_TIMEOUT_SECS: u64 = 25;
const CONTEXT_MCP_COMMAND_TIMEOUT_SECS: u64 = 120;
const CONTEXT_COMMAND_TIMEOUT: Duration = Duration::from_secs(CONTEXT_COMMAND_TIMEOUT_SECS);
const CONTEXT_MCP_COMMAND_TIMEOUT: Duration = Duration::from_secs(CONTEXT_MCP_COMMAND_TIMEOUT_SECS);
const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
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
struct ContextFootprintCategoryInput {
    name: String,
    tokens: u64,
    pct: f64,
    loading_mode: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct ContextFootprintItemInput {
    kind: String,
    name: String,
    tokens: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relative_path: Option<String>,
    loading_mode: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct ContextFootprintMcpToolInput {
    name: String,
    server: String,
    tokens: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct ContextFootprintIngestRequest {
    agent_source: String,
    machine_id: String,
    workspace_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_label_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repository_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repository_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repository_label_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repository_identity_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_kind: Option<String>,
    config_hash: String,
    captured_at: String,
    collector_version: String,
    counter_source: String,
    model: String,
    used_tokens: u64,
    context_window_tokens: u64,
    pct_context: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    free_space_tokens: Option<u64>,
    categories: Vec<ContextFootprintCategoryInput>,
    memory_files: Vec<ContextFootprintItemInput>,
    skills: Vec<ContextFootprintItemInput>,
    custom_agents: Vec<ContextFootprintItemInput>,
    mcp_tools: Vec<ContextFootprintMcpToolInput>,
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

pub fn spawn_context_footprint_sync() -> Result<()> {
    let home = crate::snapshot_sync::home_dir()?;
    let support_dir = default_support_dir();
    std::thread::Builder::new()
        .name("ottto-context-footprint-sync".to_string())
        .spawn(move || loop {
            if let Err(error) = harvest_all_once(&home, &support_dir) {
                eprintln!(
                    "context footprint harvest skipped: {}",
                    crate::snapshot_sync::safe_error(&error)
                );
            }
            std::thread::sleep(CONTEXT_FOOTPRINT_INTERVAL);
        })
        .map_err(|error| anyhow!("spawn context footprint sync: {error}"))?;
    Ok(())
}

fn harvest_all_once(home: &Path, support_dir: &Path) -> Result<()> {
    if local_harvest_disabled(support_dir) {
        return Ok(());
    }
    let (device, device_secret) = load_snapshot_device_credentials()?;
    if !crate::snapshot_sync::enabled_snapshot_sources(&device)
        .into_iter()
        .any(|source| matches!(source, SnapshotSource::ClaudeCode))
    {
        return Ok(());
    }
    let Some(machine_id) = crate::snapshot_sync::snapshot_machine_id(&device)? else {
        return Err(anyhow!("machine identity is missing"));
    };
    let api_base_url = crate::snapshot_sync::snapshot_api_base_url();
    let client = SnapshotApiClient::new(api_base_url.clone());
    harvest_source(
        &client,
        &device,
        &device_secret,
        &machine_id,
        &api_base_url,
        home,
        support_dir,
    )
}

fn harvest_source(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    machine_id: &str,
    api_base_url: &str,
    home: &Path,
    support_dir: &Path,
) -> Result<()> {
    let relay_token =
        client.issue_relay_token(device, device_secret, SnapshotSource::ClaudeCode)?;
    let identity = destination_identity(device, machine_id, api_base_url);
    let marker = org_disabled_marker_path(support_dir);
    match client.get_activity_hint(&relay_token) {
        Ok(hint) => {
            let workspace_labels_enabled = hint.workspace_labels_enabled;
            if !hint.context_footprint_harvest_enabled {
                write_marker(&marker, &identity);
                return Ok(());
            }
            let _ = fs::remove_file(&marker);
            harvest_recent_workspaces(
                client,
                &relay_token,
                support_dir,
                &identity,
                home,
                machine_id,
                workspace_labels_enabled,
            )?;
            return Ok(());
        }
        Err(_) if read_marker(&marker).as_deref() == Some(identity.as_str()) => return Ok(()),
        Err(_) => {}
    }

    harvest_recent_workspaces(
        client,
        &relay_token,
        support_dir,
        &identity,
        home,
        machine_id,
        true,
    )
}

fn harvest_recent_workspaces(
    client: &SnapshotApiClient,
    relay_token: &str,
    support_dir: &Path,
    identity: &str,
    home: &Path,
    machine_id: &str,
    workspace_labels_enabled: bool,
) -> Result<()> {
    let now = SystemTime::now();
    let mut workspaces = discover_recent_claude_workspaces(home, now);
    workspaces.truncate(MAX_WORKSPACES_PER_CYCLE);
    if workspaces.is_empty() {
        return Ok(());
    }

    let env = SpawnEnv::resolve();
    let deadline = Instant::now() + CONTEXT_CYCLE_BUDGET;
    let mut uploaded = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;
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
            include_mcp_servers,
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
        "context_footprint_harvest_metrics discovered={} uploaded={} skipped={} failed={}",
        uploaded + skipped + failed,
        uploaded,
        skipped,
        failed
    );
    if failed > 0 && uploaded == 0 && skipped == 0 {
        return Err(anyhow!(
            "context footprint harvest failed for all workspaces"
        ));
    }
    Ok(())
}

fn should_include_mcp_servers(workspace_index: usize) -> bool {
    workspace_index == 0
}

fn build_request_for_workspace(
    workspace: &Path,
    machine_id: &str,
    env: &SpawnEnv,
    workspace_labels_enabled: bool,
    include_mcp_servers: bool,
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
    })
}

fn run_claude_context(
    workspace: &Path,
    env: &SpawnEnv,
    include_mcp_servers: bool,
) -> Result<String> {
    let mut command = env.claude_command()?;
    command
        .current_dir(workspace)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let command_timeout = configure_claude_context_command(&mut command, include_mcp_servers);
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
                let _ = child.kill();
                let _ = child.wait();
                return Err(anyhow!("Claude Code /context timed out"));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => return Err(anyhow!("Claude Code /context status could not be read")),
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
    let Some(toplevel_raw) = git_stdout(workspace, &["rev-parse", "--show-toplevel"]) else {
        return RepositoryIdentity {
            repository_hash: None,
            repository_label: None,
            repository_label_source: None,
            repository_identity_source: None,
            workspace_kind: Some("non_git".to_string()),
        };
    };
    let toplevel = absolutize_git_path(workspace, &toplevel_raw);
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

fn git_stdout(workspace: &Path, args: &[&str]) -> Option<String> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child.wait_with_output().ok()?;
                if !status.success() {
                    return None;
                }
                let text = String::from_utf8(output.stdout).ok()?;
                let trimmed = text.trim();
                if trimmed.is_empty() {
                    return None;
                }
                return Some(trimmed.chars().take(4096).collect());
            }
            Ok(None) if started.elapsed() >= GIT_COMMAND_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => return None,
        }
    }
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
    })
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

fn discover_recent_claude_workspaces(home: &Path, now: SystemTime) -> Vec<WorkspaceCandidate> {
    let mut files = Vec::new();
    collect_recent_jsonl_files(&home.join(".claude").join("projects"), now, &mut files);
    files.sort_by_key(|item| std::cmp::Reverse(item.1));
    let mut by_path: BTreeMap<String, WorkspaceCandidate> = BTreeMap::new();
    for (file, mtime) in files {
        for cwd in cwd_values_from_jsonl(&file) {
            let path = PathBuf::from(&cwd);
            if !path.is_dir() {
                continue;
            }
            let key = path.to_string_lossy().to_string();
            by_path
                .entry(key)
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
    dedupe_workspace_candidates_by_repository(candidates)
}

fn dedupe_workspace_candidates_by_repository(
    candidates: Vec<WorkspaceCandidate>,
) -> Vec<WorkspaceCandidate> {
    let mut by_scope: BTreeMap<String, WorkspaceCandidate> = BTreeMap::new();
    for candidate in candidates {
        let repository_identity = resolve_repository_identity(&candidate.path, false);
        let fallback_text = candidate.path.to_string_lossy();
        let scope = repository_identity
            .repository_hash
            .unwrap_or_else(|| sha256_hex(&[fallback_text.as_ref()]));
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
    out
}

pub(crate) fn collect_recent_jsonl_files(
    dir: &Path,
    now: SystemTime,
    out: &mut Vec<(PathBuf, SystemTime)>,
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
            collect_recent_jsonl_files(&path, now, out);
            continue;
        }
        if path.extension().and_then(|value| value.to_str()) != Some("jsonl") {
            continue;
        }
        let mtime = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        if now.duration_since(mtime).unwrap_or(Duration::ZERO) <= RECENT_WORKSPACE_WINDOW {
            out.push((path, mtime));
        }
    }
}

pub(crate) fn cwd_values_from_jsonl(path: &Path) -> Vec<String> {
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

fn request_content_hash_for_request(request: &ContextFootprintIngestRequest) -> Result<String> {
    let canonical = serde_json::to_vec(&json!({
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
    }))
    .map_err(|error| anyhow!("hash encode failed: {error}"))?;
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
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(name: &str) -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ottto-context-footprint-{name}-{}-{counter}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
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
    fn token_parser_handles_suffixes() {
        assert_eq!(parse_token_count("42.2k"), Some(42_200));
        assert_eq!(parse_token_count("1m"), Some(1_000_000));
        assert_eq!(parse_token_count("8"), Some(8));
        assert_eq!(parse_percent("95.8%"), Some(95.8));
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

        let discovered = discover_recent_claude_workspaces(&home, SystemTime::now());

        assert_eq!(discovered.len(), 1);
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
    fn repository_identity_respects_label_privacy() {
        let repo = init_git_repo("repo-identity-private-labels");

        let identity = resolve_repository_identity(&repo, false);

        assert!(identity.repository_hash.is_some());
        assert!(identity.repository_label.is_none());
        assert!(identity.repository_label_source.is_none());
        assert_eq!(identity.workspace_kind.as_deref(), Some("repository_root"));
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

        let out = dedupe_workspace_candidates_by_repository(vec![
            WorkspaceCandidate {
                path: repo.clone(),
                last_seen: older,
            },
            WorkspaceCandidate {
                path: subdir.clone(),
                last_seen: newer,
            },
        ]);

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].path, subdir);
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn cache_freshness_tracks_max_staleness() {
        let now = OffsetDateTime::from_unix_timestamp(1_750_000_000).unwrap();
        let entry = FootprintCacheEntry {
            identity: "device|machine|api".to_string(),
            footprint_sha256: "abc".to_string(),
            posted_at: now.format(&Rfc3339).unwrap(),
        };
        assert!(!cache_is_stale(&entry, now));
        assert!(!cache_is_stale(
            &entry,
            now + time::Duration::seconds(CONTEXT_MAX_STALENESS_SECS - 1)
        ));
        assert!(cache_is_stale(
            &entry,
            now + time::Duration::seconds(CONTEXT_MAX_STALENESS_SECS)
        ));
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
}
