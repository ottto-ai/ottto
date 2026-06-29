//! Claude Code `/context` footprint harvest.
//!
//! This is a low-cadence, per-workspace collector for the static context
//! footprint Claude Code reports from `/context`: category totals plus memory
//! files, skills, and custom agents. It is intentionally separate from
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
const CONTEXT_COMMAND_TIMEOUT: Duration = Duration::from_secs(25);
const CONTEXT_CYCLE_BUDGET: Duration = Duration::from_secs(5 * 60);
const CONTEXT_MAX_STALENESS_SECS: i64 = 7 * 24 * 60 * 60;
const RECENT_WORKSPACE_WINDOW: Duration = Duration::from_secs(14 * 24 * 60 * 60);
const MAX_WORKSPACES_PER_CYCLE: usize = 12;

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
struct ContextFootprintIngestRequest {
    agent_source: String,
    machine_id: String,
    workspace_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_label_source: Option<String>,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkspaceCandidate {
    path: PathBuf,
    last_seen: SystemTime,
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
            if !hint.context_footprint_harvest_enabled {
                write_marker(&marker, &identity);
                return Ok(());
            }
            let _ = fs::remove_file(&marker);
        }
        Err(_) if read_marker(&marker).as_deref() == Some(identity.as_str()) => return Ok(()),
        Err(_) => {}
    }

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
    for workspace in workspaces {
        if Instant::now() >= deadline {
            break;
        }
        match build_request_for_workspace(&workspace.path, machine_id, &env) {
            Ok(request) => {
                match upload_if_changed(client, &relay_token, support_dir, &identity, &request) {
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

fn build_request_for_workspace(
    workspace: &Path,
    machine_id: &str,
    env: &SpawnEnv,
) -> Result<ContextFootprintIngestRequest> {
    let stdout = run_claude_context(workspace, env)?;
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
    let config_hash = request_content_hash(&parsed)?;
    Ok(ContextFootprintIngestRequest {
        agent_source: "claude-code".to_string(),
        machine_id: machine_id.to_string(),
        workspace_hash,
        workspace_label: workspace_label(workspace),
        workspace_label_source: Some("directory_name".to_string()),
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
    })
}

fn run_claude_context(workspace: &Path, env: &SpawnEnv) -> Result<String> {
    let mut command = env.claude_command()?;
    command
        .current_dir(workspace)
        .args([
            "-p",
            "/context",
            "--output-format",
            "json",
            "--strict-mcp-config",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
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
            Ok(None) if started.elapsed() >= CONTEXT_COMMAND_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(anyhow!("Claude Code /context timed out"));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => return Err(anyhow!("Claude Code /context status could not be read")),
        }
    }
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

fn safe_text(raw: &str, max_len: usize) -> Option<String> {
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
    candidates
}

fn collect_recent_jsonl_files(dir: &Path, now: SystemTime, out: &mut Vec<(PathBuf, SystemTime)>) {
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
    }))
    .map_err(|error| anyhow!("hash encode failed: {error}"))?;
    Ok(sha256_bytes(&canonical))
}

fn request_content_hash_for_request(request: &ContextFootprintIngestRequest) -> Result<String> {
    let canonical = serde_json::to_vec(&json!({
        "model": &request.model,
        "used_tokens": request.used_tokens,
        "context_window_tokens": request.context_window_tokens,
        "pct_context": request.pct_context,
        "free_space_tokens": request.free_space_tokens,
        "categories": &request.categories,
        "memory_files": &request.memory_files,
        "skills": &request.skills,
        "custom_agents": &request.custom_agents,
    }))
    .map_err(|error| anyhow!("hash encode failed: {error}"))?;
    Ok(sha256_bytes(&canonical))
}

fn sha256_hex(parts: &[&str]) -> String {
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

fn workspace_label(workspace: &Path) -> Option<String> {
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
"#,
        )
        .expect("parse");

        assert_eq!(parsed.model, "claude-opus-4-8");
        assert_eq!(parsed.used_tokens, 42_200);
        assert_eq!(parsed.context_window_tokens, 1_000_000);
        assert_eq!(parsed.free_space_tokens, Some(957_800));
        assert_eq!(parsed.categories.len(), 4);
        assert_eq!(parsed.categories[1].loading_mode, "on_demand");
        assert_eq!(parsed.memory_files[0].name, "CLAUDE.md");
        assert_eq!(
            parsed.memory_files[0].relative_path.as_deref(),
            Some("CLAUDE.md")
        );
        assert_eq!(parsed.skills[0].name, "frontend-flow-change");
        assert_eq!(parsed.custom_agents[0].name, "reviewer");
        let encoded = serde_json::to_string(&parsed.memory_files).unwrap();
        assert!(!encoded.contains("/Users/example"));
    }

    #[test]
    fn token_parser_handles_suffixes() {
        assert_eq!(parse_token_count("42.2k"), Some(42_200));
        assert_eq!(parse_token_count("1m"), Some(1_000_000));
        assert_eq!(parse_token_count("8"), Some(8));
        assert_eq!(parse_percent("95.8%"), Some(95.8));
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
}
