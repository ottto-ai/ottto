//! Configured-MCP context-footprint harvest.
//!
//! On each periodic snapshot sync this module discovers the MCP servers each
//! coding agent has configured (Claude Code, Codex), runs the MCP
//! `initialize` + `tools/list` handshake against every reachable server, and
//! POSTs the raw `tools/list` output to the backend ingest endpoint
//! `POST /api/v1/mcp/inventory`. The backend tokenizes the schemas and persists
//! the footprint; the daemon only sends the unweighted tool definitions.
//!
//! This is the daemon port of the reference Python harvester
//! (`backend/scripts/mcp_footprint/harvest.py`). It reuses the snapshot client's
//! device-credential / relay-token auth and API base-URL resolution, and never
//! logs server commands, arguments, URLs, environment, or tool schemas (any of
//! which can embed secrets or local paths).
//!
//! Transport coverage: **stdio is fully implemented** (the common transport for
//! locally configured MCP servers). Streamable HTTP and SSE servers are
//! discovered and reported as `reachable = false` with empty tools (cost zero)
//! until a network MCP client lands — see `TODO(mcp-http-transport)` below.

use crate::snapshot_client::{load_snapshot_device_credentials, SnapshotApiClient};
use crate::snapshots::SnapshotSource;
use anyhow::{anyhow, Result};
use ottto_core::{default_support_dir, LocalDeviceBinding};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// Per-server handshake budget. Generous because a cold MCP server may need to
/// install/launch a runtime, but bounded so one slow server cannot stall the
/// sync loop. Mirrors harvest.py's 45s ceiling.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(45);

/// How often the harvest loop runs. Deliberately slow: a harvest spawns every
/// configured MCP server's stdio process, so the cost belongs on a 6-hourly
/// cadence (run-at-start + every 6 h), not the 5-minute snapshot sync. The
/// per-server schema cost only changes when the user edits their MCP config.
const MCP_HARVEST_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Even when the inventory is byte-identical, re-POST at least this often so the
/// snapshot's `captured_at` stays fresh and a long-running machine never reads as
/// stale on the Optimize page. Between these, an unchanged inventory is skipped
/// entirely (no relay token minted, no POST).
const MCP_HARVEST_MAX_STALENESS_SECS: i64 = 7 * 24 * 60 * 60;

/// MCP protocol revision we advertise on `initialize`. Servers negotiate down
/// if they only speak an older revision; `tools/list` is stable across these.
const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

/// Default Claude-class context window used as the `% of context` denominator
/// when no explicit window is known. Matches the backend default.
const DEFAULT_CONTEXT_WINDOW_TOKENS: i64 = 200_000;

// ---------------------------------------------------------------------------
// Discovered config model
// ---------------------------------------------------------------------------

/// How a configured MCP server is reached.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Transport {
    Stdio {
        command: String,
        args: Vec<String>,
    },
    /// Streamable HTTP transport. Not yet harvested (see module docs).
    Http {
        url: String,
    },
    /// Legacy SSE transport. Not yet harvested (see module docs).
    Sse {
        url: String,
    },
}

impl Transport {
    /// The wire label persisted on the inventory (`transport` field).
    fn label(&self) -> &'static str {
        match self {
            Transport::Stdio { .. } => "stdio",
            Transport::Http { .. } => "http",
            Transport::Sse { .. } => "sse",
        }
    }
}

/// One configured MCP server, keyed by its config name.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfiguredServer {
    name: String,
    transport: Transport,
}

// ---------------------------------------------------------------------------
// Wire types (port of McpInventoryIngestRequest)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
struct McpToolInput {
    name: String,
    description: String,
    input_schema: Value,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct McpServerInput {
    server: String,
    transport: Option<String>,
    reachable: bool,
    loading_mode: String,
    tools: Vec<McpToolInput>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct McpInventoryIngestRequest {
    agent_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    machine_id: Option<String>,
    context_window_tokens: i64,
    servers: Vec<McpServerInput>,
}

// ---------------------------------------------------------------------------
// Loading mode
// ---------------------------------------------------------------------------

/// How an agent loads MCP tool schemas into context.
///
/// Claude Code defers MCP schemas (tool-search / on-demand); Codex loads them
/// eagerly every turn. Mirrors `_effective_loading_mode` in harvest.py.
fn loading_mode_for(source: SnapshotSource) -> &'static str {
    match source {
        SnapshotSource::ClaudeCode => "on_demand",
        SnapshotSource::Codex => "always_on",
        SnapshotSource::Pi => "unknown",
    }
}

/// The `agent_source` string the backend expects for an MCP inventory.
fn agent_source_for(source: SnapshotSource) -> &'static str {
    match source {
        SnapshotSource::ClaudeCode => "claude-code",
        SnapshotSource::Codex => "codex",
        SnapshotSource::Pi => "pi",
    }
}

// ---------------------------------------------------------------------------
// Config discovery
// ---------------------------------------------------------------------------

fn load_json(path: &Path) -> Option<Value> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Normalize one Claude Code MCP server config block into a [`Transport`].
///
/// Mirrors `_normalize_claude_server` in harvest.py: an explicit `type: "sse"`
/// or `type: "http"` (or a bare `url`) is a network transport; everything else
/// is treated as stdio with `command` + `args`.
fn normalize_claude_server(name: &str, cfg: &Value) -> Option<ConfiguredServer> {
    let declared = cfg.get("type").and_then(Value::as_str);
    let url = cfg.get("url").and_then(Value::as_str);
    let transport = if declared == Some("sse") {
        Transport::Sse {
            url: url?.to_string(),
        }
    } else if url.is_some() || declared == Some("http") {
        Transport::Http {
            url: url?.to_string(),
        }
    } else {
        let command = cfg.get("command").and_then(Value::as_str)?.to_string();
        let args = string_args(cfg.get("args"));
        Transport::Stdio { command, args }
    };
    Some(ConfiguredServer {
        name: name.to_string(),
        transport,
    })
}

/// Normalize one Codex `[mcp_servers.*]` block into a [`Transport`].
///
/// Mirrors `discover_codex` in harvest.py: a `url` is an HTTP transport, else
/// stdio with `command` + `args`.
fn normalize_codex_server(name: &str, cfg: &Value) -> Option<ConfiguredServer> {
    let transport = if let Some(url) = cfg.get("url").and_then(Value::as_str) {
        Transport::Http {
            url: url.to_string(),
        }
    } else {
        let command = cfg.get("command").and_then(Value::as_str)?.to_string();
        let args = string_args(cfg.get("args"));
        Transport::Stdio { command, args }
    };
    Some(ConfiguredServer {
        name: name.to_string(),
        transport,
    })
}

/// Coerce a JSON `args` value into a list of strings, dropping non-strings.
fn string_args(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Extract `mcpServers` from a JSON object as a name->config map.
fn mcp_servers_block(value: &Value) -> impl Iterator<Item = (&String, &Value)> {
    value
        .get("mcpServers")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|map| map.iter())
}

/// Discover Claude Code MCP servers across the global config and every known
/// project.
///
/// Reads, in precedence order (later wins, matching harvest.py):
///   * `~/.claude.json` top-level `mcpServers`
///   * `~/.claude.json` `projects[<dir>].mcpServers` for every project dir
///   * `<project dir>/.mcp.json` `mcpServers` for every project dir
///   * `~/.claude/settings.json` `mcpServers`
///   * `~/.claude/settings.local.json` `mcpServers`
///
/// The reference harvester is invoked with a single `--cwd`; the daemon has no
/// single project cwd, so it unions across all `projects` keys to capture every
/// configured server on the machine.
fn discover_claude_code(home: &Path) -> Vec<ConfiguredServer> {
    let mut servers: BTreeMap<String, ConfiguredServer> = BTreeMap::new();

    let claude_json = load_json(&home.join(".claude.json"));
    if let Some(root) = claude_json.as_ref() {
        // Top-level mcpServers.
        for (name, cfg) in mcp_servers_block(root) {
            if let Some(server) = normalize_claude_server(name, cfg) {
                servers.insert(name.clone(), server);
            }
        }
        // Per-project mcpServers and each project's <dir>/.mcp.json.
        if let Some(projects) = root.get("projects").and_then(Value::as_object) {
            for (project_dir, project_cfg) in projects {
                for (name, cfg) in mcp_servers_block(project_cfg) {
                    if let Some(server) = normalize_claude_server(name, cfg) {
                        servers.insert(name.clone(), server);
                    }
                }
                if let Some(dot_mcp) = load_json(&Path::new(project_dir).join(".mcp.json")) {
                    for (name, cfg) in mcp_servers_block(&dot_mcp) {
                        if let Some(server) = normalize_claude_server(name, cfg) {
                            servers.insert(name.clone(), server);
                        }
                    }
                }
            }
        }
    }

    for settings in [
        home.join(".claude").join("settings.json"),
        home.join(".claude").join("settings.local.json"),
    ] {
        if let Some(value) = load_json(&settings) {
            for (name, cfg) in mcp_servers_block(&value) {
                if let Some(server) = normalize_claude_server(name, cfg) {
                    servers.insert(name.clone(), server);
                }
            }
        }
    }

    servers.into_values().collect()
}

/// Discover Codex MCP servers from `~/.codex/config.toml` `[mcp_servers.*]`.
fn discover_codex(home: &Path) -> Vec<ConfiguredServer> {
    let path = home.join(".codex").join("config.toml");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let Ok(document) = text.parse::<toml_edit::DocumentMut>() else {
        return Vec::new();
    };
    let Some(table) = document.get("mcp_servers").and_then(|item| item.as_table()) else {
        return Vec::new();
    };
    let mut servers: BTreeMap<String, ConfiguredServer> = BTreeMap::new();
    for (name, item) in table.iter() {
        // Re-serialize the per-server sub-table to JSON via toml->json so the
        // normalizer can share Claude Code's value-shape logic.
        let Some(value) = toml_item_to_json(item) else {
            continue;
        };
        if let Some(server) = normalize_codex_server(name, &value) {
            servers.insert(name.to_string(), server);
        }
    }
    servers.into_values().collect()
}

/// Convert a `toml_edit` item into a `serde_json::Value` for the shared
/// normalizer. Only the scalar/array shapes the MCP config uses are needed.
fn toml_item_to_json(item: &toml_edit::Item) -> Option<Value> {
    let table = item.as_table_like()?;
    let mut map = Map::new();
    for (key, value) in table.iter() {
        if let Some(converted) = toml_value_to_json(value) {
            map.insert(key.to_string(), converted);
        }
    }
    Some(Value::Object(map))
}

fn toml_value_to_json(item: &toml_edit::Item) -> Option<Value> {
    if let Some(value) = item.as_value() {
        return toml_edit_value_to_json(value);
    }
    None
}

fn toml_edit_value_to_json(value: &toml_edit::Value) -> Option<Value> {
    match value {
        toml_edit::Value::String(s) => Some(Value::String(s.value().clone())),
        toml_edit::Value::Integer(i) => Some(json!(i.value())),
        toml_edit::Value::Boolean(b) => Some(Value::Bool(*b.value())),
        toml_edit::Value::Float(f) => Some(json!(f.value())),
        toml_edit::Value::Array(array) => Some(Value::Array(
            array.iter().filter_map(toml_edit_value_to_json).collect(),
        )),
        toml_edit::Value::InlineTable(table) => {
            let mut map = Map::new();
            for (key, value) in table.iter() {
                if let Some(converted) = toml_edit_value_to_json(value) {
                    map.insert(key.to_string(), converted);
                }
            }
            Some(Value::Object(map))
        }
        // Inline datetimes are not part of MCP server config; skip.
        toml_edit::Value::Datetime(_) => None,
    }
}

fn discover_servers(home: &Path, source: SnapshotSource) -> Vec<ConfiguredServer> {
    match source {
        SnapshotSource::ClaudeCode => discover_claude_code(home),
        SnapshotSource::Codex => discover_codex(home),
        SnapshotSource::Pi => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// stdio MCP handshake
// ---------------------------------------------------------------------------

/// Run `initialize` + `tools/list` against a stdio MCP server and return its
/// tool definitions. A handshake-thread + channel keeps the bounded wait off
/// the sync thread; the child is always killed on timeout or error so no
/// process is leaked.
fn harvest_stdio(command: &str, args: &[String]) -> Result<Vec<McpToolInput>> {
    let mut child = Command::new(command)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| anyhow!("spawn mcp server failed: {error}"))?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("mcp server stdin unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("mcp server stdout unavailable"))?;

    let (tx, rx) = mpsc::channel::<Result<Vec<McpToolInput>>>();
    // The handshake runs on its own thread so the read loop can be abandoned on
    // timeout without blocking the sync thread. The thread owns stdin/stdout and
    // drops them when it returns, closing the pipes.
    std::thread::Builder::new()
        .name("ottto-mcp-handshake".to_string())
        .spawn(move || {
            let _ = tx.send(run_stdio_handshake(stdin, stdout));
        })
        .map_err(|error| anyhow!("spawn mcp handshake thread failed: {error}"))?;

    match rx.recv_timeout(HANDSHAKE_TIMEOUT) {
        Ok(result) => {
            reap_child(&mut child);
            result
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // Kill the child; the detached handshake thread unblocks on the
            // closed pipe and exits, then its send fails silently.
            reap_child(&mut child);
            Err(anyhow!("mcp handshake timed out"))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            reap_child(&mut child);
            Err(anyhow!("mcp handshake thread ended unexpectedly"))
        }
    }
}

fn reap_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Drive the JSON-RPC handshake over the child's stdio pipes.
///
/// Sends `initialize`, then the `notifications/initialized` notification, then
/// `tools/list`, reading newline-delimited JSON-RPC responses and matching them
/// by request id. Tolerates interleaved server-initiated messages.
fn run_stdio_handshake(
    mut stdin: std::process::ChildStdin,
    stdout: std::process::ChildStdout,
) -> Result<Vec<McpToolInput>> {
    let mut reader = BufReader::new(stdout);

    write_message(&mut stdin, &initialize_request())?;
    let _ = read_response(&mut reader, 1)?;

    write_message(&mut stdin, &initialized_notification())?;
    write_message(&mut stdin, &tools_list_request())?;
    let response = read_response(&mut reader, 2)?;

    Ok(parse_tools(&response))
}

fn initialize_request() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "ottto-service", "version": env!("CARGO_PKG_VERSION") }
        }
    })
}

fn initialized_notification() -> Value {
    json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })
}

fn tools_list_request() -> Value {
    json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" })
}

fn write_message(stdin: &mut impl Write, message: &Value) -> Result<()> {
    let mut line =
        serde_json::to_vec(message).map_err(|error| anyhow!("encode failed: {error}"))?;
    line.push(b'\n');
    stdin
        .write_all(&line)
        .map_err(|error| anyhow!("write to mcp server failed: {error}"))?;
    stdin
        .flush()
        .map_err(|error| anyhow!("flush to mcp server failed: {error}"))?;
    Ok(())
}

/// Read newline-delimited JSON-RPC messages until one carries the expected
/// `id`. Notifications and unrelated ids are skipped; an error response for the
/// matched id surfaces as an error.
fn read_response(reader: &mut impl BufRead, expected_id: i64) -> Result<Value> {
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .map_err(|error| anyhow!("read from mcp server failed: {error}"))?;
        if read == 0 {
            return Err(anyhow!("mcp server closed before responding"));
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(message) = serde_json::from_str::<Value>(trimmed) else {
            // Non-JSON banner lines from a misbehaving server are skipped.
            continue;
        };
        if message.get("id").and_then(Value::as_i64) != Some(expected_id) {
            continue;
        }
        if let Some(error) = message.get("error") {
            let code = error
                .get("code")
                .and_then(Value::as_i64)
                .unwrap_or_default();
            return Err(anyhow!("mcp server returned error (code {code})"));
        }
        return Ok(message);
    }
}

/// Extract `{name, description, input_schema}` from a `tools/list` response,
/// matching the backend's `McpToolInput` shape.
fn parse_tools(response: &Value) -> Vec<McpToolInput> {
    response
        .get("result")
        .and_then(|result| result.get("tools"))
        .and_then(Value::as_array)
        .map(|tools| {
            tools
                .iter()
                .map(|tool| McpToolInput {
                    name: tool
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    description: tool
                        .get("description")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    input_schema: tool
                        .get("inputSchema")
                        .cloned()
                        .unwrap_or_else(|| json!({})),
                })
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Inventory assembly
// ---------------------------------------------------------------------------

/// Harvest one configured server into its wire shape. An unreachable server (or
/// an unimplemented network transport) is reported with `reachable = false` and
/// no tools, so it contributes zero context cost.
fn harvest_server(server: &ConfiguredServer, loading_mode: &str) -> McpServerInput {
    let tools = match &server.transport {
        Transport::Stdio { command, args } => harvest_stdio(command, args).ok(),
        // TODO(mcp-http-transport): implement Streamable HTTP + SSE handshakes.
        // Until then network servers are reported unreachable (cost zero) rather
        // than fabricating a footprint.
        Transport::Http { .. } | Transport::Sse { .. } => None,
    };
    match tools {
        Some(tools) => McpServerInput {
            server: server.name.clone(),
            transport: Some(server.transport.label().to_string()),
            reachable: true,
            loading_mode: loading_mode.to_string(),
            tools,
        },
        None => McpServerInput {
            server: server.name.clone(),
            transport: Some(server.transport.label().to_string()),
            reachable: false,
            loading_mode: loading_mode.to_string(),
            tools: Vec::new(),
        },
    }
}

/// Build the full inventory payload for one agent on this machine. `machine_id`
/// is omitted from the payload when `None` (e.g. a `mcp-inventory` dump on a
/// machine with no registered device).
fn build_inventory(
    home: &Path,
    source: SnapshotSource,
    machine_id: Option<&str>,
) -> McpInventoryIngestRequest {
    let loading_mode = loading_mode_for(source);
    let servers = discover_servers(home, source)
        .iter()
        .map(|server| harvest_server(server, loading_mode))
        .collect();
    McpInventoryIngestRequest {
        agent_source: agent_source_for(source).to_string(),
        machine_id: machine_id.map(str::to_string),
        context_window_tokens: DEFAULT_CONTEXT_WINDOW_TOKENS,
        servers,
    }
}

// ---------------------------------------------------------------------------
// Inventory dump (list-only, no upload) — for `ottto-service mcp-inventory` and
// the cross-tool validation harness (parity vs the reference Python harvester).
// ---------------------------------------------------------------------------

/// Map a CLI agent string to a [`SnapshotSource`].
fn source_for_agent(agent: &str) -> Option<SnapshotSource> {
    match agent {
        "claude-code" | "claude_code" | "claude" => Some(SnapshotSource::ClaudeCode),
        "codex" => Some(SnapshotSource::Codex),
        _ => None,
    }
}

/// This machine's id, resolved exactly as the upload path does so a dump payload
/// is representative of the real ingest request. Secret-free (no keychain) so a
/// dump works before registration:
/// * a registered device → its `machine_id` (via `snapshot_machine_id`, which
///   itself falls back to the machine store);
/// * no registered device → the machine store directly (a fresh/unregistered
///   machine may still surface its id for local inspection);
/// * a device binding that exists but is unreadable → `None`, NOT the legacy
///   machine-store id — the upload path could not resolve that principal either,
///   so the dump must not silently diverge from it.
fn best_effort_machine_id() -> Option<String> {
    match ottto_core::FileDeviceStore::default().load() {
        Ok(Some(device)) => crate::snapshot_sync::snapshot_machine_id(&device)
            .ok()
            .flatten(),
        Ok(None) => machine_store_id(),
        Err(_) => None,
    }
}

fn machine_store_id() -> Option<String> {
    ottto_core::FileMachineStore::default()
        .load()
        .ok()
        .flatten()
        .map(|machine| machine.machine_id)
        .filter(|id| !id.is_empty())
}

/// Harvest one agent's configured-MCP inventory and return it as the JSON the
/// backend ingest accepts — WITHOUT uploading. List-only (`initialize` +
/// `tools/list`); never executes a tool. Powers `ottto-service mcp-inventory` and
/// the validation harness's daemon≡harvester fidelity check.
pub fn dump_inventory(agent: &str) -> Result<Value> {
    let source = source_for_agent(agent)
        .ok_or_else(|| anyhow!("unknown agent (expected claude-code or codex)"))?;
    let home = crate::snapshot_sync::home_dir()?;
    let inventory = build_inventory(&home, source, best_effort_machine_id().as_deref());
    serde_json::to_value(&inventory).map_err(|error| anyhow!("encode inventory: {error}"))
}

/// Dump every supported agent's inventory as a JSON array (the default when no
/// `--agent` is given).
pub fn dump_all_inventories() -> Result<Value> {
    let home = crate::snapshot_sync::home_dir()?;
    let machine_id = best_effort_machine_id();
    let inventories: Vec<Value> = [SnapshotSource::ClaudeCode, SnapshotSource::Codex]
        .into_iter()
        .map(|source| {
            let inventory = build_inventory(&home, source, machine_id.as_deref());
            serde_json::to_value(&inventory)
        })
        .collect::<std::result::Result<_, _>>()
        .map_err(|error| anyhow!("encode inventory: {error}"))?;
    Ok(Value::Array(inventories))
}

// ---------------------------------------------------------------------------
// Unchanged-inventory cache
// ---------------------------------------------------------------------------

/// Persisted per-source record of the last successfully-uploaded inventory, so a
/// byte-identical inventory can skip the upload entirely on the next cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct InventoryCacheEntry {
    /// The destination principal that received this upload (`device_id`,
    /// `machine_id`, API base URL). A skip is only valid against the SAME
    /// destination: if the daemon is re-claimed/re-onboarded (new device or
    /// machine id) or repointed at another backend, the new principal has no
    /// inventory yet, so an unchanged config must still re-POST.
    identity: String,
    /// SHA-256 of the canonical `(agent_source, servers)` content.
    inventory_sha256: String,
    /// RFC3339 timestamp of the last successful POST (drives the staleness
    /// force-refresh).
    posted_at: String,
}

/// The destination identity an upload was attributed to. A change in any
/// component invalidates the skip cache.
fn destination_identity(
    device: &LocalDeviceBinding,
    machine_id: &str,
    api_base_url: &str,
) -> String {
    format!("{}|{}|{}", device.device_id, machine_id, api_base_url)
}

fn cache_path(support_dir: &Path, source: SnapshotSource) -> PathBuf {
    support_dir
        .join("mcp_inventory")
        .join(format!("{}.json", source.api_slug()))
}

fn read_cache(path: &Path) -> Option<InventoryCacheEntry> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Write the cache atomically (temp + rename) so a crash mid-write never leaves a
/// torn record that would force a redundant re-POST. Best-effort: a write error
/// is non-fatal (it only costs one extra upload next cycle).
fn write_cache(path: &Path, entry: &InventoryCacheEntry) {
    let Some(dir) = path.parent() else {
        return;
    };
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let Ok(payload) = serde_json::to_vec(entry) else {
        return;
    };
    let temp = path.with_extension("json.tmp");
    if std::fs::write(&temp, &payload).is_ok() {
        let _ = std::fs::rename(&temp, path);
    }
}

/// SHA-256 over the inventory's meaningful content. `machine_id` and
/// `context_window_tokens` are constant per machine, so only `agent_source` and
/// the harvested `servers` participate — the hash changes exactly when the user's
/// configured MCP surface (servers, reachability, tool schemas) changes.
fn inventory_hash(inventory: &McpInventoryIngestRequest) -> Result<String> {
    let canonical = serde_json::to_vec(&json!({
        "agent_source": inventory.agent_source,
        "servers": inventory.servers,
    }))
    .map_err(|error| anyhow!("hash encode failed: {error}"))?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    Ok(format!("{:x}", hasher.finalize()))
}

fn cache_is_stale(entry: &InventoryCacheEntry, now: OffsetDateTime) -> bool {
    // An unparseable timestamp is treated as stale so a corrupt record always
    // re-POSTs rather than pinning a machine to a never-refreshing snapshot.
    let Ok(posted) = OffsetDateTime::parse(&entry.posted_at, &Rfc3339) else {
        return true;
    };
    (now - posted).whole_seconds() >= MCP_HARVEST_MAX_STALENESS_SECS
}

// ---------------------------------------------------------------------------
// Opt-out controls
// ---------------------------------------------------------------------------

/// Env var that disables the MCP harvest on this machine regardless of the org
/// setting (a local kill-switch for power users / CI).
const LOCAL_DISABLE_ENV: &str = "OTTTO_MCP_HARVEST_DISABLED";

/// True when the machine-local override disables the harvest: either the
/// `OTTTO_MCP_HARVEST_DISABLED` env var is truthy, or a sentinel file exists at
/// `<support>/mcp_inventory/disabled`.
fn local_harvest_disabled(support_dir: &Path) -> bool {
    if std::env::var(LOCAL_DISABLE_ENV)
        .map(|value| is_truthy(&value))
        .unwrap_or(false)
    {
        return true;
    }
    support_dir.join("mcp_inventory").join("disabled").exists()
}

fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Path of the per-source marker recording that the org last disabled the harvest
/// for this source. The file stores the destination identity it applies to, so a
/// transient activity-hint failure keeps honoring a prior opt-out only for the
/// SAME destination — a re-claim/re-onboard/repoint never inherits a stale marker.
fn org_disabled_marker_path(support_dir: &Path, source: SnapshotSource) -> PathBuf {
    support_dir
        .join("mcp_inventory")
        .join(format!("{}.org_disabled", source.api_slug()))
}

/// Read the destination identity an org-disabled marker applies to, if present.
fn read_org_disabled_marker(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

/// Record that the org disabled the harvest for `identity`. Best-effort: a write
/// error is non-fatal (it only weakens the outage fallback, never blocks harvest).
fn write_org_disabled_marker(path: &Path, identity: &str) {
    if let Some(dir) = path.parent() {
        if std::fs::create_dir_all(dir).is_err() {
            return;
        }
    }
    let _ = std::fs::write(path, identity.as_bytes());
}

/// Clear any org-disabled marker (the org re-enabled, or a fresh observation).
fn clear_org_disabled_marker(path: &Path) {
    let _ = std::fs::remove_file(path);
}

// ---------------------------------------------------------------------------
// Scheduler + per-source harvest
// ---------------------------------------------------------------------------

/// Spawn the configured-MCP harvest loop: run-at-start, then every 6 h.
///
/// Independent of the 5-minute snapshot sync (see `MCP_HARVEST_INTERVAL`).
/// Gating is implicit and safe: harvest only runs for sources the relay device
/// has been granted (`enabled_snapshot_sources`), and only when the device is
/// registered at all — so telemetry-off ⇒ no device/sources ⇒ no harvest.
pub fn spawn_mcp_inventory_sync() -> Result<()> {
    let home = crate::snapshot_sync::home_dir()?;
    let support_dir = default_support_dir();
    std::thread::Builder::new()
        .name("ottto-mcp-inventory-sync".to_string())
        .spawn(move || loop {
            if let Err(error) = harvest_all_once(&home, &support_dir) {
                eprintln!(
                    "mcp inventory harvest skipped: {}",
                    crate::snapshot_sync::safe_error(&error)
                );
            }
            std::thread::sleep(MCP_HARVEST_INTERVAL);
        })
        .map_err(|error| anyhow!("spawn mcp inventory sync: {error}"))?;
    Ok(())
}

/// One harvest cycle across every granted agent source on this machine.
fn harvest_all_once(home: &Path, support_dir: &Path) -> Result<()> {
    // Local kill-switch: a user can disable the harvest on their own machine
    // (independent of the org setting) by setting `OTTTO_MCP_HARVEST_DISABLED` or
    // dropping `<support>/mcp_inventory/disabled`. Checked first, so a disabled
    // machine does nothing — no credentials read, no network.
    if local_harvest_disabled(support_dir) {
        return Ok(());
    }
    let (device, device_secret) = load_snapshot_device_credentials()?;
    let Some(machine_id) = crate::snapshot_sync::snapshot_machine_id(&device)? else {
        return Err(anyhow!("machine identity is missing"));
    };
    let api_base_url = crate::snapshot_sync::snapshot_api_base_url();
    let client = SnapshotApiClient::new(api_base_url.clone());

    let mut failed = Vec::new();
    for source in crate::snapshot_sync::enabled_snapshot_sources(&device) {
        // Pi has no MCP-config surface; nothing to harvest.
        if matches!(source, SnapshotSource::Pi) {
            continue;
        }
        if let Err(error) = harvest_source(
            &client,
            &device,
            &device_secret,
            source,
            &machine_id,
            &api_base_url,
            home,
            support_dir,
        ) {
            eprintln!(
                "mcp inventory harvest skipped for {}: {}",
                source.api_slug(),
                crate::snapshot_sync::safe_error(&error)
            );
            failed.push(source.api_slug());
        }
    }
    if !failed.is_empty() {
        return Err(anyhow!(
            "mcp inventory harvest failed for {} source(s)",
            failed.len()
        ));
    }
    Ok(())
}

/// Harvest + (conditionally) upload the configured-MCP inventory for one agent
/// source.
///
/// Mints a source-scoped relay token and first polls the backend activity hint
/// for the org's `mcp_inventory_harvest_enabled` (the full telemetry cascade). A
/// disabled org short-circuits before any MCP server is spawned. When enabled, it
/// builds the inventory and uploads it, skipping the POST when the inventory is
/// byte-identical to the last upload for the SAME destination and still fresh.
/// The hash is recorded only after a successful upload so a failed POST retries.
/// Discovery and the per-server handshakes are best-effort: a failed handshake
/// yields an unreachable server, not an aborted harvest.
#[allow(clippy::too_many_arguments)]
fn harvest_source(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    source: SnapshotSource,
    machine_id: &str,
    api_base_url: &str,
    home: &Path,
    support_dir: &Path,
) -> Result<()> {
    let relay_token = client.issue_relay_token(device, device_secret, source)?;
    let identity = destination_identity(device, machine_id, api_base_url);

    // Honor the org opt-out within one cycle. The activity hint resolves the full
    // cascade (telemetry-off / source-disabled / harvest-off ⇒ false). The marker
    // records the destination that last opted out, so a transient hint failure
    // still respects a prior opt-out — but only for the SAME destination. A
    // re-claim/re-onboard/repoint (different identity) never inherits the marker
    // and falls through to harvesting, the default-on behavior.
    let marker = org_disabled_marker_path(support_dir, source);
    match client.get_activity_hint(&relay_token) {
        Ok(hint) => {
            if !hint.mcp_inventory_harvest_enabled {
                write_org_disabled_marker(&marker, &identity);
                return Ok(());
            }
            clear_org_disabled_marker(&marker);
        }
        Err(_) if read_org_disabled_marker(&marker).as_deref() == Some(identity.as_str()) => {
            return Ok(());
        }
        Err(_) => {}
    }

    let inventory = build_inventory(home, source, Some(machine_id));
    let hash = inventory_hash(&inventory)?;
    let path = cache_path(support_dir, source);
    let now = OffsetDateTime::now_utc();

    if let Some(entry) = read_cache(&path) {
        // Skip the upload when the SAME destination already has this exact
        // inventory and it is still fresh. A new device/machine/backend (re-claim,
        // re-onboard, repoint) invalidates the skip so the new principal is
        // populated immediately.
        if entry.identity == identity
            && entry.inventory_sha256 == hash
            && !cache_is_stale(&entry, now)
        {
            return Ok(());
        }
    }

    let payload =
        serde_json::to_value(&inventory).map_err(|error| anyhow!("encode inventory: {error}"))?;
    client.upload_mcp_inventory(&relay_token, &payload)?;

    write_cache(
        &path,
        &InventoryCacheEntry {
            identity,
            inventory_sha256: hash,
            posted_at: now.format(&Rfc3339).unwrap_or_default(),
        },
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_home(name: &str) -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join("ottto-mcp-inventory-tests")
            .join(format!("{}-{name}-{counter}", std::process::id()));
        fs::create_dir_all(&dir).expect("create test home");
        dir
    }

    #[test]
    fn claude_code_discovers_stdio_http_and_sse_across_sources() {
        let home = test_home("claude-discover");
        let project_dir = home.join("workspace").join("proj");
        fs::create_dir_all(&project_dir).expect("project dir");
        fs::write(
            home.join(".claude.json"),
            serde_json::to_string(&json!({
                "mcpServers": {
                    "global-stdio": { "command": "uvx", "args": ["server", "--flag"] }
                },
                "projects": {
                    project_dir.to_string_lossy(): {
                        "mcpServers": {
                            "proj-http": { "type": "http", "url": "https://example.test/mcp" }
                        }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            project_dir.join(".mcp.json"),
            serde_json::to_string(&json!({
                "mcpServers": {
                    "dotmcp-sse": { "type": "sse", "url": "https://sse.test/events" }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        fs::create_dir_all(home.join(".claude")).unwrap();
        fs::write(
            home.join(".claude").join("settings.json"),
            serde_json::to_string(&json!({
                "mcpServers": {
                    "settings-stdio": { "command": "node", "args": ["mcp.js"] }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let mut servers = discover_claude_code(&home);
        servers.sort_by(|a, b| a.name.cmp(&b.name));

        assert_eq!(servers.len(), 4);
        let by_name: BTreeMap<_, _> = servers
            .iter()
            .map(|s| (s.name.as_str(), &s.transport))
            .collect();
        assert_eq!(
            by_name["global-stdio"],
            &Transport::Stdio {
                command: "uvx".to_string(),
                args: vec!["server".to_string(), "--flag".to_string()]
            }
        );
        assert_eq!(
            by_name["proj-http"],
            &Transport::Http {
                url: "https://example.test/mcp".to_string()
            }
        );
        assert_eq!(
            by_name["dotmcp-sse"],
            &Transport::Sse {
                url: "https://sse.test/events".to_string()
            }
        );
        assert_eq!(
            by_name["settings-stdio"],
            &Transport::Stdio {
                command: "node".to_string(),
                args: vec!["mcp.js".to_string()]
            }
        );

        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn claude_code_missing_config_yields_no_servers() {
        let home = test_home("claude-empty");
        assert!(discover_claude_code(&home).is_empty());
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn codex_discovers_stdio_and_http_from_toml() {
        let home = test_home("codex-discover");
        fs::create_dir_all(home.join(".codex")).unwrap();
        fs::write(
            home.join(".codex").join("config.toml"),
            r#"
model = "gpt-5.4"

[mcp_servers.local]
command = "uvx"
args = ["mcp-server-fetch"]

[mcp_servers.remote]
url = "https://remote.test/mcp"
"#,
        )
        .unwrap();

        let mut servers = discover_codex(&home);
        servers.sort_by(|a, b| a.name.cmp(&b.name));

        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].name, "local");
        assert_eq!(
            servers[0].transport,
            Transport::Stdio {
                command: "uvx".to_string(),
                args: vec!["mcp-server-fetch".to_string()]
            }
        );
        assert_eq!(servers[1].name, "remote");
        assert_eq!(
            servers[1].transport,
            Transport::Http {
                url: "https://remote.test/mcp".to_string()
            }
        );

        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn codex_missing_config_yields_no_servers() {
        let home = test_home("codex-empty");
        assert!(discover_codex(&home).is_empty());
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn network_transports_are_reported_unreachable_with_no_tools() {
        let http = ConfiguredServer {
            name: "remote".to_string(),
            transport: Transport::Http {
                url: "https://remote.test/mcp".to_string(),
            },
        };
        let harvested = harvest_server(&http, "always_on");

        assert_eq!(harvested.server, "remote");
        assert_eq!(harvested.transport.as_deref(), Some("http"));
        assert!(!harvested.reachable);
        assert!(harvested.tools.is_empty());
        assert_eq!(harvested.loading_mode, "always_on");
    }

    #[test]
    fn unreachable_stdio_server_is_marked_unreachable() {
        let server = ConfiguredServer {
            name: "broken".to_string(),
            transport: Transport::Stdio {
                command: "/nonexistent/ottto-mcp-binary-xyz".to_string(),
                args: Vec::new(),
            },
        };
        let harvested = harvest_server(&server, "on_demand");

        assert!(!harvested.reachable);
        assert!(harvested.tools.is_empty());
        assert_eq!(harvested.transport.as_deref(), Some("stdio"));
    }

    #[test]
    fn loading_mode_matches_agent_class() {
        assert_eq!(loading_mode_for(SnapshotSource::ClaudeCode), "on_demand");
        assert_eq!(loading_mode_for(SnapshotSource::Codex), "always_on");
    }

    #[test]
    fn agent_source_matches_backend_spelling() {
        assert_eq!(agent_source_for(SnapshotSource::ClaudeCode), "claude-code");
        assert_eq!(agent_source_for(SnapshotSource::Codex), "codex");
    }

    #[test]
    fn parse_tools_extracts_name_description_and_schema() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": [
                    {
                        "name": "fetch",
                        "description": "Fetch a URL",
                        "inputSchema": { "type": "object", "properties": { "url": { "type": "string" } } }
                    },
                    { "name": "noschema" }
                ]
            }
        });
        let tools = parse_tools(&response);

        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "fetch");
        assert_eq!(tools[0].description, "Fetch a URL");
        assert_eq!(tools[0].input_schema["type"], json!("object"));
        assert_eq!(tools[1].name, "noschema");
        assert_eq!(tools[1].description, "");
        assert_eq!(tools[1].input_schema, json!({}));
    }

    #[test]
    fn inventory_payload_matches_backend_schema_shape() {
        let inventory = McpInventoryIngestRequest {
            agent_source: "claude-code".to_string(),
            machine_id: Some("otm_test".to_string()),
            context_window_tokens: DEFAULT_CONTEXT_WINDOW_TOKENS,
            servers: vec![McpServerInput {
                server: "fetch".to_string(),
                transport: Some("stdio".to_string()),
                reachable: true,
                loading_mode: "on_demand".to_string(),
                tools: vec![McpToolInput {
                    name: "fetch".to_string(),
                    description: "Fetch a URL".to_string(),
                    input_schema: json!({ "type": "object" }),
                }],
            }],
        };
        let value = serde_json::to_value(&inventory).unwrap();

        assert_eq!(value["agent_source"], json!("claude-code"));
        assert_eq!(value["machine_id"], json!("otm_test"));
        assert_eq!(value["context_window_tokens"], json!(200_000));
        let server = &value["servers"][0];
        assert_eq!(server["server"], json!("fetch"));
        assert_eq!(server["transport"], json!("stdio"));
        assert_eq!(server["reachable"], json!(true));
        assert_eq!(server["loading_mode"], json!("on_demand"));
        let tool = &server["tools"][0];
        assert_eq!(tool["name"], json!("fetch"));
        assert_eq!(tool["description"], json!("Fetch a URL"));
        assert_eq!(tool["input_schema"], json!({ "type": "object" }));
    }

    #[test]
    fn build_inventory_for_pi_has_no_servers() {
        let home = test_home("pi-build");
        let inventory = build_inventory(&home, SnapshotSource::Pi, Some("otm_test"));
        assert_eq!(inventory.agent_source, "pi");
        assert!(inventory.servers.is_empty());
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn build_inventory_omits_machine_id_when_absent() {
        let home = test_home("no-machine");
        let value =
            serde_json::to_value(build_inventory(&home, SnapshotSource::ClaudeCode, None)).unwrap();
        assert!(
            value.get("machine_id").is_none(),
            "machine_id omitted when None"
        );
        let with_id = serde_json::to_value(build_inventory(
            &home,
            SnapshotSource::ClaudeCode,
            Some("otm_x"),
        ))
        .unwrap();
        assert_eq!(with_id["machine_id"], json!("otm_x"));
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn source_for_agent_maps_known_agents() {
        assert_eq!(
            source_for_agent("claude-code"),
            Some(SnapshotSource::ClaudeCode)
        );
        assert_eq!(
            source_for_agent("claude_code"),
            Some(SnapshotSource::ClaudeCode)
        );
        assert_eq!(source_for_agent("codex"), Some(SnapshotSource::Codex));
        assert_eq!(source_for_agent("nope"), None);
    }

    /// `dump_inventory` harvests an agent's configured servers into the ingest
    /// shape without uploading. Drives a real mock stdio MCP server via HOME.
    #[test]
    #[serial_test::serial]
    fn dump_inventory_harvests_without_upload() {
        let (home, _support) = mock_cc_home("dump");
        let _home_guard = EnvGuard::set("HOME", home.to_string_lossy().as_ref());

        let value = dump_inventory("claude-code").expect("dump");
        assert_eq!(value["agent_source"], json!("claude-code"));
        let servers = value["servers"].as_array().expect("servers array");
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0]["server"], json!("echo-srv"));
        assert_eq!(servers[0]["reachable"], json!(true));
        assert_eq!(servers[0]["tools"][0]["name"], json!("echo"));

        assert!(dump_inventory("bogus").is_err());

        let _ = fs::remove_dir_all(&home);
    }

    /// Minimal scoped env-var guard for the HOME-dependent dump test.
    struct EnvGuard {
        key: String,
        prev: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &str, value: &str) -> Self {
            let prev = std::env::var_os(key);
            std::env::set_var(key, value);
            Self {
                key: key.to_string(),
                prev,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(&self.key, v),
                None => std::env::remove_var(&self.key),
            }
        }
    }

    /// End-to-end stdio handshake against a tiny in-repo mock MCP server: a
    /// shell script speaking line-delimited JSON-RPC. Verifies initialize +
    /// tools/list parsing without any external dependency.
    #[test]
    fn stdio_handshake_against_mock_server_returns_tools() {
        let home = test_home("stdio-mock");
        let script = home.join("mock_mcp.sh");
        fs::write(
            &script,
            r#"#!/bin/sh
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*|*'"method": "initialize"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"mock","version":"0"}}}'
      ;;
    *'"method":"tools/list"'*|*'"method": "tools/list"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"Echo input","inputSchema":{"type":"object","properties":{"text":{"type":"string"}}}}]}}'
      ;;
  esac
done
"#,
        )
        .unwrap();
        let mut perms = fs::metadata(&script).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).unwrap();

        let tools = harvest_stdio(&script.to_string_lossy(), &[]).expect("handshake succeeds");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "echo");
        assert_eq!(tools[0].description, "Echo input");
        assert_eq!(tools[0].input_schema["type"], json!("object"));

        let _ = fs::remove_dir_all(&home);
    }

    fn sample_inventory(server: &str, tool: &str) -> McpInventoryIngestRequest {
        McpInventoryIngestRequest {
            agent_source: "claude-code".to_string(),
            machine_id: Some("otm_test".to_string()),
            context_window_tokens: DEFAULT_CONTEXT_WINDOW_TOKENS,
            servers: vec![McpServerInput {
                server: server.to_string(),
                transport: Some("stdio".to_string()),
                reachable: true,
                loading_mode: "on_demand".to_string(),
                tools: vec![McpToolInput {
                    name: tool.to_string(),
                    description: String::new(),
                    input_schema: json!({ "type": "object" }),
                }],
            }],
        }
    }

    #[test]
    fn inventory_hash_is_content_sensitive_and_machine_independent() {
        let a = sample_inventory("fetch", "get");
        let b = sample_inventory("fetch", "get");
        assert_eq!(
            inventory_hash(&a).unwrap(),
            inventory_hash(&b).unwrap(),
            "identical content hashes equal"
        );

        // machine_id is excluded from the hash (constant per machine).
        let mut c = sample_inventory("fetch", "get");
        c.machine_id = Some("otm_other".to_string());
        assert_eq!(inventory_hash(&a).unwrap(), inventory_hash(&c).unwrap());

        // A changed tool set changes the hash.
        let d = sample_inventory("fetch", "post");
        assert_ne!(inventory_hash(&a).unwrap(), inventory_hash(&d).unwrap());
    }

    #[test]
    fn cache_freshness_tracks_max_staleness() {
        let now = OffsetDateTime::from_unix_timestamp(1_750_000_000).unwrap();
        let fresh = InventoryCacheEntry {
            identity: "d|m|u".to_string(),
            inventory_sha256: "x".to_string(),
            posted_at: now.format(&Rfc3339).unwrap(),
        };
        assert!(!cache_is_stale(&fresh, now));
        assert!(!cache_is_stale(
            &fresh,
            now + time::Duration::seconds(MCP_HARVEST_MAX_STALENESS_SECS - 1)
        ));
        assert!(cache_is_stale(
            &fresh,
            now + time::Duration::seconds(MCP_HARVEST_MAX_STALENESS_SECS)
        ));

        // An unparseable timestamp is treated as stale (force a re-POST).
        let corrupt = InventoryCacheEntry {
            identity: "d|m|u".to_string(),
            inventory_sha256: "x".to_string(),
            posted_at: "not-a-timestamp".to_string(),
        };
        assert!(cache_is_stale(&corrupt, now));
    }

    #[test]
    fn harvest_interval_is_six_hours() {
        assert_eq!(MCP_HARVEST_INTERVAL, Duration::from_secs(6 * 60 * 60));
    }

    /// Write a CC home whose single configured stdio server is a mock MCP server
    /// speaking line-delimited JSON-RPC. Returns `(home, support_dir)`.
    fn mock_cc_home(name: &str) -> (PathBuf, PathBuf) {
        let home = test_home(name);
        let support_dir = home.join("support");
        fs::create_dir_all(&support_dir).unwrap();
        let script = home.join("mock_mcp.sh");
        fs::write(
            &script,
            r#"#!/bin/sh
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*|*'"method": "initialize"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"mock","version":"0"}}}'
      ;;
    *'"method":"tools/list"'*|*'"method": "tools/list"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"Echo","inputSchema":{"type":"object"}}]}}'
      ;;
  esac
done
"#,
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).unwrap();
        fs::write(
            home.join(".claude.json"),
            serde_json::to_string(&json!({
                "mcpServers": {
                    "echo-srv": { "command": script.to_string_lossy(), "args": [] }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        (home, support_dir)
    }

    /// How the mock backend answers the activity-hint poll.
    #[derive(Clone, Copy)]
    enum HintMode {
        Enabled,
        Disabled,
        Error,
    }

    /// Mock backend accepting exactly `count` requests, dispatching by path:
    /// `/relay-token` → token, `/activity-hints` → an activity hint carrying the
    /// requested `mcp_inventory_harvest_enabled` (or HTTP 500 for `Error`), and
    /// anything else → an inventory ack. Each captured request (line + headers +
    /// full body) is pushed to `captured`.
    fn mock_backend(
        captured: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        count: usize,
        hint: HintMode,
    ) -> (String, std::thread::JoinHandle<()>) {
        use std::io::Read;
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock backend");
        let address = listener.local_addr().expect("addr");
        let handle = std::thread::spawn(move || {
            for _ in 0..count {
                let (mut stream, _) = listener.accept().expect("accept");
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut buf = [0_u8; 4096];
                let mut request = Vec::new();
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&buf[..n]);
                    // Stop once the full body (per Content-Length) has arrived.
                    if let Some(end) = request
                        .windows(4)
                        .position(|w| w == b"\r\n\r\n")
                        .map(|p| p + 4)
                    {
                        let headers = String::from_utf8_lossy(&request[..end]);
                        let content_length = headers.lines().find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        });
                        if request.len() >= end + content_length.unwrap_or(0) {
                            break;
                        }
                    }
                }
                let text = String::from_utf8_lossy(&request).to_string();
                captured.lock().unwrap().push(text.clone());
                let (status, body) = if text.contains("/relay-token") {
                    (
                        "200 OK",
                        r#"{"token":"relay-token","expires_at":"2099-01-01T00:00:00Z"}"#
                            .to_string(),
                    )
                } else if text.contains("/activity-hints") {
                    match hint {
                        HintMode::Error => {
                            ("500 Internal Server Error", r#"{"error":"x"}"#.to_string())
                        }
                        mode => (
                            "200 OK",
                            format!(
                                r#"{{"source":"claude_code","server_time":"2099-01-01T00:00:00Z","record_count_15m":0,"record_count_24h":0,"local_usage_reconciliation_enabled":true,"backfill_window_days":183,"recommended_scan_after":"2099-01-01T00:00:00Z","mcp_inventory_harvest_enabled":{}}}"#,
                                matches!(mode, HintMode::Enabled)
                            ),
                        ),
                    }
                } else {
                    ("200 OK", r#"{"snapshot_id":"snap_1"}"#.to_string())
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (format!("http://{address}"), handle)
    }

    fn cc_device(device_id: &str) -> LocalDeviceBinding {
        LocalDeviceBinding {
            device_id: device_id.to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["claude_code".to_string()],
        }
    }

    fn run_harvest(
        client: &SnapshotApiClient,
        device: &LocalDeviceBinding,
        base: &str,
        home: &Path,
        support_dir: &Path,
    ) -> Result<()> {
        harvest_source(
            client,
            device,
            "device-secret",
            SnapshotSource::ClaudeCode,
            "otm_test",
            base,
            home,
            support_dir,
        )
    }

    fn inventory_post_count(requests: &[String]) -> usize {
        requests
            .iter()
            .filter(|r| r.contains("POST /api/v1/mcp/inventory"))
            .count()
    }

    /// End-to-end: a first harvest uploads; an unchanged second harvest still
    /// polls the org setting (relay token + activity hint) but skips the upload —
    /// the unchanged-skip + Phase-4 per-cycle gate. Drives a real mock stdio MCP
    /// server + a mock backend.
    #[test]
    fn harvest_source_uploads_then_skips_unchanged_inventory() {
        use std::sync::{Arc, Mutex};

        let (home, support_dir) = mock_cc_home("harvest-skip");
        // Cycle 1: token + hint + inventory (3). Cycle 2: token + hint, no POST (2).
        let captured = Arc::new(Mutex::new(Vec::<String>::new()));
        let (base, server) = mock_backend(captured.clone(), 5, HintMode::Enabled);
        let client = SnapshotApiClient::new(base.clone());
        let device = cc_device("device_test");

        run_harvest(&client, &device, &base, &home, &support_dir).expect("cycle 1 harvest");
        run_harvest(&client, &device, &base, &home, &support_dir).expect("cycle 2 harvest");

        server.join().expect("server thread");
        let requests = captured.lock().unwrap().clone();
        assert_eq!(
            inventory_post_count(&requests),
            1,
            "exactly one inventory POST across both cycles (cycle 2 skips)"
        );
        let post = requests
            .iter()
            .find(|r| r.contains("POST /api/v1/mcp/inventory"))
            .expect("an inventory POST");
        assert!(post.contains("\"server\":\"echo-srv\""));
        assert!(post.contains("\"name\":\"echo\""));
        assert!(cache_path(&support_dir, SnapshotSource::ClaudeCode).exists());

        let _ = fs::remove_dir_all(&home);
    }

    /// Regression for the re-claim/re-onboard gap: an identical inventory uploaded
    /// to a NEW destination (different `device_id`) must re-POST, not skip — the
    /// new backend principal has no inventory yet.
    #[test]
    fn harvest_source_reposts_after_destination_identity_change() {
        use std::sync::{Arc, Mutex};

        let (home, support_dir) = mock_cc_home("harvest-reonboard");
        // Two full cycles (token + hint + inventory each) = 6 requests.
        let captured = Arc::new(Mutex::new(Vec::<String>::new()));
        let (base, server) = mock_backend(captured.clone(), 6, HintMode::Enabled);
        let client = SnapshotApiClient::new(base.clone());

        run_harvest(
            &client,
            &cc_device("device_old"),
            &base,
            &home,
            &support_dir,
        )
        .expect("cycle 1 harvest");
        run_harvest(
            &client,
            &cc_device("device_new"),
            &base,
            &home,
            &support_dir,
        )
        .expect("cycle 2 harvest");

        server.join().expect("server thread");
        let requests = captured.lock().unwrap().clone();
        assert_eq!(
            inventory_post_count(&requests),
            2,
            "both destinations are populated"
        );
        assert!(requests
            .iter()
            .any(|r| r.contains("/api/v1/telemetry/devices/device_old/relay-token")));
        assert!(requests
            .iter()
            .any(|r| r.contains("/api/v1/telemetry/devices/device_new/relay-token")));

        let _ = fs::remove_dir_all(&home);
    }

    /// Phase 4: when the org has the harvest setting off (the activity hint reports
    /// `mcp_inventory_harvest_enabled=false`), the source is skipped before any
    /// upload and a persisted marker records the opt-out.
    #[test]
    fn harvest_source_skips_when_org_disabled() {
        use std::sync::{Arc, Mutex};

        let (home, support_dir) = mock_cc_home("harvest-org-off");
        // token + hint(disabled); no inventory POST.
        let captured = Arc::new(Mutex::new(Vec::<String>::new()));
        let (base, server) = mock_backend(captured.clone(), 2, HintMode::Disabled);
        let client = SnapshotApiClient::new(base.clone());

        run_harvest(
            &client,
            &cc_device("device_test"),
            &base,
            &home,
            &support_dir,
        )
        .expect("harvest honors org opt-out");

        server.join().expect("server thread");
        let requests = captured.lock().unwrap().clone();
        assert_eq!(
            inventory_post_count(&requests),
            0,
            "no upload when org-disabled"
        );
        assert!(org_disabled_marker_path(&support_dir, SnapshotSource::ClaudeCode).exists());
        assert!(!cache_path(&support_dir, SnapshotSource::ClaudeCode).exists());

        let _ = fs::remove_dir_all(&home);
    }

    /// Phase 4 fail-safe: when the activity hint is unreachable but a prior
    /// org-disabled marker exists FOR THIS destination, the harvest stays off
    /// (honors the last-known opt-out) rather than falling back to default-on.
    #[test]
    fn harvest_source_honors_last_known_opt_out_on_hint_failure() {
        use std::sync::{Arc, Mutex};

        let (home, support_dir) = mock_cc_home("harvest-outage");
        // token + hint(500); marker for THIS destination present → skip, no upload.
        let captured = Arc::new(Mutex::new(Vec::<String>::new()));
        let (base, server) = mock_backend(captured.clone(), 2, HintMode::Error);
        let client = SnapshotApiClient::new(base.clone());
        let device = cc_device("device_test");
        write_org_disabled_marker(
            &org_disabled_marker_path(&support_dir, SnapshotSource::ClaudeCode),
            &destination_identity(&device, "otm_test", &base),
        );

        run_harvest(&client, &device, &base, &home, &support_dir)
            .expect("harvest tolerates hint outage");

        server.join().expect("server thread");
        let requests = captured.lock().unwrap().clone();
        assert_eq!(
            inventory_post_count(&requests),
            0,
            "outage keeps honoring the prior opt-out"
        );

        let _ = fs::remove_dir_all(&home);
    }

    /// Regression for the stale-marker gap: an org-disabled marker left by a
    /// DIFFERENT destination (re-claim/re-onboard/repoint) must not suppress the
    /// new principal's harvest during a hint outage.
    #[test]
    fn harvest_source_ignores_stale_marker_for_other_destination() {
        use std::sync::{Arc, Mutex};

        let (home, support_dir) = mock_cc_home("harvest-stale-marker");
        // A marker from a prior, unrelated destination.
        write_org_disabled_marker(
            &org_disabled_marker_path(&support_dir, SnapshotSource::ClaudeCode),
            "device_old|otm_old|http://old.invalid",
        );
        // token + hint(500) + inventory POST — the stale marker is ignored.
        let captured = Arc::new(Mutex::new(Vec::<String>::new()));
        let (base, server) = mock_backend(captured.clone(), 3, HintMode::Error);
        let client = SnapshotApiClient::new(base.clone());

        run_harvest(
            &client,
            &cc_device("device_new"),
            &base,
            &home,
            &support_dir,
        )
        .expect("harvest proceeds despite a foreign marker");

        server.join().expect("server thread");
        let requests = captured.lock().unwrap().clone();
        assert_eq!(
            inventory_post_count(&requests),
            1,
            "new destination is populated despite a stale marker"
        );

        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn local_override_disables_harvest() {
        let home = test_home("harvest-local-override");
        let support_dir = home.join("support");
        fs::create_dir_all(support_dir.join("mcp_inventory")).unwrap();
        assert!(!local_harvest_disabled(&support_dir));
        // Sentinel file.
        fs::write(support_dir.join("mcp_inventory").join("disabled"), b"").unwrap();
        assert!(local_harvest_disabled(&support_dir));

        assert!(is_truthy("1"));
        assert!(is_truthy("TRUE"));
        assert!(is_truthy(" on "));
        assert!(!is_truthy("0"));
        assert!(!is_truthy("off"));

        let _ = fs::remove_dir_all(&home);
    }
}
