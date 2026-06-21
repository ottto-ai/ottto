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

use crate::snapshot_client::SnapshotApiClient;
use crate::snapshots::SnapshotSource;
use anyhow::{anyhow, Result};
use ottto_core::LocalDeviceBinding;
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// Per-server handshake budget. Generous because a cold MCP server may need to
/// install/launch a runtime, but bounded so one slow server cannot stall the
/// sync loop. Mirrors harvest.py's 45s ceiling.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(45);

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

/// Build the full inventory payload for one agent on this machine.
fn build_inventory(
    home: &Path,
    source: SnapshotSource,
    machine_id: &str,
) -> McpInventoryIngestRequest {
    let loading_mode = loading_mode_for(source);
    let servers = discover_servers(home, source)
        .iter()
        .map(|server| harvest_server(server, loading_mode))
        .collect();
    McpInventoryIngestRequest {
        agent_source: agent_source_for(source).to_string(),
        machine_id: Some(machine_id.to_string()),
        context_window_tokens: DEFAULT_CONTEXT_WINDOW_TOKENS,
        servers,
    }
}

// ---------------------------------------------------------------------------
// Sync hook
// ---------------------------------------------------------------------------

/// Harvest + upload the configured-MCP inventory for one agent source.
///
/// Mints a fresh source-scoped relay token (the same auth as snapshot batches)
/// and POSTs the inventory to `/api/v1/mcp/inventory`. Discovery and the
/// per-server handshakes are best-effort: a failed handshake yields an
/// unreachable server, not an aborted sync.
pub fn sync_mcp_inventory(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    source: SnapshotSource,
    machine_id: &str,
    home: &Path,
) -> Result<()> {
    // Pi has no MCP-config surface; nothing to harvest.
    if matches!(source, SnapshotSource::Pi) {
        return Ok(());
    }
    let inventory = build_inventory(home, source, machine_id);
    let relay_token = client.issue_relay_token(device, device_secret, source)?;
    let payload =
        serde_json::to_value(&inventory).map_err(|error| anyhow!("encode inventory: {error}"))?;
    client.upload_mcp_inventory(&relay_token, &payload)?;
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
        let inventory = build_inventory(&home, SnapshotSource::Pi, "otm_test");
        assert_eq!(inventory.agent_source, "pi");
        assert!(inventory.servers.is_empty());
        let _ = fs::remove_dir_all(&home);
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
}
