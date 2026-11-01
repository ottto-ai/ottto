//! Configured-MCP context-footprint harvest.
//!
//! Every six hours this module discovers the MCP servers each
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

use crate::locked_state_dir::write_json_atomic;
use crate::snapshot_client::{load_snapshot_device_credentials, SnapshotApiClient};
use crate::snapshots::codex_version::{CodexVersionFeed, Sample};
use crate::snapshots::SnapshotSource;
use anyhow::{anyhow, Result};
use ottto_core::{default_support_dir, LocalDeviceBinding};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
#[cfg(any(not(unix), test))]
use std::process::Child;
use std::process::Command;
#[cfg(not(unix))]
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(not(unix))]
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// Per-server handshake budget. Generous enough for a fresh machine's first
/// `npx`/`uvx` run to DOWNLOAD + launch the server (a one-time cost that a tighter
/// timeout would falsely report as unreachable on the first harvest), but bounded
/// so a hung server cannot stall a cycle. Bounded concurrency + the per-cycle
/// budget cap total wall-clock regardless, so this can stay forgiving.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// How many servers are harvested concurrently. Bounds parallel subprocess
/// fan-out (one stdio child per existing server worker) while keeping a slow/cold
/// server from serializing the whole cycle: wall-clock ≈ ⌈servers/K⌉ × timeout.
pub(crate) const MCP_HARVEST_MAX_CONCURRENCY: usize = 4;

/// Soft per-cycle wall-clock budget. Once a cycle exceeds it the harvest stops
/// launching new server probes and reports `throttled` (and skips the upload of a
/// partial inventory) so a pathological config can never run the background
/// thread unbounded. A normal 2–6 server machine finishes far inside this.
const MCP_HARVEST_CYCLE_BUDGET: Duration = Duration::from_secs(90);

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
        cwd: Option<String>,
        env: BTreeMap<String, String>,
    },
    /// Streamable HTTP transport. Not yet harvested (see module docs).
    Http { url: String },
    /// Legacy SSE transport. Not yet harvested (see module docs).
    Sse { url: String },
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
    disabled: bool,
    /// Claude Code `alwaysLoad: true` on the server block: its tool schemas
    /// are sent up front even while tool search defers everything else.
    always_load: bool,
    /// Directory of the config file that declared this server. A relative
    /// `cwd` (and the relative paths a server's own `env` points at) resolve
    /// against THIS, exactly as the agent resolves them — never against the
    /// daemon's working directory, which under launchd is `/`.
    config_dir: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Wire types (port of McpInventoryIngestRequest)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
struct McpToolInput {
    name: String,
    description: String,
    input_schema: Value,
    /// The tool's `_meta["anthropic/alwaysLoad"]` is `true`: Claude Code sends
    /// this one schema up front even when its server is deferred. Omitted when
    /// false so ordinary payloads (and their hashes) are unchanged.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    always_load: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct McpServerInput {
    disabled: bool,
    server: String,
    transport: Option<String>,
    reachable: bool,
    /// `always_on` (schemas sent every session), `on_demand` (deferred: only
    /// tool names and server instructions, or nothing, until a tool is
    /// searched), or `unknown`. See [`LoadingDecision`].
    loading_mode: String,
    /// Closed reason for `loading_mode` (see [`LoadingDecision::basis`]).
    loading_mode_basis: String,
    /// True when `loading_mode` is the client's default for its version
    /// rather than a setting read from the user's config. Neither case sees a
    /// shell environment override, which the daemon cannot read.
    loading_mode_inferred: bool,
    /// Character length of the server's `initialize` `instructions`, which
    /// Claude Code sends every session even when tools are deferred. Only the
    /// length leaves the machine, never the text.
    #[serde(skip_serializing_if = "Option::is_none")]
    instructions_chars: Option<u32>,
    tools: Vec<McpToolInput>,
}

/// Explicit machine-level capability state discovered without executing the
/// capability. Only allowlisted identifiers and booleans leave the machine.
#[derive(Debug, Clone, Serialize, PartialEq)]
struct McpCapabilityInput {
    capability_id: String,
    raw_origin: String,
    availability_state: String,
    evidence_source: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct McpInventoryIngestRequest {
    agent_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    machine_id: Option<String>,
    context_window_tokens: i64,
    /// Version of the agent client the loading modes were decided for: Claude
    /// Code's last-run version from `~/.claude.json`, Codex's from its newest
    /// session log. No process is spawned to read it.
    #[serde(skip_serializing_if = "Option::is_none")]
    client_version: Option<String>,
    /// Claude Code `ENABLE_TOOL_SEARCH=auto[:N]`: tools load up front until
    /// all deferrable tool schemas exceed N% of the model's context window.
    /// The backend, which knows both sizes, resolves servers with basis
    /// `tool_search_auto` against this percentage.
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_search_auto_pct: Option<u8>,
    servers: Vec<McpServerInput>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    capabilities: Vec<McpCapabilityInput>,
}

// ---------------------------------------------------------------------------
// Loading mode
// ---------------------------------------------------------------------------

/// Earliest Claude Code version proven to defer every MCP server by default
/// (tool search): a 2.1.170 session log lists user MCP servers among its
/// deferred tool names. Older builds may send schemas up front.
const CLAUDE_DEFERRAL_MIN_VERSION: (u64, u64, u64) = (2, 1, 170);

/// Earliest Codex version seen finding MCP tools through code mode's runtime
/// `ALL_TOOLS` list (0.149). Code-mode builds send no user MCP server names,
/// schemas or instructions in the first request. Older builds are not assumed.
const CODEX_CODE_MODE_MIN_VERSION: (u64, u64, u64) = (0, 149, 0);

/// Claude Code's default `ENABLE_TOOL_SEARCH=auto` threshold, in percent of
/// the model's context window.
const CLAUDE_TOOL_SEARCH_AUTO_DEFAULT_PCT: u8 = 10;

/// How one configured server's tool schemas reach the model.
///
/// `mode` is `always_on` (every schema is sent every session), `on_demand`
/// (deferred: Claude Code sends only tool names and server instructions,
/// Codex code mode sends nothing, until the model looks a tool up) or
/// `unknown`. `basis` is a closed reason the backend explains to the user:
///
/// * `client_default` — the client's default for its version.
/// * `tool_search_enabled` / `tool_search_disabled` — `ENABLE_TOOL_SEARCH`.
/// * `tool_search_auto` — `ENABLE_TOOL_SEARCH=auto[:N]`; up front until the
///   deferrable schemas pass N% of the window, resolved by the backend.
/// * `always_load` — the server's `alwaysLoad: true`.
/// * `proxy_base_url` — a non-Anthropic `ANTHROPIC_BASE_URL` without
///   `ENABLE_TOOL_SEARCH` turns deferral off.
/// * `experimental_betas_disabled` — `CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS`.
/// * `legacy_client` — a client version older than the proven default.
/// * `unsupported_client` — an agent without MCP loading rules.
///
/// Only config files are read. A shell environment variable can still
/// override any of these, which the daemon cannot see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LoadingDecision {
    mode: &'static str,
    basis: &'static str,
    /// True for a client default, false for a setting read from config.
    inferred: bool,
}

impl LoadingDecision {
    const fn configured(mode: &'static str, basis: &'static str) -> Self {
        Self {
            mode,
            basis,
            inferred: false,
        }
    }

    const fn client_default(mode: &'static str, basis: &'static str) -> Self {
        Self {
            mode,
            basis,
            inferred: true,
        }
    }
}

/// The Claude Code settings `env` values that decide MCP deferral.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ClaudeLoadingEnv {
    enable_tool_search: Option<String>,
    third_party_base_url: bool,
    experimental_betas_disabled: bool,
}

/// One agent's MCP loading rules, read once per harvest cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LoadingPolicy {
    Claude {
        home: PathBuf,
        version: Option<String>,
        /// The user-scope settings `env`.
        env: ClaudeLoadingEnv,
    },
    Codex {
        version: Option<String>,
    },
    Unsupported,
}

impl LoadingPolicy {
    fn read(home: &Path, source: SnapshotSource, codex_version: Option<&str>) -> Self {
        match source {
            SnapshotSource::ClaudeCode => LoadingPolicy::Claude {
                home: home.to_path_buf(),
                version: claude_client_version(home),
                env: claude_loading_env(&claude_user_settings(home)),
            },
            SnapshotSource::Codex => LoadingPolicy::Codex {
                version: codex_version.map(str::to_string),
            },
            SnapshotSource::Pi => LoadingPolicy::Unsupported,
        }
    }

    fn client_version(&self) -> Option<String> {
        match self {
            LoadingPolicy::Claude { version, .. } | LoadingPolicy::Codex { version } => {
                version.clone()
            }
            LoadingPolicy::Unsupported => None,
        }
    }

    fn tool_search_auto_pct(&self) -> Option<u8> {
        match self {
            LoadingPolicy::Claude { env, .. } => tool_search_auto_pct(env),
            _ => None,
        }
    }

    fn decide(&self, server: &ConfiguredServer) -> LoadingDecision {
        match self {
            LoadingPolicy::Claude { home, version, env } => {
                // A server declared in a project loads under that project's
                // settings, which override the user's. A user-scope server
                // keeps the user settings: the inventory cannot tell which
                // project a session runs in.
                let project_env = server
                    .config_dir
                    .as_deref()
                    .filter(|dir| *dir != home.as_path())
                    .map(|dir| {
                        let mut files = claude_user_settings(home);
                        files.extend(claude_project_settings(dir));
                        claude_loading_env(&files)
                    });
                let effective = project_env.as_ref().unwrap_or(env);
                let decision =
                    claude_loading_decision(effective, server.always_load, version.as_deref());
                // The inventory carries one auto threshold (the user's). A
                // project threshold that differs cannot be resolved with it.
                if decision.basis == "tool_search_auto"
                    && tool_search_auto_pct(effective) != tool_search_auto_pct(env)
                {
                    return LoadingDecision::configured("unknown", "tool_search_auto_project");
                }
                decision
            }
            LoadingPolicy::Codex { version } => codex_loading_decision(version.as_deref()),
            LoadingPolicy::Unsupported => {
                LoadingDecision::client_default("unknown", "unsupported_client")
            }
        }
    }
}

/// Claude Code's deferral rules, in the order the client applies them: the
/// forced up-front cases first, then `alwaysLoad`, then `ENABLE_TOOL_SEARCH`,
/// then the version default.
fn claude_loading_decision(
    env: &ClaudeLoadingEnv,
    server_always_load: bool,
    version: Option<&str>,
) -> LoadingDecision {
    let tool_search = env
        .enable_tool_search
        .as_deref()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    if env.third_party_base_url && tool_search.is_none() {
        return LoadingDecision::configured("always_on", "proxy_base_url");
    }
    if env.experimental_betas_disabled {
        return LoadingDecision::configured("always_on", "experimental_betas_disabled");
    }
    if server_always_load {
        return LoadingDecision::configured("always_on", "always_load");
    }
    match tool_search.as_deref() {
        Some("false" | "0") => {
            return LoadingDecision::configured("always_on", "tool_search_disabled")
        }
        Some("true" | "1") => {
            return LoadingDecision::configured("on_demand", "tool_search_enabled")
        }
        Some(value) if value == "auto" || value.starts_with("auto:") => {
            return LoadingDecision::configured("unknown", "tool_search_auto")
        }
        _ => {}
    }
    match version.and_then(parse_version) {
        Some(parsed) if parsed < CLAUDE_DEFERRAL_MIN_VERSION => {
            LoadingDecision::client_default("unknown", "legacy_client")
        }
        _ => LoadingDecision::client_default("on_demand", "client_default"),
    }
}

/// Codex code-mode builds keep `[mcp_servers]` tools out of the first request.
/// Older builds are reported as `unknown`, like older Claude Code builds.
fn codex_loading_decision(version: Option<&str>) -> LoadingDecision {
    match version.and_then(parse_version) {
        Some(parsed) if parsed < CODEX_CODE_MODE_MIN_VERSION => {
            LoadingDecision::client_default("unknown", "legacy_client")
        }
        _ => LoadingDecision::client_default("on_demand", "client_default"),
    }
}

/// The `ENABLE_TOOL_SEARCH=auto[:N]` threshold, when that mode is set.
fn tool_search_auto_pct(env: &ClaudeLoadingEnv) -> Option<u8> {
    let value = env
        .enable_tool_search
        .as_deref()?
        .trim()
        .to_ascii_lowercase();
    if value == "auto" {
        return Some(CLAUDE_TOOL_SEARCH_AUTO_DEFAULT_PCT);
    }
    let pct = value.strip_prefix("auto:")?.trim().parse::<u8>().ok();
    Some(
        pct.filter(|pct| *pct <= 100)
            .unwrap_or(CLAUDE_TOOL_SEARCH_AUTO_DEFAULT_PCT),
    )
}

/// `major.minor.patch` from a version string such as `2.1.300 (Claude Code)`
/// or `0.155.0-alpha.16.4`.
pub(crate) fn parse_version(value: &str) -> Option<(u64, u64, u64)> {
    let core = value
        .trim()
        .split(|c: char| c.is_whitespace() || c == '-' || c == '+')
        .next()?;
    let mut parts = core.split('.').map(|part| part.parse::<u64>().ok());
    Some((
        parts.next()??,
        parts.next()??,
        parts.next().flatten().unwrap_or(0),
    ))
}

/// The user's Claude Code settings files, lowest precedence first.
fn claude_user_settings(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join(".claude").join("settings.json"),
        home.join(".claude").join("settings.local.json"),
    ]
}

/// A project's Claude Code settings files, lowest precedence first.
fn claude_project_settings(project_dir: &Path) -> Vec<PathBuf> {
    vec![
        project_dir.join(".claude").join("settings.json"),
        project_dir.join(".claude").join("settings.local.json"),
    ]
}

/// Read the deferral settings from Claude Code settings `env` blocks; a later
/// file overrides an earlier one, as in the client.
fn claude_loading_env(settings_files: &[PathBuf]) -> ClaudeLoadingEnv {
    let mut merged: BTreeMap<String, String> = BTreeMap::new();
    for settings in settings_files {
        let Some(value) = load_json(settings) else {
            continue;
        };
        let Some(env) = value.get("env").and_then(Value::as_object) else {
            continue;
        };
        for key in [
            "ENABLE_TOOL_SEARCH",
            "ANTHROPIC_BASE_URL",
            "CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS",
        ] {
            let text = match env.get(key) {
                Some(Value::String(text)) => Some(text.clone()),
                Some(Value::Bool(flag)) => Some(flag.to_string()),
                Some(Value::Number(number)) => Some(number.to_string()),
                _ => None,
            };
            if let Some(text) = text {
                merged.insert(key.to_string(), text);
            }
        }
    }
    ClaudeLoadingEnv {
        enable_tool_search: merged.get("ENABLE_TOOL_SEARCH").cloned(),
        third_party_base_url: merged
            .get("ANTHROPIC_BASE_URL")
            .is_some_and(|url| !is_first_party_anthropic_url(url)),
        experimental_betas_disabled: merged
            .get("CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS")
            .is_some_and(|value| is_truthy(value)),
    }
}

/// An empty base URL or an `anthropic.com` host is Anthropic's own API.
fn is_first_party_anthropic_url(url: &str) -> bool {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return true;
    }
    let without_scheme = trimmed.split_once("://").map_or(trimmed, |(_, rest)| rest);
    let host = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    host == "anthropic.com" || host.ends_with(".anthropic.com")
}

/// The Claude Code version that last ran interactively (`lastReleaseNotesSeen`
/// in `~/.claude.json`), without spawning the CLI.
fn claude_client_version(home: &Path) -> Option<String> {
    load_json(&home.join(".claude.json"))?
        .get("lastReleaseNotesSeen")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|version| parse_version(version).is_some())
        .map(|version| version.chars().take(64).collect())
}

/// Stamp each harvested server with its loading decision.
fn apply_loading_policy(
    servers: &mut [McpServerInput],
    configured: &[ConfiguredServer],
    policy: &LoadingPolicy,
) {
    for server in servers {
        let Some(config) = configured.iter().find(|c| c.name == server.server) else {
            continue;
        };
        let decision = policy.decide(config);
        server.loading_mode = decision.mode.to_string();
        server.loading_mode_basis = decision.basis.to_string();
        server.loading_mode_inferred = decision.inferred;
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
fn normalize_claude_server(
    name: &str,
    cfg: &Value,
    config_dir: Option<&Path>,
) -> Option<ConfiguredServer> {
    let declared = cfg.get("type").and_then(Value::as_str);
    let url = cfg.get("url").and_then(Value::as_str);
    // A server explicitly declared `sse`/`http` is a network transport even if
    // its `url` is missing/malformed: keep it (it harvests as unreachable, cost
    // zero) rather than silently dropping a server the user sees in their config.
    let transport = if declared == Some("sse") {
        Transport::Sse {
            url: url.unwrap_or_default().to_string(),
        }
    } else if url.is_some() || declared == Some("http") {
        Transport::Http {
            url: url.unwrap_or_default().to_string(),
        }
    } else {
        let command = cfg.get("command").and_then(Value::as_str)?.to_string();
        let args = string_args(cfg.get("args"));
        Transport::Stdio {
            command,
            args,
            cwd: cfg.get("cwd").and_then(Value::as_str).map(str::to_string),
            env: string_env(cfg.get("env")),
        }
    };
    Some(ConfiguredServer {
        config_dir: config_dir.map(Path::to_path_buf),
        name: name.to_string(),
        transport,
        disabled: false,
        always_load: cfg.get("alwaysLoad").and_then(Value::as_bool) == Some(true),
    })
}

/// Normalize one Codex `[mcp_servers.*]` block into a [`Transport`].
///
/// Mirrors `discover_codex` in harvest.py: a `url` is an HTTP transport, else
/// stdio with `command` + `args`. An explicit `enabled = false` marks the
/// server disabled (Codex does not load it); `true` or an absent key is enabled.
fn normalize_codex_server(
    name: &str,
    cfg: &Value,
    config_dir: Option<&Path>,
) -> Option<ConfiguredServer> {
    let transport = if let Some(url) = cfg.get("url").and_then(Value::as_str) {
        Transport::Http {
            url: url.to_string(),
        }
    } else {
        let command = cfg.get("command").and_then(Value::as_str)?.to_string();
        let args = string_args(cfg.get("args"));
        Transport::Stdio {
            command,
            args,
            cwd: cfg.get("cwd").and_then(Value::as_str).map(str::to_string),
            env: string_env(cfg.get("env")),
        }
    };
    Some(ConfiguredServer {
        config_dir: config_dir.map(Path::to_path_buf),
        name: name.to_string(),
        transport,
        disabled: cfg.get("enabled").and_then(Value::as_bool) == Some(false),
        always_load: false,
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

/// Coerce a JSON `env` object into a BTreeMap of strings.
fn string_env(value: Option<&Value>) -> BTreeMap<String, String> {
    value
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

/// Extract disabled server names from settings.
fn get_disabled_servers(value: &Value) -> Vec<String> {
    value
        .get("disabledMcpjsonServers")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
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
            if let Some(server) = normalize_claude_server(name, cfg, Some(home)) {
                servers.insert(name.clone(), server);
            }
        }
        // Per-project mcpServers and each project's <dir>/.mcp.json.
        if let Some(projects) = root.get("projects").and_then(Value::as_object) {
            for (project_dir, project_cfg) in projects {
                for (name, cfg) in mcp_servers_block(project_cfg) {
                    if let Some(server) =
                        normalize_claude_server(name, cfg, Some(Path::new(project_dir)))
                    {
                        servers.insert(name.clone(), server);
                    }
                }
                if let Some(dot_mcp) = load_json(&Path::new(project_dir).join(".mcp.json")) {
                    for (name, cfg) in mcp_servers_block(&dot_mcp) {
                        if let Some(server) =
                            normalize_claude_server(name, cfg, Some(Path::new(project_dir)))
                        {
                            servers.insert(name.clone(), server);
                        }
                    }
                }
            }
        }
    }

    // Settings files contribute both `mcpServers` and the enable/disable lists.
    // Collect the disable list across every settings scope Claude Code reads,
    // including per-project settings, so a server the agent never loads is not
    // counted as context cost the user is paying.
    let mut disabled_names: Vec<String> = Vec::new();
    for settings in [
        home.join(".claude").join("settings.json"),
        home.join(".claude").join("settings.local.json"),
    ] {
        if let Some(value) = load_json(&settings) {
            for (name, cfg) in mcp_servers_block(&value) {
                if let Some(server) = normalize_claude_server(name, cfg, Some(home)) {
                    servers.insert(name.clone(), server);
                }
            }
            disabled_names.extend(get_disabled_servers(&value));
        }
    }
    if let Some(root) = claude_json.as_ref() {
        if let Some(projects) = root.get("projects").and_then(Value::as_object) {
            for project_dir in projects.keys() {
                for settings in [
                    Path::new(project_dir).join(".claude").join("settings.json"),
                    Path::new(project_dir)
                        .join(".claude")
                        .join("settings.local.json"),
                ] {
                    if let Some(value) = load_json(&settings) {
                        disabled_names.extend(get_disabled_servers(&value));
                    }
                }
            }
        }
    }

    // Carry the disabled state rather than dropping the server: a server the
    // user can re-enable is information worth reporting. The backend excludes
    // disabled servers from server_count / tool_count / grand_total_tokens.
    for name in disabled_names {
        if let Some(server) = servers.get_mut(&name) {
            server.disabled = true;
        }
    }

    servers.into_values().collect()
}

/// Discover Codex MCP servers from `~/.codex/config.toml` `[mcp_servers.*]`.
fn discover_codex(home: &Path) -> Vec<ConfiguredServer> {
    let codex_dir = home.join(".codex");
    let path = codex_dir.join("config.toml");
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
        if let Some(server) = normalize_codex_server(name, &value, Some(&codex_dir)) {
            servers.insert(name.to_string(), server);
        }
    }
    servers.into_values().collect()
}

fn discover_codex_capabilities(home: &Path) -> Vec<McpCapabilityInput> {
    let path = home.join(".codex").join("config.toml");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let Ok(document) = text.parse::<toml_edit::DocumentMut>() else {
        return Vec::new();
    };
    let Some(plugins) = document.get("plugins").and_then(|item| item.as_table()) else {
        return Vec::new();
    };
    let known = [
        (
            "chrome@openai-bundled",
            "browser.chrome",
            "chrome@openai-bundled",
        ),
        (
            "browser@openai-bundled",
            "browser.in_app",
            "browser@openai-bundled",
        ),
        (
            "computer-use@openai-bundled",
            "computer.use",
            "computer-use@openai-bundled",
        ),
    ];
    let mut capabilities = Vec::new();
    for (plugin_key, capability_id, raw_origin) in known {
        let Some(plugin) = plugins.get(plugin_key) else {
            continue;
        };
        let enabled = plugin
            .get("enabled")
            .and_then(toml_edit::Item::as_value)
            .and_then(toml_edit::Value::as_bool);
        let availability_state = match enabled {
            Some(true) => "enabled",
            Some(false) => "disabled",
            None => "unknown",
        };
        capabilities.push(McpCapabilityInput {
            capability_id: capability_id.to_string(),
            raw_origin: raw_origin.to_string(),
            availability_state: availability_state.to_string(),
            evidence_source: "agent_config".to_string(),
        });
    }
    capabilities
}

fn discover_capabilities(home: &Path, source: SnapshotSource) -> Vec<McpCapabilityInput> {
    match source {
        SnapshotSource::Codex => discover_codex_capabilities(home),
        SnapshotSource::ClaudeCode | SnapshotSource::Pi => Vec::new(),
    }
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

/// The environment a stdio MCP server is spawned with, resolved ONCE per harvest
/// cycle. The daemon runs under launchd with a minimal `PATH`
/// (`/usr/bin:/bin:…`), so a bare `Command::new("npx")` cannot find the common
/// MCP launchers (`npx`/`uvx`/`node`) and every such server would falsely report
/// `reachable:false`. We resolve a launchd-safe `PATH` and the user's provider
/// env exactly as the daemon spawns its other agent subprocesses, so the harvest
/// sees the same servers an interactive shell (and the reference harvester) does.
#[derive(Clone)]
struct SpawnEnv {
    path: Option<OsString>,
    provider: BTreeMap<String, OsString>,
}

impl SpawnEnv {
    /// Resolve once per cycle (`provider_env` may briefly consult a login shell).
    fn resolve() -> Self {
        Self {
            path: crate::command_env::path_env(),
            provider: crate::command_env::provider_env(),
        }
    }

    /// Resolve `command` to an absolute path against the launchd-safe search dirs
    /// (so `npx`/`uvx`/`node` are found) and apply `PATH` + provider env to the
    /// child (so the launched server and its own subprocesses resolve too).
    /// The working directory to spawn a server in, or `None` to inherit.
    ///
    /// An absolute `cwd` is used as-is. A relative one resolves against the
    /// directory of the config that declared the server, matching how the agent
    /// itself reads it. A path that does not exist after resolution is ignored
    /// rather than failing the spawn — the server may still start fine from the
    /// default directory, and a broken `cwd` should not turn into a phantom
    /// "unreachable" row.
    fn resolve_cwd(cwd: Option<&str>, config_dir: Option<&Path>) -> Option<PathBuf> {
        let raw = cwd?.trim();
        if raw.is_empty() {
            return None;
        }
        let candidate = Path::new(raw);
        let resolved = if candidate.is_absolute() {
            candidate.to_path_buf()
        } else {
            config_dir?.join(candidate)
        };
        resolved.is_dir().then_some(resolved)
    }

    /// Spawn a server with the working directory and environment block its own
    /// config declares.
    ///
    /// A server whose config sets `cwd` (and often a matching `env`) resolves
    /// its entrypoint relative to that directory. Spawning it from the daemon's
    /// cwd instead makes it fail to start, and the harvest then reports it
    /// `reachable = false` with zero tools — indistinguishable on the wire from
    /// a server that genuinely exposes nothing, and the UI turns it into a
    /// "fix or remove unreachable servers" recommendation for a server that is
    /// perfectly healthy under Claude Code.
    ///
    /// Per-server env is applied AFTER the provider block so a server can set
    /// its own value for a key the daemon also sets; PATH stays daemon-owned so
    /// a config cannot redirect which executable is resolved.
    fn command_in(
        &self,
        command: &str,
        args: &[String],
        cwd: Option<&str>,
        config_dir: Option<&Path>,
        server_env: &BTreeMap<String, String>,
    ) -> Command {
        let program = crate::command_env::executable_path(command)
            .map(PathBuf::into_os_string)
            .unwrap_or_else(|| OsString::from(command));
        let mut cmd = Command::new(program);
        cmd.args(args);
        if let Some(path) = self.path.as_ref() {
            cmd.env("PATH", path);
        }
        for (key, value) in &self.provider {
            cmd.env(key, value);
        }
        for (key, value) in server_env {
            if key != "PATH" {
                cmd.env(key, value);
            }
        }
        // Resolve a RELATIVE cwd against the directory that declared the
        // server, never against the daemon's own. `cwd: "."` is the common
        // shape and it passes `is_dir()` unconditionally, so the previous code
        // silently set the daemon's working directory (`/` under launchd); the
        // server then could not find its project and the harvest reported it
        // unreachable with zero tools — indistinguishable on the wire from a
        // server that genuinely exposes nothing.
        if let Some(dir) = Self::resolve_cwd(cwd, config_dir) {
            cmd.current_dir(dir);
        }
        cmd
    }
}

/// What one stdio probe returns: the tool definitions and the length of the
/// server's `initialize` instructions.
#[derive(Debug, Clone, PartialEq)]
struct ProbeOutput {
    tools: Vec<McpToolInput>,
    instructions_chars: Option<u32>,
}

/// Run `initialize` + `tools/list` against a stdio MCP server and return its
/// tool definitions. The non-Unix fallback retains the threaded handshake.
/// Unix uses the existing server worker and explicit child/pipe ownership below.
#[cfg(not(unix))]
fn harvest_stdio(
    command: &str,
    args: &[String],
    env: &SpawnEnv,
    cwd: Option<&str>,
    config_dir: Option<&Path>,
    server_env: &BTreeMap<String, String>,
    claude_login: Option<&ottto_core::ClaudeConfigDirSlot>,
) -> Result<ProbeOutput> {
    let mut command = env.command_in(command, args, cwd, config_dir, server_env);
    if let Some(login) = claude_login {
        crate::claude_spawn_gate::pin_claude_login(&mut command, login);
    }
    let mut child = command
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

    let (tx, rx) = mpsc::channel::<Result<ProbeOutput>>();
    // The handshake runs on its own thread so the read loop can be abandoned on
    // timeout without blocking the sync thread. The thread owns stdin/stdout and
    // drops them when it returns, closing the pipes.
    std::thread::Builder::new()
        .name("ottto-mcp-handshake".to_string())
        .spawn(move || {
            let mut stdin = stdin;
            let mut reader = BufReader::new(stdout);
            let _ = tx.send(run_stdio_handshake(&mut stdin, &mut reader));
        })
        .map_err(|error| anyhow!("spawn mcp handshake thread failed: {error}"))?;

    match rx.recv_timeout(HANDSHAKE_TIMEOUT) {
        Ok(result) => {
            reap_unless_refreshing(child, claude_login);
            result
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // Kill the child; the detached handshake thread unblocks on the
            // closed pipe and exits, then its send fails silently.
            reap_unless_refreshing(child, claude_login);
            Err(anyhow!("mcp handshake timed out"))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            reap_unless_refreshing(child, claude_login);
            Err(anyhow!("mcp handshake thread ended unexpectedly"))
        }
    }
}

#[cfg(unix)]
#[derive(Debug)]
struct McpProbeDeferred(crate::claude_spawn_gate::ClaudeSpawnRefusal);

#[cfg(unix)]
impl std::fmt::Display for McpProbeDeferred {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "mcp probe deferred: {}", self.0.code())
    }
}

#[cfg(unix)]
impl std::error::Error for McpProbeDeferred {}

#[cfg(unix)]
fn harvest_stdio(
    command: &str,
    args: &[String],
    env: &SpawnEnv,
    cwd: Option<&str>,
    config_dir: Option<&Path>,
    server_env: &BTreeMap<String, String>,
    claude_login: Option<&ottto_core::ClaudeConfigDirSlot>,
) -> Result<ProbeOutput> {
    harvest_stdio_bounded(
        command,
        args,
        env,
        cwd,
        config_dir,
        server_env,
        claude_login,
        HANDSHAKE_TIMEOUT,
    )
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn harvest_stdio_bounded(
    command: &str,
    args: &[String],
    env: &SpawnEnv,
    cwd: Option<&str>,
    config_dir: Option<&Path>,
    server_env: &BTreeMap<String, String>,
    claude_login: Option<&ottto_core::ClaudeConfigDirSlot>,
    timeout: Duration,
) -> Result<ProbeOutput> {
    use crate::claude_spawn_gate::probe::{ChildProbe, Origin, Reader, StartError, Writer};
    let started = Instant::now();
    let deadline = started + timeout.min(HANDSHAKE_TIMEOUT);
    let command = env.command_in(command, args, cwd, config_dir, server_env);
    let mut child = ChildProbe::spawn(command, claude_login, Origin::McpInventory, deadline)
        .map_err(|error| match error {
            StartError::Refused(refusal) => anyhow::Error::new(McpProbeDeferred(refusal)),
            StartError::Io(error) => anyhow!("spawn mcp server failed: {error}"),
        })?;
    // Borrow both endpoints from the guard. On every failure the same child
    // and pipes remain available to the prestarted refresh-safe cleanup owner.
    let (stdin, stdout) = child.stdin_stdout();
    let result = run_stdio_handshake(
        &mut Writer(stdin, deadline),
        &mut BufReader::new(Reader(stdout, deadline)),
    );
    let timed_out = Instant::now() >= deadline;
    child.finish(deadline);
    // A Claude Code server may contact Anthropic while starting (at least
    // zero requests); other servers are not provider calls.
    if let Some(login) = claude_login {
        use crate::provider_calls::{CallKind, CallResult, Provider, ProviderCall, Trigger};
        crate::provider_calls::record(ProviderCall::subprocess(
            Provider::Anthropic,
            CallKind::ClaudeMcpInventoryProbe,
            crate::provider_calls::trigger_or(Trigger::Schedule),
            crate::provider_calls::claude_slot_account_hash(login).as_deref(),
            match (&result, timed_out) {
                (_, true) => CallResult::Timeout,
                (Ok(_), false) => CallResult::Ok,
                (Err(_), false) => CallResult::Error("handshake_error"),
            },
            started.elapsed(),
            0,
        ));
    }
    if timed_out {
        Err(anyhow!("mcp handshake timed out"))
    } else {
        result
    }
}

#[cfg(any(not(unix), test))]
fn reap_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Stop a probed server. A Claude Code server is stopped through the shared
/// `claude_spawn_gate::stop_claude_child`, which never kills it while that
/// could cut its login's token refresh short.
#[cfg(any(not(unix), test))]
fn reap_unless_refreshing(
    mut child: Child,
    claude_login: Option<&ottto_core::ClaudeConfigDirSlot>,
) {
    match claude_login {
        Some(login) => {
            crate::claude_spawn_gate::stop_claude_child(child, login, "mcp_inventory");
        }
        None => reap_child(&mut child),
    }
}

/// The Claude login a stdio MCP server uses when the server is Claude Code
/// itself (`claude mcp serve`, or the `@anthropic-ai/claude-code` package
/// through a launcher such as `npx`). Claude Code may refresh that login as
/// it starts. `CLAUDE_CONFIG_DIR` resolves as the child sees it: the server's
/// own env, then the provider env, then the daemon's. `Err` when it is not an
/// absolute, valid config dir (fail closed: not probed).
fn claude_login_of_server(
    command: &str,
    args: &[String],
    server_env: &BTreeMap<String, String>,
    provider_env: &BTreeMap<String, OsString>,
) -> Option<std::result::Result<ottto_core::ClaudeConfigDirSlot, ()>> {
    let is_claude = Path::new(command)
        .file_name()
        .is_some_and(|name| name == "claude")
        || args
            .iter()
            .any(|arg| arg.contains("@anthropic-ai/claude-code"));
    if !is_claude {
        return None;
    }
    let config_dir = server_env
        .get("CLAUDE_CONFIG_DIR")
        .cloned()
        .or_else(|| {
            provider_env
                .get("CLAUDE_CONFIG_DIR")
                .map(|value| value.to_string_lossy().into_owned())
        })
        .or_else(|| std::env::var("CLAUDE_CONFIG_DIR").ok());
    Some(match config_dir.filter(|dir| !dir.is_empty()) {
        None => Ok(ottto_core::ClaudeConfigDirSlot::Default),
        // A relative dir resolves against the server's working directory,
        // not the daemon's: its login cannot be checked here.
        Some(dir) if !Path::new(&dir).is_absolute() => Err(()),
        Some(dir) => ottto_core::ClaudeConfigDirSlot::registered(dir).map_err(|_| ()),
    })
}

/// Drive the JSON-RPC handshake over the child's stdio pipes.
///
/// Sends `initialize`, then the `notifications/initialized` notification, then
/// `tools/list`, reading newline-delimited JSON-RPC responses and matching them
/// by request id. Tolerates interleaved server-initiated messages.
fn run_stdio_handshake(stdin: &mut impl Write, reader: &mut impl BufRead) -> Result<ProbeOutput> {
    write_message(stdin, &initialize_request())?;
    let initialized = read_response(reader, 1)?;

    write_message(stdin, &initialized_notification())?;
    write_message(stdin, &tools_list_request())?;
    let response = read_response(reader, 2)?;

    Ok(ProbeOutput {
        tools: parse_tools(&response),
        instructions_chars: instructions_chars(&initialized),
    })
}

/// Character length of an `initialize` result's `instructions`, if any.
fn instructions_chars(response: &Value) -> Option<u32> {
    let instructions = response
        .get("result")
        .and_then(|result| result.get("instructions"))
        .and_then(Value::as_str)?;
    Some(u32::try_from(instructions.chars().count()).unwrap_or(u32::MAX))
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
//
// TODO(mcp-line-cap): `read_line` is unbounded, so a pathological server could
// buffer one giant line into the heap. Unix pipe reads/writes obey the handshake
// deadline, but active response allocation and parsing cost remain unbounded.
// A raw-byte policy is a separate decision; do not silently truncate a response.
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
                    always_load: tool
                        .get("_meta")
                        .and_then(|meta| meta.get("anthropic/alwaysLoad"))
                        .and_then(Value::as_bool)
                        == Some(true),
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
///
/// A server that is Claude Code itself is not started inside its login's
/// quiet window (15 minutes before the access token expires until a new
/// expiry is saved, or while another Claude Code process refreshes it): it is
/// returned unreachable with `deferred = true`, and the cycle keeps the last
/// good inventory (see `harvest_source`).
fn harvest_server(server: &ConfiguredServer, env: &SpawnEnv) -> (McpServerInput, bool) {
    let tools = match &server.transport {
        Transport::Stdio {
            command,
            args,
            cwd,
            env: server_env,
        } => {
            let claude_login =
                match claude_login_of_server(command, args, server_env, &env.provider) {
                    None => None,
                    Some(Err(())) => {
                        eprintln!("mcp_harvest claude_server=deferred reason=config_dir");
                        return (unreachable_server(server), true);
                    }
                    Some(Ok(slot)) => {
                        if let Err(refusal) =
                            crate::claude_spawn_gate::check_background_claude_run(&slot)
                        {
                            eprintln!(
                                "mcp_harvest claude_server=deferred reason={}",
                                refusal.code()
                            );
                            return (unreachable_server(server), true);
                        }
                        Some(slot)
                    }
                };
            let result = harvest_stdio(
                command,
                args,
                env,
                cwd.as_deref(),
                server.config_dir.as_deref(),
                server_env,
                claude_login.as_ref(),
            );
            #[cfg(unix)]
            if result
                .as_ref()
                .err()
                .is_some_and(|error| error.downcast_ref::<McpProbeDeferred>().is_some())
            {
                return (unreachable_server(server), true);
            }
            result.ok()
        }
        // TODO(mcp-http-transport): implement Streamable HTTP + SSE handshakes.
        // Until then network servers are reported unreachable (cost zero) rather
        // than fabricating a footprint.
        Transport::Http { .. } | Transport::Sse { .. } => None,
    };
    let input = match tools {
        Some(probe) => McpServerInput {
            reachable: true,
            instructions_chars: probe.instructions_chars,
            tools: probe.tools,
            ..unreachable_server(server)
        },
        None => unreachable_server(server),
    };
    (input, false)
}

/// One harvest cycle's outcome: the assembled payload, whether the wall-clock
/// budget forced an early stop, and resource metrics for the cycle.
struct BuildResult {
    inventory: McpInventoryIngestRequest,
    metrics: HarvestMetrics,
}

#[cfg(unix)]
fn probe_chunk_len(configured: &[ConfiguredServer], env: &SpawnEnv) -> usize {
    let mut logins = std::collections::BTreeSet::new();
    for (index, server) in configured
        .iter()
        .take(MCP_HARVEST_MAX_CONCURRENCY)
        .enumerate()
    {
        if let Transport::Stdio {
            command,
            args,
            env: server_env,
            ..
        } = &server.transport
        {
            if let Some(Ok(login)) =
                claude_login_of_server(command, args, server_env, &env.provider)
            {
                if !logins.insert(crate::claude_spawn_gate::probe::login_key(&login)) {
                    return index;
                }
            }
        }
    }
    configured.len().min(MCP_HARVEST_MAX_CONCURRENCY)
}

/// Harvest the configured servers concurrently, at most
/// [`MCP_HARVEST_MAX_CONCURRENCY`] at a time, stopping before a chunk once
/// `deadline` passes. Returns the harvested servers (in discovery order, minus
/// any dropped by the budget), whether the cycle was throttled, and how many
/// Claude Code servers were deferred by their login's quiet window.
fn harvest_servers(
    configured: &[ConfiguredServer],
    deadline: Instant,
    env: &SpawnEnv,
) -> (Vec<McpServerInput>, bool, usize) {
    let mut out: Vec<McpServerInput> = Vec::with_capacity(configured.len());
    let mut throttled = false;
    let mut deferred = 0;
    let mut pending = configured;
    while !pending.is_empty() {
        // The deadline is checked between chunks (not mid-probe), so a cycle can
        // overrun by at most one chunk's handshake timeout — acceptable for a
        // soft budget, and it keeps every launched probe's result.
        if Instant::now() >= deadline {
            throttled = true;
            break;
        }
        // A selected Claude credential has one admitted owner. Put repeated
        // logins in the next existing batch, after active probes settle, rather
        // than treating healthy parallel entries as deferred cleanup.
        #[cfg(unix)]
        let count = probe_chunk_len(pending, env);
        #[cfg(not(unix))]
        let count = pending.len().min(MCP_HARVEST_MAX_CONCURRENCY);
        let (chunk, rest) = pending.split_at(count);
        pending = rest;
        let handles: Vec<_> = chunk
            .iter()
            .cloned()
            .map(|server| {
                let env = env.clone();
                std::thread::Builder::new()
                    .name("ottto-mcp-harvest-worker".to_string())
                    .spawn(move || harvest_server(&server, &env))
            })
            .collect();
        for (handle, server) in handles.into_iter().zip(chunk.iter()) {
            match handle {
                // A spawn failure or a panicked worker degrades that one server to
                // unreachable rather than dropping it from the inventory silently.
                Ok(joined) => {
                    let (input, was_deferred) = joined
                        .join()
                        .unwrap_or_else(|_| (unreachable_server(server), false));
                    deferred += usize::from(was_deferred);
                    out.push(input);
                }
                Err(_) => out.push(unreachable_server(server)),
            }
        }
    }
    (out, throttled, deferred)
}

/// A configured server reported unreachable with no tools (cost zero). Its
/// loading fields are stamped by [`apply_loading_policy`].
fn unreachable_server(server: &ConfiguredServer) -> McpServerInput {
    McpServerInput {
        server: server.name.clone(),
        transport: Some(server.transport.label().to_string()),
        reachable: false,
        loading_mode: "unknown".to_string(),
        loading_mode_basis: String::new(),
        loading_mode_inferred: true,
        instructions_chars: None,
        disabled: server.disabled,
        tools: Vec::new(),
    }
}

/// Build the full inventory payload for one agent on this machine, bounded by
/// `deadline`. `machine_id` is omitted from the payload when `None` (e.g. a
/// `mcp-inventory` dump on a machine with no registered device).
fn build_inventory(
    home: &Path,
    source: SnapshotSource,
    machine_id: Option<&str>,
    deadline: Instant,
    codex_version: Option<&str>,
) -> BuildResult {
    let started = Instant::now();
    let configured = discover_servers(home, source);
    let capabilities = discover_capabilities(home, source);
    let policy = LoadingPolicy::read(home, source, codex_version);
    let spawn_env = SpawnEnv::resolve();
    let (mut servers, throttled, claude_deferred) =
        harvest_servers(&configured, deadline, &spawn_env);
    apply_loading_policy(&mut servers, &configured, &policy);
    let reachable = servers.iter().filter(|s| s.reachable).count();
    let metrics = HarvestMetrics {
        source,
        wall: started.elapsed(),
        configured: configured.len(),
        reachable,
        unreachable: servers.len() - reachable,
        dropped: configured.len() - servers.len(),
        throttled,
        claude_deferred,
        version_available: policy.client_version().is_some(),
    };
    BuildResult {
        inventory: McpInventoryIngestRequest {
            agent_source: agent_source_for(source).to_string(),
            machine_id: machine_id.map(str::to_string),
            context_window_tokens: DEFAULT_CONTEXT_WINDOW_TOKENS,
            client_version: policy.client_version(),
            tool_search_auto_pct: policy.tool_search_auto_pct(),
            servers,
            capabilities,
        },
        metrics,
    }
}

/// A relaxed deadline for the interactive `mcp-inventory` dump: the user asked
/// for it and wants every server, so harvest is effectively unbounded.
fn unbounded_deadline() -> Instant {
    Instant::now() + Duration::from_secs(3600)
}

// ---------------------------------------------------------------------------
// Resource metrics
// ---------------------------------------------------------------------------

/// Per-cycle harvest metrics, emitted as a single greppable `mcp_harvest_metrics`
/// log line for live benchmarking + alerting. Never includes any server command,
/// url, or schema.
struct HarvestMetrics {
    version_available: bool,
    source: SnapshotSource,
    wall: Duration,
    configured: usize,
    reachable: usize,
    unreachable: usize,
    dropped: usize,
    throttled: bool,
    /// Claude Code servers not started because their login was inside its
    /// refresh quiet window.
    claude_deferred: usize,
}

impl HarvestMetrics {
    fn log(&self, observed: u64, rejected: u64) {
        let (self_rss_mb, children_rss_mb, cpu_s) = process_resource_usage();
        eprintln!(
            "mcp_harvest_metrics source={} wall_ms={} configured={} reachable={} \
             unreachable={} dropped={} throttled={} claude_deferred={} max_rss_self_mb={} \
             max_rss_children_mb={} cpu_s={:.2} version_available={} version_observed={} version_rejected={} seed_rejected={}",
            self.source.api_slug(),
            self.wall.as_millis(),
            self.configured,
            self.reachable,
            self.unreachable,
            self.dropped,
            self.throttled,
            self.claude_deferred,
            self_rss_mb,
            children_rss_mb,
            cpu_s,
            self.version_available,
            observed,
            rejected,
            SEED_REJECTED.load(Ordering::Relaxed),
        );
    }
}

/// Peak RSS (self + reaped children, MB) and total CPU seconds for the process,
/// via `getrusage`. macOS reports `ru_maxrss` in bytes; Linux in kilobytes.
fn process_resource_usage() -> (u64, u64, f64) {
    fn rusage(who: libc::c_int) -> Option<libc::rusage> {
        // SAFETY: getrusage writes a fully-initialized rusage on success.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrusage(who, &mut usage) } == 0 {
            Some(usage)
        } else {
            None
        }
    }
    fn max_rss_mb(usage: &libc::rusage) -> u64 {
        let raw = usage.ru_maxrss.max(0) as u64;
        if cfg!(target_os = "macos") {
            raw / (1024 * 1024)
        } else {
            raw / 1024
        }
    }
    fn cpu_seconds(usage: &libc::rusage) -> f64 {
        let part = |t: &libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1_000_000.0;
        part(&usage.ru_utime) + part(&usage.ru_stime)
    }
    let self_usage = rusage(libc::RUSAGE_SELF);
    let children_usage = rusage(libc::RUSAGE_CHILDREN);
    let self_rss = self_usage.as_ref().map(max_rss_mb).unwrap_or(0);
    let children_rss = children_usage.as_ref().map(max_rss_mb).unwrap_or(0);
    let cpu = self_usage.as_ref().map(cpu_seconds).unwrap_or(0.0)
        + children_usage.as_ref().map(cpu_seconds).unwrap_or(0.0);
    (self_rss, children_rss, cpu)
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
    let built = build_inventory(
        &home,
        source,
        best_effort_machine_id().as_deref(),
        unbounded_deadline(),
        dump_seed(source).as_ref().and_then(Sample::version),
    );
    serde_json::to_value(&built.inventory).map_err(|error| anyhow!("encode inventory: {error}"))
}

/// Dump every supported agent's inventory as a JSON array (the default when no
/// `--agent` is given).
pub fn dump_all_inventories() -> Result<Value> {
    let home = crate::snapshot_sync::home_dir()?;
    let machine_id = best_effort_machine_id();
    let inventories: Vec<Value> = [SnapshotSource::ClaudeCode, SnapshotSource::Codex]
        .into_iter()
        .map(|source| {
            let built = build_inventory(
                &home,
                source,
                machine_id.as_deref(),
                unbounded_deadline(),
                dump_seed(source).as_ref().and_then(Sample::version),
            );
            serde_json::to_value(&built.inventory)
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
#[derive(Clone, Serialize, Deserialize)]
struct InventoryCacheEntry {
    #[serde(default, deserialize_with = "load_seed")]
    seed: Option<VersionSeed>,
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

#[derive(Clone, Serialize, Deserialize)]
struct VersionSeed {
    cli_version: Option<String>,
    started_at: String,
}
impl VersionSeed {
    fn sample(&self) -> Option<Sample> {
        Sample::new(&self.started_at, self.cli_version.as_deref()).filter(|s| s.version().is_some())
    }
    fn from_sample(sample: Sample) -> Self {
        Self {
            cli_version: sample.version().map(str::to_string),
            started_at: sample.started_at.format(&Rfc3339).unwrap_or_default(),
        }
    }
}
static SEED_REJECTED: AtomicU64 = AtomicU64::new(0);
fn load_seed<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<VersionSeed>, D::Error> {
    let raw = Value::deserialize(d)?;
    if raw.is_null() {
        return Ok(None);
    }
    let seed = serde_json::from_value::<VersionSeed>(raw)
        .ok()
        .filter(|s| s.sample().is_some());
    if seed.is_none() {
        SEED_REJECTED.fetch_add(1, Ordering::Relaxed);
    }
    Ok(seed)
}
fn dump_seed(source: SnapshotSource) -> Option<Sample> {
    let device = ottto_core::FileDeviceStore::default().load().ok()??;
    let machine = crate::snapshot_sync::snapshot_machine_id(&device).ok()??;
    let identity = destination_identity(
        &device,
        &machine,
        &crate::snapshot_sync::snapshot_api_base_url().ok()?,
    );
    read_cache(&cache_path(&default_support_dir(), source))
        .filter(|c| c.identity == identity)?
        .seed?
        .sample()
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
    let mut entry = entry.clone();
    entry.seed = entry.seed.filter(|s| s.sample().is_some());
    write_json_atomic(path, &entry);
}

/// SHA-256 over the inventory's meaningful content. `machine_id` and
/// `context_window_tokens` are constant per machine, so only `agent_source`,
/// the harvested servers (with their loading decisions), the auto tool-search
/// threshold, and allowlisted capability states participate. A client version
/// bump alone is not a change: it reaches the backend with the next upload.
fn inventory_hash(inventory: &McpInventoryIngestRequest) -> Result<String> {
    let canonical = serde_json::to_vec(&json!({
        "agent_source": inventory.agent_source,
        "servers": inventory.servers,
        "tool_search_auto_pct": inventory.tool_search_auto_pct,
        "capabilities": inventory.capabilities,
    }))
    .map_err(|error| anyhow!("hash encode failed: {error}"))?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    Ok(format!("{:x}", hasher.finalize()))
}

/// A cycle that deferred a Claude Code server (its login was in the refresh
/// quiet window) keeps the last good inventory while this destination has a
/// fresh one. Without one (first upload, or past the staleness bound) it
/// uploads with that server unreachable, so a login that stays expired cannot
/// stop uploads for good.
fn keep_last_inventory(
    claude_deferred: usize,
    cached: Option<&InventoryCacheEntry>,
    identity: &str,
    now: OffsetDateTime,
) -> bool {
    claude_deferred > 0
        && cached.is_some_and(|entry| entry.identity == identity && !cache_is_stale(entry, now))
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
    spawn_inventory_sync(None)
}
pub fn spawn_mcp_inventory_sync_for_daemon(daemon: &crate::LocalDaemon) -> Result<()> {
    spawn_inventory_sync(Some(daemon.codex_versions.clone()))
}
fn spawn_inventory_sync(feed: Option<Arc<CodexVersionFeed>>) -> Result<()> {
    let home = crate::snapshot_sync::home_dir()?;
    let support_dir = default_support_dir();
    std::thread::Builder::new()
        .name("ottto-mcp-inventory-sync".to_string())
        .spawn(move || loop {
            if let Err(error) = harvest_all_once(&home, &support_dir, feed.as_deref()) {
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
fn harvest_all_once(
    home: &Path,
    support_dir: &Path,
    feed: Option<&CodexVersionFeed>,
) -> Result<()> {
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
    let api_base_url = crate::snapshot_sync::snapshot_api_base_url()?;
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
            feed,
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
    feed: Option<&CodexVersionFeed>,
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

    let path = cache_path(support_dir, source);
    let cached = read_cache(&path);
    let (live, observed, rejected) = feed
        .filter(|_| source == SnapshotSource::Codex)
        .map_or((None, 0, 0), CodexVersionFeed::snapshot);
    let seed = (source == SnapshotSource::Codex)
        .then(|| {
            Sample::newest(
                cached
                    .as_ref()
                    .filter(|c| c.identity == identity)
                    .and_then(|c| c.seed.as_ref())
                    .and_then(VersionSeed::sample),
                live,
            )
        })
        .flatten();
    let BuildResult { inventory, metrics } = build_inventory(
        home,
        source,
        Some(machine_id),
        Instant::now() + MCP_HARVEST_CYCLE_BUDGET,
        seed.as_ref().and_then(Sample::version),
    );
    metrics.log(observed, rejected);

    // A throttled cycle harvested only part of the configured surface; uploading
    // it would drop the un-probed servers from /optimize. Skip the POST and leave
    // the cache untouched so the next cycle retries the full harvest.
    if metrics.throttled {
        return Ok(());
    }

    let hash = inventory_hash(&inventory)?;
    let now = OffsetDateTime::now_utc();

    if keep_last_inventory(metrics.claude_deferred, cached.as_ref(), &identity, now) {
        return Ok(());
    }

    if let Some(entry) = cached {
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
            seed: seed
                .filter(|s| s.version() == inventory.client_version.as_deref())
                .map(VersionSeed::from_sample),
        },
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use crate::claude_spawn_gate::test_support::{set_probe_fault, ProbeFault, ProbeFixture};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[cfg(unix)]
    fn probe_mcp(
        fixture: &ProbeFixture,
        protected: bool,
        timeout: Duration,
    ) -> Result<Vec<McpToolInput>> {
        let login = ottto_core::ClaudeConfigDirSlot::Default;
        harvest_stdio_bounded(
            fixture.script.to_str().unwrap(),
            &[],
            &SpawnEnv {
                path: None,
                provider: BTreeMap::new(),
            },
            None,
            None,
            &BTreeMap::new(),
            protected.then_some(&login),
            timeout,
        )
        .map(|probe| probe.tools)
    }

    #[cfg(unix)]
    #[test]
    #[serial_test::serial]
    fn probe_mcp_preserves_large_schema_interleaving_and_eof_framing() {
        let schema = json!({"type":"object", "properties":{"text":{"type":"string", "description":"λ".repeat(600_000)}}});
        let response = json!({"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"fixture","description":"complete","inputSchema":schema}]}}).to_string();
        let fixture = ProbeFixture::new("probe-mcp-fidelity", "mcp", response.as_bytes(), 0);
        fs::write(fixture.fake.root.join("initialize"), "banner\r\n\n{\"jsonrpc\":\"2.0\",\"method\":\"notice\"}\n{\"id\":99,\"result\":{}}\n{\"id\":1,\"result\":{}}\n").unwrap();
        let account = fixture.fake.default_account("mcp-account-uuid");
        let tools = probe_mcp(&fixture, true, Duration::from_secs(3)).unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "fixture");
        // Claude Code as an MCP server may contact Anthropic while starting.
        let lines = crate::provider_calls::test_lines(
            crate::provider_calls::CallKind::ClaudeMcpInventoryProbe,
            &account,
        );
        assert_eq!(lines.len(), 1);
        assert_eq!(
            (
                lines[0].provider.as_str(),
                lines[0].result.as_str(),
                lines[0].requests_at_least
            ),
            ("anthropic", "ok", 0)
        );
        assert_eq!(tools[0].description, "complete");
        assert_eq!(tools[0].input_schema, schema);
        let requests: Vec<Value> = fs::read_to_string(fixture.fake.root.join("requests"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            requests,
            [
                initialize_request(),
                initialized_notification(),
                tools_list_request()
            ]
        );
        fixture.wait_settled();
        assert_eq!(crate::claude_spawn_gate::probe::active_count(), 0);
    }

    #[cfg(unix)]
    #[test]
    #[serial_test::serial]
    fn probe_mcp_same_login_servers_both_reach_inventory() {
        let response =
            br#"{"id":2,"result":{"tools":[{"name":"complete","inputSchema":{"type":"object"}}]}}"#;
        let fixture = ProbeFixture::new("probe-mcp-same-login", "mcp-delayed", response, 0);
        fs::write(
            fixture.fake.root.join("initialize"),
            "{\"id\":1,\"result\":{}}\n",
        )
        .unwrap();
        let configured: Vec<_> = ["first", "second"]
            .into_iter()
            .map(|name| ConfiguredServer {
                name: name.to_string(),
                disabled: false,
                always_load: false,
                config_dir: None,
                transport: Transport::Stdio {
                    command: fixture.script.to_string_lossy().into_owned(),
                    args: Vec::new(),
                    cwd: None,
                    env: [("CLAUDE_CONFIG_DIR".to_string(), String::new())].into(),
                },
            })
            .collect();
        let (servers, throttled, deferred) = harvest_servers(
            &configured,
            Instant::now() + Duration::from_secs(6),
            &SpawnEnv {
                path: None,
                provider: BTreeMap::new(),
            },
        );
        assert!(!throttled);
        assert_eq!(deferred, 0);
        assert_eq!(
            servers
                .iter()
                .map(|server| server.server.as_str())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
        assert!(servers.iter().all(|server| server.reachable
            && server.tools.len() == 1
            && server.tools[0].name == "complete"));
        assert_eq!(
            fs::read_to_string(fixture.fake.root.join("requests"))
                .unwrap()
                .lines()
                .count(),
            6
        );
        fixture.wait_settled();
    }

    /// [regress] A held stdout must reach the deadline even if the shell exits
    /// before initialize is written (Linux CI failures on several PRs).
    #[cfg(unix)]
    #[test]
    #[serial_test::serial]
    fn probe_mcp_deadline_covers_blocked_write_and_inherited_stdout() {
        for (mode, fill) in [("sleep", true), ("hold-exit", false)] {
            let fixture = ProbeFixture::new("probe-mcp-deadline", mode, &[], 0);
            if fill {
                set_probe_fault(ProbeFault::FillStdin);
            }
            let timeout = Duration::from_millis(500);
            let started = Instant::now();
            let error = probe_mcp(&fixture, false, timeout).unwrap_err();
            let elapsed = started.elapsed();
            assert!(
                elapsed >= timeout,
                "{mode}: probe failed before its deadline: {error:#}"
            );
            assert!(elapsed < Duration::from_secs(2));
            fixture.wait_started();
            assert!(!ProbeFixture::alive(fixture.pid("direct")));
            if fill {
                assert!(crate::claude_spawn_gate::test_support::probe_write_waits() > 0);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    #[serial_test::serial]
    fn probe_mcp_protected_deadline_defers_busy_inventory_until_safe() {
        let fixture = ProbeFixture::new("probe-mcp-lock", "protected", &[], 0);
        let started = Instant::now();
        assert!(probe_mcp(&fixture, true, Duration::from_millis(500))
            .err()
            .unwrap()
            .to_string()
            .contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(2));
        fixture.wait_started();
        assert!(ProbeFixture::alive(fixture.pid("direct")));
        // Admission ignores an old lock, while stop protection still honors it.
        fs::File::options()
            .write(true)
            .open(
                fixture
                    .fake
                    .root
                    .join(crate::claude_spawn_gate::REFRESH_LOCK_FILE),
            )
            .unwrap()
            .set_modified(std::time::SystemTime::now() - Duration::from_secs(3600))
            .unwrap();
        let server = ConfiguredServer {
            name: "synthetic".to_string(),
            disabled: false,
            always_load: false,
            config_dir: None,
            transport: Transport::Stdio {
                command: fixture.script.to_string_lossy().into_owned(),
                args: Vec::new(),
                cwd: None,
                env: [("CLAUDE_CONFIG_DIR".to_string(), String::new())].into(),
            },
        };
        for _ in 0..20 {
            let (input, deferred) = harvest_server(
                &server,
                &SpawnEnv {
                    path: None,
                    provider: BTreeMap::new(),
                },
            );
            assert!(deferred);
            assert!(!input.reachable);
            assert_eq!(crate::claude_spawn_gate::probe::active_count(), 1);
        }
        *fixture.policy.policy.credential.lock().unwrap() =
            crate::claude_spawn_gate::ClaudeGateCredential::ReadFailed;
        fs::remove_file(
            fixture
                .fake
                .root
                .join(crate::claude_spawn_gate::REFRESH_LOCK_FILE),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(550));
        assert!(ProbeFixture::alive(fixture.pid("direct")));
        assert_eq!(crate::claude_spawn_gate::probe::active_count(), 1);
        *fixture.policy.policy.credential.lock().unwrap() =
            crate::claude_spawn_gate::ClaudeGateCredential::Present {
                has_refresh_token: true,
                access_expires_at: Some(OffsetDateTime::now_utc() - time::Duration::hours(1)),
            };
        std::thread::sleep(Duration::from_millis(550));
        assert!(ProbeFixture::alive(fixture.pid("direct")));
        assert_eq!(crate::claude_spawn_gate::probe::active_count(), 1);
        fixture.release();
        fixture.wait_settled();
        assert_eq!(crate::claude_spawn_gate::probe::active_count(), 0);
    }

    fn test_home(name: &str) -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join("ottto-mcp-inventory-tests")
            .join(format!("{}-{name}-{counter}", std::process::id()));
        fs::create_dir_all(&dir).expect("create test home");
        dir
    }

    /// A cheap spawn env for unit tests: the test runner's PATH, no provider env
    /// (so we never spawn a login shell). Absolute-path mock servers spawn fine.
    fn test_spawn_env() -> SpawnEnv {
        SpawnEnv {
            path: std::env::var_os("PATH"),
            provider: BTreeMap::new(),
        }
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
                args: vec!["server".to_string(), "--flag".to_string()],
                cwd: None,
                env: std::collections::BTreeMap::new(),
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
                args: vec!["mcp.js".to_string()],
                cwd: None,
                env: std::collections::BTreeMap::new(),
            }
        );

        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn claude_http_server_without_url_is_kept_not_dropped() {
        // A `type:"http"` entry with no `url` must still be discovered (as an
        // unreachable HTTP server), never silently dropped from the inventory.
        let s = normalize_claude_server("noupstream", &json!({ "type": "http" }), None)
            .expect("server kept");
        assert_eq!(s.name, "noupstream");
        assert_eq!(s.transport, Transport::Http { url: String::new() });
        // And it harvests as unreachable (cost zero), not a panic.
        let (h, _) = harvest_server(&s, &test_spawn_env());
        assert!(!h.reachable);
        assert!(h.tools.is_empty());
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

[plugins."chrome@openai-bundled"]
enabled = true

[plugins."browser@openai-bundled"]
enabled = false

[plugins."computer-use@openai-bundled"]
enabled = true
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
                args: vec!["mcp-server-fetch".to_string()],
                cwd: None,
                env: std::collections::BTreeMap::new(),
            }
        );
        assert_eq!(servers[1].name, "remote");
        assert_eq!(
            servers[1].transport,
            Transport::Http {
                url: "https://remote.test/mcp".to_string()
            }
        );
        let capabilities = discover_codex_capabilities(&home);
        assert_eq!(capabilities.len(), 3);
        assert!(capabilities.iter().any(|row| {
            row.capability_id == "browser.chrome" && row.availability_state == "enabled"
        }));
        assert!(capabilities.iter().any(|row| {
            row.capability_id == "browser.in_app" && row.availability_state == "disabled"
        }));
        assert!(capabilities.iter().any(|row| {
            row.capability_id == "computer.use" && row.availability_state == "enabled"
        }));

        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn codex_enabled_false_is_reported_disabled() {
        // Codex skips a server with `enabled = false`. It stays in the
        // inventory, carried as disabled on the wire so the backend leaves it
        // out of the configured totals; `true` and an absent key stay enabled.
        let home = test_home("codex-enabled-false");
        fs::create_dir_all(home.join(".codex")).unwrap();
        fs::write(
            home.join(".codex").join("config.toml"),
            r#"
[mcp_servers.off]
url = "https://off.test/mcp"
enabled = false

[mcp_servers.on]
url = "https://on.test/mcp"
enabled = true

[mcp_servers.unset]
url = "https://unset.test/mcp"
"#,
        )
        .unwrap();

        let wire: BTreeMap<String, bool> = discover_codex(&home)
            .iter()
            .map(|server| {
                let (input, _) = harvest_server(server, &test_spawn_env());
                (input.server, input.disabled)
            })
            .collect();

        assert_eq!(
            wire,
            BTreeMap::from([
                ("off".to_string(), true),
                ("on".to_string(), false),
                ("unset".to_string(), false),
            ])
        );

        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn network_transports_are_reported_unreachable_with_no_tools() {
        let http = ConfiguredServer {
            config_dir: None,
            name: "remote".to_string(),
            transport: Transport::Http {
                url: "https://remote.test/mcp".to_string(),
            },
            disabled: false,
            always_load: false,
        };
        let (harvested, _) = harvest_server(&http, &test_spawn_env());

        assert_eq!(harvested.server, "remote");
        assert_eq!(harvested.transport.as_deref(), Some("http"));
        assert!(!harvested.reachable);
        assert!(harvested.tools.is_empty());
        // Loading fields are stamped per policy after the harvest.
        assert_eq!(harvested.loading_mode, "unknown");
    }

    #[test]
    fn unreachable_stdio_server_is_marked_unreachable() {
        let server = ConfiguredServer {
            config_dir: None,
            name: "broken".to_string(),
            transport: Transport::Stdio {
                command: "/nonexistent/ottto-mcp-binary-xyz".to_string(),
                args: Vec::new(),
                cwd: None,
                env: std::collections::BTreeMap::new(),
            },
            disabled: false,
            always_load: false,
        };
        let (harvested, _) = harvest_server(&server, &test_spawn_env());

        assert!(!harvested.reachable);
        assert!(harvested.tools.is_empty());
        assert_eq!(harvested.transport.as_deref(), Some("stdio"));
    }

    #[test]
    fn spawn_env_applies_path_and_provider_env_to_child() {
        use std::collections::HashMap;
        use std::ffi::OsStr;

        let env = SpawnEnv {
            path: Some(OsString::from("/opt/homebrew/bin:/usr/bin")),
            provider: BTreeMap::from([("ANTHROPIC_API_KEY".to_string(), OsString::from("k"))]),
        };
        // An unresolvable command falls back to the literal name (still spawnable
        // on a machine where it IS on PATH); a resolvable launcher would become an
        // absolute path. We assert the env wiring, which is what fixes the bug.
        let cmd = env.command_in(
            "ottto-not-a-real-binary-xyz",
            &["--list".to_string()],
            None,
            None,
            &BTreeMap::new(),
        );
        assert_eq!(cmd.get_program(), OsStr::new("ottto-not-a-real-binary-xyz"));
        assert_eq!(
            cmd.get_args().collect::<Vec<_>>(),
            vec![OsStr::new("--list")]
        );
        let envs: HashMap<_, _> = cmd.get_envs().collect();
        assert_eq!(
            envs.get(OsStr::new("PATH")).copied().flatten(),
            Some(OsStr::new("/opt/homebrew/bin:/usr/bin"))
        );
        assert_eq!(
            envs.get(OsStr::new("ANTHROPIC_API_KEY")).copied().flatten(),
            Some(OsStr::new("k"))
        );
    }

    #[test]
    fn servers_disabled_in_settings_are_marked_disabled() {
        // A server listed in `disabledMcpjsonServers` is never loaded by Claude
        // Code, so counting its schema as context the user pays for overstates
        // the footprint. Observed in production: the ONE server reporting any
        // tokens at all was disabled for its project, and it contributed 100%
        // of the published schema total.
        let home = test_home("disabled-servers");
        fs::write(
            home.join(".claude.json"),
            json!({
                "mcpServers": {
                    "kept": {"command": "uvx", "args": ["kept-server"]},
                    "turned-off": {"command": "uvx", "args": ["off-server"]},
                }
            })
            .to_string(),
        )
        .expect("write .claude.json");
        fs::create_dir_all(home.join(".claude")).expect("create .claude");
        fs::write(
            home.join(".claude").join("settings.local.json"),
            json!({ "disabledMcpjsonServers": ["turned-off"] }).to_string(),
        )
        .expect("write settings.local.json");

        let servers = discover_claude_code(&home);
        let by_name: BTreeMap<&str, bool> = servers
            .iter()
            .map(|server| (server.name.as_str(), server.disabled))
            .collect();

        // Both are still DISCOVERED — a disabled server the user can re-enable
        // is information, not absence — but only one is marked active.
        assert_eq!(by_name.get("kept"), Some(&false));
        assert_eq!(by_name.get("turned-off"), Some(&true));

        let _ = fs::remove_dir_all(&home);
    }

    /// A relative `cwd` must resolve against the config that declared it.
    ///
    /// `cwd: "."` is the common shape in a project `.mcp.json`, and it passes
    /// `is_dir()` unconditionally — so resolving it against the process cwd
    /// silently pointed the server at the daemon's directory (`/` under
    /// launchd). The server could not find its project, failed to start, and
    /// the harvest published it as `reachable: false` with zero tools, which is
    /// indistinguishable from a server that genuinely exposes nothing. Observed
    /// in production on `ai-provider-watch`.
    #[test]
    fn relative_cwd_resolves_against_the_declaring_config_dir() {
        let project = test_home("relative-cwd-project");
        let nested = project.join("workspace");
        fs::create_dir_all(&nested).expect("create nested project dir");

        // "." -> the config's own directory, not the daemon's.
        assert_eq!(
            SpawnEnv::resolve_cwd(Some("."), Some(&project)),
            Some(project.clone())
        );
        // A relative subdirectory resolves beneath it.
        assert_eq!(
            SpawnEnv::resolve_cwd(Some("workspace"), Some(&project)),
            Some(nested.clone())
        );
        // An absolute cwd is untouched by the base.
        assert_eq!(
            SpawnEnv::resolve_cwd(Some(&nested.to_string_lossy()), Some(&project)),
            Some(nested)
        );
        // A relative cwd with no declaring directory is ignored rather than
        // silently resolving against the daemon's own working directory.
        assert_eq!(SpawnEnv::resolve_cwd(Some("."), None), None);
        // A resolved path that does not exist is ignored, not fatal.
        assert_eq!(SpawnEnv::resolve_cwd(Some("gone"), Some(&project)), None);
        // Absent/blank stays absent.
        assert_eq!(SpawnEnv::resolve_cwd(None, Some(&project)), None);
        assert_eq!(SpawnEnv::resolve_cwd(Some("   "), Some(&project)), None);

        let _ = fs::remove_dir_all(&project);
    }

    /// The declaring directory must survive discovery, or the resolution above
    /// has nothing to resolve against.
    #[test]
    fn discovery_records_the_declaring_config_dir() {
        let home = test_home("cwd-config-dir");
        let project = home.join("proj");
        fs::create_dir_all(&project).expect("create project dir");
        fs::write(
            home.join(".claude.json"),
            json!({ "projects": { project.to_string_lossy(): {} } }).to_string(),
        )
        .expect("write .claude.json");
        fs::write(
            project.join(".mcp.json"),
            json!({
                "mcpServers": {
                    "apw": {"command": "uv", "args": ["run", "server"], "cwd": "."}
                }
            })
            .to_string(),
        )
        .expect("write .mcp.json");

        let servers = discover_claude_code(&home);
        let apw = servers
            .iter()
            .find(|s| s.name == "apw")
            .expect("project .mcp.json server discovered");
        assert_eq!(
            apw.config_dir.as_deref(),
            Some(project.as_path()),
            "a server declared in <project>/.mcp.json must carry that project dir"
        );

        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn stdio_spawn_applies_configured_cwd_and_env() {
        // A server whose config declares `cwd`/`env` resolves its entrypoint
        // relative to that directory. Spawning it from the daemon's cwd makes
        // it fail to start and report reachable:false — indistinguishable from
        // a server that genuinely exposes nothing.
        use std::ffi::OsStr;

        let dir = test_home("stdio-cwd");
        let mut server_env = BTreeMap::new();
        server_env.insert("MCP_TOKEN".to_string(), "from-config".to_string());
        // PATH stays daemon-owned: a server config must not redirect which
        // executable gets resolved.
        server_env.insert("PATH".to_string(), "/attacker/bin".to_string());

        let env = SpawnEnv {
            path: Some(OsString::from("/opt/homebrew/bin:/usr/bin")),
            provider: BTreeMap::new(),
        };
        let cmd = env.command_in("true", &[], Some(&dir.to_string_lossy()), None, &server_env);

        assert_eq!(cmd.get_current_dir(), Some(dir.as_path()));
        let envs: BTreeMap<_, _> = cmd.get_envs().collect();
        assert_eq!(
            envs.get(OsStr::new("MCP_TOKEN")).copied().flatten(),
            Some(OsStr::new("from-config"))
        );
        assert_eq!(
            envs.get(OsStr::new("PATH")).copied().flatten(),
            Some(OsStr::new("/opt/homebrew/bin:/usr/bin")),
            "server config must not override the daemon-resolved PATH"
        );

        // A cwd that no longer exists must not make the spawn fail outright —
        // the server may still start fine from the default directory.
        let missing = dir.join("gone");
        let cmd = env.command_in(
            "true",
            &[],
            Some(&missing.to_string_lossy()),
            None,
            &BTreeMap::new(),
        );
        assert_eq!(cmd.get_current_dir(), None);

        let _ = fs::remove_dir_all(&dir);
    }

    fn claude_env(
        enable_tool_search: Option<&str>,
        base_url: bool,
        betas: bool,
    ) -> ClaudeLoadingEnv {
        ClaudeLoadingEnv {
            enable_tool_search: enable_tool_search.map(str::to_string),
            third_party_base_url: base_url,
            experimental_betas_disabled: betas,
        }
    }

    #[test]
    fn claude_code_defers_mcp_by_default_and_honours_upfront_settings() {
        let current = Some("2.1.300");
        let default = claude_loading_decision(&claude_env(None, false, false), false, current);
        assert_eq!(
            default,
            LoadingDecision::client_default("on_demand", "client_default")
        );
        // A server's own `alwaysLoad` sends its schemas up front.
        let decision = claude_loading_decision(&claude_env(None, false, false), true, current);
        assert_eq!(
            decision,
            LoadingDecision::configured("always_on", "always_load")
        );
        // ENABLE_TOOL_SEARCH turns deferral off, on, or into the threshold mode.
        for (value, mode, basis) in [
            ("false", "always_on", "tool_search_disabled"),
            ("0", "always_on", "tool_search_disabled"),
            ("true", "on_demand", "tool_search_enabled"),
            ("auto", "unknown", "tool_search_auto"),
            ("auto:5", "unknown", "tool_search_auto"),
        ] {
            let decision =
                claude_loading_decision(&claude_env(Some(value), false, false), false, current);
            assert_eq!(
                decision,
                LoadingDecision::configured(mode, basis),
                "{value}"
            );
        }
        // A proxy base URL forces up-front loading unless tool search is set.
        let proxy = claude_loading_decision(&claude_env(None, true, false), false, current);
        assert_eq!(
            proxy,
            LoadingDecision::configured("always_on", "proxy_base_url")
        );
        let proxy_opt_in =
            claude_loading_decision(&claude_env(Some("true"), true, false), false, current);
        assert_eq!(proxy_opt_in.mode, "on_demand");
        let betas = claude_loading_decision(&claude_env(Some("true"), false, true), false, current);
        assert_eq!(
            betas,
            LoadingDecision::configured("always_on", "experimental_betas_disabled")
        );
        // Builds older than the proven default are not assumed either way.
        let legacy = claude_loading_decision(&claude_env(None, false, false), false, Some("2.0.9"));
        assert_eq!(
            legacy,
            LoadingDecision::client_default("unknown", "legacy_client")
        );
        // An unreadable version keeps the current default.
        let unread = claude_loading_decision(&claude_env(None, false, false), false, None);
        assert_eq!(unread.mode, "on_demand");
    }

    #[test]
    fn codex_code_mode_builds_load_no_mcp_schema_up_front() {
        assert_eq!(
            codex_loading_decision(Some("0.162.1")),
            LoadingDecision::client_default("on_demand", "client_default")
        );
        assert_eq!(
            codex_loading_decision(Some("0.149.0-alpha.4.1")),
            LoadingDecision::client_default("on_demand", "client_default")
        );
        // Builds older than code mode are not assumed either way.
        assert_eq!(
            codex_loading_decision(Some("0.146.0-alpha.3.1")),
            LoadingDecision::client_default("unknown", "legacy_client")
        );
        assert_eq!(codex_loading_decision(None).mode, "on_demand");
    }

    #[test]
    fn loading_policy_applies_project_settings_to_project_servers() {
        let home = test_home("loading-policy-project");
        let project = home.join("proj");
        fs::create_dir_all(project.join(".claude")).unwrap();
        fs::write(
            home.join(".claude.json"),
            json!({
                "lastReleaseNotesSeen": "2.1.300",
                "mcpServers": { "global": { "command": "g" } },
                "projects": {
                    project.to_string_lossy(): { "mcpServers": { "local": { "command": "l" } } }
                }
            })
            .to_string(),
        )
        .unwrap();
        fs::write(
            project.join(".mcp.json"),
            json!({ "mcpServers": { "shared": { "command": "s" } } }).to_string(),
        )
        .unwrap();
        fs::write(
            project.join(".claude").join("settings.json"),
            json!({ "env": { "ENABLE_TOOL_SEARCH": "true" } }).to_string(),
        )
        .unwrap();
        // The project's settings.local.json wins over its settings.json.
        fs::write(
            project.join(".claude").join("settings.local.json"),
            json!({ "env": { "ENABLE_TOOL_SEARCH": "false" } }).to_string(),
        )
        .unwrap();
        let policy = LoadingPolicy::read(&home, SnapshotSource::ClaudeCode, None);
        let configured = discover_claude_code(&home);
        let mut servers: Vec<McpServerInput> = configured.iter().map(unreachable_server).collect();
        apply_loading_policy(&mut servers, &configured, &policy);
        let by_name = |name: &str| servers.iter().find(|s| s.server == name).unwrap();
        for name in ["local", "shared"] {
            assert_eq!(by_name(name).loading_mode, "always_on", "{name}");
            assert_eq!(by_name(name).loading_mode_basis, "tool_search_disabled");
            assert!(!by_name(name).loading_mode_inferred);
        }
        // A user-scope server keeps the user settings (none: client default).
        assert_eq!(by_name("global").loading_mode, "on_demand");
        assert_eq!(by_name("global").loading_mode_basis, "client_default");

        // A project auto threshold other than the user's (the one the
        // inventory carries) stays unresolved.
        fs::write(
            project.join(".claude").join("settings.local.json"),
            json!({ "env": { "ENABLE_TOOL_SEARCH": "auto:5" } }).to_string(),
        )
        .unwrap();
        let policy = LoadingPolicy::read(&home, SnapshotSource::ClaudeCode, None);
        assert_eq!(policy.tool_search_auto_pct(), None);
        let mut servers: Vec<McpServerInput> = configured.iter().map(unreachable_server).collect();
        apply_loading_policy(&mut servers, &configured, &policy);
        let local = servers.iter().find(|s| s.server == "local").unwrap();
        assert_eq!(local.loading_mode, "unknown");
        assert_eq!(local.loading_mode_basis, "tool_search_auto_project");
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn loading_policy_reads_claude_settings_and_accepts_codex_sample() {
        let home = test_home("loading-policy");
        fs::create_dir_all(home.join(".claude")).unwrap();
        fs::write(
            home.join(".claude.json"),
            json!({
                "lastReleaseNotesSeen": "2.1.299",
                "mcpServers": {
                    "pinned": { "command": "x", "alwaysLoad": true },
                    "lazy": { "command": "y" }
                }
            })
            .to_string(),
        )
        .unwrap();
        fs::write(
            home.join(".claude").join("settings.json"),
            json!({ "env": { "ENABLE_TOOL_SEARCH": "false" } }).to_string(),
        )
        .unwrap();
        // settings.local.json wins over settings.json.
        fs::write(
            home.join(".claude").join("settings.local.json"),
            json!({ "env": { "ENABLE_TOOL_SEARCH": "auto:20" } }).to_string(),
        )
        .unwrap();
        let policy = LoadingPolicy::read(&home, SnapshotSource::ClaudeCode, None);
        assert_eq!(policy.client_version().as_deref(), Some("2.1.299"));
        assert_eq!(policy.tool_search_auto_pct(), Some(20));

        let configured = discover_claude_code(&home);
        let mut servers: Vec<McpServerInput> = configured.iter().map(unreachable_server).collect();
        apply_loading_policy(&mut servers, &configured, &policy);
        let by_name = |name: &str| servers.iter().find(|s| s.server == name).unwrap();
        assert_eq!(by_name("pinned").loading_mode, "always_on");
        assert_eq!(by_name("pinned").loading_mode_basis, "always_load");
        assert!(!by_name("pinned").loading_mode_inferred);
        assert_eq!(by_name("lazy").loading_mode, "unknown");
        assert_eq!(by_name("lazy").loading_mode_basis, "tool_search_auto");

        let codex = LoadingPolicy::read(&home, SnapshotSource::Codex, Some("0.162.1"));
        assert_eq!(codex.client_version().as_deref(), Some("0.162.1"));
        assert_eq!(codex.tool_search_auto_pct(), None);

        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn handshake_reports_instructions_length_and_tool_always_load() {
        let initialize = json!({"jsonrpc":"2.0","id":1,"result":{"instructions":"héllo"}});
        assert_eq!(instructions_chars(&initialize), Some(5));
        assert_eq!(instructions_chars(&json!({"id":1,"result":{}})), None);
        let tools = parse_tools(&json!({"id":2,"result":{"tools":[
            {"name":"pinned","_meta":{"anthropic/alwaysLoad":true}},
            {"name":"lazy"}
        ]}}));
        assert!(tools[0].always_load);
        assert!(!tools[1].always_load);
        // The default flag is omitted from the payload.
        let wire = serde_json::to_value(&tools[1]).unwrap();
        assert!(wire.get("always_load").is_none());
        assert_eq!(
            serde_json::to_value(&tools[0]).unwrap()["always_load"],
            json!(true)
        );
    }

    #[test]
    fn inventory_payload_matches_backend_schema_shape() {
        let inventory = McpInventoryIngestRequest {
            agent_source: "claude-code".to_string(),
            machine_id: Some("otm_test".to_string()),
            context_window_tokens: DEFAULT_CONTEXT_WINDOW_TOKENS,
            client_version: None,
            tool_search_auto_pct: None,
            servers: vec![McpServerInput {
                server: "fetch".to_string(),
                transport: Some("stdio".to_string()),
                reachable: true,
                disabled: false,
                loading_mode: "on_demand".to_string(),
                loading_mode_basis: "client_default".to_string(),
                loading_mode_inferred: true,
                instructions_chars: None,
                tools: vec![McpToolInput {
                    name: "fetch".to_string(),
                    description: "Fetch a URL".to_string(),
                    input_schema: json!({ "type": "object" }),
                    always_load: false,
                }],
            }],
            capabilities: vec![McpCapabilityInput {
                capability_id: "browser.chrome".to_string(),
                raw_origin: "chrome@openai-bundled".to_string(),
                availability_state: "enabled".to_string(),
                evidence_source: "agent_config".to_string(),
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
    fn build_inventory_omits_machine_id_when_absent() {
        let home = test_home("no-machine");
        let value = serde_json::to_value(
            build_inventory(
                &home,
                SnapshotSource::ClaudeCode,
                None,
                unbounded_deadline(),
                None,
            )
            .inventory,
        )
        .unwrap();
        assert!(
            value.get("machine_id").is_none(),
            "machine_id omitted when None"
        );
        let with_id = serde_json::to_value(
            build_inventory(
                &home,
                SnapshotSource::ClaudeCode,
                Some("otm_x"),
                unbounded_deadline(),
                None,
            )
            .inventory,
        )
        .unwrap();
        assert_eq!(with_id["machine_id"], json!("otm_x"));
        let _ = fs::remove_dir_all(&home);
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

    fn sample_inventory(server: &str, tool: &str) -> McpInventoryIngestRequest {
        McpInventoryIngestRequest {
            agent_source: "claude-code".to_string(),
            machine_id: Some("otm_test".to_string()),
            context_window_tokens: DEFAULT_CONTEXT_WINDOW_TOKENS,
            client_version: None,
            tool_search_auto_pct: None,
            servers: vec![McpServerInput {
                server: server.to_string(),
                transport: Some("stdio".to_string()),
                reachable: true,
                disabled: false,
                loading_mode: "on_demand".to_string(),
                loading_mode_basis: "client_default".to_string(),
                loading_mode_inferred: true,
                instructions_chars: None,
                tools: vec![McpToolInput {
                    name: tool.to_string(),
                    description: String::new(),
                    input_schema: json!({ "type": "object" }),
                    always_load: false,
                }],
            }],
            capabilities: Vec::new(),
        }
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
        UploadError,
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
                                matches!(mode, HintMode::Enabled | HintMode::UploadError)
                            ),
                        ),
                    }
                } else if matches!(hint, HintMode::UploadError) {
                    (
                        "500 Internal Server Error",
                        r#"{"error":"upload"}"#.to_string(),
                    )
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
            None,
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

    #[test]
    fn claude_code_servers_are_recognised_with_the_login_they_use() {
        let args = |items: &[&str]| {
            items
                .iter()
                .map(|item| item.to_string())
                .collect::<Vec<_>>()
        };
        let none = BTreeMap::new();
        let unset: BTreeMap<String, OsString> =
            [("CLAUDE_CONFIG_DIR".to_string(), OsString::new())].into();
        let env = |dir: &str| -> BTreeMap<String, String> {
            [("CLAUDE_CONFIG_DIR".to_string(), dir.to_string())].into()
        };
        assert_eq!(
            claude_login_of_server("npx", &args(&["-y", "@acme/server"]), &none, &unset),
            None
        );
        assert_eq!(
            claude_login_of_server("claude", &args(&["mcp", "serve"]), &none, &unset),
            Some(Ok(ottto_core::ClaudeConfigDirSlot::Default))
        );
        assert_eq!(
            claude_login_of_server(
                "npx",
                &args(&["-y", "@anthropic-ai/claude-code", "mcp", "serve"]),
                &none,
                &unset
            ),
            Some(Ok(ottto_core::ClaudeConfigDirSlot::Default))
        );
        assert_eq!(
            claude_login_of_server(
                "/opt/homebrew/bin/claude",
                &args(&["mcp", "serve"]),
                &env("/tmp/ottto-fixture-slot"),
                &unset
            ),
            Some(Ok(ottto_core::ClaudeConfigDirSlot::registered(
                "/tmp/ottto-fixture-slot"
            )
            .expect("slot")))
        );
        assert_eq!(
            claude_login_of_server("claude", &args(&["mcp", "serve"]), &env("rel/slot"), &unset),
            Some(Err(())),
            "fail closed on a relative config dir"
        );
    }

    /// [behaviour] Fake `claude` and fake keychain only: a Claude Code server
    /// on the default home is never started, inside its quiet window or
    /// outside it.
    #[test]
    #[serial_test::serial]
    fn a_claude_code_server_is_never_started_on_the_default_home() {
        let fake = crate::claude_spawn_gate::test_support::FakeClaudeEnv::new("mcp");
        let server = ConfiguredServer {
            name: "claude-self".to_string(),
            transport: Transport::Stdio {
                command: "claude".to_string(),
                args: vec!["mcp".to_string(), "serve".to_string()],
                cwd: None,
                env: BTreeMap::new(),
            },
            disabled: false,
            always_load: false,
            config_dir: None,
        };
        let env = SpawnEnv {
            path: None,
            provider: [("CLAUDE_CONFIG_DIR".to_string(), OsString::new())].into(),
        };
        fake.default_login_expires_in(time::Duration::minutes(10));
        let (input, deferred) = harvest_server(&server, &env);
        assert!(deferred);
        assert!(!input.reachable);
        assert!(fake.spawns().is_empty(), "not started in the quiet window");

        fake.default_login_expires_in(time::Duration::hours(3));
        let (_, deferred) = harvest_server(&server, &env);
        assert!(deferred);
        assert!(
            fake.spawns().is_empty(),
            "never started on the default home"
        );
    }

    #[test]
    fn a_deferred_claude_server_keeps_only_a_fresh_last_inventory() {
        let now = OffsetDateTime::now_utc();
        let entry = |identity: &str, age_days: i64| InventoryCacheEntry {
            seed: None,
            identity: identity.to_string(),
            inventory_sha256: "hash".to_string(),
            posted_at: (now - time::Duration::days(age_days))
                .format(&Rfc3339)
                .expect("format"),
        };
        assert!(keep_last_inventory(1, Some(&entry("dest", 1)), "dest", now));
        assert!(!keep_last_inventory(
            0,
            Some(&entry("dest", 1)),
            "dest",
            now
        ));
        assert!(!keep_last_inventory(1, None, "dest", now), "first upload");
        assert!(!keep_last_inventory(
            1,
            Some(&entry("other", 1)),
            "dest",
            now
        ));
        assert!(
            !keep_last_inventory(1, Some(&entry("dest", 8)), "dest", now),
            "stale"
        );
    }

    /// A Claude Code server is never killed while its login's refresh lock
    /// exists (any age); it is stopped once the lock is gone. Other servers
    /// are stopped at once. Fake keychain only.
    #[test]
    #[serial_test::serial]
    fn a_claude_code_server_is_never_killed_mid_refresh() {
        let _fake = crate::claude_spawn_gate::test_support::FakeClaudeEnv::new("mcp-kill");
        let alive = |pid: i32| unsafe { libc::kill(pid, 0) } == 0;
        let dir = std::env::temp_dir().join(format!(
            "ottto-mcp-refresh-lock-{}-{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        fs::create_dir_all(&dir).expect("dir");
        let login = ottto_core::ClaudeConfigDirSlot::registered(dir.to_string_lossy().to_string())
            .expect("slot");
        let lock = dir.join(crate::claude_spawn_gate::REFRESH_LOCK_FILE);
        fs::write(&lock, "").expect("lock");
        // An old lock still counts.
        let old = std::time::SystemTime::now() - Duration::from_secs(3600);
        fs::File::options()
            .write(true)
            .open(&lock)
            .and_then(|file| file.set_modified(old))
            .expect("age the lock");

        let child = Command::new("/bin/sleep").arg("30").spawn().expect("sleep");
        let pid = i32::try_from(child.id()).expect("pid");
        reap_unless_refreshing(child, Some(&login));
        std::thread::sleep(Duration::from_millis(300));
        assert!(alive(pid), "left running while the refresh lock exists");
        fs::remove_file(&lock).expect("unlock");
        let deadline = Instant::now() + Duration::from_secs(5);
        while alive(pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(!alive(pid), "stopped once the refresh lock is gone");

        let other = Command::new("/bin/sleep").arg("30").spawn().expect("sleep");
        let other_pid = i32::try_from(other.id()).expect("pid");
        reap_unless_refreshing(other, None);
        assert!(!alive(other_pid));
        let _ = fs::remove_dir_all(&dir);
    }
    include!("mcp_inventory_version_tests.rs");
}

#[cfg(test)]
#[path = "mcp_inventory_transition_fixture.rs"]
pub(crate) mod transition_fixture;
