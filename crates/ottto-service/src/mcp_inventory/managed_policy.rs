//! Claude Code's MCP policy vetoes, applied after discovery and before any
//! server is started.
//!
//! The rules follow Claude Code's documentation (code.claude.com/docs/en/
//! managed-mcp, managed-settings and settings-reference):
//!
//!   * A `managed-mcp.json` that parses takes exclusive control: only its own
//!     servers load, so every discovered server is vetoed.
//!   * A managed settings file that exists but is not valid JSON or not a JSON
//!     object stops Claude Code from starting, so every server is vetoed. An
//!     absent or unreadable file is skipped. `managed-settings.json` and the
//!     `managed-settings.d/*.json` drop-ins merge in name order: lists combine
//!     and a later single value replaces an earlier one.
//!   * `strictPluginOnlyCustomization` (`true`, or a list naming `mcp`) blocks
//!     every server that does not come from a plugin.
//!   * `deniedMcpServers` from the managed settings and the user settings files,
//!     plus, for a local-scope or `.mcp.json` server of a project, that
//!     project's own settings files, block by name, command or URL; nothing
//!     overrides a match. `disabledMcpjsonServers` (managed, or the project's)
//!     rejects `.mcp.json` servers by name.
//!   * `allowedMcpServers`: when a list is set, a server that matches no entry is
//!     blocked. Without `allowManagedMcpServersOnly` the managed and user lists
//!     merge; with it only the managed list counts. A managed value that is not
//!     a list, or a list whose entries are all invalid, blocks every server.
//!
//! Each server's scope and client identity come from discovery
//! ([`ServerSource`]): a plugin server is `plugin:<plugin>:<server>` to the
//! client, never its inventory row name. This step only ever sets `disabled`;
//! it never enables a server. Nothing here is logged.

use super::{
    claude_project_settings, get_disabled_servers, load_json, ConfiguredServer, ServerSource,
    Transport,
};
use serde_json::{Map, Value};
use std::borrow::Cow;
use std::path::{Path, PathBuf};

/// The system directory holding Claude Code's file-based managed policy.
pub(super) fn claude_managed_dir() -> Option<PathBuf> {
    if cfg!(target_os = "macos") {
        Some(PathBuf::from("/Library/Application Support/ClaudeCode"))
    } else if cfg!(target_os = "linux") {
        Some(PathBuf::from("/etc/claude-code"))
    } else if cfg!(windows) {
        Some(PathBuf::from(r"C:\Program Files\ClaudeCode"))
    } else {
        None
    }
}

/// One `allowedMcpServers` / `deniedMcpServers` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Rule {
    Name(String),
    Command(Vec<String>),
    Url(String),
}

/// The vetoes Claude Code applies on this machine.
#[derive(Debug, Default)]
struct ClaudeMcpPolicy {
    /// Exclusive `managed-mcp.json`, or managed settings Claude Code refuses.
    block_all: bool,
    plugin_only: bool,
    denied: Vec<Rule>,
    /// Managed `disabledMcpjsonServers`: `.mcp.json` servers only.
    project_disabled: Vec<String>,
    /// `None` when no allowlist is set anywhere.
    allowed: Option<Vec<Rule>>,
    /// The managed settings `env`; policy entries expand from it first.
    managed_env: Map<String, Value>,
    /// The user settings `env`; it fills variables left in deny entries.
    user_env: Map<String, Value>,
}

/// Mark every discovered server that Claude Code's policy blocks as disabled.
pub(super) fn apply_claude_policy(
    servers: &mut [ConfiguredServer],
    user_settings: &[Value],
    managed_dir: Option<&Path>,
) {
    let policy = ClaudeMcpPolicy::read(user_settings, managed_dir);
    for server in servers.iter_mut() {
        if policy.blocks(server) {
            server.disabled = true;
        }
    }
}

/// The client's name for `server`: `plugin:<plugin>:<server>` for a plugin.
fn client_name(server: &ConfiguredServer) -> Cow<'_, str> {
    match &server.source {
        ServerSource::Plugin { plugin, server } => Cow::Owned(format!("plugin:{plugin}:{server}")),
        _ => Cow::Borrowed(&server.name),
    }
}

/// The string value of `var` in an `env` block.
fn env_value(env: &Map<String, Value>, var: &str) -> Option<String> {
    env.get(var)?.as_str().map(str::to_string)
}

/// The managed settings: `managed-settings.json`, then each
/// `managed-settings.d/*.json` in name order (hidden files skipped), merged.
/// An absent or unreadable file is left out and an empty one reads as `{}`.
/// `None` when a file is not valid JSON or not a JSON object: Claude Code then
/// refuses to start.
fn managed_settings(dir: &Path) -> Option<Value> {
    let mut files = vec![dir.join("managed-settings.json")];
    if let Ok(entries) = std::fs::read_dir(dir.join("managed-settings.d")) {
        let mut drop_ins: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| !name.starts_with('.') && name.ends_with(".json"))
            })
            .collect();
        drop_ins.sort();
        files.extend(drop_ins);
    }
    let mut merged = Value::Object(Default::default());
    for path in files {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if bytes.trim_ascii().is_empty() {
            continue;
        }
        let document = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .filter(Value::is_object)?;
        merge(&mut merged, document);
    }
    Some(merged)
}

/// Merge a later managed document into `slot`: lists combine without
/// duplicates, objects merge key by key, and any other value replaces.
fn merge(slot: &mut Value, next: Value) {
    match (slot, next) {
        (Value::Array(list), Value::Array(more)) => {
            for item in more {
                if !list.contains(&item) {
                    list.push(item);
                }
            }
        }
        (Value::Object(map), Value::Object(more)) => {
            for (key, value) in more {
                match map.get_mut(&key) {
                    Some(existing) => merge(existing, value),
                    None => {
                        map.insert(key, value);
                    }
                }
            }
        }
        (slot, next) => *slot = next,
    }
}

/// A valid list entry: an object with exactly one known key. Others are
/// stripped, as Claude Code strips invalid entries. An allowlist name holds
/// only letters, digits, `-` and `_`; a denylist name is any non-empty string
/// without surrounding whitespace.
fn parse_rule(entry: &Value, allow: bool) -> Option<Rule> {
    let map = entry.as_object()?;
    if map.len() != 1 {
        return None;
    }
    let (key, value) = map.iter().next()?;
    match key.as_str() {
        "serverName" => {
            let name = value.as_str()?;
            let valid = if allow {
                name.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            } else {
                name.trim() == name
            };
            (valid && !name.is_empty()).then(|| Rule::Name(name.to_string()))
        }
        "serverUrl" => Some(Rule::Url(value.as_str()?.to_string())),
        "serverCommand" => {
            let parts: Option<Vec<String>> = value
                .as_array()?
                .iter()
                .map(|part| part.as_str().map(str::to_string))
                .collect();
            parts.filter(|parts| !parts.is_empty()).map(Rule::Command)
        }
        _ => None,
    }
}

/// The valid entries under `key`, or `None` when the value is not a list.
fn rules(scope: &Value, key: &str) -> Option<Vec<Rule>> {
    let allow = key == "allowedMcpServers";
    let entries = scope.get(key)?.as_array()?;
    Some(
        entries
            .iter()
            .filter_map(|e| parse_rule(e, allow))
            .collect(),
    )
}

/// A managed lock reads as on unless it is `false` (or the string `"false"`):
/// an unreadable value fails closed.
fn lock_on(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(text)) => text != "false",
        Some(_) => true,
    }
}

/// `strictPluginOnlyCustomization` locks MCP when it is `true` or a list
/// naming `mcp`; a value that is neither a boolean nor a list locks it.
fn plugin_only(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(on)) => *on,
        Some(Value::Array(surfaces)) => surfaces.iter().any(|s| s == "mcp"),
        Some(_) => true,
    }
}

impl ClaudeMcpPolicy {
    fn read(user: &[Value], managed_dir: Option<&Path>) -> Self {
        let empty = Value::Object(Default::default());
        let Some(managed) = managed_dir.map_or(Some(empty), managed_settings) else {
            return Self {
                block_all: true,
                ..Self::default()
            };
        };
        let mut policy = Self {
            block_all: managed_dir
                .is_some_and(|dir| load_json(&dir.join("managed-mcp.json")).is_some()),
            plugin_only: plugin_only(managed.get("strictPluginOnlyCustomization")),
            project_disabled: get_disabled_servers(&managed),
            managed_env: managed
                .get("env")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default(),
            ..Self::default()
        };
        for scope in user {
            if let Some(env) = scope.get("env").and_then(Value::as_object) {
                policy.user_env.extend(env.clone());
            }
        }
        for scope in std::iter::once(&managed).chain(user) {
            policy
                .denied
                .extend(rules(scope, "deniedMcpServers").unwrap_or_default());
        }
        if managed
            .get("allowedMcpServers")
            .is_some_and(|v| !v.is_null())
        {
            // A managed value that is not a list is enforced as empty.
            policy.allowed = Some(rules(&managed, "allowedMcpServers").unwrap_or_default());
        }
        if !lock_on(managed.get("allowManagedMcpServersOnly")) {
            for scope in user {
                if let Some(list) = rules(scope, "allowedMcpServers") {
                    policy.allowed.get_or_insert_with(Vec::new).extend(list);
                }
            }
        }
        policy
    }

    fn blocks(&self, server: &ConfiguredServer) -> bool {
        let plugin = matches!(server.source, ServerSource::Plugin { .. });
        if self.block_all || (self.plugin_only && !plugin) {
            return true;
        }
        let name = client_name(server);
        let denies = |rules: &[Rule]| {
            rules
                .iter()
                .any(|rule| self.matches(rule, server, &name, false))
        };
        if denies(&self.denied) {
            return true;
        }
        // A project's own settings files deny its local-scope and `.mcp.json`
        // servers; `disabledMcpjsonServers` rejects `.mcp.json` servers only.
        let (project, dot_mcp) = match &server.source {
            ServerSource::Local(dir) => (Some(dir), false),
            ServerSource::Project(dir) => (Some(dir), true),
            _ => (None, false),
        };
        let rejected = |names: &[String]| dot_mcp && names.iter().any(|n| *n == *name);
        if rejected(&self.project_disabled) {
            return true;
        }
        for settings in project
            .map(|dir| claude_project_settings(dir))
            .unwrap_or_default()
            .iter()
            .filter_map(|path| load_json(path))
        {
            let denied = rules(&settings, "deniedMcpServers").unwrap_or_default();
            if rejected(&get_disabled_servers(&settings)) || denies(&denied) {
                return true;
            }
        }
        let Some(allowed) = &self.allowed else {
            return false;
        };
        // A server must match an entry of its own kind once the list has one;
        // a name entry counts only when the list has none of that kind.
        let stdio = matches!(server.transport, Transport::Stdio { .. });
        let kind_listed = allowed.iter().any(|rule| match rule {
            Rule::Command(_) => stdio,
            Rule::Url(_) => !stdio,
            Rule::Name(_) => false,
        });
        !allowed.iter().any(|rule| match rule {
            Rule::Name(_) if kind_listed => false,
            _ => self.matches(rule, server, &name, true),
        })
    }

    /// Whether `rule` matches `server`, whose client name is `name`. Names
    /// never expand. Command and URL values expand `${VAR}` and
    /// `${VAR:-default}`: a policy entry from the managed `env` first, then the
    /// daemon's environment; a configured value from the daemon's environment.
    /// The daemon's environment stands in for a session's and can differ from
    /// it. An allowlist entry left with an unset variable matches nothing. A
    /// denylist entry is also tried with unset variables filled from the user
    /// settings `env`, and as written, against the configured value expanded
    /// from the daemon's environment, from the settings `env` (managed over
    /// user) and as written, so a deny never matches less.
    fn matches(&self, rule: &Rule, server: &ConfiguredServer, name: &str, allow: bool) -> bool {
        let pinned =
            |var: &str| env_value(&self.managed_env, var).or_else(|| std::env::var(var).ok());
        let entries = |text: &str| -> Vec<String> {
            let expanded = expand(text, pinned);
            if allow {
                return expanded.into_iter().collect();
            }
            let filled = expand(text, |var| {
                pinned(var).or_else(|| env_value(&self.user_env, var))
            });
            [expanded, filled, Some(text.to_string())]
                .into_iter()
                .flatten()
                .collect()
        };
        let configured = |text: &str| -> Vec<String> {
            let expanded = expand(text, |var| std::env::var(var).ok());
            if allow {
                return vec![expanded.unwrap_or_else(|| text.to_string())];
            }
            // The client applies the settings `env` (managed over user) before
            // it expands a configured value.
            let effective = expand(text, |var| {
                env_value(&self.managed_env, var)
                    .or_else(|| env_value(&self.user_env, var))
                    .or_else(|| std::env::var(var).ok())
            });
            [expanded, effective, Some(text.to_string())]
                .into_iter()
                .flatten()
                .collect()
        };
        match (rule, &server.transport) {
            (Rule::Name(entry), _) => entry == name,
            (Rule::Command(expected), Transport::Stdio { command, args, .. }) => {
                expected.len() == args.len() + 1
                    && std::iter::once(command)
                        .chain(args)
                        .zip(expected)
                        .all(|(value, entry)| {
                            let values = configured(value);
                            entries(entry).iter().any(|entry| values.contains(entry))
                        })
            }
            (Rule::Url(pattern), Transport::Http { url } | Transport::Sse { url }) => {
                let urls = configured(url);
                entries(pattern)
                    .iter()
                    .any(|pattern| urls.iter().any(|url| url_matches(pattern, url)))
            }
            _ => false,
        }
    }
}

/// Expand `${VAR}` and `${VAR:-default}` with `lookup`; `None` when a variable
/// has neither a value nor a default.
fn expand(text: &str, lookup: impl Fn(&str) -> Option<String>) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find('}')?;
        let (name, default) = match after[..end].split_once(":-") {
            Some((name, default)) => (name, Some(default)),
            None => (&after[..end], None),
        };
        out.push_str(&lookup(name).or(default.map(str::to_string))?);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

/// A URL split into scheme, host, explicit port and path.
struct UrlParts<'a> {
    scheme: String,
    host: String,
    port: Option<&'a str>,
    path: &'a str,
}

fn split_url(url: &str) -> Option<UrlParts<'_>> {
    let (scheme, rest) = url.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let path = &tail[..tail.find(['?', '#']).unwrap_or(tail.len())];
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, after) = bracketed.split_once(']')?;
        (host, after.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    Some(UrlParts {
        scheme: scheme.to_ascii_lowercase(),
        host: host.trim_end_matches('.').to_ascii_lowercase(),
        port: port.filter(|port| !port.is_empty()),
        path,
    })
}

fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "https" | "wss" => Some(443),
        "http" | "ws" => Some(80),
        _ => None,
    }
}

/// Whether `url` matches a `serverUrl` pattern: `*` wildcards in any part,
/// case-insensitive scheme and host, case-sensitive path, and no path in the
/// pattern matching every path. Without a port, a pattern whose host is written
/// out matches only the scheme's default port; one with `*` in the host
/// matches every port.
pub(super) fn url_matches(pattern: &str, url: &str) -> bool {
    let (Some(pattern), Some(url)) = (split_url(pattern), split_url(url)) else {
        return false;
    };
    let url_port = match url.port {
        Some(port) => port.parse::<u16>().ok(),
        None => default_port(&url.scheme),
    };
    let port_ok = match pattern.port {
        Some("*") => true,
        Some(port) => port
            .parse::<u16>()
            .ok()
            .is_some_and(|p| Some(p) == url_port),
        None => pattern.host.contains('*') || url_port == default_port(&url.scheme),
    };
    let path_ok = pattern.path.is_empty()
        || glob(
            pattern.path,
            if url.path.is_empty() { "/" } else { url.path },
        );
    glob(&pattern.scheme, &url.scheme) && glob(&pattern.host, &url.host) && port_ok && path_ok
}

/// `*` matches any run of characters, `/` included.
fn glob(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}
