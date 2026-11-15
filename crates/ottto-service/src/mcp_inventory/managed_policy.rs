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
//!     absent or unreadable file is skipped.
//!   * `deniedMcpServers` entries from the managed files and the user settings
//!     files, and managed `disabledMcpjsonServers` names, merge into one
//!     denylist; a match by name, command or URL blocks the server and nothing
//!     overrides it.
//!   * `allowedMcpServers`: when a list is set, a server that matches no entry is
//!     blocked. Without `allowManagedMcpServersOnly` the managed and user lists
//!     merge; with it only the managed list counts. A managed value that is not
//!     a list is enforced as an empty list.
//!
//! This step only ever sets `disabled`; it never enables a server. Entries match
//! literally: `${VAR}` references in them are not expanded. Nothing here is
//! logged.

use super::{claude_row_name, get_disabled_servers, load_json, ConfiguredServer, Transport};
use serde_json::Value;
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
    denied: Vec<Rule>,
    /// `None` when no allowlist is set anywhere.
    allowed: Option<Vec<Rule>>,
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

/// The managed settings documents: `managed-settings.json`, then each
/// `managed-settings.d/*.json` in name order, skipping hidden files. An absent
/// or unreadable file is left out and an empty one reads as `{}`. `None` when a
/// file is not valid JSON or not a JSON object: Claude Code then refuses to
/// start.
fn managed_settings(dir: &Path) -> Option<Vec<Value>> {
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
    let mut documents = Vec::new();
    for path in files {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if bytes.trim_ascii().is_empty() {
            continue;
        }
        documents.push(
            serde_json::from_slice::<Value>(&bytes)
                .ok()
                .filter(Value::is_object)?,
        );
    }
    Some(documents)
}

/// A valid list entry: an object with exactly one known key. Others are
/// stripped, as Claude Code strips invalid entries.
fn parse_rule(entry: &Value) -> Option<Rule> {
    let map = entry.as_object()?;
    if map.len() != 1 {
        return None;
    }
    let (key, value) = map.iter().next()?;
    match key.as_str() {
        "serverName" => Some(Rule::Name(value.as_str()?.to_string())),
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
    Some(
        scope
            .get(key)?
            .as_array()?
            .iter()
            .filter_map(parse_rule)
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

impl ClaudeMcpPolicy {
    fn read(user: &[Value], managed_dir: Option<&Path>) -> Self {
        let Some(managed) = managed_dir.map_or(Some(Vec::new()), managed_settings) else {
            return Self {
                block_all: true,
                ..Self::default()
            };
        };
        let mut policy = Self {
            block_all: managed_dir
                .is_some_and(|dir| load_json(&dir.join("managed-mcp.json")).is_some()),
            ..Self::default()
        };
        for scope in managed.iter().chain(user) {
            policy
                .denied
                .extend(rules(scope, "deniedMcpServers").unwrap_or_default());
        }
        for scope in &managed {
            policy
                .denied
                .extend(get_disabled_servers(scope).into_iter().map(Rule::Name));
            if scope.get("allowedMcpServers").is_some_and(|v| !v.is_null()) {
                // A managed value that is not a list is enforced as empty.
                let list = rules(scope, "allowedMcpServers").unwrap_or_default();
                policy.allowed.get_or_insert_with(Vec::new).extend(list);
            }
        }
        let managed_only = managed
            .iter()
            .any(|scope| lock_on(scope.get("allowManagedMcpServersOnly")));
        if !managed_only {
            for scope in user {
                if let Some(list) = rules(scope, "allowedMcpServers") {
                    policy.allowed.get_or_insert_with(Vec::new).extend(list);
                }
            }
        }
        policy
    }

    fn blocks(&self, server: &ConfiguredServer) -> bool {
        if self.block_all || self.denied.iter().any(|rule| rule_matches(rule, server)) {
            return true;
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
            _ => rule_matches(rule, server),
        })
    }
}

fn rule_matches(rule: &Rule, server: &ConfiguredServer) -> bool {
    match (rule, &server.transport) {
        (Rule::Name(name), _) => *name == server.name || claude_row_name(name) == server.name,
        (Rule::Command(expected), Transport::Stdio { command, args, .. }) => {
            std::iter::once(command).chain(args).eq(expected)
        }
        (Rule::Url(pattern), Transport::Http { url } | Transport::Sse { url }) => {
            url_matches(pattern, url)
        }
        _ => false,
    }
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
