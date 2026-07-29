use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub const CLAUDE_STATUSLINE_CACHE_SCHEMA_VERSION: u16 = 1;
/// Version of `claude-code-rate-limits.json` ONLY, deliberately split from the
/// shared constant above.
///
/// v2 adds `observed_under_account_identifier_hash`. v1 caches carry no account
/// identity at all, so they are discarded on upgrade rather than attributed to
/// whichever account happens to be signed in now. The context-window cache and
/// its 120-sample history stay on v1: they hold no per-account numbers, and
/// bumping one shared constant would have thrown away that history as
/// collateral damage.
///
/// v3 adds `observed_under_account_method` which records HOW the account was
/// resolved (session_store, config_dir, ambiguous, or unknown). This enables
/// the service to serve samples proven via Desktop session-store join without
/// refusing merely because multiple accounts are observable.
pub const CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION: u16 = 3;
pub const CLAUDE_STATUSLINE_CACHE_FILE_NAME: &str = "claude-code-rate-limits.json";
pub const CLAUDE_STATUSLINE_CONTEXT_CACHE_FILE_NAME: &str = "claude-code-context-window.json";
pub const CLAUDE_STATUSLINE_CONTEXT_HISTORY_FILE_NAME: &str =
    "claude-code-context-window-history.json";
pub const CLAUDE_STATUSLINE_CONTEXT_HISTORY_MAX_SAMPLES: usize = 120;
const CLAUDE_STATUSLINE_RESOLUTION_MEMO_FILE_NAME: &str = "claude-code-resolution-memo.json";
const CLAUDE_STATUSLINE_RESOLUTION_MEMO_MAX_ENTRIES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaudeStatusLineAccountResolutionMethod {
    SessionStore,
    ConfigDir,
    Ambiguous,
    Unknown,
}

impl AsRef<str> for ClaudeStatusLineAccountResolutionMethod {
    fn as_ref(&self) -> &str {
        match self {
            Self::SessionStore => "session_store",
            Self::ConfigDir => "config_dir",
            Self::Ambiguous => "ambiguous",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaudeStatusLineRateLimitCache {
    pub schema_version: u16,
    /// The Claude account that the local Claude Code credential named when this
    /// sample was written -- NOT, on its own, proof of whose numbers these are.
    ///
    /// Read the name literally. `statusLine` is a Claude *Code* mechanism
    /// configured once in `~/.claude/settings.json`, and it is invoked by
    /// whichever Claude Code surface renders: the terminal CLI and the Claude
    /// Desktop app's "Code" tab pipe to the same wrapper and overwrite this one
    /// machine-global file. The payload names no account, so a writer can only
    /// record the credential it can see, which during the live 2026-07-26 repro
    /// was the work Team account while the numbers came from the personal Max
    /// account rendering in Desktop.
    ///
    /// So this field closes exactly one hole -- the CLI `/login` account switch,
    /// the same defect `ClaudeOAuthUsageCache::account_identifier_hash` closes.
    /// Proving ownership additionally requires knowing no *other* Claude account
    /// is observable on the machine; `ottto-service` applies that second half.
    /// Empty when the local account metadata named no account at write time.
    #[serde(default)]
    pub observed_under_account_identifier_hash: String,
    /// HOW the account hash was resolved: session_store join to Desktop session store,
    /// config_dir (CLI credential), ambiguous (multiple candidates that could not be
    /// resolved), or unknown (unable to resolve). Added in schema v3.
    #[serde(default)]
    pub observed_under_account_method: String,
    pub observed_at_epoch_seconds: u64,
    pub windows: Vec<ClaudeStatusLineRateLimitWindow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaudeStatusLineRateLimitWindow {
    pub name: String,
    pub used_percent: u8,
    pub resets_at_epoch_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaudeStatusLineContextWindowCache {
    pub schema_version: u16,
    pub observed_at_epoch_seconds: u64,
    pub active_tokens: Option<u64>,
    pub max_tokens: Option<u64>,
    pub used_percent: Option<u8>,
    pub remaining_tokens: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaudeStatusLineContextWindowHistory {
    pub schema_version: u16,
    pub samples: Vec<ClaudeStatusLineContextWindowSample>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaudeStatusLineContextWindowSample {
    pub observed_at_epoch_seconds: u64,
    pub active_tokens: Option<u64>,
    pub max_tokens: Option<u64>,
    pub used_percent: Option<u8>,
    pub remaining_tokens: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudeStatusLineIngestResult {
    pub stored: bool,
    pub window_count: usize,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClaudeStatusLineResolutionMemo {
    entries: Vec<ClaudeStatusLineResolutionMemoEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClaudeStatusLineResolutionMemoEntry {
    session_id_hash: String,
    account_identifier_hash: String,
    method: String,
    timestamp_seconds: u64,
}

pub fn claude_statusline_cache_path(support_dir: &Path) -> PathBuf {
    support_dir.join(CLAUDE_STATUSLINE_CACHE_FILE_NAME)
}

pub fn claude_statusline_context_cache_path(support_dir: &Path) -> PathBuf {
    support_dir.join(CLAUDE_STATUSLINE_CONTEXT_CACHE_FILE_NAME)
}

pub fn claude_statusline_context_history_path(support_dir: &Path) -> PathBuf {
    support_dir.join(CLAUDE_STATUSLINE_CONTEXT_HISTORY_FILE_NAME)
}

fn claude_statusline_resolution_memo_path(support_dir: &Path) -> PathBuf {
    support_dir.join(CLAUDE_STATUSLINE_RESOLUTION_MEMO_FILE_NAME)
}

/// Resolve which account owns the numbers in THIS render.
///
/// SAFETY INVARIANT: the session id is hashed before memoization. The memo and
/// every persisted file NEVER contain a raw session id, cwd, or transcript path.
///
/// `cli_account_identifier_hash` is the account the local Claude CLI credential
/// names right now. It is used ONLY for the `config_dir` method, where the
/// inherited entrypoint proves the render came from a terminal/IDE session and
/// therefore used that credential. It is deliberately NOT a fallback for the
/// unresolved cases: stamping it on a sample we could not attribute would put a
/// real account name on an unproven observation, and any reader that trusted
/// the hash without also checking the method would misattribute silently.
fn resolve_claude_statusline_account_for_session(
    support_dir: &Path,
    payload: &str,
    desktop_sessions_root: Option<&Path>,
    cli_entrypoint: Option<&str>,
    cli_account_identifier_hash: &str,
) -> Result<(String, ClaudeStatusLineAccountResolutionMethod)> {
    let value: Value =
        serde_json::from_str(payload).context("parse payload to extract session_id")?;

    let Some(session_id) = value.get("session_id").and_then(Value::as_str) else {
        // No session_id in payload - cannot resolve from store
        return Ok((
            String::new(),
            ClaudeStatusLineAccountResolutionMethod::Unknown,
        ));
    };

    // Try memoization first (keyed by session_id hash, not raw session_id)
    let session_id_hash = hash_session_id(session_id);
    if let Ok(Some((hash, method))) = check_resolution_memo(support_dir, &session_id_hash) {
        return Ok((hash, method));
    }

    // Try Desktop session store
    if let Some(root) = desktop_sessions_root {
        if let Ok(Some((hash, method))) = resolve_from_desktop_session_store(root, session_id) {
            // Memoize the result
            let _ = add_to_resolution_memo(support_dir, &session_id_hash, &hash, &method);
            return Ok((hash, method));
        }
    }

    // Try CLI credential if entrypoint indicates CLI session
    let is_cli_session = cli_entrypoint.is_some_and(|ep| ep.eq("cli") || ep.contains("vscode"));
    if is_cli_session && !cli_account_identifier_hash.is_empty() {
        let method = ClaudeStatusLineAccountResolutionMethod::ConfigDir;
        let _ = add_to_resolution_memo(
            support_dir,
            &session_id_hash,
            cli_account_identifier_hash,
            &method,
        );
        return Ok((cli_account_identifier_hash.to_string(), method));
    }

    // Unable to resolve
    Ok((
        String::new(),
        ClaudeStatusLineAccountResolutionMethod::Unknown,
    ))
}

fn hash_session_id(session_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(session_id.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn check_resolution_memo(
    support_dir: &Path,
    session_id_hash: &str,
) -> Result<Option<(String, ClaudeStatusLineAccountResolutionMethod)>> {
    let memo_path = claude_statusline_resolution_memo_path(support_dir);
    if !memo_path.exists() {
        return Ok(None);
    }
    let body = fs::read_to_string(&memo_path).context("read resolution memo")?;
    let memo: ClaudeStatusLineResolutionMemo =
        serde_json::from_str(&body).context("parse resolution memo")?;

    for entry in &memo.entries {
        if entry.session_id_hash == session_id_hash {
            let method = match entry.method.as_str() {
                "session_store" => ClaudeStatusLineAccountResolutionMethod::SessionStore,
                "config_dir" => ClaudeStatusLineAccountResolutionMethod::ConfigDir,
                "ambiguous" => ClaudeStatusLineAccountResolutionMethod::Ambiguous,
                _ => ClaudeStatusLineAccountResolutionMethod::Unknown,
            };
            return Ok(Some((entry.account_identifier_hash.clone(), method)));
        }
    }
    Ok(None)
}

fn add_to_resolution_memo(
    support_dir: &Path,
    session_id_hash: &str,
    account_hash: &str,
    method: &ClaudeStatusLineAccountResolutionMethod,
) -> Result<()> {
    fs::create_dir_all(support_dir).context("create support dir")?;

    let memo_path = claude_statusline_resolution_memo_path(support_dir);
    let mut memo = if memo_path.exists() {
        let body = fs::read_to_string(&memo_path).context("read existing memo")?;
        serde_json::from_str::<ClaudeStatusLineResolutionMemo>(&body).unwrap_or_else(|_| {
            ClaudeStatusLineResolutionMemo {
                entries: Vec::new(),
            }
        })
    } else {
        ClaudeStatusLineResolutionMemo {
            entries: Vec::new(),
        }
    };

    // Remove duplicate if exists
    memo.entries
        .retain(|e| e.session_id_hash != session_id_hash);

    // Add new entry
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    memo.entries.push(ClaudeStatusLineResolutionMemoEntry {
        session_id_hash: session_id_hash.to_string(),
        account_identifier_hash: account_hash.to_string(),
        method: method.as_ref().to_string(),
        timestamp_seconds: now,
    });

    // Evict oldest entries if over capacity
    if memo.entries.len() > CLAUDE_STATUSLINE_RESOLUTION_MEMO_MAX_ENTRIES {
        memo.entries.sort_by_key(|e| e.timestamp_seconds);
        let remove_count = memo.entries.len() - CLAUDE_STATUSLINE_RESOLUTION_MEMO_MAX_ENTRIES;
        memo.entries.drain(0..remove_count);
    }

    let tmp_path = memo_path.with_extension(format!("json.tmp.{}", std::process::id()));
    let body = serde_json::to_vec_pretty(&memo).context("serialize memo")?;
    fs::write(&tmp_path, body).context("write memo temp file")?;
    fs::rename(&tmp_path, &memo_path).context("replace memo")?;

    Ok(())
}

fn resolve_from_desktop_session_store(
    sessions_root: &Path,
    session_id: &str,
) -> Result<Option<(String, ClaudeStatusLineAccountResolutionMethod)>> {
    // Scan ~/Library/Application Support/Claude/claude-code-sessions/<accountUuid>/<organizationUuid>/local_<sessionId>.json
    if !sessions_root.is_dir() {
        return Ok(None);
    }

    // (account_identifier_hash, is_archived, last_activity_at)
    let mut candidates: Vec<(String, bool, String)> = Vec::new();

    // Iterate account directories
    for account_entry in fs::read_dir(sessions_root).context("read sessions root")? {
        let account_entry = account_entry.context("read account entry")?;
        let account_path = account_entry.path();
        if !account_path.is_dir() {
            continue;
        }

        let account_uuid = match account_path.file_name().and_then(|n| n.to_str()) {
            Some(uuid) => uuid.to_string(),
            None => continue,
        };

        // Iterate organization directories
        for org_entry in fs::read_dir(&account_path).context("read org directory")? {
            let org_entry = org_entry.context("read org entry")?;
            let org_path = org_entry.path();
            if !org_path.is_dir() {
                continue;
            }

            // Look for local_<sessionId>.json files
            for session_entry in fs::read_dir(&org_path).context("read session directory")? {
                let session_entry = session_entry.context("read session entry")?;
                let session_path = session_entry.path();
                let file_name = match session_path.file_name().and_then(|n| n.to_str()) {
                    Some(name) => name.to_string(),
                    None => continue,
                };

                if !file_name.ends_with(".json") {
                    continue;
                }

                // Parse the session file
                let body = match fs::read_to_string(&session_path) {
                    Ok(b) => b,
                    Err(_) => continue,
                };

                let session_obj: Value = match serde_json::from_str(&body) {
                    Ok(obj) => obj,
                    Err(_) => continue,
                };

                let cli_session_id = match session_obj.get("cliSessionId").and_then(Value::as_str) {
                    Some(id) => id,
                    None => continue,
                };

                if cli_session_id == session_id {
                    let is_archived = session_obj
                        .get("isArchived")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);

                    let account_hash =
                        crate::billing_identity_hash("anthropic", "account", &account_uuid)
                            .unwrap_or_default();

                    // `lastActivityAt` is the second tie-break for a session
                    // mirrored under two accounts (a session resumed under the
                    // other account). Compared as a string: the store writes
                    // RFC3339 UTC, which sorts lexicographically.
                    let last_activity_at = session_obj
                        .get("lastActivityAt")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();

                    candidates.push((account_hash, is_archived, last_activity_at));
                }
            }
        }
    }

    // Distinct accounts only: the same account claiming a session twice is not
    // an ambiguity, it is one owner.
    let mut distinct: Vec<(String, bool, String)> = Vec::new();
    for candidate in candidates {
        if !distinct.iter().any(|(hash, _, _)| hash == &candidate.0) {
            distinct.push(candidate);
        }
    }

    match distinct.len() {
        0 => Ok(None),
        1 => Ok(Some((
            distinct[0].0.clone(),
            ClaudeStatusLineAccountResolutionMethod::SessionStore,
        ))),
        _ => {
            // Tie-break 1: exactly one live (non-archived) claim wins.
            let live: Vec<&(String, bool, String)> = distinct
                .iter()
                .filter(|(_, archived, _)| !archived)
                .collect();
            if live.len() == 1 {
                return Ok(Some((
                    live[0].0.clone(),
                    ClaudeStatusLineAccountResolutionMethod::SessionStore,
                )));
            }
            // Tie-break 2: among the remaining claims, a single strictly
            // greatest `lastActivityAt` wins - the account that touched the
            // session last is the one that hosted this render.
            let pool: Vec<&(String, bool, String)> = if live.len() > 1 {
                live
            } else {
                distinct.iter().collect()
            };
            let newest = pool
                .iter()
                .map(|(_, _, at)| at.as_str())
                .max()
                .unwrap_or_default();
            if !newest.is_empty() {
                let winners: Vec<&&(String, bool, String)> = pool
                    .iter()
                    .filter(|(_, _, at)| at.as_str() == newest)
                    .collect();
                if winners.len() == 1 {
                    return Ok(Some((
                        winners[0].0.clone(),
                        ClaudeStatusLineAccountResolutionMethod::SessionStore,
                    )));
                }
            }
            // Genuinely unresolvable: two accounts claim the session with no
            // discriminator. Refuse rather than guess.
            Ok(Some((
                String::new(),
                ClaudeStatusLineAccountResolutionMethod::Ambiguous,
            )))
        }
    }
}

pub fn ingest_claude_statusline_payload(
    support_dir: &Path,
    payload: &str,
    observed_at_epoch_seconds: u64,
    observed_under_account_identifier_hash: &str,
) -> Result<ClaudeStatusLineIngestResult> {
    // Resolve WHOSE numbers this render carries before anything is written. The
    // environment and the memo are read here, not in the parser, so the parser
    // stays pure and this stays the one place with ambient inputs.
    let desktop_sessions_root = std::env::var("CLAUDE_DESKTOP_SESSIONS_ROOT")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME").ok().map(|home| {
                PathBuf::from(home).join("Library/Application Support/Claude/claude-code-sessions")
            })
        });
    let cli_entrypoint = std::env::var("CLAUDE_CODE_ENTRYPOINT").ok();
    let (resolved_account_hash, resolved_method) = resolve_claude_statusline_account_for_session(
        support_dir,
        payload,
        desktop_sessions_root.as_deref(),
        cli_entrypoint.as_deref(),
        observed_under_account_identifier_hash,
    )
    .unwrap_or_else(|_| {
        (
            String::new(),
            ClaudeStatusLineAccountResolutionMethod::Unknown,
        )
    });

    let rate_cache = parse_claude_statusline_payload(
        payload,
        observed_at_epoch_seconds,
        &resolved_account_hash,
        &resolved_method,
    )?;
    let context_cache =
        parse_claude_statusline_context_window_payload(payload, observed_at_epoch_seconds)?;
    let Some(cache) = rate_cache.as_ref() else {
        if let Some(context_cache) = context_cache.as_ref() {
            write_claude_statusline_context_cache(support_dir, context_cache)?;
            append_claude_statusline_context_history(support_dir, context_cache)?;
            return Ok(ClaudeStatusLineIngestResult {
                stored: true,
                window_count: 0,
                reason: None,
            });
        }
        return Ok(ClaudeStatusLineIngestResult {
            stored: false,
            window_count: 0,
            reason: Some("rate_limits_missing".to_string()),
        });
    };
    let window_count = cache.windows.len();
    write_claude_statusline_cache(support_dir, cache)?;
    if let Some(context_cache) = context_cache.as_ref() {
        write_claude_statusline_context_cache(support_dir, context_cache)?;
        append_claude_statusline_context_history(support_dir, context_cache)?;
    }
    Ok(ClaudeStatusLineIngestResult {
        stored: true,
        window_count,
        reason: None,
    })
}

/// Parse the quota windows out of a statusLine payload and stamp them with an
/// ALREADY RESOLVED account identity.
///
/// Deliberately pure: resolution reads the environment and memoizes to disk, so
/// it lives in `ingest_claude_statusline_payload`, which owns the support dir.
/// Keeping it out of here means this function has no ambient inputs and no side
/// effects, which is also what makes it testable without touching real machine
/// state.
pub fn parse_claude_statusline_payload(
    payload: &str,
    observed_at_epoch_seconds: u64,
    observed_under_account_identifier_hash: &str,
    observed_under_account_method: &ClaudeStatusLineAccountResolutionMethod,
) -> Result<Option<ClaudeStatusLineRateLimitCache>> {
    let value: Value =
        serde_json::from_str(payload).context("parse Claude Code statusLine JSON")?;
    let Some(rate_limits) = value.get("rate_limits").and_then(Value::as_object) else {
        return Ok(None);
    };

    let mut windows = Vec::new();
    for name in ["five_hour", "seven_day"] {
        if let Some(window) = rate_limits
            .get(name)
            .and_then(|value| parse_rate_limit_window(name, value))
        {
            windows.push(window);
        }
    }

    if windows.is_empty() {
        return Ok(None);
    }

    Ok(Some(ClaudeStatusLineRateLimitCache {
        schema_version: CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
        observed_under_account_identifier_hash: observed_under_account_identifier_hash.to_string(),
        observed_under_account_method: observed_under_account_method.as_ref().to_string(),
        observed_at_epoch_seconds,
        windows,
    }))
}

pub fn parse_claude_statusline_context_window_payload(
    payload: &str,
    observed_at_epoch_seconds: u64,
) -> Result<Option<ClaudeStatusLineContextWindowCache>> {
    let value: Value =
        serde_json::from_str(payload).context("parse Claude Code statusLine JSON")?;
    let Some(context_window) = value.get("context_window").and_then(Value::as_object) else {
        return Ok(None);
    };

    let max_tokens = u64_at(
        &Value::Object(context_window.clone()),
        &[
            "context_window_size",
            "max_tokens",
            "context_window_tokens",
            "window_tokens",
        ],
    );
    let used_percent = f64_at(
        &Value::Object(context_window.clone()),
        &["used_percentage", "used_percent", "pct_context"],
    )
    .and_then(percent_to_u8);
    let mut active_tokens =
        active_tokens_from_context_window(&Value::Object(context_window.clone())).or_else(|| {
            max_tokens.and_then(|max| {
                used_percent.map(|percent| ((max as f64) * (percent as f64 / 100.0)).round() as u64)
            })
        });
    let mut remaining_tokens = u64_at(
        &Value::Object(context_window.clone()),
        &[
            "remaining_tokens",
            "available_tokens",
            "free_space_tokens",
            "free_tokens",
        ],
    )
    .or_else(|| {
        let remaining_percent = f64_at(
            &Value::Object(context_window.clone()),
            &["remaining_percentage", "remaining_percent"],
        );
        max_tokens.and_then(|max| {
            remaining_percent
                .map(|percent| ((max as f64) * (percent.clamp(0.0, 100.0) / 100.0)).round() as u64)
        })
    })
    .or_else(|| match (max_tokens, active_tokens) {
        (Some(max), Some(active)) => Some(max.saturating_sub(active)),
        _ => None,
    });

    // Claude can emit a size plus zero-valued token counters before it has
    // measured live context pressure. Preserve the advertised window size,
    // but do not turn that sentinel into a synthetic 0%-used observation.
    if used_percent.is_none()
        && active_tokens == Some(0)
        && matches!((max_tokens, remaining_tokens), (Some(max), Some(remaining)) if max == remaining)
    {
        active_tokens = None;
        remaining_tokens = None;
    }

    if max_tokens.is_none() && active_tokens.is_none() && used_percent.is_none() {
        return Ok(None);
    }

    Ok(Some(ClaudeStatusLineContextWindowCache {
        schema_version: CLAUDE_STATUSLINE_CACHE_SCHEMA_VERSION,
        observed_at_epoch_seconds,
        active_tokens,
        max_tokens,
        used_percent,
        remaining_tokens,
    }))
}

pub fn read_claude_statusline_cache(
    support_dir: &Path,
) -> Result<Option<ClaudeStatusLineRateLimitCache>> {
    let path = claude_statusline_cache_path(support_dir);
    if !path.exists() {
        return Ok(None);
    }
    let body = fs::read_to_string(&path).context("read Claude Code statusLine cache")?;
    let cache: ClaudeStatusLineRateLimitCache =
        serde_json::from_str(&body).context("parse Claude Code statusLine cache")?;
    if cache.schema_version != CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION {
        // v1 and v2 caches carry no method field (or in v2's case, unresolved origin),
        // so they cannot be safely served. Discard rather than let the service
        // make decisions based on incomplete information.
        return Ok(None);
    }
    Ok(Some(cache))
}

pub fn read_claude_statusline_context_cache(
    support_dir: &Path,
) -> Result<Option<ClaudeStatusLineContextWindowCache>> {
    let path = claude_statusline_context_cache_path(support_dir);
    if !path.exists() {
        return Ok(None);
    }
    let body = fs::read_to_string(&path).context("read Claude Code statusLine context cache")?;
    let cache: ClaudeStatusLineContextWindowCache =
        serde_json::from_str(&body).context("parse Claude Code statusLine context cache")?;
    if cache.schema_version != CLAUDE_STATUSLINE_CACHE_SCHEMA_VERSION {
        return Ok(None);
    }
    Ok(Some(cache))
}

pub fn read_claude_statusline_context_history(
    support_dir: &Path,
) -> Result<Option<ClaudeStatusLineContextWindowHistory>> {
    let path = claude_statusline_context_history_path(support_dir);
    if !path.exists() {
        return Ok(None);
    }
    let body = fs::read_to_string(&path).context("read Claude Code statusLine context history")?;
    let history: ClaudeStatusLineContextWindowHistory =
        serde_json::from_str(&body).context("parse Claude Code statusLine context history")?;
    if history.schema_version != CLAUDE_STATUSLINE_CACHE_SCHEMA_VERSION {
        return Ok(None);
    }
    Ok(Some(history))
}

pub fn write_claude_statusline_cache(
    support_dir: &Path,
    cache: &ClaudeStatusLineRateLimitCache,
) -> Result<()> {
    fs::create_dir_all(support_dir).context("create Ottto support directory")?;
    let path = claude_statusline_cache_path(support_dir);
    let tmp_path = path.with_extension(format!("json.tmp.{}", std::process::id()));
    let body =
        serde_json::to_vec_pretty(cache).context("serialize Claude Code statusLine cache")?;
    fs::write(&tmp_path, body).context("write Claude Code statusLine cache temp file")?;
    fs::rename(&tmp_path, &path).context("replace Claude Code statusLine cache")?;
    Ok(())
}

pub fn write_claude_statusline_context_cache(
    support_dir: &Path,
    cache: &ClaudeStatusLineContextWindowCache,
) -> Result<()> {
    fs::create_dir_all(support_dir).context("create Ottto support directory")?;
    let path = claude_statusline_context_cache_path(support_dir);
    let tmp_path = path.with_extension(format!("json.tmp.{}", std::process::id()));
    let body = serde_json::to_vec_pretty(cache)
        .context("serialize Claude Code statusLine context cache")?;
    fs::write(&tmp_path, body).context("write Claude Code statusLine context cache temp file")?;
    fs::rename(&tmp_path, &path).context("replace Claude Code statusLine context cache")?;
    Ok(())
}

pub fn append_claude_statusline_context_history(
    support_dir: &Path,
    cache: &ClaudeStatusLineContextWindowCache,
) -> Result<()> {
    fs::create_dir_all(support_dir).context("create Ottto support directory")?;
    let mut samples = read_claude_statusline_context_history(support_dir)?
        .map(|history| history.samples)
        .unwrap_or_default();
    let sample = ClaudeStatusLineContextWindowSample {
        observed_at_epoch_seconds: cache.observed_at_epoch_seconds,
        active_tokens: cache.active_tokens,
        max_tokens: cache.max_tokens,
        used_percent: cache.used_percent,
        remaining_tokens: cache.remaining_tokens,
    };
    if let Some(existing) = samples
        .iter_mut()
        .find(|existing| existing.observed_at_epoch_seconds == sample.observed_at_epoch_seconds)
    {
        *existing = sample;
    } else {
        samples.push(sample);
    }
    samples.sort_by_key(|sample| sample.observed_at_epoch_seconds);
    if samples.len() > CLAUDE_STATUSLINE_CONTEXT_HISTORY_MAX_SAMPLES {
        let remove_count = samples.len() - CLAUDE_STATUSLINE_CONTEXT_HISTORY_MAX_SAMPLES;
        samples.drain(0..remove_count);
    }
    write_claude_statusline_context_history(
        support_dir,
        &ClaudeStatusLineContextWindowHistory {
            schema_version: CLAUDE_STATUSLINE_CACHE_SCHEMA_VERSION,
            samples,
        },
    )
}

pub fn write_claude_statusline_context_history(
    support_dir: &Path,
    history: &ClaudeStatusLineContextWindowHistory,
) -> Result<()> {
    fs::create_dir_all(support_dir).context("create Ottto support directory")?;
    let path = claude_statusline_context_history_path(support_dir);
    let tmp_path = path.with_extension(format!("json.tmp.{}", std::process::id()));
    let body = serde_json::to_vec_pretty(history)
        .context("serialize Claude Code statusLine context history")?;
    fs::write(&tmp_path, body).context("write Claude Code statusLine context history temp file")?;
    fs::rename(&tmp_path, &path).context("replace Claude Code statusLine context history")?;
    Ok(())
}

fn parse_rate_limit_window(name: &str, value: &Value) -> Option<ClaudeStatusLineRateLimitWindow> {
    let used_percent = value
        .get("used_percentage")
        .and_then(Value::as_f64)
        .and_then(percent_to_u8)?;
    let resets_at_epoch_seconds = value.get("resets_at").and_then(Value::as_u64)?;
    Some(ClaudeStatusLineRateLimitWindow {
        name: name.to_string(),
        used_percent,
        resets_at_epoch_seconds,
    })
}

fn active_tokens_from_context_window(value: &Value) -> Option<u64> {
    u64_at(
        value,
        &[
            "active_tokens",
            "used_tokens",
            "total_input_tokens",
            "input_tokens",
            "current_tokens",
            "total_tokens",
            "total_context_tokens",
        ],
    )
    .or_else(|| {
        value.get("current_usage").and_then(|usage| {
            u64_at(
                usage,
                &[
                    "total_tokens",
                    "total_context_tokens",
                    "total",
                    "context_tokens",
                    "tokens",
                ],
            )
            .or_else(|| {
                let input = u64_at(usage, &["input_tokens", "total_input_tokens"]);
                let output = u64_at(usage, &["output_tokens", "total_output_tokens"]);
                match (input, output) {
                    (Some(input), Some(output)) => Some(input.saturating_add(output)),
                    (Some(input), None) => Some(input),
                    (None, Some(output)) => Some(output),
                    _ => None,
                }
            })
        })
    })
}

fn u64_at(value: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(json_number_to_u64))
}

fn f64_at(value: &Value, keys: &[&str]) -> Option<f64> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_f64))
}

fn json_number_to_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|v| (v >= 0).then_some(v as u64)))
        .or_else(|| {
            value
                .as_f64()
                .filter(|v| v.is_finite() && *v >= 0.0)
                .map(|v| v.round() as u64)
        })
}

fn percent_to_u8(value: f64) -> Option<u8> {
    if !value.is_finite() {
        return None;
    }
    Some(value.clamp(0.0, 100.0).round() as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn support_dir(name: &str) -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "ottto-claude-statusline-{name}-{}-{counter}",
            std::process::id()
        ))
    }

    #[test]
    fn parses_rate_limits_without_persisting_other_statusline_fields() {
        let payload = r#"{
          "session_id": "session-abc123",
          "cwd": "/Users/example/private/project",
          "transcript_path": "/Users/example/.claude/projects/session.jsonl",
          "model": { "display_name": "Opus" },
          "context_window": {
            "context_window_size": 1000000,
            "current_usage": { "input_tokens": 42194, "output_tokens": 8 },
            "used_percentage": 4.2,
            "remaining_percentage": 95.8
          },
          "rate_limits": {
            "five_hour": { "used_percentage": 23.5, "resets_at": 1738425600 },
            "seven_day": { "used_percentage": 41.2, "resets_at": 1738857600 }
          }
        }"#;

        let cache = parse_claude_statusline_payload(
            payload,
            1738422000,
            "account-a",
            &ClaudeStatusLineAccountResolutionMethod::ConfigDir,
        )
        .expect("parse")
        .expect("cache");

        assert_eq!(cache.observed_at_epoch_seconds, 1738422000);
        assert_eq!(cache.windows.len(), 2);
        assert_eq!(cache.windows[0].used_percent, 24);
        assert_eq!(cache.windows[1].used_percent, 41);
        assert_eq!(cache.observed_under_account_identifier_hash, "account-a");
        let serialized = serde_json::to_string(&cache).expect("serialize");
        assert!(!serialized.contains("/Users/example"));
        assert!(!serialized.contains("transcript_path"));
        assert!(!serialized.contains("Opus"));
        // The account discriminator is an opaque hash, never an address or a
        // path: adding it must not turn a closed scalar struct into a place
        // conversation-adjacent identifiers can land.
        assert!(!serialized.contains("session-abc123"));
        assert!(!serialized.contains('@'));

        let context_cache = parse_claude_statusline_context_window_payload(payload, 1738422000)
            .expect("parse context")
            .expect("context cache");

        assert_eq!(context_cache.max_tokens, Some(1_000_000));
        assert_eq!(context_cache.active_tokens, Some(42_202));
        assert_eq!(context_cache.used_percent, Some(4));
        assert_eq!(context_cache.remaining_tokens, Some(958_000));
        let serialized = serde_json::to_string(&context_cache).expect("serialize");
        assert!(!serialized.contains("/Users/example"));
        assert!(!serialized.contains("transcript_path"));
        assert!(!serialized.contains("Opus"));
    }

    #[test]
    fn missing_rate_limits_does_not_replace_cache() {
        let dir = support_dir("missing");
        let result = ingest_claude_statusline_payload(
            &dir,
            r#"{"session_id": "session-abc123", "model":{"display_name":"Opus"}}"#,
            1,
            "account-a",
        )
        .expect("ingest");

        assert!(!result.stored);
        assert_eq!(result.reason.as_deref(), Some("rate_limits_missing"));
        assert!(!claude_statusline_cache_path(&dir).exists());
    }

    #[test]
    fn parses_official_context_window_token_fields() {
        let payload = r#"{
          "context_window": {
            "context_window_size": 1000000,
            "total_input_tokens": 42000,
            "total_output_tokens": 12,
            "used_percentage": 4.2,
            "remaining_percentage": 95.8
          }
        }"#;

        let cache = parse_claude_statusline_context_window_payload(payload, 1738422000)
            .expect("parse context")
            .expect("context cache");

        assert_eq!(cache.max_tokens, Some(1_000_000));
        assert_eq!(cache.active_tokens, Some(42_000));
        assert_eq!(cache.used_percent, Some(4));
        assert_eq!(cache.remaining_tokens, Some(958_000));
    }

    #[test]
    fn zero_token_sentinel_preserves_only_context_window_size() {
        let payload = r#"{
          "context_window": {
            "context_window_size": 1000000,
            "total_input_tokens": 0
          }
        }"#;

        let cache = parse_claude_statusline_context_window_payload(payload, 1738422000)
            .expect("parse context")
            .expect("context cache");

        assert_eq!(cache.max_tokens, Some(1_000_000));
        assert_eq!(cache.active_tokens, None);
        assert_eq!(cache.used_percent, None);
        assert_eq!(cache.remaining_tokens, None);
    }

    #[test]
    fn context_window_without_rate_limits_is_stored() {
        let dir = support_dir("context-only");
        let result = ingest_claude_statusline_payload(
            &dir,
            r#"{"session_id": "session-abc123", "context_window":{"context_window_size":1000000,"used_tokens":42000,"used_percentage":4.2}}"#,
            10,
            "account-a",
        )
        .expect("ingest");

        assert!(result.stored);
        assert_eq!(result.window_count, 0);
        assert!(result.reason.is_none());
        assert!(!claude_statusline_cache_path(&dir).exists());
        let cache = read_claude_statusline_context_cache(&dir)
            .expect("read context")
            .expect("context cache");
        assert_eq!(cache.active_tokens, Some(42_000));
        assert_eq!(cache.max_tokens, Some(1_000_000));
        assert_eq!(cache.used_percent, Some(4));
        assert_eq!(cache.remaining_tokens, Some(958_000));
        let history = read_claude_statusline_context_history(&dir)
            .expect("read context history")
            .expect("context history");
        assert_eq!(history.samples.len(), 1);
        assert_eq!(history.samples[0].observed_at_epoch_seconds, 10);
        assert_eq!(history.samples[0].active_tokens, Some(42_000));
    }

    #[test]
    fn writes_and_reads_cache_atomically() {
        let dir = support_dir("roundtrip");
        let cache = ClaudeStatusLineRateLimitCache {
            schema_version: CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
            observed_under_account_identifier_hash: "account-a".to_string(),
            observed_under_account_method: "config_dir".to_string(),
            observed_at_epoch_seconds: 10,
            windows: vec![ClaudeStatusLineRateLimitWindow {
                name: "five_hour".to_string(),
                used_percent: 7,
                resets_at_epoch_seconds: 20,
            }],
        };

        write_claude_statusline_cache(&dir, &cache).expect("write");
        assert_eq!(
            read_claude_statusline_cache(&dir).expect("read"),
            Some(cache)
        );
    }

    #[test]
    fn version_2_rate_limit_caches_are_discarded_on_upgrade() {
        // v2 predates `observed_under_account_method`: its account origin is
        // unresolved, so they must be dropped rather than adopted without proof.
        let dir = support_dir("v2-discard");
        fs::create_dir_all(&dir).expect("create support dir");
        fs::write(
            claude_statusline_cache_path(&dir),
            serde_json::to_vec_pretty(&serde_json::json!({
                "schema_version": 2,
                "observed_under_account_identifier_hash": "account-a",
                "observed_at_epoch_seconds": 10,
                "windows": [
                    { "name": "seven_day", "used_percent": 44, "resets_at_epoch_seconds": 20 }
                ]
            }))
            .expect("serialize v2"),
        )
        .expect("write v2 cache");

        assert_eq!(read_claude_statusline_cache(&dir).expect("read"), None);
    }

    #[test]
    fn context_window_cache_survives_the_rate_limit_version_bump() {
        // The rate-limit bump must not take the 120-sample context history with
        // it: those files carry no per-account numbers and nothing about them
        // changed.
        assert_ne!(
            CLAUDE_STATUSLINE_CACHE_SCHEMA_VERSION,
            CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION
        );
        let dir = support_dir("context-survives");
        let context = ClaudeStatusLineContextWindowCache {
            schema_version: CLAUDE_STATUSLINE_CACHE_SCHEMA_VERSION,
            observed_at_epoch_seconds: 10,
            active_tokens: Some(42),
            max_tokens: Some(100),
            used_percent: Some(42),
            remaining_tokens: Some(58),
        };
        write_claude_statusline_context_cache(&dir, &context).expect("write context");
        append_claude_statusline_context_history(&dir, &context).expect("append history");

        assert_eq!(
            read_claude_statusline_context_cache(&dir).expect("read context"),
            Some(context)
        );
        assert_eq!(
            read_claude_statusline_context_history(&dir)
                .expect("read history")
                .expect("history")
                .samples
                .len(),
            1
        );
    }

    #[test]
    fn writes_and_reads_context_cache_atomically() {
        let dir = support_dir("context-roundtrip");
        let cache = ClaudeStatusLineContextWindowCache {
            schema_version: CLAUDE_STATUSLINE_CACHE_SCHEMA_VERSION,
            observed_at_epoch_seconds: 10,
            active_tokens: Some(42),
            max_tokens: Some(100),
            used_percent: Some(42),
            remaining_tokens: Some(58),
        };

        write_claude_statusline_context_cache(&dir, &cache).expect("write");
        assert_eq!(
            read_claude_statusline_context_cache(&dir).expect("read"),
            Some(cache)
        );
    }

    #[test]
    fn context_history_is_deduplicated_sorted_and_capped() {
        let dir = support_dir("context-history");
        for observed_at in 0..(CLAUDE_STATUSLINE_CONTEXT_HISTORY_MAX_SAMPLES as u64 + 5) {
            append_claude_statusline_context_history(
                &dir,
                &ClaudeStatusLineContextWindowCache {
                    schema_version: CLAUDE_STATUSLINE_CACHE_SCHEMA_VERSION,
                    observed_at_epoch_seconds: observed_at,
                    active_tokens: Some(observed_at * 100),
                    max_tokens: Some(1_000_000),
                    used_percent: Some((observed_at % 100) as u8),
                    remaining_tokens: Some(1_000_000u64.saturating_sub(observed_at * 100)),
                },
            )
            .expect("append");
        }
        append_claude_statusline_context_history(
            &dir,
            &ClaudeStatusLineContextWindowCache {
                schema_version: CLAUDE_STATUSLINE_CACHE_SCHEMA_VERSION,
                observed_at_epoch_seconds: 119,
                active_tokens: Some(99_999),
                max_tokens: Some(1_000_000),
                used_percent: Some(10),
                remaining_tokens: Some(900_001),
            },
        )
        .expect("replace duplicate");

        let history = read_claude_statusline_context_history(&dir)
            .expect("read")
            .expect("history");

        assert_eq!(
            history.samples.len(),
            CLAUDE_STATUSLINE_CONTEXT_HISTORY_MAX_SAMPLES
        );
        assert_eq!(history.samples[0].observed_at_epoch_seconds, 5);
        assert_eq!(
            history.samples.last().unwrap().observed_at_epoch_seconds,
            124
        );
        let replaced = history
            .samples
            .iter()
            .find(|sample| sample.observed_at_epoch_seconds == 119)
            .expect("duplicate timestamp remains");
        assert_eq!(replaced.active_tokens, Some(99_999));
    }

    /// Build a Desktop session store fixture: <root>/<account>/<org>/local_x.json
    fn write_store_session(
        root: &Path,
        account_uuid: &str,
        cli_session_id: &str,
        is_archived: bool,
        last_activity_at: &str,
    ) {
        let dir = root.join(account_uuid).join("org-1");
        fs::create_dir_all(&dir).expect("create store dirs");
        let body = serde_json::json!({
            "cliSessionId": cli_session_id,
            "isArchived": is_archived,
            "lastActivityAt": last_activity_at,
        });
        fs::write(
            dir.join(format!("local_{cli_session_id}.json")),
            serde_json::to_vec(&body).expect("serialize session"),
        )
        .expect("write store session");
    }

    fn account_hash(uuid: &str) -> String {
        crate::billing_identity_hash("anthropic", "account", uuid).expect("hash")
    }

    fn payload_for(session_id: &str) -> String {
        format!(
            r#"{{"session_id": "{session_id}", "rate_limits": {{"five_hour": {{"used_percentage": 10, "resets_at": 1738425600}}}}}}"#
        )
    }

    #[test]
    fn session_store_hit_resolves_the_hosting_account_and_memoizes() {
        let support = support_dir("resolve-store");
        let store = support.join("store");
        fs::create_dir_all(&support).expect("support dir");
        write_store_session(
            &store,
            "acct-desktop",
            "sess-1",
            false,
            "2026-07-29T10:00:00Z",
        );

        let (hash, method) = resolve_claude_statusline_account_for_session(
            &support,
            &payload_for("sess-1"),
            Some(&store),
            None,
            "cli-credential-hash",
        )
        .expect("resolve");
        assert_eq!(
            method,
            ClaudeStatusLineAccountResolutionMethod::SessionStore
        );
        assert_eq!(hash, account_hash("acct-desktop"));

        // The memo must carry the answer without the raw session id, and must
        // survive the store going away - that is what proves it is a memo and
        // not a rescan.
        let memo = fs::read_to_string(claude_statusline_resolution_memo_path(&support))
            .expect("memo written");
        assert!(
            !memo.contains("sess-1"),
            "memo must not hold a raw session id"
        );
        fs::remove_dir_all(&store).expect("drop store");
        let (memo_hash, memo_method) = resolve_claude_statusline_account_for_session(
            &support,
            &payload_for("sess-1"),
            Some(&store),
            None,
            "cli-credential-hash",
        )
        .expect("resolve from memo");
        assert_eq!(
            memo_method,
            ClaudeStatusLineAccountResolutionMethod::SessionStore
        );
        assert_eq!(memo_hash, hash);

        let _ = fs::remove_dir_all(&support);
    }

    #[test]
    fn mirrored_session_prefers_the_live_claim_then_the_newest() {
        // A session resumed under a second account is claimed twice. Verified on
        // a real machine: 7 of 369 store sessions are mirrored like this.
        let support = support_dir("resolve-mirrored-live");
        let store = support.join("store");
        write_store_session(&store, "acct-a", "sess-m", true, "2026-07-29T10:00:00Z");
        write_store_session(&store, "acct-b", "sess-m", false, "2026-07-29T09:00:00Z");
        let (hash, method) = resolve_claude_statusline_account_for_session(
            &support,
            &payload_for("sess-m"),
            Some(&store),
            None,
            "cli-credential-hash",
        )
        .expect("resolve");
        assert_eq!(
            method,
            ClaudeStatusLineAccountResolutionMethod::SessionStore
        );
        assert_eq!(hash, account_hash("acct-b"), "the non-archived claim wins");
        let _ = fs::remove_dir_all(&support);

        // Both live: the account that touched it last hosted this render.
        let support = support_dir("resolve-mirrored-newest");
        let store = support.join("store");
        write_store_session(&store, "acct-a", "sess-n", false, "2026-07-29T08:00:00Z");
        write_store_session(&store, "acct-b", "sess-n", false, "2026-07-29T11:30:00Z");
        let (hash, method) = resolve_claude_statusline_account_for_session(
            &support,
            &payload_for("sess-n"),
            Some(&store),
            None,
            "cli-credential-hash",
        )
        .expect("resolve");
        assert_eq!(
            method,
            ClaudeStatusLineAccountResolutionMethod::SessionStore
        );
        assert_eq!(hash, account_hash("acct-b"), "newest lastActivityAt wins");
        let _ = fs::remove_dir_all(&support);
    }

    #[test]
    fn mirrored_session_with_no_discriminator_is_ambiguous_not_a_guess() {
        let support = support_dir("resolve-ambiguous");
        let store = support.join("store");
        write_store_session(&store, "acct-a", "sess-x", false, "2026-07-29T10:00:00Z");
        write_store_session(&store, "acct-b", "sess-x", false, "2026-07-29T10:00:00Z");

        let (hash, method) = resolve_claude_statusline_account_for_session(
            &support,
            &payload_for("sess-x"),
            Some(&store),
            None,
            "cli-credential-hash",
        )
        .expect("resolve");
        assert_eq!(method, ClaudeStatusLineAccountResolutionMethod::Ambiguous);
        assert!(hash.is_empty(), "an unresolved sample carries no account");
        let _ = fs::remove_dir_all(&support);
    }

    #[test]
    fn terminal_render_falls_back_to_the_credential_only_with_a_cli_entrypoint() {
        let support = support_dir("resolve-config-dir");
        let store = support.join("store");
        fs::create_dir_all(&store).expect("empty store");

        let (hash, method) = resolve_claude_statusline_account_for_session(
            &support,
            &payload_for("sess-term"),
            Some(&store),
            Some("cli"),
            "cli-credential-hash",
        )
        .expect("resolve");
        assert_eq!(method, ClaudeStatusLineAccountResolutionMethod::ConfigDir);
        assert_eq!(hash, "cli-credential-hash");
        let _ = fs::remove_dir_all(&support);

        // No entrypoint evidence: the credential holder is NOT a fallback.
        let support = support_dir("resolve-unknown");
        let store = support.join("store");
        fs::create_dir_all(&store).expect("empty store");
        let (hash, method) = resolve_claude_statusline_account_for_session(
            &support,
            &payload_for("sess-desktop-miss"),
            Some(&store),
            None,
            "cli-credential-hash",
        )
        .expect("resolve");
        assert_eq!(method, ClaudeStatusLineAccountResolutionMethod::Unknown);
        assert!(
            hash.is_empty(),
            "a store miss on a non-CLI render must not borrow the credential holder"
        );
        let _ = fs::remove_dir_all(&support);
    }

    /// NEGATIVE CONTROL: prove the per-session store join is load-bearing.
    ///
    /// The same render resolved via the store yields the hosting account; the
    /// old behavior (credential holder) yields a DIFFERENT account. If these
    /// ever matched, every attribution test in this file would pass while the
    /// resolver did nothing.
    #[test]
    fn store_resolution_differs_from_the_credential_holder() {
        let support = support_dir("resolve-negative-control");
        let store = support.join("store");
        write_store_session(
            &store,
            "acct-desktop",
            "sess-nc",
            false,
            "2026-07-29T10:00:00Z",
        );
        let credential_holder_hash = account_hash("acct-work-credential");

        let (store_hash, method) = resolve_claude_statusline_account_for_session(
            &support,
            &payload_for("sess-nc"),
            Some(&store),
            Some("cli"),
            &credential_holder_hash,
        )
        .expect("resolve");

        assert_eq!(
            method,
            ClaudeStatusLineAccountResolutionMethod::SessionStore
        );
        assert_eq!(store_hash, account_hash("acct-desktop"));
        assert_ne!(
            store_hash, credential_holder_hash,
            "the store must win over the credential holder, otherwise this whole \
             change is decorative and the sample would be misattributed"
        );
        let _ = fs::remove_dir_all(&support);
    }

    #[test]
    fn cache_and_memo_contain_no_sensitive_strings() {
        let support_dir = support_dir("privacy-test");
        let session_id = "sensitive-session-id-xyz";
        let cwd = "/Users/sensitive/private/project";
        let transcript_path = "/Users/sensitive/.claude/projects/session.jsonl";

        let payload = format!(
            r#"{{"session_id": "{session_id}", "cwd": "{cwd}", "transcript_path": "{transcript_path}", "rate_limits": {{"five_hour": {{"used_percentage": 10, "resets_at": 1738425600}}}}}}"#
        );

        ingest_claude_statusline_payload(&support_dir, &payload, 100, "account-hash")
            .expect("ingest");

        // Check cache file
        if let Ok(Some(cache)) = read_claude_statusline_cache(&support_dir) {
            let serialized = serde_json::to_string(&cache).expect("serialize");
            assert!(!serialized.contains(session_id));
            assert!(!serialized.contains(cwd));
            assert!(!serialized.contains(transcript_path));
        }

        // Check memo file
        let memo_path = claude_statusline_resolution_memo_path(&support_dir);
        if memo_path.exists() {
            let body = fs::read_to_string(&memo_path).expect("read memo");
            assert!(!body.contains(session_id));
            assert!(!body.contains(cwd));
            assert!(!body.contains(transcript_path));
        }
    }
}
