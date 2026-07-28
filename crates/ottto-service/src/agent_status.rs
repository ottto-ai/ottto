use aes::Aes128;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use ottto_core::{
    billing_identity_hash, claude_account_identifier_hash, compiled_release_version,
    default_support_dir, read_claude_statusline_cache, read_claude_statusline_context_cache,
    read_claude_statusline_context_history, ClaudeStatusLineContextWindowCache,
    ClaudeStatusLineContextWindowHistory, ClaudeStatusLineContextWindowSample,
    ClaudeStatusLineRateLimitCache,
};
use ottto_protocol::{
    AgentAccountStatus, AgentAvailableModelStatus, AgentCapabilityGap, AgentCapabilityStatus,
    AgentContextCompleteness, AgentContextPressureSample, AgentContextState, AgentContextStatus,
    AgentCreditBalance, AgentCreditBalanceStatus, AgentCreditBalanceUnit, AgentDiagnosticSeverity,
    AgentLoginState, AgentModelStatus, AgentQuotaWindow, AgentQuotaWindowFreshness,
    AgentQuotaWindowScope, AgentQuotaWindowStatus, AgentRuntimeDefaults,
    AgentStatusCollectionMethod, AgentStatusConfidence, AgentStatusDiagnostic,
    AgentStatusPlanObservation, AgentStatusSnapshot, AgentStatusState, SourceKind,
};
use pbkdf2::pbkdf2_hmac;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use time::{
    format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime, UtcOffset,
};
use zeroize::Zeroizing;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const CODEX_APP_SERVER_TIMEOUT: Duration = Duration::from_secs(20);
const PIPE_DRAIN_TIMEOUT: Duration = Duration::from_millis(750);
const MAX_AVAILABLE_MODELS: usize = 250;
const CLAUDE_STATUSLINE_CACHE_MAX_AGE_SECONDS: u64 = 24 * 60 * 60;
const CLAUDE_STATUSLINE_CACHE_FRESH_AGE_SECONDS: u64 = 15 * 60;
const CLAUDE_STATUSLINE_CONTEXT_HISTORY_RESPONSE_MAX_SAMPLES: usize = 48;
const CLAUDE_OAUTH_KEYCHAIN_SERVICE: &str = "Claude Code-credentials";
const CLAUDE_OAUTH_USAGE_ENDPOINT: &str = "https://api.anthropic.com/api/oauth/usage";
const CLAUDE_OAUTH_BETA_HEADER: &str = "oauth-2025-04-20";
const CLAUDE_OAUTH_USAGE_CACHE_FILE: &str = "claude-code-oauth-usage-cache.json";
/// Display fallback only: how long a cached payload may still be rendered (as
/// `Stale`) when the endpoint cannot be reached. Not a refresh cadence.
const CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS: u64 = 24 * 60 * 60;
/// Base refresh cadence: ~1 fetch per hour per machine (~24/day), down from the
/// former 15-minute gate (~96/day). Sparse polling is half of the recorded
/// provider-endpoints posture (identify honestly, poll sparsely, circuit-break
/// instead of adapting).
const CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_SECONDS: u64 = 60 * 60;
/// Half-width of the deterministic spread applied to the base cadence, giving
/// an effective gate in the 55-65 minute range.
const CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_JITTER_SECONDS: u64 = 5 * 60;
const CLAUDE_OAUTH_USAGE_REFRESH_SECONDS: u64 = 5 * 60;
const CLAUDE_OAUTH_USAGE_RETRY_AFTER_FALLBACK_SECONDS: u64 = 5 * 60;
/// Off-switch sentinel: while this file exists in the daemon support dir the
/// Claude OAuth usage endpoint is never contacted and quota comes from the
/// sanctioned local statusLine surface only. The name is a fixed contract with
/// the macOS Companion toggle - do not rename it.
const CLAUDE_OAUTH_USAGE_NETWORK_DISABLED_FILE: &str = "claude-oauth-usage-network-disabled";
const CLAUDE_OAUTH_USAGE_BREAKER_FILE: &str = "claude-oauth-usage-breaker.json";
const CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION: u16 = 1;
/// How long the breaker stays open once tripped. Long on purpose: an open
/// breaker means we believe further calls could be unwelcome or useless, and a
/// short cool-down would just re-probe the same wall.
const CLAUDE_OAUTH_USAGE_BREAKER_COOLDOWN_SECONDS: u64 = 24 * 60 * 60;
/// Consecutive 401/403 responses before the breaker opens. Low: an auth/scope
/// rejection that survives a retry is structural, not transient.
const CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD: u32 = 3;
/// Consecutive unreadable/unrecognised 200 bodies (or a vanished endpoint)
/// before the breaker opens.
const CLAUDE_OAUTH_USAGE_BREAKER_SHAPE_THRESHOLD: u32 = 3;
/// Consecutive 429s before the breaker opens. Higher than the other classes:
/// a single 429 is routine here and is already handled by the retry-after
/// backoff; this catches the sustained case that backoff never clears.
const CLAUDE_OAUTH_USAGE_BREAKER_RATE_LIMIT_THRESHOLD: u32 = 5;
const CLAUDE_DESKTOP_CODE_SESSION_MAX_FILES_PER_ORG: usize = 500;
const CLAUDE_DESKTOP_AGENT_MODE_MAX_FILES_PER_ORG: usize = 200;
const CLAUDE_DESKTOP_SAFE_STORAGE_SERVICE: &str = "Claude Safe Storage";
const CLAUDE_DESKTOP_SESSION_COOKIE_NAME: &str = "sessionKey";
const CLAUDE_DESKTOP_ACTIVE_ORG_COOKIE_NAME: &str = "lastActiveOrg";
const CLAUDE_DESKTOP_USAGE_CACHE_FILE: &str = "claude-desktop-web-usage-cache.json";
const CLAUDE_DESKTOP_USAGE_ENABLED_FILE: &str = "claude-desktop-web-usage-enabled";
const CLAUDE_DESKTOP_USAGE_ENDPOINT_PREFIX: &str = "https://claude.ai/api/organizations";
const CLAUDE_DESKTOP_USAGE_CACHE_MAX_AGE_SECONDS: u64 = 24 * 60 * 60;
const CLAUDE_DESKTOP_USAGE_CACHE_FRESH_AGE_SECONDS: u64 = 5 * 60;
const CLAUDE_DESKTOP_USAGE_REFRESH_SECONDS: u64 = 5 * 60;
const CLAUDE_DESKTOP_USAGE_RETRY_AFTER_FALLBACK_SECONDS: u64 = 5 * 60;
const CLAUDE_DESKTOP_USAGE_CACHE_SCHEMA_VERSION: u16 = 2;
const CHROMIUM_COOKIE_KEY_ITERATIONS: u32 = 1003;
const CHROMIUM_COOKIE_KEY_BYTES: usize = 16;
const CHROMIUM_COOKIE_HOST_DIGEST_VERSION: i64 = 24;
static CLAUDE_DESKTOP_USAGE_ATTEMPT_GATE: OnceLock<Mutex<BTreeMap<String, u64>>> = OnceLock::new();
static CLAUDE_DESKTOP_USAGE_ACCESS_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BillingIdentityHints {
    pub(crate) account_identifier_hash: Option<String>,
    pub(crate) organization_identifier_hash: Option<String>,
    pub(crate) credential_fingerprint_hash: Option<String>,
    pub(crate) billing_identity_evidence: Option<String>,
    pub(crate) billing_identity_confidence: AgentStatusConfidence,
}

#[derive(Debug, Clone)]
struct CommandOutput {
    command_found: bool,
    success: bool,
    status_code: Option<i32>,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Clone)]
struct CodexAuthCredentials {
    access_token: Option<String>,
    id_token: Option<String>,
    account_id: Option<String>,
}

#[derive(Debug, Clone)]
struct CodexUsageProbe {
    quota_windows: Vec<AgentQuotaWindow>,
    credit_balances: Vec<AgentCreditBalance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClaudeOAuthUsageCache {
    schema_version: u16,
    /// Which Claude account the cached numbers belong to, as the same
    /// `billing_identity_hash` this collector uses everywhere else. Empty when
    /// the local account metadata could not name an account at write time.
    ///
    /// This file lives at one machine-global path, but the Claude Code CLI
    /// credential store holds exactly ONE account: `/login` as a second account
    /// overwrites the first, and `~/.claude.json` `oauthAccount` switches with
    /// it. Without this field the cache served whichever account was active at
    /// write time under whichever account is logged in now -- observed live on
    /// 2026-07-26, where a personal Max account's weekly window rendered under
    /// a work Team subscription. Mirrors `ClaudeDesktopWebUsageCache`, which
    /// keys the Claude Desktop usage cache the same way.
    #[serde(default)]
    account_identifier_hash: String,
    observed_at_epoch_seconds: u64,
    next_refresh_after_epoch_seconds: u64,
    windows: Vec<AgentQuotaWindow>,
    /// Usage-credit balances parsed from the same OAuth usage response.
    /// `serde(default)` keeps schema-version-2 caches readable if the field is
    /// absent; version-1 caches are discarded wholesale on read.
    #[serde(default)]
    credit_balances: Vec<AgentCreditBalance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClaudeDesktopWebUsageCache {
    schema_version: u16,
    account_identifier_hash: String,
    organization_identifier_hash: String,
    observed_at_epoch_seconds: u64,
    next_refresh_after_epoch_seconds: u64,
    windows: Vec<AgentQuotaWindow>,
    #[serde(default)]
    credit_balances: Vec<AgentCreditBalance>,
}

#[derive(Debug, Clone)]
struct ClaudeDesktopWebUsageTarget {
    account_identifier_hash: String,
    account_label: String,
}

struct ClaudeDesktopWebSession {
    session_key: Zeroizing<String>,
    organization_id: String,
    organization_identifier_hash: String,
}

/// v3 adds `account_identifier_hash`. Version-2 caches carry no account
/// identity at all, so they are discarded wholesale on upgrade rather than
/// treated as belonging to the account that happens to be logged in now --
/// the same precedent v1 set.
const CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION: u16 = 3;

/// Everything the Claude OAuth usage endpoint yields in one fetch.
#[derive(Debug, Clone, Default)]
struct ClaudeOAuthUsage {
    windows: Vec<AgentQuotaWindow>,
    credit_balances: Vec<AgentCreditBalance>,
}

/// A collection attempt plus anything the snapshot should say about *why* the
/// endpoint was or was not contacted. Diagnostics travel back to the caller
/// rather than being logged locally because they are the alerting channel:
/// snapshot diagnostics ride the agent-status upload to the backend (see
/// `AgentStatusSnapshot::redacted_for_backend`, which preserves `code` and
/// `message`), so an open breaker is visible server-side without a second
/// telemetry path.
#[derive(Debug)]
struct ClaudeOAuthUsageOutcome {
    result: Result<ClaudeOAuthUsage, String>,
    diagnostics: Vec<AgentStatusDiagnostic>,
}

/// The failure classes that count toward opening the breaker. Everything else
/// (transport errors, 5xx, a single 429 already covered by retry-after) is
/// transient and deliberately does not accumulate: the breaker exists to stop
/// calling when the *endpoint's answer* says stop, not when the user's Wi-Fi
/// drops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaudeOAuthUsageFailure {
    /// 401/403 - the OAuth token is rejected or lacks the scope.
    AuthRejected,
    /// A 200 body we cannot read, a 200 body with none of the expected quota
    /// fields, or a 404/410 saying the endpoint no longer exists in this shape.
    ResponseShape,
    /// 429 that keeps coming back after the retry-after backoff.
    RateLimited,
}

impl ClaudeOAuthUsageFailure {
    fn code(self) -> &'static str {
        match self {
            Self::AuthRejected => "auth_rejected",
            Self::ResponseShape => "response_shape_changed",
            Self::RateLimited => "rate_limited",
        }
    }

    fn threshold(self) -> u32 {
        match self {
            Self::AuthRejected => CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD,
            Self::ResponseShape => CLAUDE_OAUTH_USAGE_BREAKER_SHAPE_THRESHOLD,
            Self::RateLimited => CLAUDE_OAUTH_USAGE_BREAKER_RATE_LIMIT_THRESHOLD,
        }
    }
}

/// Persisted breaker state for the Claude OAuth usage read.
///
/// Lives beside the usage cache in the support dir and follows the same
/// account-keying rule: counters and an open verdict belong to the account
/// whose credential produced them, so an account switch starts clean rather
/// than inheriting the previous account's rejections.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct ClaudeOAuthUsageBreaker {
    schema_version: u16,
    #[serde(default)]
    account_identifier_hash: String,
    /// Fingerprint of the call's own configuration (endpoint, headers, honest
    /// User-Agent, sentinel state). Changing any of them means the thing that
    /// was failing is not the thing we would call next, so the breaker resets.
    #[serde(default)]
    config_fingerprint: String,
    #[serde(default)]
    auth_failures: u32,
    #[serde(default)]
    shape_failures: u32,
    #[serde(default)]
    rate_limit_failures: u32,
    #[serde(default)]
    opened_at_epoch_seconds: u64,
    /// Cool-down expiry. `0` means the breaker has never opened; the breaker is
    /// open while `now < reopen_after_epoch_seconds`.
    #[serde(default)]
    reopen_after_epoch_seconds: u64,
    /// Which failure class opened it, for the diagnostic message.
    #[serde(default)]
    opened_by: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ClaudeDesktopConfig {
    #[serde(rename = "lastKnownAccountUuid")]
    last_known_account_uuid: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ClaudeDesktopCodeSessionMetadata {
    #[serde(rename = "cliSessionId")]
    cli_session_id: Option<String>,
    #[serde(rename = "lastActivityAt")]
    last_activity_at: Option<Value>,
    #[serde(rename = "createdAt")]
    created_at: Option<Value>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ClaudeDesktopAgentModeSessionMetadata {
    #[serde(rename = "cliSessionId")]
    cli_session_id: Option<String>,
    #[serde(rename = "lastActivityAt")]
    last_activity_at: Option<Value>,
    #[serde(rename = "createdAt")]
    created_at: Option<Value>,
    #[serde(rename = "emailAddress")]
    email_address: Option<String>,
    #[serde(rename = "accountEmail")]
    account_email: Option<String>,
    email: Option<String>,
    #[serde(rename = "accountName")]
    account_name: Option<String>,
    #[serde(rename = "organizationName")]
    organization_name: Option<String>,
    #[serde(rename = "workspaceName")]
    workspace_name: Option<String>,
    #[serde(rename = "teamName")]
    team_name: Option<String>,
    #[serde(rename = "subscriptionType")]
    subscription_type: Option<String>,
    #[serde(rename = "planType")]
    plan_type: Option<String>,
    plan: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct ClaudeDesktopProfileBuilder {
    account_uuid: String,
    account_label: Option<String>,
    account_name: Option<String>,
    organization_label: Option<String>,
    plan_type: Option<String>,
    organization_uuids: BTreeSet<String>,
    current_organization_uuid: Option<String>,
    latest_activity_epoch_seconds: Option<i64>,
    latest_session_id: Option<String>,
    code_session_count: usize,
    agent_mode_session_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PiRouteClassification {
    pub model_provider: Option<String>,
    pub billing_provider: Option<String>,
    pub billing_channel: Option<String>,
    pub auth_mode: Option<String>,
    pub gateway_provider: Option<String>,
    pub subscription_product: Option<String>,
    pub source_category: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PiModelRoute {
    pub provider: String,
    pub model: String,
    pub thinking_level: Option<String>,
    pub classification: PiRouteClassification,
}

impl PiModelRoute {
    fn new(provider: &str, model: &str, thinking_level: Option<&str>) -> Option<Self> {
        let provider = provider.trim();
        let model = model.trim();
        if provider.is_empty() || !looks_like_safe_model_id(model) {
            return None;
        }
        Some(Self {
            provider: provider.to_string(),
            model: model.to_string(),
            thinking_level: thinking_level
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string),
            classification: pi_route_classification(provider, model),
        })
    }
}

pub fn collect_agent_status(
    source: &SourceKind,
    captured_at: String,
    expires_at: String,
) -> AgentStatusSnapshot {
    match source {
        SourceKind::Codex => collect_codex_status(captured_at, expires_at),
        SourceKind::ClaudeCode => collect_claude_status(captured_at, expires_at),
        SourceKind::Pi => collect_pi_status(captured_at, expires_at),
    }
}

pub fn parse_codex_status_fallback(
    text: &str,
    captured_at: String,
    expires_at: String,
) -> AgentStatusSnapshot {
    let account = parse_codex_account_text(text).unwrap_or_else(|| unsupported_account("openai"));
    let mut snapshot = base_snapshot(
        SourceKind::Codex,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::ManualFallback,
        captured_at,
        expires_at,
    );
    snapshot.account = Some(account);
    snapshot.model = parse_codex_text_model(text);
    snapshot.quota_windows = parse_codex_text_quota_windows(text);
    snapshot.context = parse_codex_text_context(text);
    snapshot
}

fn collect_codex_status(captured_at: String, expires_at: String) -> AgentStatusSnapshot {
    if !executable_exists("codex") && !codex_config_path().exists() {
        return not_installed_snapshot(SourceKind::Codex, "codex", captured_at, expires_at);
    }

    let mut snapshot = base_snapshot(
        SourceKind::Codex,
        AgentStatusState::Degraded,
        AgentStatusCollectionMethod::CommandProbe,
        captured_at,
        expires_at,
    );
    snapshot.account = Some(AgentAccountStatus {
        login_state: AgentLoginState::Unknown,
        provider: Some("openai".to_string()),
        auth_method: None,
        email: None,
        account_id: None,
        organization_id: None,
        organization_label: None,
        plan_type: None,
        subscription_product: None,
        billing_channel: None,
        subscription_period_start: None,
        subscription_period_end: None,
        account_identifier_hash: None,
        organization_identifier_hash: None,
        credential_fingerprint_hash: None,
        billing_identity_evidence: None,
        billing_identity_confidence: AgentStatusConfidence::Unknown,
        confidence: AgentStatusConfidence::Unknown,
    });

    let login = run_command_capture("codex", &["login", "status"], COMMAND_TIMEOUT);
    if login.command_found {
        snapshot.collection_method = AgentStatusCollectionMethod::CliText;
        if login.success {
            if let Some(account) = parse_codex_account_text(&login.stdout) {
                snapshot.status = AgentStatusState::Available;
                snapshot.account = Some(account);
            }
        } else {
            snapshot.diagnostics.push(command_diagnostic(
                "codex_login_status_failed",
                "codex login status did not return a usable status.",
                &login,
            ));
            if matches!(
                login.status_code,
                Some(1) | Some(2) | Some(64) | Some(65) | Some(66) | Some(67)
            ) {
                snapshot.status = AgentStatusState::AuthRequired;
                if let Some(account) = &mut snapshot.account {
                    account.login_state = AgentLoginState::SignedOut;
                    account.confidence = AgentStatusConfidence::Medium;
                }
            }
        }
    }
    if let Some(auth_account) = read_codex_auth_account() {
        snapshot.status = AgentStatusState::Available;
        snapshot.account = Some(merge_codex_accounts(snapshot.account.take(), auth_account));
    }

    let models = run_command_capture("codex", &["debug", "models", "--bundled"], COMMAND_TIMEOUT);
    let mut model_status = collect_codex_model_status_from_output(&models);
    apply_codex_config_model(
        &mut model_status,
        read_codex_config_model(),
        &mut snapshot.collection_method,
    );
    snapshot.model = Some(model_status);
    let mut quota_capability = unsupported_capability(
        "quota_windows",
        "Codex usage windows were not available from the local account probe.",
    );
    let mut credits_capability = unsupported_capability(
        "credits",
        "Codex credit balance was not available from the local account probe.",
    );
    match collect_codex_usage() {
        Ok(usage) => {
            if !usage.quota_windows.is_empty() {
                snapshot.collection_method = AgentStatusCollectionMethod::AppServer;
                snapshot.quota_windows = usage.quota_windows;
                quota_capability = supported_capability(
                    "quota_windows",
                    "Collected from the local Codex app-server rate-limit endpoint.",
                );
            } else {
                snapshot.quota_windows = vec![unsupported_quota_window("usage")];
            }
            if !usage.credit_balances.is_empty() {
                snapshot.credit_balances = usage.credit_balances;
                credits_capability = supported_capability(
                    "credits",
                    "Collected from the local Codex app-server rate-limit endpoint.",
                );
            }
        }
        Err(message) => {
            snapshot.quota_windows = vec![unsupported_quota_window("usage")];
            snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                "codex_usage_probe_failed",
                AgentDiagnosticSeverity::Warning,
                message,
            ));
        }
    }
    snapshot.context = Some(AgentContextStatus {
        status: AgentContextState::Unsupported,
        active_tokens: None,
        max_tokens: None,
        used_percent: None,
        remaining_tokens: None,
        source: Some("codex_cli_v1".to_string()),
        recent_samples: Vec::new(),
        observed_at: None,
        completeness: Some(AgentContextCompleteness::Unavailable),
        reason: Some("codex_active_context_not_collected".to_string()),
        posture: None,
    });
    snapshot.capabilities = vec![
        supported_capability("account_status", "Detected with Codex CLI/config probes."),
        quota_capability,
        credits_capability,
        unsupported_capability(
            "active_context",
            "Codex active session context requires the app-server status channel.",
        ),
    ];
    if snapshot.status == AgentStatusState::Degraded
        && snapshot
            .account
            .as_ref()
            .is_some_and(|account| account.login_state == AgentLoginState::SignedIn)
    {
        snapshot.status = AgentStatusState::Available;
    }
    append_current_plan_observation(&mut snapshot);
    append_codex_workspace_observations(&mut snapshot);
    snapshot.runtime_defaults = build_codex_runtime_defaults(&snapshot.captured_at);
    snapshot
}

fn collect_codex_usage() -> Result<CodexUsageProbe, String> {
    match collect_codex_app_server_usage() {
        Ok(usage) => Ok(usage),
        Err(app_server_message) if legacy_codex_oauth_usage_enabled() => {
            collect_codex_oauth_usage().map_err(|oauth_message| {
                format!("{app_server_message} Legacy OAuth usage fallback failed: {oauth_message}")
            })
        }
        Err(message) => Err(message),
    }
}

/// Assemble display-safe Codex runtime defaults from `~/.codex/config.toml` for
/// the agent-status upload. The backend overwrites `machine_id` from the stored
/// snapshot, so it is left unset here.
fn build_codex_runtime_defaults(captured_at: &str) -> Option<AgentRuntimeDefaults> {
    let defaults = crate::snapshots::load_codex_config_defaults(&codex_config_path())?;
    let fast_mode_enabled = defaults.display_fast_mode();
    Some(AgentRuntimeDefaults {
        captured_at: Some(captured_at.to_string()),
        provenance: Some("config_file".to_string()),
        machine_id: None,
        model: defaults.model,
        service_tier: defaults.service_tier,
        speed_mode: None,
        fast_mode_enabled,
        priority_enabled: None,
        reasoning_effort: defaults.reasoning_effort,
        approval_policy: defaults.approval_policy,
        sandbox_mode: None,
        selector_context: defaults.selector_context,
        selector_sources: defaults.selector_sources,
    })
}

/// macOS enterprise/MDM policy settings for Claude Code. Highest precedence in
/// Claude Code's own chain and not overridable by a developer, so it is applied
/// last.
const CLAUDE_MANAGED_SETTINGS_PATH: &str =
    "/Library/Application Support/ClaudeCode/managed-settings.json";

/// Claude Code settings files, lowest precedence first.
///
/// Claude Code's own order is user settings, then project settings, then local
/// project settings, then managed settings on top. Project-scoped
/// `.claude/settings*.json` files are intentionally out of scope here: the daemon
/// has no single project cwd, and a checked-out repository's settings are not a
/// machine default. `~/.claude/settings.local.json` is included because the
/// local MCP inventory already treats it as an override of `~/.claude/settings.json`.
fn claude_settings_paths() -> Vec<(String, PathBuf)> {
    vec![
        (
            "claude_code.settings".to_string(),
            home_path(".claude/settings.json"),
        ),
        (
            "claude_code.settings_local".to_string(),
            home_path(".claude/settings.local.json"),
        ),
        (
            "claude_code.managed_settings".to_string(),
            PathBuf::from(CLAUDE_MANAGED_SETTINGS_PATH),
        ),
    ]
}

/// Claude Code runtime defaults plus the honest marker for what we found.
struct ClaudeRuntimeDefaultsCapture {
    defaults: Option<AgentRuntimeDefaults>,
    capability: AgentCapabilityGap,
    diagnostic: Option<AgentStatusDiagnostic>,
}

/// Assemble display-safe Claude Code runtime defaults from the local settings
/// chain for the agent-status upload. The backend overwrites `machine_id` from
/// the stored snapshot, so it is left unset here.
fn build_claude_runtime_defaults(captured_at: &str) -> ClaudeRuntimeDefaultsCapture {
    claude_runtime_defaults_from_paths(captured_at, &claude_settings_paths())
}

fn claude_runtime_defaults_from_paths(
    captured_at: &str,
    paths: &[(String, PathBuf)],
) -> ClaudeRuntimeDefaultsCapture {
    let scopes: Vec<crate::snapshots::ClaudeSettingsScope<'_>> = paths
        .iter()
        .map(|(label, path)| crate::snapshots::ClaudeSettingsScope {
            label: label.as_str(),
            path: path.as_path(),
        })
        .collect();
    match crate::snapshots::load_claude_settings_defaults(&scopes) {
        crate::snapshots::ClaudeConfigDefaultsOutcome::Configured(defaults) => {
            ClaudeRuntimeDefaultsCapture {
                defaults: Some(AgentRuntimeDefaults {
                    captured_at: Some(captured_at.to_string()),
                    provenance: Some("config_file".to_string()),
                    machine_id: None,
                    model: defaults.model,
                    // Claude Code has no config-file service tier or speed mode;
                    // Fast is the only tier-shaped default it persists.
                    service_tier: None,
                    speed_mode: None,
                    fast_mode_enabled: defaults.fast_mode_enabled,
                    priority_enabled: None,
                    // Claude Code's durable `effortLevel` setting, which
                    // `/effort` writes. Reported exactly as configured; absent
                    // means absent, never an invented default.
                    reasoning_effort: defaults.reasoning_effort,
                    approval_policy: defaults.approval_policy,
                    sandbox_mode: defaults.sandbox_mode,
                    selector_context: defaults.selector_context,
                    selector_sources: defaults.selector_sources,
                }),
                capability: supported_capability(
                    "runtime_defaults",
                    "Read display-safe Claude Code defaults from the local settings chain.",
                ),
                diagnostic: None,
            }
        }
        crate::snapshots::ClaudeConfigDefaultsOutcome::NothingConfigured => {
            ClaudeRuntimeDefaultsCapture {
                defaults: None,
                capability: unsupported_capability(
                    "runtime_defaults",
                    "Claude Code settings were read, but none set a display-safe default (model, effort level, permission mode, fast mode, or sandbox).",
                ),
                diagnostic: Some(AgentStatusDiagnostic::source(
                    "claude_runtime_defaults_not_configured",
                    AgentDiagnosticSeverity::Info,
                    "Claude Code settings parsed cleanly and configure none of the defaults Ottto displays.",
                )),
            }
        }
        crate::snapshots::ClaudeConfigDefaultsOutcome::Unreadable => ClaudeRuntimeDefaultsCapture {
            defaults: None,
            capability: unsupported_capability(
                "runtime_defaults",
                "No readable Claude Code settings file was found on this Mac.",
            ),
            diagnostic: Some(AgentStatusDiagnostic::source(
                "claude_runtime_defaults_unreadable",
                AgentDiagnosticSeverity::Info,
                "No Claude Code settings file in the local chain could be read and parsed.",
            )),
        },
    }
}

fn collect_claude_status(captured_at: String, expires_at: String) -> AgentStatusSnapshot {
    // Presence is decided by the canonical detector, which requires the `claude`
    // binary. A lone `~/.claude/settings.json` — which Ottto's own relay-base
    // patch writes during onboarding — must NOT read as "installed", or a Mac
    // that never had Claude reports it as present and then fails verification
    // with "claude is not installed or not executable".
    let claude_desktop_root = claude_desktop_support_dir();
    let claude_cli_present =
        crate::agent_configs::detection::source_present_locally(&SourceKind::ClaudeCode);
    if !claude_cli_present && !claude_desktop_metadata_present(&claude_desktop_root) {
        return not_installed_snapshot(SourceKind::ClaudeCode, "claude", captured_at, expires_at);
    }
    let mut snapshot = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Degraded,
        AgentStatusCollectionMethod::CommandProbe,
        captured_at,
        expires_at,
    );
    let auth = run_command_capture("claude", &["auth", "status", "--json"], COMMAND_TIMEOUT);
    if auth.command_found && auth.success {
        snapshot.collection_method = AgentStatusCollectionMethod::CliJson;
        if let Ok(json) = serde_json::from_str::<Value>(&auth.stdout) {
            let mut account = parse_claude_auth_json(&json);
            let mut refined_seat_plan = None;
            let mut refined_max_plan = None;
            if let Some(oauth) = read_claude_cli_oauth_account(&claude_cli_config_path()) {
                // Mutually exclusive by plan_type gate (`team` vs `max`).
                refined_seat_plan = refine_claude_team_seat_plan(&mut account, &oauth);
                refined_max_plan = refine_claude_max_rate_limit_plan(&mut account, &oauth);
                // Regardless of plan refinement: carry the account uuid onto
                // the account so the snapshot account section and the plan
                // observation built from it resolve under the same account
                // hash the quota windows are stamped with.
                stamp_claude_cli_account_identity(&mut account, &oauth);
            }
            snapshot.account = Some(account);
            snapshot.status = AgentStatusState::Available;
            if let Some(seat_plan) = refined_seat_plan {
                snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                    "claude_team_seat_tier_detected",
                    AgentDiagnosticSeverity::Info,
                    format!(
                        "Claude Team seat tier resolved to {seat_plan} from local Claude Code account metadata."
                    ),
                ));
            }
            if let Some(max_plan) = refined_max_plan {
                snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                    "claude_max_rate_limit_tier_detected",
                    AgentDiagnosticSeverity::Info,
                    format!(
                        "Claude Max tier resolved to {max_plan} from local Claude Code account metadata."
                    ),
                ));
            }
        }
    } else {
        snapshot.account = Some(unsupported_account("anthropic"));
        if auth.command_found {
            snapshot.diagnostics.push(command_diagnostic(
                "claude_auth_status_failed",
                "claude auth status --json did not return usable JSON.",
                &auth,
            ));
        }
    }
    let version = run_command_capture("claude", &["--version"], COMMAND_TIMEOUT);
    snapshot.model = Some(AgentModelStatus {
        active_model: None,
        default_model: None,
        provider: Some("anthropic".to_string()),
        available_models: Vec::new(),
        available_model_details: Vec::new(),
        context_window_tokens: None,
    });
    let mut quota_capability = unsupported_capability(
        "quota_windows",
        "Claude Code rate-limit windows have not been observed from local OAuth usage or statusLine yet.",
    );
    // Resolved once, before any statusLine read: the statusLine cache is shared
    // by every Claude Code surface on this machine and names no account, so
    // serving it needs both the account that owns the credential now and the set
    // of other Claude accounts that could have written it. Desktop observations
    // are computed here rather than at their append site further down so the
    // gate and the snapshot agree and the session buckets are only scanned once.
    // The same resolution also scopes the OAuth usage read and stamps its
    // served windows, so cache scope, statusLine gate, and wire identity can
    // never disagree.
    let claude_oauth_account = read_claude_cli_oauth_account(&claude_cli_config_path());
    let claude_account_identifier_hash = claude_oauth_account
        .as_ref()
        .map(claude_oauth_account_identifier_hash_for)
        .unwrap_or_default();
    let claude_organization_identifier_hash = claude_oauth_account
        .as_ref()
        .and_then(|account| account.organization_uuid.as_deref())
        .and_then(|uuid| billing_identity_hash("anthropic", "organization", uuid));
    let desktop_plan_observations =
        claude_desktop_plan_observations_from_root(&claude_desktop_root, &snapshot.captured_at);
    let observable_account_identifier_hashes =
        claude_account_identifier_hashes_from_observations(&desktop_plan_observations);
    let apply_statusline_quota =
        |snapshot: &mut AgentStatusSnapshot, quota_capability: &mut AgentCapabilityGap| -> bool {
            match collect_claude_statusline_quota_windows(
                &claude_account_identifier_hash,
                &observable_account_identifier_hashes,
            ) {
                Ok(ClaudeStatusLineQuota::Windows(windows)) if !windows.is_empty() => {
                    snapshot.collection_method = AgentStatusCollectionMethod::StatusLine;
                    snapshot.quota_windows = windows;
                    *quota_capability = supported_capability(
                        "quota_windows",
                        "Collected from Claude Code's local statusLine rate_limits payload.",
                    );
                    true
                }
                Ok(ClaudeStatusLineQuota::Unattributable(reason)) => {
                    snapshot.quota_windows = vec![unsupported_quota_window("usage")];
                    *quota_capability = unsupported_capability("quota_windows", reason.detail());
                    snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                        reason.code(),
                        AgentDiagnosticSeverity::Warning,
                        reason.detail(),
                    ));
                    false
                }
                Ok(_) => {
                    snapshot.quota_windows = vec![unsupported_quota_window("usage")];
                    false
                }
                Err(message) => {
                    snapshot.quota_windows = vec![unsupported_quota_window("usage")];
                    snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                        "claude_statusline_cache_unavailable",
                        AgentDiagnosticSeverity::Warning,
                        message,
                    ));
                    false
                }
            }
        };
    let oauth_outcome = collect_claude_oauth_usage(
        &claude_account_identifier_hash,
        claude_organization_identifier_hash.as_deref(),
    );
    // Pushed before the quota branch below so the reason the endpoint was or
    // was not called rides the snapshot regardless of which source ends up
    // serving quota. These diagnostics are the alert channel for the circuit
    // breaker: they travel to the backend with the agent-status upload.
    snapshot.diagnostics.extend(oauth_outcome.diagnostics);
    match oauth_outcome.result {
        Ok(usage) if !usage.windows.is_empty() => {
            snapshot.collection_method = AgentStatusCollectionMethod::CliJson;
            snapshot.quota_windows = usage.windows;
            snapshot.credit_balances = usage.credit_balances;
            quota_capability = supported_capability(
                "quota_windows",
                "Collected from Claude Code's local OAuth usage endpoint.",
            );
        }
        Ok(_) => {
            apply_statusline_quota(&mut snapshot, &mut quota_capability);
        }
        Err(message) => {
            if !apply_statusline_quota(&mut snapshot, &mut quota_capability) {
                snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                    "claude_oauth_usage_unavailable",
                    AgentDiagnosticSeverity::Warning,
                    message,
                ));
            }
        }
    }
    let mut context_capability = unsupported_capability(
        "active_context",
        "Claude Code active context has not been observed from statusLine yet.",
    );
    match collect_claude_statusline_context_status() {
        Ok(context) => {
            if context.status == AgentContextState::Available {
                snapshot.collection_method = AgentStatusCollectionMethod::StatusLine;
                context_capability = match context.completeness {
                    Some(AgentContextCompleteness::FullPressure) => supported_capability(
                        "active_context",
                        "Collected live context pressure from Claude Code's local statusLine context_window payload.",
                    ),
                    Some(AgentContextCompleteness::WindowSizeOnly) => supported_capability(
                        "active_context",
                        "Collected Claude Code context-window size from statusLine; live pressure fields have not been reported yet.",
                    ),
                    _ => supported_capability(
                        "active_context",
                        "Collected Claude Code's local statusLine context_window payload.",
                    ),
                };
            }
            snapshot.context = Some(context);
        }
        Err(message) => {
            snapshot.context = Some(AgentContextStatus {
                status: AgentContextState::Unknown,
                active_tokens: None,
                max_tokens: None,
                used_percent: None,
                remaining_tokens: None,
                source: Some("claude_statusline_context_window".to_string()),
                recent_samples: Vec::new(),
                observed_at: None,
                completeness: Some(AgentContextCompleteness::Unknown),
                reason: Some("statusline_context_cache_unreadable".to_string()),
                posture: None,
            });
            snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                "claude_statusline_context_cache_unavailable",
                AgentDiagnosticSeverity::Warning,
                message,
            ));
        }
    }
    // Machine-local posture summary over recent sessions, derived by the
    // snapshot scan and cached (see `context_posture`). Independent of the
    // statusLine live-context channel: posture history is still served when
    // live pressure is unavailable, and vice versa.
    if let Some(context) = snapshot.context.as_mut() {
        context.posture = crate::context_posture::claude_context_posture_summary(
            &default_support_dir(),
            OffsetDateTime::now_utc(),
        );
    }
    let runtime_defaults = build_claude_runtime_defaults(&snapshot.captured_at);
    snapshot.runtime_defaults = runtime_defaults.defaults;
    snapshot.capabilities = vec![
        supported_capability(
            "account_status",
            "Read from claude auth status --json when available.",
        ),
        quota_capability,
        context_capability,
        runtime_defaults.capability,
    ];
    if let Some(diagnostic) = runtime_defaults.diagnostic {
        snapshot.diagnostics.push(diagnostic);
    }
    if version.command_found && version.success {
        snapshot.diagnostics.push(AgentStatusDiagnostic::source(
            "claude_version_detected",
            AgentDiagnosticSeverity::Info,
            "Claude Code CLI version detected.",
        ));
    }
    append_current_plan_observation(&mut snapshot);
    let desktop_observation_count =
        append_claude_desktop_plan_observations(&mut snapshot, desktop_plan_observations);
    if desktop_observation_count > 0 {
        if snapshot.status == AgentStatusState::Degraded {
            snapshot.status = AgentStatusState::Available;
        }
        snapshot.capabilities.push(supported_capability(
            "desktop_identity",
            "Read display-safe Claude Desktop account and session-bucket metadata.",
        ));
        snapshot.diagnostics.push(AgentStatusDiagnostic::source(
            "claude_desktop_profile_detected",
            AgentDiagnosticSeverity::Info,
            "Claude Desktop Code account/session bucket metadata was detected.",
        ));
        if let Some(target) = claude_desktop_web_usage_target(&snapshot.plan_observations) {
            if !claude_desktop_web_usage_enabled() {
                snapshot.capabilities.push(unsupported_capability(
                    "desktop_quota_windows",
                    "Enable Claude Desktop usage in Ottto Settings to allow local Keychain access.",
                ));
                return snapshot;
            }
            match collect_claude_desktop_web_usage(&claude_desktop_root, &target) {
                Ok(usage) if !usage.windows.is_empty() => {
                    snapshot.quota_windows.extend(usage.windows);
                    snapshot.credit_balances.extend(usage.credit_balances);
                    snapshot.capabilities.push(supported_capability(
                        "desktop_quota_windows",
                        "Collected from Claude Desktop's local web session without persisting credentials.",
                    ));
                    snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                        "claude_desktop_web_usage_detected",
                        AgentDiagnosticSeverity::Info,
                        "Claude Desktop usage windows were collected from its active local session.",
                    ));
                }
                Ok(_) => {
                    snapshot.capabilities.push(unsupported_capability(
                        "desktop_quota_windows",
                        "Claude Desktop's usage response did not contain quota windows.",
                    ));
                }
                Err(message) => {
                    snapshot.capabilities.push(unsupported_capability(
                        "desktop_quota_windows",
                        "Claude Desktop usage is unavailable until local Keychain access succeeds.",
                    ));
                    snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                        "claude_desktop_web_usage_unavailable",
                        AgentDiagnosticSeverity::Warning,
                        message,
                    ));
                }
            }
        }
    }
    snapshot
}

/// Takes the observations rather than recomputing them: the statusLine
/// attribution gate above needs the same set, and scanning the Desktop session
/// buckets twice per status tick would be pure waste.
fn append_claude_desktop_plan_observations(
    snapshot: &mut AgentStatusSnapshot,
    observations: Vec<AgentStatusPlanObservation>,
) -> usize {
    let count = observations.len();
    snapshot.plan_observations.extend(observations);
    count
}

fn claude_desktop_support_dir() -> PathBuf {
    home_path("Library/Application Support/Claude")
}

fn claude_cli_config_path() -> PathBuf {
    home_path(".claude.json")
}

fn claude_desktop_metadata_present(root: &Path) -> bool {
    root.join("config.json").is_file()
        || root.join("claude-code-sessions").is_dir()
        || root.join("local-agent-mode-sessions").is_dir()
}

fn claude_desktop_plan_observations_from_root(
    root: &Path,
    observed_at: &str,
) -> Vec<AgentStatusPlanObservation> {
    let config = read_claude_desktop_config(root);
    let last_known_account_uuid = config
        .last_known_account_uuid
        .as_deref()
        .and_then(safe_local_identifier)
        .map(ToString::to_string);
    let mut builders: BTreeMap<String, ClaudeDesktopProfileBuilder> = BTreeMap::new();

    collect_claude_desktop_code_sessions(
        &root.join("claude-code-sessions"),
        last_known_account_uuid.as_deref(),
        &mut builders,
    );
    collect_claude_desktop_agent_mode_sessions(
        &root.join("local-agent-mode-sessions"),
        &mut builders,
    );

    builders
        .into_values()
        .filter(|builder| {
            builder.code_session_count > 0
                || last_known_account_uuid.as_deref() == Some(builder.account_uuid.as_str())
        })
        .filter_map(|builder| {
            claude_desktop_builder_plan_observation(
                builder,
                observed_at,
                last_known_account_uuid.as_deref(),
            )
        })
        .collect()
}

fn read_claude_desktop_config(root: &Path) -> ClaudeDesktopConfig {
    let path = root.join("config.json");
    fs::read_to_string(path)
        .ok()
        .and_then(|body| serde_json::from_str::<ClaudeDesktopConfig>(&body).ok())
        .unwrap_or_default()
}

fn collect_claude_desktop_code_sessions(
    root: &Path,
    last_known_account_uuid: Option<&str>,
    builders: &mut BTreeMap<String, ClaudeDesktopProfileBuilder>,
) {
    let Ok(accounts) = fs::read_dir(root) else {
        return;
    };
    for account in accounts.flatten() {
        let Ok(file_type) = account.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let Some(account_uuid) = account
            .file_name()
            .to_str()
            .and_then(safe_local_identifier)
            .map(ToString::to_string)
        else {
            continue;
        };
        let Ok(orgs) = fs::read_dir(account.path()) else {
            continue;
        };
        for org in orgs.flatten() {
            let Ok(file_type) = org.file_type() else {
                continue;
            };
            if !file_type.is_dir() {
                continue;
            }
            let Some(org_uuid) = org
                .file_name()
                .to_str()
                .and_then(safe_local_identifier)
                .map(ToString::to_string)
            else {
                continue;
            };
            let builder = builders.entry(account_uuid.clone()).or_insert_with(|| {
                ClaudeDesktopProfileBuilder {
                    account_uuid: account_uuid.clone(),
                    ..Default::default()
                }
            });
            builder.organization_uuids.insert(org_uuid.clone());
            let Ok(files) = fs::read_dir(org.path()) else {
                continue;
            };
            for file in files
                .flatten()
                .filter(|entry| looks_like_local_json_file(entry.path().as_path()))
                .take(CLAUDE_DESKTOP_CODE_SESSION_MAX_FILES_PER_ORG)
            {
                let metadata = read_json_file::<ClaudeDesktopCodeSessionMetadata>(&file.path());
                let activity = metadata
                    .as_ref()
                    .and_then(|metadata| {
                        timestamp_value_epoch_seconds(metadata.last_activity_at.as_ref())
                            .or_else(|| timestamp_value_epoch_seconds(metadata.created_at.as_ref()))
                    })
                    .or_else(|| file_modified_epoch_seconds(&file.path()));
                let session_id = metadata
                    .and_then(|metadata| metadata.cli_session_id)
                    .and_then(|value| safe_local_identifier(&value).map(ToString::to_string));
                let builder = builders.get_mut(&account_uuid).expect("builder exists");
                builder.code_session_count += 1;
                if builder.record_activity(activity, session_id)
                    && last_known_account_uuid == Some(account_uuid.as_str())
                {
                    builder.current_organization_uuid = Some(org_uuid.clone());
                }
            }
        }
    }
}

fn collect_claude_desktop_agent_mode_sessions(
    root: &Path,
    builders: &mut BTreeMap<String, ClaudeDesktopProfileBuilder>,
) {
    let Ok(accounts) = fs::read_dir(root) else {
        return;
    };
    for account in accounts.flatten() {
        let Ok(file_type) = account.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let Some(account_uuid) = account
            .file_name()
            .to_str()
            .and_then(safe_local_identifier)
            .map(ToString::to_string)
        else {
            continue;
        };
        let Ok(orgs) = fs::read_dir(account.path()) else {
            continue;
        };
        for org in orgs.flatten() {
            let Ok(file_type) = org.file_type() else {
                continue;
            };
            if !file_type.is_dir() {
                continue;
            }
            let Some(org_uuid) = org
                .file_name()
                .to_str()
                .and_then(safe_local_identifier)
                .map(ToString::to_string)
            else {
                continue;
            };
            let builder = builders.entry(account_uuid.clone()).or_insert_with(|| {
                ClaudeDesktopProfileBuilder {
                    account_uuid: account_uuid.clone(),
                    ..Default::default()
                }
            });
            builder.organization_uuids.insert(org_uuid);
            let Ok(files) = fs::read_dir(org.path()) else {
                continue;
            };
            for file in files
                .flatten()
                .filter(|entry| looks_like_local_json_file(entry.path().as_path()))
                .take(CLAUDE_DESKTOP_AGENT_MODE_MAX_FILES_PER_ORG)
            {
                let Some(metadata) =
                    read_json_file::<ClaudeDesktopAgentModeSessionMetadata>(&file.path())
                else {
                    continue;
                };
                let activity = timestamp_value_epoch_seconds(metadata.last_activity_at.as_ref())
                    .or_else(|| timestamp_value_epoch_seconds(metadata.created_at.as_ref()))
                    .or_else(|| file_modified_epoch_seconds(&file.path()));
                let session_id = metadata
                    .cli_session_id
                    .as_deref()
                    .and_then(safe_local_identifier)
                    .map(ToString::to_string);
                let builder = builders.get_mut(&account_uuid).expect("builder exists");
                builder.agent_mode_session_count += 1;
                builder.record_activity(activity, session_id);
                builder.account_label = builder.account_label.clone().or_else(|| {
                    first_non_empty([
                        metadata.email_address.as_deref(),
                        metadata.account_email.as_deref(),
                        metadata.email.as_deref(),
                    ])
                    .map(ToString::to_string)
                });
                builder.account_name = builder
                    .account_name
                    .clone()
                    .or_else(|| safe_display_label(metadata.account_name.as_deref()));
                builder.organization_label = builder.organization_label.clone().or_else(|| {
                    first_non_empty([
                        metadata.organization_name.as_deref(),
                        metadata.workspace_name.as_deref(),
                        metadata.team_name.as_deref(),
                    ])
                    .and_then(|value| safe_display_label(Some(value)))
                });
                builder.plan_type = builder.plan_type.clone().or_else(|| {
                    first_non_empty([
                        metadata.subscription_type.as_deref(),
                        metadata.plan_type.as_deref(),
                        metadata.plan.as_deref(),
                    ])
                    .map(|value| normalize_plan_type(value.to_string()))
                });
            }
        }
    }
}

fn claude_desktop_builder_plan_observation(
    builder: ClaudeDesktopProfileBuilder,
    observed_at: &str,
    last_known_account_uuid: Option<&str>,
) -> Option<AgentStatusPlanObservation> {
    let account_identifier_hash =
        billing_identity_hash("anthropic", "account", &builder.account_uuid);
    // An organization is attached only when the pairing is unambiguous: the
    // current organization when the Desktop config names this account as
    // current, or the single organization the session store holds for it.
    // Picking `iter().next()` off a multi-org set fabricated pairings for
    // non-current accounts (a personal account hash next to an employer org
    // hash), which the backend then minted as a brand-new billing identity.
    // Fail closed: omit the organization rather than guess.
    let organization_id = builder.current_organization_uuid.or_else(|| {
        if builder.organization_uuids.len() == 1 {
            builder.organization_uuids.iter().next().cloned()
        } else {
            None
        }
    });
    let organization_identifier_hash = organization_id
        .as_deref()
        .and_then(|value| billing_identity_hash("anthropic", "organization", value));
    let billing_identity_evidence = billing_identity_evidence_for(
        &account_identifier_hash,
        &organization_identifier_hash,
        &None,
    );
    if account_identifier_hash.is_none() && organization_identifier_hash.is_none() {
        return None;
    }
    let plan_type = builder.plan_type;
    let subscription_product = plan_type.clone().map(|plan| {
        if plan.starts_with("claude_") {
            plan
        } else {
            format!("claude_{plan}")
        }
    });
    let is_current = last_known_account_uuid == Some(builder.account_uuid.as_str());
    Some(AgentStatusPlanObservation {
        observed_at: Some(observed_at.to_string()),
        evidence_method: Some("claude_desktop_session_bucket".to_string()),
        source_session_id: builder.latest_session_id,
        provider: Some("anthropic".to_string()),
        billing_provider: Some("anthropic".to_string()),
        model_provider: Some("anthropic".to_string()),
        billing_channel: Some("subscription".to_string()),
        auth_mode: Some("claude_desktop".to_string()),
        gateway_provider: None,
        subscription_product,
        plan_type,
        account_label: builder
            .account_label
            .or(builder.account_name)
            .or_else(|| is_current.then(|| "Claude Desktop".to_string())),
        account_id: Some(builder.account_uuid),
        organization_label: builder.organization_label,
        organization_id,
        account_identifier_hash,
        organization_identifier_hash,
        credential_fingerprint_hash: None,
        billing_identity_evidence,
        billing_identity_confidence: AgentStatusConfidence::High,
        confidence: if is_current {
            AgentStatusConfidence::High
        } else {
            AgentStatusConfidence::Medium
        },
        is_current: Some(is_current),
    })
}

fn claude_desktop_web_usage_target(
    observations: &[AgentStatusPlanObservation],
) -> Option<ClaudeDesktopWebUsageTarget> {
    observations
        .iter()
        .find(|observation| {
            observation.auth_mode.as_deref() == Some("claude_desktop")
                && observation.is_current == Some(true)
        })
        .and_then(|observation| {
            Some(ClaudeDesktopWebUsageTarget {
                account_identifier_hash: observation
                    .account_identifier_hash
                    .as_deref()
                    .filter(|value| !value.trim().is_empty())?
                    .to_string(),
                account_label: observation
                    .account_label
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())?
                    .to_string(),
            })
        })
}

pub(crate) fn claude_desktop_web_usage_enabled() -> bool {
    default_support_dir()
        .join(CLAUDE_DESKTOP_USAGE_ENABLED_FILE)
        .is_file()
}

pub(crate) fn set_claude_desktop_web_usage_enabled(enabled: bool) -> std::io::Result<bool> {
    let access_lock = CLAUDE_DESKTOP_USAGE_ACCESS_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = access_lock
        .lock()
        .map_err(|_| std::io::Error::other("Claude Desktop usage access lock is unavailable"))?;
    let path = default_support_dir().join(CLAUDE_DESKTOP_USAGE_ENABLED_FILE);
    if enabled {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, b"enabled\n")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
    } else {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let cache_path = claude_desktop_web_usage_cache_path();
        match fs::remove_file(cache_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if let Some(gate) = CLAUDE_DESKTOP_USAGE_ATTEMPT_GATE.get() {
            gate.lock()
                .map_err(|_| {
                    std::io::Error::other("Claude Desktop usage retry gate is unavailable")
                })?
                .clear();
        }
    }
    Ok(claude_desktop_web_usage_enabled())
}

fn collect_claude_desktop_web_usage(
    desktop_root: &Path,
    target: &ClaudeDesktopWebUsageTarget,
) -> Result<ClaudeOAuthUsage, String> {
    let access_lock = CLAUDE_DESKTOP_USAGE_ACCESS_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = access_lock
        .lock()
        .map_err(|_| "Claude Desktop usage access lock is unavailable.".to_string())?;
    if !claude_desktop_web_usage_enabled() {
        return Err("Claude Desktop usage access was disabled.".to_string());
    }

    let now = current_unix_seconds();
    let account_cached = read_claude_desktop_web_usage_cache()
        .filter(|cache| cache.account_identifier_hash == target.account_identifier_hash);
    if let Some(cache) = account_cached.as_ref() {
        let cache_age = now.saturating_sub(cache.observed_at_epoch_seconds);
        if !cache.windows.is_empty()
            && cache_age <= CLAUDE_DESKTOP_USAGE_CACHE_MAX_AGE_SECONDS
            && (cache_age <= CLAUDE_DESKTOP_USAGE_CACHE_FRESH_AGE_SECONDS
                || now < cache.next_refresh_after_epoch_seconds)
        {
            return Ok(claude_desktop_web_usage_from_cache(
                cache.clone(),
                now,
                &target.account_label,
            ));
        }
        if now < cache.next_refresh_after_epoch_seconds {
            return Err(
                "Claude Desktop usage refresh is waiting for its local retry window.".to_string(),
            );
        }
    }

    if !claim_claude_desktop_usage_attempt(&target.account_identifier_hash, now) {
        return Err(
            "Claude Desktop usage refresh is waiting for its local retry window.".to_string(),
        );
    }

    // Persist the retry gate before touching Keychain or the network. Manual UI
    // refreshes can arrive faster than the normal status cadence; failures must
    // not turn those refreshes into repeated prompts or endpoint calls.
    let mut preflight_cache =
        account_cached
            .clone()
            .unwrap_or_else(|| ClaudeDesktopWebUsageCache {
                schema_version: CLAUDE_DESKTOP_USAGE_CACHE_SCHEMA_VERSION,
                account_identifier_hash: target.account_identifier_hash.clone(),
                organization_identifier_hash: String::new(),
                observed_at_epoch_seconds: 0,
                next_refresh_after_epoch_seconds: now + CLAUDE_DESKTOP_USAGE_REFRESH_SECONDS,
                windows: Vec::new(),
                credit_balances: Vec::new(),
            });
    preflight_cache.next_refresh_after_epoch_seconds = now + CLAUDE_DESKTOP_USAGE_REFRESH_SECONDS;
    let _ = write_claude_desktop_web_usage_cache(&preflight_cache);

    let session = read_claude_desktop_web_session(desktop_root)?;
    let mut attempt_cache = claude_desktop_attempt_cache_for_session(
        account_cached,
        target,
        &session,
        preflight_cache.next_refresh_after_epoch_seconds,
    );
    let _ = write_claude_desktop_web_usage_cache(&attempt_cache);

    let cookie_header = Zeroizing::new(format!(
        "{}={}",
        CLAUDE_DESKTOP_SESSION_COOKIE_NAME,
        session.session_key.as_str()
    ));
    let endpoint = format!(
        "{}/{}/usage",
        CLAUDE_DESKTOP_USAGE_ENDPOINT_PREFIX, session.organization_id
    );
    let response = ureq::get(&endpoint)
        .set("Accept", "application/json")
        .set("Content-Type", "application/json")
        .set("Cookie", cookie_header.as_str())
        .set("Origin", "https://claude.ai")
        .set("Referer", "https://claude.ai/settings/usage")
        .set("anthropic-client-platform", "web_claude_ai")
        .set(
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/136.0.0.0 Electron/36.0.0 Safari/537.36",
        )
        .timeout(COMMAND_TIMEOUT)
        .call();
    let response = match response {
        Ok(response) => response,
        Err(ureq::Error::Status(429, response)) => {
            let retry_after = claude_desktop_retry_after_epoch_seconds(&response, now);
            attempt_cache.next_refresh_after_epoch_seconds = retry_after;
            let _ = write_claude_desktop_web_usage_cache(&attempt_cache);
            if !attempt_cache.windows.is_empty()
                && now.saturating_sub(attempt_cache.observed_at_epoch_seconds)
                    <= CLAUDE_DESKTOP_USAGE_CACHE_MAX_AGE_SECONDS
            {
                return Ok(claude_desktop_web_usage_from_cache(
                    attempt_cache,
                    now,
                    &target.account_label,
                ));
            }
            return Err("Claude Desktop usage endpoint is temporarily rate limited.".to_string());
        }
        Err(error) => {
            if !attempt_cache.windows.is_empty()
                && now.saturating_sub(attempt_cache.observed_at_epoch_seconds)
                    <= CLAUDE_DESKTOP_USAGE_CACHE_MAX_AGE_SECONDS
            {
                return Ok(claude_desktop_web_usage_from_cache(
                    attempt_cache,
                    now,
                    &target.account_label,
                ));
            }
            return Err(claude_desktop_usage_error(error));
        }
    };
    let value: Value = response.into_json().map_err(|_| {
        "Claude Desktop usage endpoint returned an unreadable response.".to_string()
    })?;
    let mut usage = ClaudeOAuthUsage {
        windows: claude_oauth_quota_windows(&value),
        credit_balances: claude_oauth_credit_balances(&value),
    };
    if !usage.windows.is_empty() {
        let cache = ClaudeDesktopWebUsageCache {
            schema_version: CLAUDE_DESKTOP_USAGE_CACHE_SCHEMA_VERSION,
            account_identifier_hash: target.account_identifier_hash.clone(),
            organization_identifier_hash: session.organization_identifier_hash.clone(),
            observed_at_epoch_seconds: now,
            next_refresh_after_epoch_seconds: now + CLAUDE_DESKTOP_USAGE_REFRESH_SECONDS,
            windows: usage.windows.clone(),
            credit_balances: usage.credit_balances.clone(),
        };
        let _ = write_claude_desktop_web_usage_cache(&cache);
    }
    label_claude_desktop_usage(
        &mut usage,
        &target.account_label,
        &target.account_identifier_hash,
        &session.organization_identifier_hash,
    );
    Ok(usage)
}

fn claude_desktop_attempt_cache_for_session(
    cached: Option<ClaudeDesktopWebUsageCache>,
    target: &ClaudeDesktopWebUsageTarget,
    session: &ClaudeDesktopWebSession,
    next_refresh_after_epoch_seconds: u64,
) -> ClaudeDesktopWebUsageCache {
    cached
        .filter(|cache| cache.organization_identifier_hash == session.organization_identifier_hash)
        .unwrap_or_else(|| ClaudeDesktopWebUsageCache {
            schema_version: CLAUDE_DESKTOP_USAGE_CACHE_SCHEMA_VERSION,
            account_identifier_hash: target.account_identifier_hash.clone(),
            organization_identifier_hash: session.organization_identifier_hash.clone(),
            observed_at_epoch_seconds: 0,
            next_refresh_after_epoch_seconds,
            windows: Vec::new(),
            credit_balances: Vec::new(),
        })
}

fn claim_claude_desktop_usage_attempt(account_identifier_hash: &str, now: u64) -> bool {
    let gate = CLAUDE_DESKTOP_USAGE_ATTEMPT_GATE.get_or_init(|| Mutex::new(BTreeMap::new()));
    let Ok(mut gate) = gate.lock() else {
        return false;
    };
    if gate
        .get(account_identifier_hash)
        .is_some_and(|next_attempt| now < *next_attempt)
    {
        return false;
    }
    gate.insert(
        account_identifier_hash.to_string(),
        now + CLAUDE_DESKTOP_USAGE_REFRESH_SECONDS,
    );
    true
}

fn read_claude_desktop_web_session(desktop_root: &Path) -> Result<ClaudeDesktopWebSession, String> {
    let cookie_path = desktop_root.join("Cookies");
    let connection = Connection::open_with_flags(
        cookie_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| "Claude Desktop's local cookie database could not be read.".to_string())?;
    let read_cookie = |name: &str| {
        connection
            .query_row(
                "SELECT host_key, encrypted_value FROM cookies \
             WHERE name = ?1 AND host_key IN ('claude.ai', '.claude.ai') \
             ORDER BY CASE host_key WHEN '.claude.ai' THEN 0 ELSE 1 END LIMIT 1",
                [name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| "Claude Desktop's local session cookies could not be read.".to_string())?
            .ok_or_else(|| format!("Claude Desktop does not currently have a {name} cookie."))
    };
    let session_cookie: (String, Vec<u8>) = read_cookie(CLAUDE_DESKTOP_SESSION_COOKIE_NAME)?;
    let active_org_cookie: (String, Vec<u8>) = read_cookie(CLAUDE_DESKTOP_ACTIVE_ORG_COOKIE_NAME)?;
    let cookie_database_version = chromium_cookie_database_version(&connection);
    let safe_storage_password = read_claude_desktop_safe_storage_password()?;
    let session_key = decrypt_chromium_cookie(
        &session_cookie.0,
        &session_cookie.1,
        cookie_database_version,
        safe_storage_password.as_bytes(),
    )?;
    let active_org = decrypt_chromium_cookie_value(
        &active_org_cookie.0,
        &active_org_cookie.1,
        cookie_database_version,
        safe_storage_password.as_bytes(),
    )?;
    let organization_id = safe_local_identifier(active_org.as_str())
        .ok_or_else(|| "Claude Desktop's active organization cookie was invalid.".to_string())?
        .to_string();
    let organization_identifier_hash =
        billing_identity_hash("anthropic", "organization", &organization_id).ok_or_else(|| {
            "Claude Desktop's active organization could not be identified.".to_string()
        })?;
    Ok(ClaudeDesktopWebSession {
        session_key,
        organization_id,
        organization_identifier_hash,
    })
}

fn chromium_cookie_database_version(connection: &Connection) -> i64 {
    // Chromium declares `meta.value` with text affinity. SQLite therefore
    // returns version 24 as text even though Chromium writes an integer, while
    // rusqlite's typed getter does not coerce it to i64 for us.
    connection
        .query_row(
            "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'version'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_default()
}

fn read_claude_desktop_safe_storage_password() -> Result<Zeroizing<String>, String> {
    let output = run_command_capture(
        "security",
        &[
            "find-generic-password",
            "-s",
            CLAUDE_DESKTOP_SAFE_STORAGE_SERVICE,
            "-w",
        ],
        COMMAND_TIMEOUT,
    );
    if !output.command_found || !output.success {
        return Err(
            "macOS Keychain did not grant access to Claude Desktop's local session.".to_string(),
        );
    }
    let mut password = Zeroizing::new(output.stdout);
    while matches!(password.as_bytes().last(), Some(b'\n' | b'\r')) {
        password.pop();
    }
    if password.is_empty() {
        return Err("Claude Desktop's Keychain entry was empty.".to_string());
    }
    Ok(password)
}

fn decrypt_chromium_cookie(
    host_key: &str,
    encrypted_value: &[u8],
    cookie_database_version: i64,
    safe_storage_password: &[u8],
) -> Result<Zeroizing<String>, String> {
    let session_key = decrypt_chromium_cookie_value(
        host_key,
        encrypted_value,
        cookie_database_version,
        safe_storage_password,
    )?;
    if !session_key.starts_with("sk-ant-")
        || session_key.len() > 512
        || session_key.chars().any(char::is_whitespace)
    {
        return Err("Claude Desktop's session cookie had an invalid format.".to_string());
    }
    Ok(session_key)
}

fn decrypt_chromium_cookie_value(
    host_key: &str,
    encrypted_value: &[u8],
    cookie_database_version: i64,
    safe_storage_password: &[u8],
) -> Result<Zeroizing<String>, String> {
    let ciphertext = encrypted_value.strip_prefix(b"v10").ok_or_else(|| {
        "Claude Desktop's session cookie uses an unsupported encryption format.".to_string()
    })?;
    let mut key = Zeroizing::new([0_u8; CHROMIUM_COOKIE_KEY_BYTES]);
    pbkdf2_hmac::<Sha1>(
        safe_storage_password,
        b"saltysalt",
        CHROMIUM_COOKIE_KEY_ITERATIONS,
        key.as_mut(),
    );
    let decryptor = cbc::Decryptor::<Aes128>::new(key.as_ref().into(), (&[b' '; 16]).into());
    let plaintext = decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| "Claude Desktop's session cookie could not be decrypted.".to_string())?;
    let mut plaintext = Zeroizing::new(plaintext);
    if cookie_database_version >= CHROMIUM_COOKIE_HOST_DIGEST_VERSION {
        let expected_digest = Sha256::digest(host_key.as_bytes());
        if plaintext.len() < expected_digest.len()
            || plaintext[..expected_digest.len()] != expected_digest[..]
        {
            return Err("Claude Desktop's session cookie failed its host check.".to_string());
        }
        plaintext.drain(..expected_digest.len());
    }
    let session_key = String::from_utf8(std::mem::take(plaintext.as_mut()))
        .map_err(|_| "Claude Desktop's session cookie was not valid text.".to_string())?;
    let mut value = Zeroizing::new(session_key);
    while matches!(value.as_bytes().last(), Some(b'\n' | b'\r')) {
        value.pop();
    }
    Ok(value)
}

fn claude_desktop_web_usage_cache_path() -> PathBuf {
    default_support_dir().join(CLAUDE_DESKTOP_USAGE_CACHE_FILE)
}

fn read_claude_desktop_web_usage_cache() -> Option<ClaudeDesktopWebUsageCache> {
    let body = fs::read_to_string(claude_desktop_web_usage_cache_path()).ok()?;
    let cache: ClaudeDesktopWebUsageCache = serde_json::from_str(&body).ok()?;
    (cache.schema_version == CLAUDE_DESKTOP_USAGE_CACHE_SCHEMA_VERSION).then_some(cache)
}

fn write_claude_desktop_web_usage_cache(cache: &ClaudeDesktopWebUsageCache) -> std::io::Result<()> {
    let path = claude_desktop_web_usage_cache_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut cache = cache.clone();
    for window in &mut cache.windows {
        window.account_label = None;
        window.account_identifier_hash = None;
        window.organization_identifier_hash = None;
    }
    for balance in &mut cache.credit_balances {
        balance.account_label = None;
        balance.account_identifier_hash = None;
        balance.organization_identifier_hash = None;
    }
    let body = serde_json::to_vec_pretty(&cache).map_err(std::io::Error::other)?;
    fs::write(&path, body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn claude_desktop_web_usage_from_cache(
    cache: ClaudeDesktopWebUsageCache,
    now: u64,
    account_label: &str,
) -> ClaudeOAuthUsage {
    let account_identifier_hash = cache.account_identifier_hash.clone();
    let organization_identifier_hash = cache.organization_identifier_hash.clone();
    let cache_is_stale = now.saturating_sub(cache.observed_at_epoch_seconds)
        > CLAUDE_DESKTOP_USAGE_CACHE_FRESH_AGE_SECONDS;
    let mut usage = ClaudeOAuthUsage {
        windows: cache
            .windows
            .into_iter()
            .map(|mut window| {
                if cache_is_stale {
                    window.status = AgentQuotaWindowStatus::Unknown;
                    window.freshness = AgentQuotaWindowFreshness::Stale;
                }
                window
            })
            .collect(),
        credit_balances: cache
            .credit_balances
            .into_iter()
            .map(|mut balance| {
                if cache_is_stale {
                    balance.status = AgentCreditBalanceStatus::Stale;
                    balance.freshness = AgentQuotaWindowFreshness::Stale;
                }
                balance
            })
            .collect(),
    };
    label_claude_desktop_usage(
        &mut usage,
        account_label,
        &account_identifier_hash,
        &organization_identifier_hash,
    );
    usage
}

fn label_claude_desktop_usage(
    usage: &mut ClaudeOAuthUsage,
    account_label: &str,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) {
    for window in &mut usage.windows {
        window.account_label = Some(account_label.to_string());
        window.account_identifier_hash = Some(account_identifier_hash.to_string());
        window.organization_identifier_hash = Some(organization_identifier_hash.to_string());
    }
    for balance in &mut usage.credit_balances {
        balance.account_label = Some(account_label.to_string());
        balance.account_identifier_hash = Some(account_identifier_hash.to_string());
        balance.organization_identifier_hash = Some(organization_identifier_hash.to_string());
    }
}

fn claude_desktop_retry_after_epoch_seconds(response: &ureq::Response, now: u64) -> u64 {
    response
        .header("retry-after")
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|seconds| now.saturating_add(seconds))
        .unwrap_or(now + CLAUDE_DESKTOP_USAGE_RETRY_AFTER_FALLBACK_SECONDS)
}

fn claude_desktop_usage_error(error: ureq::Error) -> String {
    match error {
        ureq::Error::Status(401 | 403, _) => {
            "Claude Desktop rejected its local session; sign in again in Claude.".to_string()
        }
        ureq::Error::Status(429, _) => {
            "Claude Desktop usage endpoint is temporarily rate limited.".to_string()
        }
        ureq::Error::Status(status, _) => {
            format!("Claude Desktop usage endpoint returned HTTP {status}.")
        }
        ureq::Error::Transport(_) => "Claude Desktop usage endpoint was unreachable.".to_string(),
    }
}

impl ClaudeDesktopProfileBuilder {
    fn record_activity(&mut self, activity: Option<i64>, session_id: Option<String>) -> bool {
        let should_replace = match (activity, self.latest_activity_epoch_seconds) {
            (Some(next), Some(current)) => next >= current,
            (Some(_), None) => true,
            (None, _) => self.latest_session_id.is_none(),
        };
        if should_replace {
            self.latest_activity_epoch_seconds = activity.or(self.latest_activity_epoch_seconds);
            if session_id.is_some() {
                self.latest_session_id = session_id;
            }
        }
        should_replace
    }
}

fn read_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    let body = fs::read_to_string(path).ok()?;
    serde_json::from_str(&body).ok()
}

fn looks_like_local_json_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.starts_with("local_") && name.ends_with(".json")
}

fn safe_local_identifier(value: &str) -> Option<&str> {
    let value = value.trim();
    if value.is_empty() || value.len() > 128 {
        return None;
    }
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        Some(value)
    } else {
        None
    }
}

fn first_non_empty<'a>(values: impl IntoIterator<Item = Option<&'a str>>) -> Option<&'a str> {
    values
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
}

fn safe_display_label(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.is_empty()
        || value.len() > 255
        || value.contains('/')
        || value.contains('\\')
        || value.to_ascii_lowercase().contains("token")
        || value.to_ascii_lowercase().contains("secret")
    {
        return None;
    }
    Some(value.to_string())
}

fn timestamp_value_epoch_seconds(value: Option<&Value>) -> Option<i64> {
    let value = value?;
    if let Some(seconds) = value.as_i64() {
        return Some(seconds);
    }
    if let Some(seconds) = value.as_u64().and_then(|value| i64::try_from(value).ok()) {
        return Some(seconds);
    }
    if let Some(seconds) = value.as_f64() {
        if seconds.is_finite() {
            return Some(seconds.round() as i64);
        }
    }
    let text = value.as_str()?.trim();
    if text.is_empty() {
        return None;
    }
    if let Ok(seconds) = text.parse::<i64>() {
        return Some(seconds);
    }
    if let Ok(seconds) = text.parse::<f64>() {
        if seconds.is_finite() {
            return Some(seconds.round() as i64);
        }
    }
    OffsetDateTime::parse(text, &Rfc3339)
        .ok()
        .map(|value| value.unix_timestamp())
}

fn file_modified_epoch_seconds(path: &Path) -> Option<i64> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    let duration = modified
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .ok()?;
    i64::try_from(duration.as_secs()).ok()
}

/// What the statusLine rate-limit cache can offer the currently-resolved
/// account. `NotObserved` (nothing usable on disk) and `Unattributable`
/// (something on disk that is not provably ours) are deliberately distinct:
/// they read identically on the surface but mean opposite things about whether
/// collection is working.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ClaudeStatusLineQuota {
    Windows(Vec<AgentQuotaWindow>),
    NotObserved,
    Unattributable(ClaudeStatusLineUnattributable),
}

/// Why a cached statusLine sample may not be served as the current account's
/// quota. Each variant is a distinct thing an operator can act on, so they stay
/// separate rather than collapsing into "unavailable".
#[derive(Debug, Clone, PartialEq, Eq)]
enum ClaudeStatusLineUnattributable {
    /// Written while a different Claude Code credential was signed in -- the
    /// `/login` switch case, the same defect `ClaudeOAuthUsageCache` fixes.
    CredentialReplaced,
    /// A second Claude account is observable on this machine, so no statusLine
    /// sample can be tied to one of them.
    MultipleAccounts,
    /// Nothing on this machine names the account that wrote the sample, or the
    /// account reading it.
    AccountUnknown,
}

impl ClaudeStatusLineUnattributable {
    fn code(&self) -> &'static str {
        match self {
            Self::CredentialReplaced => "claude_statusline_cache_credential_replaced",
            Self::MultipleAccounts => "claude_statusline_cache_multiple_accounts",
            Self::AccountUnknown => "claude_statusline_cache_account_unknown",
        }
    }

    fn detail(&self) -> &'static str {
        match self {
            Self::CredentialReplaced => {
                "Claude Code statusLine quota is not currently observable for this account: the cached sample was written while a different Claude account was signed in."
            }
            Self::MultipleAccounts => {
                "Claude Code statusLine quota is not currently observable for this account: more than one Claude account is present on this machine, and statusLine samples carry no account identity."
            }
            Self::AccountUnknown => {
                "Claude Code statusLine quota is not currently observable for this account: the local Claude account could not be identified."
            }
        }
    }
}

/// Read the statusLine rate-limit cache, but only serve it as `account`'s quota
/// when it can actually be proven to be `account`'s.
///
/// `statusLine` is a Claude *Code* mechanism, not a Claude Desktop one. It is
/// configured once in `~/.claude/settings.json` and invoked by whichever Claude
/// Code surface renders -- the terminal CLI and the Claude Desktop app's "Code"
/// tab pipe to the same Ottto wrapper and overwrite the same machine-global
/// file. The payload names no account. So unlike `ClaudeOAuthUsageCache`, where
/// the daemon fetched the numbers itself and the writer's account key IS proof,
/// here the key records only which credential was visible at write time. Taken
/// alone it would launder a wrong attribution into a confident one: during the
/// live 2026-07-26 repro the CLI credential was the work Team account both when
/// the sample was written and when it was read, while the numbers belonged to
/// the personal Max account rendering in Desktop.
///
/// Proof therefore needs both halves:
///
/// 1. the sample was written under the credential that owns the machine now, and
/// 2. no *other* Claude account is observable on the machine at all.
///
/// Desktop plan observations already carry `account_identifier_hash` derived
/// without any decrypt, which is what makes (2) answerable today; the caller
/// passes them through `claude_account_identifier_hashes_from_observations`.
/// When either half fails the caller falls through to the typed unsupported
/// window rather than rendering another account's numbers.
fn collect_claude_statusline_quota_windows(
    account_identifier_hash: &str,
    observable_account_identifier_hashes: &[String],
) -> Result<ClaudeStatusLineQuota, String> {
    let cache = read_claude_statusline_cache(&default_support_dir())
        .map_err(|_| "Claude Code statusLine cache could not be read safely.".to_string())?;
    let Some(cache) = cache else {
        return Ok(ClaudeStatusLineQuota::NotObserved);
    };
    let now = current_unix_seconds();
    if cache.observed_at_epoch_seconds > now.saturating_add(60)
        || now.saturating_sub(cache.observed_at_epoch_seconds)
            > CLAUDE_STATUSLINE_CACHE_MAX_AGE_SECONDS
    {
        return Ok(ClaudeStatusLineQuota::NotObserved);
    }
    if let Some(reason) = claude_statusline_attribution_failure(
        &cache.observed_under_account_identifier_hash,
        account_identifier_hash,
        observable_account_identifier_hashes,
    ) {
        // Refusing to attribute is not an error -- the cache is intact, it just
        // is not ours to serve.
        return Ok(ClaudeStatusLineQuota::Unattributable(reason));
    }

    Ok(ClaudeStatusLineQuota::Windows(
        claude_statusline_quota_windows_from_cache(cache, now),
    ))
}

/// Every Claude account this machine can show us, as billing identity hashes.
/// Anything in here other than the signed-in account is another writer of the
/// shared statusLine cache.
fn claude_account_identifier_hashes_from_observations(
    observations: &[AgentStatusPlanObservation],
) -> Vec<String> {
    observations
        .iter()
        .filter_map(|observation| observation.account_identifier_hash.as_deref())
        .filter(|hash| !hash.is_empty())
        .map(ToString::to_string)
        .collect()
}

/// `None` when the sample provably belongs to the account that owns the local
/// Claude Code credential now.
fn claude_statusline_attribution_failure(
    observed_under_account_identifier_hash: &str,
    account_identifier_hash: &str,
    observable_account_identifier_hashes: &[String],
) -> Option<ClaudeStatusLineUnattributable> {
    // An unnamed account cannot be matched against anything. Unlike the OAuth
    // cache -- where two empty hashes are allowed to match, because there the
    // daemon fetched the numbers itself and an unidentifiable machine would
    // otherwise lose every cache hit against a rate-limited endpoint -- there is
    // no such cost here: statusLine is free to re-observe on the next render.
    if account_identifier_hash.is_empty() || observed_under_account_identifier_hash.is_empty() {
        return Some(ClaudeStatusLineUnattributable::AccountUnknown);
    }
    if observed_under_account_identifier_hash != account_identifier_hash {
        return Some(ClaudeStatusLineUnattributable::CredentialReplaced);
    }
    // Half two: any other Claude account on this machine can render a Claude
    // Code surface into the same cache, so its mere presence makes every sample
    // ambiguous -- including one whose write-time credential matches.
    let has_other_account = observable_account_identifier_hashes
        .iter()
        .any(|hash| hash != account_identifier_hash);
    if has_other_account {
        return Some(ClaudeStatusLineUnattributable::MultipleAccounts);
    }
    None
}

fn collect_claude_statusline_context_status() -> Result<AgentContextStatus, String> {
    let support_dir = default_support_dir();
    let cache = read_claude_statusline_context_cache(&support_dir).map_err(|_| {
        "Claude Code statusLine context cache could not be read safely.".to_string()
    })?;
    let history = read_claude_statusline_context_history(&support_dir)
        .ok()
        .flatten();
    let Some(cache) = cache else {
        return Ok(claude_statusline_context_unavailable(
            "statusline_context_not_observed",
            None,
        ));
    };
    let now = current_unix_seconds();
    let observed_at = rfc3339_from_unix_seconds(cache.observed_at_epoch_seconds);
    if cache.observed_at_epoch_seconds > now.saturating_add(60)
        || now.saturating_sub(cache.observed_at_epoch_seconds)
            > CLAUDE_STATUSLINE_CACHE_MAX_AGE_SECONDS
    {
        return Ok(claude_statusline_context_unavailable(
            "statusline_context_cache_stale",
            observed_at,
        ));
    }

    Ok(claude_statusline_context_from_cache(cache, history))
}

/// Collect Claude OAuth usage and stamp every served window and credit balance
/// with the account the numbers belong to.
///
/// The caller resolves the identity once (`collect_claude_status`) and this
/// path scopes every cache read to it, so one stamp at the boundary covers
/// fresh fetches and every cache fallback alike -- the cache is discarded
/// rather than served whenever it belongs to a different account
/// (`claude_oauth_usage_cache_belongs_to_account`). An unresolved account
/// stays unstamped: unknown must read as unknown downstream, never as a guess.
fn collect_claude_oauth_usage(
    account_identifier_hash: &str,
    organization_identifier_hash: Option<&str>,
) -> ClaudeOAuthUsageOutcome {
    let mut outcome = collect_claude_oauth_usage_unstamped(account_identifier_hash);
    if let Ok(usage) = &mut outcome.result {
        claude_oauth_stamp_account_identity(
            usage,
            account_identifier_hash,
            organization_identifier_hash,
        );
    }
    outcome
}

fn claude_oauth_stamp_account_identity(
    usage: &mut ClaudeOAuthUsage,
    account_identifier_hash: &str,
    organization_identifier_hash: Option<&str>,
) {
    let account =
        (!account_identifier_hash.is_empty()).then(|| account_identifier_hash.to_string());
    let organization = organization_identifier_hash
        .filter(|hash| !hash.is_empty())
        .map(ToString::to_string);
    for window in &mut usage.windows {
        window.account_identifier_hash = account.clone();
        window.organization_identifier_hash = organization.clone();
    }
    for balance in &mut usage.credit_balances {
        balance.account_identifier_hash = account.clone();
        balance.organization_identifier_hash = organization.clone();
    }
}

fn collect_claude_oauth_usage_unstamped(account_identifier_hash: &str) -> ClaudeOAuthUsageOutcome {
    let now = current_unix_seconds();

    // Off-switch first, ahead of the cache: the sentinel turns this whole data
    // path off, not just the socket. Serving a previously fetched payload while
    // the user has switched the endpoint off would still be serving endpoint
    // data, so the cached copy is dropped from disk too and quota falls back to
    // Claude Code's own local statusLine surface.
    if claude_oauth_usage_network_disabled() {
        let _ = fs::remove_file(claude_oauth_usage_cache_path());
        return ClaudeOAuthUsageOutcome {
            result: Err(
                "Claude OAuth usage endpoint is switched off on this machine.".to_string(),
            ),
            diagnostics: vec![AgentStatusDiagnostic::source(
                "claude_oauth_usage_network_disabled",
                AgentDiagnosticSeverity::Info,
                "Claude subscription quota is read from Claude Code's local statusLine only: the Claude OAuth usage network read is switched off on this machine.",
            )],
        };
    }

    let config_fingerprint = claude_oauth_usage_config_fingerprint();
    if let Some(breaker) =
        read_claude_oauth_usage_breaker(account_identifier_hash, &config_fingerprint)
    {
        if claude_oauth_usage_breaker_is_open(&breaker, now) {
            return ClaudeOAuthUsageOutcome {
                result: Err("Claude OAuth usage endpoint is not being called.".to_string()),
                diagnostics: vec![claude_oauth_usage_circuit_open_diagnostic(&breaker, now)],
            };
        }
    }

    if let Some(cache) = read_claude_oauth_usage_cache(account_identifier_hash) {
        let cache_age = now.saturating_sub(cache.observed_at_epoch_seconds);
        if !cache.windows.is_empty()
            && cache_age <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
            && (cache_age <= claude_oauth_usage_fresh_age_seconds(account_identifier_hash)
                || now < cache.next_refresh_after_epoch_seconds)
        {
            return ClaudeOAuthUsageOutcome::from(Ok(claude_oauth_usage_from_cache(cache, now)));
        }
        if now < cache.next_refresh_after_epoch_seconds {
            return ClaudeOAuthUsageOutcome::from(Err(
                "Claude OAuth usage endpoint is rate limited.".to_string(),
            ));
        }
    }

    let Some(token) = read_claude_oauth_access_token() else {
        return ClaudeOAuthUsageOutcome::from(Err(
            "Claude OAuth credentials were not available locally.".to_string(),
        ));
    };
    let authorization = format!("Bearer {token}");
    let user_agent = ottto_user_agent();
    let response = ureq::get(CLAUDE_OAUTH_USAGE_ENDPOINT)
        .set("Accept", "application/json")
        .set("Content-Type", "application/json")
        .set("Authorization", &authorization)
        .set("anthropic-beta", CLAUDE_OAUTH_BETA_HEADER)
        .set("User-Agent", &user_agent)
        .timeout(COMMAND_TIMEOUT)
        .call();
    let response = match response {
        Ok(response) => response,
        Err(ureq::Error::Status(429, response)) => {
            let retry_after = claude_oauth_retry_after_epoch_seconds(&response, now);
            // A cache belonging to another account is not merely skipped here:
            // `unwrap_or` replaces it with an empty cache for the current
            // account, so the write below also clears the stale payload off
            // disk instead of leaving it to be reconsidered next tick.
            let mut cache = read_claude_oauth_usage_cache(account_identifier_hash).unwrap_or(
                ClaudeOAuthUsageCache {
                    schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
                    account_identifier_hash: account_identifier_hash.to_string(),
                    observed_at_epoch_seconds: now,
                    next_refresh_after_epoch_seconds: retry_after,
                    windows: Vec::new(),
                    credit_balances: Vec::new(),
                },
            );
            cache.next_refresh_after_epoch_seconds = retry_after;
            let _ = write_claude_oauth_usage_cache(&cache);
            // The retry-after backoff above still handles the transient case
            // unchanged; the breaker only fires once 429s outlive it.
            let diagnostics = record_claude_oauth_usage_failure(
                ClaudeOAuthUsageFailure::RateLimited,
                account_identifier_hash,
                &config_fingerprint,
                now,
            );
            if !cache.windows.is_empty()
                && now.saturating_sub(cache.observed_at_epoch_seconds)
                    <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
            {
                return ClaudeOAuthUsageOutcome {
                    result: Ok(claude_oauth_usage_from_cache(cache, now)),
                    diagnostics,
                };
            }
            return ClaudeOAuthUsageOutcome {
                result: Err("Claude OAuth usage endpoint is rate limited.".to_string()),
                diagnostics,
            };
        }
        Err(error) => {
            let diagnostics = match claude_oauth_usage_failure_class(&error) {
                Some(failure) => record_claude_oauth_usage_failure(
                    failure,
                    account_identifier_hash,
                    &config_fingerprint,
                    now,
                ),
                None => Vec::new(),
            };
            if let Some(cache) = read_claude_oauth_usage_cache(account_identifier_hash) {
                if !cache.windows.is_empty()
                    && now.saturating_sub(cache.observed_at_epoch_seconds)
                        <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
                {
                    return ClaudeOAuthUsageOutcome {
                        result: Ok(claude_oauth_usage_from_cache(cache, now)),
                        diagnostics,
                    };
                }
            }
            return ClaudeOAuthUsageOutcome {
                result: Err(claude_oauth_usage_error(error)),
                diagnostics,
            };
        }
    };
    let Ok(value) = response.into_json::<Value>() else {
        return ClaudeOAuthUsageOutcome {
            result: Err("Claude OAuth usage endpoint returned an unreadable response.".to_string()),
            diagnostics: record_claude_oauth_usage_failure(
                ClaudeOAuthUsageFailure::ResponseShape,
                account_identifier_hash,
                &config_fingerprint,
                now,
            ),
        };
    };
    let usage = ClaudeOAuthUsage {
        windows: claude_oauth_quota_windows(&value),
        credit_balances: claude_oauth_credit_balances(&value),
    };
    if usage.windows.is_empty() {
        // A 200 that carries none of the expected quota fields is a shape
        // change, not an empty account: every plan this endpoint answers for
        // reports at least one window.
        return ClaudeOAuthUsageOutcome {
            result: Ok(usage),
            diagnostics: record_claude_oauth_usage_failure(
                ClaudeOAuthUsageFailure::ResponseShape,
                account_identifier_hash,
                &config_fingerprint,
                now,
            ),
        };
    }
    let _ = write_claude_oauth_usage_cache(&ClaudeOAuthUsageCache {
        schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
        account_identifier_hash: account_identifier_hash.to_string(),
        observed_at_epoch_seconds: now,
        next_refresh_after_epoch_seconds: now + CLAUDE_OAUTH_USAGE_REFRESH_SECONDS,
        windows: usage.windows.clone(),
        credit_balances: usage.credit_balances.clone(),
    });
    // One clean answer clears the accumulated failure counters: the thresholds
    // below are about *consecutive* failures.
    clear_claude_oauth_usage_breaker();
    ClaudeOAuthUsageOutcome::from(Ok(usage))
}

impl From<Result<ClaudeOAuthUsage, String>> for ClaudeOAuthUsageOutcome {
    fn from(result: Result<ClaudeOAuthUsage, String>) -> Self {
        Self {
            result,
            diagnostics: Vec::new(),
        }
    }
}

/// Effective freshness gate for the Claude OAuth usage read: the ~60-minute
/// base cadence spread deterministically across a 55-65 minute band.
///
/// The spread is load-spreading across OUR OWN users - it stops every Ottto
/// install from refreshing on the same wall-clock minute. It is explicitly NOT
/// evasion and hides nothing: the request carries an honest
/// `ottto/<version> (subscription-usage-reader; ...)` User-Agent, and a
/// timer-driven daemon is identifiable from its behaviour regardless of phase.
/// Recorded provider-endpoints posture, 2026-07-26.
///
/// Derived from the account hash rather than a random draw so the gate is
/// stable for a machine: a per-tick random offset would make the cadence
/// jitter around every refresh instead of holding one steady phase.
fn claude_oauth_usage_fresh_age_seconds(seed: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"ottto:claude-oauth-usage-cadence:");
    hasher.update(seed.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    let span = CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_JITTER_SECONDS * 2 + 1;
    let offset = u64::from_be_bytes(bytes) % span;
    CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_SECONDS + offset
        - CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_JITTER_SECONDS
}

/// Whether the off-switch sentinel is present in the daemon support dir.
///
/// Same directory mechanics as the Claude Desktop usage sentinel. Absent file
/// means enabled, which keeps the default behaviour unchanged.
fn claude_oauth_usage_network_disabled() -> bool {
    default_support_dir()
        .join(CLAUDE_OAUTH_USAGE_NETWORK_DISABLED_FILE)
        .is_file()
}

fn claude_oauth_usage_breaker_path() -> PathBuf {
    default_support_dir().join(CLAUDE_OAUTH_USAGE_BREAKER_FILE)
}

/// Fingerprint of everything about the call that could make a past failure
/// irrelevant: the endpoint, the beta header, the User-Agent we identify with,
/// and whether the off-switch is engaged. When any of them changes - a daemon
/// upgrade, or the user toggling the sentinel off and back on - the breaker
/// resets rather than holding a verdict about a call we no longer make.
fn claude_oauth_usage_config_fingerprint() -> String {
    claude_oauth_usage_config_fingerprint_for(
        CLAUDE_OAUTH_USAGE_ENDPOINT,
        CLAUDE_OAUTH_BETA_HEADER,
        &ottto_user_agent(),
        claude_oauth_usage_network_disabled(),
    )
}

fn claude_oauth_usage_config_fingerprint_for(
    endpoint: &str,
    beta_header: &str,
    user_agent: &str,
    network_disabled: bool,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ottto:claude-oauth-usage-config:");
    hasher.update(endpoint.as_bytes());
    hasher.update(b"\0");
    hasher.update(beta_header.as_bytes());
    hasher.update(b"\0");
    hasher.update(user_agent.as_bytes());
    hasher.update(b"\0");
    hasher.update(if network_disabled { "off" } else { "on" }.as_bytes());
    format!("{:x}", hasher.finalize())[..16].to_string()
}

fn read_claude_oauth_usage_breaker(
    account_identifier_hash: &str,
    config_fingerprint: &str,
) -> Option<ClaudeOAuthUsageBreaker> {
    let body = fs::read_to_string(claude_oauth_usage_breaker_path()).ok()?;
    let breaker: ClaudeOAuthUsageBreaker = serde_json::from_str(&body).ok()?;
    if breaker.schema_version != CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION
        || breaker.account_identifier_hash != account_identifier_hash
        || breaker.config_fingerprint != config_fingerprint
    {
        return None;
    }
    Some(breaker)
}

fn write_claude_oauth_usage_breaker(breaker: &ClaudeOAuthUsageBreaker) -> std::io::Result<()> {
    let path = claude_oauth_usage_breaker_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_vec_pretty(breaker).map_err(std::io::Error::other)?;
    fs::write(path, body)
}

fn clear_claude_oauth_usage_breaker() {
    let _ = fs::remove_file(claude_oauth_usage_breaker_path());
}

fn claude_oauth_usage_breaker_is_open(breaker: &ClaudeOAuthUsageBreaker, now: u64) -> bool {
    // Reset by expiry: once the cool-down passes the breaker is closed again
    // and the next tick re-probes with the counters it carries.
    now < breaker.reopen_after_epoch_seconds
}

/// Fold one failure into the persisted breaker state. Pure so the thresholds
/// and the cool-down can be exercised without touching disk or the network.
fn claude_oauth_usage_breaker_after_failure(
    previous: Option<ClaudeOAuthUsageBreaker>,
    failure: ClaudeOAuthUsageFailure,
    account_identifier_hash: &str,
    config_fingerprint: &str,
    now: u64,
) -> ClaudeOAuthUsageBreaker {
    let mut breaker = previous.unwrap_or_default();
    breaker.schema_version = CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION;
    breaker.account_identifier_hash = account_identifier_hash.to_string();
    breaker.config_fingerprint = config_fingerprint.to_string();
    let counter = match failure {
        ClaudeOAuthUsageFailure::AuthRejected => &mut breaker.auth_failures,
        ClaudeOAuthUsageFailure::ResponseShape => &mut breaker.shape_failures,
        ClaudeOAuthUsageFailure::RateLimited => &mut breaker.rate_limit_failures,
    };
    *counter = counter.saturating_add(1);
    if *counter >= failure.threshold() && !claude_oauth_usage_breaker_is_open(&breaker, now) {
        breaker.opened_at_epoch_seconds = now;
        breaker.reopen_after_epoch_seconds = now + CLAUDE_OAUTH_USAGE_BREAKER_COOLDOWN_SECONDS;
        breaker.opened_by = failure.code().to_string();
    }
    breaker
}

fn record_claude_oauth_usage_failure(
    failure: ClaudeOAuthUsageFailure,
    account_identifier_hash: &str,
    config_fingerprint: &str,
    now: u64,
) -> Vec<AgentStatusDiagnostic> {
    let previous = read_claude_oauth_usage_breaker(account_identifier_hash, config_fingerprint);
    let was_open = previous
        .as_ref()
        .is_some_and(|breaker| claude_oauth_usage_breaker_is_open(breaker, now));
    let breaker = claude_oauth_usage_breaker_after_failure(
        previous,
        failure,
        account_identifier_hash,
        config_fingerprint,
        now,
    );
    let _ = write_claude_oauth_usage_breaker(&breaker);
    if !was_open && claude_oauth_usage_breaker_is_open(&breaker, now) {
        return vec![claude_oauth_usage_circuit_open_diagnostic(&breaker, now)];
    }
    Vec::new()
}

/// The alert itself. Snapshot diagnostics are uploaded with the agent-status
/// snapshot, so this reaches the backend on the next sync without a separate
/// telemetry channel.
fn claude_oauth_usage_circuit_open_diagnostic(
    breaker: &ClaudeOAuthUsageBreaker,
    now: u64,
) -> AgentStatusDiagnostic {
    let reason = if breaker.opened_by.is_empty() {
        "repeated failures".to_string()
    } else {
        breaker.opened_by.replace('_', " ")
    };
    let remaining_minutes = breaker.reopen_after_epoch_seconds.saturating_sub(now) / 60;
    AgentStatusDiagnostic::source(
        "claude_oauth_usage_circuit_open",
        AgentDiagnosticSeverity::Warning,
        format!(
            "Stopped calling the Claude OAuth usage endpoint after {reason}; quota falls back to Claude Code's local statusLine for the next {remaining_minutes} minute(s)."
        ),
    )
}

/// Which failure class, if any, a transport-level error counts as. `None` means
/// transient: transport errors and server-side 5xx say nothing about whether we
/// should keep calling.
fn claude_oauth_usage_failure_class(error: &ureq::Error) -> Option<ClaudeOAuthUsageFailure> {
    match error {
        ureq::Error::Status(401 | 403, _) => Some(ClaudeOAuthUsageFailure::AuthRejected),
        // The endpoint answering "gone" is a shape change by another name.
        ureq::Error::Status(404 | 410, _) => Some(ClaudeOAuthUsageFailure::ResponseShape),
        _ => None,
    }
}

fn read_claude_oauth_access_token() -> Option<String> {
    read_claude_oauth_access_token_from_keychain()
        .or_else(read_claude_oauth_access_token_from_credentials_file)
}

fn read_claude_oauth_access_token_from_keychain() -> Option<String> {
    let output = run_command_capture(
        "security",
        &[
            "find-generic-password",
            "-s",
            CLAUDE_OAUTH_KEYCHAIN_SERVICE,
            "-w",
        ],
        COMMAND_TIMEOUT,
    );
    if !output.command_found || !output.success {
        return None;
    }
    parse_claude_oauth_access_token(&output.stdout)
}

fn read_claude_oauth_access_token_from_credentials_file() -> Option<String> {
    let path = home_path(".claude").join(".credentials.json");
    let body = fs::read_to_string(path).ok()?;
    parse_claude_oauth_access_token(&body)
}

fn parse_claude_oauth_access_token(payload: &str) -> Option<String> {
    let value: Value = serde_json::from_str(payload).ok()?;
    value
        .get("claudeAiOauth")
        .and_then(|oauth| oauth.get("accessToken"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(ToString::to_string)
}

fn claude_oauth_usage_error(error: ureq::Error) -> String {
    match error {
        ureq::Error::Status(401 | 403, _) => {
            "Claude OAuth usage endpoint rejected the local Claude Code session.".to_string()
        }
        ureq::Error::Status(429, _) => "Claude OAuth usage endpoint is rate limited.".to_string(),
        ureq::Error::Status(status, _) => {
            format!("Claude OAuth usage endpoint returned HTTP {status}.")
        }
        ureq::Error::Transport(_) => "Claude OAuth usage endpoint was unreachable.".to_string(),
    }
}

fn claude_oauth_usage_cache_path() -> PathBuf {
    default_support_dir().join(CLAUDE_OAUTH_USAGE_CACHE_FILE)
}

/// Identify the Claude account that currently owns the local Claude Code
/// credential, as a `billing_identity_hash`. Callers resolve it from
/// `read_claude_cli_oauth_account`; an account-less config yields an empty
/// hash.
///
/// Deliberately NOT a hash of the access token: the token rotates on refresh
/// while the account does not, so a token fingerprint would discard a valid
/// same-account cache on every rotation -- extra fetches against an endpoint
/// that rate-limits, and no cache left to fall back on when it answers 429.
/// `oauthAccount` is rewritten by Claude Code itself on every profile refresh,
/// so it tracks the credential without inheriting its rotation.
fn claude_oauth_account_identifier_hash_for(account: &ClaudeCliOauthAccount) -> String {
    // Same preference order the subscription grouping uses: provider account
    // id, then organization, then email. It lives in `ottto-core` because the
    // CLI's statusLine writer stamps the same hash and the two must agree
    // exactly -- a divergence would read as "foreign cache" and quota would
    // silently vanish rather than fail loudly.
    claude_account_identifier_hash(
        account.account_uuid.as_deref(),
        account.organization_uuid.as_deref(),
        account.email_address.as_deref(),
    )
}

fn read_claude_oauth_usage_cache(account_identifier_hash: &str) -> Option<ClaudeOAuthUsageCache> {
    let path = claude_oauth_usage_cache_path();
    let body = fs::read_to_string(path).ok()?;
    let cache: ClaudeOAuthUsageCache = serde_json::from_str(&body).ok()?;
    if cache.schema_version != CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION {
        // Older cache layouts (v1: windows only; v2: no account identity) are
        // discarded so the next tick refetches under a known account.
        return None;
    }
    if !claude_oauth_usage_cache_belongs_to_account(&cache, account_identifier_hash) {
        return None;
    }
    Some(cache)
}

/// Whether a cached OAuth usage payload may be served for the account that
/// currently owns the credential.
///
/// Exact match, both directions. A cache written under account A is never
/// served once account B holds the credential -- including on the 429 and
/// transport fallback paths, where another account's quota is worse than no
/// quota at all, because the fallback window is 24h and 429s on this endpoint
/// are routine.
///
/// Two empty hashes DO match: if the local account metadata named no account
/// when the cache was written and still names none now, nothing changed that we
/// can observe. Refusing there would drop every cache hit on such machines and
/// turn each status tick into another request to a rate-limited endpoint.
fn claude_oauth_usage_cache_belongs_to_account(
    cache: &ClaudeOAuthUsageCache,
    account_identifier_hash: &str,
) -> bool {
    cache.account_identifier_hash == account_identifier_hash
}

fn write_claude_oauth_usage_cache(cache: &ClaudeOAuthUsageCache) -> std::io::Result<()> {
    let path = claude_oauth_usage_cache_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_vec_pretty(cache).map_err(std::io::Error::other)?;
    fs::write(path, body)
}

fn claude_oauth_retry_after_epoch_seconds(response: &ureq::Response, now: u64) -> u64 {
    response
        .header("retry-after")
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(CLAUDE_OAUTH_USAGE_RETRY_AFTER_FALLBACK_SECONDS)
        .saturating_add(now)
}

pub(crate) fn ottto_user_agent() -> String {
    // Honest identification: Ottto reads the user's own aggregate usage and
    // says so. Never present a claude-* client identity from an
    // Ottto-originated request (recorded provider-endpoints posture,
    // 2026-07-26). Shared by every Ottto-originated provider read, so one
    // identity change moves them all together.
    // compiled_release_version(), not CARGO_PKG_VERSION: the
    // crate manifest carries the 0.1.0 placeholder and real release versions
    // are injected via OTTTO_RELEASE_VERSION at package time.
    format!(
        "ottto/{} (subscription-usage-reader; +https://ottto.net)",
        compiled_release_version()
    )
}

fn claude_oauth_quota_windows(value: &Value) -> Vec<AgentQuotaWindow> {
    let mut windows = Vec::new();
    if let Some(window) = claude_oauth_quota_window("session", value.get("five_hour"), 5 * 60 * 60)
    {
        windows.push(window);
    }
    if let Some(window) =
        claude_oauth_quota_window("weekly", value.get("seven_day"), 7 * 24 * 60 * 60)
    {
        windows.push(window);
    }
    windows.extend(claude_oauth_scoped_limit_windows(value));
    windows
}

/// Per-model scoped limits from the `limits[]` array (e.g. `weekly_scoped`
/// for one model at 98% while the account-level `seven_day` shows 82%).
/// Entries without a model scope duplicate `five_hour`/`seven_day` account
/// windows (`session`, `weekly_all`) and are skipped.
fn claude_oauth_scoped_limit_windows(value: &Value) -> Vec<AgentQuotaWindow> {
    let Some(limits) = value.get("limits").and_then(Value::as_array) else {
        return Vec::new();
    };
    limits
        .iter()
        .filter_map(|entry| {
            let model = entry
                .get("scope")
                .and_then(|scope| scope.get("model"))
                .and_then(|model| {
                    model
                        .get("display_name")
                        .or_else(|| model.get("id"))
                        .and_then(Value::as_str)
                })
                .map(str::trim)
                .filter(|name| !name.is_empty())?;
            let used_percent = json_u8(entry, &["percent"]);
            let resets_at = json_timestamp_rfc3339(entry, &["resets_at", "reset_at"]);
            if used_percent.is_none() && resets_at.is_none() {
                return None;
            }
            let name = entry
                .get("kind")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|kind| !kind.is_empty())
                .unwrap_or("scoped")
                .to_string();
            Some(AgentQuotaWindow {
                name,
                scope: AgentQuotaWindowScope::Model,
                status: used_percent
                    .map(percent_quota_status)
                    .unwrap_or(AgentQuotaWindowStatus::Unknown),
                freshness: AgentQuotaWindowFreshness::Fresh,
                model: Some(model.to_string()),
                resets_at,
                used_percent,
                left_percent: used_percent.map(|used| 100_u8.saturating_sub(used)),
                group: json_trimmed_string(entry, "group"),
                severity: json_trimmed_string(entry, "severity"),
                is_active: entry.get("is_active").and_then(Value::as_bool),
                ..Default::default()
            })
        })
        .collect()
}

/// Usage-credit balances from the OAuth usage response. The newer `spend`
/// object is authoritative; the older `extra_usage` shape is the fallback.
/// Disabled accounts emit nothing (no credit chrome downstream), and a missing
/// or unrecognized shape fails soft to an empty list so quota windows are
/// never hidden by credit parsing.
fn claude_oauth_credit_balances(value: &Value) -> Vec<AgentCreditBalance> {
    claude_oauth_spend_credit_balance(value.get("spend"))
        .or_else(|| claude_oauth_extra_usage_credit_balance(value.get("extra_usage")))
        .into_iter()
        .collect()
}

fn claude_oauth_spend_credit_balance(spend: Option<&Value>) -> Option<AgentCreditBalance> {
    let spend = spend?;
    if spend.get("enabled").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let used = claude_oauth_money_cents(spend.get("used"));
    let quota = claude_oauth_money_cents(spend.get("cap"))
        .or_else(|| claude_oauth_money_cents(spend.get("limit")));
    let remaining =
        claude_oauth_money_cents(spend.get("balance")).or_else(|| match (quota, used) {
            (Some(quota), Some(used)) => Some(quota.saturating_sub(used)),
            _ => None,
        });
    if used.is_none() && quota.is_none() && remaining.is_none() {
        return None;
    }
    let used_percent = json_u8(spend, &["percent"]).or_else(|| match (used, quota) {
        (Some(used), Some(quota)) if quota > 0 => {
            Some(((used.saturating_mul(100)) / quota).min(100) as u8)
        }
        _ => None,
    });
    let severity = spend.get("severity").and_then(Value::as_str).unwrap_or("");
    Some(AgentCreditBalance {
        name: "Usage credits".to_string(),
        status: claude_oauth_credit_status(severity, used, quota, remaining),
        freshness: AgentQuotaWindowFreshness::Fresh,
        unit: AgentCreditBalanceUnit::Usd,
        remaining,
        used,
        quota,
        currency: claude_oauth_money_currency(spend.get("used"))
            .or_else(|| json_trimmed_string(spend, "currency")),
        resets_at: json_timestamp_rfc3339(spend, &["resets_at", "reset_at"]),
        used_percent,
        enabled: Some(true),
        ..Default::default()
    })
}

fn claude_oauth_extra_usage_credit_balance(extra: Option<&Value>) -> Option<AgentCreditBalance> {
    let extra = extra?;
    if extra.get("is_enabled").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let quota = claude_oauth_money_cents(extra.get("monthly_limit"));
    let used = claude_oauth_money_cents(extra.get("used_credits"));
    let remaining = match (quota, used) {
        (Some(quota), Some(used)) => Some(quota.saturating_sub(used)),
        _ => None,
    };
    if used.is_none() && quota.is_none() {
        return None;
    }
    let used_percent = json_u8(extra, &["utilization"]);
    Some(AgentCreditBalance {
        name: "Usage credits".to_string(),
        status: claude_oauth_credit_status("", used, quota, remaining),
        freshness: AgentQuotaWindowFreshness::Fresh,
        unit: AgentCreditBalanceUnit::Usd,
        remaining,
        used,
        quota,
        currency: json_trimmed_string(extra, "currency"),
        resets_at: None,
        used_percent,
        enabled: Some(true),
        ..Default::default()
    })
}

fn claude_oauth_credit_status(
    severity: &str,
    used: Option<u64>,
    quota: Option<u64>,
    remaining: Option<u64>,
) -> AgentCreditBalanceStatus {
    match severity.trim().to_ascii_lowercase().as_str() {
        "critical" => return AgentCreditBalanceStatus::Exhausted,
        "warning" => return AgentCreditBalanceStatus::Low,
        "normal" => return AgentCreditBalanceStatus::Ok,
        _ => {}
    }
    match (used, quota, remaining) {
        (_, _, Some(0)) => AgentCreditBalanceStatus::Exhausted,
        (Some(used), Some(quota), _) if quota > 0 && used >= quota => {
            AgentCreditBalanceStatus::Exhausted
        }
        (Some(used), Some(quota), _) if quota > 0 && used.saturating_mul(10) >= quota * 9 => {
            AgentCreditBalanceStatus::Low
        }
        (Some(_), _, _) | (_, Some(_), _) => AgentCreditBalanceStatus::Ok,
        _ => AgentCreditBalanceStatus::Unknown,
    }
}

/// Normalize a provider money value to integer minor units (cents).
///
/// Accepts either the structured shape `{"amount_minor": 321, "currency":
/// "USD", "exponent": 2}` (exponent 0..=6, scaled to 2 with round-half-up on
/// downscale) or a bare non-negative number interpreted as whole dollars.
fn claude_oauth_money_cents(value: Option<&Value>) -> Option<u64> {
    let value = value?;
    if let Some(object) = value.as_object() {
        let amount_minor = object.get("amount_minor").and_then(Value::as_i64)?;
        if amount_minor < 0 {
            return None;
        }
        let amount_minor = amount_minor as u64;
        let exponent = object.get("exponent").and_then(Value::as_u64).unwrap_or(2);
        if exponent > 6 {
            return None;
        }
        return Some(match exponent.cmp(&2) {
            std::cmp::Ordering::Equal => amount_minor,
            std::cmp::Ordering::Less => {
                amount_minor.saturating_mul(10_u64.pow((2 - exponent) as u32))
            }
            std::cmp::Ordering::Greater => {
                let divisor = 10_u64.pow((exponent - 2) as u32);
                (amount_minor + divisor / 2) / divisor
            }
        });
    }
    let dollars = value.as_f64()?;
    if !dollars.is_finite() || dollars < 0.0 {
        return None;
    }
    Some((dollars * 100.0).round() as u64)
}

fn claude_oauth_money_currency(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_object)
        .and_then(|object| object.get("currency"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|currency| !currency.is_empty())
        .map(ToString::to_string)
}

fn json_trimmed_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(ToString::to_string)
}

fn claude_oauth_quota_window(
    name: &str,
    value: Option<&Value>,
    window_seconds: u64,
) -> Option<AgentQuotaWindow> {
    let value = value?;
    let used_percent = json_u8(value, &["utilization", "used_percentage", "used_percent"]);
    let resets_at = json_timestamp_rfc3339(value, &["resets_at", "reset_at"]);
    if used_percent.is_none() && resets_at.is_none() {
        return None;
    }
    let left_percent = used_percent.map(|used| 100_u8.saturating_sub(used));
    let started_at = resets_at
        .as_deref()
        .and_then(|reset| rfc3339_minus_seconds(reset, window_seconds));
    Some(AgentQuotaWindow {
        name: name.to_string(),
        scope: AgentQuotaWindowScope::Account,
        status: used_percent
            .map(percent_quota_status)
            .unwrap_or(AgentQuotaWindowStatus::Unknown),
        freshness: AgentQuotaWindowFreshness::Fresh,
        model: None,
        account_label: None,
        window_seconds: Some(window_seconds),
        started_at,
        resets_at,
        quota: None,
        remaining: None,
        used_percent,
        left_percent,
        limit_cents: claude_oauth_money_cents(value.get("limit_dollars")),
        used_cents: claude_oauth_money_cents(value.get("used_dollars")),
        remaining_cents: claude_oauth_money_cents(value.get("remaining_dollars")),
        ..Default::default()
    })
}

fn claude_oauth_usage_from_cache(cache: ClaudeOAuthUsageCache, now: u64) -> ClaudeOAuthUsage {
    let cache_age = now.saturating_sub(cache.observed_at_epoch_seconds);
    // Same jittered gate the refresh decision uses, seeded from the account the
    // cache belongs to: a payload served as fresh must not be labelled stale.
    let cache_is_stale =
        cache_age > claude_oauth_usage_fresh_age_seconds(&cache.account_identifier_hash);
    let observed_at = rfc3339_from_unix_seconds(cache.observed_at_epoch_seconds);
    ClaudeOAuthUsage {
        windows: cache
            .windows
            .into_iter()
            .map(|mut window| {
                window.observed_at = observed_at.clone();
                if cache_is_stale {
                    window.status = AgentQuotaWindowStatus::Unknown;
                    window.freshness = AgentQuotaWindowFreshness::Stale;
                } else {
                    window.freshness = AgentQuotaWindowFreshness::Fresh;
                }
                window
            })
            .collect(),
        credit_balances: cache
            .credit_balances
            .into_iter()
            .map(|mut credit| {
                credit.freshness = if cache_is_stale {
                    AgentQuotaWindowFreshness::Stale
                } else {
                    AgentQuotaWindowFreshness::Fresh
                };
                credit
            })
            .collect(),
    }
}

fn claude_statusline_quota_windows_from_cache(
    cache: ClaudeStatusLineRateLimitCache,
    now: u64,
) -> Vec<AgentQuotaWindow> {
    let mut windows = Vec::new();
    let cache_age = now.saturating_sub(cache.observed_at_epoch_seconds);
    let cache_is_stale = cache_age > CLAUDE_STATUSLINE_CACHE_FRESH_AGE_SECONDS;
    let observed_at = rfc3339_from_unix_seconds(cache.observed_at_epoch_seconds);
    // The v2 cache records which account's credential was active when the CLI
    // writer observed these numbers, and the serve gate above only lets a
    // same-account cache through -- so the stamp is the writer's observation,
    // not a serve-time guess. An empty hash (unidentifiable writer) stays
    // absent rather than inventing an identity.
    let account_identifier_hash = (!cache.observed_under_account_identifier_hash.is_empty())
        .then(|| cache.observed_under_account_identifier_hash.clone());
    for window in cache.windows {
        if window.resets_at_epoch_seconds <= now {
            continue;
        }
        let Some(resets_at) = rfc3339_from_unix_seconds(window.resets_at_epoch_seconds) else {
            continue;
        };
        let (name, window_seconds) = match window.name.as_str() {
            "five_hour" => ("session", Some(5 * 60 * 60)),
            "seven_day" => ("weekly", Some(7 * 24 * 60 * 60)),
            _ => continue,
        };
        windows.push(AgentQuotaWindow {
            name: name.to_string(),
            scope: AgentQuotaWindowScope::Account,
            status: if cache_is_stale {
                AgentQuotaWindowStatus::Stale
            } else {
                percent_quota_status(window.used_percent)
            },
            freshness: if cache_is_stale {
                AgentQuotaWindowFreshness::Stale
            } else {
                AgentQuotaWindowFreshness::Fresh
            },
            observed_at: observed_at.clone(),
            model: None,
            account_label: None,
            account_identifier_hash: account_identifier_hash.clone(),
            window_seconds,
            started_at: None,
            resets_at: Some(resets_at),
            quota: None,
            remaining: None,
            used_percent: Some(window.used_percent),
            left_percent: Some(100u8.saturating_sub(window.used_percent)),
            ..Default::default()
        });
    }
    windows
}

fn claude_statusline_context_from_cache(
    cache: ClaudeStatusLineContextWindowCache,
    history: Option<ClaudeStatusLineContextWindowHistory>,
) -> AgentContextStatus {
    let zero_sentinel = claude_statusline_context_is_zero_sentinel(
        cache.active_tokens,
        cache.max_tokens,
        cache.used_percent,
        cache.remaining_tokens,
    );
    let active_tokens = if zero_sentinel {
        None
    } else {
        cache.active_tokens
    };
    let remaining_tokens = if zero_sentinel {
        None
    } else {
        cache.remaining_tokens
    };
    let has_pressure =
        active_tokens.is_some() || cache.used_percent.is_some() || remaining_tokens.is_some();
    let (status, completeness, reason) = if has_pressure {
        (
            AgentContextState::Available,
            AgentContextCompleteness::FullPressure,
            "full_pressure_observed",
        )
    } else if cache.max_tokens.is_some() {
        (
            AgentContextState::Available,
            AgentContextCompleteness::WindowSizeOnly,
            "context_window_size_only",
        )
    } else {
        (
            AgentContextState::Unsupported,
            AgentContextCompleteness::Unavailable,
            "statusline_context_empty",
        )
    };
    AgentContextStatus {
        status,
        active_tokens,
        max_tokens: cache.max_tokens,
        used_percent: cache.used_percent,
        remaining_tokens,
        source: Some("claude_statusline_context_window".to_string()),
        recent_samples: claude_statusline_recent_context_samples(&cache, history),
        observed_at: rfc3339_from_unix_seconds(cache.observed_at_epoch_seconds),
        completeness: Some(completeness),
        reason: Some(reason.to_string()),
        posture: None,
    }
}

fn claude_statusline_recent_context_samples(
    cache: &ClaudeStatusLineContextWindowCache,
    history: Option<ClaudeStatusLineContextWindowHistory>,
) -> Vec<AgentContextPressureSample> {
    let now = current_unix_seconds();
    let mut samples = history.map(|history| history.samples).unwrap_or_default();
    samples.push(ClaudeStatusLineContextWindowSample {
        observed_at_epoch_seconds: cache.observed_at_epoch_seconds,
        active_tokens: cache.active_tokens,
        max_tokens: cache.max_tokens,
        used_percent: cache.used_percent,
        remaining_tokens: cache.remaining_tokens,
    });
    samples.retain(|sample| {
        sample.observed_at_epoch_seconds <= now.saturating_add(60)
            && now.saturating_sub(sample.observed_at_epoch_seconds)
                <= CLAUDE_STATUSLINE_CACHE_MAX_AGE_SECONDS
            && !claude_statusline_context_is_zero_sentinel(
                sample.active_tokens,
                sample.max_tokens,
                sample.used_percent,
                sample.remaining_tokens,
            )
            && (sample.active_tokens.is_some()
                || sample.used_percent.is_some()
                || sample.remaining_tokens.is_some())
    });
    samples.sort_by_key(|sample| sample.observed_at_epoch_seconds);
    samples.dedup_by_key(|sample| sample.observed_at_epoch_seconds);
    if samples.len() > CLAUDE_STATUSLINE_CONTEXT_HISTORY_RESPONSE_MAX_SAMPLES {
        let remove_count = samples.len() - CLAUDE_STATUSLINE_CONTEXT_HISTORY_RESPONSE_MAX_SAMPLES;
        samples.drain(0..remove_count);
    }
    samples
        .into_iter()
        .filter_map(|sample| {
            Some(AgentContextPressureSample {
                at: rfc3339_from_unix_seconds(sample.observed_at_epoch_seconds)?,
                active_tokens: sample.active_tokens,
                max_tokens: sample.max_tokens,
                used_percent: sample.used_percent,
                remaining_tokens: sample.remaining_tokens,
            })
        })
        .collect()
}

fn claude_statusline_context_is_zero_sentinel(
    active_tokens: Option<u64>,
    max_tokens: Option<u64>,
    used_percent: Option<u8>,
    remaining_tokens: Option<u64>,
) -> bool {
    let remaining_is_unreported = match (max_tokens, remaining_tokens) {
        (Some(_), None) => true,
        (Some(max), Some(remaining)) => remaining == max,
        _ => false,
    };
    used_percent.is_none() && matches!(active_tokens, None | Some(0)) && remaining_is_unreported
}

fn claude_statusline_context_unavailable(
    reason: &str,
    observed_at: Option<String>,
) -> AgentContextStatus {
    AgentContextStatus {
        status: AgentContextState::Unsupported,
        active_tokens: None,
        max_tokens: None,
        used_percent: None,
        remaining_tokens: None,
        source: Some("claude_statusline_context_window".to_string()),
        recent_samples: Vec::new(),
        observed_at,
        completeness: Some(AgentContextCompleteness::Unavailable),
        reason: Some(reason.to_string()),
        posture: None,
    }
}

fn current_unix_seconds() -> u64 {
    OffsetDateTime::now_utc().unix_timestamp().max(0) as u64
}

fn rfc3339_from_unix_seconds(seconds: u64) -> Option<String> {
    let timestamp = i64::try_from(seconds).ok()?;
    OffsetDateTime::from_unix_timestamp(timestamp)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

fn percent_quota_status(used_percent: u8) -> AgentQuotaWindowStatus {
    if used_percent >= 100 {
        AgentQuotaWindowStatus::Exhausted
    } else if used_percent >= 90 {
        AgentQuotaWindowStatus::NearLimit
    } else {
        AgentQuotaWindowStatus::Ok
    }
}

fn collect_pi_status(captured_at: String, expires_at: String) -> AgentStatusSnapshot {
    if !executable_exists("pi") && !home_path(".pi").exists() {
        return not_installed_snapshot(SourceKind::Pi, "pi", captured_at, expires_at);
    }
    let mut snapshot = base_snapshot(
        SourceKind::Pi,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::CommandProbe,
        captured_at,
        expires_at,
    );
    snapshot.account = Some(AgentAccountStatus {
        login_state: AgentLoginState::Unknown,
        provider: None,
        auth_method: None,
        email: read_pi_safe_auth_metadata()
            .and_then(|metadata| first_json_string(&metadata, &["email"])),
        account_id: None,
        organization_id: None,
        organization_label: None,
        plan_type: None,
        subscription_product: None,
        billing_channel: None,
        subscription_period_start: None,
        subscription_period_end: None,
        account_identifier_hash: None,
        organization_identifier_hash: None,
        credential_fingerprint_hash: None,
        billing_identity_evidence: None,
        billing_identity_confidence: AgentStatusConfidence::Unknown,
        confidence: AgentStatusConfidence::Low,
    });
    let settings = read_pi_agent_settings();
    let auth = read_pi_agent_auth();
    let list_models = if settings.is_none() {
        Some(run_command_capture(
            "pi",
            &["--list-models"],
            COMMAND_TIMEOUT,
        ))
    } else {
        None
    };
    snapshot.model = Some(collect_pi_model_status(
        settings.as_ref(),
        list_models.as_ref(),
        auth.as_ref(),
    ));
    if settings.is_some() {
        snapshot.collection_method = AgentStatusCollectionMethod::ConfigFile;
        snapshot.diagnostics.push(AgentStatusDiagnostic::source(
            "pi_agent_settings_detected",
            AgentDiagnosticSeverity::Info,
            "Pi model route read from ~/.pi/agent/settings.json.",
        ));
    }
    snapshot.quota_windows = vec![unsupported_quota_window("usage")];
    snapshot.context = Some(AgentContextStatus {
        status: AgentContextState::Unsupported,
        active_tokens: None,
        max_tokens: None,
        used_percent: None,
        remaining_tokens: None,
        source: Some("pi_cli_v1".to_string()),
        recent_samples: Vec::new(),
        observed_at: None,
        completeness: Some(AgentContextCompleteness::Unavailable),
        reason: Some("pi_active_context_not_collected".to_string()),
        posture: None,
    });
    snapshot.capabilities = vec![
        supported_capability(
            "model_list",
            "Collected from ~/.pi/agent/settings.json enabledModels, falling back to pi --list-models.",
        ),
        unsupported_capability(
            "account_plan",
            "Pi does not publish display-safe plan metadata in v1.",
        ),
        unsupported_capability(
            "quota_windows",
            "Pi does not publish display-safe quota-window metadata in v1.",
        ),
        unsupported_capability(
            "active_context",
            "Pi does not publish active context metadata in v1.",
        ),
    ];
    append_pi_route_plan_observations(&mut snapshot);
    append_current_plan_observation(&mut snapshot);
    snapshot
}

fn append_current_plan_observation(snapshot: &mut AgentStatusSnapshot) {
    let Some(account) = &snapshot.account else {
        return;
    };
    if account.subscription_product.is_none()
        && account.plan_type.is_none()
        && account.account_id.is_none()
        && account.account_identifier_hash.is_none()
        && account.organization_identifier_hash.is_none()
        && account.credential_fingerprint_hash.is_none()
        && account.email.is_none()
        && account.organization_id.is_none()
        && account.organization_label.is_none()
    {
        return;
    }
    snapshot.plan_observations.push(AgentStatusPlanObservation {
        observed_at: Some(snapshot.captured_at.clone()),
        evidence_method: Some(collection_method_key(&snapshot.collection_method).to_string()),
        source_session_id: None,
        provider: account.provider.clone(),
        billing_provider: account.provider.clone(),
        model_provider: snapshot
            .model
            .as_ref()
            .and_then(|model| model.provider.clone()),
        billing_channel: account.billing_channel.clone(),
        auth_mode: account.auth_method.clone(),
        gateway_provider: None,
        subscription_product: account.subscription_product.clone(),
        plan_type: account.plan_type.clone(),
        account_label: account.email.clone(),
        account_id: account.account_id.clone(),
        organization_label: account.organization_label.clone(),
        organization_id: account.organization_id.clone(),
        account_identifier_hash: account.account_identifier_hash.clone(),
        organization_identifier_hash: account.organization_identifier_hash.clone(),
        credential_fingerprint_hash: account.credential_fingerprint_hash.clone(),
        billing_identity_evidence: account.billing_identity_evidence.clone(),
        billing_identity_confidence: account.billing_identity_confidence.clone(),
        confidence: account.confidence.clone(),
        is_current: Some(
            account.login_state == AgentLoginState::SignedIn
                && matches!(
                    account.confidence,
                    AgentStatusConfidence::High | AgentStatusConfidence::Medium
                ),
        ),
    });
}

fn append_pi_route_plan_observations(snapshot: &mut AgentStatusSnapshot) {
    let Some(model) = &snapshot.model else {
        return;
    };
    let observed_at = snapshot.captured_at.clone();
    for detail in model.available_model_details.iter().take(20) {
        if detail.subscription_product.is_none()
            && detail.account_identifier_hash.is_none()
            && detail.organization_identifier_hash.is_none()
            && detail.credential_fingerprint_hash.is_none()
        {
            continue;
        }
        snapshot.plan_observations.push(AgentStatusPlanObservation {
            observed_at: Some(observed_at.clone()),
            evidence_method: Some("pi_route_metadata".to_string()),
            source_session_id: None,
            provider: detail.provider.clone(),
            billing_provider: detail.billing_provider.clone(),
            model_provider: detail.model_provider.clone(),
            billing_channel: detail.billing_channel.clone(),
            auth_mode: detail.auth_mode.clone(),
            gateway_provider: detail.gateway_provider.clone(),
            subscription_product: detail.subscription_product.clone(),
            plan_type: None,
            account_label: None,
            account_id: None,
            organization_label: None,
            organization_id: None,
            account_identifier_hash: detail.account_identifier_hash.clone(),
            organization_identifier_hash: detail.organization_identifier_hash.clone(),
            credential_fingerprint_hash: detail.credential_fingerprint_hash.clone(),
            billing_identity_evidence: detail.billing_identity_evidence.clone(),
            billing_identity_confidence: detail.billing_identity_confidence.clone(),
            confidence: if detail.billing_identity_confidence == AgentStatusConfidence::Unknown {
                AgentStatusConfidence::Low
            } else {
                detail.billing_identity_confidence.clone()
            },
            is_current: Some(true),
        });
    }
}

fn append_codex_workspace_observations(snapshot: &mut AgentStatusSnapshot) {
    let Some(credentials) = read_codex_auth_credentials() else {
        return;
    };
    let Some(token) = credentials.id_token.as_deref() else {
        return;
    };
    let Some(observations) = codex_workspace_observations_from_id_token(
        token,
        &snapshot.captured_at,
        snapshot
            .model
            .as_ref()
            .and_then(|model| model.provider.clone())
            .as_deref(),
    ) else {
        return;
    };
    if observations.is_empty() {
        return;
    }
    snapshot.plan_observations.extend(observations);
    snapshot.diagnostics.push(AgentStatusDiagnostic::source(
        "codex_workspace_memberships_detected",
        AgentDiagnosticSeverity::Info,
        "Codex ID token includes additional OpenAI workspaces; plan is shown only when the token explicitly claims it.",
    ));
}

fn collection_method_key(method: &AgentStatusCollectionMethod) -> &'static str {
    match method {
        AgentStatusCollectionMethod::AppServer => "app_server",
        AgentStatusCollectionMethod::CliJson => "cli_json",
        AgentStatusCollectionMethod::CliText => "cli_text",
        AgentStatusCollectionMethod::ConfigFile => "config_file",
        AgentStatusCollectionMethod::StatusLine => "status_line",
        AgentStatusCollectionMethod::CommandProbe => "command_probe",
        AgentStatusCollectionMethod::ManualFallback => "manual_fallback",
        AgentStatusCollectionMethod::Unsupported => "unsupported",
    }
}

fn billing_identity_evidence_for(
    account_hash: &Option<String>,
    organization_hash: &Option<String>,
    credential_hash: &Option<String>,
) -> Option<String> {
    if credential_hash.is_some() {
        Some("credential_fingerprint".to_string())
    } else if account_hash.is_some() {
        Some("provider_account_id".to_string())
    } else if organization_hash.is_some() {
        Some("organization_identifier".to_string())
    } else {
        None
    }
}

fn base_snapshot(
    source: SourceKind,
    status: AgentStatusState,
    collection_method: AgentStatusCollectionMethod,
    captured_at: String,
    expires_at: String,
) -> AgentStatusSnapshot {
    AgentStatusSnapshot {
        source,
        status,
        collection_method,
        captured_at,
        expires_at,
        account: None,
        model: None,
        quota_windows: Vec::new(),
        credit_balances: Vec::new(),
        context: None,
        capabilities: Vec::new(),
        plan_observations: Vec::new(),
        diagnostics: Vec::new(),
        runtime_defaults: None,
    }
}

fn not_installed_snapshot(
    source: SourceKind,
    binary: &str,
    captured_at: String,
    expires_at: String,
) -> AgentStatusSnapshot {
    let mut snapshot = base_snapshot(
        source,
        AgentStatusState::NotInstalled,
        AgentStatusCollectionMethod::CommandProbe,
        captured_at,
        expires_at,
    );
    snapshot.account = Some(AgentAccountStatus {
        login_state: AgentLoginState::Unsupported,
        provider: None,
        auth_method: None,
        email: None,
        account_id: None,
        organization_id: None,
        organization_label: None,
        plan_type: None,
        subscription_product: None,
        billing_channel: None,
        subscription_period_start: None,
        subscription_period_end: None,
        account_identifier_hash: None,
        organization_identifier_hash: None,
        credential_fingerprint_hash: None,
        billing_identity_evidence: None,
        billing_identity_confidence: AgentStatusConfidence::Unknown,
        confidence: AgentStatusConfidence::High,
    });
    snapshot.diagnostics.push(AgentStatusDiagnostic::source(
        "agent_cli_not_found",
        AgentDiagnosticSeverity::Warning,
        format!("{binary} was not found on PATH or in known local metadata."),
    ));
    snapshot
}

fn parse_codex_account_text(text: &str) -> Option<AgentAccountStatus> {
    let lower = text.to_ascii_lowercase();
    if lower.contains("not logged in")
        || lower.contains("not signed in")
        || lower.contains("logged out")
        || lower.contains("sign in")
    {
        return Some(AgentAccountStatus {
            login_state: AgentLoginState::SignedOut,
            provider: Some("openai".to_string()),
            auth_method: Some("oauth".to_string()),
            email: None,
            account_id: None,
            organization_id: None,
            organization_label: None,
            plan_type: None,
            subscription_product: None,
            billing_channel: None,
            subscription_period_start: None,
            subscription_period_end: None,
            account_identifier_hash: None,
            organization_identifier_hash: None,
            credential_fingerprint_hash: None,
            billing_identity_evidence: None,
            billing_identity_confidence: AgentStatusConfidence::Unknown,
            confidence: AgentStatusConfidence::Medium,
        });
    }
    let email = extract_email(text);
    let plan_type = extract_plan_type(text, &["plus", "pro", "team", "enterprise", "free"]);
    if email.is_none()
        && plan_type.is_none()
        && !lower.contains("logged in")
        && !lower.contains("signed in")
    {
        return None;
    }
    Some(AgentAccountStatus {
        login_state: AgentLoginState::SignedIn,
        provider: Some("openai".to_string()),
        auth_method: Some("oauth".to_string()),
        email,
        account_id: None,
        organization_id: None,
        organization_label: None,
        plan_type: plan_type.clone(),
        subscription_product: plan_type.map(|plan| format!("chatgpt_{plan}")),
        billing_channel: Some("subscription".to_string()),
        subscription_period_start: None,
        subscription_period_end: None,
        account_identifier_hash: None,
        organization_identifier_hash: None,
        credential_fingerprint_hash: None,
        billing_identity_evidence: None,
        billing_identity_confidence: AgentStatusConfidence::Unknown,
        confidence: AgentStatusConfidence::Medium,
    })
}

fn read_codex_auth_account() -> Option<AgentAccountStatus> {
    let credentials = read_codex_auth_credentials()?;
    let token = credentials.id_token.as_deref()?;
    parse_codex_id_token_account(token)
}

fn read_codex_auth_credentials() -> Option<CodexAuthCredentials> {
    let body = fs::read_to_string(codex_auth_path()).ok()?;
    let json: Value = serde_json::from_str(&body).ok()?;
    let access_token = json
        .get("tokens")
        .and_then(|tokens| tokens.get("access_token"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string);
    let id_token = json
        .get("tokens")
        .and_then(|tokens| tokens.get("id_token"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string);
    let account_id = first_json_string(&json, &["account_id", "chatgpt_account_id"])
        .or_else(|| {
            json.get("tokens")
                .and_then(|tokens| first_json_string(tokens, &["account_id", "chatgpt_account_id"]))
        })
        .or_else(|| id_token.as_deref().and_then(codex_account_id_from_id_token));
    if access_token.is_none() && id_token.is_none() {
        return None;
    }
    Some(CodexAuthCredentials {
        access_token,
        id_token,
        account_id,
    })
}

fn codex_account_id_from_id_token(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: Value = serde_json::from_slice(&decoded).ok()?;
    let auth_claim = claims.get("https://api.openai.com/auth");
    auth_claim
        .and_then(|value| first_json_string(value, &["chatgpt_account_id", "chatgpt_user_id"]))
        .or_else(|| first_json_string(&claims, &["chatgpt_account_id", "chatgpt_user_id"]))
}

fn parse_codex_id_token_account(token: &str) -> Option<AgentAccountStatus> {
    let payload = token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: Value = serde_json::from_slice(&decoded).ok()?;
    let auth_claim = claims.get("https://api.openai.com/auth");
    let plan_type = auth_claim
        .and_then(|value| first_json_string(value, &["chatgpt_plan_type"]))
        .map(normalize_plan_type)
        .filter(|value| !value.is_empty());
    let account_id = auth_claim
        .and_then(|value| {
            first_json_string(value, &["chatgpt_account_id", "chatgpt_user_id", "user_id"])
        })
        .or_else(|| first_json_string(&claims, &["sub"]));
    let organization = auth_claim.and_then(default_codex_organization);
    let email = first_json_string(&claims, &["email"]);
    // The same claim object that carries `chatgpt_plan_type` also carries the
    // real subscription period. Read it here rather than deriving one: the
    // backend contract is "reported or absent".
    let subscription_period_start = auth_claim.and_then(|value| {
        subscription_period_timestamp(value, "chatgpt_subscription_active_start")
    });
    let subscription_period_end = auth_claim.and_then(|value| {
        subscription_period_timestamp(value, "chatgpt_subscription_active_until")
    });
    // Deliberately unchanged: a period with no plan, account, email, or
    // organization is not a useful account row, so it does not by itself
    // resurrect one.
    if plan_type.is_none() && account_id.is_none() && email.is_none() && organization.is_none() {
        return None;
    }
    let organization_id = organization.as_ref().and_then(|org| org.id.clone());
    let organization_label = organization.and_then(|org| org.label);
    let account_identifier_hash = account_id
        .as_deref()
        .and_then(|value| billing_identity_hash("openai", "account", value));
    let organization_identifier_hash = organization_id
        .as_deref()
        .and_then(|value| billing_identity_hash("openai", "organization", value));
    let billing_identity_evidence = billing_identity_evidence_for(
        &account_identifier_hash,
        &organization_identifier_hash,
        &None,
    );
    Some(AgentAccountStatus {
        login_state: AgentLoginState::SignedIn,
        provider: Some("openai".to_string()),
        auth_method: Some("oauth".to_string()),
        email,
        account_id,
        organization_id,
        organization_label,
        plan_type: plan_type.clone(),
        subscription_product: plan_type.map(chatgpt_subscription_product),
        billing_channel: Some("subscription".to_string()),
        subscription_period_start,
        subscription_period_end,
        account_identifier_hash,
        organization_identifier_hash,
        credential_fingerprint_hash: None,
        billing_identity_evidence,
        billing_identity_confidence: AgentStatusConfidence::High,
        confidence: AgentStatusConfidence::High,
    })
}

/// Sanity window for a reported subscription-period boundary, in Unix seconds.
///
/// The claim's wire type is not guaranteed, so a millisecond-encoded value is a
/// real possibility. It lands far outside this window and therefore reads as
/// "not reported" rather than as a year-57000 renewal date.
const SUBSCRIPTION_PERIOD_MIN_UNIX_SECONDS: i64 = 1_420_070_400; // 2015-01-01T00:00:00Z
const SUBSCRIPTION_PERIOD_MAX_UNIX_SECONDS: i64 = 4_102_444_800; // 2100-01-01T00:00:00Z

/// Read one subscription-period boundary from a provider auth claim.
///
/// Format-tolerant by design: epoch seconds (number or numeric string) and
/// RFC3339 strings are both accepted and normalized to an offset-bearing UTC
/// RFC3339 timestamp. Anything unparseable, or outside the sanity window,
/// returns `None`. No failure path substitutes `now`.
fn subscription_period_timestamp(value: &Value, key: &str) -> Option<String> {
    let parsed = OffsetDateTime::parse(&json_timestamp_rfc3339(value, &[key])?, &Rfc3339).ok()?;
    if !(SUBSCRIPTION_PERIOD_MIN_UNIX_SECONDS..=SUBSCRIPTION_PERIOD_MAX_UNIX_SECONDS)
        .contains(&parsed.unix_timestamp())
    {
        return None;
    }
    // An offset-bearing input is converted, not reinterpreted: the instant is
    // preserved and every emitted boundary reads as UTC.
    parsed.to_offset(UtcOffset::UTC).format(&Rfc3339).ok()
}

fn collect_codex_app_server_usage() -> Result<CodexUsageProbe, String> {
    let value = call_codex_app_server_rate_limits()?;
    Ok(CodexUsageProbe {
        quota_windows: codex_app_server_quota_windows(&value),
        credit_balances: codex_app_server_credit_balances(&value),
    })
}

fn call_codex_app_server_rate_limits() -> Result<Value, String> {
    let Some(program_path) = crate::command_env::executable_path("codex") else {
        return Err("Codex CLI was not found for app-server rate-limit collection.".to_string());
    };
    let mut command = Command::new(program_path);
    command
        .args(["app-server", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(path_env) = crate::command_env::path_env() {
        command.env("PATH", path_env);
    }
    let mut child = command
        .spawn()
        .map_err(|_| "Codex app-server could not be started.".to_string())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "Codex app-server stdout was unavailable.".to_string())?;
    let (sender, receiver) = mpsc::channel::<Value>();
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(value) = serde_json::from_str::<Value>(line) {
                let _ = sender.send(value);
            }
        }
    });

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "Codex app-server stdin was unavailable.".to_string())?;
    let initialize = serde_json::json!({
        "method": "initialize",
        "id": 1,
        "params": {
            "clientInfo": {
                "name": "ottto_local_platform",
                "title": "Ottto Local Platform",
                "version": compiled_release_version()
            },
            "capabilities": {
                "experimentalApi": true,
                "optOutNotificationMethods": ["account/rateLimits/updated"]
            }
        }
    });
    let initialized = serde_json::json!({"method": "initialized"});
    let read = serde_json::json!({
        "method": "account/rateLimits/read",
        "id": "ottto_rate_limits"
    });
    let write_result = (|| -> Result<(), String> {
        for message in [initialize, initialized, read] {
            serde_json::to_writer(&mut stdin, &message)
                .map_err(|_| "Codex app-server request serialization failed.".to_string())?;
            stdin
                .write_all(b"\n")
                .map_err(|_| "Codex app-server request write failed.".to_string())?;
        }
        stdin
            .flush()
            .map_err(|_| "Codex app-server request flush failed.".to_string())
    })();
    if let Err(message) = write_result {
        drop(stdin);
        let _ = child.kill();
        let _ = child.wait();
        return Err(message);
    }

    let start = Instant::now();
    while start.elapsed() < CODEX_APP_SERVER_TIMEOUT {
        let remaining = CODEX_APP_SERVER_TIMEOUT
            .checked_sub(start.elapsed())
            .unwrap_or_else(|| Duration::from_millis(0));
        match receiver.recv_timeout(remaining.min(Duration::from_millis(250))) {
            Ok(message) => {
                if message.get("id").and_then(Value::as_str) == Some("ottto_rate_limits") {
                    drop(stdin);
                    let _ = child.kill();
                    let _ = child.wait();
                    if message.get("error").is_some() {
                        return Err("Codex app-server rate-limit read failed.".to_string());
                    }
                    return message.get("result").cloned().ok_or_else(|| {
                        "Codex app-server rate-limit read returned no result.".to_string()
                    });
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
    Err("Codex app-server rate-limit read timed out.".to_string())
}

fn codex_app_server_quota_windows(value: &Value) -> Vec<AgentQuotaWindow> {
    let Some(rate_limit) = codex_app_server_rate_limit_snapshot(value) else {
        return Vec::new();
    };
    let mut windows = Vec::new();
    if let Some(primary) = rate_limit.get("primary") {
        if let Some(window) = codex_app_server_quota_window("session", primary) {
            windows.push(window);
        }
    }
    if let Some(secondary) = rate_limit.get("secondary") {
        if let Some(window) = codex_app_server_quota_window("weekly", secondary) {
            windows.push(window);
        }
    }
    windows
}

fn codex_app_server_rate_limit_snapshot(value: &Value) -> Option<&Value> {
    let by_limit_id = value.get("rateLimitsByLimitId").and_then(Value::as_object);
    by_limit_id
        .and_then(|map| map.get("codex"))
        .filter(|snapshot| codex_rate_limit_snapshot_has_usage(snapshot))
        .or_else(|| {
            value
                .get("rateLimits")
                .filter(|snapshot| codex_rate_limit_snapshot_has_usage(snapshot))
        })
        .or_else(|| {
            by_limit_id.and_then(|map| {
                map.values()
                    .find(|snapshot| codex_rate_limit_snapshot_has_usage(snapshot))
            })
        })
}

fn codex_rate_limit_snapshot_has_usage(value: &Value) -> bool {
    value.get("primary").is_some()
        || value.get("secondary").is_some()
        || value.get("credits").is_some()
}

fn codex_app_server_quota_window(name: &str, value: &Value) -> Option<AgentQuotaWindow> {
    let used_percent = json_u8(value, &["usedPercent", "used_percent"]);
    let left_percent = used_percent.map(|used| 100_u8.saturating_sub(used));
    let resets_at = json_timestamp_rfc3339(value, &["resetsAt", "resets_at"]);
    let window_seconds = json_u64(value, &["windowDurationMins", "window_duration_mins"])
        .map(|minutes| minutes.saturating_mul(60));
    let started_at = resets_at
        .as_deref()
        .zip(window_seconds)
        .and_then(|(reset, seconds)| rfc3339_minus_seconds(reset, seconds));
    if used_percent.is_none() && resets_at.is_none() && window_seconds.is_none() {
        return None;
    }
    Some(AgentQuotaWindow {
        name: name.to_string(),
        scope: AgentQuotaWindowScope::Account,
        status: match left_percent {
            Some(0) => AgentQuotaWindowStatus::Exhausted,
            Some(value) if value <= 20 => AgentQuotaWindowStatus::NearLimit,
            Some(_) => AgentQuotaWindowStatus::Ok,
            None => AgentQuotaWindowStatus::Unknown,
        },
        freshness: AgentQuotaWindowFreshness::Fresh,
        model: None,
        account_label: None,
        window_seconds,
        started_at,
        resets_at,
        quota: None,
        remaining: None,
        used_percent,
        left_percent,
        ..Default::default()
    })
}

fn codex_app_server_credit_balances(value: &Value) -> Vec<AgentCreditBalance> {
    let mut balances = Vec::new();
    if let Some(rate_limit) = codex_app_server_rate_limit_snapshot(value) {
        if let Some(credits) = rate_limit.get("credits") {
            if let Some(balance) = codex_credit_balance_from_credits_snapshot(credits, rate_limit) {
                balances.push(balance);
            }
        }
    }
    if let Some(reset_credits) = value.get("rateLimitResetCredits") {
        if let Some(remaining) = json_u64(reset_credits, &["availableCount", "available_count"]) {
            balances.push(AgentCreditBalance {
                name: "reset_bank".to_string(),
                status: if remaining == 0 {
                    AgentCreditBalanceStatus::Exhausted
                } else {
                    AgentCreditBalanceStatus::Ok
                },
                freshness: AgentQuotaWindowFreshness::Fresh,
                unit: AgentCreditBalanceUnit::Resets,
                account_label: None,
                remaining: Some(remaining),
                used: None,
                quota: None,
                unlimited: Some(false),
                updated_at: None,
                ..Default::default()
            });
        }
    }
    balances
}

fn codex_credit_balance_from_credits_snapshot(
    credits: &Value,
    container: &Value,
) -> Option<AgentCreditBalance> {
    let remaining = json_u64(credits, &["balance", "remaining", "credits"]);
    let unlimited = json_bool(credits, &["unlimited"]);
    let has_credits = json_bool(credits, &["hasCredits", "has_credits"]).unwrap_or(false);
    // `credits` sits beside `primary`/`secondary` on the rate-limit snapshot; the
    // sibling `spend_control_reached`, `rate_limit_reached_type`, and `limit_id`
    // fields (e.g. `limitId: "codex"`) live on that container. Mirror the OAuth
    // wham/usage path so both collectors carry the spend-cap contract.
    let spend_control_reached =
        json_bool(container, &["spend_control_reached", "spendControlReached"]);
    let rate_limit_reached_type = first_json_string(
        container,
        &["rate_limit_reached_type", "rateLimitReachedType"],
    );
    let limit_id = first_json_string(container, &["limit_id", "limitId"]);
    if remaining.is_none()
        && unlimited.is_none()
        && !has_credits
        && spend_control_reached != Some(true)
    {
        return None;
    }
    // A reached spend control means the account is spend-capped even if a nominal
    // credit figure remains, so treat it as exhausted regardless of the balance.
    let status = if spend_control_reached == Some(true) {
        AgentCreditBalanceStatus::Exhausted
    } else {
        codex_credit_balance_status(remaining, unlimited, has_credits)
    };
    Some(AgentCreditBalance {
        name: "credits".to_string(),
        status,
        freshness: AgentQuotaWindowFreshness::Fresh,
        unit: AgentCreditBalanceUnit::Credits,
        account_label: None,
        remaining,
        used: None,
        quota: None,
        unlimited,
        updated_at: None,
        spend_control_reached,
        rate_limit_reached_type,
        limit_id,
        ..Default::default()
    })
}

fn codex_credit_balance_status(
    remaining: Option<u64>,
    unlimited: Option<bool>,
    has_credits: bool,
) -> AgentCreditBalanceStatus {
    if unlimited == Some(true) {
        AgentCreditBalanceStatus::Unlimited
    } else if remaining == Some(0) {
        AgentCreditBalanceStatus::Exhausted
    } else if remaining.is_some_and(|value| value > 0 && value <= 5) {
        AgentCreditBalanceStatus::Low
    } else if remaining.is_some() || has_credits {
        AgentCreditBalanceStatus::Ok
    } else {
        AgentCreditBalanceStatus::Unknown
    }
}

fn legacy_codex_oauth_usage_enabled() -> bool {
    std::env::var("OTTTO_CODEX_LEGACY_OAUTH_USAGE")
        .map(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn collect_codex_oauth_usage() -> Result<CodexUsageProbe, String> {
    let credentials = read_codex_auth_credentials()
        .ok_or_else(|| "Codex OAuth credentials were not found.".to_string())?;
    let access_token = credentials
        .access_token
        .ok_or_else(|| "Codex OAuth access token was not available.".to_string())?;
    let authorization = format!("Bearer {access_token}");
    let mut request = ureq::get("https://chatgpt.com/backend-api/wham/usage")
        .set("Accept", "application/json")
        .set("Authorization", &authorization)
        .timeout(COMMAND_TIMEOUT);
    if let Some(account_id) = credentials.account_id.as_deref() {
        request = request.set("ChatGPT-Account-Id", account_id);
    }
    let value: Value = request
        .call()
        .map_err(codex_usage_probe_error)?
        .into_json()
        .map_err(|_| "Codex usage endpoint returned an unreadable response.".to_string())?;
    Ok(CodexUsageProbe {
        quota_windows: codex_usage_quota_windows(&value),
        credit_balances: codex_usage_credit_balances(&value),
    })
}

fn codex_usage_probe_error(error: ureq::Error) -> String {
    match error {
        ureq::Error::Status(status, _) if status == 401 || status == 403 => {
            "Codex usage endpoint rejected the local OAuth session.".to_string()
        }
        ureq::Error::Status(status, _) => {
            format!("Codex usage endpoint returned HTTP {status}.")
        }
        ureq::Error::Transport(_) => "Codex usage endpoint was unreachable.".to_string(),
    }
}

fn codex_usage_quota_windows(value: &Value) -> Vec<AgentQuotaWindow> {
    // The wham/usage payload historically nested the windows under `rate_limit`
    // with `primary_window`/`secondary_window` keys. Since OpenAI's 2026-07-12
    // change the fields can arrive top-level as `primary`/`secondary` (with the
    // primary window now weekly and secondary null). Locate the container either
    // way, then accept both the legacy and current key names.
    let container = value
        .get("rate_limit")
        .filter(|value| value.is_object())
        .unwrap_or(value);
    let mut windows = Vec::new();
    if let Some(primary) = container
        .get("primary_window")
        .or_else(|| container.get("primary"))
    {
        if let Some(window) = codex_usage_quota_window(0, primary) {
            windows.push(window);
        }
    }
    if let Some(secondary) = container
        .get("secondary_window")
        .or_else(|| container.get("secondary"))
    {
        if let Some(window) = codex_usage_quota_window(1, secondary) {
            windows.push(window);
        }
    }
    windows
}

/// Window duration in seconds, reading `*_seconds` first and falling back to the
/// minutes-denominated fields (`limit_window_minutes`/`window_minutes`) that the
/// current wham/usage payload reports.
fn codex_usage_window_seconds(value: &Value) -> Option<u64> {
    json_u64(value, &["limit_window_seconds", "window_seconds"]).or_else(|| {
        json_u64(value, &["limit_window_minutes", "window_minutes"])
            .and_then(|minutes| minutes.checked_mul(60))
    })
}

/// Name a Codex usage window from its duration when known rather than purely by
/// position: OpenAI's 2026-07 change made the primary window weekly, so the old
/// "primary is the session window" assumption no longer holds. Windows lasting
/// roughly five days or more are weekly; roughly four to six hours are session
/// windows; anything else keeps the positional fallback (index 0 -> session,
/// otherwise weekly).
fn codex_usage_window_name(window_seconds: Option<u64>, position: usize) -> &'static str {
    if let Some(seconds) = window_seconds {
        if seconds >= 5 * 86_400 {
            return "weekly";
        }
        if (4 * 3_600..=6 * 3_600).contains(&seconds) {
            return "session";
        }
    }
    if position == 0 {
        "session"
    } else {
        "weekly"
    }
}

fn codex_usage_quota_window(position: usize, value: &Value) -> Option<AgentQuotaWindow> {
    let used_percent = json_u8(value, &["used_percent", "usedPercent"]);
    let left_percent = used_percent.map(|used| 100_u8.saturating_sub(used));
    let resets_at = json_timestamp_rfc3339(value, &["reset_at", "resets_at", "resetAt"]);
    let window_seconds = codex_usage_window_seconds(value);
    let started_at = resets_at
        .as_deref()
        .zip(window_seconds)
        .and_then(|(reset, seconds)| rfc3339_minus_seconds(reset, seconds));
    if used_percent.is_none() && resets_at.is_none() && window_seconds.is_none() {
        return None;
    }
    Some(AgentQuotaWindow {
        name: codex_usage_window_name(window_seconds, position).to_string(),
        scope: AgentQuotaWindowScope::Account,
        status: match left_percent {
            Some(0) => AgentQuotaWindowStatus::Exhausted,
            Some(value) if value <= 20 => AgentQuotaWindowStatus::NearLimit,
            Some(_) => AgentQuotaWindowStatus::Ok,
            None => AgentQuotaWindowStatus::Unknown,
        },
        freshness: AgentQuotaWindowFreshness::Fresh,
        model: None,
        account_label: None,
        window_seconds,
        started_at,
        resets_at,
        quota: None,
        remaining: None,
        used_percent,
        left_percent,
        ..Default::default()
    })
}

fn codex_usage_credit_balances(value: &Value) -> Vec<AgentCreditBalance> {
    // `credits` sits beside `primary`/`secondary`; the sibling `spend_control_reached`,
    // `rate_limit_reached_type`, and `limit_id` fields live on the same container.
    let container = value
        .get("rate_limit")
        .filter(|value| value.is_object())
        .unwrap_or(value);
    let Some(credits) = container.get("credits") else {
        return Vec::new();
    };
    let remaining = json_u64(credits, &["balance", "remaining", "credits"]);
    let unlimited = json_bool(credits, &["unlimited"]);
    let has_credits = json_bool(credits, &["has_credits", "hasCredits"]).unwrap_or(false);
    let spend_control_reached =
        json_bool(container, &["spend_control_reached", "spendControlReached"]);
    let rate_limit_reached_type = first_json_string(
        container,
        &["rate_limit_reached_type", "rateLimitReachedType"],
    );
    let limit_id = first_json_string(container, &["limit_id", "limitId"]);
    if remaining.is_none()
        && unlimited.is_none()
        && !has_credits
        && spend_control_reached != Some(true)
    {
        return Vec::new();
    }
    // A reached spend control means the account is spend-capped even if a nominal
    // credit figure remains, so treat it as exhausted regardless of the balance.
    let status = if spend_control_reached == Some(true) {
        AgentCreditBalanceStatus::Exhausted
    } else {
        codex_credit_balance_status(remaining, unlimited, has_credits)
    };
    vec![AgentCreditBalance {
        name: "credits".to_string(),
        status,
        freshness: AgentQuotaWindowFreshness::Fresh,
        unit: AgentCreditBalanceUnit::Credits,
        account_label: None,
        remaining,
        used: None,
        quota: None,
        unlimited,
        updated_at: None,
        spend_control_reached,
        rate_limit_reached_type,
        limit_id,
        ..Default::default()
    }]
}

#[derive(Debug, Clone)]
struct CodexOrganization {
    id: Option<String>,
    label: Option<String>,
    is_default: bool,
    plan_type: Option<String>,
}

fn default_codex_organization(value: &Value) -> Option<CodexOrganization> {
    let organizations = codex_organizations(value);
    organizations
        .iter()
        .find(|organization| organization.is_default)
        .cloned()
        .or_else(|| organizations.into_iter().next())
}

fn codex_workspace_observations_from_id_token(
    token: &str,
    observed_at: &str,
    model_provider: Option<&str>,
) -> Option<Vec<AgentStatusPlanObservation>> {
    let payload = token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: Value = serde_json::from_slice(&decoded).ok()?;
    let auth_claim = claims.get("https://api.openai.com/auth")?;
    let email = first_json_string(&claims, &["email"]);
    let account_id = first_json_string(
        auth_claim,
        &["chatgpt_account_id", "chatgpt_user_id", "user_id"],
    )
    .or_else(|| first_json_string(&claims, &["sub"]));
    let account_identifier_hash = account_id
        .as_deref()
        .and_then(|value| billing_identity_hash("openai", "account", value));
    Some(
        codex_organizations(auth_claim)
            .into_iter()
            .filter(|organization| !organization.is_default)
            .filter(|organization| organization.id.is_some() || organization.label.is_some())
            .map(|organization| {
                let subscription_product = organization
                    .plan_type
                    .clone()
                    .map(chatgpt_subscription_product);
                let billing_channel = if subscription_product.is_some() {
                    "subscription"
                } else {
                    "workspace_membership"
                };
                let subscription_identity_hash = if subscription_product.is_some() {
                    account_identifier_hash.clone()
                } else {
                    None
                };
                let account_id = if subscription_product.is_some() {
                    account_id.clone()
                } else {
                    None
                };
                let organization_id = if subscription_product.is_some() {
                    organization.id
                } else {
                    None
                };
                AgentStatusPlanObservation {
                    observed_at: Some(observed_at.to_string()),
                    evidence_method: Some("id_token_organization".to_string()),
                    source_session_id: None,
                    provider: Some("openai".to_string()),
                    billing_provider: Some("openai".to_string()),
                    model_provider: model_provider.map(ToString::to_string),
                    billing_channel: Some(billing_channel.to_string()),
                    auth_mode: Some("oauth".to_string()),
                    gateway_provider: None,
                    subscription_product,
                    plan_type: organization.plan_type,
                    account_label: email.clone(),
                    account_id,
                    organization_label: organization.label,
                    organization_id,
                    // Do not emit organization hashes for plan-unknown
                    // memberships. The local app can show the workspace label,
                    // while backend redaction stores the observation without
                    // materializing a misleading subscription profile.
                    account_identifier_hash: subscription_identity_hash.clone(),
                    organization_identifier_hash: None,
                    credential_fingerprint_hash: None,
                    billing_identity_evidence: subscription_identity_hash
                        .as_ref()
                        .map(|_| "provider_account_id".to_string()),
                    billing_identity_confidence: if subscription_identity_hash.is_some() {
                        AgentStatusConfidence::High
                    } else {
                        AgentStatusConfidence::Unknown
                    },
                    confidence: if billing_channel == "subscription" {
                        AgentStatusConfidence::High
                    } else {
                        AgentStatusConfidence::Medium
                    },
                    is_current: Some(false),
                }
            })
            .collect(),
    )
}

fn codex_organizations(value: &Value) -> Vec<CodexOrganization> {
    let Some(organizations) = value.get("organizations").and_then(Value::as_array) else {
        return Vec::new();
    };
    organizations
        .iter()
        .filter_map(|organization| {
            let id = first_json_string(organization, &["id"]);
            let label = first_json_string(organization, &["title", "name", "label"]);
            if id.is_none() && label.is_none() {
                return None;
            }
            Some(CodexOrganization {
                id,
                label,
                is_default: organization
                    .get("is_default")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                plan_type: first_json_string(
                    organization,
                    &[
                        "chatgpt_plan_type",
                        "plan_type",
                        "planType",
                        "subscription_plan",
                        "subscriptionPlan",
                        "tier",
                    ],
                )
                .map(normalize_plan_type)
                .filter(|value| !value.is_empty()),
            })
        })
        .collect()
}

fn merge_codex_accounts(
    existing: Option<AgentAccountStatus>,
    auth_account: AgentAccountStatus,
) -> AgentAccountStatus {
    let Some(existing) = existing else {
        return auth_account;
    };
    AgentAccountStatus {
        login_state: auth_account.login_state,
        provider: auth_account.provider.or(existing.provider),
        auth_method: auth_account.auth_method.or(existing.auth_method),
        email: auth_account.email.or(existing.email),
        account_id: auth_account.account_id.or(existing.account_id),
        organization_id: auth_account.organization_id.or(existing.organization_id),
        organization_label: auth_account
            .organization_label
            .or(existing.organization_label),
        plan_type: auth_account.plan_type.or(existing.plan_type),
        subscription_product: auth_account
            .subscription_product
            .or(existing.subscription_product),
        billing_channel: auth_account.billing_channel.or(existing.billing_channel),
        // This struct is rebuilt field-by-field, so a field added upstream and
        // not carried here is dropped silently on every merged Codex account.
        subscription_period_start: auth_account
            .subscription_period_start
            .or(existing.subscription_period_start),
        subscription_period_end: auth_account
            .subscription_period_end
            .or(existing.subscription_period_end),
        account_identifier_hash: auth_account
            .account_identifier_hash
            .or(existing.account_identifier_hash),
        organization_identifier_hash: auth_account
            .organization_identifier_hash
            .or(existing.organization_identifier_hash),
        credential_fingerprint_hash: auth_account
            .credential_fingerprint_hash
            .or(existing.credential_fingerprint_hash),
        billing_identity_evidence: auth_account
            .billing_identity_evidence
            .or(existing.billing_identity_evidence),
        billing_identity_confidence: if auth_account.billing_identity_confidence
            != AgentStatusConfidence::Unknown
        {
            auth_account.billing_identity_confidence
        } else {
            existing.billing_identity_confidence
        },
        confidence: auth_account.confidence,
    }
}

fn normalize_plan_type(value: String) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace(|c: char| c.is_whitespace() || c == '-' || c == '/', "_")
}

fn chatgpt_subscription_product(plan_type: String) -> String {
    if plan_type.starts_with("chatgpt_") {
        plan_type
    } else {
        format!("chatgpt_{plan_type}")
    }
}

fn parse_claude_auth_json(value: &Value) -> AgentAccountStatus {
    let login_state = match first_json_string(
        value,
        &["status", "state", "login_state", "logged_in", "loggedIn"],
    )
    .as_deref()
    {
        Some("authenticated") | Some("signed_in") | Some("logged_in") | Some("true") => {
            AgentLoginState::SignedIn
        }
        Some("signed_out") | Some("logged_out") | Some("unauthenticated") | Some("false") => {
            AgentLoginState::SignedOut
        }
        _ => {
            if first_json_string(value, &["email", "account_email", "accountEmail"]).is_some() {
                AgentLoginState::SignedIn
            } else {
                AgentLoginState::Unknown
            }
        }
    };
    let plan_type = first_json_string(
        value,
        &[
            "subscription_type",
            "subscriptionType",
            "plan_type",
            "planType",
            "plan",
            "tier",
        ],
    )
    .map(normalize_plan_type);
    let api_provider = first_json_string(value, &["api_provider", "apiProvider"]);
    let organization_id = first_json_string(
        value,
        &["organization_id", "organizationId", "org_id", "orgId"],
    )
    .or_else(|| nested_json_string(value, &["organization", "org"], &["id"]));
    let organization_label = first_json_string(
        value,
        &[
            "organization_label",
            "organizationLabel",
            "organization_name",
            "organizationName",
            "org_name",
            "orgName",
        ],
    )
    .or_else(|| nested_json_string(value, &["organization", "org"], &["name", "label"]));
    let account_id = first_json_string(value, &["account_id", "accountId", "user_id", "userId"]);
    let account_identifier_hash = account_id
        .as_deref()
        .and_then(|value| billing_identity_hash("anthropic", "account", value));
    let organization_identifier_hash = organization_id
        .as_deref()
        .and_then(|value| billing_identity_hash("anthropic", "organization", value));
    let billing_identity_evidence = billing_identity_evidence_for(
        &account_identifier_hash,
        &organization_identifier_hash,
        &None,
    );
    AgentAccountStatus {
        login_state,
        provider: Some("anthropic".to_string()),
        auth_method: first_json_string(
            value,
            &[
                "auth_method",
                "authMethod",
                "auth_type",
                "authType",
                "method",
            ],
        )
        .or(Some("oauth".to_string())),
        email: first_json_string(value, &["email", "account_email", "accountEmail"]),
        account_id,
        organization_id,
        organization_label,
        plan_type: plan_type.clone(),
        subscription_product: plan_type.clone().map(|plan| {
            if plan.starts_with("claude_") {
                plan
            } else {
                format!("claude_{plan}")
            }
        }),
        billing_channel: Some(claude_billing_channel(
            api_provider.as_deref(),
            plan_type.as_deref(),
        )),
        subscription_period_start: None,
        subscription_period_end: None,
        account_identifier_hash,
        organization_identifier_hash,
        credential_fingerprint_hash: None,
        billing_identity_evidence,
        billing_identity_confidence: AgentStatusConfidence::High,
        confidence: AgentStatusConfidence::High,
    }
}

fn claude_billing_channel(api_provider: Option<&str>, plan_type: Option<&str>) -> String {
    match api_provider.map(|value| normalize_plan_type(value.to_string())) {
        Some(provider) if provider.contains("bedrock") => "amazon_bedrock".to_string(),
        Some(provider) if provider.contains("vertex") => "google_vertex".to_string(),
        Some(provider) if provider.contains("first_party") || provider.contains("firstparty") => {
            "subscription".to_string()
        }
        Some(provider) if provider.contains("anthropic") && plan_type.is_none() => {
            "direct_api".to_string()
        }
        _ if plan_type.is_some() => "subscription".to_string(),
        _ => "subscription".to_string(),
    }
}

/// Display-safe account metadata Claude Code itself persists to
/// `~/.claude.json` under `oauthAccount` after each profile refresh. The file
/// holds no tokens or secrets; it is the same class of local app state as the
/// Claude Desktop config and statusLine caches this collector already reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ClaudeCliOauthAccount {
    account_uuid: Option<String>,
    email_address: Option<String>,
    organization_uuid: Option<String>,
    organization_type: Option<String>,
    seat_tier: Option<String>,
    organization_rate_limit_tier: Option<String>,
    user_rate_limit_tier: Option<String>,
}

fn read_claude_cli_oauth_account(path: &Path) -> Option<ClaudeCliOauthAccount> {
    let raw = std::fs::read_to_string(path).ok()?;
    let value: Value = serde_json::from_str(&raw).ok()?;
    parse_claude_cli_oauth_account(&value)
}

fn parse_claude_cli_oauth_account(value: &Value) -> Option<ClaudeCliOauthAccount> {
    let account = value.get("oauthAccount")?;
    if !account.is_object() {
        return None;
    }
    let field = |key: &str| {
        account
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_string)
    };
    Some(ClaudeCliOauthAccount {
        account_uuid: field("accountUuid"),
        email_address: field("emailAddress"),
        organization_uuid: field("organizationUuid"),
        organization_type: field("organizationType"),
        seat_tier: field("seatTier"),
        organization_rate_limit_tier: field("organizationRateLimitTier"),
        user_rate_limit_tier: field("userRateLimitTier"),
    })
}

/// Identity guard shared by every consumer of `~/.claude.json` account
/// metadata: the file can lag behind `claude auth status` after an account
/// switch, so metadata is only trusted when neither the email nor the
/// organization contradicts the auth-status identity. A field absent on
/// either side is not a mismatch — only two present-and-different values
/// refuse.
fn claude_cli_oauth_identity_mismatch(
    account: &AgentAccountStatus,
    oauth: &ClaudeCliOauthAccount,
) -> bool {
    let mismatch = |ours: &Option<String>, theirs: &Option<String>| match (ours, theirs) {
        (Some(a), Some(b)) => !a.eq_ignore_ascii_case(b.trim()),
        _ => false,
    };
    mismatch(&account.email, &oauth.email_address)
        || mismatch(&account.organization_id, &oauth.organization_uuid)
}

/// Stamp the Claude account identity from the local Claude Code account
/// metadata (`~/.claude.json` `oauthAccount`) onto the auth-status account.
/// `claude auth status --json` names the organization but not the account
/// uuid, so without this the CLI plan observation reaches the backend with an
/// organization hash only while the quota windows from the very same
/// `oauthAccount` carry the account hash — plan and quota evidence then
/// resolve at different ranks and cannot deterministically converge.
///
/// Same identity guard as the seat/tier refinements above: stale metadata
/// from a different account must never be stamped, and a present auth-status
/// account id that disagrees with `accountUuid` also refuses. Uses the exact
/// `billing_identity_hash("anthropic", "account", …)` the quota path stamps,
/// never a second hashing implementation.
fn stamp_claude_cli_account_identity(
    account: &mut AgentAccountStatus,
    oauth: &ClaudeCliOauthAccount,
) -> bool {
    if claude_cli_oauth_identity_mismatch(account, oauth) {
        return false;
    }
    let Some(account_uuid) = oauth.account_uuid.as_deref() else {
        return false;
    };
    if let Some(existing) = account.account_id.as_deref() {
        if !existing.eq_ignore_ascii_case(account_uuid.trim()) {
            return false;
        }
    }
    let Some(account_identifier_hash) = billing_identity_hash("anthropic", "account", account_uuid)
    else {
        return false;
    };
    if account.account_id.is_none() {
        account.account_id = Some(account_uuid.to_string());
    }
    if account.account_identifier_hash.is_none() {
        account.account_identifier_hash = Some(account_identifier_hash);
    }
    account.billing_identity_evidence = billing_identity_evidence_for(
        &account.account_identifier_hash,
        &account.organization_identifier_hash,
        &account.credential_fingerprint_hash,
    );
    true
}

/// Refine a generic Claude `team` plan into `team_premium` / `team_standard`
/// when the local Claude Code account metadata carries an explicit seat-tier
/// signal. Mirrors the Claude Max 5x/20x rule: explicit collector evidence
/// only, never a guess — an unrecognized or absent signal leaves the generic
/// `team` plan untouched. Premium detection accepts either a literal
/// `seatTier` value or the `*_max_5x` rate-limit tier, which is the signal
/// Claude Code's own internals use to identify a premium Team seat.
fn refine_claude_team_seat_plan(
    account: &mut AgentAccountStatus,
    oauth: &ClaudeCliOauthAccount,
) -> Option<&'static str> {
    if account.plan_type.as_deref() != Some("team") {
        return None;
    }
    // Identity guard: `~/.claude.json` can lag behind `claude auth status`
    // after an account switch. Refuse to mix metadata across accounts.
    if claude_cli_oauth_identity_mismatch(account, oauth) {
        return None;
    }
    if let Some(organization_type) = oauth.organization_type.as_deref() {
        if normalize_plan_type(organization_type.to_string()) != "claude_team" {
            return None;
        }
    }
    let seat_tier = oauth
        .seat_tier
        .clone()
        .map(normalize_plan_type)
        .unwrap_or_default();
    // Only the user-level rate-limit tier can prove a per-seat tier: Team
    // orgs mix Standard and Premium seats, so the org-wide tier says nothing
    // about THIS seat.
    let rate_limit_tier = oauth
        .user_rate_limit_tier
        .clone()
        .map(normalize_plan_type)
        .unwrap_or_default();
    let seat_plan = if seat_tier.contains("premium") || rate_limit_tier.ends_with("max_5x") {
        "team_premium"
    } else if seat_tier.contains("standard") {
        "team_standard"
    } else {
        return None;
    };
    account.plan_type = Some(seat_plan.to_string());
    account.subscription_product = Some(format!("claude_{seat_plan}"));
    Some(seat_plan)
}

/// Refine a generic Claude `max` plan into `max_5x` / `max_20x` when the local
/// Claude Code account metadata carries an explicit rate-limit tier. Mirrors
/// `refine_claude_team_seat_plan`: explicit collector evidence only, never a
/// guess — `claude auth status` reports bare `max` for BOTH Max tiers, so an
/// absent or unrecognized signal leaves the generic plan untouched (the
/// backend prices that as the conservative lower bound). Max is an individual
/// plan, so the organization-level rate-limit tier speaks for the account;
/// the user-level tier is accepted as a same-shaped fallback.
fn refine_claude_max_rate_limit_plan(
    account: &mut AgentAccountStatus,
    oauth: &ClaudeCliOauthAccount,
) -> Option<&'static str> {
    if account.plan_type.as_deref() != Some("max") {
        return None;
    }
    // Identity guard: `~/.claude.json` can lag behind `claude auth status`
    // after an account switch. Refuse to mix metadata across accounts.
    if claude_cli_oauth_identity_mismatch(account, oauth) {
        return None;
    }
    if let Some(organization_type) = oauth.organization_type.as_deref() {
        if normalize_plan_type(organization_type.to_string()) != "claude_max" {
            return None;
        }
    }
    let tier_signal = |value: &Option<String>| -> Option<&'static str> {
        let normalized = value.clone().map(normalize_plan_type)?;
        if normalized.ends_with("max_5x") {
            Some("max_5x")
        } else if normalized.ends_with("max_20x") {
            Some("max_20x")
        } else {
            None
        }
    };
    let refined = tier_signal(&oauth.organization_rate_limit_tier)
        .or_else(|| tier_signal(&oauth.user_rate_limit_tier))?;
    account.plan_type = Some(refined.to_string());
    account.subscription_product = Some(format!("claude_{refined}"));
    Some(refined)
}

fn parse_codex_text_model(text: &str) -> Option<AgentModelStatus> {
    let model = text.lines().find_map(|line| {
        let lower = line.to_ascii_lowercase();
        if lower.contains("model") {
            line.split(':')
                .nth(1)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| {
                    value
                        .trim_matches(|c: char| c == '"' || c == '\'' || c == '`')
                        .to_string()
                })
        } else {
            None
        }
    });
    model.map(|active_model| AgentModelStatus {
        active_model: Some(active_model.clone()),
        default_model: Some(active_model),
        provider: Some("openai".to_string()),
        available_models: Vec::new(),
        available_model_details: Vec::new(),
        context_window_tokens: None,
    })
}

fn parse_codex_text_quota_windows(text: &str) -> Vec<AgentQuotaWindow> {
    let mut windows = Vec::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if !lower.contains("quota") && !lower.contains("limit") && !lower.contains("remaining") {
            continue;
        }
        let left_percent = extract_percent_before(&lower, &["left", "remaining"]);
        let used_percent = extract_percent_before(&lower, &["used"]);
        if left_percent.is_some() || used_percent.is_some() {
            let left =
                left_percent.or_else(|| used_percent.map(|used| 100_u8.saturating_sub(used)));
            windows.push(AgentQuotaWindow {
                name: "usage".to_string(),
                scope: AgentQuotaWindowScope::Source,
                status: match left {
                    Some(0) => AgentQuotaWindowStatus::Exhausted,
                    Some(value) if value <= 20 => AgentQuotaWindowStatus::NearLimit,
                    Some(_) => AgentQuotaWindowStatus::Ok,
                    None => AgentQuotaWindowStatus::Unknown,
                },
                freshness: AgentQuotaWindowFreshness::Fresh,
                model: None,
                account_label: None,
                window_seconds: None,
                started_at: None,
                resets_at: None,
                quota: None,
                remaining: None,
                used_percent,
                left_percent: left,
                ..Default::default()
            });
        }
    }
    windows
}

fn parse_codex_text_context(text: &str) -> Option<AgentContextStatus> {
    let context_line = text
        .lines()
        .map(str::to_ascii_lowercase)
        .find(|line| line.contains("context"))?;
    let used_percent = extract_percent_before(&context_line, &["used", "context"]);
    Some(AgentContextStatus {
        status: AgentContextState::Available,
        active_tokens: None,
        max_tokens: None,
        used_percent,
        remaining_tokens: None,
        source: Some("codex_status_text".to_string()),
        recent_samples: Vec::new(),
        observed_at: None,
        completeness: Some(AgentContextCompleteness::FullPressure),
        reason: Some("codex_status_text_observed".to_string()),
        posture: None,
    })
}

fn collect_model_status_from_output(output: &CommandOutput, provider: &str) -> AgentModelStatus {
    let mut models = BTreeSet::new();
    if output.command_found && output.success {
        if let Ok(json) = serde_json::from_str::<Value>(&output.stdout) {
            collect_model_names_from_json(&json, &mut models);
        } else {
            for line in output.stdout.lines() {
                let trimmed = line.trim().trim_matches(|c: char| {
                    c == '-' || c == '*' || c == '"' || c == '\'' || c == '`' || c.is_whitespace()
                });
                if looks_like_model_name(trimmed) {
                    models.insert(trimmed.to_string());
                }
            }
        }
    }
    AgentModelStatus {
        active_model: models.iter().next().cloned(),
        default_model: models.iter().next().cloned(),
        provider: Some(provider.to_string()),
        available_models: models.into_iter().take(MAX_AVAILABLE_MODELS).collect(),
        available_model_details: Vec::new(),
        context_window_tokens: None,
    }
}

fn collect_codex_model_status_from_output(output: &CommandOutput) -> AgentModelStatus {
    if !output.command_found || !output.success {
        return collect_model_status_from_output(output, "openai");
    }
    let Ok(json) = serde_json::from_str::<Value>(&output.stdout) else {
        return collect_model_status_from_output(output, "openai");
    };
    let Some(models) = json.get("models").and_then(Value::as_array) else {
        return collect_model_status_from_output(output, "openai");
    };

    let mut details = Vec::new();
    let mut seen = BTreeSet::new();
    for model in models {
        let Some(model) = model.as_object() else {
            continue;
        };
        let id = ["slug", "id", "model", "name"]
            .iter()
            .find_map(|key| model.get(*key).and_then(Value::as_str))
            .map(str::trim)
            .filter(|value| looks_like_model_name(value) && looks_like_safe_model_id(value));
        let Some(id) = id else {
            continue;
        };
        if id.chars().any(char::is_whitespace) || !seen.insert(id.to_string()) {
            continue;
        }
        let context_window_tokens = model
            .get("context_window")
            .or_else(|| model.get("max_context_window"))
            .and_then(Value::as_u64);
        let max_output_tokens = model
            .get("max_output_tokens")
            .or_else(|| model.get("max_output"))
            .and_then(Value::as_u64);
        let supports_thinking = model
            .get("supported_reasoning_levels")
            .and_then(Value::as_array)
            .map(|levels| !levels.is_empty())
            .or_else(|| {
                model
                    .get("supports_reasoning_summaries")
                    .and_then(Value::as_bool)
            });
        let supports_images = model
            .get("input_modalities")
            .and_then(Value::as_array)
            .map(|modalities| {
                modalities
                    .iter()
                    .any(|value| value.as_str() == Some("image"))
            })
            .or_else(|| {
                model
                    .get("supports_image_detail_original")
                    .and_then(Value::as_bool)
            });
        details.push(AgentAvailableModelStatus {
            id: id.to_string(),
            provider: Some("openai".to_string()),
            model_provider: Some("openai".to_string()),
            // The bundled-model list identifies the model provider, not the
            // account's actual billing route (subscription, API, or gateway).
            billing_provider: None,
            billing_channel: None,
            auth_mode: None,
            gateway_provider: None,
            subscription_product: None,
            source_category: None,
            account_identifier_hash: None,
            organization_identifier_hash: None,
            credential_fingerprint_hash: None,
            billing_identity_evidence: None,
            billing_identity_confidence: AgentStatusConfidence::Unknown,
            context_window_tokens,
            max_output_tokens,
            supports_thinking,
            supports_images,
        });
        if details.len() >= MAX_AVAILABLE_MODELS {
            break;
        }
    }

    if details.is_empty() {
        return collect_model_status_from_output(output, "openai");
    }
    let default_model = details.first().map(|detail| detail.id.clone());
    let context_window_tokens = details
        .first()
        .and_then(|detail| detail.context_window_tokens);
    AgentModelStatus {
        active_model: default_model.clone(),
        default_model,
        provider: Some("openai".to_string()),
        available_models: details.iter().map(|detail| detail.id.clone()).collect(),
        available_model_details: details,
        context_window_tokens,
    }
}

pub(crate) fn read_pi_smoke_routes() -> Vec<PiModelRoute> {
    if let Some(settings) = read_pi_agent_settings() {
        if let Some(route) = collect_default_pi_smoke_route_from_settings(&settings) {
            return vec![route];
        }
    }
    Vec::new()
}

fn apply_codex_config_model(
    model_status: &mut AgentModelStatus,
    config_model: Option<String>,
    collection_method: &mut AgentStatusCollectionMethod,
) {
    let Some(config_model) = config_model else {
        return;
    };
    let config_model = config_model.trim();
    if config_model.is_empty() {
        return;
    }
    let config_model = config_model.to_string();
    let only_config_available = model_status.available_models.is_empty();
    model_status.active_model = Some(config_model.clone());
    model_status.default_model = Some(config_model.clone());
    if !model_status
        .available_models
        .iter()
        .any(|model| model == &config_model)
    {
        let mut available_models = Vec::with_capacity(model_status.available_models.len() + 1);
        available_models.push(config_model.clone());
        available_models.extend(
            model_status
                .available_models
                .iter()
                .filter(|model| model.trim() != config_model.as_str())
                .take(MAX_AVAILABLE_MODELS.saturating_sub(1))
                .cloned(),
        );
        model_status.available_models = available_models;
    }
    model_status.context_window_tokens = model_status
        .available_model_details
        .iter()
        .find(|detail| detail.id == config_model)
        .and_then(|detail| detail.context_window_tokens);
    if only_config_available && *collection_method == AgentStatusCollectionMethod::CommandProbe {
        *collection_method = AgentStatusCollectionMethod::ConfigFile;
    }
}

fn collect_pi_model_status(
    settings: Option<&Value>,
    list_models: Option<&CommandOutput>,
    auth: Option<&Value>,
) -> AgentModelStatus {
    if let Some(settings) = settings {
        let status = collect_pi_model_status_from_settings(settings, auth);
        if !status.available_models.is_empty() || status.default_model.is_some() {
            return status;
        }
    }
    if let Some(output) = list_models {
        return collect_pi_model_status_from_output(output, auth);
    }
    AgentModelStatus {
        active_model: None,
        default_model: None,
        provider: None,
        available_models: Vec::new(),
        available_model_details: Vec::new(),
        context_window_tokens: None,
    }
}

fn collect_pi_model_status_from_settings(
    settings: &Value,
    auth: Option<&Value>,
) -> AgentModelStatus {
    let default_provider = first_json_string(
        settings,
        &["defaultProvider", "default_provider", "provider"],
    );
    let default_model = first_json_string(settings, &["defaultModel", "default_model", "model"]);
    let default_thinking = first_json_string(
        settings,
        &[
            "defaultThinkingLevel",
            "default_thinking_level",
            "thinkingLevel",
        ],
    );
    let mut routes = Vec::new();
    let mut seen = BTreeSet::new();
    if let Some(enabled_models) = settings
        .get("enabledModels")
        .or_else(|| settings.get("enabled_models"))
    {
        collect_pi_enabled_model_routes(
            enabled_models,
            default_provider.as_deref(),
            default_thinking.as_deref(),
            &mut seen,
            &mut routes,
        );
    }
    if let (Some(provider), Some(model)) = (default_provider.as_deref(), default_model.as_deref()) {
        push_pi_model_route(
            provider,
            model,
            default_thinking.as_deref(),
            &mut seen,
            &mut routes,
        );
    }
    let details: Vec<AgentAvailableModelStatus> = routes
        .iter()
        .map(|route| {
            let identity = pi_identity_hints_for_route(auth, route);
            pi_model_detail_from_route(route, None, None, None, None, Some(&identity))
        })
        .collect();
    let providers: BTreeSet<&str> = details
        .iter()
        .filter_map(|detail| detail.provider.as_deref())
        .collect();
    AgentModelStatus {
        active_model: default_model.clone(),
        default_model,
        provider: match providers.len() {
            0 => default_provider,
            1 => providers
                .iter()
                .next()
                .map(|provider| (*provider).to_string()),
            _ => Some("multi_provider".to_string()),
        },
        available_models: details
            .iter()
            .map(|detail| detail.id.clone())
            .take(MAX_AVAILABLE_MODELS)
            .collect(),
        available_model_details: details.into_iter().take(MAX_AVAILABLE_MODELS).collect(),
        context_window_tokens: None,
    }
}

#[cfg(test)]
fn collect_pi_routes_from_settings(settings: &Value) -> Vec<PiModelRoute> {
    let default_provider = first_json_string(
        settings,
        &["defaultProvider", "default_provider", "provider"],
    );
    let default_model = first_json_string(settings, &["defaultModel", "default_model", "model"]);
    let default_thinking = first_json_string(
        settings,
        &[
            "defaultThinkingLevel",
            "default_thinking_level",
            "thinkingLevel",
        ],
    );
    let mut routes = Vec::new();
    let mut seen = BTreeSet::new();
    if let Some(enabled_models) = settings
        .get("enabledModels")
        .or_else(|| settings.get("enabled_models"))
    {
        collect_pi_enabled_model_routes(
            enabled_models,
            default_provider.as_deref(),
            default_thinking.as_deref(),
            &mut seen,
            &mut routes,
        );
    }
    if let (Some(provider), Some(model)) = (default_provider.as_deref(), default_model.as_deref()) {
        push_pi_model_route(
            provider,
            model,
            default_thinking.as_deref(),
            &mut seen,
            &mut routes,
        );
    }
    routes
}

fn collect_default_pi_smoke_route_from_settings(settings: &Value) -> Option<PiModelRoute> {
    let default_provider = first_json_string(
        settings,
        &["defaultProvider", "default_provider", "provider"],
    );
    let default_model = first_json_string(settings, &["defaultModel", "default_model", "model"]);
    let default_thinking = first_json_string(
        settings,
        &[
            "defaultThinkingLevel",
            "default_thinking_level",
            "thinkingLevel",
        ],
    );
    let provider = default_provider.as_deref()?;
    let model = default_model.as_deref()?;
    PiModelRoute::new(provider, model, default_thinking.as_deref())
}

fn collect_pi_enabled_model_routes(
    value: &Value,
    default_provider: Option<&str>,
    default_thinking: Option<&str>,
    seen: &mut BTreeSet<(Option<String>, String)>,
    routes: &mut Vec<PiModelRoute>,
) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_pi_enabled_model_routes(
                    item,
                    default_provider,
                    default_thinking,
                    seen,
                    routes,
                );
            }
        }
        Value::Object(map) => {
            if let Some(enabled) = map.get("enabled").and_then(Value::as_bool) {
                if !enabled {
                    return;
                }
            }
            let provider = first_json_string(
                value,
                &["provider", "defaultProvider", "provider_id", "providerId"],
            )
            .or_else(|| default_provider.map(ToString::to_string));
            let model = first_json_string(value, &["model", "id", "model_id", "modelId", "name"]);
            if let (Some(provider), Some(model)) = (provider.as_deref(), model.as_deref()) {
                let thinking = first_json_string(
                    value,
                    &["thinkingLevel", "thinking_level", "defaultThinkingLevel"],
                )
                .or_else(|| default_thinking.map(ToString::to_string));
                push_pi_model_route(provider, model, thinking.as_deref(), seen, routes);
                return;
            }
            for nested in map.values() {
                collect_pi_enabled_model_routes(
                    nested,
                    default_provider,
                    default_thinking,
                    seen,
                    routes,
                );
            }
        }
        Value::String(route) => {
            if let Some((provider, model, route_thinking)) =
                parse_pi_route_string(route, default_provider)
            {
                let thinking = route_thinking.as_deref().or(default_thinking);
                push_pi_model_route(&provider, &model, thinking, seen, routes);
            }
        }
        _ => {}
    }
}

fn parse_pi_route_string(
    route: &str,
    default_provider: Option<&str>,
) -> Option<(String, String, Option<String>)> {
    let trimmed = route.trim();
    if trimmed.is_empty() {
        return None;
    }

    let (route_body, thinking_level) = parse_pi_route_thinking_suffix(trimmed);
    for separator in ["/", ":"] {
        if let Some((provider, model)) = route_body.split_once(separator) {
            if looks_like_safe_model_id(model) && !provider.trim().is_empty() {
                return Some((
                    provider.trim().to_string(),
                    model.trim().to_string(),
                    thinking_level,
                ));
            }
        }
    }
    default_provider
        .filter(|_| looks_like_safe_model_id(route_body))
        .map(|provider| (provider.to_string(), route_body.to_string(), thinking_level))
}

fn parse_pi_route_thinking_suffix(route: &str) -> (&str, Option<String>) {
    let Some((body, suffix)) = route.rsplit_once(':') else {
        return (route, None);
    };
    let suffix = suffix.trim();
    if !body.contains('/') || !looks_like_pi_thinking_level(suffix) {
        return (route, None);
    }
    (body.trim(), Some(suffix.to_ascii_lowercase()))
}

fn looks_like_pi_thinking_level(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "none" | "off" | "low" | "medium" | "high" | "xhigh"
    )
}

fn push_pi_model_route(
    provider: &str,
    model: &str,
    thinking_level: Option<&str>,
    seen: &mut BTreeSet<(Option<String>, String)>,
    routes: &mut Vec<PiModelRoute>,
) {
    let Some(route) = PiModelRoute::new(provider, model, thinking_level) else {
        return;
    };
    let key = (Some(route.provider.clone()), route.model.clone());
    if !seen.insert(key) {
        return;
    }
    routes.push(route);
}

fn pi_model_detail_from_route(
    route: &PiModelRoute,
    context_window_tokens: Option<u64>,
    max_output_tokens: Option<u64>,
    supports_thinking: Option<bool>,
    supports_images: Option<bool>,
    billing_identity: Option<&BillingIdentityHints>,
) -> AgentAvailableModelStatus {
    let identity = billing_identity.cloned().unwrap_or_default();
    AgentAvailableModelStatus {
        id: route.model.clone(),
        provider: Some(route.provider.clone()),
        model_provider: route.classification.model_provider.clone(),
        billing_provider: route.classification.billing_provider.clone(),
        billing_channel: route.classification.billing_channel.clone(),
        auth_mode: route.classification.auth_mode.clone(),
        gateway_provider: route.classification.gateway_provider.clone(),
        subscription_product: route.classification.subscription_product.clone(),
        source_category: route.classification.source_category.clone(),
        account_identifier_hash: identity.account_identifier_hash,
        organization_identifier_hash: identity.organization_identifier_hash,
        credential_fingerprint_hash: identity.credential_fingerprint_hash,
        billing_identity_evidence: identity.billing_identity_evidence,
        billing_identity_confidence: identity.billing_identity_confidence,
        context_window_tokens,
        max_output_tokens,
        supports_thinking: supports_thinking.or_else(|| {
            route
                .thinking_level
                .as_deref()
                .map(|value| value != "none" && value != "off")
        }),
        supports_images,
    }
}

fn collect_pi_model_status_from_output(
    output: &CommandOutput,
    auth: Option<&Value>,
) -> AgentModelStatus {
    let mut details = Vec::new();
    let mut seen = BTreeSet::new();
    if output.command_found && output.success {
        let text = command_output_text(output);
        for line in text.lines() {
            let Some(detail) = parse_pi_model_table_line(line, auth) else {
                continue;
            };
            if seen.insert((detail.provider.clone(), detail.id.clone())) {
                details.push(detail);
            }
            if details.len() >= MAX_AVAILABLE_MODELS {
                break;
            }
        }
    }
    let available_models = details.iter().map(|detail| detail.id.clone()).collect();
    let providers: BTreeSet<&str> = details
        .iter()
        .filter_map(|detail| detail.provider.as_deref())
        .collect();
    AgentModelStatus {
        active_model: None,
        default_model: None,
        provider: match providers.len() {
            0 => None,
            1 => providers
                .iter()
                .next()
                .map(|provider| (*provider).to_string()),
            _ => Some("multi_provider".to_string()),
        },
        available_models,
        available_model_details: details,
        context_window_tokens: None,
    }
}

fn parse_pi_model_table_line(
    line: &str,
    auth: Option<&Value>,
) -> Option<AgentAvailableModelStatus> {
    let mut parts = line.split_whitespace();
    let provider = parts.next()?;
    let model = parts.next()?;
    if provider == "provider" || model == "model" {
        return None;
    }
    let context = parts.next();
    let max_output = parts.next();
    let thinking = parts.next();
    let images = parts.next();
    if provider.is_empty() || model.is_empty() || !looks_like_safe_model_id(model) {
        return None;
    }
    let route = PiModelRoute::new(provider, model, None)?;
    let identity = pi_identity_hints_for_route(auth, &route);
    Some(pi_model_detail_from_route(
        &route,
        context.and_then(parse_pi_token_count),
        max_output.and_then(parse_pi_token_count),
        thinking.and_then(parse_yes_no),
        images.and_then(parse_yes_no),
        Some(&identity),
    ))
}

fn command_output_text(output: &CommandOutput) -> String {
    match (
        output.stdout.trim().is_empty(),
        output.stderr.trim().is_empty(),
    ) {
        (true, true) => String::new(),
        (false, true) => output.stdout.clone(),
        (true, false) => output.stderr.clone(),
        (false, false) => format!("{}\n{}", output.stdout, output.stderr),
    }
}

fn parse_yes_no(value: &str) -> Option<bool> {
    match value {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

fn parse_pi_token_count(value: &str) -> Option<u64> {
    let trimmed = value.trim().replace(',', "");
    if trimmed.is_empty() {
        return None;
    }
    let (number, multiplier) = match trimmed.chars().last()? {
        'K' | 'k' => (&trimmed[..trimmed.len() - 1], 1_000_f64),
        'M' | 'm' => (&trimmed[..trimmed.len() - 1], 1_000_000_f64),
        _ => (trimmed.as_str(), 1_f64),
    };
    number
        .parse::<f64>()
        .ok()
        .map(|value| (value * multiplier).round() as u64)
}

fn pi_billing_channel(provider: &str) -> &str {
    match provider {
        "openai-codex" | "anthropic" | "github-copilot" => "subscription",
        "amazon-bedrock" => "amazon_bedrock",
        "google-vertex" => "google_vertex",
        "azure-openai-responses" => "azure_openai",
        "cloudflare-ai-gateway" | "cloudflare-workers-ai" | "vercel-ai-gateway" => "gateway",
        _ => "direct_api",
    }
}

fn pi_route_classification(provider: &str, model: &str) -> PiRouteClassification {
    let provider = normalize_pi_provider(provider);
    let model_key = model.to_ascii_lowercase();
    match provider.as_str() {
        "openai-codex" => PiRouteClassification {
            model_provider: Some("openai".to_string()),
            billing_provider: Some("openai".to_string()),
            billing_channel: Some("subscription".to_string()),
            auth_mode: Some("oauth".to_string()),
            gateway_provider: None,
            subscription_product: Some("chatgpt".to_string()),
            source_category: Some("chatgpt_openai_subscription".to_string()),
        },
        "openai" => PiRouteClassification {
            model_provider: Some("openai".to_string()),
            billing_provider: Some("openai".to_string()),
            billing_channel: Some("direct_api".to_string()),
            auth_mode: Some("api_key".to_string()),
            gateway_provider: None,
            subscription_product: None,
            source_category: Some("openai_api_key".to_string()),
        },
        "google-vertex" => PiRouteClassification {
            model_provider: Some("google".to_string()),
            billing_provider: Some("google".to_string()),
            billing_channel: Some("google_vertex".to_string()),
            auth_mode: Some("service_account".to_string()),
            gateway_provider: None,
            subscription_product: None,
            source_category: Some("google_cloud_vertex".to_string()),
        },
        "google" | "google-gemini" => PiRouteClassification {
            model_provider: Some("google".to_string()),
            billing_provider: Some("google".to_string()),
            billing_channel: Some("direct_api".to_string()),
            auth_mode: Some("api_key".to_string()),
            gateway_provider: None,
            subscription_product: None,
            source_category: Some("google_gemini_api_key".to_string()),
        },
        "amazon-bedrock" | "aws-bedrock" => {
            let model_provider = infer_pi_model_provider_from_model(&model_key)
                .unwrap_or_else(|| "amazon".to_string());
            PiRouteClassification {
                model_provider: Some(model_provider.clone()),
                billing_provider: Some(model_provider),
                billing_channel: Some("amazon_bedrock".to_string()),
                auth_mode: Some("service_account".to_string()),
                gateway_provider: None,
                subscription_product: None,
                source_category: Some("aws_bedrock".to_string()),
            }
        }
        "azure-openai-responses" | "azure-openai" => PiRouteClassification {
            model_provider: Some("openai".to_string()),
            billing_provider: Some("openai".to_string()),
            billing_channel: Some("azure_openai".to_string()),
            auth_mode: Some("api_key".to_string()),
            gateway_provider: None,
            subscription_product: None,
            source_category: Some("azure_openai".to_string()),
        },
        "cloudflare-ai-gateway" | "cloudflare-workers-ai" => {
            gateway_classification("cloudflare", &model_key)
        }
        "openrouter" => gateway_classification("openrouter", &model_key),
        "vercel-ai-gateway" | "vercel_ai_gateway" => {
            gateway_classification("vercel_ai_gateway", &model_key)
        }
        "github-copilot" => PiRouteClassification {
            model_provider: infer_pi_model_provider_from_model(&model_key),
            billing_provider: Some("github".to_string()),
            billing_channel: Some("subscription".to_string()),
            auth_mode: Some("oauth".to_string()),
            gateway_provider: None,
            subscription_product: Some("github_copilot".to_string()),
            source_category: Some("unknown".to_string()),
        },
        "anthropic" | "claude" | "claude-code" => PiRouteClassification {
            model_provider: Some("anthropic".to_string()),
            billing_provider: Some("anthropic".to_string()),
            billing_channel: Some("subscription".to_string()),
            auth_mode: Some("oauth".to_string()),
            gateway_provider: None,
            subscription_product: Some("claude".to_string()),
            source_category: Some("unknown".to_string()),
        },
        other => PiRouteClassification {
            model_provider: infer_pi_model_provider_from_model(&model_key),
            billing_provider: Some(other.to_string()),
            billing_channel: Some(pi_billing_channel(other).to_string()),
            auth_mode: Some("api_key".to_string()),
            gateway_provider: None,
            subscription_product: None,
            source_category: Some("unknown".to_string()),
        },
    }
}

fn gateway_classification(gateway_provider: &str, model_key: &str) -> PiRouteClassification {
    PiRouteClassification {
        model_provider: infer_pi_model_provider_from_model(model_key),
        billing_provider: Some(gateway_provider.to_string()),
        billing_channel: Some("gateway".to_string()),
        auth_mode: Some("api_key".to_string()),
        gateway_provider: Some(gateway_provider.to_string()),
        subscription_product: None,
        source_category: Some("gateway".to_string()),
    }
}

fn normalize_pi_provider(provider: &str) -> String {
    provider
        .trim()
        .to_ascii_lowercase()
        .replace('_', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("-")
}

fn infer_pi_model_provider_from_model(model_key: &str) -> Option<String> {
    let model_key = model_key.trim().to_ascii_lowercase();
    if model_key.is_empty() {
        return None;
    }
    if model_key.contains("anthropic.") || model_key.contains("claude") {
        return Some("anthropic".to_string());
    }
    if model_key.starts_with("openai.")
        || model_key.starts_with("gpt-")
        || model_key.starts_with("o1")
        || model_key.starts_with("o3")
        || model_key.starts_with("o4")
    {
        return Some("openai".to_string());
    }
    if model_key.starts_with("google.")
        || model_key.starts_with("gemini")
        || model_key.contains(".gemini")
    {
        return Some("google".to_string());
    }
    if model_key.starts_with("meta.") || model_key.contains("llama") {
        return Some("meta".to_string());
    }
    if model_key.starts_with("mistral.") || model_key.contains("mistral") {
        return Some("mistral".to_string());
    }
    if model_key.starts_with("xai.") || model_key.contains("grok") {
        return Some("xai".to_string());
    }
    if let Some((prefix, _)) = model_key.split_once('.') {
        if !matches!(prefix, "global" | "us" | "eu" | "apac") {
            return Some(prefix.to_string());
        }
    }
    None
}

fn collect_model_names_from_json(value: &Value, models: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                if matches!(key.as_str(), "id" | "model" | "name" | "slug") {
                    if let Some(model) =
                        nested.as_str().filter(|value| looks_like_model_name(value))
                    {
                        models.insert(model.to_string());
                    }
                }
                collect_model_names_from_json(nested, models);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_model_names_from_json(item, models);
            }
        }
        Value::String(value) if looks_like_model_name(value) => {
            models.insert(value.clone());
        }
        _ => {}
    }
}

fn looks_like_model_name(value: &str) -> bool {
    let value = value.trim();
    if value.len() < 2 || value.len() > 128 || value.contains('/') || value.contains('\\') {
        return false;
    }
    if is_codex_automatic_review_model_label(value) {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    lower.contains("gpt")
        || lower.contains("claude")
        || lower.contains("gemini")
        || lower.contains("o3")
        || lower.contains("o4")
        || lower.contains("o5")
        || lower.contains("model")
}

fn is_codex_automatic_review_model_label(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let tokens = lower
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    tokens.contains(&"automatic")
        && tokens.contains(&"approval")
        && tokens.contains(&"review")
        && tokens.contains(&"codex")
}

fn looks_like_safe_model_id(value: &str) -> bool {
    let value = value.trim();
    if value.len() < 2 || value.len() > 128 || value.contains('\\') {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    !lower.contains("/users/")
        && !lower.contains("/home/")
        && !lower.contains("/.codex")
        && !lower.contains("/.claude")
        && !lower.contains("/.pi/")
}

fn read_codex_config_model() -> Option<String> {
    let body = fs::read_to_string(codex_config_path()).ok()?;
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || !trimmed.contains('=') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key != "model" && key != "default_model" {
            continue;
        }
        let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
        if looks_like_model_name(value) {
            return Some(value.to_string());
        }
    }
    None
}

fn read_pi_safe_auth_metadata() -> Option<Value> {
    for path in [
        pi_agent_auth_path(),
        home_path(".pi/auth.json"),
        home_path(".pi/profile.json"),
        home_path(".pi/config.json"),
    ] {
        if let Ok(body) = fs::read_to_string(path) {
            if let Ok(json) = serde_json::from_str::<Value>(&body) {
                return Some(strip_secret_json(json));
            }
        }
    }
    None
}

pub(crate) fn read_pi_agent_auth() -> Option<Value> {
    let body = fs::read_to_string(pi_agent_auth_path()).ok()?;
    serde_json::from_str::<Value>(&body).ok()
}

fn read_pi_agent_settings() -> Option<Value> {
    let body = fs::read_to_string(pi_agent_settings_path()).ok()?;
    serde_json::from_str::<Value>(&body)
        .ok()
        .map(strip_secret_json)
}

fn pi_agent_dir() -> PathBuf {
    if let Ok(value) = std::env::var("PI_CODING_AGENT_DIR") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            if let Some(relative) = trimmed.strip_prefix("~/") {
                return home_path(relative);
            }
            return PathBuf::from(trimmed);
        }
    }
    home_path(".pi/agent")
}

fn pi_agent_auth_path() -> PathBuf {
    pi_agent_dir().join("auth.json")
}

fn pi_agent_settings_path() -> PathBuf {
    pi_agent_dir().join("settings.json")
}

fn pi_auth_entry<'a>(auth: &'a Value, provider: &str) -> Option<&'a Value> {
    let Value::Object(map) = auth else {
        return None;
    };
    let provider_lower = provider.trim().to_ascii_lowercase();
    let mut aliases = vec![provider_lower.clone(), provider_lower.replace('-', "_")];
    aliases.push(
        match provider_lower.as_str() {
            "openai-codex" | "openai_codex" => "openai",
            "google-vertex" | "google_vertex" | "vertex" => "google",
            "anthropic-api" | "anthropic_api" => "anthropic",
            other => other,
        }
        .to_string(),
    );
    aliases.iter().find_map(|alias| map.get(alias.as_str()))
}

fn jwt_claims(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice(&decoded).ok()
}

fn openai_codex_account_id_from_auth_entry(entry: &Value) -> Option<String> {
    first_json_string(
        entry,
        &[
            "accountId",
            "account_id",
            "chatgpt_account_id",
            "chatgptAccountId",
        ],
    )
    .or_else(|| {
        for key in [
            "accessToken",
            "access_token",
            "idToken",
            "id_token",
            "token",
        ] {
            let token = first_json_string(entry, &[key])?;
            let claims = jwt_claims(&token)?;
            let auth_claim = claims.get("https://api.openai.com/auth");
            if let Some(account_id) = auth_claim.and_then(|value| {
                first_json_string(value, &["chatgpt_account_id", "chatgpt_user_id", "user_id"])
            }) {
                return Some(account_id);
            }
            if let Some(subject) = first_json_string(&claims, &["sub"]) {
                return Some(subject);
            }
        }
        None
    })
}

pub(crate) fn pi_identity_hints_for_route(
    auth: Option<&Value>,
    route: &PiModelRoute,
) -> BillingIdentityHints {
    let Some(entry) = auth.and_then(|auth| pi_auth_entry(auth, &route.provider)) else {
        return BillingIdentityHints::default();
    };
    let provider_for_hash = route
        .classification
        .billing_provider
        .as_deref()
        .unwrap_or(route.provider.as_str());
    let auth_type = first_json_string(entry, &["type", "auth_type", "authType", "auth_method"])
        .map(normalize_plan_type);

    let mut account_identifier_hash = None;
    let mut organization_identifier_hash = None;
    let mut credential_fingerprint_hash = None;
    let mut evidence = None;

    if route.provider.eq_ignore_ascii_case("openai-codex")
        || route.provider.eq_ignore_ascii_case("openai_codex")
    {
        account_identifier_hash = openai_codex_account_id_from_auth_entry(entry)
            .as_deref()
            .and_then(|value| billing_identity_hash("openai", "account", value));
    }

    if matches!(
        route.classification.billing_channel.as_deref(),
        Some("google_vertex")
    ) {
        organization_identifier_hash = first_json_string(
            entry,
            &[
                "projectId",
                "project_id",
                "quota_project_id",
                "quotaProjectId",
                "billing_project",
            ],
        )
        .as_deref()
        .and_then(|value| billing_identity_hash("google_vertex", "project", value));
        credential_fingerprint_hash = first_json_string(
            entry,
            &[
                "client_email",
                "clientEmail",
                "service_account",
                "serviceAccount",
            ],
        )
        .as_deref()
        .and_then(|value| billing_identity_hash("google_vertex", "service_account", value));
        if organization_identifier_hash.is_some() {
            evidence = Some("cloud_project_id".to_string());
        }
    }

    if route.classification.auth_mode.as_deref() == Some("api_key")
        || auth_type.as_deref() == Some("api_key")
    {
        credential_fingerprint_hash = first_json_string(
            entry,
            &[
                "key",
                "api_key",
                "apiKey",
                "access_key",
                "accessKey",
                "secret_access_key",
                "secretAccessKey",
            ],
        )
        .as_deref()
        .and_then(|value| billing_identity_hash(provider_for_hash, "credential", value));
    }

    if evidence.is_none() {
        evidence = billing_identity_evidence_for(
            &account_identifier_hash,
            &organization_identifier_hash,
            &credential_fingerprint_hash,
        );
    }
    let billing_identity_confidence = if evidence.is_some() {
        AgentStatusConfidence::High
    } else {
        AgentStatusConfidence::Unknown
    };
    BillingIdentityHints {
        account_identifier_hash,
        organization_identifier_hash,
        credential_fingerprint_hash,
        billing_identity_evidence: evidence,
        billing_identity_confidence,
    }
}

fn strip_secret_json(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter_map(|(key, nested)| {
                    let lower = key.to_ascii_lowercase();
                    if lower.contains("token")
                        || lower.contains("secret")
                        || lower.contains("password")
                        || lower.contains("key")
                        || lower.contains("cookie")
                    {
                        None
                    } else {
                        Some((key, strip_secret_json(nested)))
                    }
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(strip_secret_json).collect()),
        other => other,
    }
}

fn first_json_string(value: &Value, keys: &[&str]) -> Option<String> {
    match value {
        Value::Object(map) => {
            for key in keys {
                if let Some(nested) = map.get(*key) {
                    match nested {
                        Value::String(value) if !value.trim().is_empty() => {
                            return Some(value.trim().to_string())
                        }
                        Value::Bool(value) => return Some(value.to_string()),
                        Value::Number(value) => return Some(value.to_string()),
                        _ => {}
                    }
                }
            }
            for nested in map.values() {
                if let Some(value) = first_json_string(nested, keys) {
                    return Some(value);
                }
            }
            None
        }
        Value::Array(items) => items.iter().find_map(|item| first_json_string(item, keys)),
        _ => None,
    }
}

fn json_u64(value: &Value, keys: &[&str]) -> Option<u64> {
    for key in keys {
        let Some(nested) = value.get(*key) else {
            continue;
        };
        if let Some(number) = nested.as_u64() {
            return Some(number);
        }
        if let Some(number) = nested.as_i64().and_then(|value| u64::try_from(value).ok()) {
            return Some(number);
        }
        if let Some(number) = nested.as_f64() {
            if number.is_finite() && number >= 0.0 {
                return Some(number.round() as u64);
            }
        }
        if let Some(text) = nested.as_str() {
            if let Ok(number) = text.trim().parse::<u64>() {
                return Some(number);
            }
            if let Ok(number) = text.trim().parse::<f64>() {
                if number.is_finite() && number >= 0.0 {
                    return Some(number.round() as u64);
                }
            }
        }
    }
    None
}

fn json_u8(value: &Value, keys: &[&str]) -> Option<u8> {
    json_u64(value, keys).map(|value| value.min(100) as u8)
}

fn json_bool(value: &Value, keys: &[&str]) -> Option<bool> {
    for key in keys {
        let Some(nested) = value.get(*key) else {
            continue;
        };
        if let Some(boolean) = nested.as_bool() {
            return Some(boolean);
        }
        if let Some(text) = nested.as_str() {
            match text.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" => return Some(true),
                "false" | "0" | "no" => return Some(false),
                _ => {}
            }
        }
    }
    None
}

fn rfc3339_minus_seconds(timestamp: &str, seconds: u64) -> Option<String> {
    let parsed = OffsetDateTime::parse(timestamp, &Rfc3339).ok()?;
    let duration = TimeDuration::seconds(i64::try_from(seconds).ok()?);
    (parsed - duration).format(&Rfc3339).ok()
}

fn json_timestamp_rfc3339(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        let Some(nested) = value.get(*key) else {
            continue;
        };
        if let Some(text) = nested
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            if let Ok(parsed) = OffsetDateTime::parse(text, &Rfc3339) {
                return parsed.format(&Rfc3339).ok();
            }
            if let Ok(seconds) = text.parse::<i64>() {
                return OffsetDateTime::from_unix_timestamp(seconds)
                    .ok()
                    .and_then(|value| value.format(&Rfc3339).ok());
            }
            if let Ok(seconds) = text.parse::<f64>() {
                if seconds.is_finite() {
                    return OffsetDateTime::from_unix_timestamp(seconds.round() as i64)
                        .ok()
                        .and_then(|value| value.format(&Rfc3339).ok());
                }
            }
        }
        if let Some(seconds) = nested.as_i64() {
            return OffsetDateTime::from_unix_timestamp(seconds)
                .ok()
                .and_then(|value| value.format(&Rfc3339).ok());
        }
        if let Some(seconds) = nested.as_u64().and_then(|value| i64::try_from(value).ok()) {
            return OffsetDateTime::from_unix_timestamp(seconds)
                .ok()
                .and_then(|value| value.format(&Rfc3339).ok());
        }
        if let Some(seconds) = nested.as_f64() {
            if seconds.is_finite() {
                return OffsetDateTime::from_unix_timestamp(seconds.round() as i64)
                    .ok()
                    .and_then(|value| value.format(&Rfc3339).ok());
            }
        }
    }
    None
}

fn nested_json_string(value: &Value, object_keys: &[&str], value_keys: &[&str]) -> Option<String> {
    let Value::Object(map) = value else {
        return None;
    };
    for key in object_keys {
        if let Some(nested) = map.get(*key) {
            if let Some(value) = first_json_string(nested, value_keys) {
                return Some(value);
            }
        }
    }
    None
}

fn unsupported_account(provider: &str) -> AgentAccountStatus {
    AgentAccountStatus {
        login_state: AgentLoginState::Unsupported,
        provider: Some(provider.to_string()),
        auth_method: None,
        email: None,
        account_id: None,
        organization_id: None,
        organization_label: None,
        plan_type: None,
        subscription_product: None,
        billing_channel: None,
        subscription_period_start: None,
        subscription_period_end: None,
        account_identifier_hash: None,
        organization_identifier_hash: None,
        credential_fingerprint_hash: None,
        billing_identity_evidence: None,
        billing_identity_confidence: AgentStatusConfidence::Unknown,
        confidence: AgentStatusConfidence::Unknown,
    }
}

fn unsupported_quota_window(name: &str) -> AgentQuotaWindow {
    AgentQuotaWindow {
        name: name.to_string(),
        scope: AgentQuotaWindowScope::Source,
        status: AgentQuotaWindowStatus::Unsupported,
        freshness: AgentQuotaWindowFreshness::Unsupported,
        model: None,
        account_label: None,
        window_seconds: None,
        started_at: None,
        resets_at: None,
        quota: None,
        remaining: None,
        used_percent: None,
        left_percent: None,
        ..Default::default()
    }
}

fn supported_capability(capability: &str, detail: &str) -> AgentCapabilityGap {
    AgentCapabilityGap {
        capability: capability.to_string(),
        status: AgentCapabilityStatus::Supported,
        detail: Some(detail.to_string()),
    }
}

fn unsupported_capability(capability: &str, detail: &str) -> AgentCapabilityGap {
    AgentCapabilityGap {
        capability: capability.to_string(),
        status: AgentCapabilityStatus::Unsupported,
        detail: Some(detail.to_string()),
    }
}

fn command_diagnostic(code: &str, message: &str, output: &CommandOutput) -> AgentStatusDiagnostic {
    let status = output
        .status_code
        .map(|code| format!(" exit {code}"))
        .unwrap_or_default();
    let stderr_hint = if output.stderr.trim().is_empty() {
        String::new()
    } else {
        " stderr redacted".to_string()
    };
    AgentStatusDiagnostic::source(
        code,
        AgentDiagnosticSeverity::Warning,
        format!("{message}{status}.{stderr_hint}"),
    )
}

fn extract_email(text: &str) -> Option<String> {
    text.split_whitespace()
        .map(|token| {
            token.trim_matches(|c: char| {
                c == '<' || c == '>' || c == ',' || c == ';' || c == ':' || c == '"' || c == '\''
            })
        })
        .find(|token| {
            let parts: Vec<&str> = token.split('@').collect();
            parts.len() == 2
                && !parts[0].is_empty()
                && parts[1].contains('.')
                && !token.contains('/')
        })
        .map(ToString::to_string)
}

fn extract_plan_type(text: &str, candidates: &[&str]) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    candidates
        .iter()
        .find(|candidate| lower.contains(**candidate))
        .map(|candidate| candidate.to_string())
}

fn extract_percent_before(text: &str, markers: &[&str]) -> Option<u8> {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let mut start = index;
            while start > 0 && bytes[start - 1].is_ascii_digit() {
                start -= 1;
            }
            if start < index {
                if let Ok(value) = text[start..index].parse::<u8>() {
                    let context_start = start.saturating_sub(24);
                    let context_end = (index + 24).min(text.len());
                    let context = &text[context_start..context_end];
                    if markers.iter().any(|marker| context.contains(marker)) {
                        return Some(value.min(100));
                    }
                }
            }
        }
        index += 1;
    }
    None
}

fn run_command_capture(program: &str, args: &[&str], timeout: Duration) -> CommandOutput {
    let start = Instant::now();
    let Some(program_path) = crate::command_env::executable_path(program) else {
        return CommandOutput {
            command_found: false,
            success: false,
            status_code: None,
            stdout: String::new(),
            stderr: String::new(),
        };
    };
    let mut command = Command::new(program_path);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(path_env) = crate::command_env::path_env() {
        command.env("PATH", path_env);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            return CommandOutput {
                command_found: false,
                success: false,
                status_code: None,
                stdout: String::new(),
                stderr: String::new(),
            };
        }
    };

    let stdout_reader = child.stdout.take().map(spawn_pipe_reader);
    let stderr_reader = child.stderr.take().map(spawn_pipe_reader);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = collect_pipe_reader(stdout_reader, PIPE_DRAIN_TIMEOUT);
                let stderr = collect_pipe_reader(stderr_reader, PIPE_DRAIN_TIMEOUT);
                return CommandOutput {
                    command_found: true,
                    success: status.success(),
                    status_code: status.code(),
                    stdout,
                    stderr,
                };
            }
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                let stdout = collect_pipe_reader(stdout_reader, PIPE_DRAIN_TIMEOUT);
                let stderr = collect_pipe_reader(stderr_reader, PIPE_DRAIN_TIMEOUT);
                return CommandOutput {
                    command_found: true,
                    success: false,
                    status_code: None,
                    stdout,
                    stderr,
                };
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(_) => {
                let _ = child.kill();
                let stdout = collect_pipe_reader(stdout_reader, PIPE_DRAIN_TIMEOUT);
                let stderr = collect_pipe_reader(stderr_reader, PIPE_DRAIN_TIMEOUT);
                return CommandOutput {
                    command_found: true,
                    success: false,
                    status_code: None,
                    stdout,
                    stderr,
                };
            }
        }
    }
}

fn spawn_pipe_reader<R>(mut pipe: R) -> mpsc::Receiver<String>
where
    R: Read + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut output = String::new();
        let _ = pipe.read_to_string(&mut output);
        let _ = sender.send(output);
    });
    receiver
}

fn collect_pipe_reader(reader: Option<mpsc::Receiver<String>>, timeout: Duration) -> String {
    reader
        .and_then(|receiver| receiver.recv_timeout(timeout).ok())
        .unwrap_or_default()
}

fn executable_exists(program: &str) -> bool {
    crate::command_env::executable_path(program).is_some()
}

fn codex_config_path() -> PathBuf {
    home_path(".codex/config.toml")
}

fn codex_auth_path() -> PathBuf {
    home_path(".codex/auth.json")
}

fn home_path(relative: &str) -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(relative)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The account resolution `collect_claude_status` performs, for tests that
    /// exercise the OAuth path directly.
    fn claude_oauth_account_identifier_hash() -> String {
        read_claude_cli_oauth_account(&claude_cli_config_path())
            .as_ref()
            .map(claude_oauth_account_identifier_hash_for)
            .unwrap_or_default()
    }
    use ottto_core::{
        write_claude_statusline_cache, ClaudeStatusLineRateLimitWindow,
        CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
    };
    use serial_test::serial;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set_os(key: &'static str, value: OsString) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match self.previous.as_ref() {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    #[test]
    #[serial]
    fn run_command_capture_drains_large_stdout_before_waiting() {
        let dir =
            std::env::temp_dir().join(format!("ottto-command-capture-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let executable = dir.join("large-output");
        std::fs::write(
            &executable,
            "#!/bin/sh\nexec /usr/bin/python3 -c 'import sys; sys.stdout.write(\"x\" * 200000)'\n",
        )
        .expect("write executable");
        let mut permissions = std::fs::metadata(&executable)
            .expect("metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).expect("chmod executable");

        let _guard =
            EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", dir.as_os_str().to_os_string());
        let output = run_command_capture("large-output", &[], Duration::from_secs(5));

        assert!(output.success, "{output:?}");
        assert_eq!(output.stdout.len(), 200000);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    #[serial]
    fn run_command_capture_timeout_does_not_wait_on_inherited_pipe() {
        let dir = std::env::temp_dir().join(format!(
            "ottto-command-capture-held-pipe-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let executable = dir.join("held-pipe");
        std::fs::write(&executable, "#!/bin/sh\n(sh -c 'sleep 2') &\nsleep 30\n")
            .expect("write executable");
        let mut permissions = std::fs::metadata(&executable)
            .expect("metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).expect("chmod executable");

        let _guard =
            EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", dir.as_os_str().to_os_string());
        let started = Instant::now();
        let output = run_command_capture("held-pipe", &[], Duration::from_millis(200));

        assert!(!output.success, "{output:?}");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "timeout path must not block on a descendant-held stdout pipe"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    #[serial]
    fn codex_app_server_reader_keeps_stdin_open_until_async_response() {
        let dir = std::env::temp_dir().join(format!("ottto-app-server-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let helper = dir.join("fake_codex.py");
        std::fs::write(
            &helper,
            r#"import select
import sys

if sys.argv[1:] != ["app-server", "--stdio"]:
    sys.exit(1)

for line in sys.stdin:
    if '"id":1' in line:
        print('{"id":1,"result":{"userAgent":"fake"}}', flush=True)
    if "account/rateLimits/read" in line:
        ready, _, _ = select.select([sys.stdin], [], [], 0.2)
        if ready and sys.stdin.readline() == "":
            sys.exit(0)
        print('{"id":"ottto_rate_limits","result":{"rateLimitResetCredits":{"availableCount":2},"rateLimitsByLimitId":{},"rateLimits":{}}}', flush=True)
        sys.exit(0)
"#,
        )
        .expect("write helper");
        let executable = dir.join("codex");
        std::fs::write(
            &executable,
            format!(
                "#!/bin/sh\nexec /usr/bin/python3 '{}' \"$@\"\n",
                helper.display()
            ),
        )
        .expect("write executable");
        let mut permissions = std::fs::metadata(&executable)
            .expect("metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).expect("chmod executable");

        let _guard =
            EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", dir.as_os_str().to_os_string());
        let value = call_codex_app_server_rate_limits().expect("rate limits");

        assert_eq!(
            value
                .pointer("/rateLimitResetCredits/availableCount")
                .and_then(Value::as_u64),
            Some(2)
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn codex_text_parser_extracts_account_model_quota_and_context() {
        let snapshot = parse_codex_status_fallback(
            "Logged in as test@example.com\nPlan: Pro\nModel: gpt-5.1\nUsage quota: 18% left\nContext: 72% used",
            "2026-05-06T10:00:00Z".to_string(),
            "2026-05-06T10:05:00Z".to_string(),
        );

        assert_eq!(snapshot.status, AgentStatusState::Available);
        assert_eq!(
            snapshot.account.and_then(|account| account.email),
            Some("test@example.com".to_string())
        );
        assert_eq!(
            snapshot.model.and_then(|model| model.active_model),
            Some("gpt-5.1".to_string())
        );
        assert_eq!(
            snapshot.quota_windows[0].status,
            AgentQuotaWindowStatus::NearLimit
        );
        assert_eq!(
            snapshot.context.and_then(|context| context.used_percent),
            Some(72)
        );
    }

    #[test]
    fn codex_model_parser_drops_automatic_review_prose() {
        let output = CommandOutput {
            command_found: true,
            success: true,
            status_code: Some(0),
            stdout: serde_json::json!({
                "models": [
                    {"name": "Automatic approval review model for Codex."},
                    {"id": "gpt-5.4-codex"}
                ]
            })
            .to_string(),
            stderr: String::new(),
        };

        let status = collect_model_status_from_output(&output, "openai");

        assert_eq!(status.active_model.as_deref(), Some("gpt-5.4-codex"));
        assert!(!status
            .available_models
            .iter()
            .any(|model| model.contains("approval review")));
    }

    #[test]
    fn codex_config_model_overrides_bundled_debug_model_summary() {
        let output = CommandOutput {
            command_found: true,
            success: true,
            status_code: Some(0),
            stdout: serde_json::json!({
                "models": [
                    {"id": "gpt-5.4-codex"}
                ]
            })
            .to_string(),
            stderr: String::new(),
        };
        let mut status = collect_model_status_from_output(&output, "openai");
        let mut collection_method = AgentStatusCollectionMethod::CommandProbe;

        apply_codex_config_model(
            &mut status,
            Some("gpt-5.5".to_string()),
            &mut collection_method,
        );

        assert_eq!(status.active_model.as_deref(), Some("gpt-5.5"));
        assert_eq!(status.default_model.as_deref(), Some("gpt-5.5"));
        assert_eq!(
            status.available_models.first().map(String::as_str),
            Some("gpt-5.5")
        );
        assert!(status
            .available_models
            .iter()
            .any(|model| model == "gpt-5.4-codex"));
        assert_eq!(collection_method, AgentStatusCollectionMethod::CommandProbe);
    }

    #[test]
    fn codex_bundled_models_preserve_structured_gpt56_metadata() {
        let output = CommandOutput {
            command_found: true,
            success: true,
            status_code: Some(0),
            stdout: serde_json::json!({
                "models": [
                    {
                        "slug": "gpt-5.6-sol",
                        "display_name": "GPT-5.6-Sol",
                        "description": "Latest frontier agentic coding model.",
                        "context_window": 372000,
                        "max_context_window": 372000,
                        "supported_reasoning_levels": [
                            {"effort": "low"},
                            {"effort": "max"}
                        ],
                        "input_modalities": ["text", "image"]
                    },
                    {
                        "slug": "gpt-5.6-terra",
                        "context_window": 372000,
                        "supported_reasoning_levels": [{"effort": "medium"}],
                        "input_modalities": ["text", "image"]
                    }
                ]
            })
            .to_string(),
            stderr: String::new(),
        };

        let status = collect_codex_model_status_from_output(&output);

        assert_eq!(status.active_model.as_deref(), Some("gpt-5.6-sol"));
        assert_eq!(status.default_model.as_deref(), Some("gpt-5.6-sol"));
        assert_eq!(status.context_window_tokens, Some(372_000));
        assert_eq!(
            status.available_models,
            vec!["gpt-5.6-sol".to_string(), "gpt-5.6-terra".to_string()]
        );
        assert_eq!(status.available_model_details.len(), 2);
        assert_eq!(
            status.available_model_details[0].context_window_tokens,
            Some(372_000)
        );
        assert_eq!(
            status.available_model_details[0].supports_thinking,
            Some(true)
        );
        assert_eq!(
            status.available_model_details[0].supports_images,
            Some(true)
        );
        assert!(!status
            .available_models
            .iter()
            .any(|model| model.contains("frontier")));
    }

    #[test]
    fn codex_config_model_selects_matching_structured_context_window() {
        let output = CommandOutput {
            command_found: true,
            success: true,
            status_code: Some(0),
            stdout: serde_json::json!({
                "models": [
                    {"slug": "gpt-5.6-sol", "context_window": 372000},
                    {"slug": "gpt-5.4-mini", "context_window": 258400}
                ]
            })
            .to_string(),
            stderr: String::new(),
        };
        let mut status = collect_codex_model_status_from_output(&output);
        let mut collection_method = AgentStatusCollectionMethod::CommandProbe;

        apply_codex_config_model(
            &mut status,
            Some("gpt-5.4-mini".to_string()),
            &mut collection_method,
        );

        assert_eq!(status.active_model.as_deref(), Some("gpt-5.4-mini"));
        assert_eq!(status.context_window_tokens, Some(258_400));
    }

    #[test]
    fn codex_id_token_parser_extracts_chatgpt_plan_claims() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            r#"{
                "email": "codex@example.com",
                "sub": "account_sub",
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": "account_123",
                    "chatgpt_user_id": "user_123",
                    "chatgpt_plan_type": "Team",
                    "chatgpt_subscription_active_start": 1782864000,
                    "chatgpt_subscription_active_until": 1785542400,
                    "organizations": [
                        {"id": "org_old", "title": "Old Org", "is_default": false},
                        {"id": "org_current", "title": "Current Org", "is_default": true}
                    ]
                }
            }"#,
        );
        let token = format!("{header}.{payload}.signature");

        let account = parse_codex_id_token_account(&token).expect("account");

        assert_eq!(account.login_state, AgentLoginState::SignedIn);
        assert_eq!(account.provider.as_deref(), Some("openai"));
        assert_eq!(account.email.as_deref(), Some("codex@example.com"));
        assert_eq!(account.account_id.as_deref(), Some("account_123"));
        assert_eq!(account.organization_id.as_deref(), Some("org_current"));
        assert_eq!(account.organization_label.as_deref(), Some("Current Org"));
        assert_eq!(account.plan_type.as_deref(), Some("team"));
        assert_eq!(
            account.subscription_product.as_deref(),
            Some("chatgpt_team")
        );
        assert_eq!(
            account.subscription_period_start.as_deref(),
            Some("2026-07-01T00:00:00Z")
        );
        assert_eq!(
            account.subscription_period_end.as_deref(),
            Some("2026-08-01T00:00:00Z")
        );
        assert_eq!(account.confidence, AgentStatusConfidence::High);
    }

    fn codex_id_token_with_auth_claim(auth_claim: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(format!(
            r#"{{
                "email": "codex@example.com",
                "sub": "account_sub",
                "https://api.openai.com/auth": {auth_claim}
            }}"#
        ));
        format!("{header}.{payload}.signature")
    }

    #[test]
    fn codex_id_token_subscription_period_is_absent_when_the_claims_are_absent() {
        let token = codex_id_token_with_auth_claim(
            r#"{"chatgpt_account_id": "account_123", "chatgpt_plan_type": "Pro"}"#,
        );

        let account = parse_codex_id_token_account(&token).expect("account");

        assert_eq!(account.plan_type.as_deref(), Some("pro"));
        assert_eq!(account.subscription_period_start, None);
        assert_eq!(account.subscription_period_end, None);
    }

    #[test]
    fn codex_id_token_subscription_period_reads_rfc3339_strings_as_utc() {
        let token = codex_id_token_with_auth_claim(
            r#"{
                "chatgpt_account_id": "account_123",
                "chatgpt_plan_type": "Pro",
                "chatgpt_subscription_active_start": "2026-07-01T03:00:00+03:00",
                "chatgpt_subscription_active_until": "1785542400"
            }"#,
        );

        let account = parse_codex_id_token_account(&token).expect("account");

        // An offset-bearing string is converted, not reinterpreted: same instant.
        assert_eq!(
            account.subscription_period_start.as_deref(),
            Some("2026-07-01T00:00:00Z")
        );
        assert_eq!(
            account.subscription_period_end.as_deref(),
            Some("2026-08-01T00:00:00Z")
        );
    }

    #[test]
    fn codex_id_token_subscription_period_drops_malformed_and_out_of_range_claims() {
        // Milliseconds, a non-date string, a null, and a nested object are all
        // "not reported" - never a panic, never a substituted `now`.
        for claim in [
            r#"{"chatgpt_plan_type": "Pro", "chatgpt_subscription_active_start": 1782864000000, "chatgpt_subscription_active_until": 1785542400000}"#,
            r#"{"chatgpt_plan_type": "Pro", "chatgpt_subscription_active_start": "not-a-date", "chatgpt_subscription_active_until": "also-not-a-date"}"#,
            r#"{"chatgpt_plan_type": "Pro", "chatgpt_subscription_active_start": null, "chatgpt_subscription_active_until": null}"#,
            r#"{"chatgpt_plan_type": "Pro", "chatgpt_subscription_active_start": {"seconds": 1782864000}, "chatgpt_subscription_active_until": []}"#,
            r#"{"chatgpt_plan_type": "Pro", "chatgpt_subscription_active_start": 0, "chatgpt_subscription_active_until": -1}"#,
        ] {
            let account = parse_codex_id_token_account(&codex_id_token_with_auth_claim(claim))
                .expect("account");
            assert_eq!(account.plan_type.as_deref(), Some("pro"), "claim: {claim}");
            assert_eq!(account.subscription_period_start, None, "claim: {claim}");
            assert_eq!(account.subscription_period_end, None, "claim: {claim}");
        }
    }

    #[test]
    fn codex_id_token_subscription_period_accepts_one_sided_reporting() {
        let token = codex_id_token_with_auth_claim(
            r#"{
                "chatgpt_plan_type": "Pro",
                "chatgpt_subscription_active_until": 1785542400
            }"#,
        );

        let account = parse_codex_id_token_account(&token).expect("account");

        assert_eq!(account.subscription_period_start, None);
        assert_eq!(
            account.subscription_period_end.as_deref(),
            Some("2026-08-01T00:00:00Z")
        );
    }

    #[test]
    fn codex_id_token_subscription_period_alone_does_not_resurrect_an_empty_account() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            r#"{
                "https://api.openai.com/auth": {
                    "chatgpt_subscription_active_start": 1782864000,
                    "chatgpt_subscription_active_until": 1785542400
                }
            }"#,
        );
        let token = format!("{header}.{payload}.signature");

        assert!(parse_codex_id_token_account(&token).is_none());
    }

    #[test]
    fn merged_codex_accounts_carry_the_subscription_period() {
        let mut auth_account = unsupported_account("openai");
        auth_account.login_state = AgentLoginState::SignedIn;
        auth_account.subscription_period_start = Some("2026-07-01T00:00:00Z".to_string());
        auth_account.subscription_period_end = Some("2026-08-01T00:00:00Z".to_string());
        let mut existing = unsupported_account("openai");
        existing.email = Some("codex@example.com".to_string());

        let merged = merge_codex_accounts(Some(existing), auth_account.clone());

        assert_eq!(
            merged.subscription_period_start.as_deref(),
            Some("2026-07-01T00:00:00Z")
        );
        assert_eq!(
            merged.subscription_period_end.as_deref(),
            Some("2026-08-01T00:00:00Z")
        );

        // A later probe that reports nothing must not blank a known period.
        let mut silent = unsupported_account("openai");
        silent.login_state = AgentLoginState::SignedIn;
        let preserved = merge_codex_accounts(Some(merged), silent);

        assert_eq!(
            preserved.subscription_period_start.as_deref(),
            Some("2026-07-01T00:00:00Z")
        );
        assert_eq!(
            preserved.subscription_period_end.as_deref(),
            Some("2026-08-01T00:00:00Z")
        );
    }

    #[test]
    fn subscription_period_is_omitted_from_the_wire_when_absent() {
        let account = unsupported_account("openai");

        let wire = serde_json::to_value(&account).expect("serialize");

        assert!(wire.get("subscription_period_start").is_none());
        assert!(wire.get("subscription_period_end").is_none());
    }

    #[test]
    fn codex_id_token_workspace_observations_keep_unknown_plans_as_memberships() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            r#"{
                "email": "codex@example.com",
                "sub": "account_sub",
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": "account_123",
                    "chatgpt_plan_type": "Pro",
                    "organizations": [
                        {"id": "org_current", "title": "Current Org", "is_default": true},
                        {"id": "org_related", "title": "Related Org", "is_default": false}
                    ]
                }
            }"#,
        );
        let token = format!("{header}.{payload}.signature");

        let observations = codex_workspace_observations_from_id_token(
            &token,
            "2026-06-07T10:00:00Z",
            Some("openai"),
        )
        .expect("observations");

        assert_eq!(observations.len(), 1);
        let related = &observations[0];
        assert_eq!(
            related.evidence_method.as_deref(),
            Some("id_token_organization")
        );
        assert_eq!(
            related.billing_channel.as_deref(),
            Some("workspace_membership")
        );
        assert_eq!(related.subscription_product, None);
        assert_eq!(related.plan_type, None);
        assert_eq!(related.account_label.as_deref(), Some("codex@example.com"));
        assert_eq!(related.organization_label.as_deref(), Some("Related Org"));
        assert_eq!(related.account_id, None);
        assert_eq!(related.organization_id, None);
        assert_eq!(related.is_current, Some(false));
        assert_eq!(related.account_identifier_hash, None);
        assert_eq!(related.organization_identifier_hash, None);
        assert_eq!(
            related.billing_identity_confidence,
            AgentStatusConfidence::Unknown
        );
        assert_eq!(related.confidence, AgentStatusConfidence::Medium);
    }

    #[test]
    fn codex_id_token_workspace_observations_promote_explicit_org_plans() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            r#"{
                "email": "codex@example.com",
                "sub": "account_sub",
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": "account_123",
                    "organizations": [
                        {"id": "org_current", "title": "Current Org", "is_default": true},
                        {"id": "org_team", "title": "Team Org", "subscription_plan": "Team"}
                    ]
                }
            }"#,
        );
        let token = format!("{header}.{payload}.signature");

        let observations = codex_workspace_observations_from_id_token(
            &token,
            "2026-06-07T10:00:00Z",
            Some("openai"),
        )
        .expect("observations");

        assert_eq!(observations.len(), 1);
        let team = &observations[0];
        assert_eq!(team.billing_channel.as_deref(), Some("subscription"));
        assert_eq!(team.plan_type.as_deref(), Some("team"));
        assert_eq!(team.subscription_product.as_deref(), Some("chatgpt_team"));
        assert_eq!(team.organization_label.as_deref(), Some("Team Org"));
        assert_eq!(team.account_id.as_deref(), Some("account_123"));
        assert_eq!(team.organization_id.as_deref(), Some("org_team"));
        assert_eq!(team.is_current, Some(false));
        assert!(team.account_identifier_hash.is_some());
        assert_eq!(
            team.billing_identity_evidence.as_deref(),
            Some("provider_account_id")
        );
        assert_eq!(
            team.billing_identity_confidence,
            AgentStatusConfidence::High
        );
        assert_eq!(team.confidence, AgentStatusConfidence::High);
    }

    #[test]
    fn codex_usage_parser_extracts_windows_and_credits() {
        let json = serde_json::json!({
            "rate_limit": {
                "primary_window": {
                    "used_percent": 3,
                    "reset_at": 1779049800,
                    "limit_window_seconds": 18000
                },
                "secondary_window": {
                    "used_percent": 1,
                    "reset_at": "1779613200",
                    "limit_window_seconds": 604800
                },
                "credits": {
                    "has_credits": true,
                    "unlimited": false,
                    "balance": 0
                }
            }
        });

        let windows = codex_usage_quota_windows(&json);
        let credits = codex_usage_credit_balances(&json);

        assert_eq!(windows.len(), 2);
        // Names are now derived from duration: 5h -> session, 7d -> weekly, which
        // happens to match the legacy positional labels for this payload.
        assert_eq!(windows[0].name, "session");
        assert_eq!(windows[0].left_percent, Some(97));
        assert_eq!(
            windows[0].started_at.as_deref(),
            Some("2026-05-17T15:30:00Z")
        );
        assert_eq!(windows[1].name, "weekly");
        assert_eq!(windows[1].left_percent, Some(99));
        assert_eq!(credits.len(), 1);
        assert_eq!(credits[0].status, AgentCreditBalanceStatus::Exhausted);
        assert_eq!(credits[0].remaining, Some(0));
        // The legacy payload carries none of the 2026-07 credit metadata.
        assert_eq!(credits[0].spend_control_reached, None);
        assert_eq!(credits[0].rate_limit_reached_type, None);
        assert_eq!(credits[0].limit_id, None);
    }

    #[test]
    fn codex_usage_parser_handles_weekly_primary_window() {
        // OpenAI's 2026-07-12 change: the wham/usage fields arrive top-level with
        // a weekly primary window (minutes-denominated), a null secondary, and
        // sibling credit metadata (limit_id, spend_control_reached, ...).
        let json = serde_json::json!({
            "limit_id": "codex",
            "limit_name": null,
            "primary": {
                "used_percent": 30.0,
                "window_minutes": 10080,
                "resets_at": 1784963503_u64
            },
            "secondary": null,
            "credits": {
                "has_credits": false,
                "unlimited": false,
                "balance": "0"
            },
            "individual_limit": null,
            "spend_control_reached": null,
            "plan_type": "pro",
            "rate_limit_reached_type": null
        });

        let windows = codex_usage_quota_windows(&json);
        let credits = codex_usage_credit_balances(&json);

        // Single window: the null secondary is dropped; the primary is weekly by
        // duration (10080 min == 7 days) despite arriving in the primary slot.
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].name, "weekly");
        assert_eq!(windows[0].window_seconds, Some(604800));
        assert_eq!(windows[0].used_percent, Some(30));
        assert_eq!(windows[0].left_percent, Some(70));

        assert_eq!(credits.len(), 1);
        assert_eq!(credits[0].remaining, Some(0));
        assert_eq!(credits[0].status, AgentCreditBalanceStatus::Exhausted);
        assert_eq!(credits[0].limit_id.as_deref(), Some("codex"));
        // Explicit JSON nulls stay absent rather than becoming Some(false)/Some("").
        assert_eq!(credits[0].spend_control_reached, None);
        assert_eq!(credits[0].rate_limit_reached_type, None);
    }

    #[test]
    fn codex_usage_parser_treats_spend_control_reached_as_exhausted() {
        // A reached spend control caps the account even with a positive balance.
        let json = serde_json::json!({
            "limit_id": "codex",
            "primary": {
                "used_percent": 12,
                "window_minutes": 10080,
                "resets_at": 1784963503_u64
            },
            "secondary": null,
            "credits": {
                "has_credits": true,
                "unlimited": false,
                "balance": "42"
            },
            "spend_control_reached": true,
            "rate_limit_reached_type": "primary"
        });

        let credits = codex_usage_credit_balances(&json);
        assert_eq!(credits.len(), 1);
        assert_eq!(credits[0].remaining, Some(42));
        assert_eq!(credits[0].status, AgentCreditBalanceStatus::Exhausted);
        assert_eq!(credits[0].spend_control_reached, Some(true));
        assert_eq!(
            credits[0].rate_limit_reached_type.as_deref(),
            Some("primary")
        );
        assert_eq!(credits[0].limit_id.as_deref(), Some("codex"));
    }

    #[test]
    fn codex_app_server_parser_extracts_windows_and_reset_bank() {
        let json = serde_json::json!({
            "rateLimits": {
                "limitId": "codex_bengalfox",
                "primary": {
                    "usedPercent": 9,
                    "windowDurationMins": 300,
                    "resetsAt": 1779049800
                },
                "secondary": {
                    "usedPercent": 37,
                    "windowDurationMins": 10080,
                    "resetsAt": 1779613200
                },
                "credits": {
                    "hasCredits": true,
                    "unlimited": false,
                    "balance": "4"
                },
                "planType": "pro"
            },
            "rateLimitsByLimitId": {
                "codex_bengalfox": {
                    "limitId": "codex_bengalfox",
                    "primary": {"usedPercent": 9, "windowDurationMins": 300, "resetsAt": 1779049800}
                },
                "codex": {
                    "limitId": "codex",
                    "primary": {
                        "usedPercent": 3,
                        "windowDurationMins": 300,
                        "resetsAt": 1779049800
                    },
                    "secondary": {
                        "usedPercent": 5,
                        "windowDurationMins": 10080,
                        "resetsAt": 1779613200
                    },
                    "credits": {
                        "hasCredits": true,
                        "unlimited": false,
                        "balance": "12.4"
                    },
                    "planType": "pro"
                }
            },
            "rateLimitResetCredits": {
                "availableCount": 2
            }
        });

        let windows = codex_app_server_quota_windows(&json);
        let credits = codex_app_server_credit_balances(&json);

        assert_eq!(windows.len(), 2);
        assert_eq!(windows[0].name, "session");
        assert_eq!(windows[0].left_percent, Some(97));
        assert_eq!(
            windows[0].started_at.as_deref(),
            Some("2026-05-17T15:30:00Z")
        );
        assert_eq!(windows[1].name, "weekly");
        assert_eq!(windows[1].left_percent, Some(95));
        assert_eq!(credits.len(), 2);
        assert_eq!(credits[0].name, "credits");
        assert_eq!(credits[0].remaining, Some(12));
        // A payload without the spend-cap fields leaves them unset.
        assert_eq!(credits[0].spend_control_reached, None);
        assert_eq!(credits[0].rate_limit_reached_type, None);
        assert_eq!(credits[0].limit_id.as_deref(), Some("codex"));
        assert_eq!(credits[1].name, "reset_bank");
        assert_eq!(credits[1].unit, AgentCreditBalanceUnit::Resets);
        assert_eq!(credits[1].status, AgentCreditBalanceStatus::Ok);
        assert_eq!(credits[1].remaining, Some(2));
    }

    #[test]
    fn codex_app_server_parser_carries_credit_spend_control_fields() {
        // The app-server snapshot is the PRIMARY collector (the OAuth wham/usage
        // path is legacy fallback), so it must carry the spend-cap contract too.
        let json = serde_json::json!({
            "rateLimitsByLimitId": {
                "codex": {
                    "limitId": "codex",
                    "primary": {
                        "usedPercent": 100,
                        "windowDurationMins": 300,
                        "resetsAt": 1779049800
                    },
                    "credits": {
                        "hasCredits": true,
                        "unlimited": false,
                        "balance": "9"
                    },
                    "spendControlReached": true,
                    "rateLimitReachedType": "primary"
                }
            }
        });

        let credits = codex_app_server_credit_balances(&json);

        assert_eq!(credits.len(), 1);
        assert_eq!(credits[0].name, "credits");
        assert_eq!(credits[0].remaining, Some(9));
        // A reached spend cap is a hard stop even with a nominal balance remaining.
        assert_eq!(credits[0].status, AgentCreditBalanceStatus::Exhausted);
        assert_eq!(credits[0].spend_control_reached, Some(true));
        assert_eq!(
            credits[0].rate_limit_reached_type.as_deref(),
            Some("primary")
        );
        assert_eq!(credits[0].limit_id.as_deref(), Some("codex"));
    }

    #[test]
    fn codex_app_server_parser_preserves_zero_reset_bank_count() {
        let json = serde_json::json!({
            "rateLimits": {
                "limitId": "codex",
                "primary": null,
                "secondary": null,
                "credits": null
            },
            "rateLimitResetCredits": {
                "availableCount": 0
            }
        });

        let credits = codex_app_server_credit_balances(&json);

        assert_eq!(credits.len(), 1);
        assert_eq!(credits[0].name, "reset_bank");
        assert_eq!(credits[0].unit, AgentCreditBalanceUnit::Resets);
        assert_eq!(credits[0].status, AgentCreditBalanceStatus::Exhausted);
        assert_eq!(credits[0].remaining, Some(0));
    }

    #[test]
    fn claude_json_parser_normalizes_safe_fields() {
        let json = serde_json::json!({
            "status": "authenticated",
            "email": "user@example.com",
            "organization": {"id": "org_1", "name": "Research"},
            "subscription_type": "max_5x"
        });

        let account = parse_claude_auth_json(&json);

        assert_eq!(account.login_state, AgentLoginState::SignedIn);
        assert_eq!(account.provider.as_deref(), Some("anthropic"));
        assert_eq!(account.email.as_deref(), Some("user@example.com"));
        assert_eq!(account.organization_id.as_deref(), Some("org_1"));
        assert_eq!(
            account.subscription_product.as_deref(),
            Some("claude_max_5x")
        );
    }

    #[test]
    fn claude_json_parser_accepts_current_camel_case_auth_status() {
        let json = serde_json::json!({
            "loggedIn": true,
            "authMethod": "claude.ai",
            "apiProvider": "firstParty",
            "email": "user@example.com",
            "orgId": "org_2",
            "orgName": "Research Team",
            "subscriptionType": "max"
        });

        let account = parse_claude_auth_json(&json);

        assert_eq!(account.login_state, AgentLoginState::SignedIn);
        assert_eq!(account.auth_method.as_deref(), Some("claude.ai"));
        assert_eq!(account.organization_id.as_deref(), Some("org_2"));
        assert_eq!(account.organization_label.as_deref(), Some("Research Team"));
        assert_eq!(account.plan_type.as_deref(), Some("max"));
        assert_eq!(account.subscription_product.as_deref(), Some("claude_max"));
        assert_eq!(account.billing_channel.as_deref(), Some("subscription"));
    }

    fn team_auth_account(email: &str, org_id: &str) -> AgentAccountStatus {
        parse_claude_auth_json(&serde_json::json!({
            "loggedIn": true,
            "authMethod": "claude.ai",
            "apiProvider": "firstParty",
            "email": email,
            "orgId": org_id,
            "orgName": "Singular",
            "subscriptionType": "team"
        }))
    }

    #[test]
    fn claude_cli_oauth_account_parser_reads_display_safe_fields() {
        let parsed = parse_claude_cli_oauth_account(&serde_json::json!({
            "oauthAccount": {
                "accountUuid": "acct-1",
                "emailAddress": "ron.s@singular.net",
                "organizationUuid": "org-1",
                "organizationType": "claude_team",
                "seatTier": "premium",
                "organizationRateLimitTier": "claude_team",
                "userRateLimitTier": "default_claude_max_5x"
            }
        }))
        .expect("oauthAccount parsed");

        assert_eq!(parsed.account_uuid.as_deref(), Some("acct-1"));
        assert_eq!(parsed.email_address.as_deref(), Some("ron.s@singular.net"));
        assert_eq!(parsed.organization_uuid.as_deref(), Some("org-1"));
        assert_eq!(parsed.organization_type.as_deref(), Some("claude_team"));
        assert_eq!(parsed.seat_tier.as_deref(), Some("premium"));
        assert_eq!(
            parsed.user_rate_limit_tier.as_deref(),
            Some("default_claude_max_5x")
        );
        assert!(parse_claude_cli_oauth_account(&serde_json::json!({})).is_none());
    }

    #[test]
    fn claude_cli_account_identity_stamps_account_hash_onto_plan_observation() {
        // `claude auth status --json` names the org but not the account uuid;
        // the uuid rides `~/.claude.json` `oauthAccount`. The stamped hash must
        // be the exact `billing_identity_hash` the quota windows carry so plan
        // and quota evidence converge on one billing identity.
        let mut account = team_auth_account("ron.s@singular.net", "org-1");
        assert!(account.account_id.is_none());
        assert!(account.account_identifier_hash.is_none());
        let oauth = ClaudeCliOauthAccount {
            account_uuid: Some("acct-1".to_string()),
            email_address: Some("ron.s@singular.net".to_string()),
            organization_uuid: Some("org-1".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        assert!(stamp_claude_cli_account_identity(&mut account, &oauth));

        assert_eq!(account.account_id.as_deref(), Some("acct-1"));
        assert_eq!(
            account.account_identifier_hash,
            billing_identity_hash("anthropic", "account", "acct-1")
        );
        assert!(account.organization_identifier_hash.is_some());
        assert_eq!(
            account.billing_identity_evidence.as_deref(),
            Some("provider_account_id")
        );

        let mut snapshot = base_snapshot(
            SourceKind::ClaudeCode,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::CliJson,
            "2026-07-28T10:00:00Z".to_string(),
            "2026-07-28T10:30:00Z".to_string(),
        );
        snapshot.account = Some(account);
        append_current_plan_observation(&mut snapshot);

        let observation = snapshot
            .plan_observations
            .first()
            .expect("plan observation");
        assert_eq!(observation.account_id.as_deref(), Some("acct-1"));
        assert_eq!(
            observation.account_identifier_hash,
            billing_identity_hash("anthropic", "account", "acct-1")
        );
        assert!(observation.organization_identifier_hash.is_some());
        assert_eq!(
            observation.billing_identity_evidence.as_deref(),
            Some("provider_account_id")
        );
    }

    #[test]
    fn claude_cli_account_identity_refuses_mismatched_metadata() {
        // `~/.claude.json` lagging behind an account switch must never stamp a
        // different account's uuid onto the signed-in account.
        let mut account = team_auth_account("ron.s@singular.net", "org-1");
        let stale_email = ClaudeCliOauthAccount {
            account_uuid: Some("acct-other".to_string()),
            email_address: Some("someone.else@example.com".to_string()),
            ..ClaudeCliOauthAccount::default()
        };
        assert!(!stamp_claude_cli_account_identity(
            &mut account,
            &stale_email
        ));
        assert!(account.account_id.is_none());
        assert!(account.account_identifier_hash.is_none());

        let stale_org = ClaudeCliOauthAccount {
            account_uuid: Some("acct-other".to_string()),
            organization_uuid: Some("org-other".to_string()),
            ..ClaudeCliOauthAccount::default()
        };
        assert!(!stamp_claude_cli_account_identity(&mut account, &stale_org));
        assert!(account.account_identifier_hash.is_none());

        // A present auth-status account id that disagrees with `accountUuid`
        // refuses too, and the existing id is left untouched.
        account.account_id = Some("acct-auth-status".to_string());
        let conflicting = ClaudeCliOauthAccount {
            account_uuid: Some("acct-other".to_string()),
            email_address: Some("ron.s@singular.net".to_string()),
            organization_uuid: Some("org-1".to_string()),
            ..ClaudeCliOauthAccount::default()
        };
        assert!(!stamp_claude_cli_account_identity(
            &mut account,
            &conflicting
        ));
        assert_eq!(account.account_id.as_deref(), Some("acct-auth-status"));
        assert!(account.account_identifier_hash.is_none());

        // No account uuid in the metadata: nothing to stamp.
        let uuid_less = ClaudeCliOauthAccount {
            email_address: Some("ron.s@singular.net".to_string()),
            ..ClaudeCliOauthAccount::default()
        };
        let mut fresh = team_auth_account("ron.s@singular.net", "org-1");
        assert!(!stamp_claude_cli_account_identity(&mut fresh, &uuid_less));
        assert!(fresh.account_identifier_hash.is_none());
    }

    #[test]
    fn claude_team_seat_tier_refines_premium_from_seat_tier() {
        let mut account = team_auth_account("ron.s@singular.net", "org-1");
        let oauth = ClaudeCliOauthAccount {
            email_address: Some("ron.s@singular.net".to_string()),
            organization_uuid: Some("org-1".to_string()),
            organization_type: Some("claude_team".to_string()),
            seat_tier: Some("premium".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        let refined = refine_claude_team_seat_plan(&mut account, &oauth);

        assert_eq!(refined, Some("team_premium"));
        assert_eq!(account.plan_type.as_deref(), Some("team_premium"));
        assert_eq!(
            account.subscription_product.as_deref(),
            Some("claude_team_premium")
        );
    }

    #[test]
    fn claude_team_seat_tier_refines_premium_from_user_rate_limit_tier() {
        let mut account = team_auth_account("ron.s@singular.net", "org-1");
        let oauth = ClaudeCliOauthAccount {
            email_address: Some("ron.s@singular.net".to_string()),
            user_rate_limit_tier: Some("default_claude_max_5x".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        assert_eq!(
            refine_claude_team_seat_plan(&mut account, &oauth),
            Some("team_premium")
        );
    }

    #[test]
    fn claude_team_seat_tier_refines_standard_from_seat_tier() {
        let mut account = team_auth_account("ron.s@singular.net", "org-1");
        let oauth = ClaudeCliOauthAccount {
            seat_tier: Some("standard".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        assert_eq!(
            refine_claude_team_seat_plan(&mut account, &oauth),
            Some("team_standard")
        );
        assert_eq!(
            account.subscription_product.as_deref(),
            Some("claude_team_standard")
        );
    }

    #[test]
    fn claude_team_seat_tier_leaves_generic_team_without_explicit_signal() {
        let mut account = team_auth_account("ron.s@singular.net", "org-1");
        let oauth = ClaudeCliOauthAccount {
            email_address: Some("ron.s@singular.net".to_string()),
            organization_type: Some("claude_team".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        assert_eq!(refine_claude_team_seat_plan(&mut account, &oauth), None);
        assert_eq!(account.plan_type.as_deref(), Some("team"));
        assert_eq!(account.subscription_product.as_deref(), Some("claude_team"));
    }

    #[test]
    fn claude_team_seat_tier_ignores_mismatched_account_metadata() {
        // `~/.claude.json` lagging behind an account switch must not leak a
        // different account's seat tier onto the signed-in account.
        let mut account = team_auth_account("ron.s@singular.net", "org-1");
        let oauth = ClaudeCliOauthAccount {
            email_address: Some("someone.else@example.com".to_string()),
            seat_tier: Some("premium".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        assert_eq!(refine_claude_team_seat_plan(&mut account, &oauth), None);
        assert_eq!(account.plan_type.as_deref(), Some("team"));
    }

    #[test]
    fn claude_team_seat_tier_ignores_non_team_plans_and_orgs() {
        let mut max_account = parse_claude_auth_json(&serde_json::json!({
            "loggedIn": true,
            "email": "user@example.com",
            "subscriptionType": "max"
        }));
        let premium_oauth = ClaudeCliOauthAccount {
            seat_tier: Some("premium".to_string()),
            user_rate_limit_tier: Some("default_claude_max_5x".to_string()),
            ..ClaudeCliOauthAccount::default()
        };
        assert_eq!(
            refine_claude_team_seat_plan(&mut max_account, &premium_oauth),
            None
        );
        assert_eq!(max_account.plan_type.as_deref(), Some("max"));

        // A stale non-team organizationType blocks refinement even when the
        // auth status says team.
        let mut team_account = team_auth_account("ron.s@singular.net", "org-1");
        let stale_oauth = ClaudeCliOauthAccount {
            organization_type: Some("claude_max".to_string()),
            seat_tier: Some("premium".to_string()),
            ..ClaudeCliOauthAccount::default()
        };
        assert_eq!(
            refine_claude_team_seat_plan(&mut team_account, &stale_oauth),
            None
        );
    }

    fn max_auth_account(email: &str) -> AgentAccountStatus {
        parse_claude_auth_json(&serde_json::json!({
            "loggedIn": true,
            "authMethod": "claude.ai",
            "apiProvider": "firstParty",
            "email": email,
            "subscriptionType": "max"
        }))
    }

    #[test]
    fn claude_max_tier_refines_20x_from_organization_rate_limit_tier() {
        let mut account = max_auth_account("user@example.com");
        let oauth = ClaudeCliOauthAccount {
            email_address: Some("user@example.com".to_string()),
            organization_type: Some("claude_max".to_string()),
            organization_rate_limit_tier: Some("default_claude_max_20x".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        let refined = refine_claude_max_rate_limit_plan(&mut account, &oauth);

        assert_eq!(refined, Some("max_20x"));
        assert_eq!(account.plan_type.as_deref(), Some("max_20x"));
        assert_eq!(
            account.subscription_product.as_deref(),
            Some("claude_max_20x")
        );
    }

    #[test]
    fn claude_max_tier_refines_5x_from_user_rate_limit_tier_fallback() {
        let mut account = max_auth_account("user@example.com");
        let oauth = ClaudeCliOauthAccount {
            email_address: Some("user@example.com".to_string()),
            user_rate_limit_tier: Some("default_claude_max_5x".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        assert_eq!(
            refine_claude_max_rate_limit_plan(&mut account, &oauth),
            Some("max_5x")
        );
        assert_eq!(account.plan_type.as_deref(), Some("max_5x"));
        assert_eq!(
            account.subscription_product.as_deref(),
            Some("claude_max_5x")
        );
    }

    #[test]
    fn claude_max_tier_left_generic_without_explicit_signal() {
        // Bare `max` is emitted for BOTH Max tiers: no recognized rate-limit
        // tier means no refinement, never a guess.
        let mut account = max_auth_account("user@example.com");
        let oauth = ClaudeCliOauthAccount {
            email_address: Some("user@example.com".to_string()),
            organization_rate_limit_tier: Some("claude_max".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        assert_eq!(
            refine_claude_max_rate_limit_plan(&mut account, &oauth),
            None
        );
        assert_eq!(account.plan_type.as_deref(), Some("max"));
        assert_eq!(account.subscription_product.as_deref(), Some("claude_max"));
    }

    #[test]
    fn claude_max_tier_ignores_mismatched_account_metadata() {
        // `~/.claude.json` lagging behind an account switch must not leak a
        // different account's tier onto the signed-in account.
        let mut account = max_auth_account("user@example.com");
        let oauth = ClaudeCliOauthAccount {
            email_address: Some("someone.else@example.com".to_string()),
            organization_rate_limit_tier: Some("default_claude_max_20x".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        assert_eq!(
            refine_claude_max_rate_limit_plan(&mut account, &oauth),
            None
        );
        assert_eq!(account.plan_type.as_deref(), Some("max"));
    }

    #[test]
    fn claude_max_tier_ignores_non_max_plans_and_orgs() {
        // Team plan: the max refinement never fires.
        let mut team_account = team_auth_account("ron.s@singular.net", "org-1");
        let oauth = ClaudeCliOauthAccount {
            organization_rate_limit_tier: Some("default_claude_max_20x".to_string()),
            ..ClaudeCliOauthAccount::default()
        };
        assert_eq!(
            refine_claude_max_rate_limit_plan(&mut team_account, &oauth),
            None
        );

        // A stale non-max organizationType blocks refinement even when the
        // auth status says max.
        let mut max_account = max_auth_account("user@example.com");
        let stale_oauth = ClaudeCliOauthAccount {
            organization_type: Some("claude_team".to_string()),
            organization_rate_limit_tier: Some("default_claude_max_20x".to_string()),
            ..ClaudeCliOauthAccount::default()
        };
        assert_eq!(
            refine_claude_max_rate_limit_plan(&mut max_account, &stale_oauth),
            None
        );
        assert_eq!(max_account.plan_type.as_deref(), Some("max"));
    }

    #[test]
    fn claude_desktop_metadata_observations_split_current_desktop_account() {
        let root = std::env::temp_dir().join(format!(
            "ottto-claude-desktop-profile-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create root");
        std::fs::write(
            root.join("config.json"),
            r#"{"lastKnownAccountUuid":"desktop-account-current"}"#,
        )
        .expect("write config");

        let current_code = root
            .join("claude-code-sessions")
            .join("desktop-account-current")
            .join("singular-org-bucket");
        std::fs::create_dir_all(&current_code).expect("create current code bucket");
        std::fs::write(
            current_code.join("local_current.json"),
            r#"{
              "cliSessionId": "current-cli-session",
              "lastActivityAt": "2026-07-08T10:00:00Z",
              "cwd": "/Users/example/private",
              "title": "ignored"
            }"#,
        )
        .expect("write current code metadata");
        let current_identity = root
            .join("local-agent-mode-sessions")
            .join("desktop-account-current")
            .join("different-agent-mode-bucket");
        std::fs::create_dir_all(&current_identity).expect("create current identity bucket");
        std::fs::write(
            current_identity.join("local_identity.json"),
            // lastActivityAt must be explicit and OLDER than the code-session
            // bucket's: without it the reader falls back to file mtime (= test
            // run time), which outranks the code session's fixed timestamp and
            // flips latest_session_id — a wall-clock time bomb.
            r#"{
              "cliSessionId": "identity-cli-session",
              "lastActivityAt": "2026-07-06T10:00:00Z",
              "emailAddress": "ron.s@singular.net",
              "accountName": "Ron",
              "organizationName": "Singular",
              "subscriptionType": "team",
              "initialMessage": "must not be persisted"
            }"#,
        )
        .expect("write current identity metadata");

        let old_code = root
            .join("claude-code-sessions")
            .join("desktop-account-old")
            .join("gmail-org-bucket");
        std::fs::create_dir_all(&old_code).expect("create old code bucket");
        std::fs::write(
            old_code.join("local_old.json"),
            r#"{"cliSessionId":"old-cli-session","lastActivityAt":"2026-07-07T10:00:00Z"}"#,
        )
        .expect("write old code metadata");
        let old_identity = root
            .join("local-agent-mode-sessions")
            .join("desktop-account-old")
            .join("gmail-org-bucket");
        std::fs::create_dir_all(&old_identity).expect("create old identity bucket");
        std::fs::write(
            old_identity.join("local_identity.json"),
            r#"{"emailAddress":"ronshub88@gmail.com"}"#,
        )
        .expect("write old identity metadata");

        let observations =
            claude_desktop_plan_observations_from_root(&root, "2026-07-08T10:01:00Z");

        assert_eq!(observations.len(), 2);
        let current = observations
            .iter()
            .find(|observation| observation.is_current == Some(true))
            .expect("current desktop observation");
        assert_eq!(
            current.evidence_method.as_deref(),
            Some("claude_desktop_session_bucket")
        );
        assert_eq!(current.auth_mode.as_deref(), Some("claude_desktop"));
        assert_eq!(current.billing_channel.as_deref(), Some("subscription"));
        assert_eq!(current.account_label.as_deref(), Some("ron.s@singular.net"));
        assert_eq!(current.organization_label.as_deref(), Some("Singular"));
        assert_eq!(current.plan_type.as_deref(), Some("team"));
        assert_eq!(current.subscription_product.as_deref(), Some("claude_team"));
        assert_eq!(
            current.account_id.as_deref(),
            Some("desktop-account-current")
        );
        assert_eq!(
            current.organization_id.as_deref(),
            Some("singular-org-bucket")
        );
        assert_eq!(
            current.source_session_id.as_deref(),
            Some("current-cli-session")
        );
        assert!(current.account_identifier_hash.is_some());
        assert!(current.organization_identifier_hash.is_some());
        assert_eq!(
            current.billing_identity_evidence.as_deref(),
            Some("provider_account_id")
        );
        assert_eq!(
            current.billing_identity_confidence,
            AgentStatusConfidence::High
        );

        let old = observations
            .iter()
            .find(|observation| observation.account_label.as_deref() == Some("ronshub88@gmail.com"))
            .expect("old desktop observation");
        assert_eq!(old.is_current, Some(false));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn claude_oauth_token_parser_extracts_only_access_token() {
        let payload = r#"{
          "claudeAiOauth": {
            "accessToken": " access-token ",
            "refreshToken": "refresh-token",
            "expiresAt": 1782750000000
          }
        }"#;

        assert_eq!(
            parse_claude_oauth_access_token(payload).as_deref(),
            Some("access-token")
        );
    }

    #[test]
    fn claude_desktop_chromium_cookie_decrypts_v24_host_bound_value() {
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};
        use zeroize::Zeroize;

        let host = ".claude.ai";
        let safe_storage_password = b"fixture-safe-storage-password";
        let expected_session_key = "sk-ant-sid-fixture-value";
        let mut plaintext = Sha256::digest(host.as_bytes()).to_vec();
        plaintext.extend_from_slice(expected_session_key.as_bytes());
        let mut key = [0_u8; CHROMIUM_COOKIE_KEY_BYTES];
        pbkdf2_hmac::<Sha1>(
            safe_storage_password,
            b"saltysalt",
            CHROMIUM_COOKIE_KEY_ITERATIONS,
            &mut key,
        );
        let iv = [b' '; 16];
        let ciphertext = cbc::Encryptor::<Aes128>::new((&key).into(), (&iv).into())
            .encrypt_padded_vec_mut::<Pkcs7>(&plaintext);
        key.zeroize();
        plaintext.zeroize();
        let mut encrypted_value = b"v10".to_vec();
        encrypted_value.extend_from_slice(&ciphertext);

        let decrypted = decrypt_chromium_cookie(
            host,
            &encrypted_value,
            CHROMIUM_COOKIE_HOST_DIGEST_VERSION,
            safe_storage_password,
        )
        .expect("decrypt host-bound cookie");

        assert_eq!(decrypted.as_str(), expected_session_key);
    }

    #[test]
    fn claude_desktop_cookie_database_reads_text_affinity_version() {
        let connection = Connection::open_in_memory().expect("open cookie database fixture");
        connection
            .execute_batch(
                "CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);\
                 INSERT INTO meta(key, value) VALUES('version', 24);",
            )
            .expect("create cookie database metadata fixture");

        let storage_class: String = connection
            .query_row(
                "SELECT typeof(value) FROM meta WHERE key = 'version'",
                [],
                |row| row.get(0),
            )
            .expect("read metadata storage class");
        assert_eq!(storage_class, "text");

        let version = chromium_cookie_database_version(&connection);
        assert_eq!(version, CHROMIUM_COOKIE_HOST_DIGEST_VERSION);
    }

    #[test]
    fn claude_desktop_chromium_cookie_rejects_wrong_host() {
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};
        use zeroize::Zeroize;

        let safe_storage_password = b"fixture-safe-storage-password";
        let mut plaintext = Sha256::digest(b".different.example").to_vec();
        plaintext.extend_from_slice(b"sk-ant-sid-fixture-value");
        let mut key = [0_u8; CHROMIUM_COOKIE_KEY_BYTES];
        pbkdf2_hmac::<Sha1>(
            safe_storage_password,
            b"saltysalt",
            CHROMIUM_COOKIE_KEY_ITERATIONS,
            &mut key,
        );
        let iv = [b' '; 16];
        let ciphertext = cbc::Encryptor::<Aes128>::new((&key).into(), (&iv).into())
            .encrypt_padded_vec_mut::<Pkcs7>(&plaintext);
        key.zeroize();
        plaintext.zeroize();
        let mut encrypted_value = b"v10".to_vec();
        encrypted_value.extend_from_slice(&ciphertext);

        let error = decrypt_chromium_cookie(
            ".claude.ai",
            &encrypted_value,
            CHROMIUM_COOKIE_HOST_DIGEST_VERSION,
            safe_storage_password,
        )
        .expect_err("reject a cookie copied from another host");

        assert_eq!(
            error,
            "Claude Desktop's session cookie failed its host check."
        );
    }

    #[test]
    fn claude_desktop_web_target_requires_current_labeled_desktop_account() {
        let observations = vec![AgentStatusPlanObservation {
            observed_at: Some("2026-07-14T18:00:00Z".to_string()),
            evidence_method: Some("claude_desktop_session_bucket".to_string()),
            source_session_id: None,
            provider: Some("anthropic".to_string()),
            billing_provider: Some("anthropic".to_string()),
            model_provider: Some("anthropic".to_string()),
            billing_channel: Some("subscription".to_string()),
            auth_mode: Some("claude_desktop".to_string()),
            gateway_provider: None,
            subscription_product: Some("claude_max".to_string()),
            plan_type: Some("max".to_string()),
            account_label: Some("person@example.com".to_string()),
            account_id: Some("account-123".to_string()),
            organization_label: None,
            organization_id: Some("organization-456".to_string()),
            account_identifier_hash: Some("account-hash".to_string()),
            organization_identifier_hash: Some("organization-hash".to_string()),
            credential_fingerprint_hash: None,
            billing_identity_evidence: Some("provider_account_id".to_string()),
            billing_identity_confidence: AgentStatusConfidence::High,
            confidence: AgentStatusConfidence::High,
            is_current: Some(true),
        }];

        let target = claude_desktop_web_usage_target(&observations).expect("current target");

        assert_eq!(target.account_identifier_hash, "account-hash");
        assert_eq!(target.account_label, "person@example.com");
    }

    #[test]
    fn current_claude_desktop_profile_gets_safe_label_fallback() {
        let observation = claude_desktop_builder_plan_observation(
            ClaudeDesktopProfileBuilder {
                account_uuid: "account-123".to_string(),
                organization_uuids: BTreeSet::from(["organization-456".to_string()]),
                code_session_count: 1,
                ..Default::default()
            },
            "2026-07-14T18:00:00Z",
            Some("account-123"),
        )
        .expect("current Desktop observation");

        assert_eq!(observation.account_label.as_deref(), Some("Claude Desktop"));
        assert!(claude_desktop_web_usage_target(&[observation]).is_some());
    }

    #[test]
    fn claude_desktop_multi_org_account_without_current_org_omits_organization() {
        // A non-current account with session buckets under several orgs must
        // not have one picked for it: pairing an account hash with an
        // arbitrary org hash minted a chimera billing identity in production
        // (personal account + employer org). Fail closed: no org at all.
        let observation = claude_desktop_builder_plan_observation(
            ClaudeDesktopProfileBuilder {
                account_uuid: "account-multi".to_string(),
                organization_uuids: BTreeSet::from([
                    "employer-org".to_string(),
                    "personal-org".to_string(),
                ]),
                code_session_count: 2,
                ..Default::default()
            },
            "2026-07-28T10:00:00Z",
            Some("some-other-account"),
        )
        .expect("multi-org Desktop observation");

        assert_eq!(observation.organization_id, None);
        assert_eq!(observation.organization_identifier_hash, None);
        assert_eq!(
            observation.account_identifier_hash,
            billing_identity_hash("anthropic", "account", "account-multi")
        );
        assert_eq!(
            observation.billing_identity_evidence.as_deref(),
            Some("provider_account_id")
        );
        assert_eq!(observation.is_current, Some(false));
    }

    #[test]
    fn claude_desktop_single_org_account_keeps_its_organization() {
        let observation = claude_desktop_builder_plan_observation(
            ClaudeDesktopProfileBuilder {
                account_uuid: "account-single".to_string(),
                organization_uuids: BTreeSet::from(["only-org".to_string()]),
                code_session_count: 1,
                ..Default::default()
            },
            "2026-07-28T10:00:00Z",
            None,
        )
        .expect("single-org Desktop observation");

        assert_eq!(observation.organization_id.as_deref(), Some("only-org"));
        assert_eq!(
            observation.organization_identifier_hash,
            billing_identity_hash("anthropic", "organization", "only-org")
        );
        assert_eq!(observation.is_current, Some(false));
    }

    #[test]
    fn claude_desktop_current_org_wins_over_multi_org_ambiguity() {
        let observation = claude_desktop_builder_plan_observation(
            ClaudeDesktopProfileBuilder {
                account_uuid: "account-current".to_string(),
                organization_uuids: BTreeSet::from([
                    "employer-org".to_string(),
                    "personal-org".to_string(),
                ]),
                current_organization_uuid: Some("employer-org".to_string()),
                code_session_count: 2,
                ..Default::default()
            },
            "2026-07-28T10:00:00Z",
            Some("account-current"),
        )
        .expect("current multi-org Desktop observation");

        assert_eq!(observation.organization_id.as_deref(), Some("employer-org"));
        assert_eq!(
            observation.organization_identifier_hash,
            billing_identity_hash("anthropic", "organization", "employer-org")
        );
        assert_eq!(observation.is_current, Some(true));
    }

    #[test]
    fn claude_desktop_org_switch_drops_previous_org_quota_cache() {
        let target = ClaudeDesktopWebUsageTarget {
            account_identifier_hash: "account-hash".to_string(),
            account_label: "person@example.com".to_string(),
        };
        let session = ClaudeDesktopWebSession {
            session_key: Zeroizing::new("sk-ant-sid-fixture".to_string()),
            organization_id: "new-organization".to_string(),
            organization_identifier_hash: "new-organization-hash".to_string(),
        };
        let old_cache = ClaudeDesktopWebUsageCache {
            schema_version: CLAUDE_DESKTOP_USAGE_CACHE_SCHEMA_VERSION,
            account_identifier_hash: "account-hash".to_string(),
            organization_identifier_hash: "old-organization-hash".to_string(),
            observed_at_epoch_seconds: 100,
            next_refresh_after_epoch_seconds: 200,
            windows: vec![AgentQuotaWindow {
                name: "weekly".to_string(),
                used_percent: Some(99),
                ..Default::default()
            }],
            credit_balances: Vec::new(),
        };

        let cache =
            claude_desktop_attempt_cache_for_session(Some(old_cache), &target, &session, 300);

        assert_eq!(cache.organization_identifier_hash, "new-organization-hash");
        assert_eq!(cache.observed_at_epoch_seconds, 0);
        assert!(cache.windows.is_empty());
        assert!(cache.credit_balances.is_empty());
    }

    #[test]
    #[serial]
    fn claude_desktop_web_preference_is_explicit_and_disable_clears_cache() {
        let support_dir = std::env::temp_dir().join(format!(
            "ottto-claude-desktop-web-preference-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&support_dir);
        let _guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            support_dir.as_os_str().to_os_string(),
        );

        assert!(!claude_desktop_web_usage_enabled());
        assert!(set_claude_desktop_web_usage_enabled(true).expect("enable preference"));
        let marker = support_dir.join(CLAUDE_DESKTOP_USAGE_ENABLED_FILE);
        assert!(marker.is_file());
        assert_eq!(
            std::fs::metadata(&marker)
                .expect("marker metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        std::fs::write(
            support_dir.join(CLAUDE_DESKTOP_USAGE_CACHE_FILE),
            b"normalized-cache-fixture",
        )
        .expect("write cache fixture");

        assert!(!set_claude_desktop_web_usage_enabled(false).expect("disable preference"));
        assert!(!marker.exists());
        assert!(!support_dir.join(CLAUDE_DESKTOP_USAGE_CACHE_FILE).exists());

        let _ = std::fs::remove_dir_all(support_dir);
    }

    #[test]
    fn claude_oauth_usage_maps_five_hour_and_weekly_windows() {
        let json = serde_json::json!({
            "five_hour": {
                "utilization": 24.0,
                "resets_at": "2026-06-29T18:10:00.937562+00:00"
            },
            "seven_day": {
                "utilization": 72.0,
                "resets_at": "2026-07-04T05:00:00.937587+00:00"
            },
            "seven_day_sonnet": {
                "utilization": 7.0,
                "resets_at": "2026-07-04T05:00:00.937594+00:00"
            }
        });

        let windows = claude_oauth_quota_windows(&json);

        assert_eq!(windows.len(), 2);
        assert_eq!(windows[0].name, "session");
        assert_eq!(windows[0].scope, AgentQuotaWindowScope::Account);
        assert_eq!(windows[0].status, AgentQuotaWindowStatus::Ok);
        assert_eq!(windows[0].freshness, AgentQuotaWindowFreshness::Fresh);
        assert_eq!(windows[0].used_percent, Some(24));
        assert_eq!(windows[0].left_percent, Some(76));
        assert_eq!(windows[0].window_seconds, Some(5 * 60 * 60));
        assert_eq!(
            windows[0].resets_at.as_deref(),
            Some("2026-06-29T18:10:00.937562Z")
        );
        assert_eq!(windows[1].name, "weekly");
        assert_eq!(windows[1].status, AgentQuotaWindowStatus::Ok);
        assert_eq!(windows[1].used_percent, Some(72));
        assert_eq!(windows[1].left_percent, Some(28));
        assert_eq!(windows[1].window_seconds, Some(7 * 24 * 60 * 60));
        assert_eq!(
            windows[1].resets_at.as_deref(),
            Some("2026-07-04T05:00:00.937587Z")
        );
    }

    #[test]
    fn claude_oauth_usage_cache_keeps_fresh_windows() {
        let cache = ClaudeOAuthUsageCache {
            schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
            account_identifier_hash: "account-a".to_string(),
            observed_at_epoch_seconds: 100,
            next_refresh_after_epoch_seconds: 400,
            windows: vec![AgentQuotaWindow {
                name: "session".to_string(),
                scope: AgentQuotaWindowScope::Account,
                status: AgentQuotaWindowStatus::Ok,
                freshness: AgentQuotaWindowFreshness::Fresh,
                window_seconds: Some(5 * 60 * 60),
                resets_at: Some("2026-06-29T18:10:00Z".to_string()),
                used_percent: Some(25),
                left_percent: Some(75),
                ..Default::default()
            }],
            credit_balances: vec![AgentCreditBalance {
                name: "Usage credits".to_string(),
                status: AgentCreditBalanceStatus::Ok,
                freshness: AgentQuotaWindowFreshness::Fresh,
                unit: AgentCreditBalanceUnit::Usd,
                used: Some(321),
                quota: Some(500),
                remaining: Some(179),
                enabled: Some(true),
                ..Default::default()
            }],
        };

        let usage = claude_oauth_usage_from_cache(cache, 200);

        assert_eq!(usage.windows.len(), 1);
        assert_eq!(usage.windows[0].status, AgentQuotaWindowStatus::Ok);
        assert_eq!(usage.windows[0].freshness, AgentQuotaWindowFreshness::Fresh);
        assert_eq!(usage.windows[0].used_percent, Some(25));
        assert_eq!(
            usage.windows[0].observed_at.as_deref(),
            Some("1970-01-01T00:01:40Z")
        );
        assert_eq!(usage.credit_balances.len(), 1);
        assert_eq!(
            usage.credit_balances[0].freshness,
            AgentQuotaWindowFreshness::Fresh
        );
        assert_eq!(usage.credit_balances[0].used, Some(321));
    }

    #[test]
    fn claude_oauth_usage_cache_marks_old_windows_stale() {
        let cache = ClaudeOAuthUsageCache {
            schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
            account_identifier_hash: "account-a".to_string(),
            observed_at_epoch_seconds: 100,
            next_refresh_after_epoch_seconds: 400,
            windows: vec![AgentQuotaWindow {
                name: "weekly".to_string(),
                scope: AgentQuotaWindowScope::Account,
                status: AgentQuotaWindowStatus::Ok,
                freshness: AgentQuotaWindowFreshness::Fresh,
                window_seconds: Some(7 * 24 * 60 * 60),
                resets_at: Some("2026-07-04T05:00:00Z".to_string()),
                used_percent: Some(72),
                left_percent: Some(28),
                ..Default::default()
            }],
            credit_balances: vec![AgentCreditBalance {
                name: "Usage credits".to_string(),
                status: AgentCreditBalanceStatus::Ok,
                freshness: AgentQuotaWindowFreshness::Fresh,
                unit: AgentCreditBalanceUnit::Usd,
                used: Some(321),
                quota: Some(500),
                enabled: Some(true),
                ..Default::default()
            }],
        };

        // Past the account's own jittered gate, not the bare base constant.
        let usage = claude_oauth_usage_from_cache(
            cache,
            100 + claude_oauth_usage_fresh_age_seconds("account-a") + 1,
        );

        assert_eq!(usage.windows.len(), 1);
        assert_eq!(usage.windows[0].status, AgentQuotaWindowStatus::Unknown);
        assert_eq!(usage.windows[0].freshness, AgentQuotaWindowFreshness::Stale);
        assert_eq!(usage.windows[0].used_percent, Some(72));
        assert_eq!(
            usage.credit_balances[0].freshness,
            AgentQuotaWindowFreshness::Stale
        );
    }

    #[test]
    fn claude_oauth_usage_cache_discards_v1_schema() {
        let v1 = serde_json::json!({
            "schema_version": 1,
            "observed_at_epoch_seconds": 100,
            "next_refresh_after_epoch_seconds": 400,
            "windows": []
        });
        let cache: ClaudeOAuthUsageCache = serde_json::from_value(v1).unwrap();
        assert_ne!(
            cache.schema_version,
            CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION
        );
    }

    #[test]
    fn claude_oauth_usage_cache_discards_v2_schema() {
        // Version-2 caches predate `account_identifier_hash`: their numbers
        // cannot be attributed to any account, so they must be discarded on
        // upgrade rather than adopted by whoever is logged in now.
        let v2 = serde_json::json!({
            "schema_version": 2,
            "observed_at_epoch_seconds": 100,
            "next_refresh_after_epoch_seconds": 400,
            "windows": [],
            "credit_balances": []
        });
        let cache: ClaudeOAuthUsageCache = serde_json::from_value(v2).unwrap();
        assert!(cache.account_identifier_hash.is_empty());
        assert_ne!(
            cache.schema_version,
            CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION
        );
    }

    #[test]
    fn claude_oauth_account_identifier_hash_prefers_account_uuid() {
        let account_a = ClaudeCliOauthAccount {
            account_uuid: Some("acct-a".to_string()),
            email_address: Some("a@example.test".to_string()),
            organization_uuid: Some("org-shared".to_string()),
            ..ClaudeCliOauthAccount::default()
        };
        let account_b = ClaudeCliOauthAccount {
            account_uuid: Some("acct-b".to_string()),
            email_address: Some("b@example.test".to_string()),
            organization_uuid: Some("org-shared".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        let hash_a = claude_oauth_account_identifier_hash_for(&account_a);
        let hash_b = claude_oauth_account_identifier_hash_for(&account_b);

        assert_eq!(
            hash_a,
            billing_identity_hash("anthropic", "account", "acct-a").expect("account hash")
        );
        // Two accounts inside one organization must still separate.
        assert_ne!(hash_a, hash_b);

        // Falls back to organization, then email, then gives up.
        let org_only = ClaudeCliOauthAccount {
            organization_uuid: Some("org-shared".to_string()),
            ..ClaudeCliOauthAccount::default()
        };
        assert_eq!(
            claude_oauth_account_identifier_hash_for(&org_only),
            billing_identity_hash("anthropic", "organization", "org-shared")
                .expect("organization hash")
        );
        let email_only = ClaudeCliOauthAccount {
            email_address: Some("a@example.test".to_string()),
            ..ClaudeCliOauthAccount::default()
        };
        assert_eq!(
            claude_oauth_account_identifier_hash_for(&email_only),
            billing_identity_hash("anthropic", "email", "a@example.test").expect("email hash")
        );
        assert!(
            claude_oauth_account_identifier_hash_for(&ClaudeCliOauthAccount::default()).is_empty()
        );
    }

    #[test]
    #[serial]
    fn claude_oauth_usage_cache_is_not_served_across_accounts() {
        // Regression, observed live 2026-07-26 on Ottto 0.1.96: the Claude Code
        // CLI credential store is single-slot, so `/login` as a second account
        // replaces the first while this machine-global cache keeps the first
        // account's numbers. Account A's weekly window rendered under account
        // B's Team subscription, complete with A's reset boundary.
        let support_dir = std::env::temp_dir().join(format!(
            "ottto-claude-oauth-usage-cache-account-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&support_dir);
        std::fs::create_dir_all(&support_dir).expect("create support dir");
        let _guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            support_dir.as_os_str().to_os_string(),
        );

        let account_a = claude_oauth_account_identifier_hash_for(&ClaudeCliOauthAccount {
            account_uuid: Some("acct-a".to_string()),
            ..ClaudeCliOauthAccount::default()
        });
        let account_b = claude_oauth_account_identifier_hash_for(&ClaudeCliOauthAccount {
            account_uuid: Some("acct-b".to_string()),
            ..ClaudeCliOauthAccount::default()
        });
        assert_ne!(account_a, account_b);

        let now = 10_000;
        write_claude_oauth_usage_cache(&ClaudeOAuthUsageCache {
            schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
            account_identifier_hash: account_a.clone(),
            observed_at_epoch_seconds: now,
            next_refresh_after_epoch_seconds: now + CLAUDE_OAUTH_USAGE_REFRESH_SECONDS,
            windows: vec![AgentQuotaWindow {
                name: "weekly".to_string(),
                scope: AgentQuotaWindowScope::Account,
                status: AgentQuotaWindowStatus::Ok,
                freshness: AgentQuotaWindowFreshness::Fresh,
                window_seconds: Some(7 * 24 * 60 * 60),
                // Account A's reset boundary -- the tell that made the live
                // misattribution unambiguous.
                resets_at: Some("2026-08-01T05:00:00Z".to_string()),
                used_percent: Some(44),
                left_percent: Some(56),
                ..Default::default()
            }],
            credit_balances: Vec::new(),
        })
        .expect("write cache");

        // The account that wrote it still reads it.
        let served = read_claude_oauth_usage_cache(&account_a).expect("own account is served");
        assert_eq!(served.windows[0].used_percent, Some(44));

        // The replacing account must not.
        assert!(
            read_claude_oauth_usage_cache(&account_b).is_none(),
            "cache written under account A was served to account B"
        );
        // Nor may an unidentifiable credential inherit a named account's cache.
        assert!(read_claude_oauth_usage_cache("").is_none());

        // Same guard on the 429 / transport fallback path, where the 24h max
        // age applies and serving another account's numbers is worse than
        // serving none. This mirrors the `unwrap_or` in
        // `collect_claude_oauth_usage`'s 429 arm.
        let retry_after = now + CLAUDE_OAUTH_USAGE_RETRY_AFTER_FALLBACK_SECONDS;
        let fallback = read_claude_oauth_usage_cache(&account_b).unwrap_or(ClaudeOAuthUsageCache {
            schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
            account_identifier_hash: account_b.clone(),
            observed_at_epoch_seconds: now,
            next_refresh_after_epoch_seconds: retry_after,
            windows: Vec::new(),
            credit_balances: Vec::new(),
        });
        assert!(
            fallback.windows.is_empty(),
            "429 fallback served account A's windows to account B"
        );
        assert_eq!(fallback.account_identifier_hash, account_b);
        // Writing that empty cache back is what clears A's payload off disk.
        write_claude_oauth_usage_cache(&fallback).expect("write fallback cache");
        assert!(read_claude_oauth_usage_cache(&account_a).is_none());

        let _ = std::fs::remove_dir_all(&support_dir);
    }

    #[test]
    fn claude_oauth_usage_cache_account_match_is_exact_both_ways() {
        let cache = |hash: &str| ClaudeOAuthUsageCache {
            schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
            account_identifier_hash: hash.to_string(),
            observed_at_epoch_seconds: 0,
            next_refresh_after_epoch_seconds: 0,
            windows: Vec::new(),
            credit_balances: Vec::new(),
        };

        assert!(claude_oauth_usage_cache_belongs_to_account(
            &cache("account-a"),
            "account-a"
        ));
        assert!(!claude_oauth_usage_cache_belongs_to_account(
            &cache("account-a"),
            "account-b"
        ));
        // A named cache is not served to an unidentifiable credential, and an
        // unattributed cache is not adopted by a named account.
        assert!(!claude_oauth_usage_cache_belongs_to_account(
            &cache("account-a"),
            ""
        ));
        assert!(!claude_oauth_usage_cache_belongs_to_account(
            &cache(""),
            "account-a"
        ));
        // Nothing observable changed: keep serving rather than hammering a
        // rate-limited endpoint every tick.
        assert!(claude_oauth_usage_cache_belongs_to_account(&cache(""), ""));
    }

    #[test]
    fn claude_oauth_usage_cadence_is_hourly_within_a_five_minute_spread() {
        // The spread is load-spreading across our own installs, so it must be
        // bounded and deterministic -- never an open-ended random delay.
        for seed in [
            "",
            "account-a",
            "account-b",
            "9f1c0c1a4b5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7",
        ] {
            let gate = claude_oauth_usage_fresh_age_seconds(seed);
            assert!(
                (55 * 60..=65 * 60).contains(&gate),
                "gate for {seed:?} out of the 55-65 minute band: {gate}"
            );
            assert_eq!(
                gate,
                claude_oauth_usage_fresh_age_seconds(seed),
                "gate must be stable for a given account, not redrawn per call"
            );
        }
        // Different accounts land on different phases; that is the whole point.
        assert_ne!(
            claude_oauth_usage_fresh_age_seconds("account-a"),
            claude_oauth_usage_fresh_age_seconds("account-b")
        );
        // Sanity on the base cadence itself: ~24 calls/day, not ~96.
        assert_eq!(CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_SECONDS, 60 * 60);
        // The 24h max age stays a display fallback, well clear of the gate.
        assert!(
            CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
                > claude_oauth_usage_fresh_age_seconds("account-a")
        );
    }

    #[test]
    fn claude_oauth_usage_breaker_opens_on_each_trigger_class() {
        for (failure, threshold, code) in [
            (
                ClaudeOAuthUsageFailure::AuthRejected,
                CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD,
                "auth_rejected",
            ),
            (
                ClaudeOAuthUsageFailure::ResponseShape,
                CLAUDE_OAUTH_USAGE_BREAKER_SHAPE_THRESHOLD,
                "response_shape_changed",
            ),
            (
                ClaudeOAuthUsageFailure::RateLimited,
                CLAUDE_OAUTH_USAGE_BREAKER_RATE_LIMIT_THRESHOLD,
                "rate_limited",
            ),
        ] {
            let mut breaker = None;
            for attempt in 1..=threshold {
                breaker = Some(claude_oauth_usage_breaker_after_failure(
                    breaker,
                    failure,
                    "account-a",
                    "fingerprint-a",
                    1_000,
                ));
                let current = breaker.as_ref().expect("breaker");
                let open = claude_oauth_usage_breaker_is_open(current, 1_000);
                assert_eq!(
                    open,
                    attempt >= threshold,
                    "{code} opened at attempt {attempt} of {threshold}"
                );
            }
            let opened = breaker.expect("breaker");
            assert_eq!(opened.opened_by, code);
            assert_eq!(opened.opened_at_epoch_seconds, 1_000);
            assert_eq!(
                opened.reopen_after_epoch_seconds,
                1_000 + CLAUDE_OAUTH_USAGE_BREAKER_COOLDOWN_SECONDS
            );
        }
    }

    #[test]
    fn claude_oauth_usage_breaker_counts_failure_classes_separately() {
        // One 429 plus one 401 must not add up to a trip: a mixed dribble of
        // unrelated transient failures is not the structural signal.
        let mut breaker = None;
        for _ in 0..CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD {
            breaker = Some(claude_oauth_usage_breaker_after_failure(
                breaker,
                ClaudeOAuthUsageFailure::RateLimited,
                "account-a",
                "fingerprint-a",
                1_000,
            ));
        }
        let breaker = breaker.expect("breaker");
        assert!(!claude_oauth_usage_breaker_is_open(&breaker, 1_000));
        assert_eq!(breaker.auth_failures, 0);
        assert_eq!(breaker.shape_failures, 0);
    }

    #[test]
    fn claude_oauth_usage_breaker_closes_after_cooldown() {
        let mut breaker = None;
        for _ in 0..CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD {
            breaker = Some(claude_oauth_usage_breaker_after_failure(
                breaker,
                ClaudeOAuthUsageFailure::AuthRejected,
                "account-a",
                "fingerprint-a",
                1_000,
            ));
        }
        let breaker = breaker.expect("breaker");
        assert!(claude_oauth_usage_breaker_is_open(&breaker, 1_000));
        assert!(claude_oauth_usage_breaker_is_open(
            &breaker,
            1_000 + CLAUDE_OAUTH_USAGE_BREAKER_COOLDOWN_SECONDS - 1
        ));
        assert!(!claude_oauth_usage_breaker_is_open(
            &breaker,
            1_000 + CLAUDE_OAUTH_USAGE_BREAKER_COOLDOWN_SECONDS
        ));
    }

    #[test]
    fn claude_oauth_usage_config_fingerprint_tracks_the_call_it_governs() {
        let baseline = claude_oauth_usage_config_fingerprint_for(
            "https://api.anthropic.com/api/oauth/usage",
            "oauth-2025-04-20",
            "ottto/1.2.3 (subscription-usage-reader; +https://ottto.net)",
            false,
        );
        assert_eq!(
            baseline,
            claude_oauth_usage_config_fingerprint_for(
                "https://api.anthropic.com/api/oauth/usage",
                "oauth-2025-04-20",
                "ottto/1.2.3 (subscription-usage-reader; +https://ottto.net)",
                false,
            )
        );
        for changed in [
            claude_oauth_usage_config_fingerprint_for(
                "https://api.anthropic.com/api/oauth/usage/v2",
                "oauth-2025-04-20",
                "ottto/1.2.3 (subscription-usage-reader; +https://ottto.net)",
                false,
            ),
            claude_oauth_usage_config_fingerprint_for(
                "https://api.anthropic.com/api/oauth/usage",
                "oauth-2026-01-01",
                "ottto/1.2.3 (subscription-usage-reader; +https://ottto.net)",
                false,
            ),
            claude_oauth_usage_config_fingerprint_for(
                "https://api.anthropic.com/api/oauth/usage",
                "oauth-2025-04-20",
                "ottto/1.2.4 (subscription-usage-reader; +https://ottto.net)",
                false,
            ),
            // Toggling the off-switch resets the breaker: the sentinel is part
            // of the configuration the verdict was about.
            claude_oauth_usage_config_fingerprint_for(
                "https://api.anthropic.com/api/oauth/usage",
                "oauth-2025-04-20",
                "ottto/1.2.3 (subscription-usage-reader; +https://ottto.net)",
                true,
            ),
        ] {
            assert_ne!(baseline, changed);
        }
    }

    #[test]
    #[serial]
    fn claude_oauth_usage_breaker_state_is_scoped_and_resettable() {
        let support_dir = std::env::temp_dir().join(format!(
            "ottto-claude-oauth-breaker-state-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&support_dir);
        std::fs::create_dir_all(&support_dir).expect("create support dir");
        let _guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            support_dir.as_os_str().to_os_string(),
        );

        assert!(read_claude_oauth_usage_breaker("account-a", "fingerprint-a").is_none());
        for _ in 0..CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD {
            record_claude_oauth_usage_failure(
                ClaudeOAuthUsageFailure::AuthRejected,
                "account-a",
                "fingerprint-a",
                1_000,
            );
        }
        let stored =
            read_claude_oauth_usage_breaker("account-a", "fingerprint-a").expect("stored breaker");
        assert!(claude_oauth_usage_breaker_is_open(&stored, 1_000));
        // Account-keyed and config-keyed, exactly like the usage cache: a
        // different account or a changed call configuration starts clean.
        assert!(read_claude_oauth_usage_breaker("account-b", "fingerprint-a").is_none());
        assert!(read_claude_oauth_usage_breaker("account-a", "fingerprint-b").is_none());

        clear_claude_oauth_usage_breaker();
        assert!(read_claude_oauth_usage_breaker("account-a", "fingerprint-a").is_none());

        let _ = std::fs::remove_dir_all(&support_dir);
    }

    #[test]
    #[serial]
    fn claude_oauth_usage_breaker_alerts_once_and_then_skips_the_network() {
        let support_dir = std::env::temp_dir().join(format!(
            "ottto-claude-oauth-breaker-alert-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&support_dir);
        std::fs::create_dir_all(&support_dir).expect("create support dir");
        let _guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            support_dir.as_os_str().to_os_string(),
        );
        // Pin the account to "unidentifiable" (no `~/.claude.json` under this
        // HOME) so the state this test writes is the state
        // `collect_claude_oauth_usage` reads back, on any machine.
        let _home_guard = EnvVarGuard::set_os("HOME", support_dir.as_os_str().to_os_string());
        let account = claude_oauth_account_identifier_hash();
        let fingerprint = claude_oauth_usage_config_fingerprint();
        let now = current_unix_seconds();

        let mut emitted = Vec::new();
        for _ in 0..CLAUDE_OAUTH_USAGE_BREAKER_RATE_LIMIT_THRESHOLD {
            emitted.extend(record_claude_oauth_usage_failure(
                ClaudeOAuthUsageFailure::RateLimited,
                &account,
                &fingerprint,
                now,
            ));
        }
        assert_eq!(
            emitted.len(),
            1,
            "the breaker alerts on the transition, not on every failure"
        );
        assert_eq!(emitted[0].code, "claude_oauth_usage_circuit_open");
        assert_eq!(emitted[0].severity, AgentDiagnosticSeverity::Warning);
        assert!(emitted[0].message.contains("rate limited"));
        // Further failures while open must not re-alert.
        assert!(record_claude_oauth_usage_failure(
            ClaudeOAuthUsageFailure::RateLimited,
            &account,
            &fingerprint,
            now + 100,
        )
        .is_empty());

        // While open, the collector never reaches the network: it returns the
        // breaker error plus the alert without a token read or a request.
        let outcome = collect_claude_oauth_usage(&account, None);
        assert!(outcome.result.is_err());
        assert!(outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "claude_oauth_usage_circuit_open"));

        let _ = std::fs::remove_dir_all(&support_dir);
    }

    #[test]
    fn claude_oauth_usage_transient_errors_do_not_count_toward_the_breaker() {
        assert_eq!(
            claude_oauth_usage_failure_class(&ureq::Error::Status(
                401,
                ureq::Response::new(401, "Unauthorized", "{}").expect("response")
            )),
            Some(ClaudeOAuthUsageFailure::AuthRejected)
        );
        assert_eq!(
            claude_oauth_usage_failure_class(&ureq::Error::Status(
                403,
                ureq::Response::new(403, "Forbidden", "{}").expect("response")
            )),
            Some(ClaudeOAuthUsageFailure::AuthRejected)
        );
        assert_eq!(
            claude_oauth_usage_failure_class(&ureq::Error::Status(
                404,
                ureq::Response::new(404, "Not Found", "{}").expect("response")
            )),
            Some(ClaudeOAuthUsageFailure::ResponseShape)
        );
        // A 5xx is the vendor having a bad day, not a signal to stop asking.
        assert_eq!(
            claude_oauth_usage_failure_class(&ureq::Error::Status(
                503,
                ureq::Response::new(503, "Unavailable", "{}").expect("response")
            )),
            None
        );
    }

    #[test]
    #[serial]
    fn claude_oauth_usage_sentinel_disables_the_network_read() {
        let support_dir = std::env::temp_dir().join(format!(
            "ottto-claude-oauth-off-switch-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&support_dir);
        std::fs::create_dir_all(&support_dir).expect("create support dir");
        let _guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            support_dir.as_os_str().to_os_string(),
        );

        // Default (no sentinel) is enabled -- unchanged behaviour.
        assert!(!claude_oauth_usage_network_disabled());

        // A previously fetched payload that the sentinel must retire.
        write_claude_oauth_usage_cache(&ClaudeOAuthUsageCache {
            schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
            account_identifier_hash: String::new(),
            observed_at_epoch_seconds: current_unix_seconds(),
            next_refresh_after_epoch_seconds: current_unix_seconds() + 60,
            windows: vec![AgentQuotaWindow {
                name: "session".to_string(),
                scope: AgentQuotaWindowScope::Account,
                status: AgentQuotaWindowStatus::Ok,
                freshness: AgentQuotaWindowFreshness::Fresh,
                used_percent: Some(25),
                ..Default::default()
            }],
            credit_balances: Vec::new(),
        })
        .expect("write cache fixture");

        // The exact filename is a contract with the macOS Companion toggle.
        std::fs::write(
            support_dir.join("claude-oauth-usage-network-disabled"),
            b"disabled\n",
        )
        .expect("write sentinel");
        assert!(claude_oauth_usage_network_disabled());

        let outcome = collect_claude_oauth_usage(&claude_oauth_account_identifier_hash(), None);
        assert!(outcome.result.is_err());
        assert_eq!(outcome.diagnostics.len(), 1);
        assert_eq!(
            outcome.diagnostics[0].code,
            "claude_oauth_usage_network_disabled"
        );
        assert_eq!(
            outcome.diagnostics[0].severity,
            AgentDiagnosticSeverity::Info
        );
        assert!(
            !claude_oauth_usage_cache_path().exists(),
            "the off-switch retires the endpoint's cached payload too"
        );

        let _ = std::fs::remove_dir_all(&support_dir);
    }

    #[test]
    fn claude_oauth_usage_diagnostics_survive_the_backend_upload_redaction() {
        // The circuit-breaker alert reaches our servers by riding the
        // agent-status snapshot upload; `redacted_for_backend` is the only
        // transform between the collector and the wire.
        let breaker = ClaudeOAuthUsageBreaker {
            schema_version: CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION,
            account_identifier_hash: "account-a".to_string(),
            config_fingerprint: "fingerprint-a".to_string(),
            auth_failures: CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD,
            opened_at_epoch_seconds: 1_000,
            reopen_after_epoch_seconds: 1_000 + CLAUDE_OAUTH_USAGE_BREAKER_COOLDOWN_SECONDS,
            opened_by: "auth_rejected".to_string(),
            ..Default::default()
        };
        let mut snapshot = base_snapshot(
            SourceKind::ClaudeCode,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::StatusLine,
            "2026-07-26T00:00:00Z".to_string(),
            "2026-07-26T00:30:00Z".to_string(),
        );
        snapshot
            .diagnostics
            .push(claude_oauth_usage_circuit_open_diagnostic(&breaker, 1_000));
        snapshot.diagnostics.push(AgentStatusDiagnostic::source(
            "claude_oauth_usage_network_disabled",
            AgentDiagnosticSeverity::Info,
            "Claude subscription quota is read from Claude Code's local statusLine only: the Claude OAuth usage network read is switched off on this machine.",
        ));

        let uploaded = snapshot.redacted_for_backend();
        let codes: Vec<&str> = uploaded
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect();
        assert_eq!(
            codes,
            vec![
                "claude_oauth_usage_circuit_open",
                "claude_oauth_usage_network_disabled"
            ]
        );
        // Codes and messages must survive intact -- a redacted message would
        // reach the backend as "diagnostic redacted" and the alert would be
        // useless.
        assert!(uploaded.diagnostics.iter().all(|diagnostic| {
            diagnostic.message != "diagnostic redacted" && diagnostic.code != "redacted"
        }));
    }

    #[test]
    fn claude_oauth_spend_disabled_emits_no_credit_balance() {
        // Live disabled-state sample observed 2026-07-06 (Max account).
        let json = serde_json::json!({
            "spend": {
                "used": {"amount_minor": 0, "currency": "USD", "exponent": 2},
                "limit": null, "cap": null, "balance": null,
                "percent": 0, "severity": "normal", "enabled": false,
                "can_purchase_credits": false, "can_toggle": false
            },
            "extra_usage": {"is_enabled": false, "monthly_limit": null, "used_credits": null}
        });
        assert!(claude_oauth_credit_balances(&json).is_empty());
    }

    #[test]
    fn claude_oauth_spend_enabled_maps_usage_credit_balance() {
        let json = serde_json::json!({
            "spend": {
                "used": {"amount_minor": 321, "currency": "USD", "exponent": 2},
                "cap": {"amount_minor": 500, "currency": "USD", "exponent": 2},
                "balance": {"amount_minor": 179, "currency": "USD", "exponent": 2},
                "percent": 64, "severity": "warning", "enabled": true
            }
        });
        let balances = claude_oauth_credit_balances(&json);
        assert_eq!(balances.len(), 1);
        let credit = &balances[0];
        assert_eq!(credit.name, "Usage credits");
        assert_eq!(credit.unit, AgentCreditBalanceUnit::Usd);
        assert_eq!(credit.status, AgentCreditBalanceStatus::Low);
        assert_eq!(credit.used, Some(321));
        assert_eq!(credit.quota, Some(500));
        assert_eq!(credit.remaining, Some(179));
        assert_eq!(credit.used_percent, Some(64));
        assert_eq!(credit.currency.as_deref(), Some("USD"));
        assert_eq!(credit.enabled, Some(true));
    }

    #[test]
    fn claude_oauth_spend_falls_back_to_limit_and_derives_remaining() {
        let json = serde_json::json!({
            "spend": {
                "used": {"amount_minor": 500, "currency": "USD", "exponent": 2},
                "limit": 5.0,
                "severity": "critical",
                "enabled": true
            }
        });
        let balances = claude_oauth_credit_balances(&json);
        assert_eq!(balances.len(), 1);
        assert_eq!(balances[0].status, AgentCreditBalanceStatus::Exhausted);
        assert_eq!(balances[0].used, Some(500));
        assert_eq!(balances[0].quota, Some(500));
        assert_eq!(balances[0].remaining, Some(0));
    }

    #[test]
    fn claude_oauth_money_cents_normalizes_exponents_and_bare_numbers() {
        let object = serde_json::json!({"amount_minor": 3215, "exponent": 3});
        assert_eq!(claude_oauth_money_cents(Some(&object)), Some(322));
        let zero_exp = serde_json::json!({"amount_minor": 5, "exponent": 0});
        assert_eq!(claude_oauth_money_cents(Some(&zero_exp)), Some(500));
        let bare = serde_json::json!(5.0);
        assert_eq!(claude_oauth_money_cents(Some(&bare)), Some(500));
        let negative = serde_json::json!({"amount_minor": -1, "exponent": 2});
        assert_eq!(claude_oauth_money_cents(Some(&negative)), None);
        assert_eq!(claude_oauth_money_cents(None), None);
    }

    #[test]
    fn claude_oauth_extra_usage_fallback_maps_credit_balance() {
        let json = serde_json::json!({
            "extra_usage": {
                "is_enabled": true,
                "monthly_limit": 5.0,
                "used_credits": 3.21,
                "utilization": 64,
                "currency": "USD"
            }
        });
        let balances = claude_oauth_credit_balances(&json);
        assert_eq!(balances.len(), 1);
        assert_eq!(balances[0].used, Some(321));
        assert_eq!(balances[0].quota, Some(500));
        assert_eq!(balances[0].remaining, Some(179));
        assert_eq!(balances[0].used_percent, Some(64));
    }

    #[test]
    fn claude_oauth_scoped_limits_map_model_windows_and_skip_account_kinds() {
        let json = serde_json::json!({
            "five_hour": {"utilization": 0.0, "resets_at": "2026-07-06T22:40:00+00:00"},
            "seven_day": {"utilization": 82.0, "resets_at": "2026-07-11T05:00:00+00:00"},
            "limits": [
                {"kind": "session", "group": "session", "percent": 0,
                 "severity": "normal", "resets_at": "2026-07-06T22:40:00+00:00",
                 "scope": null, "is_active": false},
                {"kind": "weekly_all", "group": "weekly", "percent": 82,
                 "severity": "warning", "resets_at": "2026-07-11T05:00:00+00:00",
                 "scope": null, "is_active": false},
                {"kind": "weekly_scoped", "group": "weekly", "percent": 98,
                 "severity": "critical", "resets_at": "2026-07-11T05:00:00+00:00",
                 "scope": {"model": {"id": null, "display_name": "Fable"}},
                 "is_active": true}
            ]
        });
        let windows = claude_oauth_quota_windows(&json);
        // session + weekly account windows, plus exactly one scoped model window
        assert_eq!(windows.len(), 3);
        let scoped = &windows[2];
        assert_eq!(scoped.name, "weekly_scoped");
        assert_eq!(scoped.scope, AgentQuotaWindowScope::Model);
        assert_eq!(scoped.model.as_deref(), Some("Fable"));
        assert_eq!(scoped.used_percent, Some(98));
        assert_eq!(scoped.group.as_deref(), Some("weekly"));
        assert_eq!(scoped.severity.as_deref(), Some("critical"));
        assert_eq!(scoped.is_active, Some(true));
    }

    #[test]
    fn claude_oauth_window_dollar_fields_map_to_cents() {
        let json = serde_json::json!({
            "five_hour": {
                "utilization": 24.0,
                "resets_at": "2026-06-29T18:10:00+00:00",
                "limit_dollars": 25.0,
                "used_dollars": 6.0,
                "remaining_dollars": 19.0
            }
        });
        let windows = claude_oauth_quota_windows(&json);
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].limit_cents, Some(2500));
        assert_eq!(windows[0].used_cents, Some(600));
        assert_eq!(windows[0].remaining_cents, Some(1900));
    }

    /// The hash a Claude Desktop plan observation would carry for `account_uuid`
    /// -- the same `billing_identity_hash` shape
    /// `claude_desktop_builder_plan_observation` produces.
    fn observable_account_hashes(account_uuids: &[&str]) -> Vec<String> {
        account_uuids
            .iter()
            .filter_map(|uuid| billing_identity_hash("anthropic", "account", uuid))
            .collect()
    }

    #[test]
    fn claude_statusline_sample_is_attributed_only_to_the_account_that_owns_the_credential() {
        let account_a = claude_account_identifier_hash(Some("acct-a"), None, None);
        let account_b = claude_account_identifier_hash(Some("acct-b"), None, None);
        assert_ne!(account_a, account_b);

        // Same account, nothing else on the machine: provable, so serve it.
        assert_eq!(
            claude_statusline_attribution_failure(&account_a, &account_a, &[]),
            None
        );
        // A Desktop observation for the SAME account is not a second account.
        assert_eq!(
            claude_statusline_attribution_failure(
                &account_a,
                &account_a,
                &observable_account_hashes(&["acct-a"])
            ),
            None
        );

        // Written under a credential that has since been replaced.
        assert_eq!(
            claude_statusline_attribution_failure(&account_a, &account_b, &[]),
            Some(ClaudeStatusLineUnattributable::CredentialReplaced)
        );

        // An unnamed account on either side matches nothing. Unlike the OAuth
        // cache, two empty hashes must NOT match here: statusLine re-observes on
        // the next render, so refusing costs nothing.
        assert_eq!(
            claude_statusline_attribution_failure("", &account_a, &[]),
            Some(ClaudeStatusLineUnattributable::AccountUnknown)
        );
        assert_eq!(
            claude_statusline_attribution_failure(&account_a, "", &[]),
            Some(ClaudeStatusLineUnattributable::AccountUnknown)
        );
        assert_eq!(
            claude_statusline_attribution_failure("", "", &[]),
            Some(ClaudeStatusLineUnattributable::AccountUnknown)
        );
    }

    #[test]
    fn claude_statusline_sample_is_refused_when_a_second_claude_account_exists() {
        // The live 2026-07-26 repro, which plain account-keying does NOT catch:
        // the CLI credential was the work Team account both when the sample was
        // written and when it was read, so the write-time key matched -- while
        // the numbers came from the personal Max account rendering in the Claude
        // Desktop app's "Code" tab, through the same wrapper, into the same
        // machine-global file.
        let team = claude_account_identifier_hash(Some("acct-team"), None, None);

        assert_eq!(
            claude_statusline_attribution_failure(
                &team,
                &team,
                &observable_account_hashes(&["acct-max"])
            ),
            Some(ClaudeStatusLineUnattributable::MultipleAccounts),
            "a matching write-time key is not proof while a second Claude account can write this cache"
        );

        // Observations that name no account cannot establish a second one --
        // `claude_account_identifier_hashes_from_observations` drops them.
        assert!(claude_account_identifier_hashes_from_observations(&[]).is_empty());
        assert_eq!(
            claude_statusline_attribution_failure(&team, &team, &[]),
            None
        );
    }

    #[test]
    #[serial]
    fn claude_statusline_quota_is_not_served_across_accounts() {
        let support_dir = std::env::temp_dir().join(format!(
            "ottto-claude-statusline-account-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&support_dir);
        std::fs::create_dir_all(&support_dir).expect("create support dir");
        let _guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            support_dir.as_os_str().to_os_string(),
        );

        let account_a = claude_account_identifier_hash(Some("acct-a"), None, None);
        let account_b = claude_account_identifier_hash(Some("acct-b"), None, None);
        let now = current_unix_seconds();
        write_claude_statusline_cache(
            &support_dir,
            &ClaudeStatusLineRateLimitCache {
                schema_version: CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
                observed_under_account_identifier_hash: account_a.clone(),
                observed_at_epoch_seconds: now,
                windows: vec![ClaudeStatusLineRateLimitWindow {
                    name: "seven_day".to_string(),
                    used_percent: 44,
                    resets_at_epoch_seconds: now + 7 * 24 * 60 * 60,
                }],
            },
        )
        .expect("write cache");

        // Its own account, alone on the machine: served.
        match collect_claude_statusline_quota_windows(&account_a, &[]).expect("collect") {
            ClaudeStatusLineQuota::Windows(windows) => {
                assert_eq!(windows.len(), 1);
                assert_eq!(windows[0].used_percent, Some(44));
            }
            other => panic!("own account was not served: {other:?}"),
        }

        // The replacing account must not be shown account A's 44%.
        assert_eq!(
            collect_claude_statusline_quota_windows(&account_b, &[]).expect("collect"),
            ClaudeStatusLineQuota::Unattributable(
                ClaudeStatusLineUnattributable::CredentialReplaced
            )
        );

        // Nor may a matching key be served while a second Claude account can
        // write the same file.
        assert_eq!(
            collect_claude_statusline_quota_windows(
                &account_a,
                &observable_account_hashes(&["acct-max"])
            )
            .expect("collect"),
            ClaudeStatusLineQuota::Unattributable(ClaudeStatusLineUnattributable::MultipleAccounts)
        );

        // A pre-fix (v1) cache carries no account identity and is discarded
        // outright rather than adopted by whoever is signed in now.
        std::fs::write(
            support_dir.join("claude-code-rate-limits.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "schema_version": 1,
                "observed_at_epoch_seconds": now,
                "windows": [{
                    "name": "seven_day",
                    "used_percent": 44,
                    "resets_at_epoch_seconds": now + 7 * 24 * 60 * 60
                }]
            }))
            .expect("serialize v1"),
        )
        .expect("write v1 cache");
        assert_eq!(
            collect_claude_statusline_quota_windows(&account_a, &[]).expect("collect"),
            ClaudeStatusLineQuota::NotObserved
        );

        let _ = std::fs::remove_dir_all(&support_dir);
    }

    #[test]
    fn claude_statusline_cache_maps_fresh_windows() {
        let cache = ClaudeStatusLineRateLimitCache {
            schema_version: CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
            observed_under_account_identifier_hash: "account-a".to_string(),
            observed_at_epoch_seconds: 100,
            windows: vec![
                ClaudeStatusLineRateLimitWindow {
                    name: "five_hour".to_string(),
                    used_percent: 24,
                    resets_at_epoch_seconds: 200,
                },
                ClaudeStatusLineRateLimitWindow {
                    name: "seven_day".to_string(),
                    used_percent: 91,
                    resets_at_epoch_seconds: 300,
                },
            ],
        };

        let windows = claude_statusline_quota_windows_from_cache(cache, 150);

        assert_eq!(windows.len(), 2);
        assert_eq!(windows[0].name, "session");
        assert_eq!(windows[0].scope, AgentQuotaWindowScope::Account);
        assert_eq!(windows[0].status, AgentQuotaWindowStatus::Ok);
        assert_eq!(windows[0].used_percent, Some(24));
        assert_eq!(windows[0].left_percent, Some(76));
        assert_eq!(windows[0].window_seconds, Some(5 * 60 * 60));
        assert_eq!(
            windows[0].observed_at.as_deref(),
            Some("1970-01-01T00:01:40Z")
        );
        assert_eq!(windows[1].name, "weekly");
        assert_eq!(windows[1].status, AgentQuotaWindowStatus::NearLimit);
        assert_eq!(windows[1].window_seconds, Some(7 * 24 * 60 * 60));
        // Every served statusLine window names the account whose credential
        // was active when the CLI writer observed it.
        assert_eq!(
            windows[0].account_identifier_hash.as_deref(),
            Some("account-a")
        );
        assert_eq!(
            windows[1].account_identifier_hash.as_deref(),
            Some("account-a")
        );
    }

    #[test]
    fn claude_statusline_windows_from_unidentified_writer_stay_unstamped() {
        let cache = ClaudeStatusLineRateLimitCache {
            schema_version: CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
            observed_under_account_identifier_hash: String::new(),
            observed_at_epoch_seconds: 100,
            windows: vec![ClaudeStatusLineRateLimitWindow {
                name: "five_hour".to_string(),
                used_percent: 24,
                resets_at_epoch_seconds: 200,
            }],
        };

        let windows = claude_statusline_quota_windows_from_cache(cache, 150);

        assert_eq!(windows.len(), 1);
        assert_eq!(
            windows[0].account_identifier_hash, None,
            "an unidentifiable writer must serve as unknown, never as a guessed account"
        );
    }

    #[test]
    fn claude_oauth_usage_stamps_served_windows_and_balances() {
        let mut usage = ClaudeOAuthUsage {
            windows: vec![
                AgentQuotaWindow {
                    name: "session".to_string(),
                    scope: AgentQuotaWindowScope::Account,
                    ..Default::default()
                },
                AgentQuotaWindow {
                    name: "weekly".to_string(),
                    scope: AgentQuotaWindowScope::Account,
                    ..Default::default()
                },
            ],
            credit_balances: vec![AgentCreditBalance {
                name: "Usage credits".to_string(),
                ..Default::default()
            }],
        };

        claude_oauth_stamp_account_identity(&mut usage, "account-hash", Some("org-hash"));

        for window in &usage.windows {
            assert_eq!(
                window.account_identifier_hash.as_deref(),
                Some("account-hash")
            );
            assert_eq!(
                window.organization_identifier_hash.as_deref(),
                Some("org-hash")
            );
        }
        assert_eq!(
            usage.credit_balances[0].account_identifier_hash.as_deref(),
            Some("account-hash")
        );
        assert_eq!(
            usage.credit_balances[0]
                .organization_identifier_hash
                .as_deref(),
            Some("org-hash")
        );

        // Negative control: an unresolved account stamps nothing -- unknown
        // must stay unknown downstream, never become a guessed identity.
        let mut unresolved = ClaudeOAuthUsage {
            windows: vec![AgentQuotaWindow {
                name: "session".to_string(),
                ..Default::default()
            }],
            credit_balances: Vec::new(),
        };
        claude_oauth_stamp_account_identity(&mut unresolved, "", Some(""));
        assert_eq!(unresolved.windows[0].account_identifier_hash, None);
        assert_eq!(unresolved.windows[0].organization_identifier_hash, None);
    }

    #[test]
    fn claude_statusline_cache_skips_expired_and_unknown_windows() {
        let cache = ClaudeStatusLineRateLimitCache {
            schema_version: CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
            observed_under_account_identifier_hash: "account-a".to_string(),
            observed_at_epoch_seconds: 100,
            windows: vec![
                ClaudeStatusLineRateLimitWindow {
                    name: "five_hour".to_string(),
                    used_percent: 100,
                    resets_at_epoch_seconds: 150,
                },
                ClaudeStatusLineRateLimitWindow {
                    name: "monthly".to_string(),
                    used_percent: 10,
                    resets_at_epoch_seconds: 300,
                },
                ClaudeStatusLineRateLimitWindow {
                    name: "seven_day".to_string(),
                    used_percent: 100,
                    resets_at_epoch_seconds: 300,
                },
            ],
        };

        let windows = claude_statusline_quota_windows_from_cache(cache, 150);

        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].name, "weekly");
        assert_eq!(windows[0].status, AgentQuotaWindowStatus::Exhausted);
        assert_eq!(windows[0].left_percent, Some(0));
    }

    #[test]
    fn claude_statusline_cache_marks_old_windows_stale() {
        let cache = ClaudeStatusLineRateLimitCache {
            schema_version: CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
            observed_under_account_identifier_hash: "account-a".to_string(),
            observed_at_epoch_seconds: 100,
            windows: vec![ClaudeStatusLineRateLimitWindow {
                name: "five_hour".to_string(),
                used_percent: 24,
                resets_at_epoch_seconds: 2_000,
            }],
        };

        let windows = claude_statusline_quota_windows_from_cache(
            cache,
            100 + CLAUDE_STATUSLINE_CACHE_FRESH_AGE_SECONDS + 1,
        );

        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].name, "session");
        assert_eq!(windows[0].status, AgentQuotaWindowStatus::Stale);
        assert_eq!(windows[0].freshness, AgentQuotaWindowFreshness::Stale);
        assert_eq!(windows[0].used_percent, Some(24));
        assert_eq!(windows[0].left_percent, Some(76));
    }

    #[test]
    fn claude_statusline_context_cache_maps_live_context() {
        let cache = ClaudeStatusLineContextWindowCache {
            schema_version: 1,
            observed_at_epoch_seconds: 100,
            active_tokens: Some(42_000),
            max_tokens: Some(1_000_000),
            used_percent: Some(4),
            remaining_tokens: Some(958_000),
        };

        let context = claude_statusline_context_from_cache(cache, None);

        assert_eq!(context.status, AgentContextState::Available);
        assert_eq!(context.active_tokens, Some(42_000));
        assert_eq!(context.max_tokens, Some(1_000_000));
        assert_eq!(context.used_percent, Some(4));
        assert_eq!(context.remaining_tokens, Some(958_000));
        assert_eq!(
            context.completeness,
            Some(AgentContextCompleteness::FullPressure)
        );
        assert_eq!(context.reason.as_deref(), Some("full_pressure_observed"));
        assert_eq!(
            context.source.as_deref(),
            Some("claude_statusline_context_window")
        );
    }

    #[test]
    fn claude_statusline_context_cache_maps_window_size_only() {
        let cache = ClaudeStatusLineContextWindowCache {
            schema_version: 1,
            observed_at_epoch_seconds: 100,
            active_tokens: None,
            max_tokens: Some(1_000_000),
            used_percent: None,
            remaining_tokens: None,
        };

        let context = claude_statusline_context_from_cache(cache, None);

        assert_eq!(context.status, AgentContextState::Available);
        assert_eq!(context.active_tokens, None);
        assert_eq!(context.max_tokens, Some(1_000_000));
        assert_eq!(context.used_percent, None);
        assert_eq!(context.remaining_tokens, None);
        assert_eq!(
            context.completeness,
            Some(AgentContextCompleteness::WindowSizeOnly)
        );
        assert_eq!(context.reason.as_deref(), Some("context_window_size_only"));
        assert!(context.recent_samples.is_empty());
    }

    #[test]
    fn claude_statusline_context_cache_normalizes_legacy_zero_sentinel() {
        let now = current_unix_seconds();
        let cache = ClaudeStatusLineContextWindowCache {
            schema_version: 1,
            observed_at_epoch_seconds: now,
            active_tokens: Some(0),
            max_tokens: Some(1_000_000),
            used_percent: None,
            remaining_tokens: Some(1_000_000),
        };
        let history = ClaudeStatusLineContextWindowHistory {
            schema_version: 1,
            samples: vec![ClaudeStatusLineContextWindowSample {
                observed_at_epoch_seconds: now.saturating_sub(60),
                active_tokens: Some(0),
                max_tokens: Some(1_000_000),
                used_percent: None,
                remaining_tokens: Some(1_000_000),
            }],
        };

        let context = claude_statusline_context_from_cache(cache, Some(history));

        assert_eq!(context.status, AgentContextState::Available);
        assert_eq!(context.active_tokens, None);
        assert_eq!(context.max_tokens, Some(1_000_000));
        assert_eq!(context.used_percent, None);
        assert_eq!(context.remaining_tokens, None);
        assert_eq!(
            context.completeness,
            Some(AgentContextCompleteness::WindowSizeOnly)
        );
        assert_eq!(context.reason.as_deref(), Some("context_window_size_only"));
        assert!(context.recent_samples.is_empty());
    }

    #[test]
    fn claude_statusline_context_cache_maps_recent_history_samples() {
        let now = current_unix_seconds();
        let cache = ClaudeStatusLineContextWindowCache {
            schema_version: 1,
            observed_at_epoch_seconds: now,
            active_tokens: Some(45_000),
            max_tokens: Some(1_000_000),
            used_percent: Some(5),
            remaining_tokens: Some(955_000),
        };
        let history = ClaudeStatusLineContextWindowHistory {
            schema_version: 1,
            samples: vec![
                ClaudeStatusLineContextWindowSample {
                    observed_at_epoch_seconds: now.saturating_sub(120),
                    active_tokens: Some(40_000),
                    max_tokens: Some(1_000_000),
                    used_percent: Some(4),
                    remaining_tokens: Some(960_000),
                },
                ClaudeStatusLineContextWindowSample {
                    observed_at_epoch_seconds: now.saturating_sub(60),
                    active_tokens: Some(42_000),
                    max_tokens: Some(1_000_000),
                    used_percent: Some(4),
                    remaining_tokens: Some(958_000),
                },
            ],
        };

        let context = claude_statusline_context_from_cache(cache, Some(history));

        assert_eq!(context.recent_samples.len(), 3);
        assert_eq!(context.recent_samples[0].active_tokens, Some(40_000));
        assert_eq!(context.recent_samples[1].active_tokens, Some(42_000));
        assert_eq!(context.recent_samples[2].active_tokens, Some(45_000));
    }

    #[test]
    fn secret_keys_are_removed_from_pi_metadata() {
        let stripped = strip_secret_json(serde_json::json!({
            "email": "pi@example.com",
            "api_key": "secret",
            "nested": {"refresh_token": "secret", "org": "team"}
        }));

        assert_eq!(
            first_json_string(&stripped, &["email"]).as_deref(),
            Some("pi@example.com")
        );
        assert!(first_json_string(&stripped, &["api_key", "refresh_token"]).is_none());
        assert_eq!(
            first_json_string(&stripped, &["org"]).as_deref(),
            Some("team")
        );
    }

    #[test]
    fn pi_model_table_parser_preserves_provider_billing_and_capabilities() {
        let output = CommandOutput {
            command_found: true,
            success: true,
            status_code: Some(0),
            stdout: String::new(),
            stderr: "\
provider        model                                  context  max-out  thinking  images
openai-codex    gpt-5.4-mini                           272K     128K     yes       yes
google-vertex   gemini-2.5-flash-lite                  1.0M     65.5K    yes       yes
amazon-bedrock  global.anthropic.claude-sonnet-4-6     1M       64K      yes       yes
"
            .to_string(),
        };

        let model_status = collect_pi_model_status_from_output(&output, None);

        assert_eq!(model_status.provider.as_deref(), Some("multi_provider"));
        assert_eq!(model_status.available_models.len(), 3);
        assert_eq!(model_status.available_model_details.len(), 3);
        assert_eq!(
            model_status.available_model_details[0]
                .billing_provider
                .as_deref(),
            Some("openai")
        );
        assert_eq!(
            model_status.available_model_details[1]
                .billing_provider
                .as_deref(),
            Some("google")
        );
        assert_eq!(
            model_status.available_model_details[2]
                .billing_provider
                .as_deref(),
            Some("anthropic")
        );
        assert_eq!(
            model_status.available_model_details[0]
                .source_category
                .as_deref(),
            Some("chatgpt_openai_subscription")
        );
        assert_eq!(
            model_status.available_model_details[1]
                .source_category
                .as_deref(),
            Some("google_cloud_vertex")
        );
        assert_eq!(
            model_status.available_model_details[2]
                .model_provider
                .as_deref(),
            Some("anthropic")
        );
        assert_eq!(
            model_status.available_model_details[0].context_window_tokens,
            Some(272_000)
        );
        assert_eq!(
            model_status.available_model_details[1].max_output_tokens,
            Some(65_500)
        );
        assert_eq!(
            model_status.available_model_details[2]
                .billing_channel
                .as_deref(),
            Some("amazon_bedrock")
        );
        assert_eq!(
            model_status.available_model_details[2].supports_images,
            Some(true)
        );
    }

    #[test]
    fn pi_settings_parser_prefers_enabled_default_route() {
        let settings = serde_json::json!({
            "defaultProvider": "openai-codex",
            "defaultModel": "gpt-5.4-mini",
            "defaultThinkingLevel": "high",
            "enabledModels": [
                {"provider": "openai-codex", "model": "gpt-5.4-mini"},
                {"provider": "google-vertex", "model": "gemini-2.5-flash-lite"},
                "amazon-bedrock/global.anthropic.claude-sonnet-4-6"
            ]
        });

        let model_status = collect_pi_model_status_from_settings(&settings, None);

        assert_eq!(model_status.active_model.as_deref(), Some("gpt-5.4-mini"));
        assert_eq!(model_status.default_model.as_deref(), Some("gpt-5.4-mini"));
        assert_eq!(model_status.provider.as_deref(), Some("multi_provider"));
        assert_eq!(model_status.available_model_details.len(), 3);
        assert_eq!(
            model_status.available_model_details[0].provider.as_deref(),
            Some("openai-codex")
        );
        assert_eq!(
            model_status.available_model_details[0].supports_thinking,
            Some(true)
        );
        assert_eq!(
            model_status.available_model_details[2]
                .billing_channel
                .as_deref(),
            Some("amazon_bedrock")
        );

        let routes = collect_pi_routes_from_settings(&settings);
        assert_eq!(routes.len(), 3);
        assert_eq!(routes[0].provider, "openai-codex");
        assert_eq!(routes[0].thinking_level.as_deref(), Some("high"));
        assert_eq!(
            routes[1].classification.source_category.as_deref(),
            Some("google_cloud_vertex")
        );
    }

    #[test]
    fn pi_smoke_route_prefers_default_model_only() {
        let settings = serde_json::json!({
            "defaultProvider": "google-vertex",
            "defaultModel": "gemini-3.1-pro-preview-customtools",
            "defaultThinkingLevel": "high",
            "enabledModels": [
                "google-vertex/gemini-3.1-pro-preview-customtools:xhigh",
                "google-vertex/gemini-3.1-pro-preview:xhigh",
                "google-vertex/gemini-2.5-pro:xhigh"
            ]
        });

        let route = collect_default_pi_smoke_route_from_settings(&settings)
            .expect("default Pi smoke route");

        assert_eq!(route.provider, "google-vertex");
        assert_eq!(route.model, "gemini-3.1-pro-preview-customtools");
        assert_eq!(route.thinking_level.as_deref(), Some("high"));
    }

    #[test]
    fn pi_settings_parser_splits_string_route_thinking_suffix() {
        let settings = serde_json::json!({
            "defaultProvider": "google-vertex",
            "defaultModel": "gemini-3.1-pro-preview-customtools",
            "defaultThinkingLevel": "high",
            "enabledModels": [
                "OpenAI Codex/gpt-5.5:xhigh",
                "Google Vertex/gemini-3.1-pro-preview:xhigh"
            ]
        });

        let routes = collect_pi_routes_from_settings(&settings);

        assert_eq!(routes.len(), 3);
        assert_eq!(routes[0].provider, "OpenAI Codex");
        assert_eq!(routes[0].model, "gpt-5.5");
        assert_eq!(routes[0].thinking_level.as_deref(), Some("xhigh"));
        assert_eq!(
            routes[0].classification.source_category.as_deref(),
            Some("chatgpt_openai_subscription")
        );
        assert_eq!(routes[1].provider, "Google Vertex");
        assert_eq!(routes[1].model, "gemini-3.1-pro-preview");
        assert_eq!(routes[1].thinking_level.as_deref(), Some("xhigh"));
        assert_eq!(
            routes[1].classification.source_category.as_deref(),
            Some("google_cloud_vertex")
        );
        assert_eq!(routes[2].provider, "google-vertex");
        assert_eq!(routes[2].model, "gemini-3.1-pro-preview-customtools");

        let model_status = collect_pi_model_status_from_settings(&settings, None);
        assert_eq!(model_status.available_model_details[0].id, "gpt-5.5");
        assert_eq!(
            model_status.available_model_details[0].provider.as_deref(),
            Some("OpenAI Codex")
        );
        assert_eq!(
            model_status.available_model_details[0]
                .billing_channel
                .as_deref(),
            Some("subscription")
        );
        assert_eq!(
            model_status.available_model_details[1]
                .billing_channel
                .as_deref(),
            Some("google_vertex")
        );
    }

    #[test]
    fn pi_route_classifier_maps_supported_platforms() {
        let openai = pi_route_classification("openai", "gpt-5.4-mini");
        assert_eq!(openai.source_category.as_deref(), Some("openai_api_key"));
        assert_eq!(openai.auth_mode.as_deref(), Some("api_key"));

        let codex_subscription = pi_route_classification("OpenAI Codex", "gpt-5.5");
        assert_eq!(
            codex_subscription.billing_channel.as_deref(),
            Some("subscription")
        );
        assert_eq!(codex_subscription.auth_mode.as_deref(), Some("oauth"));
        assert_eq!(
            codex_subscription.source_category.as_deref(),
            Some("chatgpt_openai_subscription")
        );

        let vertex = pi_route_classification("google-vertex", "gemini-2.5-flash-lite");
        assert_eq!(vertex.billing_channel.as_deref(), Some("google_vertex"));
        assert_eq!(
            vertex.source_category.as_deref(),
            Some("google_cloud_vertex")
        );

        let display_vertex = pi_route_classification("Google Vertex", "gemini-3.1-pro-preview");
        assert_eq!(
            display_vertex.billing_channel.as_deref(),
            Some("google_vertex")
        );
        assert_eq!(display_vertex.auth_mode.as_deref(), Some("service_account"));
        assert_eq!(
            display_vertex.source_category.as_deref(),
            Some("google_cloud_vertex")
        );

        let bedrock =
            pi_route_classification("amazon-bedrock", "global.anthropic.claude-sonnet-4-6");
        assert_eq!(bedrock.billing_provider.as_deref(), Some("anthropic"));
        assert_eq!(bedrock.source_category.as_deref(), Some("aws_bedrock"));

        let gateway = pi_route_classification("vercel-ai-gateway", "openai.gpt-5.4-mini");
        assert_eq!(gateway.billing_channel.as_deref(), Some("gateway"));
        assert_eq!(
            gateway.gateway_provider.as_deref(),
            Some("vercel_ai_gateway")
        );
    }

    fn claude_settings_fixture(name: &str, body: &str) -> (PathBuf, Vec<(String, PathBuf)>) {
        let root = std::env::temp_dir().join(format!(
            "ottto-claude-runtime-defaults-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let claude_dir = root.join(".claude");
        std::fs::create_dir_all(&claude_dir).expect("create .claude");
        if !body.is_empty() {
            std::fs::write(claude_dir.join("settings.json"), body).expect("write settings");
        }
        let paths = vec![
            (
                "claude_code.settings".to_string(),
                claude_dir.join("settings.json"),
            ),
            (
                "claude_code.settings_local".to_string(),
                claude_dir.join("settings.local.json"),
            ),
            (
                "claude_code.managed_settings".to_string(),
                root.join("managed-settings.json"),
            ),
        ];
        (root, paths)
    }

    #[test]
    fn claude_runtime_defaults_carry_config_file_provenance() {
        let (root, paths) = claude_settings_fixture(
            "provenance",
            "{\"model\": \"claude-opus-4-7\", \"permissions\": {\"defaultMode\": \"plan\"}}\n",
        );

        let capture = claude_runtime_defaults_from_paths("2026-07-25T10:00:00Z", &paths);
        let defaults = capture.defaults.expect("runtime defaults present");
        assert_eq!(defaults.provenance.as_deref(), Some("config_file"));
        // The backend fills machine_id from the stored snapshot.
        assert_eq!(defaults.machine_id, None);
        assert_eq!(
            defaults.captured_at.as_deref(),
            Some("2026-07-25T10:00:00Z")
        );
        assert_eq!(defaults.model.as_deref(), Some("claude-opus-4-7"));
        assert_eq!(defaults.approval_policy.as_deref(), Some("plan"));
        assert_eq!(capture.capability.capability, "runtime_defaults");
        assert_eq!(capture.capability.status, AgentCapabilityStatus::Supported);
        assert!(capture.diagnostic.is_none());

        // The strict backend schema must accept what we emit unchanged.
        let mut snapshot = base_snapshot(
            SourceKind::ClaudeCode,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::CliJson,
            "2026-07-25T10:00:00Z".to_string(),
            "2026-07-25T10:05:00Z".to_string(),
        );
        snapshot.runtime_defaults = Some(defaults);
        let redacted = snapshot.redacted_for_backend();
        let survived = redacted.runtime_defaults.expect("survives redaction");
        assert_eq!(survived.model.as_deref(), Some("claude-opus-4-7"));
        assert_eq!(survived.approval_policy.as_deref(), Some("plan"));

        let _ = std::fs::remove_dir_all(root);
    }

    /// Claude Code's `effortLevel` is durable: `/effort` writes it to the
    /// settings file and it persists across sessions. It maps straight through
    /// to `reasoning_effort`.
    #[test]
    fn claude_runtime_defaults_report_configured_effort_level() {
        let (root, paths) = claude_settings_fixture(
            "effort-level",
            "{\"model\": \"claude-opus-4-7\", \"effortLevel\": \"xhigh\"}\n",
        );

        let capture = claude_runtime_defaults_from_paths("2026-07-25T10:00:00Z", &paths);
        let defaults = capture.defaults.expect("runtime defaults present");
        assert_eq!(defaults.reasoning_effort.as_deref(), Some("xhigh"));
        assert_eq!(
            defaults
                .selector_sources
                .get("reasoning_effort")
                .map(String::as_str),
            Some("claude_code.settings.effortLevel")
        );
        // The Codex-shaped tier fields Claude's settings have no equivalent for
        // stay unset.
        assert_eq!(defaults.service_tier, None);
        assert_eq!(defaults.speed_mode, None);
        assert_eq!(defaults.priority_enabled, None);

        // The emitted effort value must survive the backend-facing guard.
        let mut snapshot = base_snapshot(
            SourceKind::ClaudeCode,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::CliJson,
            "2026-07-25T10:00:00Z".to_string(),
            "2026-07-25T10:05:00Z".to_string(),
        );
        snapshot.runtime_defaults = Some(defaults);
        let survived = snapshot
            .redacted_for_backend()
            .runtime_defaults
            .expect("survives redaction");
        assert_eq!(survived.reasoning_effort.as_deref(), Some("xhigh"));

        let _ = std::fs::remove_dir_all(root);
    }

    /// Absent `effortLevel` must stay absent. Claude Code's own default is not
    /// ours to invent, and an unset field is what tells the UI "not configured".
    #[test]
    fn claude_runtime_defaults_leave_effort_unset_when_not_configured() {
        let (root, paths) = claude_settings_fixture(
            "no-effort-level",
            concat!(
                "{\"model\": \"claude-opus-4-7\",\n",
                " \"alwaysThinkingEnabled\": true,\n",
                " \"env\": {\"MAX_THINKING_TOKENS\": \"32000\"}}\n"
            ),
        );

        let capture = claude_runtime_defaults_from_paths("2026-07-25T10:00:00Z", &paths);
        let defaults = capture.defaults.expect("runtime defaults present");
        assert_eq!(defaults.reasoning_effort, None);
        assert!(!defaults.selector_context.contains_key("reasoning_effort"));
        assert!(!defaults.selector_sources.contains_key("reasoning_effort"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn claude_runtime_defaults_absent_marks_not_configured_and_unreadable_apart() {
        let (configured_root, configured_paths) =
            claude_settings_fixture("not-configured", "{\"agentPushNotifEnabled\": true}\n");
        let capture = claude_runtime_defaults_from_paths("2026-07-25T10:00:00Z", &configured_paths);
        assert!(
            capture.defaults.is_none(),
            "an empty struct must not be attached when nothing is configured"
        );
        assert_eq!(
            capture.capability.status,
            AgentCapabilityStatus::Unsupported
        );
        assert_eq!(
            capture.diagnostic.as_ref().map(|entry| entry.code.as_str()),
            Some("claude_runtime_defaults_not_configured")
        );
        let _ = std::fs::remove_dir_all(configured_root);

        let (missing_root, missing_paths) = claude_settings_fixture("unreadable", "");
        let capture = claude_runtime_defaults_from_paths("2026-07-25T10:00:00Z", &missing_paths);
        assert!(capture.defaults.is_none());
        assert_eq!(
            capture.diagnostic.as_ref().map(|entry| entry.code.as_str()),
            Some("claude_runtime_defaults_unreadable")
        );
        let _ = std::fs::remove_dir_all(missing_root);
    }

    #[test]
    fn ottto_user_agent_identifies_honestly() {
        let user_agent = ottto_user_agent();
        assert!(
            user_agent.starts_with("ottto/"),
            "usage reads must identify as ottto, got {user_agent}"
        );
        assert!(user_agent.contains("subscription-usage-reader"));
        assert!(
            !user_agent.to_ascii_lowercase().contains("claude"),
            "never present a claude-* client identity: {user_agent}"
        );
    }
}
