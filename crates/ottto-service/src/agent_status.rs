use aes::Aes128;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use ottto_core::{
    compiled_release_version, default_support_dir, read_claude_statusline_cache,
    read_claude_statusline_context_cache, read_claude_statusline_context_history,
    ClaudeStatusLineContextWindowCache, ClaudeStatusLineContextWindowHistory,
    ClaudeStatusLineContextWindowSample, ClaudeStatusLineRateLimitCache,
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
use time::{format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime};
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
const CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS: u64 = 24 * 60 * 60;
const CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_SECONDS: u64 = 15 * 60;
const CLAUDE_OAUTH_USAGE_REFRESH_SECONDS: u64 = 5 * 60;
const CLAUDE_OAUTH_USAGE_RETRY_AFTER_FALLBACK_SECONDS: u64 = 5 * 60;
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

const CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION: u16 = 2;

/// Everything the Claude OAuth usage endpoint yields in one fetch.
#[derive(Debug, Clone, Default)]
struct ClaudeOAuthUsage {
    windows: Vec<AgentQuotaWindow>,
    credit_balances: Vec<AgentCreditBalance>,
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
                    // Intentionally never set for Claude Code: reasoning effort
                    // is chosen per session, so there is no durable machine
                    // default to report and inventing one would misstate what
                    // the customer configured.
                    reasoning_effort: None,
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
                    "Claude Code settings were read, but none set a display-safe default (model, permission mode, fast mode, or sandbox).",
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
            let refined_seat_plan = read_claude_cli_oauth_account(&claude_cli_config_path())
                .and_then(|oauth| refine_claude_team_seat_plan(&mut account, &oauth));
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
    match collect_claude_oauth_usage(&version) {
        Ok(usage) if !usage.windows.is_empty() => {
            snapshot.collection_method = AgentStatusCollectionMethod::CliJson;
            snapshot.quota_windows = usage.windows;
            snapshot.credit_balances = usage.credit_balances;
            quota_capability = supported_capability(
                "quota_windows",
                "Collected from Claude Code's local OAuth usage endpoint.",
            );
        }
        Ok(_) => match collect_claude_statusline_quota_windows() {
            Ok(windows) if !windows.is_empty() => {
                snapshot.collection_method = AgentStatusCollectionMethod::StatusLine;
                snapshot.quota_windows = windows;
                quota_capability = supported_capability(
                    "quota_windows",
                    "Collected from Claude Code's local statusLine rate_limits payload.",
                );
            }
            Ok(_) => {
                snapshot.quota_windows = vec![unsupported_quota_window("usage")];
            }
            Err(message) => {
                snapshot.quota_windows = vec![unsupported_quota_window("usage")];
                snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                    "claude_statusline_cache_unavailable",
                    AgentDiagnosticSeverity::Warning,
                    message,
                ));
            }
        },
        Err(message) => match collect_claude_statusline_quota_windows() {
            Ok(windows) if !windows.is_empty() => {
                snapshot.collection_method = AgentStatusCollectionMethod::StatusLine;
                snapshot.quota_windows = windows;
                quota_capability = supported_capability(
                    "quota_windows",
                    "Collected from Claude Code's local statusLine rate_limits payload.",
                );
            }
            Ok(_) | Err(_) => {
                snapshot.quota_windows = vec![unsupported_quota_window("usage")];
                snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                    "claude_oauth_usage_unavailable",
                    AgentDiagnosticSeverity::Warning,
                    message,
                ));
            }
        },
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
        append_claude_desktop_plan_observations(&mut snapshot, &claude_desktop_root);
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

fn append_claude_desktop_plan_observations(
    snapshot: &mut AgentStatusSnapshot,
    desktop_root: &Path,
) -> usize {
    let observations =
        claude_desktop_plan_observations_from_root(desktop_root, &snapshot.captured_at);
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
    let organization_id = builder
        .current_organization_uuid
        .or_else(|| builder.organization_uuids.iter().next().cloned());
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

fn collect_claude_statusline_quota_windows() -> Result<Vec<AgentQuotaWindow>, String> {
    let cache = read_claude_statusline_cache(&default_support_dir())
        .map_err(|_| "Claude Code statusLine cache could not be read safely.".to_string())?;
    let Some(cache) = cache else {
        return Ok(Vec::new());
    };
    let now = current_unix_seconds();
    if cache.observed_at_epoch_seconds > now.saturating_add(60)
        || now.saturating_sub(cache.observed_at_epoch_seconds)
            > CLAUDE_STATUSLINE_CACHE_MAX_AGE_SECONDS
    {
        return Ok(Vec::new());
    }

    Ok(claude_statusline_quota_windows_from_cache(cache, now))
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

fn collect_claude_oauth_usage(version: &CommandOutput) -> Result<ClaudeOAuthUsage, String> {
    let now = current_unix_seconds();
    if let Some(cache) = read_claude_oauth_usage_cache() {
        let cache_age = now.saturating_sub(cache.observed_at_epoch_seconds);
        if !cache.windows.is_empty()
            && cache_age <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
            && (cache_age <= CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_SECONDS
                || now < cache.next_refresh_after_epoch_seconds)
        {
            return Ok(claude_oauth_usage_from_cache(cache, now));
        }
        if now < cache.next_refresh_after_epoch_seconds {
            return Err("Claude OAuth usage endpoint is rate limited.".to_string());
        }
    }

    let token = read_claude_oauth_access_token()
        .ok_or_else(|| "Claude OAuth credentials were not available locally.".to_string())?;
    let authorization = format!("Bearer {token}");
    let user_agent = claude_code_user_agent(version);
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
            let mut cache = read_claude_oauth_usage_cache().unwrap_or(ClaudeOAuthUsageCache {
                schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
                observed_at_epoch_seconds: now,
                next_refresh_after_epoch_seconds: retry_after,
                windows: Vec::new(),
                credit_balances: Vec::new(),
            });
            cache.next_refresh_after_epoch_seconds = retry_after;
            let _ = write_claude_oauth_usage_cache(&cache);
            if !cache.windows.is_empty()
                && now.saturating_sub(cache.observed_at_epoch_seconds)
                    <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
            {
                return Ok(claude_oauth_usage_from_cache(cache, now));
            }
            return Err("Claude OAuth usage endpoint is rate limited.".to_string());
        }
        Err(error) => {
            if let Some(cache) = read_claude_oauth_usage_cache() {
                if !cache.windows.is_empty()
                    && now.saturating_sub(cache.observed_at_epoch_seconds)
                        <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
                {
                    return Ok(claude_oauth_usage_from_cache(cache, now));
                }
            }
            return Err(claude_oauth_usage_error(error));
        }
    };
    let value: Value = response
        .into_json()
        .map_err(|_| "Claude OAuth usage endpoint returned an unreadable response.".to_string())?;
    let usage = ClaudeOAuthUsage {
        windows: claude_oauth_quota_windows(&value),
        credit_balances: claude_oauth_credit_balances(&value),
    };
    if !usage.windows.is_empty() {
        let _ = write_claude_oauth_usage_cache(&ClaudeOAuthUsageCache {
            schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
            observed_at_epoch_seconds: now,
            next_refresh_after_epoch_seconds: now + CLAUDE_OAUTH_USAGE_REFRESH_SECONDS,
            windows: usage.windows.clone(),
            credit_balances: usage.credit_balances.clone(),
        });
    }
    Ok(usage)
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

fn read_claude_oauth_usage_cache() -> Option<ClaudeOAuthUsageCache> {
    let path = claude_oauth_usage_cache_path();
    let body = fs::read_to_string(path).ok()?;
    let cache: ClaudeOAuthUsageCache = serde_json::from_str(&body).ok()?;
    if cache.schema_version != CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION {
        // Older cache layouts (v1: windows only) are discarded so the next
        // tick refetches and repopulates the credit balances.
        return None;
    }
    Some(cache)
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

fn claude_code_user_agent(version: &CommandOutput) -> String {
    let version = if version.command_found && version.success {
        version
            .stdout
            .split_whitespace()
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("2.1.0")
    } else {
        "2.1.0"
    };
    format!("claude-code/{version}")
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
    let cache_is_stale = cache_age > CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_SECONDS;
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

fn billing_identity_hash(provider: &str, kind: &str, value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let material = format!(
        "{}:{}:{}",
        provider.trim().to_ascii_lowercase(),
        kind.trim().to_ascii_lowercase(),
        value.to_ascii_lowercase()
    );
    let mut hasher = Sha256::new();
    hasher.update(material.as_bytes());
    Some(format!("{:x}", hasher.finalize()))
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
        account_identifier_hash,
        organization_identifier_hash,
        credential_fingerprint_hash: None,
        billing_identity_evidence,
        billing_identity_confidence: AgentStatusConfidence::High,
        confidence: AgentStatusConfidence::High,
    })
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
        email_address: field("emailAddress"),
        organization_uuid: field("organizationUuid"),
        organization_type: field("organizationType"),
        seat_tier: field("seatTier"),
        organization_rate_limit_tier: field("organizationRateLimitTier"),
        user_rate_limit_tier: field("userRateLimitTier"),
    })
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
    let mismatch = |ours: &Option<String>, theirs: &Option<String>| match (ours, theirs) {
        (Some(a), Some(b)) => !a.eq_ignore_ascii_case(b.trim()),
        _ => false,
    };
    if mismatch(&account.email, &oauth.email_address)
        || mismatch(&account.organization_id, &oauth.organization_uuid)
    {
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
    use ottto_core::ClaudeStatusLineRateLimitWindow;
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
        assert_eq!(account.confidence, AgentStatusConfidence::High);
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

        assert_eq!(parsed.email_address.as_deref(), Some("ron.s@singular.net"));
        assert_eq!(parsed.organization_type.as_deref(), Some("claude_team"));
        assert_eq!(parsed.seat_tier.as_deref(), Some("premium"));
        assert_eq!(
            parsed.user_rate_limit_tier.as_deref(),
            Some("default_claude_max_5x")
        );
        assert!(parse_claude_cli_oauth_account(&serde_json::json!({})).is_none());
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

        let usage = claude_oauth_usage_from_cache(
            cache,
            100 + CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_SECONDS + 1,
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

    #[test]
    fn claude_statusline_cache_maps_fresh_windows() {
        let cache = ClaudeStatusLineRateLimitCache {
            schema_version: 1,
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
    }

    #[test]
    fn claude_statusline_cache_skips_expired_and_unknown_windows() {
        let cache = ClaudeStatusLineRateLimitCache {
            schema_version: 1,
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
            schema_version: 1,
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

    /// Claude Code picks reasoning effort per session, so there is no durable
    /// machine default to report. Emitting one would misstate what the customer
    /// configured, so this field must stay unset for Claude Code no matter what
    /// the settings files contain.
    #[test]
    fn claude_runtime_defaults_never_report_reasoning_effort() {
        let (root, paths) = claude_settings_fixture(
            "no-effort",
            concat!(
                "{\"model\": \"claude-opus-4-7\",\n",
                " \"effortLevel\": \"xhigh\",\n",
                " \"alwaysThinkingEnabled\": true,\n",
                " \"reasoning_effort\": \"high\",\n",
                " \"env\": {\"MAX_THINKING_TOKENS\": \"32000\"}}\n"
            ),
        );

        let capture = claude_runtime_defaults_from_paths("2026-07-25T10:00:00Z", &paths);
        let defaults = capture.defaults.expect("runtime defaults present");
        assert_eq!(
            defaults.reasoning_effort, None,
            "Claude Code has no durable reasoning-effort default"
        );
        assert!(!defaults.selector_context.contains_key("reasoning_effort"));
        assert!(!defaults.selector_sources.contains_key("reasoning_effort"));
        // Nor any of the other Codex-shaped tier fields Claude config lacks.
        assert_eq!(defaults.service_tier, None);
        assert_eq!(defaults.speed_mode, None);
        assert_eq!(defaults.priority_enabled, None);

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
}
