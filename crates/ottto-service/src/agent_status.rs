use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ottto_core::{
    default_support_dir, read_claude_statusline_cache, ClaudeStatusLineRateLimitCache,
};
use ottto_protocol::{
    AgentAccountStatus, AgentAvailableModelStatus, AgentCapabilityGap, AgentCapabilityStatus,
    AgentContextState, AgentContextStatus, AgentCreditBalance, AgentCreditBalanceStatus,
    AgentCreditBalanceUnit, AgentDiagnosticSeverity, AgentLoginState, AgentModelStatus,
    AgentQuotaWindow, AgentQuotaWindowFreshness, AgentQuotaWindowScope, AgentQuotaWindowStatus,
    AgentStatusCollectionMethod, AgentStatusConfidence, AgentStatusDiagnostic,
    AgentStatusPlanObservation, AgentStatusSnapshot, AgentStatusState, SourceKind,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use time::{format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_AVAILABLE_MODELS: usize = 250;
const CLAUDE_STATUSLINE_CACHE_MAX_AGE_SECONDS: u64 = 24 * 60 * 60;

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
    let mut model_status = collect_model_status_from_output(&models, "openai");
    if model_status.available_models.is_empty() {
        if let Some(config_model) = read_codex_config_model() {
            if snapshot.collection_method == AgentStatusCollectionMethod::CommandProbe {
                snapshot.collection_method = AgentStatusCollectionMethod::ConfigFile;
            }
            model_status.default_model = Some(config_model.clone());
            model_status.active_model = Some(config_model);
        }
    }
    snapshot.model = Some(model_status);
    let mut quota_capability = unsupported_capability(
        "quota_windows",
        "Codex usage windows were not available from the local account probe.",
    );
    let mut credits_capability = unsupported_capability(
        "credits",
        "Codex credit balance was not available from the local account probe.",
    );
    match collect_codex_oauth_usage() {
        Ok(usage) => {
            if !usage.quota_windows.is_empty() {
                snapshot.collection_method = AgentStatusCollectionMethod::AppServer;
                snapshot.quota_windows = usage.quota_windows;
                quota_capability = supported_capability(
                    "quota_windows",
                    "Collected from the local Codex OAuth account usage endpoint.",
                );
            } else {
                snapshot.quota_windows = vec![unsupported_quota_window("usage")];
            }
            if !usage.credit_balances.is_empty() {
                snapshot.credit_balances = usage.credit_balances;
                credits_capability = supported_capability(
                    "credits",
                    "Collected from the local Codex OAuth account usage endpoint.",
                );
            }
        }
        Err(message) => {
            snapshot.quota_windows = vec![unsupported_quota_window("usage")];
            snapshot.diagnostics.push(AgentStatusDiagnostic {
                code: "codex_usage_probe_failed".to_string(),
                severity: AgentDiagnosticSeverity::Warning,
                message,
            });
        }
    }
    snapshot.context = Some(AgentContextStatus {
        status: AgentContextState::Unsupported,
        active_tokens: None,
        max_tokens: None,
        used_percent: None,
        remaining_tokens: None,
        source: Some("codex_cli_v1".to_string()),
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
    snapshot
}

fn collect_claude_status(captured_at: String, expires_at: String) -> AgentStatusSnapshot {
    if !executable_exists("claude") && !claude_settings_path().exists() {
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
            snapshot.account = Some(parse_claude_auth_json(&json));
            snapshot.status = AgentStatusState::Available;
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
        "Claude Code rate-limit windows have not been observed from statusLine yet.",
    );
    match collect_claude_statusline_quota_windows() {
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
            snapshot.diagnostics.push(AgentStatusDiagnostic {
                code: "claude_statusline_cache_unavailable".to_string(),
                severity: AgentDiagnosticSeverity::Warning,
                message,
            });
        }
    }
    snapshot.context = Some(AgentContextStatus {
        status: AgentContextState::Unsupported,
        active_tokens: None,
        max_tokens: None,
        used_percent: None,
        remaining_tokens: None,
        source: Some("claude_cli_v1".to_string()),
    });
    snapshot.capabilities = vec![
        supported_capability(
            "account_status",
            "Read from claude auth status --json when available.",
        ),
        quota_capability,
        unsupported_capability(
            "active_context",
            "Claude Code CLI does not expose active context metadata in v1.",
        ),
    ];
    if version.command_found && version.success {
        snapshot.diagnostics.push(AgentStatusDiagnostic {
            code: "claude_version_detected".to_string(),
            severity: AgentDiagnosticSeverity::Info,
            message: "Claude Code CLI version detected.".to_string(),
        });
    }
    append_current_plan_observation(&mut snapshot);
    snapshot
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

fn claude_statusline_quota_windows_from_cache(
    cache: ClaudeStatusLineRateLimitCache,
    now: u64,
) -> Vec<AgentQuotaWindow> {
    let mut windows = Vec::new();
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
            status: percent_quota_status(window.used_percent),
            freshness: AgentQuotaWindowFreshness::Fresh,
            model: None,
            account_label: None,
            window_seconds,
            started_at: None,
            resets_at: Some(resets_at),
            quota: None,
            remaining: None,
            used_percent: Some(window.used_percent),
            left_percent: Some(100u8.saturating_sub(window.used_percent)),
        });
    }
    windows
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
        snapshot.diagnostics.push(AgentStatusDiagnostic {
            code: "pi_agent_settings_detected".to_string(),
            severity: AgentDiagnosticSeverity::Info,
            message: "Pi model route read from ~/.pi/agent/settings.json.".to_string(),
        });
    }
    snapshot.quota_windows = vec![unsupported_quota_window("usage")];
    snapshot.context = Some(AgentContextStatus {
        status: AgentContextState::Unsupported,
        active_tokens: None,
        max_tokens: None,
        used_percent: None,
        remaining_tokens: None,
        source: Some("pi_cli_v1".to_string()),
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
    snapshot.diagnostics.push(AgentStatusDiagnostic {
        code: "agent_cli_not_found".to_string(),
        severity: AgentDiagnosticSeverity::Warning,
        message: format!("{binary} was not found on PATH or in known local metadata."),
    });
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
    let Some(rate_limit) = value.get("rate_limit") else {
        return Vec::new();
    };
    let mut windows = Vec::new();
    if let Some(primary) = rate_limit.get("primary_window") {
        if let Some(window) = codex_usage_quota_window("session", primary) {
            windows.push(window);
        }
    }
    if let Some(secondary) = rate_limit.get("secondary_window") {
        if let Some(window) = codex_usage_quota_window("weekly", secondary) {
            windows.push(window);
        }
    }
    windows
}

fn codex_usage_quota_window(name: &str, value: &Value) -> Option<AgentQuotaWindow> {
    let used_percent = json_u8(value, &["used_percent", "usedPercent"]);
    let left_percent = used_percent.map(|used| 100_u8.saturating_sub(used));
    let resets_at = json_timestamp_rfc3339(value, &["reset_at", "resets_at", "resetAt"]);
    let window_seconds = json_u64(value, &["limit_window_seconds", "window_seconds"]);
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
    })
}

fn codex_usage_credit_balances(value: &Value) -> Vec<AgentCreditBalance> {
    let credits = value
        .pointer("/rate_limit/credits")
        .or_else(|| value.get("credits"));
    let Some(credits) = credits else {
        return Vec::new();
    };
    let remaining = json_u64(credits, &["balance", "remaining", "credits"]);
    let unlimited = json_bool(credits, &["unlimited"]);
    let has_credits = json_bool(credits, &["has_credits", "hasCredits"]).unwrap_or(false);
    if remaining.is_none() && unlimited.is_none() && !has_credits {
        return Vec::new();
    }
    let status = if unlimited == Some(true) {
        AgentCreditBalanceStatus::Unlimited
    } else if remaining == Some(0) {
        AgentCreditBalanceStatus::Exhausted
    } else if remaining.is_some_and(|value| value > 0 && value <= 5) {
        AgentCreditBalanceStatus::Low
    } else if remaining.is_some() || has_credits {
        AgentCreditBalanceStatus::Ok
    } else {
        AgentCreditBalanceStatus::Unknown
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
    }]
}

#[derive(Debug)]
struct CodexOrganization {
    id: Option<String>,
    label: Option<String>,
}

fn default_codex_organization(value: &Value) -> Option<CodexOrganization> {
    let organizations = value.get("organizations")?.as_array()?;
    let selected = organizations
        .iter()
        .find(|organization| {
            organization
                .get("is_default")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .or_else(|| organizations.first())?;
    Some(CodexOrganization {
        id: first_json_string(selected, &["id"]),
        label: first_json_string(selected, &["title", "name", "label"]),
    })
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

pub(crate) fn read_pi_smoke_routes() -> Vec<PiModelRoute> {
    if let Some(settings) = read_pi_agent_settings() {
        if let Some(route) = collect_default_pi_smoke_route_from_settings(&settings) {
            return vec![route];
        }
    }
    Vec::new()
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
    let lower = value.to_ascii_lowercase();
    lower.contains("gpt")
        || lower.contains("claude")
        || lower.contains("gemini")
        || lower.contains("o3")
        || lower.contains("o4")
        || lower.contains("o5")
        || lower.contains("model")
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
    AgentStatusDiagnostic {
        code: code.to_string(),
        severity: AgentDiagnosticSeverity::Warning,
        message: format!("{message}{status}.{stderr_hint}"),
    }
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

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = String::new();
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stdout.take() {
                    let _ = pipe.read_to_string(&mut stdout);
                }
                if let Some(mut pipe) = child.stderr.take() {
                    let _ = pipe.read_to_string(&mut stderr);
                }
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
                return CommandOutput {
                    command_found: true,
                    success: false,
                    status_code: None,
                    stdout: String::new(),
                    stderr: String::new(),
                };
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(_) => {
                let _ = child.kill();
                return CommandOutput {
                    command_found: true,
                    success: false,
                    status_code: None,
                    stdout: String::new(),
                    stderr: String::new(),
                };
            }
        }
    }
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

fn claude_settings_path() -> PathBuf {
    home_path(".claude/settings.json")
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
}
